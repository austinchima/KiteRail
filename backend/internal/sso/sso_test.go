package sso

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/austinchima/elodea/internal/auth"
	"github.com/austinchima/elodea/internal/config"
	"github.com/austinchima/elodea/internal/db"
)

const (
	consoleOrigin = "http://console.test"
	clientID      = "elodea-console"
)

// fakeIdP is a minimal OIDC provider: discovery, JWKS, and a token endpoint
// that checks PKCE and returns an RS256-signed ID token.
type fakeIdP struct {
	t      *testing.T
	server *httptest.Server
	key    *rsa.PrivateKey

	mu        sync.Mutex
	challenge string // code_challenge seen in the authorize redirect
	claims    func(nonce string) map[string]any
	nonce     string
}

func newFakeIdP(t *testing.T) *fakeIdP {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	idp := &fakeIdP{t: t, key: key}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                idp.server.URL,
			"authorization_endpoint":                idp.server.URL + "/authorize",
			"token_endpoint":                        idp.server.URL + "/token",
			"jwks_uri":                              idp.server.URL + "/keys",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("GET /keys", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
			{Key: &idp.key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"},
		}})
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		idp.mu.Lock()
		challenge, claims, nonce := idp.challenge, idp.claims, idp.nonce
		idp.mu.Unlock()
		if r.PostForm.Get("code") != "good-code" || base64.RawURLEncoding.EncodeToString(sum[:]) != challenge {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "at", "token_type": "Bearer", "expires_in": 300,
			"id_token": idp.sign(claims(nonce)),
		})
	})
	idp.server = httptest.NewServer(mux)
	t.Cleanup(idp.server.Close)
	idp.claims = idp.standardClaims(map[string]any{"email": "Priya.Raman@Corp.test", "email_verified": true, "groups": []string{"treasury-reviewers"}})
	return idp
}

func (idp *fakeIdP) standardClaims(extra map[string]any) func(string) map[string]any {
	return func(nonce string) map[string]any {
		c := map[string]any{
			"iss": idp.server.URL, "sub": "user-123", "aud": clientID, "nonce": nonce,
			"iat": time.Now().Unix(), "exp": time.Now().Add(5 * time.Minute).Unix(),
		}
		for k, v := range extra {
			c[k] = v
		}
		return c
	}
}

func (idp *fakeIdP) sign(claims map[string]any) string {
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: idp.key}, (&jose.SignerOptions{}).WithHeader("kid", "k1"))
	require.NoError(idp.t, err)
	payload, err := json.Marshal(claims)
	require.NoError(idp.t, err)
	object, err := signer.Sign(payload)
	require.NoError(idp.t, err)
	token, err := object.CompactSerialize()
	require.NoError(idp.t, err)
	return token
}

// memStore is an in-memory Store with the same semantics as the SQL queries.
type memStore struct {
	mu       sync.Mutex
	attempts map[string]db.CreateLoginAttemptParams
	sessions map[string]*db.Session
	touched  int
}

func newMemStore() *memStore {
	return &memStore{attempts: map[string]db.CreateLoginAttemptParams{}, sessions: map[string]*db.Session{}}
}

func (m *memStore) CreateLoginAttempt(_ context.Context, a db.CreateLoginAttemptParams) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.attempts[a.State] = a
	return nil
}

func (m *memStore) ConsumeLoginAttempt(_ context.Context, state string) (db.ConsumeLoginAttemptRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.attempts[state]
	delete(m.attempts, state)
	if !ok || !a.ExpiresAt.After(time.Now()) {
		return db.ConsumeLoginAttemptRow{}, sql.ErrNoRows
	}
	return db.ConsumeLoginAttemptRow{Nonce: a.Nonce, CodeVerifier: a.CodeVerifier, ReturnTo: a.ReturnTo}, nil
}

func (m *memStore) DeleteExpiredLoginAttempts(context.Context) error { return nil }
func (m *memStore) DeleteExpiredSessions(context.Context) error      { return nil }

func (m *memStore) CreateSession(_ context.Context, a db.CreateSessionParams) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	m.sessions[a.IDHash] = &db.Session{IDHash: a.IDHash, Subject: a.Subject, Email: a.Email, Role: a.Role, CreatedAt: now, ExpiresAt: a.ExpiresAt, LastSeenAt: now}
	return nil
}

func (m *memStore) GetActiveSession(_ context.Context, a db.GetActiveSessionParams) (db.GetActiveSessionRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[a.IDHash]
	if !ok || s.RevokedAt.Valid || !s.ExpiresAt.After(time.Now()) || !s.LastSeenAt.After(a.LastSeenAt) {
		return db.GetActiveSessionRow{}, sql.ErrNoRows
	}
	return db.GetActiveSessionRow{IDHash: s.IDHash, Subject: s.Subject, Email: s.Email, Role: s.Role, CreatedAt: s.CreatedAt, ExpiresAt: s.ExpiresAt, LastSeenAt: s.LastSeenAt}, nil
}

func (m *memStore) TouchSession(_ context.Context, idHash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.touched++
	if s, ok := m.sessions[idHash]; ok {
		s.LastSeenAt = time.Now()
	}
	return nil
}

func (m *memStore) RevokeSession(_ context.Context, idHash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.sessions[idHash]; ok {
		s.RevokedAt = sql.NullTime{Time: time.Now(), Valid: true}
	}
	return nil
}

func newTestService(t *testing.T, idp *fakeIdP, store *memStore) *Service {
	cfg := config.OIDCConfig{
		Issuer: idp.server.URL, ClientID: clientID, ClientSecret: "secret",
		RedirectURL: "http://api.test/auth/callback", ProviderName: "Okta",
		GroupsClaim: "groups", IdentityClaim: "email", Scopes: []string{"openid", "email", "groups"},
		ReviewerGroups: []string{"treasury-reviewers"}, AdminGroups: []string{"elodea-admins"},
		SessionTTL: 8 * time.Hour, SessionIdleTTL: time.Hour,
	}
	svc := New(cfg, []string{consoleOrigin}, store, zap.NewNop())
	require.NoError(t, svc.Discover(context.Background()))
	return svc
}

// signIn runs /auth/login then /auth/callback and returns the callback response.
func signIn(t *testing.T, svc *Service, idp *fakeIdP, returnTo string) (*httptest.ResponseRecorder, url.Values) {
	t.Helper()
	routes := svc.Routes()
	rec := httptest.NewRecorder()
	routes.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/login?return_to="+url.QueryEscape(returnTo), nil))
	require.Equal(t, http.StatusFound, rec.Code, rec.Body.String())
	authorize, err := url.Parse(rec.Header().Get("Location"))
	require.NoError(t, err)
	params := authorize.Query()
	idp.mu.Lock()
	idp.challenge, idp.nonce = params.Get("code_challenge"), params.Get("nonce")
	idp.mu.Unlock()

	rec = httptest.NewRecorder()
	routes.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/callback?code=good-code&state="+url.QueryEscape(params.Get("state")), nil))
	return rec, params
}

func sessionCookie(t *testing.T, rec *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == devCookieName {
			return c
		}
	}
	t.Fatalf("no session cookie in %v", rec.Header())
	return nil
}

func TestSignIn_IssuesSessionForVerifiedReviewer(t *testing.T) {
	idp, store := newFakeIdP(t), newMemStore()
	svc := newTestService(t, idp, store)

	rec, params := signIn(t, svc, idp, consoleOrigin+"/inbox")
	assert.Equal(t, "S256", params.Get("code_challenge_method"), "PKCE is always used")
	assert.Contains(t, params.Get("scope"), "openid")
	require.Equal(t, http.StatusFound, rec.Code)
	assert.Equal(t, consoleOrigin+"/inbox", rec.Header().Get("Location"))

	cookie := sessionCookie(t, rec)
	assert.True(t, cookie.HttpOnly)
	assert.Equal(t, http.SameSiteLaxMode, cookie.SameSite)
	_, stored := store.sessions[cookie.Value]
	assert.False(t, stored, "the database holds only a hash of the session token")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	req.AddCookie(cookie)
	identity, ok := svc.AuthenticateSession(req)
	require.True(t, ok)
	assert.Equal(t, auth.Identity{ID: "priya.raman@corp.test", Role: auth.RoleReviewer}, identity)
}

func TestSignIn_AdminGroupWinsOverReviewer(t *testing.T) {
	idp, store := newFakeIdP(t), newMemStore()
	idp.claims = idp.standardClaims(map[string]any{"email": "ops@corp.test", "email_verified": true, "groups": []string{"treasury-reviewers", "elodea-admins"}})
	svc := newTestService(t, idp, store)

	rec, _ := signIn(t, svc, idp, consoleOrigin)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(sessionCookie(t, rec))
	identity, ok := svc.AuthenticateSession(req)
	require.True(t, ok)
	assert.Equal(t, auth.RoleAdmin, identity.Role)
}

func TestSignIn_RefusesUnsafeTokens(t *testing.T) {
	cases := []struct {
		name   string
		claims func(idp *fakeIdP) func(string) map[string]any
		want   string
	}{
		{"unverified email", func(idp *fakeIdP) func(string) map[string]any {
			return idp.standardClaims(map[string]any{"email": "a@corp.test", "email_verified": false, "groups": []string{"treasury-reviewers"}})
		}, errUnverified},
		{"no matching group", func(idp *fakeIdP) func(string) map[string]any {
			return idp.standardClaims(map[string]any{"email": "a@corp.test", "email_verified": true, "groups": []string{"marketing"}})
		}, errNoRole},
		{"no email", func(idp *fakeIdP) func(string) map[string]any {
			return idp.standardClaims(map[string]any{"groups": []string{"treasury-reviewers"}})
		}, errNoIdentity},
		{"wrong audience", func(idp *fakeIdP) func(string) map[string]any {
			return idp.standardClaims(map[string]any{"aud": "another-app", "email": "a@corp.test", "email_verified": true, "groups": []string{"treasury-reviewers"}})
		}, errFailed},
		{"expired", func(idp *fakeIdP) func(string) map[string]any {
			return idp.standardClaims(map[string]any{"exp": time.Now().Add(-time.Minute).Unix(), "email": "a@corp.test", "email_verified": true, "groups": []string{"treasury-reviewers"}})
		}, errFailed},
		{"nonce mismatch", func(idp *fakeIdP) func(string) map[string]any {
			return idp.standardClaims(map[string]any{"nonce": "attacker", "email": "a@corp.test", "email_verified": true, "groups": []string{"treasury-reviewers"}})
		}, errFailed},
		{"wrong issuer", func(idp *fakeIdP) func(string) map[string]any {
			return idp.standardClaims(map[string]any{"iss": "https://evil.test", "email": "a@corp.test", "email_verified": true, "groups": []string{"treasury-reviewers"}})
		}, errFailed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			idp, store := newFakeIdP(t), newMemStore()
			idp.claims = tc.claims(idp)
			svc := newTestService(t, idp, store)

			rec, _ := signIn(t, svc, idp, consoleOrigin)
			require.Equal(t, http.StatusFound, rec.Code)
			assert.Equal(t, consoleOrigin+"/?sso_error="+tc.want, rec.Header().Get("Location"))
			assert.Empty(t, rec.Result().Cookies(), "no session on refusal")
			assert.Empty(t, store.sessions)
		})
	}
}

func TestCallback_StateIsSingleUse(t *testing.T) {
	idp, store := newFakeIdP(t), newMemStore()
	svc := newTestService(t, idp, store)

	_, params := signIn(t, svc, idp, consoleOrigin)
	rec := httptest.NewRecorder()
	svc.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/callback?code=good-code&state="+url.QueryEscape(params.Get("state")), nil))
	assert.Equal(t, http.StatusBadRequest, rec.Code, "a replayed callback must not create a second session")

	rec = httptest.NewRecorder()
	svc.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/callback?code=good-code&state=forged", nil))
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestCallback_ProviderErrorReturnsToConsole(t *testing.T) {
	idp, store := newFakeIdP(t), newMemStore()
	svc := newTestService(t, idp, store)

	rec := httptest.NewRecorder()
	svc.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/login", nil))
	state, _ := url.Parse(rec.Header().Get("Location"))

	rec = httptest.NewRecorder()
	svc.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/callback?error=access_denied&state="+url.QueryEscape(state.Query().Get("state")), nil))
	assert.Equal(t, consoleOrigin+"/?sso_error="+errDenied, rec.Header().Get("Location"))
}

func TestLogin_RejectsReturnToOutsideAllowedOrigins(t *testing.T) {
	idp, store := newFakeIdP(t), newMemStore()
	svc := newTestService(t, idp, store)

	for _, returnTo := range []string{
		"https://evil.test",
		"http://console.test.evil.test/",
		"http://user@console.test/",
		"javascript:alert(1)",
		"//evil.test",
	} {
		rec := httptest.NewRecorder()
		svc.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/login?return_to="+url.QueryEscape(returnTo), nil))
		assert.Equal(t, http.StatusBadRequest, rec.Code, returnTo)
	}
	got, ok := svc.validReturnTo(consoleOrigin + "//evil.test")
	assert.True(t, ok)
	assert.Equal(t, consoleOrigin+"/", got, "a protocol-relative path collapses to the console root")
}

func TestLogin_UnavailableUntilDiscovered(t *testing.T) {
	svc := New(config.OIDCConfig{Issuer: "http://127.0.0.1:1"}, []string{consoleOrigin}, newMemStore(), zap.NewNop())
	rec := httptest.NewRecorder()
	svc.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/login", nil))
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

func TestLogout_RequiresCSRFHeaderAndRevokes(t *testing.T) {
	idp, store := newFakeIdP(t), newMemStore()
	svc := newTestService(t, idp, store)
	rec, _ := signIn(t, svc, idp, consoleOrigin)
	cookie := sessionCookie(t, rec)

	forged := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	forged.AddCookie(cookie)
	rec = httptest.NewRecorder()
	svc.Routes().ServeHTTP(rec, forged)
	assert.Equal(t, http.StatusForbidden, rec.Code)

	logout := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	logout.Header.Set(auth.CSRFHeader, auth.CSRFHeaderValue)
	logout.AddCookie(cookie)
	rec = httptest.NewRecorder()
	svc.Routes().ServeHTTP(rec, logout)
	assert.Equal(t, http.StatusNoContent, rec.Code)
	assert.True(t, strings.Contains(rec.Header().Get("Set-Cookie"), "Max-Age=0"), "the cookie is cleared")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(cookie)
	_, ok := svc.AuthenticateSession(req)
	assert.False(t, ok, "a signed-out session cookie no longer works")
}

func TestAuthenticateSession_IdleSessionsExpireAndActiveOnesAreTouched(t *testing.T) {
	idp, store := newFakeIdP(t), newMemStore()
	svc := newTestService(t, idp, store)
	rec, _ := signIn(t, svc, idp, consoleOrigin)
	cookie := sessionCookie(t, rec)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(cookie)

	for _, s := range store.sessions {
		s.LastSeenAt = time.Now().Add(-5 * time.Minute)
	}
	_, ok := svc.AuthenticateSession(req)
	require.True(t, ok)
	assert.Equal(t, 1, store.touched, "activity older than a minute is recorded")
	_, _ = svc.AuthenticateSession(req)
	assert.Equal(t, 1, store.touched, "recent activity is not rewritten on every request")

	for _, s := range store.sessions {
		s.LastSeenAt = time.Now().Add(-2 * time.Hour)
	}
	_, ok = svc.AuthenticateSession(req)
	assert.False(t, ok, "a session idle past the idle TTL is rejected")

	bogus := httptest.NewRequest(http.MethodGet, "/", nil)
	bogus.AddCookie(&http.Cookie{Name: devCookieName, Value: "not-a-session"})
	_, ok = svc.AuthenticateSession(bogus)
	assert.False(t, ok)
}

func TestSecureCookieUsesHostPrefix(t *testing.T) {
	svc := New(config.OIDCConfig{RedirectURL: "https://elodea.corp.test/auth/callback", CookieSameSite: "none"}, nil, newMemStore(), zap.NewNop())
	c := svc.cookie("v", 60)
	assert.Equal(t, secureCookieName, c.Name)
	assert.True(t, c.Secure)
	assert.Equal(t, http.SameSiteNoneMode, c.SameSite)
	assert.Equal(t, "/", c.Path)
	assert.Empty(t, c.Domain)
}
