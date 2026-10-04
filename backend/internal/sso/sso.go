// Package sso signs reviewers and admins in through the customer's OIDC
// identity provider (Okta, Entra ID, Google Workspace, Auth0, Keycloak).
//
// It follows the backend-for-frontend pattern: the server runs the
// Authorization Code flow with PKCE, verifies the ID token, and gives the
// browser only an opaque HttpOnly session cookie. Provider tokens never
// reach the browser, and the database stores only the SHA-256 of each
// session token. Roles come from IdP groups, so offboarding happens in the
// IdP, not by editing Elodea's configuration.
package sso

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"go.uber.org/zap"
	"golang.org/x/oauth2"

	"github.com/austinchima/elodea/internal/auth"
	"github.com/austinchima/elodea/internal/config"
	"github.com/austinchima/elodea/internal/db"
)

// Store is the persistence the sign-in flow needs; *db.Queries implements it.
type Store interface {
	CreateLoginAttempt(ctx context.Context, arg db.CreateLoginAttemptParams) error
	ConsumeLoginAttempt(ctx context.Context, state string) (db.ConsumeLoginAttemptRow, error)
	DeleteExpiredLoginAttempts(ctx context.Context) error
	CreateSession(ctx context.Context, arg db.CreateSessionParams) error
	GetActiveSession(ctx context.Context, arg db.GetActiveSessionParams) (db.GetActiveSessionRow, error)
	TouchSession(ctx context.Context, idHash string) error
	RevokeSession(ctx context.Context, idHash string) error
	DeleteExpiredSessions(ctx context.Context) error
}

const (
	// loginAttemptTTL bounds one round trip to the identity provider.
	loginAttemptTTL = 10 * time.Minute
	// touchInterval limits last_seen_at writes to one per session per minute.
	touchInterval = time.Minute
	// The __Host- prefix makes the browser enforce Secure, Path=/ and no
	// Domain attribute, so a sibling subdomain cannot plant or read it.
	secureCookieName = "__Host-elodea_session"
	devCookieName    = "elodea_session"
)

// Sign-in failure codes, passed back to the console as ?sso_error=.
const (
	errDenied        = "denied"
	errUnavailable   = "unavailable"
	errFailed        = "failed"
	errNoIdentity    = "no_identity"
	errUnverified    = "unverified_email"
	errNoRole        = "no_role"
	errSessionFailed = "session_failed"
)

// Service runs SSO sign-in and resolves session cookies to identities.
type Service struct {
	cfg            config.OIDCConfig
	allowedOrigins []string
	store          Store
	logger         *zap.Logger
	httpClient     *http.Client
	now            func() time.Time

	mu       sync.RWMutex
	verifier *oidc.IDTokenVerifier
	oauth    *oauth2.Config
}

// New builds the service. Sign-in stays unavailable until Discover succeeds;
// that never blocks startup or agent traffic.
func New(cfg config.OIDCConfig, allowedOrigins []string, store Store, logger *zap.Logger) *Service {
	return &Service{
		cfg:            cfg,
		allowedOrigins: allowedOrigins,
		store:          store,
		logger:         logger,
		httpClient:     &http.Client{Timeout: 10 * time.Second},
		now:            time.Now,
	}
}

// Discover fetches the provider's metadata and signing keys.
func (s *Service) Discover(ctx context.Context) error {
	provider, err := oidc.NewProvider(oidc.ClientContext(ctx, s.httpClient), s.cfg.Issuer)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.verifier = provider.Verifier(&oidc.Config{ClientID: s.cfg.ClientID, Now: s.now})
	s.oauth = &oauth2.Config{
		ClientID:     s.cfg.ClientID,
		ClientSecret: s.cfg.ClientSecret,
		RedirectURL:  s.cfg.RedirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       s.cfg.Scopes,
	}
	return nil
}

// Run discovers the provider, retrying with backoff while it is
// unreachable, then deletes expired login attempts and sessions hourly.
func (s *Service) Run(ctx context.Context) {
	delay := 2 * time.Second
	for {
		err := s.Discover(ctx)
		if err == nil {
			s.logger.Info("SSO provider discovered", zap.String("issuer", s.cfg.Issuer))
			break
		}
		s.logger.Warn("SSO provider not reachable yet, retrying", zap.String("issuer", s.cfg.Issuer), zap.Duration("retry_in", delay), zap.Error(err))
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		delay = min(delay*2, time.Minute)
	}
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.store.DeleteExpiredLoginAttempts(ctx); err != nil {
				s.logger.Warn("failed to delete expired login attempts", zap.Error(err))
			}
			if err := s.store.DeleteExpiredSessions(ctx); err != nil {
				s.logger.Warn("failed to delete expired sessions", zap.Error(err))
			}
		}
	}
}

func (s *Service) client() (*oidc.IDTokenVerifier, *oauth2.Config, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.verifier, s.oauth, s.oauth != nil
}

// Routes serves /auth/login, /auth/callback and /auth/logout.
func (s *Service) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /auth/login", s.login)
	mux.HandleFunc("GET /auth/callback", s.callback)
	mux.HandleFunc("POST /auth/logout", s.logout)
	return mux
}

// ConfigHandler tells the console which sign-in options to show.
func (s *Service) ConfigHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"sso": true, "provider": s.cfg.ProviderName})
	})
}

func (s *Service) login(w http.ResponseWriter, r *http.Request) {
	_, oauthCfg, ok := s.client()
	if !ok {
		http.Error(w, "Single sign-on is unavailable: the identity provider has not answered yet.", http.StatusServiceUnavailable)
		return
	}
	returnTo, ok := s.validReturnTo(r.URL.Query().Get("return_to"))
	if !ok {
		http.Error(w, "return_to must be an allowed console origin.", http.StatusBadRequest)
		return
	}
	state, nonce := randomToken(), randomToken()
	verifier := oauth2.GenerateVerifier()
	if err := s.store.CreateLoginAttempt(r.Context(), db.CreateLoginAttemptParams{
		State: state, Nonce: nonce, CodeVerifier: verifier, ReturnTo: returnTo,
		ExpiresAt: s.now().Add(loginAttemptTTL),
	}); err != nil {
		s.logger.Error("failed to store login attempt", zap.Error(err))
		http.Error(w, "Sign-in is temporarily unavailable.", http.StatusServiceUnavailable)
		return
	}
	http.Redirect(w, r, oauthCfg.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier)), http.StatusFound)
}

func (s *Service) callback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	query := r.URL.Query()
	attempt, err := s.store.ConsumeLoginAttempt(ctx, query.Get("state"))
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			s.logger.Error("failed to read login attempt", zap.Error(err))
		}
		http.Error(w, "This sign-in link has expired or was already used. Start again from the console.", http.StatusBadRequest)
		return
	}
	fail := func(code, reason string, fields ...zap.Field) {
		s.logger.Warn("SSO sign-in refused: "+reason, append(fields, zap.String("code", code))...)
		http.Redirect(w, r, withQuery(attempt.ReturnTo, "sso_error", code), http.StatusFound)
	}
	if idpErr := query.Get("error"); idpErr != "" {
		fail(errDenied, "identity provider returned an error", zap.String("error", idpErr))
		return
	}
	verifier, oauthCfg, ok := s.client()
	if !ok {
		fail(errUnavailable, "provider not discovered")
		return
	}
	token, err := oauthCfg.Exchange(oidc.ClientContext(ctx, s.httpClient), query.Get("code"), oauth2.VerifierOption(attempt.CodeVerifier))
	if err != nil {
		fail(errFailed, "code exchange failed", zap.Error(err))
		return
	}
	rawIDToken, _ := token.Extra("id_token").(string)
	if rawIDToken == "" {
		fail(errFailed, "token response had no id_token")
		return
	}
	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		fail(errFailed, "ID token verification failed", zap.Error(err))
		return
	}
	if subtle.ConstantTimeCompare([]byte(idToken.Nonce), []byte(attempt.Nonce)) != 1 {
		fail(errFailed, "ID token nonce mismatch")
		return
	}
	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		fail(errFailed, "unreadable ID token claims", zap.Error(err))
		return
	}
	identity, code := s.identityFrom(claims)
	if code != "" {
		fail(code, "no usable identity claim", zap.String("subject", idToken.Subject))
		return
	}
	role, ok := s.roleFrom(claims)
	if !ok {
		fail(errNoRole, "user is in no reviewer or admin group", zap.String("identity", identity))
		return
	}

	sessionToken := randomToken()
	if err := s.store.CreateSession(ctx, db.CreateSessionParams{
		IDHash: hashToken(sessionToken), Subject: idToken.Subject, Email: identity, Role: string(role),
		ExpiresAt: s.now().Add(s.cfg.SessionTTL),
	}); err != nil {
		s.logger.Error("failed to create session", zap.Error(err))
		fail(errSessionFailed, "session store unavailable")
		return
	}
	http.SetCookie(w, s.cookie(sessionToken, int(s.cfg.SessionTTL.Seconds())))
	s.logger.Info("SSO sign-in", zap.String("identity", identity), zap.String("role", string(role)))
	http.Redirect(w, r, attempt.ReturnTo, http.StatusFound)
}

func (s *Service) logout(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get(auth.CSRFHeader) != auth.CSRFHeaderValue {
		http.Error(w, `{"error": "cross-site request rejected"}`, http.StatusForbidden)
		return
	}
	if cookie, err := r.Cookie(s.cookieName()); err == nil && cookie.Value != "" {
		if err := s.store.RevokeSession(r.Context(), hashToken(cookie.Value)); err != nil {
			s.logger.Error("failed to revoke session", zap.Error(err))
			http.Error(w, `{"error": "sign-out failed, try again"}`, http.StatusServiceUnavailable)
			return
		}
	}
	http.SetCookie(w, s.cookie("", -1))
	w.WriteHeader(http.StatusNoContent)
}

// AuthenticateSession implements auth.SessionAuthenticator.
func (s *Service) AuthenticateSession(r *http.Request) (auth.Identity, bool) {
	cookie, err := r.Cookie(s.cookieName())
	if err != nil || cookie.Value == "" {
		return auth.Identity{}, false
	}
	idHash := hashToken(cookie.Value)
	now := s.now()
	row, err := s.store.GetActiveSession(r.Context(), db.GetActiveSessionParams{
		IDHash: idHash, LastSeenAt: now.Add(-s.cfg.SessionIdleTTL),
	})
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			s.logger.Error("failed to read session", zap.Error(err))
		}
		return auth.Identity{}, false
	}
	role := auth.Role(row.Role)
	if role != auth.RoleReviewer && role != auth.RoleAdmin {
		return auth.Identity{}, false
	}
	if now.Sub(row.LastSeenAt) > touchInterval {
		if err := s.store.TouchSession(r.Context(), idHash); err != nil {
			s.logger.Warn("failed to refresh session activity", zap.Error(err))
		}
	}
	return auth.Identity{ID: row.Email, Role: role}, true
}

// identityFrom returns the identity recorded for this user, or a failure
// code. The default "email" claim must be verified by the provider, or
// anyone able to set an unverified address could act as that person.
func (s *Service) identityFrom(claims map[string]any) (string, string) {
	value, _ := claims[s.cfg.IdentityClaim].(string)
	value = strings.TrimSpace(value)
	if value == "" {
		return "", errNoIdentity
	}
	if s.cfg.IdentityClaim == "email" {
		if verified, _ := claims["email_verified"].(bool); !verified {
			return "", errUnverified
		}
		value = strings.ToLower(value)
	}
	return value, ""
}

// roleFrom maps the user's groups to a role; admin wins over reviewer.
func (s *Service) roleFrom(claims map[string]any) (auth.Role, bool) {
	var groups []string
	switch v := claims[s.cfg.GroupsClaim].(type) {
	case string:
		groups = []string{v}
	case []any:
		for _, g := range v {
			if name, ok := g.(string); ok {
				groups = append(groups, name)
			}
		}
	}
	member := func(want []string) bool {
		for _, g := range groups {
			if slices.Contains(want, g) {
				return true
			}
		}
		return false
	}
	switch {
	case member(s.cfg.AdminGroups):
		return auth.RoleAdmin, true
	case member(s.cfg.ReviewerGroups):
		return auth.RoleReviewer, true
	}
	return "", false
}

// validReturnTo accepts only an exactly allowed console origin plus an
// optional path, so the sign-in flow cannot be used as an open redirect.
func (s *Service) validReturnTo(raw string) (string, bool) {
	if raw == "" {
		for _, origin := range s.allowedOrigins {
			if origin != "*" && origin != "" {
				return origin + "/", true
			}
		}
		return "", false
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
		return "", false
	}
	origin := u.Scheme + "://" + u.Host
	if !slices.Contains(s.allowedOrigins, origin) {
		return "", false
	}
	path := u.EscapedPath()
	if path == "" || !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") {
		path = "/"
	}
	return origin + path, true
}

func (s *Service) cookieName() string {
	if s.cfg.SecureCookies() {
		return secureCookieName
	}
	return devCookieName
}

func (s *Service) cookie(value string, maxAge int) *http.Cookie {
	sameSite := http.SameSiteLaxMode
	switch strings.ToLower(s.cfg.CookieSameSite) {
	case "strict":
		sameSite = http.SameSiteStrictMode
	case "none":
		sameSite = http.SameSiteNoneMode
	}
	return &http.Cookie{
		Name:     s.cookieName(),
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   s.cfg.SecureCookies(),
		SameSite: sameSite,
	}
}

func withQuery(raw, key, value string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	q := u.Query()
	q.Set(key, value)
	u.RawQuery = q.Encode()
	return u.String()
}

// randomToken returns 32 bytes of crypto randomness, base64url-encoded.
func randomToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b) // crypto/rand.Read does not fail on supported platforms
	return base64.RawURLEncoding.EncodeToString(b)
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
