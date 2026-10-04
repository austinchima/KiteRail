package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/austinchima/elodea/internal/auth"
)

const testSessionCookie = "elodea_session"

// fakeSSO accepts one session cookie value as reviewer "priya@corp.test".
type fakeSSO struct{}

func (fakeSSO) AuthenticateSession(r *http.Request) (auth.Identity, bool) {
	if c, err := r.Cookie(testSessionCookie); err == nil && c.Value == "valid-session" {
		return auth.Identity{ID: "priya@corp.test", Role: auth.RoleReviewer}, true
	}
	return auth.Identity{}, false
}

func (fakeSSO) Routes() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusTeapot) })
}

func (fakeSSO) ConfigHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{"sso":true}`)) })
}

func newSSOFixture(t *testing.T) *fixture {
	return newFixtureWith(t, 1000, 1000, func(d *httpDeps) {
		d.sso = fakeSSO{}
		d.allowedOrigins = []string{"https://console.corp.test"}
	})
}

func withSession(req *http.Request) *http.Request {
	req.AddCookie(&http.Cookie{Name: testSessionCookie, Value: "valid-session"})
	return req
}

func TestSSO_SessionAuthenticatesHumanRoutes(t *testing.T) {
	f := newSSOFixture(t)
	rr := httptest.NewRecorder()
	f.handler.ServeHTTP(rr, withSession(httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)))
	require.Equal(t, http.StatusOK, rr.Code)
	assert.JSONEq(t, `{"id":"priya@corp.test","role":"reviewer"}`, rr.Body.String())

	rr = httptest.NewRecorder()
	f.handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/v1/me", nil))
	assert.Equal(t, http.StatusUnauthorized, rr.Code, "no cookie, no bearer")
}

func TestSSO_SessionMutationsRequireCSRFHeader(t *testing.T) {
	f := newSSOFixture(t)

	rr := httptest.NewRecorder()
	f.handler.ServeHTTP(rr, withSession(httptest.NewRequest(http.MethodPost, "/api/v1/quarantine/1042/approve", nil)))
	assert.Equal(t, http.StatusForbidden, rr.Code, "a forged cross-site form post carries the cookie but not the header")

	req := withSession(httptest.NewRequest(http.MethodPost, "/api/v1/quarantine/1042/approve", nil))
	req.Header.Set(auth.CSRFHeader, auth.CSRFHeaderValue)
	req.Header.Set("Origin", "https://evil.test")
	rr = httptest.NewRecorder()
	f.handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusForbidden, rr.Code, "CORS rejects an unlisted origin before auth")

	req = withSession(httptest.NewRequest(http.MethodPost, "/api/v1/quarantine/1042/approve", nil))
	req.Header.Set(auth.CSRFHeader, auth.CSRFHeaderValue)
	req.Header.Set("Origin", "https://console.corp.test")
	rr = httptest.NewRecorder()
	f.handler.ServeHTTP(rr, req)
	assert.NotEqual(t, http.StatusForbidden, rr.Code)
	assert.NotEqual(t, http.StatusUnauthorized, rr.Code)
}

func TestSSO_AgentRouteNeverAcceptsSessions(t *testing.T) {
	f := newSSOFixture(t)
	req := withSession(httptest.NewRequest(http.MethodPost, "/", nil))
	req.Header.Set(auth.CSRFHeader, auth.CSRFHeaderValue)
	rr := httptest.NewRecorder()
	f.handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Zero(t, f.hits.Load(), "nothing reaches the upstream")
}

func TestSSO_BearerStillWinsAndInvalidBearerDoesNotFallBack(t *testing.T) {
	f := newSSOFixture(t)
	req := withSession(httptest.NewRequest(http.MethodGet, "/api/v1/me", nil))
	req.Header.Set("Authorization", "Bearer not-a-real-token")
	rr := httptest.NewRecorder()
	f.handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusForbidden, rr.Code, "a bad bearer token is rejected, not silently replaced by the cookie")

	rr = doReq(t, f.handler, http.MethodGet, "/api/v1/me", testAdminTok, nil, nil)
	assert.Contains(t, rr.Body.String(), `"role":"admin"`)
}

func TestSSO_RoutesAndConfigAreMounted(t *testing.T) {
	f := newSSOFixture(t)
	rr := doReq(t, f.handler, http.MethodGet, "/auth/login", "", nil, nil)
	assert.Equal(t, http.StatusTeapot, rr.Code)
	rr = doReq(t, f.handler, http.MethodGet, "/api/v1/auth/config", "", nil, nil)
	assert.JSONEq(t, `{"sso":true}`, rr.Body.String())

	plain := newFixture(t, 1000, 1000)
	rr = doReq(t, plain.handler, http.MethodGet, "/api/v1/auth/config", "", nil, nil)
	assert.JSONEq(t, `{"sso":false}`, rr.Body.String())
}

func TestCORS_CredentialsOnlyForExplicitOrigins(t *testing.T) {
	handler := corsMiddleware([]string{"https://console.corp.test", "*"})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	req := httptest.NewRequest(http.MethodOptions, "/", nil)
	req.Header.Set("Origin", "https://console.corp.test")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(t, "true", rr.Header().Get("Access-Control-Allow-Credentials"))
	assert.Contains(t, rr.Header().Get("Access-Control-Allow-Headers"), auth.CSRFHeader)

	req = httptest.NewRequest(http.MethodOptions, "/", nil)
	req.Header.Set("Origin", "https://anything.test")
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Empty(t, rr.Header().Get("Access-Control-Allow-Credentials"), "the wildcard never admits credentials")
}
