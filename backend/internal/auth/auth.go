// Package auth implements role-based authentication for KiteRail.
//
// Three trust domains exist and MUST NOT share credentials:
//
//   - agents:    machine clients calling the proxy with tool invocations
//   - reviewers: humans approving quarantined actions, reading the ledger
//   - admins:    policy mutation (read-only policies in v1.0 MVP)
package auth

import (
	"context"
	"crypto/subtle"
	"net/http"

	"go.uber.org/zap"
)

type Role string

const (
	RoleAgent    Role = "agent"
	RoleReviewer Role = "reviewer"
	RoleAdmin    Role = "admin"
)

type Identity struct {
	ID   string
	Role Role
}

type contextKey string

const identityContextKey contextKey = "kiterail_identity"

// FromContext returns the authenticated identity, if any.
func FromContext(ctx context.Context) (Identity, bool) {
	v, ok := ctx.Value(identityContextKey).(Identity)
	return v, ok
}

// WithIdentity attaches an identity to a context. Primarily for tests and
// trusted internal wiring — the HTTP path sets it via Middleware only.
func WithIdentity(ctx context.Context, id Identity) context.Context {
	return context.WithValue(ctx, identityContextKey, id)
}

// AgentFromContext returns the authenticated agent ID, or "unknown".
func AgentFromContext(ctx context.Context) string {
	if id, ok := FromContext(ctx); ok {
		return id.ID
	}
	return "unknown"
}

// lookupIdentity finds the identity for a presented token without leaking
// timing information about which configured token it does or doesn't match.
// A plain map lookup hashes-then-buckets the key, which already avoids a
// naive byte-by-byte prefix comparison — but it's still input-dependent
// (bucket chain length, hash collisions) in ways that are cheap to close off
// entirely. This is O(n) in the number of configured identities, which is
// the right trade-off for the tens-to-low-hundreds of API keys KiteRail
// expects; it is NOT the right approach once you're validating against
// thousands of keys; at that scale switch to HMAC-derived tokens you can
// verify without a lookup table at all.
func lookupIdentity(identities map[string]Identity, token string) (Identity, bool) {
	tokenBytes := []byte(token)
	var found Identity
	var ok bool
	for candidate, identity := range identities {
		if subtle.ConstantTimeCompare([]byte(candidate), tokenBytes) == 1 {
			found = identity
			ok = true
			// Deliberately no early return: bailing out as soon as we find a
			// match reintroduces a timing signal (fast match vs. scanning the
			// whole map on a miss). Keep iterating every candidate so a hit
			// and a miss take the same number of comparisons.
		}
	}
	return found, ok
}

// Middleware authenticates requests using a token → Identity map.
// Tokens are accepted ONLY via the Authorization: Bearer header —
// never query parameters, which leak into logs, referrers and proxies.
func Middleware(identities map[string]Identity, logger *zap.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		const prefix = "Bearer "
		if len(authHeader) < len(prefix) || authHeader[:len(prefix)] != prefix {
			w.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(w, `{"error": "missing or malformed Authorization header, expected Bearer token"}`, http.StatusUnauthorized)
			return
		}
		token := authHeader[len(prefix):]

		identity, ok := lookupIdentity(identities, token)
		if !ok {
			logger.Warn("rejected unauthorized request",
				zap.String("token_prefix", token[:min(8, len(token))]),
				zap.String("path", r.URL.Path),
			)
			http.Error(w, `{"error": "invalid API key"}`, http.StatusForbidden)
			return
		}

		ctx := context.WithValue(r.Context(), identityContextKey, identity)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireRole wraps a handler so it only accepts identities holding one of
// the given roles. Agents hitting reviewer/admin routes get 403.
func RequireRole(roles ...Role) func(http.Handler) http.Handler {
	allowed := make(map[Role]bool, len(roles))
	for _, r := range roles {
		allowed[r] = true
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			identity, ok := FromContext(r.Context())
			if !ok || !allowed[identity.Role] {
				http.Error(w, `{"error": "insufficient role"}`, http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// ReviewerOrAdmin is the common guard for human-facing routes.
func ReviewerOrAdmin() func(http.Handler) http.Handler {
	return RequireRole(RoleReviewer, RoleAdmin)
}
