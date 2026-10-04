package policystore

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"go.uber.org/zap"

	"github.com/austinchima/kiterail/internal/auth"
	"github.com/austinchima/kiterail/internal/opaengine"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReload_AdminOnlyAndRejectsBrokenBundle(t *testing.T) {
	ctx := context.Background()
	dir := simulatePolicyDir(t)
	store, err := New(dir)
	require.NoError(t, err)
	engine, err := opaengine.New(ctx, dir, zap.NewNop())
	require.NoError(t, err)
	handler := NewHandler(store, engine, zap.NewNop())
	before := engine.Version()

	reload := func(role auth.Role) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/reload", nil)
		req = req.WithContext(auth.WithIdentity(req.Context(), auth.Identity{ID: "someone", Role: role}))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}

	assert.Equal(t, http.StatusForbidden, reload(auth.RoleReviewer).Code)

	rec := reload(auth.RoleAdmin)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, before, body["policy_version"])

	require.NoError(t, os.WriteFile(filepath.Join(dir, "broken.rego"), []byte("package elodea.authz\nnot rego"), 0o644))
	rec = reload(auth.RoleAdmin)
	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)
	assert.Equal(t, before, engine.Version(), "a rejected bundle must not replace the active policy")
}
