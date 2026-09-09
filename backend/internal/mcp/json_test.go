package mcp

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecodeObjectRejectsDuplicateMembersAtEveryDepth(t *testing.T) {
	for _, body := range [][]byte{
		[]byte(`{"method":"tools/call","method":"tools/list"}`),
		[]byte(`{"params":{"name":"a","name":"b"}}`),
	} {
		_, err := DecodeObject(body)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "duplicate JSON member")
	}
}

func TestDecodeObjectPreservesLargeNumbers(t *testing.T) {
	object, err := DecodeObject([]byte(`{"id":9007199254740993}`))
	require.NoError(t, err)
	assert.Equal(t, "9007199254740993", object["id"].(interface{ String() string }).String())
}

func TestDecodeReplayHeadersFiltersCredentials(t *testing.T) {
	headers, err := DecodeReplayHeaders([]byte(`{
		"Mcp-Method":["tools/call"],
		"Mcp-Param-Tenant":["blue"],
		"Authorization":["Bearer attacker"],
		"Cookie":["session=attacker"]
	}`))
	require.NoError(t, err)
	assert.Equal(t, "tools/call", headers.Get("Mcp-Method"))
	assert.Equal(t, "blue", headers.Get("Mcp-Param-Tenant"))
	assert.Empty(t, headers.Get("Authorization"))
	assert.Empty(t, headers.Get("Cookie"))
	assert.IsType(t, http.Header{}, headers)
}
