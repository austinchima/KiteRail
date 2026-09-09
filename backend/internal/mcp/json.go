// Package mcp provides the request decoding and transport metadata shared by
// policy ingress and quarantined request replay.
package mcp

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"unicode/utf8"
)

// DecodeObject decodes exactly one JSON object without rounding numbers.
// Duplicate member names, including escaped aliases and nested members, are
// rejected because different JSON consumers could otherwise execute a different
// value from the one checked by policy. Callers must bound the body size first.
func DecodeObject(body []byte) (map[string]any, error) {
	if !utf8.Valid(body) || !json.Valid(body) {
		return nil, errors.New("body must contain one valid UTF-8 JSON value")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	value, err := decodeValue(decoder)
	if err != nil {
		return nil, err
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, errors.New("body must be a single JSON object; batching is not supported")
	}
	return object, nil
}

// decodeValue walks a syntax-checked JSON value so each object's member names
// can be checked before insertion. Decoder.Token preserves numbers as json.Number.
func decodeValue(decoder *json.Decoder) (any, error) {
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	switch token {
	case json.Delim('{'):
		object := make(map[string]any)
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return nil, err
			}
			key, ok := keyToken.(string)
			if !ok {
				return nil, errors.New("JSON object member name must be a string")
			}
			if _, exists := object[key]; exists {
				return nil, fmt.Errorf("duplicate JSON member %q", key)
			}
			value, err := decodeValue(decoder)
			if err != nil {
				return nil, err
			}
			object[key] = value
		}
		_, err := decoder.Token()
		return object, err
	case json.Delim('['):
		values := make([]any, 0)
		for decoder.More() {
			value, err := decodeValue(decoder)
			if err != nil {
				return nil, err
			}
			values = append(values, value)
		}
		_, err := decoder.Token()
		return values, err
	default:
		return token, nil
	}
}
