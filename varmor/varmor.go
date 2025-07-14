// Package varmor provides versioned armoring for arbitrary sequences of bytes.
//
// The armored form is free of whitespace (including newlines), safe to embed in URLs (other than possibly
// its length) and safe to pass unescaped in a POSIX shell.
package varmor

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

const (
	magicPrefix = "saltybox"
	v1Magic     = "saltybox1:"
)

// Wrap an array of bytes in armor, returning the resulting string.
func Wrap(body []byte) string {
	encoded := base64.RawURLEncoding.EncodeToString(body)

	return fmt.Sprintf("%s%s", v1Magic, encoded)
}

// Unwrap an armored string.
//
// Error conditions include:
//
//   - The input is provably truncated.
//   - Base64 decoding failure.
//   - Input indicates a future version of the format that we do not support.
//   - Input does not appear to be the result of Wrap().
func Unwrap(varmoredBody string) ([]byte, error) {
	if len(varmoredBody) < len(v1Magic) {
		return nil, errors.New("input size smaller than magic marker; likely truncated")
	}

	switch {
	case strings.HasPrefix(varmoredBody, v1Magic):
		armoredBody := strings.TrimPrefix(varmoredBody, v1Magic)
		body, err := base64.RawURLEncoding.DecodeString(armoredBody)
		if err != nil {
			return nil, fmt.Errorf("base64 decoding failed: %w", err)
		}
		return body, nil
	case strings.HasPrefix(varmoredBody, magicPrefix):
		return nil, errors.New("input claims to be saltybox, but not a version we support")
	default:
		return nil, errors.New("input unrecognized as saltybox data")
	}
}
