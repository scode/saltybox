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
	_MAGIC_PREFIX = "saltybox"
	_V1_MAGIC     = "saltybox1:"
)

// Wrap an array of bytes in armor, returning the resulting string.
func Wrap(body []byte) string {
	encoded := base64.RawURLEncoding.EncodeToString(body)

	return fmt.Sprintf("%s%s", _V1_MAGIC, encoded)
}

// Unwrap an armored string.
//
// Errors conditions include:
//
//   * The input is provably truncated.
//   * Base64 decoding failure.
//   * Input indicates a future version of of the format that we do not support.
//   * Input does not appear to be the the result of Wrap().
func Unwrap(varmoredBody string) ([]byte, error) {
	if len(varmoredBody) < len(_V1_MAGIC) {
		return nil, errors.New("input size smaller than magic marker; likely truncated")
	}

	if strings.HasPrefix(varmoredBody, _V1_MAGIC) {
		armoredBody := strings.TrimPrefix(varmoredBody, _V1_MAGIC)
		body, err := base64.RawURLEncoding.DecodeString(armoredBody)
		if err != nil {
			return nil, fmt.Errorf("base64 decoding failed: %s", err)
		}

		return body, nil
	} else if strings.HasPrefix(varmoredBody, _MAGIC_PREFIX) {
		return nil, errors.New("input claims to be saltybox, but not a version we support")
	} else {
		return nil, errors.New("input unrecognized as saltybox data")
	}
}
