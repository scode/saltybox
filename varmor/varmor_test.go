package varmor

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func preserve(t *testing.T, s string) {
	b, err := Unwrap(Wrap([]byte(s)))
	assert.NoError(t, err)
	assert.Equal(t, s, string(b))
}

func TestPreservation(t *testing.T) {
	preserve(t, "")
	preserve(t, "test")
}

func TestTruncated(t *testing.T) {
	b, err := Unwrap("")
	assert.Error(t, err)
	assert.Nil(t, b)
}

func TestWrongVersion(t *testing.T) {
	b, err := Unwrap("saltybox999999:...")
	assert.Error(t, err)
	assert.Equal(t, "input claims to be saltybox, but not a version we support", err.Error())
	assert.Nil(t, b)
}
