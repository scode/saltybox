package varmor

import (
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

func preserveString(t *testing.T, s string) {
	b, err := Unwrap(Wrap([]byte(s)))
	assert.NoError(t, err)
	assert.Equal(t, s, string(b))
}

func preserveBytes(t *testing.T, b []byte) {
	wrapped, err := Unwrap(Wrap(b))
	assert.NoError(t, err)
	assert.EqualValues(t, b, wrapped)
}

func TestPreservation(t *testing.T) {
	preserveString(t, "")
	preserveString(t, "test")

	rnd := rand.New(rand.NewSource(0))
	rbytes := make([]byte, 100000)
	n, err := rnd.Read(rbytes)
	assert.NoError(t, err)
	assert.Equal(t, 100000, n)
	preserveBytes(t, rbytes)
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

func TestNotSaltybox(t *testing.T) {
	b, err := Unwrap("something not looking like saltybox data")
	assert.Error(t, err)
	assert.Equal(t, "input unrecognized as saltybox data", err.Error())
	assert.Nil(t, b)
}

func TestAllByteValues(t *testing.T) {
	allBytes := make([]byte, 256)
	for i := 0; i <= 255; i++ {
		allBytes[i] = byte(i)
	}

	preserveBytes(t, allBytes)

	wrapped := Wrap(allBytes)
	assert.Equal(t,
		"saltybox1:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0-P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn-AgYKDhIWGh4iJiouMjY6PkJGSk5SVlpeYmZqbnJ2en6ChoqOkpaanqKmqq6ytrq-wsbKztLW2t7i5uru8vb6_wMHCw8TFxsfIycrLzM3Oz9DR0tPU1dbX2Nna29zd3t_g4eLj5OXm5-jp6uvs7e7v8PHy8_T19vf4-fr7_P3-_w",
		wrapped)
}

func TestUnwrapBadBase64(t *testing.T) {
	b, err := Unwrap("saltybox1:bad$$")
	assert.Error(t, err)
	assert.ErrorContains(t, err, "base64 decoding failed")
	assert.Nil(t, b)
}
