package preader

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestReaderReaderSuccess(t *testing.T) {
	r := NewReader(strings.NewReader("passphrase"))

	pf, err := r.ReadPassphrase()
	assert.NoError(t, err)
	assert.Equal(t, "passphrase", pf)
}

type erroringReader struct{}

func (r *erroringReader) Read(p []byte) (n int, err error) {
	return 0, errors.New("mock reader error")
}

func TestReaderReaderError(t *testing.T) {
	r := NewReader(&erroringReader{})

	pf, err := r.ReadPassphrase()
	assert.Error(t, err)
	assert.Equal(t, "", pf)
}

func TestReaderReaderEmpty(t *testing.T) {
	r := NewReader(strings.NewReader(""))

	pf, err := r.ReadPassphrase()
	assert.NoError(t, err)
	assert.Equal(t, "", pf)
}

type mockPassphraseReader struct {
	constantPassphrase string
	callCount          int
}

func (r *mockPassphraseReader) ReadPassphrase() (string, error) {
	r.callCount++
	return r.constantPassphrase, nil
}

func TestCachingPassphraseReader_ReadPassphrase(t *testing.T) {
	upstream := mockPassphraseReader{constantPassphrase: "phrase"}
	caching := NewCaching(&upstream)

	// The first read should penetrate the cache.
	phrase, err := caching.ReadPassphrase()
	assert.NoError(t, err)
	assert.Equal(t, "phrase", phrase)
	assert.Equal(t, 1, upstream.callCount)

	// But the second read should not (so callCount should remain the same).
	phrase, err = caching.ReadPassphrase()
	assert.NoError(t, err)
	assert.Equal(t, "phrase", phrase)
	assert.Equal(t, 1, upstream.callCount)
}
