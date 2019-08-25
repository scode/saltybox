package main

import (
	"testing"

	"github.com/scode/saltybox/preader"

	"github.com/stretchr/testify/assert"
)

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
	caching := preader.NewCaching(&upstream)

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

