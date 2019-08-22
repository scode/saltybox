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
