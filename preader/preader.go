package preader

import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"golang.org/x/term"
)

type PassphraseReader interface {
	ReadPassphrase() (string, error)
}

func NewTerminal() PassphraseReader {
	return &terminalPassphraseReader{}
}

func NewCaching(upstream PassphraseReader) PassphraseReader {
	return &cachingPassphraseReader{Upstream: upstream}
}

func NewReader(reader io.Reader) PassphraseReader {
	return &readerPassphraseReader{reader: reader}
}

func NewConstant(passphrase string) PassphraseReader {
	return &constantPassphraseReader{passphrase: passphrase}
}

type constantPassphraseReader struct {
	passphrase string
}

func (r *constantPassphraseReader) ReadPassphrase() (string, error) {
	return r.passphrase, nil
}

type terminalPassphraseReader struct{}

func (r *terminalPassphraseReader) ReadPassphrase() (string, error) {
	if !term.IsTerminal(0) {
		return "", errors.New("cannot read passphrase from terminal - stdin is not a terminal")
	}

	_, err := fmt.Fprint(os.Stderr, "Passphrase (saltybox): ")
	if err != nil {
		return "", err
	}
	phrase, err := term.ReadPassword(0)
	if err != nil {
		return "", fmt.Errorf("failure reading passphrase: %s", err)
	}

	return string(phrase), nil
}

// cachingPassphraseReader will wrap a PassphraseReader by adding caching.
//
// This is useful to allow "at most once" semantics when reading the passphrase, while
// still lazily deferring the first invocation.
type cachingPassphraseReader struct {
	Upstream         PassphraseReader
	cachedPassphrase string
	cached           bool
}

func (r *cachingPassphraseReader) ReadPassphrase() (string, error) {
	if !r.cached {
		cached, err := r.Upstream.ReadPassphrase()
		if err != nil {
			return "", err
		}
		r.cachedPassphrase = cached
		r.cached = true
	}

	return r.cachedPassphrase, nil
}

type readerPassphraseReader struct {
	reader io.Reader
}

func (r *readerPassphraseReader) ReadPassphrase() (string, error) {
	data, err := ioutil.ReadAll(r.reader)
	if err != nil {
		return "", fmt.Errorf("error reading passphrase: %v", err)
	}

	return string(data), nil
}
