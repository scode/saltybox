package preader

import (
	"bufio"
	"fmt"
	"golang.org/x/crypto/ssh/terminal"
	"io/ioutil"
	"os"
)

type PassphraseReader interface {
	ReadPassphrase() (string, error)
}

type StdinPassphraseReader struct{}

// CachingPassphraseReader will wrap a PassphraseReader by adding caching.
//
// This is useful to allow "at most once" semantics when reading the passphrase, while
// still lazily deferring the first invocation.
type CachingPassphraseReader struct {
	Upstream         PassphraseReader
	cachedPassphrase string
	cached           bool
}

func (r *StdinPassphraseReader) ReadPassphrase() (string, error) {
	if terminal.IsTerminal(0) {
		_, err := fmt.Fprint(os.Stderr, "Passphrase (saltybox): ")
		if err != nil {
			return "", err
		}
		phrase, err := terminal.ReadPassword(0)
		if err != nil {
			return "", fmt.Errorf("failure reading passphrase: %s", err)
		}

		return string(phrase), nil
	}

	// Undocumented support for reading passphrase from stdin. It's undocumented because we should switch to
	// real command line handling and only enable this if asked rather than just because stdin isn't a terminal.
	// In the mean time, this enables better testing in travis.
	data, err := ioutil.ReadAll(bufio.NewReader(os.Stdin))
	if err != nil {
		return "", fmt.Errorf("failure reading passphrase from stdin: %s", err)
	}

	return string(data), nil
}

func (r *CachingPassphraseReader) ReadPassphrase() (string, error) {
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

