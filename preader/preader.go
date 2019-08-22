package preader

import (
	"bufio"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"golang.org/x/crypto/ssh/terminal"
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

type terminalPassphraseReader struct{}

func (r *terminalPassphraseReader) ReadPassphrase() (string, error) {
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