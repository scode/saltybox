package main

import (
	"bufio"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path"

	"github.com/urfave/cli"

	"github.com/scode/saltybox/secretcrypt"
	"github.com/scode/saltybox/varmor"
	"golang.org/x/crypto/ssh/terminal"
)

type passphraseReader interface {
	ReadPassphrase() (string, error)
}

type stdinPassphraseReader struct{}

// cachingPassphraseReader will wrap a passphraseReader by adding caching.
//
// This is useful to allow "at most once" semantics when reading the passphrase, while
// still lazily deferring the first invocation.
type cachingPassphraseReader struct {
	Upstream         passphraseReader
	cachedPassphrase string
	cached           bool
}

func (r *stdinPassphraseReader) ReadPassphrase() (string, error) {
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

func passphraseEncrypt(passphrase string, plaintext []byte) (string, error) {
	cipherBytes, err := secretcrypt.Encrypt(passphrase, plaintext)
	if err != nil {
		return "", fmt.Errorf("encryption failed: %s", err)
	}

	varmoredBytes := varmor.Wrap(cipherBytes)

	return string(varmoredBytes), nil
}

func passphraseEncryptFile(inpath string, outpath string, preader passphraseReader) error {
	plaintext, err := ioutil.ReadFile(inpath)
	if err != nil {
		return fmt.Errorf("failed to read from %s: %s", inpath, err)
	}

	passphrase, err := preader.ReadPassphrase()
	if err != nil {
		return err
	}
	encryptedString, err := passphraseEncrypt(passphrase, plaintext)
	if err != nil {
		return fmt.Errorf("encryption failed: %s", err)
	}

	err = ioutil.WriteFile(outpath, []byte(encryptedString), 0700)
	if err != nil {
		return fmt.Errorf("failed to write to %s: %s", outpath, err)
	}

	return nil
}

func passphraseDecrypt(passphrase string, encryptedString string) ([]byte, error) {
	cipherBytes, err := varmor.Unwrap(encryptedString)
	if err != nil {
		return nil, fmt.Errorf("failed to unarmor: %s", err)
	}

	plaintext, err := secretcrypt.Decrypt(passphrase, cipherBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %s", err)
	}

	return plaintext, nil
}

func passphraseDecryptFile(inpath string, outpath string, preader passphraseReader) error {
	varmoredBytes, err := ioutil.ReadFile(inpath)
	if err != nil {
		return fmt.Errorf("failed to read from %s: %s", inpath, err)
	}

	passphrase, err := preader.ReadPassphrase()
	if err != nil {
		return err
	}
	plaintext, err := passphraseDecrypt(passphrase, string(varmoredBytes))
	if err != nil {
		return fmt.Errorf("failed to decrypt: %s", err)
	}

	err = ioutil.WriteFile(outpath, plaintext, 0700)
	if err != nil {
		return fmt.Errorf("failed to write to %s: %s", outpath, err)
	}

	return nil
}

func passphraseUpdateFile(plainfile string, cryptfile string, preader passphraseReader) (err error) {
	// Decrypt existing file in order to validate that the provided passphrase is correct,
	// in order to prevent accidental changing of the passphrase (but we discard the plain
	// text).
	varmoredBytes, err := ioutil.ReadFile(cryptfile)
	if err != nil {
		return fmt.Errorf("failed to read from %s: %s", cryptfile, err)
	}

	cachingPreader := cachingPassphraseReader{Upstream: preader}

	passphrase, err := cachingPreader.ReadPassphrase()
	if err != nil {
		return err
	}
	_, err = passphraseDecrypt(passphrase, string(varmoredBytes))
	if err != nil {
		return fmt.Errorf("failed to decrypt: %s", err)
	}

	// Encrypt contents into the target file using atomic semantics (write to tempfile, fsync()
	// and rename). This guarantees that the resulting file will either be the old file or the new
	// file, but never corrupt (assuming a correctly functioning filesystem I/O stack).
	cryptDir, _ := path.Split(cryptfile)

	tmpfile, err := ioutil.TempFile(cryptDir, "saltybox-update-tmp")
	if err != nil {
		return fmt.Errorf("failed to create tempfile: %s", err)
	}
	defer func(fname string) {
		if _, localErr := os.Stat(fname); !os.IsNotExist(localErr) {
			err = os.Remove(fname)
		}
	}(tmpfile.Name())
	defer func(tmpfile *os.File) {
		err = tmpfile.Close()
	}(tmpfile)

	err = passphraseEncryptFile(plainfile, tmpfile.Name(), &cachingPreader)
	if err != nil {
		return fmt.Errorf("failed to encrypt: %s", err)
	}

	// Re-open the file to ensure that we are Sync():ing the correct file. Technically this is not
	// required because passphraseEncryptFile() will cause the target file to be truncated rather than recreated.
	// However, let's defensively avoid relying on that subtle behavior and re-open the file.
	reopenedTmpFile, err := os.Open(tmpfile.Name())
	if err != nil {
		return fmt.Errorf("failed to re-open tempfile after encryption: %s", err)
	}
	defer func(f *os.File) {
		err = f.Close()
	}(reopenedTmpFile)

	err = reopenedTmpFile.Sync()
	if err != nil {
		return fmt.Errorf("failed to sync file prior to rename: %s", err)
	}

	err = os.Rename(reopenedTmpFile.Name(), cryptfile)
	if err != nil {
		return fmt.Errorf("failed to rename to target file: %s", err)
	}

	return nil
}

func main() {
	app := cli.NewApp()
	app.Name = "saltybox"
	app.Version = "master"
	app.Usage = "an encryption tool"

	var inputArg string
	var outputArg string

	app.Commands = []cli.Command{
		{
			Name:    "encrypt",
			Aliases: []string{"e"},
			Usage:   "encrypt a file",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:        "input, i",
					Usage:       "path to the file whose contents is to be encrypted",
					Required:    true,
					Destination: &inputArg,
				},
				cli.StringFlag{
					Name:        "output, o",
					Usage:       "path to the file to write the encrypted text to",
					Required:    true,
					Destination: &outputArg,
				},
			},
			Action: func(c *cli.Context) error {
				return passphraseEncryptFile(inputArg, outputArg, &stdinPassphraseReader{})
			},
		},
		{
			Name:    "decrypt",
			Aliases: []string{"e"},
			Usage:   "decrypt a file",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:        "input, i",
					Usage:       "path to the file whose contents is to be decrypted",
					Required:    true,
					Destination: &inputArg,
				},
				cli.StringFlag{
					Name:        "output, o",
					Usage:       "path to the file to write the unencrypted text to",
					Required:    true,
					Destination: &outputArg,
				},
			},
			Action: func(c *cli.Context) error {
				return passphraseDecryptFile(inputArg, outputArg, &stdinPassphraseReader{})
			},
		},
		{
			Name:    "update",
			Aliases: []string{"e"},
			Usage:   "update an encrypted file with new encrypted content",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:        "input, i",
					Usage:       "path to the file whose contents is to be encrypted",
					Required:    true,
					Destination: &inputArg,
				},
				cli.StringFlag{
					Name:        "output, o",
					Usage:       "path to the existing saltybox file to replace with encrypted text",
					Required:    true,
					Destination: &outputArg,
				},
			},
			Action: func(c *cli.Context) error {
				return passphraseUpdateFile(inputArg, outputArg, &stdinPassphraseReader{})
			},
		},
	}

	app.Action = func(c *cli.Context) error {
		return errors.New("command is required; use help to see list of commands")
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
