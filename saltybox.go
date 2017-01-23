package main

import (
	"fmt"
	"github.com/scode/saltybox/secretcrypt"
	"github.com/scode/saltybox/varmor"
	"golang.org/x/crypto/ssh/terminal"
	"io/ioutil"
	"os"
)

type passphraseReader interface {
	ReadPassphrase() string
}

type stdinPassphraseReader struct{}

type constantPassphraseReader struct {
	constantPassphrase string
}

func (r stdinPassphraseReader) ReadPassphrase() string {
	fmt.Fprint(os.Stderr, "Passphrase (saltybox): ")
	phrase, err := terminal.ReadPassword(0)
	if err != nil {
		panic(fmt.Sprintf("failure reading passphrase: %s", err))
	}

	return string(phrase)
}

func (r constantPassphraseReader) ReadPassphrase() string {
	return r.constantPassphrase
}

func passphraseEncryptFile(inpath string, outpath string, preader passphraseReader) error {
	plaintext, err := ioutil.ReadFile(inpath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "failed to read from %s: %s", inpath, err)
		return err
	}

	passphrase := preader.ReadPassphrase()
	cipherBytes, err := secretcrypt.Encrypt(passphrase, plaintext)
	if err != nil {
		fmt.Fprintln(os.Stderr, "encryption failed: %s", err)
		return err
	}

	varmoredBytes := varmor.Wrap(cipherBytes)
	err = ioutil.WriteFile(outpath, []byte(varmoredBytes), 0700)
	if err != nil {
		fmt.Fprintln(os.Stderr, "failed to write to %s: %s", outpath, err)
		return err
	}

	return nil
}

func passphraseDecryptFile(inpath string, outpath string, preader passphraseReader) error {
	varmoredBytes, err := ioutil.ReadFile(inpath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "failed to read from %s: %s", inpath, err)
		return err
	}

	cipherBytes, err := varmor.Unwrap(string(varmoredBytes))
	if err != nil {
		fmt.Fprintln(os.Stderr, "failed to unarmor: %s", err)
		return err
	}

	passphrase := preader.ReadPassphrase()
	plaintext, err := secretcrypt.Decrypt(passphrase, cipherBytes)
	if err != nil {
		fmt.Fprintln(os.Stderr, "failed to decrypt: %s", err)
		return err
	}

	err = ioutil.WriteFile(outpath, plaintext, 0700)
	if err != nil {
		fmt.Fprintln(os.Stderr, "failed to write to %s: %s", outpath, err)
		return err
	}

	return nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage: %s <command> [-help]")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Commands:")
		fmt.Fprintln(os.Stderr, "   passphrase-encrypt-file <inpath> <outpath> - encrypt file using passphrase")
		fmt.Fprintln(os.Stderr, "   passphrase-decrypt-file <inpath> <outpath> - decrypt file using passphrase")
		os.Exit(1)
	}

	if os.Args[1] == "passphrase-encrypt-file" {
		err := passphraseEncryptFile(os.Args[2], os.Args[3], stdinPassphraseReader{})
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	} else if os.Args[1] == "passphrase-decrypt-file" {
		err := passphraseDecryptFile(os.Args[2], os.Args[3], stdinPassphraseReader{})
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	} else {
		fmt.Fprintln(os.Stderr, "unrecognized command")
		os.Exit(1)
	}
}
