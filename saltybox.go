package main

import (
	"fmt"
	"github.com/scode/saltybox/secretcrypt"
	"github.com/scode/saltybox/varmor"
	"golang.org/x/crypto/ssh/terminal"
	"io/ioutil"
	"log"
	"os"
)

type passphraseReader interface {
	ReadPassphrase() string
}

type stdinPassphraseReader struct{}

func (r stdinPassphraseReader) ReadPassphrase() string {
	fmt.Fprint(os.Stderr, "Passphrase (saltybox): ")
	phrase, err := terminal.ReadPassword(0)
	if err != nil {
		panic(fmt.Sprintf("failure reading passphrase: %s", err))
	}

	return string(phrase)
}

func passphraseEncryptFile(inpath string, outpath string, preader passphraseReader) error {
	plaintext, err := ioutil.ReadFile(inpath)
	if err != nil {
		return fmt.Errorf("failed to read from %s: %s", inpath, err)
	}

	passphrase := preader.ReadPassphrase()
	cipherBytes, err := secretcrypt.Encrypt(passphrase, plaintext)
	if err != nil {
		return fmt.Errorf("encryption failed: %s", err)
	}

	varmoredBytes := varmor.Wrap(cipherBytes)
	err = ioutil.WriteFile(outpath, []byte(varmoredBytes), 0700)
	if err != nil {
		return fmt.Errorf("failed to write to %s: %s", outpath, err)
	}

	return nil
}

func passphraseDecryptFile(inpath string, outpath string, preader passphraseReader) error {
	varmoredBytes, err := ioutil.ReadFile(inpath)
	if err != nil {
		return fmt.Errorf("failed to read from %s: %s", inpath, err)
	}

	cipherBytes, err := varmor.Unwrap(string(varmoredBytes))
	if err != nil {
		return fmt.Errorf("failed to unarmor: %s", err)
	}

	passphrase := preader.ReadPassphrase()
	plaintext, err := secretcrypt.Decrypt(passphrase, cipherBytes)
	if err != nil {
		return fmt.Errorf("failed to decrypt: %s", err)
	}

	err = ioutil.WriteFile(outpath, plaintext, 0700)
	if err != nil {
		return fmt.Errorf("failed to write to %s: %s", outpath, err)
	}

	return nil
}

func main() {
	log.SetFlags(0)
	if len(os.Args) < 2 {
		log.Printf("Usage: %s <command> [-help]", os.Args[0])
		log.Print("")
		log.Print("Commands:")
		log.Print("   passphrase-encrypt-file <inpath> <outpath> - encrypt file using passphrase")
		log.Print("   passphrase-decrypt-file <inpath> <outpath> - decrypt file using passphrase")
		os.Exit(1)
	}

	if os.Args[1] == "passphrase-encrypt-file" {
		err := passphraseEncryptFile(os.Args[2], os.Args[3], stdinPassphraseReader{})
		if err != nil {
			log.Fatal(err)
		}
	} else if os.Args[1] == "passphrase-decrypt-file" {
		err := passphraseDecryptFile(os.Args[2], os.Args[3], stdinPassphraseReader{})
		if err != nil {
			log.Fatal(err)
		}
	} else {
		log.Fatal("unrecognized command")
	}
}
