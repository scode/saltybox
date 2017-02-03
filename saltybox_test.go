package main

import (
	"bytes"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

func panicOnError(e error) {
	if e != nil {
		panic(e)
	}
}

func TestEncryptDecrypt(t *testing.T) {
	tempdir, err := ioutil.TempDir(os.TempDir(), "saltyboxtest")
	if err != nil {
		t.Fatalf("failed creating temp dir: %s", err)
	}
	defer panicOnError(os.Remove(tempdir))

	plainPath := filepath.Join(tempdir, "plain")
	err = ioutil.WriteFile(plainPath, []byte("super secret"), 0777)
	if err != nil {
		t.Fatalf("failed to write to %s: %s", plainPath, err)
	}
	defer panicOnError(os.Remove(plainPath))

	encryptedPath := filepath.Join(tempdir, "encrypted")
	defer panicOnError(os.Remove(encryptedPath))

	panicOnError(passphraseEncryptFile(plainPath, encryptedPath, constantPassphraseReader{constantPassphrase: "test"}))

	newPlainPath := filepath.Join(tempdir, "newplain")
	defer panicOnError(os.Remove(newPlainPath))

	panicOnError(passphraseDecryptFile(encryptedPath, newPlainPath, constantPassphraseReader{constantPassphrase: "test"}))

	newPlainText, err := ioutil.ReadFile(newPlainPath)
	if err != nil {
		t.Fatalf("failed to read from %s: %s", newPlainPath, err)
	}

	if !bytes.Equal(newPlainText, []byte("super secret")) {
		t.Fatal("plain text does not match original plain text")
	}
}
