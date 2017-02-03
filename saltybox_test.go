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
	defer func(tempdir string) {
		panicOnError(os.Remove(tempdir))

	}(tempdir)

	plainPath := filepath.Join(tempdir, "plain")
	err = ioutil.WriteFile(plainPath, []byte("super secret"), 0777)
	if err != nil {
		t.Fatalf("failed to write to %s: %s", plainPath, err)
	}
	defer func(plainPath string) {
		panicOnError(os.Remove(plainPath))
	}(plainPath)

	encryptedPath := filepath.Join(tempdir, "encrypted")
	defer func(encryptedPath string) {
		panicOnError(os.Remove(encryptedPath))
	}(encryptedPath)

	panicOnError(passphraseEncryptFile(plainPath, encryptedPath, constantPassphraseReader{constantPassphrase: "test"}))

	newPlainPath := filepath.Join(tempdir, "newplain")
	defer func(newPlainPath string) {
		panicOnError(os.Remove(newPlainPath))
	}(newPlainPath)

	panicOnError(passphraseDecryptFile(encryptedPath, newPlainPath, constantPassphraseReader{constantPassphrase: "test"}))

	newPlainText, err := ioutil.ReadFile(newPlainPath)
	if err != nil {
		t.Fatalf("failed to read from %s: %s", newPlainPath, err)
	}

	if !bytes.Equal(newPlainText, []byte("super secret")) {
		t.Fatal("plain text does not match original plain text")
	}
}
