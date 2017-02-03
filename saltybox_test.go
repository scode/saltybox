package main

import (
	"bytes"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"testing"
)

func checkedRemove(fname string) {
	err := os.Remove(fname)
	if err != nil {
		log.Panicf("removal of file %s failed: %s", fname, err)
	}
}

type constantPassphraseReader struct {
	constantPassphrase string
}

func (r constantPassphraseReader) ReadPassphrase() string {
	return r.constantPassphrase
}

func TestEncryptDecrypt(t *testing.T) {
	tempdir, err := ioutil.TempDir(os.TempDir(), "saltyboxtest")
	if err != nil {
		t.Fatalf("failed creating temp dir: %s", err)
	}
	defer checkedRemove(tempdir)

	plainPath := filepath.Join(tempdir, "plain")
	err = ioutil.WriteFile(plainPath, []byte("super secret"), 0777)
	if err != nil {
		t.Fatalf("failed to write to %s: %s", plainPath, err)
	}
	defer checkedRemove(plainPath)

	encryptedPath := filepath.Join(tempdir, "encrypted")
	defer checkedRemove(encryptedPath)

	err = passphraseEncryptFile(plainPath, encryptedPath, constantPassphraseReader{constantPassphrase: "test"})
	if err != nil {
		t.Fatalf("encryption failed: %s", err)
	}

	newPlainPath := filepath.Join(tempdir, "newplain")
	defer checkedRemove(newPlainPath)

	err = passphraseDecryptFile(encryptedPath, newPlainPath, constantPassphraseReader{constantPassphrase: "test"})
	if err != nil {
		t.Fatalf("decryption failed: %s", err)
	}

	newPlainText, err := ioutil.ReadFile(newPlainPath)
	if err != nil {
		t.Fatalf("failed to read from %s: %s", newPlainPath, err)
	}

	if !bytes.Equal(newPlainText, []byte("super secret")) {
		t.Fatal("plain text does not match original plain text")
	}
}

func TestBackwardsCompatibility(t *testing.T) {
	tempdir, err := ioutil.TempDir(os.TempDir(), "saltyboxtest")
	if err != nil {
		t.Fatalf("failed creating temp dir: %s", err)
	}
	defer checkedRemove(tempdir)

	encryptedPath := filepath.Join(tempdir, "plain")
	err = ioutil.WriteFile(encryptedPath, []byte("saltybox1:RF0qX8mpCMXVBq6zxHfamdiT64s6Pwvb99Qj9gV61sMAAAAAAAAAFE6RVTWMhBCMJGL0MmgdDUBHoJaW"), 0777)
	if err != nil {
		t.Fatalf("failed to write to %s: %s", encryptedPath, err)
	}
	defer checkedRemove(encryptedPath)

	newPlainPath := filepath.Join(tempdir, "newplain")
	defer checkedRemove(newPlainPath)

	err = passphraseDecryptFile(encryptedPath, newPlainPath, constantPassphraseReader{constantPassphrase: "test"})
	if err != nil {
		t.Fatalf("decryption failed: %s", err)
	}

	newPlainText, err := ioutil.ReadFile(newPlainPath)
	if err != nil {
		t.Fatalf("failed to read from %s: %s", newPlainPath, err)
	}

	if !bytes.Equal(newPlainText, []byte("test")) {
		t.Fatal("plain text does not match original plain text")
	}
}
