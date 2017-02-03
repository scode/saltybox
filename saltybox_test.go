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
