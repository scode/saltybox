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
	callCount          int
}

func (r *constantPassphraseReader) ReadPassphrase() string {
	r.callCount++
	return r.constantPassphrase
}

func TestCachingPassphraseReader_ReadPassphrase(t *testing.T) {
	upstream := constantPassphraseReader{constantPassphrase: "phrase"}
	caching := cachingPassphraseReader{Upstream: &upstream}

	if caching.ReadPassphrase() != "phrase" {
		t.Fatal("expected valid passphrase")
	}

	if upstream.callCount != 1 {
		t.Fatalf("expected call count 1, was %d", upstream.callCount)
	}

	// And again, and ensure we didn't call upstream a second time.
	if caching.ReadPassphrase() != "phrase" {
		t.Fatal("expected valid passphrase")
	}

	if upstream.callCount != 1 {
		t.Fatalf("expected call count 1, was %d", upstream.callCount)
	}
}

func TestEncryptDecryptUpdate(t *testing.T) {
	tempdir, err := ioutil.TempDir(os.TempDir(), "saltyboxtest")
	if err != nil {
		t.Fatalf("failed creating temp dir: %s", err)
	}
	defer checkedRemove(tempdir)

	// Encrypt
	plainPath := filepath.Join(tempdir, "plain")
	err = ioutil.WriteFile(plainPath, []byte("super secret"), 0777)
	if err != nil {
		t.Fatalf("failed to write to %s: %s", plainPath, err)
	}
	defer checkedRemove(plainPath)

	encryptedPath := filepath.Join(tempdir, "encrypted")
	defer checkedRemove(encryptedPath)

	err = passphraseEncryptFile(plainPath, encryptedPath, &constantPassphraseReader{constantPassphrase: "test"})
	if err != nil {
		t.Fatalf("encryption failed: %s", err)
	}

	newPlainPath := filepath.Join(tempdir, "newplain")
	defer checkedRemove(newPlainPath)

	// Decrypt
	err = passphraseDecryptFile(encryptedPath, newPlainPath, &constantPassphraseReader{constantPassphrase: "test"})
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

	// Update with wrong passphrase
	updatedPlainPath := filepath.Join(tempdir, "updatedplain")
	err = ioutil.WriteFile(updatedPlainPath, []byte("updated super secret"), 0777)
	if err != nil {
		t.Fatalf("failed to write to %s: %s", updatedPlainPath, err)
	}
	defer checkedRemove(updatedPlainPath)

	err = passphraseUpdateFile(updatedPlainPath, encryptedPath, &constantPassphraseReader{constantPassphrase: "wrong"})
	if err == nil {
		t.Fatal("did NOT fail to update file despite invalid passpharse")
	}

	// Update with right passphrase
	err = passphraseUpdateFile(updatedPlainPath, encryptedPath, &constantPassphraseReader{constantPassphrase: "test"})
	if err != nil {
		t.Fatalf("failed to update file: %s", err)
	}

	newUpdatedPlainPath := filepath.Join(tempdir, "newupdatedplain")
	defer checkedRemove(newUpdatedPlainPath)
	err = passphraseDecryptFile(encryptedPath, newUpdatedPlainPath, &constantPassphraseReader{constantPassphrase: "test"})
	if err != nil {
		t.Fatalf("decryption failed: %s", err)
	}

	newUpdatedPlainText, err := ioutil.ReadFile(newUpdatedPlainPath)
	if err != nil {
		t.Fatalf("failed to read from %s: %s", newUpdatedPlainPath, err)
	}

	if !bytes.Equal(newUpdatedPlainText, []byte("updated super secret")) {
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

	err = passphraseDecryptFile(encryptedPath, newPlainPath, &constantPassphraseReader{constantPassphrase: "test"})
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
