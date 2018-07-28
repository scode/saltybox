package main

import (
	"bytes"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

func checkedRemove(t *testing.T, fname string) {
	err := os.Remove(fname)
	assert.NoError(t, err, "removal of file %s filed: %v", fname, err)
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

	// The first read should penetrate the cache.
	assert.Equal(t, "phrase", caching.ReadPassphrase())
	assert.Equal(t, 1, upstream.callCount)

	// But the second read should not (so callCount should remain the same).
	assert.Equal(t, "phrase", caching.ReadPassphrase())
	assert.Equal(t, 1, upstream.callCount)
}

func TestEncryptDecryptUpdate(t *testing.T) {
	tempdir, err := ioutil.TempDir(os.TempDir(), "saltyboxtest")
	if err != nil {
		t.Fatalf("failed creating temp dir: %s", err)
	}
	defer checkedRemove(t, tempdir)

	// Encrypt
	plainPath := filepath.Join(tempdir, "plain")
	err = ioutil.WriteFile(plainPath, []byte("super secret"), 0777)
	if err != nil {
		t.Fatalf("failed to write to %s: %s", plainPath, err)
	}
	defer checkedRemove(t, plainPath)

	encryptedPath := filepath.Join(tempdir, "encrypted")
	defer checkedRemove(t, encryptedPath)

	err = passphraseEncryptFile(plainPath, encryptedPath, &constantPassphraseReader{constantPassphrase: "test"})
	if err != nil {
		t.Fatalf("encryption failed: %s", err)
	}

	newPlainPath := filepath.Join(tempdir, "newplain")
	defer checkedRemove(t, newPlainPath)

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
	defer checkedRemove(t, updatedPlainPath)

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
	defer checkedRemove(t, newUpdatedPlainPath)
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
	defer checkedRemove(t, tempdir)

	encryptedPath := filepath.Join(tempdir, "plain")
	err = ioutil.WriteFile(encryptedPath, []byte("saltybox1:RF0qX8mpCMXVBq6zxHfamdiT64s6Pwvb99Qj9gV61sMAAAAAAAAAFE6RVTWMhBCMJGL0MmgdDUBHoJaW"), 0777)
	if err != nil {
		t.Fatalf("failed to write to %s: %s", encryptedPath, err)
	}
	defer checkedRemove(t, encryptedPath)

	newPlainPath := filepath.Join(tempdir, "newplain")
	defer checkedRemove(t, newPlainPath)

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
