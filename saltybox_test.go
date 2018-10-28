package main

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
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
	if !assert.NoError(t, err) {
		assert.FailNow(t, "failed to create temporary directory")
	}
	defer checkedRemove(t, tempdir)

	// Encrypt
	plainPath := filepath.Join(tempdir, "plain")
	err = ioutil.WriteFile(plainPath, []byte("super secret"), 0777)
	if !assert.NoError(t, err) {
		assert.FailNow(t, "failed to write secret to file")
	}
	defer checkedRemove(t, plainPath)

	encryptedPath := filepath.Join(tempdir, "encrypted")
	defer checkedRemove(t, encryptedPath)

	err = passphraseEncryptFile(plainPath, encryptedPath, &constantPassphraseReader{constantPassphrase: "test"})
	assert.NoError(t, err)

	newPlainPath := filepath.Join(tempdir, "newplain")
	defer checkedRemove(t, newPlainPath)

	// Decrypt
	err = passphraseDecryptFile(encryptedPath, newPlainPath, &constantPassphraseReader{constantPassphrase: "test"})
	assert.NoError(t, err)

	newPlainText, err := ioutil.ReadFile(newPlainPath)
	assert.NoError(t, err)
	assert.EqualValues(t, []byte("super secret"), newPlainText)

	// Update with wrong passphrase
	updatedPlainPath := filepath.Join(tempdir, "updatedplain")
	err = ioutil.WriteFile(updatedPlainPath, []byte("updated super secret"), 0777)
	assert.NoError(t, err)
	defer checkedRemove(t, updatedPlainPath)

	err = passphraseUpdateFile(updatedPlainPath, encryptedPath, &constantPassphraseReader{constantPassphrase: "wrong"})
	assert.Error(t, err)

	// Update with right passphrase
	err = passphraseUpdateFile(updatedPlainPath, encryptedPath, &constantPassphraseReader{constantPassphrase: "test"})
	assert.NoError(t, err)

	newUpdatedPlainPath := filepath.Join(tempdir, "newupdatedplain")
	defer checkedRemove(t, newUpdatedPlainPath)
	err = passphraseDecryptFile(encryptedPath, newUpdatedPlainPath, &constantPassphraseReader{constantPassphrase: "test"})
	assert.NoError(t, err)

	newUpdatedPlainText, err := ioutil.ReadFile(newUpdatedPlainPath)
	assert.NoError(t, err)

	assert.EqualValues(t, []byte("updated super secret"), newUpdatedPlainText)
}

func TestBackwardsCompatibility(t *testing.T) {
	tempdir, err := ioutil.TempDir(os.TempDir(), "saltyboxtest")
	if !assert.NoError(t, err) {
		assert.FailNow(t, "failed to create temp dir")
	}
	defer checkedRemove(t, tempdir)

	encryptedPath := filepath.Join(tempdir, "plain")
	err = ioutil.WriteFile(encryptedPath, []byte("saltybox1:RF0qX8mpCMXVBq6zxHfamdiT64s6Pwvb99Qj9gV61sMAAAAAAAAAFE6RVTWMhBCMJGL0MmgdDUBHoJaW"), 0777)
	assert.NoError(t, err)
	defer checkedRemove(t, encryptedPath)

	newPlainPath := filepath.Join(tempdir, "newplain")
	defer checkedRemove(t, newPlainPath)

	err = passphraseDecryptFile(encryptedPath, newPlainPath, &constantPassphraseReader{constantPassphrase: "test"})
	assert.NoError(t, err)

	newPlainText, err := ioutil.ReadFile(newPlainPath)
	assert.NoError(t, err)

	assert.EqualValues(t, []byte("test"), newPlainText)
}
