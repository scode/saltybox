package commands

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/scode/saltybox/preader"
	"github.com/stretchr/testify/assert"
)

func checkedRemove(t *testing.T, fname string) {
	err := os.Remove(fname)
	assert.NoError(t, err, "removal of file %s filed: %v", fname, err)
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

	err = Encrypt(plainPath, encryptedPath, preader.NewConstant("test"))
	assert.NoError(t, err)

	newPlainPath := filepath.Join(tempdir, "newplain")
	defer checkedRemove(t, newPlainPath)

	// Decrypt
	err = Decrypt(encryptedPath, newPlainPath, preader.NewConstant("test"))
	assert.NoError(t, err)

	newPlainText, err := ioutil.ReadFile(newPlainPath)
	assert.NoError(t, err)
	assert.EqualValues(t, []byte("super secret"), newPlainText)

	// Update with wrong passphrase
	updatedPlainPath := filepath.Join(tempdir, "updatedplain")
	err = ioutil.WriteFile(updatedPlainPath, []byte("updated super secret"), 0777)
	assert.NoError(t, err)
	defer checkedRemove(t, updatedPlainPath)

	err = Update(updatedPlainPath, encryptedPath, preader.NewConstant("wrong"))
	assert.Error(t, err)

	// Update with right passphrase
	err = Update(updatedPlainPath, encryptedPath, preader.NewConstant("test"))
	assert.NoError(t, err)

	newUpdatedPlainPath := filepath.Join(tempdir, "newupdatedplain")
	defer checkedRemove(t, newUpdatedPlainPath)
	err = Decrypt(encryptedPath, newUpdatedPlainPath, preader.NewConstant("test"))
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

	err = Decrypt(encryptedPath, newPlainPath, preader.NewConstant("test"))
	assert.NoError(t, err)

	newPlainText, err := ioutil.ReadFile(newPlainPath)
	assert.NoError(t, err)

	assert.EqualValues(t, []byte("test"), newPlainText)
}
