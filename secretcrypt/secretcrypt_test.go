package secretcrypt

import (
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

func passthrough(t *testing.T, passphrase string, plaintext []byte) {
	crypted, err := Encrypt(passphrase, plaintext)
	assert.NoError(t, err)

	plainResult, err := Decrypt(passphrase, crypted)
	assert.NoError(t, err)
	assert.EqualValues(t, plaintext, plainResult)
}

func TestEncryptDecryptDoesNotCorrupt(t *testing.T) {
	rand.NewSource(0)
	rSource := rand.NewSource(0)
	r := rand.New(rSource)

	// Choose a small number of sizes for performance reasons. Because key stretching happens on every
	// call, we're slow.
	plaintextLens := []int{0, 5, 64000, 128000}
	for i := 0; i < len(plaintextLens); i++ {
		b := make([]byte, plaintextLens[i])

		n, err := r.Read(b)
		if n != len(b) || err != nil {
			assert.FailNow(t, "infallible Read() failed")
		}
		passthrough(t, "testphrase", b)
	}
}
