package secretcrypt

import (
	"encoding/binary"
	"math/rand"
	"strconv"
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

func TestDecryptNegativeLength(t *testing.T) {
	crypted, err := Encrypt("pass", []byte("hello"))
	assert.NoError(t, err)

	offset := saltLen + secretboxNonceLen
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, ^uint64(0))
	copy(crypted[offset:], b)

	_, err = Decrypt("pass", crypted)
	assert.ErrorContains(t, err, "negative")
}

func TestDecryptTooLargeLength(t *testing.T) {
	if strconv.IntSize >= 64 {
		t.Skip("int is >= 64-bit; cannot represent a value greater than max int")
	}

	crypted, err := Encrypt("pass", []byte("hello"))
	assert.NoError(t, err)

	offset := saltLen + secretboxNonceLen
	large := uint64(int(^uint(0)>>1)) + 1
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, large)
	copy(crypted[offset:], b)

	_, err = Decrypt("pass", crypted)
	assert.ErrorContains(t, err, "too large")
}

func TestDecryptWithTrailingJunk(t *testing.T) {
	plaintext := []byte("test message")
	crypted, err := Encrypt("testpass", plaintext)
	assert.NoError(t, err)

	// Append junk data to the encrypted message
	junkData := []byte("this is junk that should not be ignored")
	cryptedWithJunk := make([]byte, len(crypted)+len(junkData))
	copy(cryptedWithJunk, crypted)
	copy(cryptedWithJunk[len(crypted):], junkData)

	// Decryption should fail due to trailing junk
	_, err = Decrypt("testpass", cryptedWithJunk)
	assert.ErrorContains(t, err, "unexpected data after sealed box")

	// Verify that original (without junk) still works
	decrypted, err := Decrypt("testpass", crypted)
	assert.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}
