package armoredcrypt

import (
	"testing"
	"math/rand"
	"bytes"
)

func passthrough(passphrase string, plaintext []byte) {
	crypted, err := Encrypt(passphrase, plaintext)
	if err != nil {
		panic(err)
	}

	plainResult, err := Decrypt(passphrase, crypted)
	if err != nil {
		panic(err)
	}

	if !bytes.Equal(plainResult, plaintext) {
		panic("expected correct plaintext")
	}
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

		r.Read(b)
		passthrough("testphrase", b)
	}
}
