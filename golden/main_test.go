package main

import (
	"testing"

	"github.com/scode/saltybox/varmor"
	"github.com/stretchr/testify/assert"
)

func TestEncryptDeterministically(t *testing.T) {
	plaintext := []byte("hello world")
	passphrase := "testpass"

	var salt [8]byte
	copy(salt[:], []byte("testsalt"))

	var nonce [24]byte
	copy(nonce[:], []byte("testnonce123456789012"))

	// Encrypt deterministically
	armored, err := encryptDeterministically(plaintext, passphrase, &salt, &nonce)
	assert.NoError(t, err)
	assert.NotEmpty(t, armored)
	assert.Contains(t, armored, "saltybox1:")

	// Verify it can be decrypted (unarmor and check format)
	cipherBytes, err := varmor.Unwrap(armored)
	assert.NoError(t, err)
	assert.NotEmpty(t, cipherBytes)

	// Verify deterministic behavior - same inputs produce same output
	armored2, err := encryptDeterministically(plaintext, passphrase, &salt, &nonce)
	assert.NoError(t, err)
	assert.Equal(t, armored, armored2)
}

func TestEncryptDeterministicallyEmptyPlaintext(t *testing.T) {
	plaintext := []byte{}
	passphrase := "testpass"

	var salt [8]byte
	copy(salt[:], []byte("salt0000"))

	var nonce [24]byte
	copy(nonce[:], []byte("nonce000000000000000000"))

	// Encrypt empty plaintext
	armored, err := encryptDeterministically(plaintext, passphrase, &salt, &nonce)
	assert.NoError(t, err)
	assert.Contains(t, armored, "saltybox1:")

	// Verify it can be unarmored
	cipherBytes, err := varmor.Unwrap(armored)
	assert.NoError(t, err)
	assert.NotEmpty(t, cipherBytes) // Even empty plaintext produces non-empty ciphertext (salt, nonce, length, MAC)
}

func TestEncryptDeterministicallyBinaryData(t *testing.T) {
	// Test with binary data including null bytes
	plaintext := []byte{0x00, 0x01, 0xFF, 0xFE, 0x00, 0x00}
	passphrase := "testpass"

	var salt [8]byte
	copy(salt[:], []byte("binary00"))

	var nonce [24]byte
	copy(nonce[:], []byte("binarynonce000000000000"))

	armored, err := encryptDeterministically(plaintext, passphrase, &salt, &nonce)
	assert.NoError(t, err)
	assert.Contains(t, armored, "saltybox1:")

	// Verify it can be unarmored
	cipherBytes, err := varmor.Unwrap(armored)
	assert.NoError(t, err)
	assert.NotEmpty(t, cipherBytes)
}
