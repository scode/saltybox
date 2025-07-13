// Package secretcrypt implements passphrase based encryption/decryption with a simple interface.
//
// The format used is guaranteed to never change. Any such change will some in the form of a
// different package rather than evolving this implementation.
package secretcrypt

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/scrypt"
)

const (
	saltLen = 8 // Length of salt in number of bytes.

	// These values are the recommended ones for 2009, except another power of 2 added to N for 32768 instead
	// of 16384. See:
	//
	//   https://godoc.org/golang.org/x/crypto/scrypt
	//   http://stackoverflow.com/questions/11126315/what-are-optimal-scrypt-work-factors
	scryptN = 32768
	scryptR = 8
	scryptP = 1

	keyLen            = 32
	secretboxNonceLen = 24
)

func genKey(passphrase string, salt []byte) (*[keyLen]byte, error) {
	secretKey, err := scrypt.Key([]byte(passphrase), salt, scryptN, scryptR, scryptP, keyLen)
	if err != nil {
		return nil, err
	}

	// Copy merely to obtain a value of type [keyLen]byte for the caller's convenience (due to
	// secretbox's API).
	var secretKeyCopy [keyLen]byte
	copy(secretKeyCopy[:], secretKey)

	return &secretKeyCopy, nil
}

// Encrypt encrypts bytes using a passphrase.
//
// Returns encrypted bytes and an error, if any.
func Encrypt(passphrase string, plaintext []byte) ([]byte, error) {
	var salt [saltLen]byte
	n, err := rand.Read(salt[:])
	if err != nil {
		return nil, fmt.Errorf("rand.Read() should never fail, but did: %v", err)
	}
	if n != len(salt) {
		return nil, fmt.Errorf("rand.Read() should always return the requested length, but did not: %v", n)
	}

	secretKey, err := genKey(passphrase, salt[:])
	if err != nil {
		return nil, err
	}

	var nonce [secretboxNonceLen]byte
	n, err = rand.Read(nonce[:])
	if err != nil {
		return nil, fmt.Errorf("rand.Read() should never fail, but did: %v", err)
	}
	if n != len(nonce) {
		return nil, fmt.Errorf("rand.Read() should always return the requested length, but did not: %v", n)
	}

	sealedBox := secretbox.Seal(
		nil,
		plaintext,
		&nonce,
		secretKey,
	)

	var buf bytes.Buffer
	if _, err = buf.Write(salt[:]); err != nil {
		return nil, fmt.Errorf("infallible Write() failed: %v", err)
	}
	if _, err = buf.Write(nonce[:]); err != nil {
		return nil, fmt.Errorf("infallible Write() failed: %v", err)
	}
	if err = binary.Write(&buf, binary.BigEndian, int64(len(sealedBox))); err != nil {
		return nil, fmt.Errorf("infallible Write() failed: %v", err)
	}
	if _, err = buf.Write(sealedBox); err != nil {
		return nil, fmt.Errorf("infallible Write() failed: %v", err)
	}

	return buf.Bytes(), nil
}

// Decrypt decrypts a sequence of bytes previously created with Encrypt.
//
// Errors conditions include (but may not be limited to):
//
//   - The input is truncated.
//   - The input is otherwise invalid (arbitrary corruption).
//   - The passphrase does not match that which was used during encryption.
//
// There is no way to tell programatically whether an error is due to a bad passphrase or
// for other reasons.
func Decrypt(passphrase string, crypttext []byte) ([]byte, error) {
	cryptReader := bytes.NewReader(crypttext)

	var salt [saltLen]byte
	n, err := io.ReadFull(cryptReader, salt[:])
	if err != nil {
		return nil, fmt.Errorf("input likely truncated while reading salt: %v", err)
	}
	if n != len(salt) {
		return nil, fmt.Errorf("ReadFull() succeeded yet byte count was not as expected: %v", n)
	}

	var nonce [secretboxNonceLen]byte
	n, err = io.ReadFull(cryptReader, nonce[:])
	if err != nil {
		return nil, fmt.Errorf("input likely truncated while reading nonce: %v", err)
	}
	if n != len(nonce) {
		return nil, fmt.Errorf("ReadFull() succeeded yet byte count was not as expected: %v", n)
	}

	var sealedBoxLen int64
	if err = binary.Read(cryptReader, binary.BigEndian, &sealedBoxLen); err != nil {
		return nil, fmt.Errorf("input likely truncated while reading sealed box: %v", err)
	}
	if sealedBoxLen < 0 {
		return nil, errors.New("negative sealed box length")
	}
	maxInt := int(^uint(0) >> 1)
	if sealedBoxLen > int64(maxInt) {
		return nil, errors.New("sealed box length exceeds max int")
	}
	if sealedBoxLen > int64(len(crypttext)) {
		return nil, errors.New("truncated or corrupt input; claimed length greater than available input")
	}

	sealedBox := make([]byte, int(sealedBoxLen))
	n, err = io.ReadFull(cryptReader, sealedBox)
	if err != nil {
		return nil, errors.New("truncated or corrupt input (while reading sealed box)")
	}
	if n != len(sealedBox) {
		return nil, fmt.Errorf("ReadFull() succeeded yet byte count was not as expected: %v", n)
	}

	// Verify that input ends exactly after the sealed box (no trailing junk)
	if cryptReader.Len() > 0 {
		return nil, errors.New("invalid input: unexpected data after sealed box")
	}

	secretKey, err := genKey(passphrase, salt[:])
	if err != nil {
		return nil, err
	}

	plaintext, success := secretbox.Open(
		nil,
		sealedBox,
		&nonce,
		secretKey,
	)
	if !success {
		return nil, errors.New("corrupt input, tampered-with data, or bad passphrase")
	}

	if plaintext == nil {
		plaintext = []byte{}
	}

	return plaintext, nil
}
