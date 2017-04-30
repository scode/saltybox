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
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/scrypt"
	"io"
	"log"
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

	keyLen             = 32
	secretboxNounceLen = 24
)

func genKey(passphrase string, salt []byte) [keyLen]byte {
	secretKey, err := scrypt.Key([]byte(passphrase), salt[:], scryptN, scryptR, scryptP, keyLen)
	if err != nil {
		panic(err)
	}

	// Copy merely to obtain a value of type [keyLen]byte for the caller's convenience (due to
	// secretbox's API).
	var secretKeyCopy [keyLen]byte
	copy(secretKeyCopy[:], secretKey)

	return secretKeyCopy
}

// Encrypt encrypts bytes using a passphrase.
//
// Returns encrypted bytes and an error, if any.
//
// The current implementation never returns an error, but callers should not assume that this remains
// the case.
func Encrypt(passphrase string, plaintext []byte) ([]byte, error) {
	var salt [saltLen]byte
	n, err := rand.Read(salt[:])
	if err != nil {
		log.Panic("rand.Read() should never fail")
	}
	if n != len(salt) {
		log.Panic("rand.Read() should always return expected length")
	}

	secretKey := genKey(passphrase, salt[:])

	var nounce [secretboxNounceLen]byte
	n, err = rand.Read(nounce[:])
	if err != nil {
		log.Panic("rand.Read() should never fail")
	}
	if n != len(nounce) {
		log.Panic("rand.Read() should always return expected length")
	}

	sealedBox := secretbox.Seal(
		nil,
		plaintext,
		&nounce,
		&secretKey,
	)

	var buf bytes.Buffer
	if _, err = buf.Write(salt[:]); err != nil {
		log.Panic(err)
	}
	if _, err = buf.Write(nounce[:]); err != nil {
		log.Panic(err)
	}
	if err = binary.Write(&buf, binary.BigEndian, int64(len(sealedBox))); err != nil {
		log.Panic(err)
	}
	if _, err = buf.Write(sealedBox); err != nil {
		log.Panic(err)
	}

	return buf.Bytes(), nil
}

// Decrypt decrypts a sequence of bytes previously created with Encrypt.
//
// Errors conditions include (but may not be limited to):
//
//   * The input is truncated.
//   * The input is otherwise invalid (arbitrary corruption).
//   * The passphrase does not match that which was used during encryption.
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
		log.Panic("expected correct byte count on successfull io.ReadFull()")
	}

	var nounce [secretboxNounceLen]byte
	n, err = io.ReadFull(cryptReader, nounce[:])
	if err != nil {
		return nil, fmt.Errorf("input likely truncated while reading nounce: %v", err)
	}
	if n != len(nounce) {
		log.Panic("expected correct byte count on successfull io.ReadFull()")
	}

	var sealedBoxLen int64
	if err = binary.Read(cryptReader, binary.BigEndian, &sealedBoxLen); err != nil {
		return nil, fmt.Errorf("input likely truncated while reading sealed box: %v", err)
	}
	if sealedBoxLen > int64(len(crypttext)) {
		return nil, errors.New("truncated or corrupt input; claimed length greater than available input")
	}

	sealedBox := make([]byte, sealedBoxLen)
	n, err = io.ReadFull(cryptReader, sealedBox)
	if err != nil {
		return nil, errors.New("truncated or corrupt input (while reading sealed box)")
	}
	if n != len(sealedBox) {
		log.Panic("expected correct byte count on successful io.ReadFull()")
	}

	secretKey := genKey(passphrase, salt[:])
	plaintext, success := secretbox.Open(
		nil,
		sealedBox,
		&nounce,
		&secretKey,
	)
	if !success {
		return nil, errors.New("corrupt input, tampered-with data, or bad passphrase")
	}

	return plaintext, nil
}
