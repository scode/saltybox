package secretcrypt

import (
	"bytes"
	"testing"
)

func passthrough(plaintext string) {
	crypted, err := Encrypt("testphrase", []byte(plaintext))
	if err != nil {
		panic(err)
	}

	plain, err := Decrypt("testphrase", crypted)
	if err != nil {
		panic(err)
	}

	if !bytes.Equal(plain, []byte(plain)) {
		panic("expected correct plaintext")
	}
}

func TestEncryptDecryptDoesNotCorrupt(t *testing.T) {
	passthrough("test")
	passthrough("")
	passthrough("t")
}
