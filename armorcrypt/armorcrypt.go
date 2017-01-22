package armoredcrypt

import (
	"github.com/scode/saltybox/secretcrypt"
	"fmt"
	"encoding/base64"
	"strings"
)

const (
	_MAGIC_PREFIX = "saltybox"
	_V1_MAGIC = "saltybox1:"
)

func Encrypt(passphrase string, plaintext []byte) (string, error) {
	cipherBytes, err := secretcrypt.Encrypt(passphrase, plaintext)
	if err != nil {
		return "", err
	}

	cipherString := base64.RawURLEncoding.EncodeToString(cipherBytes)

	return fmt.Sprintf("%s%s", _V1_MAGIC, cipherString), nil
}

func Decrypt(passphrase string, armoredtext string) ([]byte, error) {
	if len(armoredtext) < len(_V1_MAGIC) {
		return nil, fmt.Errorf("input size smaller than magic marker; likely truncated")
	}

	if strings.HasPrefix(armoredtext, _V1_MAGIC) {
		cipherString := strings.TrimPrefix(armoredtext, _V1_MAGIC)
		cipherBytes, err := base64.RawURLEncoding.DecodeString(cipherString)
		if err != nil {
			return nil, fmt.Errorf("base64 decoding failed: %s", err)
		}

		plaintext, err := secretcrypt.Decrypt(passphrase, cipherBytes)
		if err != nil {
			return nil, err
		}
		return plaintext, nil
	} else if strings.HasPrefix(armoredtext, _MAGIC_PREFIX) {
		return nil, fmt.Errorf("input claims to be saltybox, but not a version we support")
	} else {
		return nil, fmt.Errorf("input unrecognized as saltybox data")
	}
}
