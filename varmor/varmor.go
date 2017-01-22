package armoredcrypt

import (
	"fmt"
	"encoding/base64"
	"strings"
	"errors"
)

const (
	_MAGIC_PREFIX = "saltybox"
	_V1_MAGIC = "saltybox1:"
)

func Wrap(body []byte) string {
	encoded := base64.RawURLEncoding.EncodeToString(body)

	return fmt.Sprintf("%s%s", _V1_MAGIC, encoded)
}

func Unwrap(varmoredBody string) ([]byte, error) {
	if len(varmoredBody) < len(_V1_MAGIC) {
		return nil, errors.New("input size smaller than magic marker; likely truncated")
	}

	if strings.HasPrefix(varmoredBody, _V1_MAGIC) {
		armoredBody := strings.TrimPrefix(varmoredBody, _V1_MAGIC)
		body, err := base64.RawURLEncoding.DecodeString(armoredBody)
		if err != nil {
			return nil, fmt.Errorf("base64 decoding failed: %s", err)
		}

		return body, nil
	} else if strings.HasPrefix(varmoredBody, _MAGIC_PREFIX) {
		return nil, errors.New("input claims to be saltybox, but not a version we support")
	} else {
		return nil, errors.New("input unrecognized as saltybox data")
	}
}
