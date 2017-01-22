package armoredcrypt

import (
	"testing"
)

func preserve(t *testing.T, s string) {
	b, err := Unwrap(Wrap([]byte(s)))
	if err != nil {
		t.Error("Unwrap should not have failed")
	}

	if string(b) != s {
		t.Error("Wrapping and unwrapping produced non-equal results")
	}

}

func TestPreservation(t *testing.T) {
	preserve(t, "")
	preserve(t, "test")
}

func TestTruncated(t *testing.T) {
	b, err := Unwrap("")
	if b != nil {
		t.Error("truncated input to Unwrap should result in empty bytes")
	}
	if err == nil {
		t.Error("truncated input to Unwrap should result in error")
	}
}

func TestWrongVersion(t *testing.T) {
	b, err := Unwrap("saltybox999999:...")
	if b != nil {
		t.Error("future versioned input to Unwrap should result in empty bytes")
	}
	if err == nil {
		t.Error("future versioned input to Unwrap should result in error")
	}
	if err.Error() != "input claims to be saltybox, but not a version we support" {
		t.Error("future versioned input to Unwrap should result in friendly error")
	}
}