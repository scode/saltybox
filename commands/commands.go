package commands

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/scode/saltybox/preader"
	"github.com/scode/saltybox/secretcrypt"
	"github.com/scode/saltybox/varmor"
)

func encryptBytes(passphrase string, plaintext []byte) (string, error) {
	cipherBytes, err := secretcrypt.Encrypt(passphrase, plaintext)
	if err != nil {
		return "", fmt.Errorf("encryption failed: %w", err)
	}

	varmoredString := varmor.Wrap(cipherBytes)

	return varmoredString, nil
}

func Encrypt(inpath string, outpath string, preader preader.PassphraseReader) error {
	plaintext, err := os.ReadFile(inpath)
	if err != nil {
		return fmt.Errorf("failed to read from %s: %w", inpath, err)
	}

	passphrase, err := preader.ReadPassphrase()
	if err != nil {
		return err
	}
	encryptedString, err := encryptBytes(passphrase, plaintext)
	if err != nil {
		return fmt.Errorf("encryption failed: %w", err)
	}

	err = os.WriteFile(outpath, []byte(encryptedString), 0600)
	if err != nil {
		return fmt.Errorf("failed to write to %s: %w", outpath, err)
	}

	return nil
}

func decryptString(passphrase string, encryptedString string) ([]byte, error) {
	cipherBytes, err := varmor.Unwrap(encryptedString)
	if err != nil {
		return nil, fmt.Errorf("failed to unarmor: %w", err)
	}

	plaintext, err := secretcrypt.Decrypt(passphrase, cipherBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return plaintext, nil
}

func Decrypt(inpath string, outpath string, preader preader.PassphraseReader) error {
	varmoredBytes, err := os.ReadFile(inpath)
	if err != nil {
		return fmt.Errorf("failed to read from %s: %w", inpath, err)
	}

	passphrase, err := preader.ReadPassphrase()
	if err != nil {
		return err
	}
	plaintext, err := decryptString(passphrase, string(varmoredBytes))
	if err != nil {
		return fmt.Errorf("failed to decrypt: %w", err)
	}

	err = os.WriteFile(outpath, plaintext, 0600)
	if err != nil {
		return fmt.Errorf("failed to write to %s: %w", outpath, err)
	}

	return nil
}

func Update(plainfile string, cryptfile string, pr preader.PassphraseReader) (err error) {
	// Decrypt existing file in order to validate that the provided passphrase is correct,
	// in order to prevent accidental changing of the passphrase (but we discard the plain
	// text).
	varmoredBytes, err := os.ReadFile(cryptfile)
	if err != nil {
		return fmt.Errorf("failed to read from %s: %w", cryptfile, err)
	}

	cachingPreader := preader.NewCaching(pr)

	passphrase, err := cachingPreader.ReadPassphrase()
	if err != nil {
		return err
	}
	_, err = decryptString(passphrase, string(varmoredBytes))
	if err != nil {
		return fmt.Errorf("failed to decrypt: %w", err)
	}

	// Encrypt contents into the target file using atomic semantics (write to tempfile, fsync()
	// and rename). This guarantees that the resulting file will either be the old file or the new
	// file, but never corrupt (assuming a correctly functioning filesystem I/O stack).
	cryptDir, _ := filepath.Split(cryptfile)

	tmpfile, err := os.CreateTemp(cryptDir, "saltybox-update-tmp")
	if err != nil {
		return fmt.Errorf("failed to create tempfile: %w", err)
	}
	defer func(fname string) {
		if _, localErr := os.Stat(fname); !os.IsNotExist(localErr) {
			err = os.Remove(fname)
		}
	}(tmpfile.Name())
	defer func(tmpfile *os.File) {
		err = tmpfile.Close()
	}(tmpfile)

	err = Encrypt(plainfile, tmpfile.Name(), cachingPreader)
	if err != nil {
		return fmt.Errorf("failed to encrypt: %w", err)
	}

	// Re-open the file to ensure that we are Sync():ing the correct file. Technically this is not
	// required because passphraseEncryptFile() will cause the target file to be truncated rather than recreated.
	// However, let's defensively avoid relying on that subtle behavior and re-open the file.
	reopenedTmpFile, err := os.Open(tmpfile.Name())
	if err != nil {
		return fmt.Errorf("failed to re-open tempfile after encryption: %w", err)
	}
	defer func(f *os.File) {
		err = f.Close()
	}(reopenedTmpFile)

	err = reopenedTmpFile.Sync()
	if err != nil {
		return fmt.Errorf("failed to sync file prior to rename: %w", err)
	}

	err = os.Rename(reopenedTmpFile.Name(), cryptfile)
	if err != nil {
		return fmt.Errorf("failed to rename to target file: %w", err)
	}

	return nil
}
