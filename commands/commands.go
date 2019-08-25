package commands

import (
	"fmt"
	"github.com/scode/saltybox/preader"
	"github.com/scode/saltybox/secretcrypt"
	"github.com/scode/saltybox/varmor"
	"io/ioutil"
	"os"
	"path"
)

func passphraseEncrypt(passphrase string, plaintext []byte) (string, error) {
	cipherBytes, err := secretcrypt.Encrypt(passphrase, plaintext)
	if err != nil {
		return "", fmt.Errorf("encryption failed: %s", err)
	}

	varmoredBytes := varmor.Wrap(cipherBytes)

	return string(varmoredBytes), nil
}

func PassphraseEncryptFile(inpath string, outpath string, preader preader.PassphraseReader) error {
	plaintext, err := ioutil.ReadFile(inpath)
	if err != nil {
		return fmt.Errorf("failed to read from %s: %s", inpath, err)
	}

	passphrase, err := preader.ReadPassphrase()
	if err != nil {
		return err
	}
	encryptedString, err := passphraseEncrypt(passphrase, plaintext)
	if err != nil {
		return fmt.Errorf("encryption failed: %s", err)
	}

	err = ioutil.WriteFile(outpath, []byte(encryptedString), 0700)
	if err != nil {
		return fmt.Errorf("failed to write to %s: %s", outpath, err)
	}

	return nil
}

func passphraseDecrypt(passphrase string, encryptedString string) ([]byte, error) {
	cipherBytes, err := varmor.Unwrap(encryptedString)
	if err != nil {
		return nil, fmt.Errorf("failed to unarmor: %s", err)
	}

	plaintext, err := secretcrypt.Decrypt(passphrase, cipherBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %s", err)
	}

	return plaintext, nil
}

func PassphraseDecryptFile(inpath string, outpath string, preader preader.PassphraseReader) error {
	varmoredBytes, err := ioutil.ReadFile(inpath)
	if err != nil {
		return fmt.Errorf("failed to read from %s: %s", inpath, err)
	}

	passphrase, err := preader.ReadPassphrase()
	if err != nil {
		return err
	}
	plaintext, err := passphraseDecrypt(passphrase, string(varmoredBytes))
	if err != nil {
		return fmt.Errorf("failed to decrypt: %s", err)
	}

	err = ioutil.WriteFile(outpath, plaintext, 0700)
	if err != nil {
		return fmt.Errorf("failed to write to %s: %s", outpath, err)
	}

	return nil
}

func PassphraseUpdateFile(plainfile string, cryptfile string, pr preader.PassphraseReader) (err error) {
	// Decrypt existing file in order to validate that the provided passphrase is correct,
	// in order to prevent accidental changing of the passphrase (but we discard the plain
	// text).
	varmoredBytes, err := ioutil.ReadFile(cryptfile)
	if err != nil {
		return fmt.Errorf("failed to read from %s: %s", cryptfile, err)
	}

	cachingPreader := preader.NewCaching(pr)

	passphrase, err := cachingPreader.ReadPassphrase()
	if err != nil {
		return err
	}
	_, err = passphraseDecrypt(passphrase, string(varmoredBytes))
	if err != nil {
		return fmt.Errorf("failed to decrypt: %s", err)
	}

	// Encrypt contents into the target file using atomic semantics (write to tempfile, fsync()
	// and rename). This guarantees that the resulting file will either be the old file or the new
	// file, but never corrupt (assuming a correctly functioning filesystem I/O stack).
	cryptDir, _ := path.Split(cryptfile)

	tmpfile, err := ioutil.TempFile(cryptDir, "saltybox-update-tmp")
	if err != nil {
		return fmt.Errorf("failed to create tempfile: %s", err)
	}
	defer func(fname string) {
		if _, localErr := os.Stat(fname); !os.IsNotExist(localErr) {
			err = os.Remove(fname)
		}
	}(tmpfile.Name())
	defer func(tmpfile *os.File) {
		err = tmpfile.Close()
	}(tmpfile)

	err = PassphraseEncryptFile(plainfile, tmpfile.Name(), cachingPreader)
	if err != nil {
		return fmt.Errorf("failed to encrypt: %s", err)
	}

	// Re-open the file to ensure that we are Sync():ing the correct file. Technically this is not
	// required because passphraseEncryptFile() will cause the target file to be truncated rather than recreated.
	// However, let's defensively avoid relying on that subtle behavior and re-open the file.
	reopenedTmpFile, err := os.Open(tmpfile.Name())
	if err != nil {
		return fmt.Errorf("failed to re-open tempfile after encryption: %s", err)
	}
	defer func(f *os.File) {
		err = f.Close()
	}(reopenedTmpFile)

	err = reopenedTmpFile.Sync()
	if err != nil {
		return fmt.Errorf("failed to sync file prior to rename: %s", err)
	}

	err = os.Rename(reopenedTmpFile.Name(), cryptfile)
	if err != nil {
		return fmt.Errorf("failed to rename to target file: %s", err)
	}

	return nil
}
