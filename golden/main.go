package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"sort"

	"github.com/scode/saltybox/secretcrypt"
	"github.com/scode/saltybox/varmor"
	"github.com/urfave/cli/v3"
)

func main() {
	rootCmd := &cli.Command{
		Name:        "golden",
		Version:     "unknown (master)",
		Usage:       "a tool to ensure correctness/compatibility of saltybox format reading and writing",
		HideVersion: true,
		Commands: []*cli.Command{
			{
				Name:  "generate",
				Usage: "Generate golden test data",
				Action: func(_ context.Context, _ *cli.Command) error {
					return generateGolden()
				},
			},
			{
				Name:  "validate",
				Usage: "Validate golden test data",
				Action: func(_ context.Context, _ *cli.Command) error {
					return validateGolden()
				},
			},
		},
		Action: func(_ context.Context, _ *cli.Command) error {
			return errors.New("command is required; use help to see list of commands")
		},
	}

	err := rootCmd.Run(context.Background(), os.Args)
	if err != nil {
		log.Fatal(err)
	}
}

type goldenVector struct {
	Plaintext  string `json:"plaintext"`
	Ciphertext string `json:"ciphertext"`
	Nonce      string `json:"nonce"`
	Salt       string `json:"salt"`
	Passphrase string `json:"passphrase"`
	Comment    string `json:"comment"`
}

// encryptDeterministically encrypts plaintext with the given passphrase, salt, and nonce,
// returning the armored ciphertext string.
//
// This is a helper function for generating golden test vectors.
func encryptDeterministically(plaintext []byte, passphrase string, salt *[8]byte, nonce *[24]byte) (string, error) {
	cipherBytes, err := secretcrypt.EncryptDeterministically(passphrase, plaintext, salt, nonce)
	if err != nil {
		return "", fmt.Errorf("encryption failed: %w", err)
	}

	varmoredString := varmor.Wrap(cipherBytes)

	return varmoredString, nil
}

//nolint:gocyclo // Function is complex due to many test cases, but readable
func generateGolden() error {
	vectors := []goldenVector{}

	// Helper to add a test vector
	addVector := func(plaintext []byte, passphrase string, saltSeed, nonceSeed string, comment string) error {
		var salt [8]byte
		copy(salt[:], []byte(saltSeed))

		var nonce [24]byte
		copy(nonce[:], []byte(nonceSeed))

		armoredCiphertext, err := encryptDeterministically(plaintext, passphrase, &salt, &nonce)
		if err != nil {
			return err
		}

		vectors = append(vectors, goldenVector{
			Plaintext:  base64.StdEncoding.EncodeToString(plaintext),
			Ciphertext: armoredCiphertext,
			Nonce:      base64.StdEncoding.EncodeToString(nonce[:]),
			Salt:       base64.StdEncoding.EncodeToString(salt[:]),
			Passphrase: base64.StdEncoding.EncodeToString([]byte(passphrase)),
			Comment:    comment,
		})
		return nil
	}

	if err := addVector([]byte{}, "testpass", "salt0000", "nonce000000000000000000", "empty plaintext"); err != nil {
		return err
	}

	if err := addVector([]byte("x"), "testpass", "salt0001", "nonce000000000000000001", "single byte plaintext"); err != nil {
		return err
	}

	if err := addVector([]byte("hello world"), "testpass", "salt0002", "nonce000000000000000002", "basic hello world"); err != nil {
		return err
	}

	if err := addVector([]byte{0, 0, 0, 0, 0}, "testpass", "salt0003", "nonce000000000000000003", "all zero bytes plaintext"); err != nil {
		return err
	}

	if err := addVector([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, "testpass", "salt0004", "nonce000000000000000004", "all 0xFF bytes plaintext"); err != nil {
		return err
	}

	binaryData := make([]byte, 256)
	for i := 0; i < 256; i++ {
		binaryData[i] = byte(i)
	}
	if err := addVector(binaryData, "testpass", "salt0005", "nonce000000000000000005", "all byte values 0-255 in plaintext"); err != nil {
		return err
	}

	largePlaintext := make([]byte, 10000)
	for i := range largePlaintext {
		largePlaintext[i] = byte(i % 256)
	}
	if err := addVector(largePlaintext, "testpass", "salt0006", "nonce000000000000000006", "large plaintext 10KB"); err != nil {
		return err
	}

	if err := addVector([]byte("Hello 世界 🌍"), "testpass", "salt0007", "nonce000000000000000007", "UTF-8 multibyte characters"); err != nil {
		return err
	}

	if err := addVector([]byte("secret"), "", "salt0008", "nonce000000000000000008", "empty passphrase"); err != nil {
		return err
	}

	longPass := string(make([]byte, 1000))
	if err := addVector([]byte("data"), longPass, "salt0009", "nonce000000000000000009", "very long passphrase"); err != nil {
		return err
	}

	if err := addVector([]byte("data"), "p@ss w0rd!🔐", "salt0010", "nonce000000000000000010", "passphrase with special chars"); err != nil {
		return err
	}

	if err := addVector([]byte("test"), "testpass", "\x00\x00\x00\x00\x00\x00\x00\x00", "nonce000000000000000011", "all zero salt"); err != nil {
		return err
	}

	if err := addVector([]byte("test"), "testpass", "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF", "nonce000000000000000012", "all 0xFF salt"); err != nil {
		return err
	}

	if err := addVector([]byte("test"), "testpass", "salt0013", "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", "all zero nonce"); err != nil {
		return err
	}

	if err := addVector([]byte("test"), "testpass", "salt0014", "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF", "all 0xFF nonce"); err != nil {
		return err
	}

	if err := addVector([]byte("line1\nline2\r\nline3\r"), "testpass", "salt0016", "nonce000000000000000016", "newlines in plaintext"); err != nil {
		return err
	}

	if err := addVector([]byte("saltybox1:fakedata"), "testpass", "salt0017", "nonce000000000000000017", "plaintext resembling format header"); err != nil {
		return err
	}

	veryLongPass := string(make([]byte, 10000))
	if err := addVector([]byte("x"), veryLongPass, "salt0018", "nonce000000000000000018", "tiny data, huge passphrase"); err != nil {
		return err
	}

	allBytes := make([]byte, 256)
	for i := 0; i < 256; i++ {
		allBytes[i] = byte(i)
	}

	if err := addVector([]byte("test"), string(allBytes), "salt0019", "nonce000000000000000019", "all byte values 0-255 in passphrase"); err != nil {
		return err
	}

	for i := 0; i < 32; i++ {
		saltStart := i * 8
		saltEnd := saltStart + 8
		saltStr := string(allBytes[saltStart:saltEnd])
		comment := fmt.Sprintf("all byte values %d-%d in salt", saltStart, saltEnd-1)
		nonceID := fmt.Sprintf("nonce00000000000000000%02d", 20+i)
		if err := addVector([]byte("test"), "testpass", saltStr, nonceID, comment); err != nil {
			return err
		}
	}

	for i := 0; i < 10; i++ {
		nonceStart := i * 24
		nonceEnd := nonceStart + 24
		nonceStr := string(allBytes[nonceStart:nonceEnd])
		comment := fmt.Sprintf("all byte values %d-%d in nonce", nonceStart, nonceEnd-1)
		saltID := fmt.Sprintf("salt00%02d", 52+i)
		if err := addVector([]byte("test"), "testpass", saltID, nonceStr, comment); err != nil {
			return err
		}
	}
	// Final nonce test with remaining 16 bytes (240-255)
	nonceStr := string(allBytes[240:256])
	// Pad to 24 bytes
	noncePadded := nonceStr + string([]byte{0, 0, 0, 0, 0, 0, 0, 0})
	if err := addVector([]byte("test"), "testpass", "salt0062", noncePadded, "all byte values 240-255 in nonce"); err != nil {
		return err
	}

	// Sort by ciphertext for stability (primarily so that this code
	// can be modified and generate reasonable diffs in generated test
	// data).
	sort.Slice(vectors, func(i, j int) bool {
		return vectors[i].Ciphertext < vectors[j].Ciphertext
	})

	f, err := os.Create("testdata/golden-vectors.json")
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := f.Close(); closeErr != nil && err == nil {
			err = closeErr
		}
	}()

	encoder := json.NewEncoder(f)
	encoder.SetIndent("", "  ")
	if err = encoder.Encode(vectors); err != nil {
		return err
	}

	return nil
}

func validateGolden() error {
	data, err := os.ReadFile("testdata/golden-vectors.json")
	if err != nil {
		return fmt.Errorf("failed to read golden vectors: %w", err)
	}

	var vectors []goldenVector
	if err := json.Unmarshal(data, &vectors); err != nil {
		return fmt.Errorf("failed to parse golden vectors: %w", err)
	}

	fmt.Printf("Validating %d golden vectors...\n", len(vectors))

	failCount := 0
	for i, v := range vectors {
		plaintext, err := base64.StdEncoding.DecodeString(v.Plaintext)
		if err != nil {
			fmt.Printf("FAIL [%d] %s: failed to decode plaintext: %v\n", i, v.Comment, err)
			failCount++
			continue
		}

		passphrase, err := base64.StdEncoding.DecodeString(v.Passphrase)
		if err != nil {
			fmt.Printf("FAIL [%d] %s: failed to decode passphrase: %v\n", i, v.Comment, err)
			failCount++
			continue
		}

		cipherBytes, err := varmor.Unwrap(v.Ciphertext)
		if err != nil {
			fmt.Printf("FAIL [%d] %s: failed to unarmor ciphertext: %v\n", i, v.Comment, err)
			failCount++
			continue
		}

		decrypted, err := secretcrypt.Decrypt(string(passphrase), cipherBytes)
		if err != nil {
			fmt.Printf("FAIL [%d] %s: failed to decrypt: %v\n", i, v.Comment, err)
			failCount++
			continue
		}

		if string(decrypted) != string(plaintext) {
			fmt.Printf("FAIL [%d] %s: plaintext mismatch (expected %d bytes, got %d bytes)\n", i, v.Comment, len(plaintext), len(decrypted))
			failCount++
			continue
		}

		fmt.Printf("PASS [%d] %s\n", i, v.Comment)
	}

	if failCount > 0 {
		return fmt.Errorf("%d of %d tests failed", failCount, len(vectors))
	}

	fmt.Printf("\nAll %d tests passed!\n", len(vectors))
	return nil
}
