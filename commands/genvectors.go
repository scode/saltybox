package commands

import (
    "crypto/rand"
    "encoding/csv"
    "fmt"
    mrand "math/rand"
    "os"
    "strings"

    "github.com/scode/saltybox/varmor"
)

// GenerateVectors writes a CSV file with columns: passphrase, plaintext, ciphertext.
//
// The generator reuses the project's existing encoding and crypto primitives:
//   - Plaintext is emitted using varmor.Wrap(plaintextBytes) to ensure it is URL/CSV safe.
//   - Ciphertext is produced by encryptBytes(passphrase, plaintextBytes) which calls
//     secretcrypt.Encrypt() and then varmor.Wrap() on the result.
//
// Each test case category below is documented to explain its purpose and the edge case it exercises.
func GenerateVectors(outputPath string, maxRows int, seed int64) error {
    if maxRows <= 0 {
        return fmt.Errorf("maxRows must be positive; got %d", maxRows)
    }

    f, err := os.Create(outputPath)
    if err != nil {
        return fmt.Errorf("failed to create %s: %w", outputPath, err)
    }
    defer func() {
        _ = f.Close()
    }()

    writer := csv.NewWriter(f)
    defer writer.Flush()

    if err := writer.Write([]string{"passphrase", "plaintext", "ciphertext"}); err != nil {
        return fmt.Errorf("failed to write CSV header: %w", err)
    }

    // Deterministic generator for reproducibility of plaintext/passphrase selection.
    // Note: secretcrypt.Encrypt() uses crypto/rand internally for salt and nonce,
    // so ciphertext will differ across runs even with the same seed; this is expected and desired.
    r := mrand.New(mrand.NewSource(seed))

    // Helper to write one test case row.
    writeCase := func(passphrase string, plaintext []byte) error {
        // Armor plaintext bytes to keep the CSV fully text-safe while still losslessly representing bytes.
        armoredPlain := varmor.Wrap(plaintext)

        // Produce varmored ciphertext using the project commands helper.
        armoredCipher, err := encryptBytes(passphrase, plaintext)
        if err != nil {
            return err
        }

        // Very small sanity check: decrypt and ensure round-trip (defensive programming).
        // We intentionally ignore the error context here; any failure indicates vector emission bug.
        plainRT, err := decryptString(passphrase, armoredCipher)
        if err != nil {
            return fmt.Errorf("round-trip decrypt failed: %w", err)
        }
        if !bytesEqual(plaintext, plainRT) {
            return fmt.Errorf("round-trip plaintext mismatch")
        }

        return writer.Write([]string{passphrase, armoredPlain, armoredCipher})
    }

    rowsWritten := 0

    // CATEGORY 1: Empty values and minimal sizes
    // - Empty plaintext and/or empty passphrase hit edge handling around zero-length inputs.
    {
        cases := []struct{
            pass string
            plain []byte
        }{
            {"", []byte("")},                 // both empty
            {"", []byte("hello")},           // empty passphrase
            {"test", []byte("")},           // empty plaintext
            {" ", []byte(" ")},              // single space values
            {"\t", []byte("\t")},          // tab characters
        }
        for _, c := range cases {
            if rowsWritten >= maxRows {
                return nil
            }
            if err := writeCase(c.pass, c.plain); err != nil {
                return err
            }
            rowsWritten++
        }
    }

    // CATEGORY 2: ASCII texts with CSV-tricky characters
    // - Exercise quoting, commas, quotes, and newlines in passphrase while keeping plaintext armored.
    {
        passphrases := []string{
            `simple`,
            `comma,separated`,
            `with "quotes" inside`,
            "line1\nline2",
            "trailing,comma,",
        }
        plains := [][]byte{
            []byte("hello world"),
            []byte("the quick brown fox jumps over the lazy dog"),
            []byte(strings.Repeat("A", 100)),
        }
        for _, p := range passphrases {
            for _, b := range plains {
                if rowsWritten >= maxRows {
                    return nil
                }
                if err := writeCase(p, b); err != nil {
                    return err
                }
                rowsWritten++
            }
        }
    }

    // CATEGORY 3: Unicode and complex scripts in passphrase and plaintext
    // - Ensure UTF-8 handling works across different scripts and emoji.
    {
        passphrases := []string{
            "pässwörd",
            "пароль",
            "密碼",
            "كلمةالسر",
            "🙂🔥🔒",
            "a\u0301", // combining acute accent
            "עברית-RTL",
        }
        plains := [][]byte{
            []byte("こんにちは世界"),
            []byte("안녕하세요 세계"),
            []byte("😀🍕📦 varmor test 🧪"),
            []byte("𝔘𝔫𝔦𝔠𝔬𝔡𝔢 𝕋𝕖𝕤𝕥"),
        }
        for _, p := range passphrases {
            for _, b := range plains {
                if rowsWritten >= maxRows {
                    return nil
                }
                if err := writeCase(p, b); err != nil {
                    return err
                }
                rowsWritten++
            }
        }
    }

    // CATEGORY 4: All byte values (0..255) and zero bytes patterns
    // - Validates that every possible byte value survives armoring and encryption.
    {
        all := make([]byte, 256)
        for i := 0; i < 256; i++ {
            all[i] = byte(i)
        }
        if rowsWritten < maxRows {
            if err := writeCase("all-bytes-pass", all); err != nil {
                return err
            }
            rowsWritten++
        }

        if rowsWritten < maxRows {
            zeros := make([]byte, 1024)
            if err := writeCase("zeros", zeros); err != nil {
                return err
            }
            rowsWritten++
        }
    }

    // CATEGORY 5: Random byte payloads around interesting size boundaries
    // - Includes off-by-one sizes near 16/24/32/64 and larger blobs.
    // - Note: We keep the count small because scrypt key-derivation is intentionally expensive.
    {
        sizes := []int{1, 2, 15, 16, 17, 23, 24, 25, 31, 32, 33, 63, 64, 65, 128, 1024, 4096}
        buf := make([]byte, 65536)
        // Fill a buffer once with crypto randomness and slice as needed for variety.
        // Fall back to math/rand if crypto/rand fails (extremely unlikely).
        if _, err := rand.Read(buf); err != nil {
            for i := range buf {
                buf[i] = byte(r.Intn(256))
            }
        }
        for _, sz := range sizes {
            if rowsWritten >= maxRows {
                return nil
            }
            payload := make([]byte, sz)
            copy(payload, buf[:sz])
            if err := writeCase(fmt.Sprintf("rand-%d", sz), payload); err != nil {
                return err
            }
            rowsWritten++
        }
    }

    // CATEGORY 6: Repeated patterns and structured plaintexts
    // - Highlights potential weaknesses if patterns were visible (they should not be in ciphertext).
    {
        patterns := []string{
            strings.Repeat("A", 512),
            strings.Repeat("AB", 512),
            strings.Repeat("\u0000\u0001", 512),
            "{\"key\":\"value\",\"arr\":[1,2,3],\"nested\":{\"a\":true}}",
            "<xml><a>1</a><b>2</b></xml>",
        }
        for idx, s := range patterns {
            if rowsWritten >= maxRows {
                return nil
            }
            if err := writeCase(fmt.Sprintf("pattern-%d", idx+1), []byte(s)); err != nil {
                return err
            }
            rowsWritten++
        }
    }

    // CATEGORY 7: Long passphrases and edge whitespace
    // - Very long passphrases, leading/trailing whitespace, and mixed whitespace forms.
    {
        long := strings.Repeat("p", 4096)
        pws := []string{
            long,
            "  leading space",
            "trailing space  ",
            "\t tabs and spaces \t",
            "multi\nline\npassphrase",
        }
        for _, pw := range pws {
            if rowsWritten >= maxRows {
                return nil
            }
            if err := writeCase(pw, []byte("passphrase stress test payload")); err != nil {
                return err
            }
            rowsWritten++
        }
    }

    // CATEGORY 8: Random fuzz pairs (lightweight)
    // - Produces additional coverage without exploding runtime. Keep count modest.
    {
        extra := 50
        for i := 0; i < extra && rowsWritten < maxRows; i++ {
            // Random passphrase of length 1..32, including some non-ASCII.
            plen := 1 + r.Intn(32)
            var sb strings.Builder
            for j := 0; j < plen; j++ {
                // Mix of ranges: ASCII, extended Latin, emoji slices.
                switch r.Intn(4) {
                case 0:
                    sb.WriteByte(byte(32 + r.Intn(95)))
                case 1:
                    sb.WriteRune(rune(0x00C0 + r.Intn(0x017F-0x00C0)))
                case 2:
                    sb.WriteRune(rune(0x0400 + r.Intn(0x04FF-0x0400)))
                default:
                    sb.WriteRune(rune(0x1F600 + r.Intn(0x1F64F-0x1F600)))
                }
            }
            // Random payload size 0..256
            psz := r.Intn(257)
            plain := make([]byte, psz)
            for j := range plain {
                plain[j] = byte(r.Intn(256))
            }
            if err := writeCase(sb.String(), plain); err != nil {
                return err
            }
            rowsWritten++
        }
    }

    return nil
}

// bytesEqual is a tiny inlined equivalent of bytes.Equal to avoid importing the whole package here,
// keeping dependencies minimal in this helper file.
func bytesEqual(a, b []byte) bool {
    if len(a) != len(b) {
        return false
    }
    for i := range a {
        if a[i] != b[i] {
            return false
        }
    }
    return true
}

