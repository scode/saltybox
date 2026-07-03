# saltybox specification

This document specifies saltybox's user-visible behavior: the command-line interface and the on-disk file formats. It is
a specification of behavior — what users and other implementations can rely on — not documentation of the
implementation. Implementation details do not belong here.

NOTE: Coverage is deliberately incremental. Behavior not described here is existing-but-unspecified, not nonexistent.
When a change touches user-visible behavior, the touched area must be specified — including its pre-existing behavior —
in the same change. `AGENTS.md` states the compliance rule.

## Commands

All commands take a passphrase: interactively from the terminal with echo disabled, or — when the global
`--passphrase-stdin` option is given — from standard input, read to end-of-input and used exactly as provided (trailing
newlines are NOT stripped, and the passphrase need not be valid UTF-8). On any failure, commands exit with a nonzero
status and report the error on standard error.

Commands write their output file atomically via a same-directory private temporary file: on success the output contains
exactly the intended bytes; on any failure an existing file at the output path is left unchanged and no partial file
ever appears there. A failed or interrupted write may leave the temporary file (owner-only permissions, name prefixed
`.saltybox-`) behind in the output directory; rename failures report its path. On Unix the final output file mode
is 0600.

### encrypt

`saltybox encrypt -i <input> -o <output>` reads plaintext from `<input>` — any byte sequence, including empty — and
writes one armored saltybox unit to `<output>`. The output format is selected by the write-format override described
below; by default the saltybox1 format is written. The output format never depends on any existing file. Salt and nonce
are freshly generated at random for every encryption, so encrypting the same input twice produces different output.

### decrypt

`saltybox decrypt -i <input> -o <output>` reads an armored saltybox file from `<input>` and writes the decrypted
plaintext to `<output>`.

Accepted input: a file whose entire contents are valid UTF-8 consisting of one armored saltybox unit in any supported
format (see File formats). The format is selected by the magic prefix; both `saltybox1` and `saltybox2` inputs are
accepted.

Failures are diagnosed per scenario, each with a distinct message:

- Input that is not valid UTF-8 is rejected before any format interpretation.
- Input that is a proper prefix of a supported magic (including empty input) is rejected as likely truncated.
- Input starting with `saltybox` that matches no supported version's magic is rejected as an unsupported (future)
  version.
- Input not recognizable as saltybox data at all is rejected as unrecognized.
- Input with a supported magic whose base64 body fails to decode is rejected as an armor decoding error.
- Structurally malformed binary payloads — truncated fields, invalid length fields, out-of-range key-derivation
  parameters, trailing data where the format forbids it — are rejected as format errors with a diagnostic specific to
  the failure. These are deliberately distinct from authentication failures.
- A wrong passphrase, or sealed data that has been tampered with or corrupted, is rejected with a single
  authentication-failure diagnostic. There is no way to tell programmatically (or otherwise) which of the two occurred;
  they are cryptographically indistinguishable.

### update

`saltybox update -i <input> -o <existing>` replaces the contents of the existing encrypted file `<existing>` with newly
encrypted plaintext from `<input>`, validating first that the passphrase matches the existing file (preventing
accidental passphrase changes). `<input>` and `<existing>` must be different files; identical paths and aliases of the
same file (via symlinks, path traversal, or hard links) are rejected.

The validation read decrypts `<existing>` and accepts the same formats as `decrypt`, with the same failure taxonomy. Any
failure — including a wrong passphrase — aborts the update and leaves `<existing>` unchanged.

On successful validation, the new plaintext is encrypted with the validated passphrase and written atomically over
`<existing>`. The output format is a function of the write-format override alone (below), never of the existing file's
format: with the override unset, updating a saltybox2 file rewrites it as saltybox1 — a format downgrade.

### Experimental write-format override

NOTE: `SALTYBOX_EXPERIMENTAL_V2` is experimental and scheduled for removal when saltybox2 becomes the default write
format. Do not build automation on it.

The environment variable `SALTYBOX_EXPERIMENTAL_V2` selects the format that `encrypt` and `update` write:

- Unset: saltybox1 is written.
- Set to exactly `1`: saltybox2 is written, with Argon2 parameters m=262144 KiB, t=3, p=1.
- Set to any other value (including values that are not valid Unicode): write commands fail with an error naming the
  variable, rather than guessing.

`decrypt` ignores the variable entirely, including invalid values.

## File formats

An armored saltybox unit is an ASCII magic prefix (`saltybox1:` or `saltybox2:`) directly followed by the base64url
encoding (RFC 4648 URL-safe alphabet, no padding) of a binary payload. Armored data contains no whitespace and is safe
to embed in URLs and to pass unescaped to a POSIX shell. Base64 bodies must be canonical: padding characters and
non-canonical trailing bits are rejected.

### saltybox1

Binary payload layout, in order:

- salt: 8 bytes
- nonce: 24 bytes
- length: 8 bytes, big-endian signed 64-bit integer; the byte length of the sealed box that follows. Negative values,
  and values exceeding the available input, are rejected as format errors.
- sealed box: NaCl secretbox (XSalsa20-Poly1305) output — a 16-byte Poly1305 tag followed by the ciphertext. The sealed
  box is always exactly 16 bytes longer than the plaintext; the plaintext is encrypted as provided, with no padding and
  no metadata.

Data after the sealed box is rejected as a format error.

Key derivation: scrypt over the passphrase and salt with N=32768 (2^15), r=8, p=1, producing a 32-byte key. These
parameters are fixed properties of the saltybox1 format.

### saltybox2

Binary payload layout, in order:

- salt: 16 bytes
- m: unsigned 32-bit big-endian integer, Argon2 memory cost in KiB
- t: unsigned 32-bit big-endian integer, Argon2 time cost (passes)
- p: unsigned 32-bit big-endian integer, Argon2 parallelism (lanes)
- nonce: 24 bytes
- sealed data: XChaCha20-Poly1305 output — the ciphertext followed by a 16-byte Poly1305 tag — extending to the end of
  the payload. There is no length field, and trailing data is therefore impossible by construction. Empty plaintext is
  valid: the sealed data is then exactly the 16-byte tag.

Key derivation: Argon2id version 0x13 over the passphrase and salt with the m, t, p values from the header, producing a
32-byte key. The Argon2 version and key length are fixed properties of the saltybox2 format.

Key-derivation parameters are validated BEFORE any key derivation work, so a hostile file cannot cause large memory or
CPU consumption via its header. The accepted ranges are:

- t: at least 1, at most 64
- p: at least 1, at most 8
- m: at most 4194304 KiB (4 GiB), and at least 8×p KiB (the Argon2 minimum)

Out-of-range parameters are a format error, deliberately distinct from authentication failure. Any in-range parameter
combination decrypts normally; readers must not assume files were written with any particular parameter values.

The AEAD associated data is the ASCII armor magic `saltybox2:` concatenated with the entire header (salt, m, t, p,
nonce). A successful decrypt therefore proves the whole envelope — version identifier included — was untampered.
