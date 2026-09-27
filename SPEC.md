# saltybox specification

This document specifies saltybox's user-visible behavior (the command-line interface and the on-disk file formats) and
the few project-level rules that constrain what saltybox is and how it is built (see Project scope and Build integrity).
It is a specification of what users and other implementations can rely on, not documentation of the implementation.
Implementation details do not belong here.

NOTE: Coverage is deliberately incremental. Behavior not described here is existing-but-unspecified, not nonexistent.
When a change touches user-visible behavior, the touched area must be specified — including its pre-existing behavior —
in the same change. `AGENTS.md` states the compliance rule.

## Project scope

saltybox is a program, not a library. Its contracts are the command-line interface and the on-disk file formats this
document describes, and nothing else. The Rust crate happens to be split into a library and a binary, but that split is
an implementation convenience: the library's public items exist only to serve the `saltybox` binary and make no
affordances for external consumers. Behavior that is reachable only by calling the library directly, and not through the
command line, is not part of any contract.

## Build integrity

Every `uses:` reference in a GitHub Actions workflow (a step's action or a job's reusable workflow) to anything outside
this repository pins it by full commit SHA (or, for a container image, by digest), never by a tag or branch, with the
version that SHA corresponds to in a trailing comment (for example `actions/checkout@<40-hex-sha> # v5.1.0`). A tag or
branch can be moved by whoever controls the action's repository, and every later run would then silently execute the new
code; a commit SHA cannot be moved. The rule covers `uses:` references only: the Rust toolchain version, runner images,
and tools that workflow steps download and run are not covered. `AGENTS.md` describes how to upgrade a pinned action.

## Supported platforms

saltybox is supported on Unix-like systems (Linux and macOS). Windows is not supported: the code may compile there, but
no Windows binaries are released, nothing is tested on Windows, and the file-permission guarantees below are
deliberately Unix-only. Output and temporary files written on Windows carry no access restriction beyond what the output
directory grants.

## Commands

All commands take a passphrase: interactively from the terminal with echo disabled, or — when the global
`--passphrase-stdin` option is given — from standard input, read to end-of-input and used exactly as provided (nothing
is stripped, and the passphrase need not be valid UTF-8). A failure to read standard input under `--passphrase-stdin` (a
broken pipe, an unreadable redirect) is a user error reported as a passphrase read failure with the underlying cause,
not an internal failure. Without `--passphrase-stdin`, commands fail when standard input is not a terminal rather than
attempting to read a passphrase. Conversely, with `--passphrase-stdin`, commands fail when standard input is a terminal:
that input is read with echo on, so a passphrase typed there would be printed as it is typed and kept in the terminal's
scrollback. Omitting the option gives the no-echo prompt instead.

An empty passphrase is an error for every command, regardless of how the passphrase was provided: it offers no
meaningful protection, and empty input almost always means a mistake (an unset shell variable expands to empty) rather
than intent. NOTE: this makes files encrypted with an empty passphrase by older versions undecryptable by these
commands. A passphrase containing a line break (a `\n` or `\r` byte) anywhere is likewise an error for every command:
`echo "$PASS"` without `-n` appends a newline the user never meant to choose, and with `PASS` unset the passphrase is
that newline alone. Pipe the passphrase without one (`echo -n`, `printf '%s' "$PASS"`). NOTE: this makes files encrypted
by older versions with a passphrase containing a line break undecryptable by these commands.

On any failure, commands exit with a nonzero status and report the error on standard error. The one exception is a
process killed for lack of memory during key derivation, which the saltybox2 section describes.

Any I/O failure on a path the user supplied (an input file, the output file, or the output file's directory) is a user
error: a missing file, a directory given where a file was expected, a permission denial, or an unwritable output
directory are all the caller's environment. Internal failures are reserved for operations on paths the program chose
itself, such as writing and syncing its own temporary file.

Commands write their output file atomically via a same-directory temporary file (private on Unix; see Supported
platforms): on success the output contains exactly the intended bytes, and no partial file ever appears at the output
path under any circumstances. On any failure before the atomic rename, an existing file at the output path is left
unchanged. (One narrow exception to "unchanged on failure": if making the rename durable fails after the rename itself
succeeded, the output has already been replaced — with complete contents — while the command still exits nonzero.) A
write interrupted by a crash or a signal (such as Ctrl-C) may leave the temporary file (on Unix with owner-only
permissions; name prefixed `.saltybox-`) behind in the output directory. Any failure the command itself detects after
creating the temporary file, including a failed rename, removes it; if that removal also fails, the error names the
temporary file so it can be removed by hand. Failures before the temporary file is created (such as an unusable output
directory) leave nothing behind and are reported without implying a write took place; a nonexistent output directory is
reported as such, an empty output path is rejected as such (like an empty passphrase, it almost always means an unset
shell variable), and so is an output path that ends in a path separator, which can only name a directory
(`-o "$DIR/$NAME"` with `NAME` unset produces one). On Unix the final output file mode is 0600.

When the output path is a symbolic link, or a chain of them, commands follow it and replace the file it ultimately
points to: the temporary file is created in that file's directory and renamed onto that file, and the link itself is
left in place. The file `update` validates the passphrase against and the file it replaces are therefore always the same
file. An output symlink whose target does not exist is rejected as a user error rather than followed to create the
target. When writing, hard links get no special treatment: the output path's name is replaced like any other file, and
other names for the old file keep its old contents.

On Unix, the directory the output file is written in (for a symlinked output path, the directory of the file it points
to) must be readable as well as writable. It is opened before the temporary file is created, so that the directory can
be synced after the rename and the new directory entry survives a crash. A directory that cannot be opened for reading
(for example a write-only drop-box directory) is therefore refused as a user error, even though creating a file in it
would otherwise succeed.

### encrypt

`saltybox encrypt -i <input> -o <output>` reads plaintext from `<input>` — any byte sequence, including empty — and
writes one armored saltybox unit to `<output>` in the saltybox2 format, with Argon2 parameters m=262144 KiB, t=3, p=1.
The output format never depends on any existing file. Salt and nonce are freshly generated at random for every
encryption, so encrypting the same input twice produces different output.

When the passphrase is read interactively from the terminal, `encrypt` asks for it twice and fails with a user error,
writing nothing, if the two entries differ. The prompt has echo disabled, so a typo would otherwise become the
passphrase of a file nobody can decrypt. There is no second entry with `--passphrase-stdin`, and none for `decrypt` or
`update`, where the existing file already confirms the passphrase.

saltybox1 output cannot be produced: that format is decrypt-only. Consequently, files written by this version cannot be
read by saltybox versions that predate saltybox2 support.

### decrypt

`saltybox decrypt -i <input> -o <output>` reads an armored saltybox file from `<input>` and writes the decrypted
plaintext to `<output>`.

Accepted input: a file whose entire contents are valid UTF-8 consisting of one armored saltybox unit in any supported
format (see File formats). The format is selected by the magic prefix; both `saltybox1` and `saltybox2` inputs are
accepted.

Failures are diagnosed per scenario, each with a distinct message:

- Input that is not valid UTF-8 is rejected before any format interpretation.
- Input that is a proper prefix of a supported magic (including empty input) is rejected as likely truncated.
- Input starting with `saltybox` that neither matches a supported magic nor is a proper prefix of one is rejected as an
  unsupported (future) version.
- Input not recognizable as saltybox data at all is rejected as unrecognized.
- saltybox2 input that does not end with the `:end` marker is rejected as likely truncated, with a message naming the
  missing marker (a plain-text aid; not a cryptographic check).
- Input with a supported magic whose base64 body fails to decode is rejected as an armor decoding error.
- saltybox1 input ending in whitespace, such as a final newline, is rejected with a message naming the trailing
  whitespace rather than as a generic decoding error. saltybox1 allows no whitespace at all (unlike saltybox2, which
  ignores whitespace after `:end`), so such a file only decrypts once the whitespace is removed.
- Structurally malformed binary payloads — truncated fields, invalid length fields, out-of-range key-derivation
  parameters, trailing data where the format forbids it — are rejected as format errors with a diagnostic specific to
  the failure. These are deliberately distinct from authentication failures.
- A wrong passphrase, or sealed data that has been tampered with or corrupted, is rejected with a single
  authentication-failure diagnostic. There is no way to tell programmatically (or otherwise) which of the two occurred;
  they are cryptographically indistinguishable. "Single" is a promise within a format: the two causes share one
  diagnostic, so nothing about the message reveals which one occurred. The wording may differ between saltybox1 and
  saltybox2, since the format is already public from the magic prefix and reveals nothing about the cause.

### update

`saltybox update -i <input> -o <existing>` replaces the contents of the existing encrypted file `<existing>` with newly
encrypted plaintext from `<input>`, validating first that the passphrase matches the existing file (preventing
accidental passphrase changes). `<input>` and `<existing>` must be different files; identical paths and aliases of the
same file via symlinks or path traversal are rejected, and on Unix, hard-link aliases are rejected as well.

The validation read decrypts `<existing>`, accepting the same formats as `decrypt` and failing in the same scenarios
with the same classifications (messages may differ in how they name the input file). Any failure — including a wrong
passphrase — aborts the update and leaves `<existing>` unchanged.

On successful validation, the new plaintext is encrypted with the validated passphrase and written atomically over
`<existing>`, always in the current write format (saltybox2), regardless of the existing file's format. Updating a
saltybox1 file therefore rewrites it as saltybox2: this is the intended migration path for upgrading old files.

## File formats

An armored saltybox unit is an ASCII magic prefix identifying the format version, directly followed by the base64url
encoding (RFC 4648 URL-safe alphabet, no padding) of a binary payload:

- saltybox1: `saltybox1:` followed by the payload.
- saltybox2: `saltybox2:` followed by the payload, terminated by the literal marker `:end`.

Armored data contains no whitespace and is safe to embed in URLs and to pass unescaped to a POSIX shell. Base64 bodies
must be canonical: padding characters and non-canonical trailing bits are rejected.

The saltybox2 `:end` marker is a plain-text truncation aid: armored text gets copy-pasted, and a paste that loses its
tail is rejected up front with a message attributing the rejection to the missing marker. The marker is deliberately not
covered by any cryptographic check, and its presence proves nothing about integrity — that is solely the job of the
sealed data's authentication tag. Trailing whitespace after the marker — any character with the Unicode White_Space
property — is accepted and ignored: files routinely end with a newline, and a complete unit followed by whitespace is
not truncated.

### saltybox1

Binary payload layout, in order:

- salt: 8 bytes
- nonce: 24 bytes
- length: 8 bytes, big-endian signed 64-bit integer; the byte length of the sealed box that follows. Negative values,
  values below 16 (a sealed box is never shorter than its tag), and values exceeding the available input, are rejected
  as format errors.
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

Key-derivation parameters are validated BEFORE any key derivation work, so the memory and CPU a file's header can demand
is bounded by the ceilings below rather than by the 32-bit fields. The accepted ranges are:

- t: at least 1, at most 64
- p: at least 1, at most 8
- m: at most 4194304 KiB (4 GiB), and at least 8×p KiB (the Argon2 minimum)

Out-of-range parameters are a format error, deliberately distinct from authentication failure. Any in-range parameter
combination decrypts normally; readers must not assume files were written with any particular parameter values.

The ceilings are deliberately far above the write defaults, and that is a trade-off, not an oversight: a file from an
untrusted source can legitimately cost up to the full ceiling (4 GiB of memory and 64 passes) before it fails
authentication. The ceilings are wide so that files written with stronger-than-default parameters, by this or any other
implementation, stay readable; they are a format constant, and lowering them would make existing files undecryptable.
Users decrypting files from untrusted senders should expect that worst case, and readers must not tighten the ranges.

If the machine cannot supply the memory key derivation needs (the header's m when decrypting or validating an update,
256 MiB when encrypting), the command fails with a user error saying how much memory was required. On systems that
overcommit memory (Linux does by default), the allocation can appear to succeed and the operating system's out-of-memory
killer can terminate the process later, while the memory is in use, before saltybox can report anything on standard
error. Either way the command does not succeed, and since key derivation happens before any output is written, output
files (including the existing file for `update`) are left unchanged.

The AEAD associated data is the ASCII armor magic `saltybox2:` concatenated with the entire header (salt, m, t, p,
nonce). A successful decrypt therefore proves the whole envelope — version identifier included — was untampered.
