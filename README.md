<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->
**Table of Contents**  *generated with [DocToc](https://github.com/thlorenz/doctoc)*

- [Introduction](#introduction)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Features and limitations](#features-and-limitations)
- [Guidance for use](#guidance-for-use)
  - [Use `update` whenever possible](#use-update-whenever-possible)
  - [Keep a copy of saltybox](#keep-a-copy-of-saltybox)
- [Format/API contract](#formatapi-contract)
- [Important crypto disclaimer](#important-crypto-disclaimer)
- [Details: Encrypted File Format (saltybox format version 1)](#details-encrypted-file-format-saltybox-format-version-1)
  - [Armored (Text) Format](#armored-text-format)
  - [Binary Format](#binary-format)
    - [Key Derivation](#key-derivation)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

# Introduction

Saltybox is a tool for encrypting files with a passphrase.

Its primary intended use-case is for encrypting small amounts of personal data for safe keeping on untrusted media
(physical or otherwise).

# Requirements

* Go 1.21 or later is required to be [installed](https://golang.org/doc/install).

# Installation

```
 $ go install github.com/scode/saltybox@latest
```

Assuming `$GOPATH/bin` (default: `~/go/bin`) is in your `$PATH`, saltybox is now ready
to use.

If you decide to use saltybox for anything important, please review
[guidance for use](#guidance-for-use).

# Usage

Here's how to encrypt a file (you will be interactively prompted for a
passphrase):

```
./saltybox encrypt -i allmysecrets.txt -o allmysecrets.txt.saltybox
```

And here is how to decrypt it afterwards (again, you will be
interactively prompted for a passphrase):

```
./saltybox decrypt -i allmysecrets.txt.saltybox -o allmysecrets.txt
```

And here is how to update a previously encrypted file in a manner that
ensures the passphrase is not accidentally changed:

```
./saltybox update -i allmysecrets-updated.txt -o allmysecrets.txt.saltybox
```

# Features and limitations

* Files must fit comfortably in memory and there is no support for encrypting a stream in an incremental fashion.
* There is no attempt to lock the passphrase or derived key into memory. The passphrase may be paged to disk by the operating system. You are responsible for the security of the device on which you run this program.
* The format is based upon well known algorithms with exceedingly
  simple layering on top. scrypt is used for key stretching, nacl is
  used for encryption, and a base64 variant is used for encoding.
* The amount of code is relatively small and light on dependencies.

# Guidance for use

## Use `update` whenever possible

Always use `update` when updating an existing
encrypted file. This avoids the possibility of accidentally changing
the passphrase by providing a different passphrase than what was used
to encrypt the existing file. If you manually decrypt and re-encrypt,
you lose this protection.

## Keep a copy of saltybox

It is important to consider the possibility that saltybox disappears from github,
or stops building because a dependency has changed or becomes unavailable. In order to ensure
that you are able to decrypt your data if such a thing were to happen, the following steps
are recommended:

* Store a copy of the binary for your platform(s) in a safe place.
* In a copy of the source code, run `go mod vendor` to download all necessary dependencies
  into the `vendor` directory. Ensure saltybox builds with `go build -mod=vendor`. Then
  store a copy of the complete source tree (including `vendor`) in a safe place.

In an emergency need to decrypt data, this should maximize your chances of being able to do so without
relying on external projects/people aside from the Go language tools themselves remaining available.

# Format/API contract

* Future versions if any will remain able to decrypt data encrypted by
  older versions.
* The command line interface may change at any time. It is currently not
  intended for automated scripting (for this reason and others).
* The code in this project is not meant to be consumed as a library and may
  be refactored or changed at will. It's possible this changes in the future,
  but if so it will be explicitly made clear.

# Important crypto disclaimer

I am not a cryptographer and the code has not been reviewed by any
cryptographers. Are you one? Please send me feedback
(peter.schuller@infidyne.com).

Although I certainly did not attempt to invent any new cryptographic
primitives and rather use well established trusted primitives, there
is generally a risk that cryptographic primitives are used incorrectly
when composed into a larger program.

Unfortunately, I have not been able to find a tool like this that
satisfies my personal criteria for what I want to depend on for
emergency life recovery media.

# Details: Encrypted File Format (saltybox format version 1)

Saltybox encrypts files using a passphrase-based encryption scheme. The output is a text file
containing an armored (ASCII text) string that represents the encrypted data. This section
documents the format.

## Armored (Text) Format

- The contents of the file starts with the string `saltybox1:` which identifies the format.
- This is followed by a base64 encoded (RFC 4648, no padding) payload whose format is described below ("binary format").
- Example: `saltybox1:RF0qX8mpCMXVBq6zxHfamdiT64s6Pwvb99Qj9gV61sMAAAAAAAAAFE6RVTWMhBCMJGL0MmgdDUBHoJaW`
  - The `1` in the prefix indicates the format version. Future versions would use a different version
    number (e.g., `saltybox2:`).

## Binary Format

The binary format contains the following, in order:

  1. **Salt** (8 bytes): Random salt used for key derivation.
  2. **Nonce** (24 bytes): Random nonce for the NaCl secretbox encryption.
  3. **Length** (8 bytes): Big-endian encoded signed 64-bit integer (int64) indicating the
    number of bytes in the sealed box that follows. This value must be non-negative and must
    not exceed the remaining length of the input data after the salt, nonce, and length fields.
    During decryption, invalid lengths (negative, too large, or causing truncation) are
    rejected as format errors.
  4. **Sealed Box** (variable length, as specified by the length field): The encrypted payload,
     sealed using NaCl's `secretbox` (XSalsa20 stream cipher with Poly1305 MAC). The sealed box
     contains the user's plaintext exactly - without any padding or additional metadata.

The encryption key is derived from the user-provided passphrase and the salt using scrypt
with parameters:

  - N = 32768
  - r = 8
  - p = 1
  - Key length = 32 bytes
