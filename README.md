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

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

# Introduction

Saltybox is a tool for encrypting files with a passphrase.

Its primary intended use-case is for encrypting small amounts of personal data for safe keeping on untrusted media
(physical or otherwise).

# Requirements

* Go 1.11 or later is required to be [installed](https://golang.org/doc/install).

# Installation

```
 $ GO111MODULE=on go get github.com/scode/saltybox
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
* There is no attempt to lock the passphrase or derived key into memory. The passphrase may be paged to disk by
  the operating system. You are responsible for the security of the device on which you run this program.
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
