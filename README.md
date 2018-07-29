<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->
**Table of Contents**  *generated with [DocToc](https://github.com/thlorenz/doctoc)*

- [Introduction](#introduction)
- [Building](#building)
- [Usage](#usage)
- [Important crypto disclaimer](#important-crypto-disclaimer)
- [Notable features](#notable-features)
- [Guidance for use](#guidance-for-use)
- [Format/API contract](#formatapi-contract)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

# Introduction

Saltybox is a minimalistic tool that implements passphrase based
encryption of files. Its primary intended use-case is for encrypting
small amounts of personal data for safe keeping on untrusted media
(physical or otherwise).

Make sure to finish this README completely before deciding to use it.

# Building

Go 1.11+ (preferred, uses vgo):

```
go build
```

Go 1.10 and below:

```
go get
go build
```

# Usage

Here's how to encrypt a file (you will be interactively prompted for a
passphrase):

```
./saltybox passphrase-encrypt-file allmysecrets.txt allmysecrets.txt.saltybox
```

And here is how to decrypt it afterwards (again, you will be
interactively prompted for a passphrase):

```
./saltybox passphrase-decrypt-file allmysecrets.txt.saltybox allmysecrets.txt
```

And here is how to update a previously encrypted file in a manner that
does not allow accidental changing of the passphrase
(`passphrase-update-file` will first decrypt the existing file using
the passphrase to validate that the passphrase is correct, and then
encrypt the new contents):

```
./saltybox passphrase-update-file allmysecrets-updated.txt allmysecrets.txt.saltybox
```

# Important crypto disclaimer

I am not a cryptographer and the code has not been revewied by any
cryptographers. Are you one? Please send me feedback
(peter.schuller@infidyne.com).

Although I certainly did not attempt to invent any new cryptographic
primitives and rather use well established trusted primitives, there
is generally a risk that cryptographic primitives are used incorrectly
when composed into a larger program.

Unfortunately, I have not been able to find a tool like this that
satisfies my personal criteria for what I want to depend on for
emergency life recovery media.

# Notable features

* The user interface is incredibly basic and is *not* suitable for scripting.
* There is no attempt to lock the passphrase into memory. The passphrase
  may be paged to disk or included in a core dump (should the program
  crash). You are responsible for the security of the device on which you
  run this program.
* The format is based upon well known algorithms with exceedingly
  simple layering on top. scrypt is used for key stretching, nacl is
  used for encryption, and a base64 variant is used for encoding. An exact
  spec would ideally exist, but currently you are left to interpret the
  source code.
* The amount of code is very small compared to certain other options and
  should be easy to audit.
* Zero dependencies beyond Go itself and official golang.org libraries.

# Guidance for use

I recommend that you store a copy of the program source code and a
built binary for your platform(s) alongside the encrypted data. This
ensures you will be able to recover your data even if this project
disappears from github or is otherwise inaccessible. Including the
built binary is important to ensure you can reproduce exactly the
program used to encrypt the data. This is not a well known and well
replicated program, so do not assume it's available online in an
emergency.

Further, always use `passphrase-update-file` when updating an existing
encrypted file. This avoids the possibility of accidentally changing
the passphrase by providing a different passphrase than what was used
to encrypt the existing file.

# Format/API contract

* Future versions if any will remain able to decrypt data in older
  formats.
* The command line interface may change and is not suitable for
  automated scripting.
* The library API may also change.
