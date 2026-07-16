#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = ["argon2-cffi>=23", "pynacl>=1.5"]
# ///
"""Generate golden test vectors for the saltybox2 format.

This deliberately uses an independent implementation stack (Argon2 via
argon2-cffi, XChaCha20-Poly1305 via libsodium through PyNaCl) rather than the
Rust implementation under test. Agreement between the two is evidence the
Rust code implements the specified format, not merely that it agrees with
itself. If the two ever disagree, trust neither blindly: re-derive from the
saltybox2 format specification in SPEC.md.

Run from the repo root:

    uv run testdata/generate-golden-vectors-v2.py > testdata/golden-vectors-v2.json

The output is committed; regeneration should only be needed if vectors are
added. The saltybox2 format itself is frozen, so existing vectors must never
change.
"""

import base64
import json
import struct

from argon2.low_level import Type, hash_secret_raw
from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_encrypt

MAGIC = b"saltybox2:"
# A plain-text truncation aid terminating the armor; deliberately outside
# any cryptographic check. See the saltybox2 format specification.
END_MARKER = b":end"


def b64std(data: bytes) -> str:
    return base64.b64encode(data).decode()


def armor(payload: bytes) -> str:
    return (MAGIC + base64.urlsafe_b64encode(payload).rstrip(b"=") + END_MARKER).decode()


def vector(
    comment: str,
    passphrase: bytes,
    plaintext: bytes,
    salt: bytes,
    nonce: bytes,
    m_cost_kib: int,
    t_cost: int,
    p_cost: int,
) -> dict:
    assert len(salt) == 16 and len(nonce) == 24
    key = hash_secret_raw(
        secret=passphrase,
        salt=salt,
        time_cost=t_cost,
        memory_cost=m_cost_kib,
        parallelism=p_cost,
        hash_len=32,
        type=Type.ID,
        version=19,  # Argon2 v1.3 (0x13), fixed by the saltybox2 format
    )
    header = salt + struct.pack(">III", m_cost_kib, t_cost, p_cost) + nonce
    ciphertext = crypto_aead_xchacha20poly1305_ietf_encrypt(
        plaintext, MAGIC + header, nonce, key
    )
    return {
        "comment": comment,
        "passphrase": b64std(passphrase),
        "plaintext": b64std(plaintext),
        "salt": b64std(salt),
        "nonce": b64std(nonce),
        "m_cost_kib": m_cost_kib,
        "t_cost": t_cost,
        "p_cost": p_cost,
        "armored": armor(header + ciphertext),
    }


# Deliberately cheap Argon2 parameters keep the Rust test suite fast. The
# format is identical at any in-range parameter values, so nothing is lost
# by not using the expensive write defaults.
VECTORS = [
    vector(
        "empty plaintext",
        b"test",
        b"",
        bytes([0x42]) * 16,
        bytes([0x24]) * 24,
        8192,
        3,
        1,
    ),
    vector(
        "basic text",
        b"test",
        b"test payload",
        bytes(range(16)),
        bytes(range(24)),
        8192,
        3,
        1,
    ),
    vector(
        "all byte values as plaintext, non-UTF-8 passphrase",
        bytes([0xFF, 0xFE, 0x00, 0x01]),
        bytes(range(256)),
        bytes([0xA5]) * 16,
        bytes([0x5A]) * 24,
        8192,
        3,
        1,
    ),
    vector(
        "multiple lanes (p=2) pin cross-implementation lane handling",
        b"lanes",
        b"parallel lanes",
        bytes([0x11]) * 16,
        bytes([0x22]) * 24,
        8192,
        1,
        2,
    ),
    vector(
        "minimum legal memory cost for one lane",
        b"tiny",
        b"tiny memory",
        bytes([0x33]) * 16,
        bytes([0x44]) * 24,
        8,
        1,
        1,
    ),
]

print(json.dumps(VECTORS, indent=2))
