#!/usr/bin/env -S uv run
# /// script
# requires-python = ">=3.10"
# dependencies = ["cryptography"]
# ///
"""
Encrypt a secret message for use with single.html

Usage:
    uv run encrypt.py <password> <secret_message>
    uv run encrypt.py "mypassword" "This is my secret"

Output: JSON object to embed in single.html
"""

import json
import os
import sys

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Constants (must match single.html)
SALT_SIZE = 32  # bytes
BLOCK_SIZE = 16  # bytes (IV size for AES-GCM)
KEY_SIZE = 32  # bytes (AES-256)
ITERATIONS = 5000000


def pkcs7_pad(data: bytes, block_size: int) -> bytes:
    """Apply PKCS#7 padding."""
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def encrypt(password: str, plaintext: str) -> dict:
    """Encrypt plaintext with password using PBKDF2 + AES-GCM."""

    # Generate random salt and IV
    salt = os.urandom(SALT_SIZE)
    iv = os.urandom(BLOCK_SIZE)

    # Derive key using PBKDF2 with SHA-512
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(),
        length=KEY_SIZE,
        salt=salt,
        iterations=ITERATIONS,
    )
    key = kdf.derive(password.encode("utf-8"))

    # Pad plaintext (PKCS#7)
    plaintext_bytes = plaintext.encode("utf-8")
    padded = pkcs7_pad(plaintext_bytes, BLOCK_SIZE)

    # Encrypt with AES-GCM
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(iv, padded, None)

    return {
        "salt": salt.hex(),
        "iv": iv.hex(),
        "cipher": ciphertext.hex(),
        "iterations": ITERATIONS,
    }


def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <password> <secret_message>", file=sys.stderr)
        print(f"Example: {sys.argv[0]} 'mypass' 'Hello World'", file=sys.stderr)
        sys.exit(1)

    password = sys.argv[1]
    secret = sys.argv[2]

    if not password:
        print("Error: Password cannot be empty", file=sys.stderr)
        sys.exit(1)

    result = encrypt(password, secret)
    print(json.dumps(result))


if __name__ == "__main__":
    main()
