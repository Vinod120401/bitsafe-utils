"""Cryptographic helpers for secure password handling.

This module enables a client to encrypt a password with an RSA public key
and a wrapper service to decrypt that payload and re-encrypt it using an
application secret before forwarding it to the Bitsafe backend.
"""

from __future__ import annotations

import base64

import hashlib
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.fernet import Fernet


def encrypt_with_public_key(password: str, public_key_pem: bytes) -> str:
    """Encrypt ``password`` using the given RSA ``public_key_pem``.

    Returns:
        Base64 encoded ciphertext ready to be sent to the wrapper service.
    """
    public_key = serialization.load_pem_public_key(public_key_pem)
    ciphertext = public_key.encrypt(
        password.encode("utf-8"),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return base64.b64encode(ciphertext).decode("utf-8")


def decrypt_with_private_key(encrypted_b64: str, private_key_pem: bytes) -> str:
    """Decrypt base64 ``encrypted_b64`` using the RSA ``private_key_pem``."""
    private_key = serialization.load_pem_private_key(private_key_pem, password=None)

    encrypted = base64.b64decode(encrypted_b64)
    plaintext = private_key.decrypt(
        encrypted,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return plaintext.decode("utf-8")


def encrypt_with_app_secret(password: str, app_secret: str) -> str:
    """Encrypt ``password`` using the Fernet ``app_secret`` key."""
    fernet = Fernet(app_secret.encode("utf-8"))
    token = fernet.encrypt(password.encode("utf-8"))
    return token.decode("utf-8")
=======
def _derive_fernet_key(app_secret: str) -> bytes:
    """Derive a Fernet-compatible key from app_secret."""
    # Fernet keys must be 32 bytes, URL-safe base64 encoded
    key = hashlib.sha256(app_secret.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(key)


def encrypt_with_app_secret(password: str, app_secret: str) -> str:
    """Encrypt ``password`` using ``app_secret`` with Fernet (AES-128-CBC).

    Returns a base64 encoded string containing the encrypted password.
    """
    key = _derive_fernet_key(app_secret)
    fernet = Fernet(key)
    encrypted = fernet.encrypt(password.encode("utf-8"))
    return base64.b64encode(encrypted).decode("utf-8")



def decrypt_with_app_secret(encrypted_b64: str, app_secret: str) -> str:
    """Decrypt payload produced by :func:`encrypt_with_app_secret`."""

    fernet = Fernet(app_secret.encode("utf-8"))
    plaintext = fernet.decrypt(encrypted_b64.encode("utf-8"))

    return plaintext.decode("utf-8")


def process_password(encrypted_b64: str, private_key_pem: bytes, app_secret: str) -> str:
    """Decrypt RSA-encrypted payload and re-encrypt with ``app_secret``."""
    plaintext = decrypt_with_private_key(encrypted_b64, private_key_pem)
    return encrypt_with_app_secret(plaintext, app_secret)
