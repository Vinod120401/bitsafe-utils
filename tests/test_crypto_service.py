from bitsafe_utils.crypto_service import (
    decrypt_with_app_secret,
    encrypt_with_public_key,
    process_password,
)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.fernet import Fernet
import base64
import os
import sys

# Add the parent directory to the path for module imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


def test_process_password_round_trip():
    private_pem, public_pem = generate_keys()
    password = "Tr0ub4dor&3"

    # Generate a proper Fernet key and use it as app secret
    app_secret = base64.urlsafe_b64encode(os.urandom(32)).decode()

    encrypted_for_wrapper = encrypt_with_public_key(password, public_pem)
    re_encrypted = process_password(
        encrypted_for_wrapper, private_pem, app_secret)
    decrypted = decrypt_with_app_secret(re_encrypted, app_secret)
    assert decrypted == password
