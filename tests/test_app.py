import os
import base64

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from bitsafe_utils.app import re_encrypt_password, PasswordRequest
from bitsafe_utils.crypto_service import encrypt_with_public_key, decrypt_with_app_secret


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


def test_re_encrypt_endpoint_round_trip():
    private_pem, public_pem = generate_keys()
    app_secret = base64.urlsafe_b64encode(os.urandom(32)).decode()
    os.environ["PRIVATE_KEY"] = private_pem.decode().replace("\n", "\\n")
    os.environ["APP_SECRET"] = app_secret

    password = "S3cur3Pass!"
    encrypted = encrypt_with_public_key(password, public_pem)
    result = re_encrypt_password(PasswordRequest(password=encrypted))
    re_encrypted = result["password"]
    assert decrypt_with_app_secret(re_encrypted, app_secret) == password
