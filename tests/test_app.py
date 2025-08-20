import os

from bitsafe_utils.app import re_encrypt_password, PasswordRequest
from bitsafe_utils.crypto_service import encrypt_with_public_key, decrypt_with_app_secret
from tests.helpers import generate_test_keys


def test_re_encrypt_endpoint_round_trip():
    private_pem, public_pem, app_secret = generate_test_keys()
    os.environ["PRIVATE_KEY"] = private_pem.decode().replace("\n", "\\n")
    os.environ["APP_SECRET"] = app_secret

    password = "S3cur3Pass!"
    encrypted = encrypt_with_public_key(password, public_pem)
    result = re_encrypt_password(PasswordRequest(password=encrypted))
    re_encrypted = result["password"]
    assert decrypt_with_app_secret(re_encrypted, app_secret) == password
