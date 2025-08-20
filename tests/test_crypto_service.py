from bitsafe_utils.crypto_service import (
    decrypt_with_app_secret,
    encrypt_with_public_key,
    process_password,
)
import base64
import os
import sys

from tests.utils.keys import generate_keys

# Add the parent directory to the path so we can import server

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

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
