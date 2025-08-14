from bitsafe_utils.crypto_service import (
    decrypt_with_app_secret,
    encrypt_with_public_key,
    process_password,
)
import unittest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import base64
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestCryptoServiceIntegration(unittest.TestCase):
    def generate_keys(self):
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

    def test_process_password_integration(self):
        private_pem, public_pem = self.generate_keys()
        password = "Tr0ub4dor&3"
        app_secret = "super-secret-key"

        encrypted_for_wrapper = encrypt_with_public_key(password, public_pem)
        re_encrypted = process_password(
            encrypted_for_wrapper, private_pem, app_secret)
        decrypted = decrypt_with_app_secret(re_encrypted, app_secret)
        self.assertEqual(decrypted, password)


if __name__ == '__main__':
    unittest.main()
