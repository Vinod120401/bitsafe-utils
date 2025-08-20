from bitsafe_utils.crypto_service import (
    decrypt_with_app_secret,
    encrypt_with_public_key,
    process_password,
)
import unittest
import os
import sys

from tests.utils.keys import generate_keys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestCryptoServiceIntegration(unittest.TestCase):
    def test_process_password_integration(self):
        private_pem, public_pem = generate_keys()
        password = "Tr0ub4dor&3"
        app_secret = "super-secret-key"

        encrypted_for_wrapper = encrypt_with_public_key(password, public_pem)
        re_encrypted = process_password(
            encrypted_for_wrapper, private_pem, app_secret)
        decrypted = decrypt_with_app_secret(re_encrypted, app_secret)
        self.assertEqual(decrypted, password)


if __name__ == '__main__':
    unittest.main()
