import os
import sys
import unittest

from bitsafe_utils.crypto_service import (
    decrypt_with_app_secret,
    encrypt_with_public_key,
    process_password,
)
from tests.helpers import generate_test_keys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestCryptoServiceIntegration(unittest.TestCase):
    def test_process_password_integration(self):
        private_pem, public_pem, app_secret = generate_test_keys()
        password = "Tr0ub4dor&3"

        encrypted_for_wrapper = encrypt_with_public_key(password, public_pem)
        re_encrypted = process_password(
            encrypted_for_wrapper, private_pem, app_secret)
        decrypted = decrypt_with_app_secret(re_encrypted, app_secret)
        self.assertEqual(decrypted, password)


if __name__ == '__main__':
    unittest.main()
