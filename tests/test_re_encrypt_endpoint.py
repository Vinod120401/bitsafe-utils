"""
Tests for the re-encrypt password endpoint.
"""

from server import app
import unittest
import json
import sys
import os
from unittest.mock import patch, MagicMock

# Add the parent directory to the path so we can import server
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestReEncryptEndpoint(unittest.TestCase):
    """Test cases for the re-encrypt password endpoint."""

    def setUp(self):
        """Set up test client and mock data."""
        app.config['TESTING'] = True
        self.app = app.test_client()

        # Mock app configuration
        self.test_app_id = "test_app_123"
        self.test_app_secret = "test_secret_key_12345"
        self.test_public_key = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4f5wg5l2hKsTeNem/V41
fGnJm6gOdrj8ym3rFkEjWT2btf7FMEo6UqFkk91zxMqAUTsXHwIFYr2wwAIuAMYi
koQYxAHw1JXmSRgGg7hSuMhvqwVA6+sAkNtKpmoaFa7j2d33EgI=
-----END PUBLIC KEY-----"""

    def test_re_encrypt_password_success(self):
        """Test successful password re-encryption."""
        with patch('bitsafe_utils.middleware_service.BitsafeMiddleware') as mock_middleware_class:
            mock_middleware = mock_middleware_class.return_value
            mock_app_config = MagicMock()
            mock_app_config.app_secret = self.test_app_secret
            mock_app_config.public_key = self.test_public_key.encode('utf-8')

            mock_middleware._get_app_config.return_value = mock_app_config
            mock_middleware.process_password = MagicMock(
                return_value="re_encrypted_password_123")

            payload = {
                'encryptedPassword': 'encrypted_password_from_frontend'
            }

            response = self.app.post(
                f'/apps/{self.test_app_id}/re-encrypt-password',
                data=json.dumps(payload),
                content_type='application/json'
            )

            self.assertEqual(response.status_code, 200)
            data = json.loads(response.data)
            self.assertIn('reEncryptedPassword', data)
            self.assertEqual(data['reEncryptedPassword'],
                             're_encrypted_password_123')

    def test_re_encrypt_password_missing_field(self):
        """Test error when encryptedPassword field is missing."""
        payload = {}

        response = self.app.post(
            f'/apps/{self.test_app_id}/re-encrypt-password',
            data=json.dumps(payload),
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 400)
        data = json.loads(response.data)
        self.assertIn('error', data)
        self.assertIn('encryptedPassword', data['error'])

    def test_re_encrypt_password_invalid_json(self):
        """Test error when invalid JSON is provided."""
        response = self.app.post(
            f'/apps/{self.test_app_id}/re-encrypt-password',
            data='invalid json',
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 400)

    def test_re_encrypt_password_app_not_found(self):
        """Test error when app ID is not registered."""
        with patch('bitsafe_utils.middleware_service.BitsafeMiddleware') as mock_middleware_class:
            mock_middleware = mock_middleware_class.return_value
            mock_app_config = MagicMock()
            mock_app_config.app_secret = "test_secret"
            mock_app_config.public_key = b"test_public_key"

            mock_middleware._get_app_config.side_effect = ValueError(
                "App not found")

            payload = {
                'encryptedPassword': 'encrypted_password_from_frontend'
            }

            response = self.app.post(
                '/apps/nonexistent_app/re-encrypt-password',
                data=json.dumps(payload),
                content_type='application/json'
            )

            self.assertEqual(response.status_code, 404)
            data = json.loads(response.data)
            self.assertIn('error', data)

    def test_re_encrypt_password_empty_payload(self):
        """Test error when payload is empty."""
        response = self.app.post(
            f'/apps/{self.test_app_id}/re-encrypt-password',
            data='',
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 400)


if __name__ == '__main__':
    unittest.main()
