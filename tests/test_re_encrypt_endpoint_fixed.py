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

        self.test_app_id = "test_app_123"

    def test_re_encrypt_password_success(self):
        """Test successful password re-encryption."""
        with patch('bitsafe_utils.middleware_service.BitsafeMiddleware') as mock_middleware_class:
            mock_middleware = mock_middleware_class.return_value
            mock_app_config = MagicMock()
            mock_app_config.app_secret = "test_secret"
            mock_app_config.public_key = b"test_public_key"

            mock_middleware._get_app_config.return_value = mock_app_config

            payload = {
                'encryptedPassword': 'encrypted_password_from_frontend'
            }

            response = self.app.post(
                f'/apps/{self.test_app_id}/re-encrypt-password',
                data=json.dumps(payload),
                content_type='application/json'
            )

            self.assertEqual(response.status_code, 200)

    def test_re_encrypt_password_missing_field(self):
        """Test error when encryptedPassword field is missing."""
        payload = {}

        response = self.app.post(
            f'/apps/{self.test_app_id}/re-encrypt-password',
            data=json.dumps(payload),
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 400)

    def test_re_encrypt_password_app_not_found(self):
        """Test error when app ID is not registered."""
        response = self.app.post(
            '/apps/nonexistent_app/re-encrypt-password',
            data=json.dumps({'encryptedPassword': 'test'}),
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 404)


if __name__ == '__main__':
    unittest.main()
