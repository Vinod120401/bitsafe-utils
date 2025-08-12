"""
Bitsafe Middleware Service

This service acts as a secure wrapper around the Bitsafe backend API,
handling password encryption and app-secret management without exposing
secrets to frontend applications.
"""

import os
import json
import logging
from typing import Dict, Any, Optional
from dataclasses import dataclass
import requests
from .crypto_service import process_password, encrypt_with_public_key

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class AppConfig:
    """Configuration for a registered application."""
    app_id: str
    app_secret: str
    public_key: bytes


class BitsafeMiddleware:
    """Middleware service for secure communication with Bitsafe backend."""

    def __init__(self, backend_url: str = "https://api.bitsafe.io"):
        self.backend_url = backend_url.rstrip('/')
        self.apps: Dict[str, AppConfig] = {}

    def register_app(self, app_id: str, app_secret: str, public_key_pem: str):
        """Register a new application with its configuration."""
        self.apps[app_id] = AppConfig(
            app_id=app_id,
            app_secret=app_secret,
            public_key=public_key_pem.encode('utf-8')
        )
        logger.info(f"Registered app: {app_id}")

    def _get_app_config(self, app_id: str) -> AppConfig:
        """Get app configuration or raise error if not found."""
        if app_id not in self.apps:
            raise ValueError(f"App ID {app_id} not registered")
        return self.apps[app_id]

    def _make_backend_request(self, endpoint: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Make authenticated request to Bitsafe backend."""
        url = f"{self.backend_url}/{endpoint.lstrip('/')}"

        try:
            response = requests.post(
                url,
                json=payload,
                headers={'Content-Type': 'application/json'},
                timeout=30
            )
            response.raise_for_status()
            return response.json()

        except requests.exceptions.RequestException as e:
            logger.error(f"Backend request failed: {e}")
            raise

    def register_user(self, app_id: str, username: str, encrypted_password: str,
                      email: Optional[str] = None, **kwargs) -> Dict[str, Any]:
        """
        Register a new user through the middleware.

        Args:
            app_id: The application's ID
            username: Username for registration
            encrypted_password: Password encrypted with the app's public key
            email: Optional email address
            **kwargs: Additional registration fields

        Returns:
            Backend response with user details
        """
        app_config = self._get_app_config(app_id)

        # Decrypt and re-encrypt password with app secret
        password_for_backend = process_password(
            encrypted_password,
            app_config.public_key,
            app_config.app_secret
        )

        payload = {
            'appId': app_id,
            'username': username,
            'password': password_for_backend,
            'email': email,
            **kwargs
        }

        return self._make_backend_request('/auth/register', payload)

    def login_user(self, app_id: str, username: str, encrypted_password: str) -> Dict[str, Any]:
        """
        Login a user through the middleware.

        Args:
            app_id: The application's ID
            username: Username for login
            encrypted_password: Password encrypted with the app's public key

        Returns:
            Backend response with auth token
        """
        app_config = self._get_app_config(app_id)

        # Decrypt and re-encrypt password with app secret
        password_for_backend = process_password(
            encrypted_password,
            app_config.public_key,
            app_config.app_secret
        )

        payload = {
            'appId': app_id,
            'username': username,
            'password': password_for_backend
        }

        return self._make_backend_request('/auth/login', payload)

    def get_public_key(self, app_id: str) -> str:
        """Get the public key for an app to be used by frontend clients."""
        app_config = self._get_app_config(app_id)
        return app_config.public_key.decode('utf-8')

    def get_user_balance(self, app_id: str, user_token: str) -> Dict[str, Any]:
        """Get user balance from backend."""
        payload = {
            'appId': app_id,
            'userToken': user_token
        }
        return self._make_backend_request('/wallet/balance', payload)

    def transfer_tokens(self, app_id: str, user_token: str, to_address: str,
                        amount: str, token: str) -> Dict[str, Any]:
        """Transfer tokens through backend."""
        payload = {
            'appId': app_id,
            'userToken': user_token,
            'toAddress': to_address,
            'amount': amount,
            'token': token
        }
        return self._make_backend_request('/wallet/transfer', payload)

    def redeem_reward(self, app_id: str, user_token: str, reward_id: str) -> Dict[str, Any]:
        """Redeem a pending reward."""
        payload = {
            'appId': app_id,
            'userToken': user_token,
            'rewardId': reward_id
        }
        return self._make_backend_request('/rewards/redeem', payload)


# Global middleware instance
middleware = BitsafeMiddleware()

# Convenience functions for easy import
register_app = middleware.register_app
register_user = middleware.register_user
login_user = middleware.login_user
get_public_key = middleware.get_public_key
get_user_balance = middleware.get_user_balance
transfer_tokens = middleware.transfer_tokens
redeem_reward = middleware.redeem_reward
