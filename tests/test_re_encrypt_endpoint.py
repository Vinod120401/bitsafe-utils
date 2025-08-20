"""Tests for the re-encrypt password endpoint."""

from __future__ import annotations

from fastapi.testclient import TestClient

from bitsafe_utils.app import app, middleware
from bitsafe_utils.crypto_service import (
    encrypt_with_public_key,
    decrypt_with_app_secret,
)
from tests.helpers import generate_test_keys

client = TestClient(app)


def _setup_app() -> tuple[str, str, bytes]:
    """Register a temporary app and return its identifiers."""
    middleware.apps.clear()
    app_id = "test_app_123"
    private_pem, public_pem, app_secret = generate_test_keys()
    middleware.register_app(
        app_id,
        app_secret,
        private_pem.decode(),
        public_pem.decode(),
    )
    return app_id, app_secret, public_pem


def test_re_encrypt_password_success() -> None:
    """Passwords are decrypted and re-encrypted with the app secret."""
    app_id, app_secret, public_pem = _setup_app()
    password = "StrongPassw0rd!"
    encrypted = encrypt_with_public_key(password, public_pem)

    resp = client.post(
        f"/apps/{app_id}/re-encrypt-password",
        json={"encryptedPassword": encrypted},
    )

    assert resp.status_code == 200
    re_encrypted = resp.json()["reEncryptedPassword"]
    assert decrypt_with_app_secret(re_encrypted, app_secret) == password


def test_re_encrypt_password_missing_field() -> None:
    """Missing payload field triggers validation error."""
    app_id, _, _ = _setup_app()

    resp = client.post(f"/apps/{app_id}/re-encrypt-password", json={})
    assert resp.status_code == 422


def test_re_encrypt_password_app_not_found() -> None:
    """Unregistered app IDs return 404."""
    middleware.apps.clear()
    app_id = "unknown_app"

    resp = client.post(
        f"/apps/{app_id}/re-encrypt-password",
        json={"encryptedPassword": "irrelevant"},
    )

    assert resp.status_code == 404
    assert resp.json()["detail"] == f"App ID {app_id} not registered"


def test_re_encrypt_password_invalid_json() -> None:
    """Invalid JSON body returns 422."""
    app_id, _, _ = _setup_app()

    resp = client.post(
        f"/apps/{app_id}/re-encrypt-password",
        content="not json",
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 422
