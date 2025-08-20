"""Tests for the re-encrypt password endpoint using FastAPI."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

from bitsafe_utils.app import app, middleware


client = TestClient(app)


def test_re_encrypt_password_success() -> None:
    """Password is re-encrypted with the app secret."""
    app_id = "test_app_123"
    payload = {"encryptedPassword": "encrypted_password_from_frontend"}

    mock_config = MagicMock()
    mock_config.app_secret = "test_secret"
    mock_config.private_key = b"test_private_key"

    with (
        patch.object(middleware, "_get_app_config", return_value=mock_config),
        patch.object(middleware, "process_password", return_value="re_encrypted"),
    ):
        resp = client.post(
            f"/apps/{app_id}/re-encrypt-password",
            data=json.dumps(payload),
            headers={"Content-Type": "application/json"},
        )

    assert resp.status_code == 200
    assert resp.json()["reEncryptedPassword"] == "re_encrypted"


def test_re_encrypt_password_missing_field() -> None:
    """Missing field returns HTTP 422."""
    app_id = "test_app_123"
    resp = client.post(
        f"/apps/{app_id}/re-encrypt-password",
        data=json.dumps({}),
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 422


def test_re_encrypt_password_app_not_found() -> None:
    """Unknown app ID yields 404."""
    app_id = "missing_app"
    payload = {"encryptedPassword": "x"}
    with patch.object(middleware, "_get_app_config", side_effect=ValueError("App not found")):
        resp = client.post(
            f"/apps/{app_id}/re-encrypt-password",
            data=json.dumps(payload),
            headers={"Content-Type": "application/json"},
        )
    assert resp.status_code == 404
    assert resp.json()["detail"] == "App not found"


def test_re_encrypt_password_invalid_json() -> None:
    """Invalid JSON returns 422."""
    app_id = "test_app_123"
    resp = client.post(
        f"/apps/{app_id}/re-encrypt-password",
        data="not json",
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 422

