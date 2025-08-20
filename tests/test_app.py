import os
import base64

from fastapi.testclient import TestClient

from bitsafe_utils.app import app
from bitsafe_utils.crypto_service import encrypt_with_public_key, decrypt_with_app_secret
from tests.utils.keys import generate_keys


def test_re_encrypt_endpoint_round_trip():
    private_pem, public_pem = generate_keys()
    app_secret = base64.urlsafe_b64encode(os.urandom(32)).decode()
    os.environ["PRIVATE_KEY"] = private_pem.decode().replace("\n", "\\n")
    os.environ["APP_SECRET"] = app_secret

    client = TestClient(app)

    password = "S3cur3Pass!"
    encrypted = encrypt_with_public_key(password, public_pem)
    resp = client.post("/re-encrypt", json={"password": encrypted})
    assert resp.status_code == 200
    re_encrypted = resp.json()["password"]
    assert decrypt_with_app_secret(re_encrypted, app_secret) == password
