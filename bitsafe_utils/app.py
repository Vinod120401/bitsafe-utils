"""FastAPI application exposing password re-encryption endpoint."""

from __future__ import annotations

import os

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from .crypto_service import process_password

app = FastAPI()


class PasswordRequest(BaseModel):
    password: str  # RSA-encrypted password from frontend


@app.post("/re-encrypt")
def re_encrypt_password(payload: PasswordRequest) -> dict[str, str]:
    """Return ``payload.password`` re-encrypted with the application secret."""
    private_key = os.environ.get("PRIVATE_KEY")
    app_secret = os.environ.get("APP_SECRET")
    if not private_key or not app_secret:
        raise HTTPException(status_code=500, detail="Server misconfiguration")
    try:
        private_key_bytes = private_key.replace("\\n", "\n").encode("utf-8")
        re_encrypted = process_password(payload.password, private_key_bytes, app_secret)
    except Exception as exc:  # pragma: no cover - defensive
        raise HTTPException(status_code=400, detail="Invalid payload") from exc
    return {"password": re_encrypted}
