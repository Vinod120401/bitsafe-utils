"""Unified FastAPI application exposing Bitsafe middleware endpoints."""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from . import middleware_service
from .crypto_service import process_password

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Middleware setup
# ---------------------------------------------------------------------------

BACKEND_URL = os.getenv("BITSAFE_BACKEND_URL", "https://api.bitsafe.io")
middleware = middleware_service.BitsafeMiddleware(BACKEND_URL)


def load_apps_from_env() -> list[str]:
    """Load app configurations from environment variables."""
    app_configs: list[str] = []
    i = 1
    while True:
        app_id = os.getenv(f"APP_{i}_ID")
        app_secret = os.getenv(f"APP_{i}_SECRET")
        private_key_path = os.getenv(f"APP_{i}_PRIVATE_KEY_PATH")
        public_key_path = os.getenv(f"APP_{i}_PUBLIC_KEY_PATH")
        if not all([app_id, app_secret, private_key_path, public_key_path]):
            break
        try:
            with open(private_key_path, "r", encoding="utf-8") as f:
                private_key = f.read()
            with open(public_key_path, "r", encoding="utf-8") as f:
                public_key = f.read()
            middleware.register_app(app_id, app_secret, private_key, public_key)
            app_configs.append(app_id)
        except Exception as exc:  # pragma: no cover - defensive
            logger.error("Failed to load app %s: %s", app_id, exc)
        i += 1
    return app_configs


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Load apps at startup using FastAPI's lifespan events."""
    load_apps_from_env()
    yield


app = FastAPI(lifespan=lifespan)


# ---------------------------------------------------------------------------
# Single-app re-encryption endpoint (backwards compatibility)
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Middleware-backed endpoints
# ---------------------------------------------------------------------------


class EncryptedPasswordPayload(BaseModel):
    encryptedPassword: str


@app.get("/health")
def health_check() -> dict[str, object]:
    """Health check endpoint."""
    return {"status": "healthy", "registered_apps": list(middleware.apps.keys())}


@app.get("/apps/{app_id}/public-key")
def get_public_key(app_id: str) -> dict[str, str]:
    """Get public key for an app to be used by frontend clients."""
    try:
        public_key = middleware.get_public_key(app_id)
        return {"publicKey": public_key}
    except ValueError as exc:  # pragma: no cover - defensive
        raise HTTPException(status_code=404, detail=str(exc))


@app.post("/apps/{app_id}/re-encrypt-password")
def re_encrypt_password_for_app(
    app_id: str, payload: EncryptedPasswordPayload
) -> dict[str, str]:
    """Re-encrypt a password using the app's secret for backend communication."""
    try:
        app_config = middleware._get_app_config(app_id)  # noqa: SLF001
        re_encrypted_password = middleware.process_password(
            payload.encryptedPassword,
            app_config.private_key,
            app_config.app_secret,
        )
        return {"reEncryptedPassword": re_encrypted_password}
    except ValueError as exc:  # pragma: no cover - defensive
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:  # pragma: no cover - defensive
        raise HTTPException(
            status_code=500, detail=f"Failed to re-encrypt password: {exc}"
        )


class RegisterPayload(BaseModel):
    appId: str
    username: str
    encryptedPassword: str
    email: Optional[str] = None


@app.post("/auth/register")
def register_user(payload: RegisterPayload) -> dict[str, object]:
    """Register a new user."""
    try:
        return middleware.register_user(
            app_id=payload.appId,
            username=payload.username,
            encrypted_password=payload.encryptedPassword,
            email=payload.email,
        )
    except Exception as exc:  # pragma: no cover - defensive
        raise HTTPException(status_code=500, detail=str(exc))


class LoginPayload(BaseModel):
    appId: str
    username: str
    encryptedPassword: str


@app.post("/auth/login")
def login_user(payload: LoginPayload) -> dict[str, object]:
    """Login a user."""
    try:
        return middleware.login_user(
            app_id=payload.appId,
            username=payload.username,
            encrypted_password=payload.encryptedPassword,
        )
    except Exception as exc:  # pragma: no cover - defensive
        raise HTTPException(status_code=500, detail=str(exc))


class BalancePayload(BaseModel):
    appId: str
    userToken: str


@app.post("/wallet/balance")
def get_balance(payload: BalancePayload) -> dict[str, object]:
    """Get user balance."""
    try:
        return middleware.get_user_balance(
            app_id=payload.appId,
            user_token=payload.userToken,
        )
    except Exception as exc:  # pragma: no cover - defensive
        raise HTTPException(status_code=500, detail=str(exc))


class TransferPayload(BaseModel):
    appId: str
    userToken: str
    toAddress: str
    amount: str
    token: str


@app.post("/wallet/transfer")
def transfer_tokens(payload: TransferPayload) -> dict[str, object]:
    """Transfer tokens."""
    try:
        return middleware.transfer_tokens(
            app_id=payload.appId,
            user_token=payload.userToken,
            to_address=payload.toAddress,
            amount=payload.amount,
            token=payload.token,
        )
    except Exception as exc:  # pragma: no cover - defensive
        raise HTTPException(status_code=500, detail=str(exc))


class RewardPayload(BaseModel):
    appId: str
    userToken: str
    rewardId: str


@app.post("/rewards/redeem")
def redeem_reward(payload: RewardPayload) -> dict[str, object]:
    """Redeem a reward."""
    try:
        return middleware.redeem_reward(
            app_id=payload.appId,
            user_token=payload.userToken,
            reward_id=payload.rewardId,
        )
    except Exception as exc:  # pragma: no cover - defensive
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/")
def index() -> str:
    """Index endpoint."""
    return "Bitsafe Middleware API is running."


__all__ = ["app", "middleware"]

