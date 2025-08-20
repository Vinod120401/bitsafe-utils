# AGENTS

- Use Python 3.11+ with type hints and PEP 8 style.
- Avoid exposing secrets; load sensitive data from environment variables.
- Run `PYTHONPATH=. pytest` before committing any changes.
- Keep dependencies minimal and specify them in `requirements.txt`.
- API endpoints live in `bitsafe_utils.app` and use FastAPI served by
  `uvicorn`.
- Per-application configuration is loaded from environment variables
  `APP_i_ID`, `APP_i_SECRET`, `APP_i_PRIVATE_KEY_PATH`, and
  `APP_i_PUBLIC_KEY_PATH`.
- Store the RSA private key as `PRIVATE_KEY` and the Fernet key as `APP_SECRET`.
- Key generation utilities live in `scripts/generate_keys.py`; do not add duplicate key generation scripts elsewhere.
