# AGENTS

- Use Python 3.11+ with type hints and PEP 8 style.
- Avoid exposing secrets; load sensitive data from environment variables.
- For local development, `.env` files can be loaded with `python-dotenv`.
- Run `PYTHONPATH=. pytest` before committing any changes.
- Keep dependencies minimal and specify them in `requirements.txt`.
- Use `requests` for HTTP client interactions; avoid adding `httpx` unless necessary.
- API endpoints live in `bitsafe_utils.app` and use FastAPI.
- Per-application configuration is loaded from environment variables
  `APP_i_ID`, `APP_i_SECRET`, `APP_i_PRIVATE_KEY_PATH`, and
  `APP_i_PUBLIC_KEY_PATH`.
- Store the RSA private key as `PRIVATE_KEY` and the Fernet key as `APP_SECRET`.
- Return descriptive error messages; missing apps must yield
  `"App ID {app_id} not registered"`.
- Key generation utilities live in `scripts/generate_keys.py`; do not add duplicate key generation scripts elsewhere.

- Unit tests can generate ephemeral RSA and Fernet keys via
  `tests/helpers.py::generate_test_keys`.
  Avoid adding additional key-generation helpers under `tests/`.

