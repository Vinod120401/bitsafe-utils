# AGENTS

- Use Python 3.11+ with type hints and PEP 8 style.
- Avoid exposing secrets; load sensitive data from environment variables.
- Run `pytest` before committing any changes.
- Keep dependencies minimal and specify them in `requirements.txt`.
- API endpoints live in `bitsafe_utils.app` and use FastAPI.
- `server.py` exposes Flask endpoints and should instantiate a new
  `BitsafeMiddleware` when `app.config['TESTING']` is true so tests can mock it.
- Store the RSA private key as `PRIVATE_KEY` and the Fernet key as `APP_SECRET`.
- Key generation utilities live in `scripts/generate_keys.py`; do not add duplicate key generation scripts elsewhere.
