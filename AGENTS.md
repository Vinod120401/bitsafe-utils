# AGENTS

- Use Python 3.11+ with type hints and PEP 8 style.
- Avoid exposing secrets; load sensitive data from environment variables.
- Run `pytest` before committing any changes.
- Keep dependencies minimal and specify them in `requirements.txt`.
- Write descriptive commit messages summarizing your changes.
- API endpoints live in `bitsafe_utils.app` and use FastAPI.
- Store the RSA private key as `PRIVATE_KEY` and the Fernet key as `APP_SECRET`.
