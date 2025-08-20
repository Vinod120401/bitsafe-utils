# bitsafe-utils

Building a system to motivate users into knowing, using and holding our token.

## Crypto Service

`bitsafe_utils.crypto_service` provides helpers to decrypt a password with an
RSA private key and re-encrypt it using an application secret before sending it
to the Bitsafe backend using the Fernet algorithm. This keeps the application
secret outside of the frontend while ensuring the backend never sees the
password in plaintext.

`bitsafe_utils.app` exposes a FastAPI application with endpoints for password
re-encryption and proxying authentication requests to the Bitsafe backend. The
`/re-encrypt` endpoint accepts an RSA-encrypted password and returns it
encrypted with the app secret. The endpoint expects the following environment
variables:

- `PRIVATE_KEY`: RSA private key in PEM format (newlines encoded as `\n`).
- `APP_SECRET`: Fernet key used to encrypt the password for the Bitsafe API.

Run the service with:

```bash
uvicorn bitsafe_utils.app:app --host 0.0.0.0 --port 8000
```

Use `scripts/generate_keys.py` to generate a fresh RSA key pair. The script
writes the private key with `600` permissions so it isn't world readable:

```bash
python scripts/generate_keys.py --private ./private_key.pem --public ./public_key.pem
```

For tests, use `generate_test_keys` from `tests/helpers.py` to create in-memory RSA and Fernet keys.



Applications are configured through environment variables. For an index `i`,
define the following variables:

- `APP_i_ID`: Application identifier.
- `APP_i_SECRET`: Fernet key used for backend communication.
- `APP_i_PRIVATE_KEY_PATH`: Path to the RSA private key in PEM format.
- `APP_i_PUBLIC_KEY_PATH`: Path to the corresponding RSA public key served to
  clients.


If a client requests an unregistered application, the middleware responds with a
`404` status and a JSON body of the form
`{"error": "App ID <app_id> not registered"}`.


### Development

Install dependencies:

```bash
pip install -r requirements.txt
```

Environment variables can be loaded from a `.env` file using `python-dotenv`.
HTTP requests are handled using the `requests` library. The `httpx` package is
only required for FastAPI's test client.

### Testing

```bash
PYTHONPATH=. pytest
```

Test utilities in `tests/helpers.py` provide `generate_test_keys` to create
temporary RSA and Fernet keys for unit tests.

### Contributing

- Use descriptive commit messages that summarize your changes.
- Ensure the test suite passes locally with `pytest` before pushing.
