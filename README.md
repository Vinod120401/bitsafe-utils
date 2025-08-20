# bitsafe-utils

Building a system to motivate users into knowing, using and holding our token.

## Crypto Service

`bitsafe_utils.crypto_service` provides helpers to decrypt a password with an
RSA private key and re-encrypt it using an application secret before sending it
to the Bitsafe backend using the Fernet algorithm. This keeps the application
secret outside of the frontend while ensuring the backend never sees the
password in plaintext.

`bitsafe_utils.app` exposes a FastAPI endpoint `/re-encrypt` that accepts an
RSA-encrypted password and returns it encrypted with the app secret. The
endpoint expects the following environment variables:

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

## Flask Middleware Server

`server.py` provides a Flask implementation suitable for multi-application
deployments. Each request can instantiate a fresh
`BitsafeMiddleware` when `app.config['TESTING']` is enabled, allowing the
middleware to be easily mocked in unit tests.

Each application is configured through environment variables. For an index
`i`, define the following variables:

- `APP_i_ID`: Application identifier.
- `APP_i_SECRET`: Fernet key used for backend communication.
- `APP_i_PRIVATE_KEY_PATH`: Path to the RSA private key in PEM format.
- `APP_i_PUBLIC_KEY_PATH`: Path to the corresponding RSA public key served to
  clients.

Run the server with:

```bash
python server.py  # uses Waitress in production
```

Set `DEBUG=true` to use Flask's development server during local development.

### Development

Install dependencies:

```bash
pip install -r requirements.txt
```

### Testing

```bash
PYTHONPATH=. pytest
```

Test utilities in `tests/helpers.py` provide `generate_test_keys` to create
temporary RSA and Fernet keys for unit tests.

### Contributing

- Use descriptive commit messages that summarize your changes.
- Ensure the test suite passes locally with `pytest` before pushing.
