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

Use `scripts/generate_keys.py` to generate a fresh RSA key pair:

```bash
python scripts/generate_keys.py --private ./private_key.pem --public ./public_key.pem
```

### Development

Install dependencies:

```bash
pip install -r requirements.txt
```

### Testing

```bash
pytest
```
