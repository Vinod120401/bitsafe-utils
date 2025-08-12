# bitsafe-utils

Building a system to motivate users into knowing, using and holding our token.

## Crypto Service

`bitsafe_utils.crypto_service` provides helpers to decrypt a password with an
RSA private key and re-encrypt it using an application secret before sending it
to the Bitsafe backend. This keeps the application secret outside of the
frontend while ensuring the backend never sees the password in plaintext.

### Development

Install dependencies:

```bash
pip install -r requirements.txt
```

### Testing

```bash
pytest
```
