"""Generate an RSA key pair and write it to disk with secure permissions."""

from __future__ import annotations

import argparse
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def write_file(path: Path, data: bytes, private: bool = False) -> None:
    path.write_bytes(data)
    if private:
        os.chmod(path, 0o600)


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate RSA key pair")
    parser.add_argument("--private", default="private_key.pem", help="Private key output path")
    parser.add_argument("--public", default="public_key.pem", help="Public key output path")
    args = parser.parse_args()

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    write_file(Path(args.private), private_pem, private=True)
    write_file(Path(args.public), public_pem)
    print(f"Private key written to {args.private}")
    print(f"Public key written to {args.public}")


if __name__ == "__main__":
    main()
