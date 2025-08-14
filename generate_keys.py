#!/usr/bin/env python3
"""
Key generation utility for Bitsafe middleware.

This script generates RSA public-private key pairs for secure password encryption.
"""

import argparse
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def generate_key_pair(key_size=2048):
    """Generate RSA public-private key pair."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_pem.decode('utf-8'), public_pem.decode('utf-8')


def main():
    parser = argparse.ArgumentParser(
        description='Generate RSA key pairs for Bitsafe')
    parser.add_argument('--key-size', type=int, default=2048,
                        help='RSA key size (default: 2048)')
    parser.add_argument('--output-dir', type=str, default='.',
                        help='Output directory for keys')

    args = parser.parse_args()

    private_key, public_key = generate_key_pair(args.key_size)

    # Save keys to files
    with open(f'{args.output_dir}/private_key.pem', 'w') as f:
        f.write(private_key)

    with open(f'{args.output_dir}/public_key.pem', 'w') as f:
        f.write(public_key)

    print(f"✅ Generated {args.key_size}-bit RSA key pair")
    print(f"📁 Private key saved to: {args.output_dir}/private_key.pem")
    print(f"📁 Public key saved to: {args.output_dir}/public_key.pem")
    print("\n🔒 Keep the private key secure and never share it!")
    print("📤 Share the public key with Dario for frontend encryption")


if __name__ == "__main__":
    main()
