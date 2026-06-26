#!/usr/bin/env python3
"""
Generate a fresh Ed25519 keypair for catalog or plugin signing.

Writes the private key as 32-byte raw bytes (matches the platform's
PluginSignatureVerifier.swift convention) and the public key as both raw
bytes (for the platform) and hex-encoded SHA-256 fingerprint (for the
catalog's signer_public_key_sha256 field).

Output files:
    <name>.key           — 32-byte raw private (KEEP SECRET; chmod 0600)
    <name>.pub           — 32-byte raw public (operator-distributed)
    <name>.fingerprint   — SHA-256(public) hex string (catalog-entry handle)

Usage:
    generate-ed25519-keypair.py <name>
"""

import hashlib
import os
import sys
from pathlib import Path

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
except ImportError:
    print("error: python3 -m pip install --user cryptography", file=sys.stderr)
    sys.exit(2)


def main():
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <name>", file=sys.stderr)
        sys.exit(2)
    name = sys.argv[1]
    if "/" in name or ".." in name:
        print("error: name must not contain path separators", file=sys.stderr)
        sys.exit(2)
    out_dir = Path.cwd()
    privkey_path = out_dir / f"{name}.key"
    pubkey_path = out_dir / f"{name}.pub"
    fingerprint_path = out_dir / f"{name}.fingerprint"
    if privkey_path.exists():
        print(f"refuse to overwrite {privkey_path}", file=sys.stderr)
        sys.exit(2)
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    priv_raw = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_raw = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    pub_fp = hashlib.sha256(pub_raw).hexdigest()
    privkey_path.write_bytes(priv_raw)
    os.chmod(privkey_path, 0o600)
    pubkey_path.write_bytes(pub_raw)
    fingerprint_path.write_text(pub_fp + "\n")
    print(f"private key:        {privkey_path}  (mode 0600 — keep secret)")
    print(f"public key:         {pubkey_path}")
    print(f"public fingerprint: {pub_fp}")
    print(f"                    (use as signer_public_key_sha256 in catalog)")


if __name__ == "__main__":
    main()
