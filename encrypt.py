#!/usr/bin/env python3
"""
Encryption script - Encrypt conversation files using AES-256-GCM.
"""

import os
import sys
import json
import base64
import hashlib
import argparse
import secrets
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ZK_DIR = Path.home() / ".zkp"
DATA_DIR = ZK_DIR / "data"
KEYS_FILE = ZK_DIR / "keys" / "identity.json"

def get_session_key() -> bytes:
    """Derive session key from identity key."""
    if not KEYS_FILE.exists():
        print("❌ Keys not found. Run init_protection.py first.")
        sys.exit(1)
    
    with open(KEYS_FILE) as f:
        keys = json.load(f)
    
    # Derive encryption key from secret
    # In production, use proper KDF
    key = hashlib.pbkdf2_hmac(
        'sha256',
        keys['secret_key'].encode(),
        b'conversation_encryption',
        100000,
        dklen=32
    )
    
    return key

def encrypt_file(input_path: Path, output_path: Path = None):
    """Encrypt a single file."""
    key = get_session_key()
    aesgcm = AESGCM(key)
    
    # Read file content
    with open(input_path, 'rb') as f:
        plaintext = f.read()
    
    # Generate nonce
    nonce = secrets.token_bytes(12)
    
    # Encrypt
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    
    # Create encrypted file format
    encrypted_data = {
        "version": 1,
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "original_name": input_path.name,
        "original_size": len(plaintext)
    }
    
    # Determine output path
    if output_path is None:
        output_path = DATA_DIR / f"{input_path.name}.enc"
    
    # Write encrypted data
    with open(output_path, 'w') as f:
        json.dump(encrypted_data, f)
    
    print(f"✅ Encrypted: {input_path.name} -> {output_path.name}")
    print(f"   Original: {len(plaintext)} bytes")
    print(f"   Encrypted: {len(ciphertext)} bytes")

def encrypt_directory(directory: Path, pattern: str = "*.md"):
    """Encrypt all files in a directory."""
    files = list(directory.glob(pattern))
    
    if not files:
        print(f"No files matching {pattern} in {directory}")
        return
    
    print(f"Encrypting {len(files)} files...")
    for f in files:
        # Save to .zkp/data
        output_path = DATA_DIR / f"{f.name}.enc"
        encrypt_file(f, output_path)
    
    print(f"\n✅ Encrypted {len(files)} files")

def main():
    parser = argparse.ArgumentParser(description="Encrypt conversation files")
    parser.add_argument("--file", type=str, help="File to encrypt")
    parser.add_argument("--all", action="store_true", help="Encrypt all conversation files")
    parser.add_argument("--directory", type=str, default="memory", help="Directory to encrypt")
    
    args = parser.parse_args()
    
    # Ensure data directory exists
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    
    if args.file:
        encrypt_file(Path(args.file))
    elif args.all:
        directory = Path.home() / ".openclaw" / "workspace" / args.directory
        if not directory.exists():
            print(f"❌ Directory not found: {directory}")
            return
        encrypt_directory(directory)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
