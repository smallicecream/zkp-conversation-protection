#!/usr/bin/env python3
"""
Decryption script - Decrypt conversation files using AES-256-GCM.
"""

import os
import sys
import json
import base64
import hashlib
import argparse
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
    
    key = hashlib.pbkdf2_hmac(
        'sha256',
        keys['secret_key'].encode(),
        b'conversation_encryption',
        100000,
        dklen=32
    )
    
    return key

def decrypt_file(input_path: Path, output_path: Path = None):
    """Decrypt a single file."""
    key = get_session_key()
    aesgcm = AESGCM(key)
    
    # Read encrypted data
    with open(input_path, 'r') as f:
        encrypted_data = json.load(f)
    
    # Decode
    nonce = base64.b64decode(encrypted_data["nonce"])
    ciphertext = base64.b64decode(encrypted_data["ciphertext"])
    
    # Decrypt
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    except Exception as e:
        print(f"❌ Decryption failed: {e}")
        return None
    
    # Determine output path
    if output_path is None:
        # Output next to original
        output_path = input_path.with_suffix(input_path.suffix + ".decrypted")
    
    # Write decrypted data
    with open(output_path, 'wb') as f:
        f.write(plaintext)
    
    print(f"✅ Decrypted: {input_path.name} -> {output_path.name}")
    print(f"   Original size: {encrypted_data['original_size']} bytes")
    
    return plaintext

def list_encrypted_files():
    """List all encrypted files."""
    if not DATA_DIR.exists():
        print("No encrypted files found")
        return []
    
    files = list(DATA_DIR.glob("*.enc"))
    return files

def main():
    parser = argparse.ArgumentParser(description="Decrypt conversation files")
    parser.add_argument("--file", type=str, help="File to decrypt")
    parser.add_argument("--list", action="store_true", help="List encrypted files")
    parser.add_argument("--directory", type=str, help="Output directory")
    
    args = parser.parse_args()
    
    if args.list:
        files = list_encrypted_files()
        print(f"Encrypted files in {DATA_DIR}:")
        for f in files:
            print(f"  - {f.name}")
        return
    
    if args.file:
        input_path = Path(args.file)
        if not input_path.exists():
            # Try in DATA_DIR
            input_path = DATA_DIR / args.file
        
        output_dir = Path(args.directory) if args.directory else None
        output_path = None
        if output_dir:
            output_dir.mkdir(parents=True, exist_ok=True)
            output_path = output_dir / input_path.stem.replace(".enc", "")
        
        decrypt_file(input_path, output_path)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
