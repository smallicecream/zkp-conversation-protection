#!/usr/bin/env python3
"""
ZKP Conversation Protection - Initialization Script
Creates the protection system directories and keys.
"""

import os
import sys
import json
import hashlib
import secrets
from pathlib import Path

ZK_DIR = Path.home() / ".zkp"
KEYS_DIR = ZK_DIR / "keys"
DATA_DIR = ZK_DIR / "data"
CONFIG_FILE = ZK_DIR / "config.yaml"

def create_directories():
    """Create necessary directories."""
    for d in [ZK_DIR, KEYS_DIR, DATA_DIR]:
        d.mkdir(parents=True, exist_ok=True)
        print(f"✓ Created {d}")

def generate_keys():
    """Generate ZKP key pair and secret."""
    # Generate secret key (256-bit)
    secret_key = secrets.token_hex(32)
    
    # Generate public key from secret (simple hash for demo)
    # In production, use proper ECDH
    public_key = hashlib.sha256(secret_key.encode()).hexdigest()
    
    # Store keys
    keys = {
        "secret_key": secret_key,
        "public_key": public_key,
        "created_at": __import__("datetime").datetime.now().isoformat()
    }
    
    key_file = KEYS_DIR / "identity.json"
    with open(key_file, "w") as f:
        json.dump(keys, f, indent=2)
    
    # Set restrictive permissions
    os.chmod(key_file, 0o600)
    
    print(f"✓ Generated ZKP identity keys")
    print(f"  Public key: {public_key[:16]}...")
    
    return secret_key, public_key

def create_config():
    """Create default configuration."""
    config = """# ZKP Conversation Protection Configuration

protection:
  # Auto-encrypt after this many seconds of idle
  auto_encrypt_idle_seconds: 300
  
  # Require ZKP proof for network access
  require_proof_for_network: true
  
  # Allowed network origins (empty = allow all)
  allowed_network_origins: []
  
  # Network port to guard
  guard_port: 18060

zkp:
  # Elliptic curve for ZKP
  curve: secp256k1
  
  # Hash algorithm
  hash_algorithm: sha256
  
  # Proof difficulty (higher = more secure but slower)
  difficulty: 16

storage:
  # Encryption algorithm
  cipher: AES-256-GCM
  
  # Key derivation rounds
  kdf_rounds: 100000
"""
    
    with open(CONFIG_FILE, "w") as f:
        f.write(config)
    
    os.chmod(CONFIG_FILE, 0o600)
    print(f"✓ Created configuration at {CONFIG_FILE}")

def main():
    print("=" * 50)
    print("ZKP Conversation Protection - Initialization")
    print("=" * 50)
    print()
    
    if ZK_DIR.exists():
        print("⚠ Protection system already exists!")
        response = input("Re-initialize? This will generate new keys (y/N): ")
        if response.lower() != 'y':
            print("Cancelled.")
            return
    
    print("Creating directories...")
    create_directories()
    print()
    
    print("Generating ZKP keys...")
    secret, public = generate_keys()
    print()
    
    print("Creating configuration...")
    create_config()
    print()
    
    print("=" * 50)
    print("✅ Initialization complete!")
    print("=" * 50)
    print()
    print("Next steps:")
    print("  1. Install network guard: python3 scripts/guard.py --install")
    print("  2. Verify setup: python3 scripts/guard.py --status")
    print()

if __name__ == "__main__":
    main()
