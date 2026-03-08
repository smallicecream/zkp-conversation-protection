---
name: zkp-conversation-protection
description: >
  Zero-Knowledge Proof based protection for local conversation files. Provides three-layer protection:
  (1) Encrypted storage when idle, (2) ZK proof verification for network access, (3) Transparent local access.
  Use when: securing conversation history, protecting against network attacks, or when user asks about conversation security.
---

# ZKP Conversation Protection

Zero-knowledge proof based protection system for local conversation files. Protects against both idle theft and network attacks while maintaining normal conversation speed.

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                    Access Layer                      │
├─────────────────────────────────────────────────────┤
│  Local (direct file access)    vs    Network Access │
│  ┌─────────────┐                    ┌─────────────┐ │
│  │  Direct     │                    │  ZK Proof   │ │
│  │  Read/Write │                    │  Required   │ │
│  └─────────────┘                    └─────────────┘ │
│         ↓                                  ↓         │
│  ┌─────────────────────────────────────────────────┐│
│  │           Active Session (Memory)                ││
│  │    - Decrypted content in memory                 ││
│  │    - Auto-cleared on idle                        ││
│  └─────────────────────────────────────────────────┘│
│                        ↓                            │
│  ┌─────────────────────────────────────────────────┐│
│  │           Idle State (Encrypted)                 ││
│  │    - AES-256-GCM encrypted                       ││
│  │    - Key only in memory                          ││
│  └─────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────┘
```

## Quick Start

### 1. Initialize Protection System

```bash
python3 scripts/init_protection.py
```

This creates:
- `~/.zkp/keys/` - Key storage
- `~/.zkp/data/` - Encrypted conversation files
- `~/.zkp/config.yaml` - Configuration

### 2. Configure Network Guard

```bash
python3 scripts/guard.py --install
```

Installs network access guard that intercepts external requests.

### 3. Verify Setup

```bash
python3 scripts/zk_prover.py --verify
python3 scripts/guard.py --status
```

## Scripts

| Script | Purpose |
|--------|---------|
| `init_protection.py` | Initialize ZKP protection system |
| `encrypt.py` | Encrypt conversation files |
| `decrypt.py` | Decrypt with ZK proof |
| `zk_prover.py` | Generate ZK proof of AI identity |
| `zk_verifier.py` | Verify ZK proof |
| `guard.py` | Network access guard |
| `auto_protect.py` | Auto-encrypt on idle |

## Usage

### Normal Conversation (Local)

No changes - files automatically encrypted when idle.

### Network Access

External requests must include valid ZK proof:

```python
# Client request
proof = zk_prover.generate_proof(secret_key, challenge)
request = {"challenge": challenge, "proof": proof}

# Server verification  
if zk_verifier.verify(proof):
    # Grant access
else:
    # Deny access
```

### Manual Operations

```bash
# Encrypt all conversation files
python3 scripts/encrypt.py --all

# Decrypt for reading
python3 scripts/decrypt.py --file memory/2026-03-08.md

# Check protection status
python3 scripts/guard.py --status
```

## Security Properties

1. **Zero-Knowledge**: Verifier learns nothing about the secret key
2. **Non-Interactive**: Single message proof (Schnorr-based)
3. **Fast Verification**: ~1ms per proof check
4. **Forward Secrecy**: Session keys rotated on each access

## Configuration

Edit `~/.zkp/config.yaml`:

```yaml
protection:
  auto_encrypt_idle_seconds: 300
  require_proof_for_network: true
  allowed_network_origins:
    - localhost
    - 127.0.0.1
  
zkp:
  curve: secp256k1
  hash_algorithm: sha256
```

## References

- [architecture.md](references/architecture.md) - Detailed architecture
- [security.md](references/security.md) - Security analysis
- [api.md](references/api.md) - API documentation
