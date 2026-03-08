# ZKP Conversation Protection

Zero-knowledge proof based protection system for local conversation files. Provides three-layer protection against physical theft, network attacks, and idle data exposure while maintaining transparent local access.

## Features

- 🔐 **Encrypted at Rest**: AES-256-GCM encryption when idle
- 🌐 **ZK Network Guard**: Zero-knowledge proof required for network access
- 🏠 **Transparent Local**: No overhead for normal conversation
- ⏰ **Auto-Protection**: Automatically encrypts after idle period

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                  Access Layer                        │
├─────────────────────────────────────────────────────┤
│  Local (direct file access)    vs    Network Access│
│  ┌─────────────┐                    ┌─────────────┐ │
│  │  Direct     │                    │  ZK Proof   │ │
│  │  Read/Write │                    │  Required   │ │
│  └─────────────┘                    └─────────────┘ │
└─────────────────────────────────────────────────────┘
```

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Initialize protection system
python3 scripts/init_protection.py

# Start network guard (in separate terminal)
python3 scripts/guard.py

# Start auto-protection daemon
python3 scripts/auto_protect.py --start
```

## Scripts

| Script | Purpose |
|--------|---------|
| `init_protection.py` | Initialize ZKP protection system |
| `encrypt.py` | Encrypt conversation files |
| `decrypt.py` | Decrypt with ZK proof |
| `zk_prover.py` | Generate ZK proof of AI identity |
| `guard.py` | Network access guard |
| `auto_protect.py` | Auto-encrypt on idle |

## Security

See [references/security.md](references/security.md) for detailed security analysis.
