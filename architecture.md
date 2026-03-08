# ZKP Conversation Protection - Architecture

## Overview

This system provides zero-knowledge proof based protection for local conversation files. It combines:
- **Encryption at rest**: AES-256-GCM for file encryption
- **Identity verification**: ZK proofs for network access
- **Transparent local access**: No overhead for normal usage

## System Components

```
┌─────────────────────────────────────────────────────────────────┐
│                        User Space                               │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   ┌──────────────┐     ┌──────────────┐     ┌──────────────┐  │
│   │   OpenClaw   │     │  Auto-Protect │     │   Network    │  │
│   │   (正常对话)   │     │   (闲置监控)   │     │   Guard     │  │
│   └──────┬───────┘     └──────┬───────┘     └──────┬───────┘  │
│          │                    │                    │           │
│          └────────────┬────────┴────────────────────┘           │
│                       ↓                                          │
│   ┌────────────────────────────────────────────────────────────┐ │
│   │                    Key Manager                              │ │
│   │              (.zkp/keys/identity.json)                     │ │
│   └────────────────────────────────────────────────────────────┘ │
│                       ↓                                          │
│   ┌────────────────────────────────────────────────────────────┐ │
│   │                    Crypto Layer                            │ │
│   │    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐  │ │
│   │    │   AES-256   │    │    ZKP      │    │    KDF      │  │ │
│   │    │   (加密)     │    │  (证明)     │    │   (密钥派生)  │  │ │
│   │    └─────────────┘    └─────────────┘    └─────────────┘  │ │
│   └────────────────────────────────────────────────────────────┘ │
│                       ↓                                          │
│   ┌────────────────────────────────────────────────────────────┐ │
│   │                    Storage Layer                            │ │
│   │    ┌─────────────┐    ┌─────────────┐                     │ │
│   │    │  明文文件    │    │  加密文件   │                     │ │
│   │    │  (memory/)  │    │  (.zkp/)   │                     │ │
│   │    └─────────────┘    └─────────────┘                     │ │
│   └────────────────────────────────────────────────────────────┘ │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Access Patterns

### 1. Local Direct Access (Default)

```
用户 ←→ OpenClaw ←→ memory/*.md (明文)
```

- No encryption/decryption overhead
- Files always accessible
- Used during active conversation

### 2. Idle State

```
┌─────────────────────────────────────┐
│  闲置超过阈值 (默认5分钟)            │
└─────────────────┬───────────────────┘
                  ↓
┌─────────────────────────────────────┐
│  auto_protect.py 检测到闲置         │
└─────────────────┬───────────────────┘
                  ↓
┌─────────────────────────────────────┐
│  encrypt.py 加密所有对话文件         │
│  → .zkp/data/*.enc                  │
└─────────────────┬───────────────────┘
                  ↓
┌─────────────────────────────────────┐
│  内存中的密钥保留                     │
│  (下一会话可直接使用)                 │
└─────────────────────────────────────┘
```

### 3. Network Access (External)

```
外部请求 ──→ guard.py ──→ 需ZK证明
                      │
                      ├─ 证明有效 ──→ 解密 ──→ 返回数据
                      │
                      └─ 证明无效 ──→ 拒绝访问
```

## Key Files

| File | Location | Purpose |
|------|----------|---------|
| `identity.json` | `~/.zkp/keys/` | ZKP identity keys |
| `config.yaml` | `~/.zkp/` | System configuration |
| `*.enc` | `~/.zkp/data/` | Encrypted conversation files |
| `last_access.json` | `~/.zkp/` | Idle tracking |

## Data Flow

### Encryption Flow

```
1. load secret_key from identity.json
2. derive encryption_key via PBKDF2(secret_key, "conversation_encryption")
3. generate random nonce (12 bytes)
4. encrypt plaintext with AES-256-GCM(key, nonce, plaintext)
5. store: {version, nonce, ciphertext, original_name}
```

### ZK Proof Flow (Network Access)

```
Prover (AI Agent):
1. generate random challenge (32 bytes)
2. compute response = H(secret_key || challenge)
3. compute PoW = H(public_key || challenge || counter) 
   (with increasing counter until hash starts with N zeros)
4. send {challenge, response, proof_of_work, counter, public_key}

Verifier (Guard):
1. check PoW difficulty
2. verify response = H(secret_key || challenge)
3. if valid: grant access
   else: deny access
```

### Access Decision Logic

```
Request arrives:
  │
  ├─ 来源 = 本地 (127.0.0.1/localhost)?
  │   └─ 是 → 允许访问 (透明)
  │
  ├─ 来源 = 网络?
  │   │
  │   ├─ 有 X-ZKP-Proof header?
  │   │   └─ 否 → 401 要求证明
  │   │
  │   └─ 有证明 → 验证
  │       │
  │       ├─ 有效 → 200 允许
  │       └─ 无效 → 403 拒绝
```

## Security Properties

### Encryption Security

- **Algorithm**: AES-256-GCM (authenticated encryption)
- **Key Derivation**: PBKDF2-HMAC-SHA256 with 100,000 iterations
- **Nonce**: 96-bit random per encryption
- **Integrity**: GCM provides authentication

### ZKP Security

- **Proof Type**: Schnorr-like (non-interactive)
- **Knowledge**: Proves knowledge of secret key without revealing it
- **Non-transferable**: Proof cannot be replayed (challenge is random)
- **Proof of Work**: Prevents brute-force attacks

### Network Security

- **Transparent Local**: No ZK overhead for local access
- **Guard on Edge**: All network traffic through guard
- **Default Deny**: No access without valid proof
