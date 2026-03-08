# Security Analysis

## Threat Model

We consider the following threats:

1. **Physical Theft**: Device stolen, hard drive extracted
2. **Network Attack**: External attacker tries to access files
3. **Memory Attack**: Cold boot attack, memory dump
4. **Eavesdropping**: Network traffic interception

## Security Properties

### 1. Encrypted at Rest

| Property | Implementation |
|----------|---------------|
| Confidentiality | AES-256-GCM encryption |
| Integrity | GCM authentication tag |
| Key Derivation | PBKDF2 (100k iterations) |

**Protection against**: Physical theft, hard drive extraction

### 2. Zero-Knowledge Network Access

| Property | Implementation |
|----------|---------------|
| Knowledge | Prover knows secret, verifier learns nothing |
| Non-interactive | Single message proof |
| Freshness | Random challenge each time |
| DoS Resistance | Proof of work |

**Protection against**: Network attacks, external malicious access

### 3. Transparent Local Access

| Property | Implementation |
|----------|---------------|
| Performance | No encryption overhead during conversation |
| Seamless | Same user experience as before |

**Design goal**: Security without sacrificing usability

## Attack Scenarios

### Scenario 1: Laptop Stolen

```
Attack: Extract hard drive, read memory files
Defense: Files encrypted with AES-256-GCM
Result: ❌ Attacker cannot read
```

### Scenario 2: Network Port Scan

```
Attack: Scan port 18060, try to access API
Defense: Guard requires valid ZK proof
Result: ❌ Attack blocked (no valid proof)
```

### Scenario 3: Malicious Input via Network

```
Attack: Send crafted requests to network API
Defense: ZK proof verifies AI identity + input validation
Result: ❌ Rejected
```

### Scenario 4: Replay Attack

```
Attack: Replay previous valid request
Defense: Fresh random challenge each time
Result: ❌ Rejected (challenge doesn't match)
```

### Scenario 5: Brute Force ZK Proof

```
Attack: Try to guess proof
Defense: Proof of work (16+ zeros prefix)
Result: ❌ Computationally infeasible
```

## Limitations

### Not Protected Against

1. **Runtime Memory Access**: If attacker has code execution, can read memory
2. **Coordinated Attack**: If both keys and encrypted files stolen
3. **Social Engineering**: If user reveals keys

### Trade-offs

1. **Local Keys**: Keys stored on device (necessary for auto-decrypt)
2. **Performance vs Security**: Faster proof = lower difficulty
3. **Usability vs Safety**: More strict = less convenient

## Recommendations

### Production Use

1. **Increase PoW difficulty** from 16 to 20+ zeros
2. **Use hardware security module** (HSM) for key storage
3. **Add rate limiting** to guard
4. **Use TLS** even for local connections

### Key Management

1. **Backup keys** securely (encrypted USB)
2. **Never share** secret key
3. **Rotate keys** periodically

## Verification

Test security with:

```bash
# 1. Verify encryption works
python3 scripts/encrypt.py --all
# Files in .zkp/data should be unreadable

# 2. Test network protection
curl http://localhost:18060/api/test
# Should return 401

# 3. Test with valid proof
proof=$(python3 scripts/zk_prover.py -o /dev/stdout)
curl -H "X-ZKP-Proof: $proof" http://localhost:18060/api/test
# Should return 200
```
