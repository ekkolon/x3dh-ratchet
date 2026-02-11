# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Cryptographic Primitives

This implementation uses the following well-reviewed cryptographic libraries:

- **x25519-dalek** (v2.0+) - X25519 key exchange
- **ed25519-dalek** (v2.1+) - Ed25519 signatures
- **curve25519-dalek** (v4.1+) - Curve25519 operations
- **hkdf** (v0.12+) - HMAC-based key derivation
- **sha2** (v0.10+) - SHA-256 hashing
- **hmac** (v0.12+) - HMAC construction

All primitives are from well-established, audited crates in the Rust ecosystem.

## Security Assumptions

### What We Guarantee

1. **Memory Safety**: `#![forbid(unsafe_code)]` - no unsafe Rust
2. **Key Zeroization**: All secret material zeroized on drop
3. **Constant-Time Operations**: Where provided by underlying libraries
4. **Non-Leaky Errors**: Error messages don't expose sensitive data

### What We DON'T Guarantee

1. **Side-Channel Resistance**: Not formally verified against timing attacks
2. **Post-Quantum Security**: X25519/Ed25519 are vulnerable to quantum computers
3. **Implementation Audit**: This code has not undergone professional security audit
4. **Formal Verification**: No machine-checked proofs of correctness

## Known Limitations

### 1. Simplified AEAD

**Current Implementation**: Uses HMAC-based encryption (demonstration only)

**Required for Production**: Replace with proper ChaCha20-Poly1305 AEAD

```rust
// Current (NOT production-safe):
encrypt() -> HMAC-based construction

// Required (production):
encrypt() -> ChaCha20-Poly1305 AEAD
```

**Impact**: Current encryption is NOT semantically secure for production use.

**Mitigation**: See TODO in `src/crypto.rs` - integration with `chacha20poly1305` crate required.

### 2. RNG Injection

**Issue**: Some internal operations use `OsRng` directly rather than accepting injected RNG.

**Impact**: Reduces testability and deterministic reproducibility.

**Status**: Planned for v0.2.0

### 3. Header Encryption

**Current**: Message headers are authenticated but not encrypted.

**Impact**: Metadata leakage (message numbers, ratchet state).

**Status**: Roadmap item, not critical for basic functionality.

## Threat Model

### In Scope

- **Passive network adversary**: Can observe all traffic
- **Active network adversary**: Can modify, inject, drop messages
- **Device compromise**: Adversary gets snapshot of device state
- **Malformed input**: Fuzz testing ensures no panics or UB

### Out of Scope

- **Traffic analysis**: Timing, size, pattern analysis
- **Endpoint security**: Malware, keyloggers, screen capture
- **Physical attacks**: Side-channels, fault injection
- **Social engineering**: Phishing, impersonation
- **Quantum computers**: Post-quantum cryptography

## Reporting Security Vulnerabilities

**CRITICAL**: Do NOT open public GitHub issues for security vulnerabilities.

### Responsible Disclosure

1. **Email**: security@example.com (PGP key: [link])
2. **Subject**: `[SECURITY] signal-protocol-rs: <brief description>`
3. **Include**:
   - Description of vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### Response Timeline

- **24 hours**: Initial response acknowledging receipt
- **7 days**: Assessment and severity classification
- **30 days**: Patch development and testing
- **Public disclosure**: Coordinated after patch release

### Bug Bounty

Currently no bug bounty program. This may change in future versions.

## Security Best Practices for Users

### 1. Key Management

```rust
// ✅ Good: Generate fresh keys
let key = IdentityKeyPair::generate(&mut OsRng);

// ❌ Bad: Reuse keys across sessions
static KEY: IdentityKeyPair = /* ... */; // DON'T DO THIS
```

### 2. Prekey Rotation

```rust
// Rotate signed prekey regularly (e.g., weekly)
if prekey_age > Duration::from_days(7) {
    prekey_state = PreKeyState::generate(&mut OsRng, &identity);
}

// Replenish one-time prekeys
if prekey_state.one_time_prekeys.len() < 20 {
    // Generate more prekeys
}
```

### 3. Storage Security

```rust
// Encrypt keys at rest
fn store_prekey(key: &SecretKey) -> Result<()> {
    let encrypted = encrypt_with_master_key(key)?;
    database.store(encrypted)?;
    Ok(())
}
```

### 4. Error Handling

```rust
// ✅ Good: Handle errors without leaking info
match decrypt_message(ciphertext) {
    Ok(plaintext) => process(plaintext),
    Err(e) => {
        // Log generic error, don't expose details
        error!("Decryption failed");
        return Err(Error::DecryptionFailed);
    }
}

// ❌ Bad: Leaking information
Err(e) => {
    error!("Decryption failed: key={:?}, error={}", key, e); // DON'T
}
```

### 5. Associated Data

```rust
// Use context-specific associated data
let ad = format!("chat:{}:msg:{}", room_id, sequence);
let encrypted = ratchet.encrypt(message, ad.as_bytes())?;
```

## Audit History

**Status**: No professional audits conducted yet.

**Planned**: Seeking audit partners for v1.0 release.

## Security Contacts

- **Primary**: security@example.com
- **Backup**: [maintainer email]
- **PGP Key**: [fingerprint]

## Updates

Subscribe to security advisories:

- GitHub Security Advisories: [link]
- RSS feed: [link]
- Mailing list: [link]

---

Last updated: 2024-01-01
