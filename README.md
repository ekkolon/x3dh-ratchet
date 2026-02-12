# Signal Protocol Implementation in Rust

[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE)
[![Rust Version](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org)

Production-grade implementation of the [Signal Protocol](https://signal.org/docs/) in Rust, featuring:

- **X3DH (Extended Triple Diffie-Hellman)** - Asynchronous key agreement
- **Double Ratchet** - Forward-secure message encryption
- Memory-safe, constant-time operations
- Comprehensive test coverage (unit, property, fuzz)
- Security-focused API design

## ⚠️ Security Notice

This implementation is designed for production use but has not undergone formal security audit. Use at your own risk. For mission-critical applications, consider professionally audited alternatives.

## Security Properties

### Provided Guarantees

1. **Forward Secrecy**: Compromise of long-term keys does not compromise past messages
2. **Post-Compromise Security**: Communication security restored after key compromise
3. **Deniable Authentication**: No cryptographic proof of message authorship
4. **Asynchronous Communication**: Sender can encrypt without recipient being online
5. **Out-of-Order Message Handling**: Messages decrypt correctly regardless of delivery order

### Threat Model

**Assumes:**

- Adversary can compromise devices and extract key material
- Adversary can inject, modify, delay, or drop messages
- Adversary cannot break X25519, Ed25519, HKDF-SHA256, or AEAD primitives

**Does NOT protect against:**

- Side-channel attacks (timing, power analysis, etc.) - partially mitigated but not formally verified
- Traffic analysis and metadata
- Endpoint compromise during active use
- Post-quantum adversaries (unless using X448 feature with appropriate KEM)

## Installation

Add to `Cargo.toml`:

```toml
[dependencies]
signal-protocol = "0.1"
```

Or with serialization support:

```toml
[dependencies]
signal-protocol = { version = "0.1", features = ["serde"] }
```

## Quick Start

```rust
use x3dh_ratchet::keys::IdentityKeyPair;
use x3dh_ratchet::x3dh::{initiate, respond, PreKeyState};
use x3dh_ratchet::double_ratchet::DoubleRatchet;
use rand_core::OsRng;

// Responder (Bob) generates prekey bundle
let bob_identity = IdentityKeyPair::generate(&mut OsRng);
let mut bob_prekeys = PreKeyState::generate(&mut OsRng, &bob_identity);
let bob_bundle = bob_prekeys.public_bundle();

// Initiator (Alice) performs X3DH
let alice_identity = IdentityKeyPair::generate(&mut OsRng);
let alice_x3dh = initiate(&mut OsRng, &alice_identity, &bob_bundle)?;

// Bob responds
let bob_x3dh = respond(&mut bob_prekeys, &alice_x3dh.initial_message)?;

// Both now have identical shared secret
assert_eq!(
    alice_x3dh.shared_secret.as_bytes(),
    bob_x3dh.shared_secret.as_bytes()
);

// Initialize Double Ratchet
let bob_dh = SecretKey::generate(&mut OsRng);
let mut alice_ratchet = DoubleRatchet::init_sender(
    &mut OsRng,
    alice_x3dh,
    bob_dh.public_key(),
);
let mut bob_ratchet = DoubleRatchet::init_receiver(
    bob_x3dh.shared_secret,
    bob_dh,
);

// Exchange encrypted messages
let message = b"Hello, World!";
let encrypted = alice_ratchet.encrypt(message, b"")?;
let decrypted = bob_ratchet.decrypt(&encrypted, b"")?;

assert_eq!(&decrypted, message);
```

See [examples/complete_flow.rs](examples/complete_flow.rs) for detailed usage.

## Architecture

### Module Structure

```txt
signal_protocol/
├── x3dh/           # X3DH key agreement
├── double_ratchet/ # Double Ratchet encryption
├── keys/           # Cryptographic key types
├── crypto/         # Primitives (HKDF, KDF chains)
├── storage/        # Prekey and message key storage
└── error/          # Non-leaky error types
```

### X3DH Protocol Flow

```txt
|─────────────────|                    |──────────────────|
| Responder (Bob) |                    |Initiator (Alice) |
|─────────────────|                    |──────────────────|

1. Generate identity key (IK_B)
2. Generate signed prekey (SPK_B)
3. Sign SPK_B with IK_B
4. Generate one-time prekeys (OPK_B)
5. Publish bundle
                                        6. Fetch bundle
                                        7. Verify signature
                                        8. Generate ephemeral key (EK_A)
                                        9. Compute:
                                           DH1 = DH(IK_A, SPK_B)
                                           DH2 = DH(EK_A, IK_B)
                                           DH3 = DH(EK_A, SPK_B)
                                           DH4 = DH(EK_A, OPK_B)
                                           SK = KDF(DH1‖DH2‖DH3‖DH4)
                                        10. Send (IK_A, EK_A, used_OPK_B)
11. Compute same DH operations
12. Derive same SK
```

### Double Ratchet Algorithm

```txt
     Root Chain              Sending Chain           Receiving Chain
     ──────────              ─────────────           ───────────────
        RK                        CKs                     CKr
         │                         │                       │
    DH ratchet ───────────────────┘                       │
         │                         │                       │
         ├─────────────────────────┼───────────────────────┤
         │                         │                       │
       New RK                  Message Key 1           Message Key 1'
         │                         │                       │
         │                     Encrypt M1              Decrypt M1
         │                         │                       │
         │                   Symmetric ratchet        Symmetric ratchet
         │                         │                       │
```

## Testing

### Run Unit Tests

```bash
cargo test
```

### Run Property Tests

```bash
cargo test --test property_tests
```

### Run Benchmarks

```bash
cargo bench
```

Expected performance on modern hardware:

- X3DH handshake: ~100-200 μs
- Message encryption: ~10-20 μs per message
- Message decryption: ~10-20 μs per message

### Fuzz Testing

```bash
cargo install cargo-fuzz
cargo +nightly fuzz run bundle_parsing
cargo +nightly fuzz run message_parsing
cargo +nightly fuzz run encrypt_decrypt
cargo +nightly fuzz run header_parsing
```

## API Design Principles

### 1. Correct Before Clever

Prioritize correctness over performance optimizations. All crypto operations use well-reviewed implementations.

### 2. Explicit Over Implicit

No hidden state or magic. All randomness is explicitly injected.

```rust
// Good: Explicit RNG
let key = SecretKey::generate(&mut OsRng);

// Bad: Hidden global RNG (not used in this crate)
let key = SecretKey::generate(); // ❌
```

### 3. Safe By Default

Secret keys automatically zeroize on drop. No manual cleanup required.

```rust
{
    let secret = SecretKey::generate(&mut OsRng);
    // ... use secret ...
} // Automatically zeroized here
```

### 4. Misuse Resistant

Type system prevents common errors:

```rust
// Cannot accidentally print secrets
println!("{:?}", secret_key); // Shows "SecretKey([REDACTED])"

// Cannot clone secrets without explicit intent
let copy = secret_key.clone(); // ❌ Compile error

// Cannot reuse ephemeral keys
// Enforced by ownership system
```

## Error Handling

All errors are non-leaky and typed:

```rust
pub enum Error {
    InvalidSignature,
    InvalidPublicKey,
    KeyAgreementFailed,
    DecryptionFailed,
    // ... etc
}
```

Errors never expose:

- Key material
- Plaintext data
- Internal state
- Timing information (where possible)

## Serialization

Optional serialization via `serde` feature:

```toml
[dependencies]
signal-protocol = { version = "0.1", features = ["serde"] }
```

**Security Note**: Only public bundles are serializable by default. Private keys require explicit opt-in to prevent accidental exposure.

## Best Practices

### Key Rotation

```rust
// Rotate signed prekey periodically (e.g., weekly)
let new_prekey_state = PreKeyState::generate(&mut OsRng, &identity);

// Replenish one-time prekeys when running low
if prekey_state.one_time_prekeys.len() < 10 {
    // Generate more...
}
```

### Storage

Implement custom storage backend:

```rust
use x3dh_ratchet::storage::PreKeyStorage;

struct DatabaseStorage { /* ... */ }

impl PreKeyStorage for DatabaseStorage {
    fn store_one_time_prekey(&mut self, id: u32, key: SecretKey) -> Result<()> {
        // Store in database with encryption at rest
    }
    // ... implement other methods
}
```

### Associated Data

Use associated data for context binding:

```rust
let context = format!("chat_room:{}", room_id);
let encrypted = ratchet.encrypt(plaintext, context.as_bytes())?;
```

## Roadmap

- [ ] Formal security audit
- [ ] X448 support for post-quantum resistance
- [ ] ChaCha20-Poly1305 AEAD (currently simplified)
- [ ] Header encryption
- [ ] Group messaging (Sender Keys)
- [ ] Sealed sender
- [ ] Session management utilities

## Contributing

Contributions welcome! Please:

1. Run `cargo test` and `cargo clippy` before submitting
2. Add tests for new functionality
3. Update documentation
4. Follow existing code style

## Security Reporting

**DO NOT** open public issues for security vulnerabilities.

Please report security issues privately to: <ekkolon@proton.com>

## References

- [Signal Protocol Specification](https://signal.org/docs/specifications/doubleratchet/)
- [X3DH Specification](https://signal.org/docs/specifications/x3dh/)
- [Double Ratchet Algorithm](https://signal.org/docs/specifications/doubleratchet/)
- [The Double Ratchet Algorithm (PDF)](https://signal.org/docs/specifications/doubleratchet/doubleratchet.pdf)

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option.

## Disclaimer

This software is provided "as is" without warranty. The authors assume no liability for any damages from use.
