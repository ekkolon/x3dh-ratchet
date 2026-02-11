# Signal Protocol Implementation - Design Document

## Overview

This document explains the design decisions, architecture, and implementation details of this Signal Protocol implementation in Rust.

## Goals

1. **Correctness**: Faithful implementation of Signal specifications
2. **Security**: Memory-safe, side-channel resistant where possible
3. **Usability**: Clean API that prevents misuse
4. **Performance**: Sub-millisecond handshakes on modern hardware
5. **Auditability**: Clear, readable code suitable for security review

## Non-Goals

- Custom cryptographic primitives (use well-reviewed libraries)
- Backward compatibility with non-compliant implementations
- Network transport (application layer responsibility)
- Group messaging (future extension)

## Architecture

### Module Hierarchy

```
signal_protocol
├── x3dh              # X3DH key agreement protocol
│   ├── Bundle        # Public prekey bundle
│   ├── PreKeyState   # Responder's secret state
│   ├── initiate()    # Initiator side
│   └── respond()     # Responder side
│
├── double_ratchet    # Double Ratchet encryption
│   ├── DoubleRatchet # Main ratchet state machine
│   ├── Header        # Message header structure
│   └── Message       # Encrypted message
│
├── keys              # Key types and operations
│   ├── SecretKey     # X25519 secret key
│   ├── PublicKey     # X25519 public key
│   ├── IdentityKeyPair
│   └── SigningKeyPair
│
├── crypto            # Cryptographic primitives
│   ├── derive_x3dh_secret()
│   ├── kdf_root()
│   ├── kdf_chain()
│   ├── encrypt()
│   └── decrypt()
│
├── storage           # Key storage abstractions
│   ├── PreKeyStorage trait
│   └── InMemoryStorage
│
└── error             # Error types
    └── Error enum
```

## X3DH Implementation

### Protocol Flow

```
Responder                          Initiator
─────────                          ─────────
IK_B (long-term)
SPK_B (signed prekey)
OPK_B (one-time prekey)
                                   IK_A (long-term)
                                   EK_A (ephemeral)

Publish: (IK_B, SPK_B, sig, OPK_B)
                 ─────────────────→ Fetch bundle
                                   Verify signature

                                   Compute:
                                   DH1 = DH(IK_A, SPK_B)
                                   DH2 = DH(EK_A, IK_B)
                                   DH3 = DH(EK_A, SPK_B)
                                   DH4 = DH(EK_A, OPK_B)

                                   SK = HKDF(DH1‖DH2‖DH3‖DH4)

                 ←──────────────── Send: (IK_A, EK_A, OPK_B_id)

Compute same DHs
Derive same SK
```

### Design Decisions

#### 1. Signature Scheme

**Decision**: Use Ed25519 for signing, separate from X25519 DH keys.

**Rationale**:

- Clear separation of key usage (DH vs signatures)
- Best practice per cryptographic guidelines
- Prevents key reuse vulnerabilities

**Alternative Considered**: XEdDSA (convert X25519 to Ed25519)

- **Rejected**: Added complexity, non-standard

#### 2. One-Time Prekey Management

**Decision**: Vector-based storage with explicit consumption.

**Implementation**:

```rust
pub struct PreKeyState {
    one_time_prekeys: Vec<SecretKey>,
}

impl PreKeyState {
    pub fn consume_one_time_prekey(&mut self) -> Result<SecretKey> {
        self.one_time_prekeys.pop().ok_or(Error::MissingOneTimePrekey)
    }
}
```

**Rationale**:

- Simple and correct
- Prevents accidental reuse
- Easy to extend with database backend

**Alternative Considered**: HashMap with explicit deletion

- **Rejected**: More complex, same functionality

#### 3. Bundle Verification

**Decision**: Separate `verify_signature()` method on Bundle.

**Rationale**:

- Makes verification explicit
- Allows checking bundle validity before initiating
- Clear point for error handling

```rust
let bundle = fetch_bundle()?;
bundle.verify_signature()?; // Explicit verification
let result = initiate(&mut rng, &identity, &bundle)?;
```

## Double Ratchet Implementation

### State Machine

```
State Components:
- root_key: SymmetricKey           # Updated on DH ratchet
- send_chain_key: SymmetricKey     # Updated per sent message
- recv_chain_key: SymmetricKey     # Updated per received message
- dh_send: SecretKey               # Current sending DH key
- dh_recv: PublicKey               # Current receiving DH key
- send_count: u32                  # Messages sent in current chain
- recv_count: u32                  # Messages received in current chain
- skipped_message_keys: HashMap    # Out-of-order message keys
```

### Ratchet Steps

#### Symmetric Ratchet (Every Message)

```
Current Chain Key
        │
        ├────→ Message Key (for encryption)
        │
        └────→ New Chain Key (for next message)
```

**Implementation**:

```rust
fn kdf_chain(chain_key: &SymmetricKey) -> (SymmetricKey, SymmetricKey) {
    let message_key = HMAC(chain_key, 0x01);
    let new_chain_key = HMAC(chain_key, 0x02);
    (new_chain_key, message_key)
}
```

#### DH Ratchet (New DH Public Key)

```
Old Root Key + DH Output
        │
        ├────→ New Root Key
        │
        └────→ New Chain Key
```

**Implementation**:

```rust
fn kdf_root(root_key: &SymmetricKey, dh_output: &DhOutput)
    -> (SymmetricKey, SymmetricKey) {
    let hkdf = HKDF::new(Some(root_key), dh_output);
    let (new_root, new_chain) = hkdf.expand(ROOT_INFO);
    (new_root, new_chain)
}
```

### Design Decisions

#### 1. Initialization

**Decision**: Separate `init_sender()` and `init_receiver()` constructors.

**Rationale**:

- Makes asymmetry explicit
- Prevents incorrect initialization
- Type-safe API

**Alternative Considered**: Single `new()` with role parameter

- **Rejected**: Error-prone, allows runtime mistakes

#### 2. Out-of-Order Messages

**Decision**: HashMap for skipped message keys with MAX_SKIP limit.

**Implementation**:

```rust
const MAX_SKIP: usize = 1000;

skipped_message_keys: HashMap<(PublicKey, u32), SymmetricKey>
```

**Rationale**:

- Prevents DoS via unbounded key storage
- O(1) lookup for skipped messages
- Configurable limit

**Security Consideration**: MAX_SKIP prevents adversary from forcing unbounded memory usage by sending high message numbers.

#### 3. Message Format

**Decision**: Length-prefixed header + ciphertext.

```
[4 bytes: header_len] [header_len bytes: header] [remaining: ciphertext]
```

**Rationale**:

- Simple framing
- No fixed-size constraints
- Easy to parse

## Key Types

### Memory Safety

All secret keys implement:

```rust
#[derive(Zeroize, ZeroizeOnDrop)]
struct SecretKey(StaticSecret);

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}
```

**Guarantees**:

- Automatic zeroization on drop
- No accidental cloning (no `Clone` trait)
- No debug printing (custom `Debug` impl)

### Type Safety

```rust
pub struct PublicKey([u8; 32]);     // Can copy, debug, serialize
pub struct SecretKey(StaticSecret); // Cannot copy, no debug
```

**Rationale**:

- Compiler enforces key handling rules
- Impossible to accidentally leak secrets
- Clear distinction between public and private

## Cryptographic Primitives

### Key Derivation

**X3DH Shared Secret**:

```
SK = HKDF-SHA256(
    ikm = DH1 ‖ DH2 ‖ DH3 ‖ DH4,
    salt = None,
    info = "Signal_X3DH_v1"
)
```

**Root KDF**:

```
(RK', CK') = HKDF-SHA256(
    ikm = dh_output,
    salt = RK,
    info = "Signal_DoubleRatchet_Root"
)
```

**Chain KDF**:

```
CK' = HMAC-SHA256(CK, 0x02)
MK  = HMAC-SHA256(CK, 0x01)
```

### Design Decisions

#### 1. Domain Separation

**Decision**: Unique info strings for each KDF usage.

**Rationale**:

- Prevents key reuse across contexts
- Cryptographic best practice
- Specified by Signal protocol

#### 2. Constant Extraction

**Decision**: Use fixed constants (0x01, 0x02) for chain KDF.

**Rationale**:

- Simple and efficient
- Specified by Double Ratchet spec
- Different from root KDF (uses HKDF)

## Error Handling

### Non-Leaky Errors

```rust
pub enum Error {
    InvalidSignature,      // No details
    DecryptionFailed,      // No key info
    KeyAgreementFailed,    // No intermediate values
}
```

**Principle**: Errors reveal minimal information.

**Anti-Pattern**:

```rust
// ❌ BAD - leaks key material
Err(format!("Decryption failed with key {:?}", key))

// ✅ GOOD - generic error
Err(Error::DecryptionFailed)
```

## Performance Considerations

### Benchmarking Results (Target)

```
X3DH initiate:     100-200 μs
X3DH respond:      100-200 μs
Encrypt (1KB):     10-20 μs
Decrypt (1KB):     10-20 μs
```

### Optimizations

1. **Precomputed Tables**: Use dalek's precomputed tables for scalar multiplication
2. **Batching**: Allow batch signature verification (future)
3. **Zero-Copy**: Minimize allocations in hot paths

### Non-Optimizations

**Deliberately NOT optimized**:

- Signature verification (correctness over speed)
- Key zeroization (security over speed)
- Error paths (rarely executed)

## Testing Strategy

### Test Pyramid

```
         /\
        /  \  Fuzz Tests (no panics, no UB)
       /────\
      /      \  Property Tests (invariants)
     /────────\
    /          \  Integration Tests (full protocol)
   /────────────\
  /              \  Unit Tests (individual functions)
 /────────────────\
```

### Coverage Goals

- **Unit Tests**: 100% of public API
- **Integration Tests**: All protocol flows
- **Property Tests**: Cryptographic properties
- **Fuzz Tests**: All parsing functions

### Test Vectors

**Source**: Signal specification test vectors (when available)

**Custom**: Generated via reference implementation for edge cases

## Future Work

### v0.2.0

- Replace simplified AEAD with ChaCha20-Poly1305
- RNG injection throughout
- Session management utilities

### v0.3.0

- Header encryption
- X448 support
- Sealed sender

### v1.0.0

- Professional security audit
- Formal verification of critical paths
- Group messaging (Sender Keys)

## References

1. [Signal Protocol Specification](https://signal.org/docs/)
2. [X3DH Specification](https://signal.org/docs/specifications/x3dh/)
3. [Double Ratchet Specification](https://signal.org/docs/specifications/doubleratchet/)
4. [Rust Cryptography Guidelines](https://www.rust-lang.org/policies/security)

---

**Document Version**: 1.0  
**Last Updated**: 2024-01-01  
**Authors**: Implementation Team
