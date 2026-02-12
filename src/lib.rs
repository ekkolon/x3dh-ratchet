//! Signal Protocol implementation providing end-to-end encrypted messaging.
//!
//! This crate implements the X3DH key agreement protocol and Double Ratchet
//! algorithm as specified by Signal. It provides forward secrecy, post-compromise
//! security, and deniable authentication for asynchronous messaging.
//!
//! # Security Properties
//!
//! ## Forward Secrecy
//! Past messages remain confidential even if long-term identity keys are later
//! compromised. Each message uses ephemeral keys that are deleted after use.
//!
//! ## Post-Compromise Security
//! If an attacker compromises session state, security is automatically restored
//! after a single honest message exchange via DH ratcheting.
//!
//! ## Deniable Authentication
//! Messages are authenticated but provide no cryptographic proof of sender identity
//! to third parties. Sender could always claim their key was compromised.
//!
//! ## Asynchronous Operation
//! Sender can encrypt messages for offline recipients using prekey bundles published
//! in advance. No real-time key exchange required.
//!
//! # Threat Model
//!
//! **Assumed adversary capabilities:**
//! - Full device compromise with extraction of all key material
//! - Active network attacker (inject, modify, delay, drop messages)
//! - Unlimited computational resources for cryptanalysis
//!
//! **Security assumptions:**
//! - X25519 ECDH provides computational security
//! - HKDF-SHA256 is a secure key derivation function
//! - ChaCha20-Poly1305 is a secure AEAD cipher
//! - Random number generator is cryptographically secure
//!
//! # Protocol Flow
//!
//! ## 1. Setup (Responder/Bob)
//! ```rust
//! use signal_protocol::{IdentityKeyPair, PreKeyState, x3dh, DoubleRatchet};
//! use signal_protocol::keys::SecretKey;
//! use rand_core::OsRng;
//!
//! // Generate long-term identity
//! let identity = IdentityKeyPair::generate(&mut OsRng);
//!
//! // Generate signed prekey and one-time prekeys
//! let prekey_state = PreKeyState::generate(&mut OsRng, &identity);
//!
//! // Publish this bundle to a server
//! let bundle = prekey_state.public_bundle();
//! ```
//!
//! ## 2. Initial Key Agreement (Initiator/Alice)
//! ```no_run
//! # use signal_protocol::{IdentityKeyPair, PreKeyState, x3dh, DoubleRatchet};
//! # use signal_protocol::keys::SecretKey;
//! # use rand_core::OsRng;
//! let bob_identity = IdentityKeyPair::generate(&mut OsRng);
//! let bob_prekeys = PreKeyState::generate(&mut OsRng, &bob_identity);
//! let bundle = bob_prekeys.public_bundle();
//!
//! // Fetch Bob's prekey bundle from server
//! let alice_identity = IdentityKeyPair::generate(&mut OsRng);
//!
//! // Perform X3DH key agreement
//! let init_result = x3dh::initiate(&mut OsRng, &alice_identity, &bundle).unwrap();
//!
//! // Initialize Double Ratchet session
//! let bob_dh_key = SecretKey::generate(&mut OsRng).public_key();
//! let mut alice_session = DoubleRatchet::init_sender(
//!     &mut OsRng,
//!     &init_result,
//!     bob_dh_key,
//! );
//!
//! // Send init_result.initial_message to Bob
//! ```
//!
//! ## 3. Response (Responder/Bob)
//! ```no_run
//! # use signal_protocol::{IdentityKeyPair, PreKeyState, x3dh, DoubleRatchet};
//! # use signal_protocol::keys::SecretKey;
//! # use rand_core::OsRng;
//! let bob_identity = IdentityKeyPair::generate(&mut OsRng);
//! let mut bob_prekeys = PreKeyState::generate(&mut OsRng, &bob_identity);
//! let bundle = bob_prekeys.public_bundle();
//!
//! let alice_identity = IdentityKeyPair::generate(&mut OsRng);
//!
//! let init_result = x3dh::initiate(&mut OsRng, &alice_identity, &bundle).unwrap();
//! let initial_message = &init_result.initial_message;
//!
//! // Receive initial_message from Alice
//! let resp_result = x3dh::respond(
//!     &mut bob_prekeys,
//!     &bob_identity,
//!     initial_message,
//! ).unwrap();
//!
//! // Initialize Double Ratchet session
//! let bob_dh_key = SecretKey::generate(&mut OsRng);
//! let mut bob_session = DoubleRatchet::init_receiver(
//!     resp_result.shared_secret,
//!     bob_dh_key,
//! );
//! ```
//!
//! ## 4. Messaging
//! ```no_run
//! # use signal_protocol::{IdentityKeyPair, PreKeyState, x3dh, DoubleRatchet};
//! # use signal_protocol::keys::SecretKey;
//! # use rand_core::OsRng;
//! let alice_identity = IdentityKeyPair::generate(&mut OsRng);
//!
//! let bob_identity = IdentityKeyPair::generate(&mut OsRng);
//! let mut bob_prekeys = PreKeyState::generate(&mut OsRng, &bob_identity);
//! let bundle = bob_prekeys.public_bundle();
//!
//! let init_result = x3dh::initiate(&mut OsRng, &alice_identity, &bundle).unwrap();
//! let bob_dh = SecretKey::generate(&mut OsRng);
//!
//! let mut alice_session = DoubleRatchet::init_sender(&mut OsRng, &init_result, bob_dh.public_key()).unwrap();
//!
//! let resp = x3dh::respond(&mut bob_prekeys, &bob_identity, &init_result.initial_message).unwrap();
//! let mut bob_session = DoubleRatchet::init_receiver(resp.shared_secret, bob_dh);
//!
//! // Alice encrypts and sends
//! let message = alice_session.encrypt(b"Hello Bob!", b"").unwrap();
//! // (send message over network)
//!
//! // Bob receives and decrypts
//! let plaintext = bob_session.decrypt(&message, b"").unwrap();
//! assert_eq!(&plaintext, b"Hello Bob!");
//!
//! // Bob can reply
//! let reply = bob_session.encrypt(b"Hello Alice!", b"").unwrap();
//! let plaintext = alice_session.decrypt(&reply, b"").unwrap();
//! ```
//!
//! # Modules
//!
//! - [`x3dh`]: Extended Triple Diffie-Hellman key agreement protocol
//! - [`double_ratchet`]: Double Ratchet for forward-secure messaging
//! - [`crypto`]: Cryptographic primitives (KDF, AEAD encryption)
//! - [`keys`]: Key types with automatic zeroization
//! - [`storage`]: Storage abstractions for prekeys and skipped message keys
//! - [`error`]: Error types

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms, unreachable_pub)]
#![cfg_attr(not(test), deny(clippy::unwrap_used))]
#![warn(clippy::all, clippy::pedantic, clippy::cargo)]
#![allow(
    missing_docs,
    clippy::missing_errors_doc,
    clippy::missing_fields_in_debug
)]

pub mod crypto;
pub mod double_ratchet;
pub mod error;
pub mod keys;
pub mod storage;
pub mod x3dh;
pub mod xeddsa;

// Re-export main types
pub use double_ratchet::{DoubleRatchet, Header, Message};
pub use error::{Error, Result};
pub use keys::{IdentityKeyPair, PublicKey, SecretKey};
pub use x3dh::{InitialMessage, InitiatorResult, PreKeyBundle, PreKeyState, ResponderResult};
