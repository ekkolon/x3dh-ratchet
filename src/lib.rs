//! # Signal Protocol Implementation
//!
//! Production-grade implementation of X3DH and Double Ratchet protocols.
//!
//! ## Security Properties
//!
//! - **Forward Secrecy**: Past messages cannot be decrypted if long-term keys are compromised
//! - **Post-Compromise Security**: Future messages are secure after compromise recovery  
//! - **Deniable Authentication**: No cryptographic proof of who sent a message
//! - **Asynchronous**: Sender can encrypt without recipient being online
//!
//! ## Threat Model
//!
//! This implementation assumes:
//! - Adversary can compromise devices and extract all key material
//! - Adversary can inject, modify, delay, or drop messages
//! - Adversary cannot break X25519, HKDF-SHA256, or AEAD primitives
//! - Side-channel attacks are mitigated but not formally verified
//!
//! ## Usage
//!
//! ```rust,no_run
//! use signal_protocol::{IdentityKeyPair, PreKeyState};
//! use rand_core::OsRng;
//!
//! // Responder generates prekey bundle
//! let identity = IdentityKeyPair::generate(&mut OsRng);
//! let prekey_state = PreKeyState::generate(&mut OsRng, &identity);
//! let bundle = prekey_state.public_bundle();
//!
//! // Initiator performs X3DH
//! let init_result = signal_protocol::x3dh::initiate(
//!     &mut OsRng,
//!     &IdentityKeyPair::generate(&mut OsRng),
//!     &bundle
//! ).unwrap();
//!
//! // Initialize Double Ratchet for messaging
//! // use signal_protocol::{DoubleRatchet, Message};
//! // ... see module documentation
//! ```

#![forbid(unsafe_code)]
#![deny(
    missing_docs,
    missing_debug_implementations,
    rust_2018_idioms,
    unreachable_pub
)]
#![cfg_attr(not(test), deny(clippy::unwrap_used))]
#![warn(clippy::all, clippy::pedantic, clippy::cargo)]

pub mod crypto;
pub mod double_ratchet;
pub mod error;
pub mod keys;
pub mod storage;
pub mod x3dh;

// Re-export main types
pub use double_ratchet::{DoubleRatchet, Header, Message};
pub use error::{Error, Result};
pub use keys::{IdentityKeyPair, PublicKey, SecretKey, SigningKeyPair};
pub use x3dh::{InitialMessage, InitiatorResult, PreKeyBundle, PreKeyState, ResponderResult};
