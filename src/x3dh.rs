//! X3DH (Extended Triple Diffie-Hellman) key agreement protocol
//!
//! Implements the Signal protocol's asynchronous key agreement as specified in:
//! <https://signal.org/docs/specifications/x3dh>/
//!
//! ## Protocol Flow
//!
//! 1. **Responder** generates and publishes a prekey bundle containing:
//!    - Identity key (long-term)
//!    - Signed prekey (medium-term, rotated periodically)
//!    - One-time prekeys (ephemeral, used once)
//!
//! 2. **Initiator** fetches bundle and performs:
//!    - DH1 = `DH(IK_A`, `SPK_B`)
//!    - DH2 = `DH(EK_A`, `IK_B`)  
//!    - DH3 = `DH(EK_A`, `SPK_B`)
//!    - DH4 = `DH(EK_A`, `OPK_B`) [if OPK available]
//!    - SK = KDF(DH1 || DH2 || DH3 || DH4)
//!
//! 3. **Responder** receives initial message and computes same SK

use crate::crypto::{derive_x3dh_secret, SymmetricKey};
use crate::error::{Error, Result};
use crate::keys::{verify_signature, IdentityKeyPair, PublicKey, SecretKey};
use ed25519_dalek::Signature;
use rand_core::CryptoRngCore;

/// Prekey bundle published by responder
///
/// Contains all public keys needed for initiator to perform X3DH
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PreKeyBundle {
    /// Responder's identity key (long-term public key)
    pub identity_key: PublicKey,

    /// Responder's signed prekey (rotated periodically)
    pub signed_prekey: PublicKey,

    /// Signature over signed prekey using identity key
    #[cfg_attr(feature = "serde", serde(with = "serde_arrays"))]
    pub signed_prekey_signature: [u8; 64],

    /// Verifying key for signature validation
    #[cfg_attr(feature = "serde", serde(with = "serde_arrays"))]
    pub verifying_key: [u8; 32],

    /// Optional one-time prekey (consumed after use)
    pub one_time_prekey: Option<PublicKey>,
}

impl PreKeyBundle {
    /// Verify the signed prekey signature
    pub fn verify_signature(&self) -> Result<()> {
        verify_signature(
            &self.verifying_key,
            self.signed_prekey.as_bytes(),
            &self.signed_prekey_signature,
        )
    }
}

/// State maintained by responder for X3DH
///
/// Contains secret keys needed to respond to handshake
pub struct PreKeyState {
    /// Store only public part
    pub identity_public: PublicKey,
    /// For bundle creation
    pub verifying_key_bytes: [u8; 32],

    /// Signed prekey pair
    pub signed_prekey: SecretKey,

    /// Signature over signed prekey
    signed_prekey_signature: Signature,

    /// One-time prekey pairs (consumed when used)
    pub one_time_prekeys: Vec<SecretKey>,
}

impl PreKeyState {
    /// Generate new prekey state with specified number of one-time prekeys
    pub fn generate<R: CryptoRngCore>(rng: &mut R, identity: &IdentityKeyPair) -> Self {
        Self::generate_with_count(rng, identity, 100)
    }

    /// Generate with specific one-time prekey count
    pub fn generate_with_count<R: CryptoRngCore>(
        rng: &mut R,
        identity: &IdentityKeyPair,
        opk_count: usize,
    ) -> Self {
        let signed_prekey = SecretKey::generate(rng);
        let signed_prekey_signature = identity
            .signing_key
            .sign(signed_prekey.public_key().as_bytes());

        let one_time_prekeys: Vec<SecretKey> =
            (0..opk_count).map(|_| SecretKey::generate(rng)).collect();

        Self {
            identity_public: identity.public_key(),
            verifying_key_bytes: identity.signing_key.verifying_key_bytes(),
            signed_prekey,
            signed_prekey_signature,
            one_time_prekeys,
        }
    }

    /// Create public bundle for distribution
    #[must_use]
    pub fn public_bundle(&self) -> PreKeyBundle {
        PreKeyBundle {
            identity_key: self.identity_public,
            signed_prekey: self.signed_prekey.public_key(),
            signed_prekey_signature: self.signed_prekey_signature.to_bytes(),
            verifying_key: self.verifying_key_bytes,
            one_time_prekey: self
                .one_time_prekeys
                .first()
                .map(super::keys::SecretKey::public_key),
        }
    }

    /// Consume a one-time prekey (returns error if none available)
    pub fn consume_one_time_prekey(&mut self) -> Result<SecretKey> {
        self.one_time_prekeys
            .pop()
            .ok_or(Error::MissingOneTimePrekey)
    }
}

impl std::fmt::Debug for PreKeyState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreKeyState")
            .field("identity_public", &self.identity_public)
            .field("signed_prekey_public", &self.signed_prekey.public_key())
            .field("one_time_prekey_count", &self.one_time_prekeys.len())
            .finish()
    }
}

/// Initial message sent by initiator
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct InitialMessage {
    /// Initiator's identity key
    pub identity_key: PublicKey,

    /// Initiator's ephemeral key
    pub ephemeral_key: PublicKey,

    /// Which one-time prekey was used (if any)
    pub used_one_time_prekey: Option<PublicKey>,
}

/// Result of initiator's X3DH computation
pub struct InitiatorResult {
    /// Shared secret derived from X3DH
    pub shared_secret: SymmetricKey,

    /// Initial message to send to responder
    pub initial_message: InitialMessage,

    /// Associated data for first message
    pub associated_data: Vec<u8>,
}

impl std::fmt::Debug for InitiatorResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InitiatorResult")
            .field("initial_message", &self.initial_message)
            .finish()
    }
}

/// Result of responder's X3DH computation
pub struct ResponderResult {
    /// Shared secret derived from X3DH
    pub shared_secret: SymmetricKey,

    /// Associated data for first message
    pub associated_data: Vec<u8>,
}

impl std::fmt::Debug for ResponderResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResponderResult").finish()
    }
}

/// Initiator side of X3DH handshake
///
/// Computes:
/// - DH1 = `DH(IK_A`, `SPK_B`)
/// - DH2 = `DH(EK_A`, `IK_B`)
/// - DH3 = `DH(EK_A`, `SPK_B`)
/// - DH4 = `DH(EK_A`, `OPK_B`) [if present]
/// - SK  = KDF(DH1 || DH2 || DH3 || DH4)
pub fn initiate<R: CryptoRngCore>(
    rng: &mut R,
    initiator_identity: &IdentityKeyPair,
    bundle: &PreKeyBundle,
) -> Result<InitiatorResult> {
    bundle.verify_signature()?;

    let ephemeral = SecretKey::generate(rng);

    // DH operations
    let dh1 = initiator_identity
        .dh_key
        .diffie_hellman(&bundle.signed_prekey);
    let dh2 = ephemeral.diffie_hellman(&bundle.identity_key);
    let dh3 = ephemeral.diffie_hellman(&bundle.signed_prekey);
    let dh4 = bundle
        .one_time_prekey
        .as_ref()
        .map(|opk| ephemeral.diffie_hellman(opk));

    let shared_secret = derive_x3dh_secret(&dh1, &dh2, &dh3, dh4.as_ref());

    // Build initial message
    let initial_message = InitialMessage {
        identity_key: initiator_identity.public_key(),
        ephemeral_key: ephemeral.public_key(),
        used_one_time_prekey: bundle.one_time_prekey,
    };

    // Associated data = initiator_identity || responder_identity
    let mut associated_data = Vec::with_capacity(64);
    associated_data.extend_from_slice(initiator_identity.public_key().as_bytes());
    associated_data.extend_from_slice(bundle.identity_key.as_bytes());

    Ok(InitiatorResult {
        shared_secret,
        initial_message,
        associated_data,
    })
}

/// Responder side of X3DH handshake
///
/// Computes same shared secret as initiator using received ephemeral key
pub fn respond(
    prekey_state: &mut PreKeyState,
    identity: &IdentityKeyPair,
    initial_message: &InitialMessage,
) -> Result<ResponderResult> {
    // Perform DH operations (symmetric to initiator)
    let dh1 = prekey_state
        .signed_prekey
        .diffie_hellman(&initial_message.identity_key);
    let dh2 = identity
        .dh_key
        .diffie_hellman(&initial_message.ephemeral_key);
    let dh3 = prekey_state
        .signed_prekey
        .diffie_hellman(&initial_message.ephemeral_key);

    // Handle one-time prekey if present
    let dh4 = if initial_message.used_one_time_prekey.is_some() {
        let opk = prekey_state.consume_one_time_prekey()?;
        Some(opk.diffie_hellman(&initial_message.ephemeral_key))
    } else {
        None
    };

    // Derive same shared secret
    let shared_secret = derive_x3dh_secret(&dh1, &dh2, &dh3, dh4.as_ref());

    // Associated data = initiator_identity || responder_identity
    let mut associated_data = Vec::with_capacity(64);
    associated_data.extend_from_slice(initial_message.identity_key.as_bytes());
    associated_data.extend_from_slice(identity.public_key().as_bytes());

    Ok(ResponderResult {
        shared_secret,
        associated_data,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn test_x3dh_handshake_with_opk() {
        // Responder setup
        let responder_identity = IdentityKeyPair::generate(&mut OsRng);
        let mut responder_state = PreKeyState::generate(&mut OsRng, &responder_identity);
        let bundle = responder_state.public_bundle();

        // Initiator handshake
        let initiator_identity = IdentityKeyPair::generate(&mut OsRng);
        let init_result = initiate(&mut OsRng, &initiator_identity, &bundle).unwrap();

        // Responder handshake
        let resp_result = respond(
            &mut responder_state,
            &responder_identity,
            &init_result.initial_message,
        )
        .unwrap();

        // Verify shared secrets match
        assert_eq!(
            init_result.shared_secret.as_bytes(),
            resp_result.shared_secret.as_bytes()
        );

        // Verify associated data matches
        assert_eq!(init_result.associated_data, resp_result.associated_data);
    }

    #[test]
    fn test_x3dh_handshake_without_opk() {
        // Bundle without one-time prekey
        let responder_identity = IdentityKeyPair::generate(&mut OsRng);
        let responder_state = PreKeyState::generate_with_count(&mut OsRng, &responder_identity, 0);
        let mut bundle = responder_state.public_bundle();
        bundle.one_time_prekey = None;

        // Initiator handshake
        let initiator_identity = IdentityKeyPair::generate(&mut OsRng);
        let init_result = initiate(&mut OsRng, &initiator_identity, &bundle).unwrap();

        // Verify no OPK in message
        assert!(init_result.initial_message.used_one_time_prekey.is_none());
    }

    #[test]
    fn test_invalid_signature() {
        let responder_identity = IdentityKeyPair::generate(&mut OsRng);
        let responder_state = PreKeyState::generate(&mut OsRng, &responder_identity);
        let mut bundle = responder_state.public_bundle();

        // Corrupt signature
        bundle.signed_prekey_signature[0] ^= 1;

        let result = bundle.verify_signature();
        assert!(result.is_err());
    }
}
