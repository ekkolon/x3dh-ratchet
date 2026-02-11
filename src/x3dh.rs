//! X3DH (Extended Triple Diffie-Hellman) key agreement protocol.
//!
//! Implements Signal's asynchronous key agreement as specified in:
//! <https://signal.org/docs/specifications/x3dh/>
//!
//! ## Security Against Identity Substitution
//!
//! **Important:** The official Signal specification uses `XEdDSA` signatures where
//! the Ed25519 signing key is cryptographically derived from the X25519 DH key,
//! providing inherent binding between identity components.
//!
//! This implementation uses **independent** X25519 and Ed25519 keys for simplicity.
//! To prevent identity substitution attacks, the signature covers:
//!
//! ```text
//! signature = Sign(IK_signing, IK_dh || IK_verifying || SPK)
//! ```
//!
//! This binds both identity key components (DH and signing) to the signed prekey,
//! preventing an attacker from substituting one without invalidating the signature.
//!
//! ### Attack Prevented
//!
//! Without this binding:
//! 1. Attacker intercepts Bob's bundle
//! 2. Replaces `identity_key` (X25519 DH) with attacker's key
//! 3. Keeps `verifying_key` (Ed25519) as Bob's
//! 4. Signature still verifies (Bob's signature with Bob's key)
//! 5. But Alice performs DH with attacker's key → MITM
//!
//! With binding: Any modification to either identity component breaks the signature.
//!
//! ## Protocol Flow
//!
//! 1. **Responder (Bob)** generates and publishes a prekey bundle containing:
//!    - Identity key (long-term X25519 DH key)
//!    - Identity verifying key (long-term Ed25519 signing key)
//!    - Signed prekey (medium-term, rotated periodically)
//!    - Prekey signature (binds all keys together)
//!    - One-time prekeys (ephemeral, used once)
//!
//! 2. **Initiator (Alice)** fetches bundle and performs:
//!    - DH1 = `DH(IK_A, SPK_B)`
//!    - DH2 = `DH(EK_A, IK_B)`  
//!    - DH3 = `DH(EK_A, SPK_B)`
//!    - DH4 = `DH(EK_A, OPK_B)` [if OPK available]
//!    - SK = KDF(DH1 || DH2 || DH3 || DH4)
//!
//! 3. **Responder (Bob)** receives initial message and computes same SK

use crate::crypto::{SymmetricKey, derive_x3dh_secret};
use crate::error::{Error, Result};
use crate::keys::{IdentityKeyPair, PublicKey, SecretKey, verify_signature};
use chacha20poly1305::aead::rand_core::CryptoRngCore;
use ed25519_dalek::Signature;
use zeroize::Zeroize;

/// Prekey bundle published by responder (Bob).
///
/// Contains all public keys needed for initiator (Alice) to perform X3DH.
/// The bundle is authenticated via an Ed25519 signature over all identity
/// components and the signed prekey.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PreKeyBundle {
    /// Responder's long-term DH public key (X25519)
    pub identity_key: PublicKey,

    /// Responder's long-term verifying key (Ed25519)
    ///
    /// This is separate from `identity_key` because we use independent
    /// X25519/Ed25519 keys rather than `XEdDSA`.
    #[cfg_attr(feature = "serde", serde(with = "serde_arrays"))]
    pub identity_verifying_key: [u8; 32],

    /// Responder's signed prekey (rotated periodically)
    pub signed_prekey: PublicKey,

    /// Signature over (`identity_key` || `identity_verifying_key` || `signed_prekey`)
    ///
    /// Binds both identity key components to prevent substitution attacks.
    #[cfg_attr(feature = "serde", serde(with = "serde_arrays"))]
    pub signed_prekey_signature: [u8; 64],

    /// Optional one-time prekey (consumed after use)
    pub one_time_prekey: Option<PublicKey>,
}

impl PreKeyBundle {
    /// Verifies the signed prekey signature.
    ///
    /// Ensures the bundle was created by the holder of both identity key components
    /// and prevents MITM identity substitution attacks.
    ///
    /// # Security
    ///
    /// The signature covers all three public key components:
    /// - `identity_key` (X25519 DH key)
    /// - `identity_verifying_key` (Ed25519 signing key)
    /// - `signed_prekey`
    ///
    /// This prevents an attacker from substituting either identity component
    /// without invalidating the signature.
    pub fn verify_signature(&self) -> Result<()> {
        // Build message: identity_dh || identity_verifying || signed_prekey
        let mut message = Vec::with_capacity(96); // 32 + 32 + 32
        message.extend_from_slice(self.identity_key.as_bytes());
        message.extend_from_slice(&self.identity_verifying_key);
        message.extend_from_slice(self.signed_prekey.as_bytes());

        verify_signature(
            &self.identity_verifying_key,
            &message,
            &self.signed_prekey_signature,
        )
    }
}

/// State maintained by responder for X3DH.
///
/// Contains secret keys needed to respond to handshake initiations.
pub struct PreKeyState {
    /// Identity public key (X25519 DH)
    pub identity_public: PublicKey,

    /// Identity verifying key (Ed25519)
    pub verifying_key_bytes: [u8; 32],

    /// Signed prekey pair
    pub signed_prekey: SecretKey,

    /// Signature over (`identity_public` || `verifying_key_bytes` || `signed_prekey.public`)
    signed_prekey_signature: Signature,

    /// One-time prekey pairs (consumed when used)
    pub one_time_prekeys: Vec<SecretKey>,
}

impl PreKeyState {
    /// Generates new prekey state with default number of one-time prekeys (100).
    pub fn generate<R: CryptoRngCore>(rng: &mut R, identity: &IdentityKeyPair) -> Self {
        Self::generate_with_count(rng, identity, 100)
    }

    /// Generates prekey state with specific one-time prekey count.
    ///
    /// # Arguments
    /// * `rng` - Cryptographically secure RNG
    /// * `identity` - Long-term identity keypair
    /// * `opk_count` - Number of one-time prekeys to generate
    pub fn generate_with_count<R: CryptoRngCore>(
        rng: &mut R,
        identity: &IdentityKeyPair,
        opk_count: usize,
    ) -> Self {
        let signed_prekey = SecretKey::generate(rng);

        // Create signature binding all three public key components
        let mut message = Vec::with_capacity(96);
        message.extend_from_slice(identity.public_key().as_bytes());
        message.extend_from_slice(&identity.verifying_key().to_bytes());
        message.extend_from_slice(signed_prekey.public_key().as_bytes());

        let signed_prekey_signature = identity.signing_key.sign(&message);

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

    /// Creates public bundle for distribution to initiators.
    ///
    /// The bundle includes one one-time prekey if available (first in the list).
    #[must_use]
    pub fn public_bundle(&self) -> PreKeyBundle {
        PreKeyBundle {
            identity_key: self.identity_public,
            identity_verifying_key: self.verifying_key_bytes,
            signed_prekey: self.signed_prekey.public_key(),
            signed_prekey_signature: self.signed_prekey_signature.to_bytes(),
            one_time_prekey: self
                .one_time_prekeys
                .first()
                .map(super::keys::SecretKey::public_key),
        }
    }

    /// Consumes a one-time prekey from the end of the list.
    ///
    /// # Errors
    /// Returns `Error::MissingOneTimePrekey` if no OPKs remain.
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

/// Initial message sent by initiator (Alice) to responder (Bob).
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct InitialMessage {
    /// Initiator's identity key (X25519 DH public key)
    pub identity_key: PublicKey,

    /// Initiator's ephemeral key (generated fresh for this session)
    pub ephemeral_key: PublicKey,

    /// Which one-time prekey was used (if any)
    pub used_one_time_prekey: Option<PublicKey>,
}

/// Result of initiator's X3DH computation.
pub struct InitiatorResult {
    /// Shared secret derived from X3DH (input to Double Ratchet)
    pub shared_secret: SymmetricKey,

    /// Initial message to send to responder
    pub initial_message: InitialMessage,

    /// Associated data for first encrypted message
    ///
    /// Contains `IK_A || IK_B` for additional authentication context.
    pub associated_data: Vec<u8>,
}

impl std::fmt::Debug for InitiatorResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InitiatorResult")
            .field("initial_message", &self.initial_message)
            .finish()
    }
}

/// Result of responder's X3DH computation.
pub struct ResponderResult {
    /// Shared secret derived from X3DH (must match initiator's)
    pub shared_secret: SymmetricKey,

    /// Associated data for first encrypted message (must match initiator's)
    pub associated_data: Vec<u8>,
}

impl std::fmt::Debug for ResponderResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResponderResult").finish()
    }
}

/// Initiator (Alice) side of X3DH handshake.
///
/// Performs the following DH operations:
/// - DH1 = `DH(IK_A, SPK_B)` - Alice's identity with Bob's signed prekey
/// - DH2 = `DH(EK_A, IK_B)` - Alice's ephemeral with Bob's identity
/// - DH3 = `DH(EK_A, SPK_B)` - Alice's ephemeral with Bob's signed prekey
/// - DH4 = `DH(EK_A, OPK_B)` - Alice's ephemeral with Bob's one-time prekey [if present]
///
/// Derives: SK = KDF(DH1 || DH2 || DH3 || DH4)
///
/// # Security
///
/// - DH1 and DH2 provide mutual authentication
/// - DH3 and DH4 provide forward secrecy
/// - Ephemeral key is zeroized after use
///
/// # Errors
///
/// Returns error if signature verification fails.
pub fn initiate<R: CryptoRngCore>(
    rng: &mut R,
    initiator_identity: &IdentityKeyPair,
    bundle: &PreKeyBundle,
) -> Result<InitiatorResult> {
    // Verify bundle signature first (prevents MITM)
    bundle.verify_signature()?;

    // Generate ephemeral key for this session
    let mut ephemeral = SecretKey::generate(rng);
    let ephemeral_public = ephemeral.public_key();

    // Perform 4 DH operations (or 3 if no OPK)
    let mut dh1 = initiator_identity
        .dh_key
        .diffie_hellman(&bundle.signed_prekey);
    let mut dh2 = ephemeral.diffie_hellman(&bundle.identity_key);
    let mut dh3 = ephemeral.diffie_hellman(&bundle.signed_prekey);
    let mut dh4 = bundle
        .one_time_prekey
        .as_ref()
        .map(|opk| ephemeral.diffie_hellman(opk));

    // Derive shared secret
    let shared_secret = derive_x3dh_secret(&dh1, &dh2, &dh3, dh4.as_ref());

    // Zeroize sensitive material immediately
    ephemeral.zeroize();
    dh1.zeroize();
    dh2.zeroize();
    dh3.zeroize();
    if let Some(ref mut d4) = dh4 {
        d4.zeroize();
    }

    // Build initial message
    let initial_message = InitialMessage {
        identity_key: initiator_identity.public_key(),
        ephemeral_key: ephemeral_public,
        used_one_time_prekey: bundle.one_time_prekey,
    };

    // Associated data: IK_A || IK_B
    let mut associated_data = Vec::with_capacity(64);
    associated_data.extend_from_slice(initiator_identity.public_key().as_bytes());
    associated_data.extend_from_slice(bundle.identity_key.as_bytes());

    Ok(InitiatorResult {
        shared_secret,
        initial_message,
        associated_data,
    })
}

/// Responder (Bob) side of X3DH handshake.
///
/// Computes the same shared secret as initiator using received ephemeral key.
/// Performs symmetric DH operations:
/// - DH1 = `DH(SPK_B, IK_A)` - Symmetric to initiator's DH1
/// - DH2 = `DH(IK_B, EK_A)` - Symmetric to initiator's DH2
/// - DH3 = `DH(SPK_B, EK_A)` - Symmetric to initiator's DH3
/// - DH4 = `DH(OPK_B, EK_A)` - Symmetric to initiator's DH4 [if used]
///
/// # Security
///
/// - One-time prekey is consumed (removed from state) after use
/// - One-time prekey reuse is detected and rejected
///
/// # Errors
///
/// Returns `Error::OneTimePreKeyConsumed` if the OPK was already used.
pub fn respond(
    prekey_state: &mut PreKeyState,
    responder_identity: &IdentityKeyPair,
    initial_message: &InitialMessage,
) -> Result<ResponderResult> {
    // Perform DH operations symmetric to initiator
    let dh1 = prekey_state
        .signed_prekey
        .diffie_hellman(&initial_message.identity_key);
    let dh2 = responder_identity
        .dh_key
        .diffie_hellman(&initial_message.ephemeral_key);
    let dh3 = prekey_state
        .signed_prekey
        .diffie_hellman(&initial_message.ephemeral_key);

    // Handle one-time prekey if present in message
    let dh4 = if let Some(used_opk_public) = initial_message.used_one_time_prekey {
        // Find the OPK that was used
        let opk_index = prekey_state
            .one_time_prekeys
            .iter()
            .position(|sk| sk.public_key() == used_opk_public)
            .ok_or(Error::OneTimePreKeyConsumed)?;

        // Remove and use it (forward secrecy)
        let opk = prekey_state.one_time_prekeys.remove(opk_index);
        Some(opk.diffie_hellman(&initial_message.ephemeral_key))
    } else {
        None
    };

    // Derive same shared secret as initiator
    let shared_secret = derive_x3dh_secret(&dh1, &dh2, &dh3, dh4.as_ref());

    // Associated data: IK_A || IK_B (must match initiator's)
    let mut associated_data = Vec::with_capacity(64);
    associated_data.extend_from_slice(initial_message.identity_key.as_bytes());
    associated_data.extend_from_slice(responder_identity.public_key().as_bytes());

    Ok(ResponderResult {
        shared_secret,
        associated_data,
    })
}

#[cfg(test)]
mod tests {
    use chacha20poly1305::aead::OsRng;

    use super::*;

    #[test]
    fn test_x3dh_handshake_with_opk() {
        let responder_identity = IdentityKeyPair::generate(&mut OsRng);
        let mut responder_state = PreKeyState::generate(&mut OsRng, &responder_identity);
        let bundle = responder_state.public_bundle();

        let initiator_identity = IdentityKeyPair::generate(&mut OsRng);
        let init_result = initiate(&mut OsRng, &initiator_identity, &bundle).unwrap();

        let resp_result = respond(
            &mut responder_state,
            &responder_identity,
            &init_result.initial_message,
        )
        .unwrap();

        assert_eq!(
            init_result.shared_secret.as_bytes(),
            resp_result.shared_secret.as_bytes()
        );
        assert_eq!(init_result.associated_data, resp_result.associated_data);
    }

    #[test]
    fn test_x3dh_handshake_without_opk() {
        let responder_identity = IdentityKeyPair::generate(&mut OsRng);
        let responder_state = PreKeyState::generate_with_count(&mut OsRng, &responder_identity, 0);
        let mut bundle = responder_state.public_bundle();
        bundle.one_time_prekey = None;

        let initiator_identity = IdentityKeyPair::generate(&mut OsRng);
        let init_result = initiate(&mut OsRng, &initiator_identity, &bundle).unwrap();

        assert!(init_result.initial_message.used_one_time_prekey.is_none());
    }

    #[test]
    fn test_invalid_signature() {
        let responder_identity = IdentityKeyPair::generate(&mut OsRng);
        let responder_state = PreKeyState::generate(&mut OsRng, &responder_identity);
        let mut bundle = responder_state.public_bundle();

        bundle.signed_prekey_signature[0] ^= 1;

        let result = bundle.verify_signature();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), Error::InvalidSignature);
    }

    /// Tests identity substitution attack is prevented
    #[test]
    fn test_identity_substitution_attack_prevented() {
        let bob_identity = IdentityKeyPair::generate(&mut OsRng);
        let attacker_identity = IdentityKeyPair::generate(&mut OsRng);

        let bob_prekeys = PreKeyState::generate(&mut OsRng, &bob_identity);
        let original_bundle = bob_prekeys.public_bundle();

        // Verify original bundle is valid
        assert!(original_bundle.verify_signature().is_ok());

        // Attack 1: Replace DH key only
        let mut attack1 = original_bundle.clone();
        attack1.identity_key = attacker_identity.public_key();
        assert!(
            attack1.verify_signature().is_err(),
            "DH key substitution must fail"
        );

        // Attack 2: Replace verifying key only
        let mut attack2 = original_bundle.clone();
        attack2.identity_verifying_key = attacker_identity.verifying_key().to_bytes();
        assert!(
            attack2.verify_signature().is_err(),
            "Verifying key substitution must fail"
        );

        // Attack 3: Replace both keys
        let mut attack3 = original_bundle.clone();
        attack3.identity_key = attacker_identity.public_key();
        attack3.identity_verifying_key = attacker_identity.verifying_key().to_bytes();
        assert!(
            attack3.verify_signature().is_err(),
            "Full identity substitution must fail"
        );
    }

    /// Tests MITM attack at X3DH initiation level
    #[test]
    fn test_mitm_attack_rejected() {
        let alice_identity = IdentityKeyPair::generate(&mut OsRng);
        let bob_identity = IdentityKeyPair::generate(&mut OsRng);
        let attacker_identity = IdentityKeyPair::generate(&mut OsRng);

        let bob_prekeys = PreKeyState::generate(&mut OsRng, &bob_identity);
        let mut bundle = bob_prekeys.public_bundle();

        // Attacker replaces Bob's DH key
        bundle.identity_key = attacker_identity.public_key();

        // Alice tries to initiate - must fail
        let result = initiate(&mut OsRng, &alice_identity, &bundle);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), Error::InvalidSignature);
    }

    /// Tests signature cannot be reused with different signed prekey
    #[test]
    fn test_signature_non_reusable() {
        let bob_identity = IdentityKeyPair::generate(&mut OsRng);
        let bob_prekeys = PreKeyState::generate(&mut OsRng, &bob_identity);
        let bundle1 = bob_prekeys.public_bundle();

        let new_spk = SecretKey::generate(&mut OsRng);
        let mut bundle2 = bundle1.clone();
        bundle2.signed_prekey = new_spk.public_key();

        assert!(
            bundle2.verify_signature().is_err(),
            "Signature must not verify with different SPK"
        );
    }
}
