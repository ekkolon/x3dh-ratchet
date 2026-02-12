//! X3DH (Extended Triple Diffie-Hellman) key agreement protocol.
//!
//! Implements Signal's asynchronous key agreement as specified in:
//! <https://signal.org/docs/specifications/x3dh/>
//!
//! ## Security Against Identity Substitution
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
use crate::keys::{IdentityKeyPair, PublicKey, SecretKey};
use crate::xeddsa::{SIGNATURE_LENGTH, XEdDSAPrivateKey, XEdDSAPublicKey};
use rand_core::CryptoRngCore;
use std::collections::HashMap;

/// Prekey bundle published by a user for others to initiate sessions.
///
/// Contains an identity key, a signed prekey with signature, and optionally
/// a one-time prekey. The signature proves possession of the identity key
/// and binds it to the signed prekey.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PreKeyBundle {
    /// Long-term identity key (X25519 public key)
    pub identity_key: PublicKey,

    /// Medium-term signed prekey (X25519 public key)
    pub signed_prekey: PublicKey,

    /// XEdDSA signature over (identity_key || signed_prekey)
    /// Signature is 64 bytes: R (32) || s (32)
    #[cfg_attr(feature = "serde", serde(with = "serde_arrays"))]
    pub signed_prekey_signature: [u8; SIGNATURE_LENGTH],

    /// Optional one-time prekey ID and corresponding X25519 public key
    /// If present, enables 4-DH mode for stronger forward secrecy.
    pub one_time_prekey: Option<(u32, PublicKey)>,
}

impl PreKeyBundle {
    /// Verifies the XEdDSA signature on the signed prekey.
    ///
    /// Ensures the bundle was created by the owner of the identity key
    /// and hasn't been tampered with.
    ///
    /// # Returns
    /// - `Ok(())` if signature is valid
    /// - `Err(Error::InvalidSignature)` if verification fails
    pub fn verify_signature(&self) -> Result<()> {
        // Convert X25519 identity key to XEdDSA public key
        let xeddsa_public = XEdDSAPublicKey::from_x25519_public(&self.identity_key)?;

        // Message format: identity_key || signed_prekey
        let mut message = Vec::with_capacity(64);
        message.extend_from_slice(self.identity_key.as_bytes());
        message.extend_from_slice(self.signed_prekey.as_bytes());

        // Verify XEdDSA signature
        xeddsa_public.verify(&message, &self.signed_prekey_signature)
    }
}

/// Prekey state maintained by a user (Bob) to respond to X3DH initiations.
///
/// Contains:
/// - Identity keypair (long-term)
/// - Signed prekey (medium-term, rotated periodically)
/// - One-time prekeys (single-use, consumed per session)
// #[cfg_attr(feature = "serde", derive(Encode, Decode))]
pub struct PreKeyState {
    identity: IdentityKeyPair,
    signed_prekey: SecretKey,
    signed_prekey_signature: [u8; SIGNATURE_LENGTH],
    one_time_prekeys: HashMap<u32, SecretKey>,
    next_opk_id: u32,
}

impl PreKeyState {
    /// Generates a new prekey state with specified number of one-time prekeys.
    ///
    /// # Arguments
    /// * `rng` - Cryptographically secure RNG
    /// * `identity` - Long-term identity keypair
    /// * `num_one_time_keys` - Number of one-time prekeys to generate (default: 100)
    pub fn generate<R: CryptoRngCore>(rng: &mut R, identity: &IdentityKeyPair) -> Self {
        Self::generate_with_count(rng, identity, 100)
    }

    /// Generates prekey state with custom one-time prekey count.
    pub fn generate_with_count<R: CryptoRngCore>(
        rng: &mut R,
        identity: &IdentityKeyPair,
        num_one_time_keys: u32,
    ) -> Self {
        let signed_prekey = SecretKey::generate(rng);

        // Create XEdDSA signature over (identity_key || signed_prekey)
        let mut message = Vec::with_capacity(64);
        message.extend_from_slice(identity.public_key().as_bytes());
        message.extend_from_slice(signed_prekey.public_key().as_bytes());

        // Generate 64 bytes of randomness for XEdDSA signing
        let mut random = [0u8; 64];
        rng.fill_bytes(&mut random);

        // Convert identity key to XEdDSA and sign
        let xeddsa_private =
            XEdDSAPrivateKey::from_x25519_private(identity.secret_key().as_bytes())
                .expect("Failed to convert identity key to XEdDSA");

        let signed_prekey_signature = xeddsa_private.sign(&message, &random);

        // Generate one-time prekeys
        let mut one_time_prekeys = HashMap::new();
        for i in 0..num_one_time_keys {
            one_time_prekeys.insert(i, SecretKey::generate(rng));
        }

        Self {
            identity: identity.clone(),
            signed_prekey,
            signed_prekey_signature,
            one_time_prekeys,
            next_opk_id: num_one_time_keys,
        }
    }

    /// Returns the public prekey bundle for distribution.
    ///
    /// Includes an available one-time prekey if any remain.
    pub fn public_bundle(&self) -> PreKeyBundle {
        let one_time_prekey = self
            .one_time_prekeys
            .iter()
            .next()
            .map(|(id, sk)| (*id, sk.public_key())); // ← Include ID!

        PreKeyBundle {
            identity_key: *self.identity.public_key(),
            signed_prekey: self.signed_prekey.public_key(),
            signed_prekey_signature: self.signed_prekey_signature,
            one_time_prekey,
        }
    }

    /// Consumes a one-time prekey by ID.
    ///
    /// Returns the secret key if it exists and hasn't been consumed.
    pub fn consume_one_time_prekey(&mut self, id: u32) -> Option<SecretKey> {
        self.one_time_prekeys.remove(&id)
    }

    /// Adds new one-time prekeys to the state.
    pub fn add_one_time_prekeys<R: CryptoRngCore>(&mut self, rng: &mut R, count: u32) {
        for _ in 0..count {
            let sk = SecretKey::generate(rng);
            self.one_time_prekeys.insert(self.next_opk_id, sk);
            self.next_opk_id += 1;
        }
    }

    /// Returns reference to identity keypair.
    pub fn identity(&self) -> &IdentityKeyPair {
        &self.identity
    }

    /// Returns reference to signed prekey secret.
    pub fn signed_prekey(&self) -> &SecretKey {
        &self.signed_prekey
    }

    /// Returns number of available one-time prekeys.
    pub fn one_time_prekey_count(&self) -> usize {
        self.one_time_prekeys.len()
    }
}

/// Initial message sent by Alice to Bob to initiate X3DH.
///
/// Contains Alice's identity and ephemeral public keys, allowing Bob
/// to perform the X3DH computation and derive the shared secret.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct InitialMessage {
    /// Alice's identity public key
    pub identity_key: PublicKey,

    /// Alice's ephemeral public key
    pub ephemeral_key: PublicKey,

    /// ID of Bob's one-time prekey used (if any)
    pub one_time_prekey_id: Option<u32>,
}

/// Result of X3DH initiation by Alice.
#[derive(Debug)]
pub struct InitiatorResult {
    /// Shared secret derived from DH operations
    pub shared_secret: SymmetricKey,

    /// Initial message to send to Bob
    pub initial_message: InitialMessage,

    /// Associated data for authentication (identity keys)
    pub associated_data: Vec<u8>,
}

/// Result of X3DH response by Bob.
#[derive(Debug)]
pub struct ResponderResult {
    /// Shared secret derived from DH operations
    pub shared_secret: SymmetricKey,

    /// Associated data for authentication (identity keys)
    pub associated_data: Vec<u8>,
}

/// Initiates X3DH key agreement (Alice's side).
///
/// Performs 3 or 4 Diffie-Hellman operations depending on whether
/// a one-time prekey is available in Bob's bundle.
///
/// # Arguments
/// * `rng` - Cryptographically secure RNG
/// * `alice_identity` - Alice's long-term identity keypair
/// * `bob_bundle` - Bob's prekey bundle
///
/// # Returns
/// Shared secret and initial message to send to Bob
pub fn initiate<R: CryptoRngCore>(
    rng: &mut R,
    alice_identity: &IdentityKeyPair,
    bob_bundle: &PreKeyBundle,
) -> Result<InitiatorResult> {
    // Verify Bob's signature on the bundle
    bob_bundle.verify_signature()?;

    // Alice's ephemeral keypair
    let alice_ephemeral = SecretKey::generate(rng);

    // DH1 = DH(IK_A, SPK_B)
    let dh1 = alice_identity
        .secret_key()
        .diffie_hellman(&bob_bundle.signed_prekey);

    // DH2 = DH(EK_A, IK_B)
    let dh2 = alice_ephemeral.diffie_hellman(&bob_bundle.identity_key);

    // DH3 = DH(EK_A, SPK_B)
    let dh3 = alice_ephemeral.diffie_hellman(&bob_bundle.signed_prekey);

    // DH4 = DH(EK_A, OPK_B) if one-time prekey available
    let (dh4, one_time_prekey_id) = if let Some((opk_id, opk_public)) = bob_bundle.one_time_prekey {
        let dh4 = alice_ephemeral.diffie_hellman(&opk_public);
        (Some(dh4), Some(opk_id))
    } else {
        (None, None)
    };

    // Derive shared secret: SK = KDF(DH1 || DH2 || DH3 || [DH4])
    let shared_secret = derive_x3dh_secret(&dh1, &dh2, &dh3, dh4.as_ref());

    // Associated data: IK_A || IK_B
    let mut associated_data = Vec::with_capacity(64);
    associated_data.extend_from_slice(alice_identity.public_key().as_bytes());
    associated_data.extend_from_slice(bob_bundle.identity_key.as_bytes());

    let initial_message = InitialMessage {
        identity_key: *alice_identity.public_key(),
        ephemeral_key: alice_ephemeral.public_key(),
        one_time_prekey_id,
    };

    Ok(InitiatorResult {
        shared_secret,
        initial_message,
        associated_data,
    })
}

/// Responds to X3DH initiation (Bob's side).
///
/// Uses the initial message from Alice to compute the same shared secret.
///
/// # Arguments
/// * `prekey_state` - Bob's prekey state
/// * `bob_identity` - Bob's identity keypair
/// * `initial_message` - Initial message from Alice
///
/// # Returns
/// Shared secret matching Alice's derivation
pub fn respond(
    prekey_state: &mut PreKeyState,
    bob_identity: &IdentityKeyPair,
    initial_message: &InitialMessage,
) -> Result<ResponderResult> {
    // DH1 = DH(SPK_B, IK_A)
    let dh1 = prekey_state
        .signed_prekey
        .diffie_hellman(&initial_message.identity_key);

    // DH2 = DH(IK_B, EK_A)
    let dh2 = bob_identity
        .secret_key()
        .diffie_hellman(&initial_message.ephemeral_key);

    // DH3 = DH(SPK_B, EK_A)
    let dh3 = prekey_state
        .signed_prekey
        .diffie_hellman(&initial_message.ephemeral_key);

    // DH4 = DH(OPK_B, EK_A) if one-time prekey was used
    let dh4 = if let Some(opk_id) = initial_message.one_time_prekey_id {
        let opk = prekey_state
            .consume_one_time_prekey(opk_id)
            .ok_or(Error::OneTimePreKeyConsumed)?;
        Some(opk.diffie_hellman(&initial_message.ephemeral_key))
    } else {
        None
    };

    // Derive shared secret: SK = KDF(DH1 || DH2 || DH3 || [DH4])
    let shared_secret = derive_x3dh_secret(&dh1, &dh2, &dh3, dh4.as_ref());

    // Associated data: IK_A || IK_B
    let mut associated_data = Vec::with_capacity(64);
    associated_data.extend_from_slice(initial_message.identity_key.as_bytes());
    associated_data.extend_from_slice(bob_identity.public_key().as_bytes());

    Ok(ResponderResult {
        shared_secret,
        associated_data,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chacha20poly1305::aead::OsRng;

    #[test]
    fn test_x3dh_handshake_with_opk() {
        let alice_identity = IdentityKeyPair::generate(&mut OsRng);
        let bob_identity = IdentityKeyPair::generate(&mut OsRng);

        let mut bob_prekeys = PreKeyState::generate(&mut OsRng, &bob_identity);
        let bundle = bob_prekeys.public_bundle();

        assert!(bundle.verify_signature().is_ok());
        assert!(bundle.one_time_prekey.is_some());

        let alice_result = initiate(&mut OsRng, &alice_identity, &bundle).unwrap();

        let bob_result = respond(
            &mut bob_prekeys,
            &bob_identity,
            &alice_result.initial_message,
        )
        .unwrap();

        assert_eq!(
            alice_result.shared_secret.as_bytes(),
            bob_result.shared_secret.as_bytes()
        );
        assert_eq!(alice_result.associated_data, bob_result.associated_data);
    }

    #[test]
    fn test_x3dh_handshake_without_opk() {
        let alice_identity = IdentityKeyPair::generate(&mut OsRng);
        let bob_identity = IdentityKeyPair::generate(&mut OsRng);

        let mut bob_prekeys = PreKeyState::generate_with_count(&mut OsRng, &bob_identity, 0);
        let bundle = bob_prekeys.public_bundle();

        assert!(bundle.verify_signature().is_ok());
        assert!(bundle.one_time_prekey.is_none());

        let alice_result = initiate(&mut OsRng, &alice_identity, &bundle).unwrap();

        let bob_result = respond(
            &mut bob_prekeys,
            &bob_identity,
            &alice_result.initial_message,
        )
        .unwrap();

        assert_eq!(
            alice_result.shared_secret.as_bytes(),
            bob_result.shared_secret.as_bytes()
        );
    }

    #[test]
    fn test_invalid_signature() {
        let bob_identity = IdentityKeyPair::generate(&mut OsRng);
        let bob_prekeys = PreKeyState::generate(&mut OsRng, &bob_identity);
        let mut bundle = bob_prekeys.public_bundle();

        // Corrupt the signature
        bundle.signed_prekey_signature[0] ^= 0xFF;

        assert!(bundle.verify_signature().is_err());
    }

    #[test]
    fn test_identity_substitution_attack_prevented() {
        let bob_identity = IdentityKeyPair::generate(&mut OsRng);
        let eve_identity = IdentityKeyPair::generate(&mut OsRng);

        let bob_prekeys = PreKeyState::generate(&mut OsRng, &bob_identity);
        let original_bundle = bob_prekeys.public_bundle();

        assert!(original_bundle.verify_signature().is_ok());

        // Eve tries to substitute Bob's identity key with her own
        let mut malicious_bundle = original_bundle.clone();
        malicious_bundle.identity_key = *eve_identity.public_key();

        // Signature verification should fail
        assert!(malicious_bundle.verify_signature().is_err());
    }

    #[test]
    fn test_signature_non_reusable() {
        let bob_identity = IdentityKeyPair::generate(&mut OsRng);
        let bob_prekeys = PreKeyState::generate(&mut OsRng, &bob_identity);
        let bundle = bob_prekeys.public_bundle();

        // attempt to reuse signature with different signed prekey
        let mut bundle2 = bundle.clone();
        bundle2.signed_prekey = SecretKey::generate(&mut OsRng).public_key();

        assert!(bundle2.verify_signature().is_err());
    }

    #[test]
    fn test_mitm_attack_rejected() {
        let alice_identity = IdentityKeyPair::generate(&mut OsRng);
        let bob_identity = IdentityKeyPair::generate(&mut OsRng);
        let eve_identity = IdentityKeyPair::generate(&mut OsRng);

        let eve_prekeys = PreKeyState::generate(&mut OsRng, &eve_identity);
        let eve_bundle = eve_prekeys.public_bundle();

        // Alice initiates with what she thinks is Bob's bundle (but is Eve's)
        let alice_result = initiate(&mut OsRng, &alice_identity, &eve_bundle).unwrap();

        // Eve cannot present this to Bob because Bob will derive different secret
        let mut bob_prekeys = PreKeyState::generate(&mut OsRng, &bob_identity);
        let bob_result = respond(
            &mut bob_prekeys,
            &bob_identity,
            &alice_result.initial_message,
        );

        // Bob's computation will succeed but produce different secret
        assert!(bob_result.is_ok());
        assert_ne!(
            alice_result.shared_secret.as_bytes(),
            bob_result.unwrap().shared_secret.as_bytes()
        );
    }
}
