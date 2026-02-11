//! Cryptographic key types with automatic memory safety and zeroization.

use crate::{
    crypto::KEY_SIZE_32,
    error::{Error, Result},
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::CryptoRngCore;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// X25519 public key for Diffie-Hellman key agreement.
///
/// 32-byte curve point on Curve25519. Implements `Copy` for efficient passing.
/// Can be safely logged or transmitted as it contains no secret information.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(bincode::Decode, bincode::Encode))]
pub struct PublicKey([u8; KEY_SIZE_32]);

impl PublicKey {
    /// Size of X25519 public key in bytes.
    pub const SIZE: usize = KEY_SIZE_32;

    /// Creates a public key from raw bytes.
    #[must_use]
    pub fn from_bytes(bytes: [u8; KEY_SIZE_32]) -> Self {
        Self(bytes)
    }

    /// Returns the public key as a byte array reference.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; KEY_SIZE_32] {
        &self.0
    }

    pub(crate) fn to_x25519(self) -> X25519PublicKey {
        X25519PublicKey::from(self.0)
    }
}

impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Show first 8 bytes as hex fingerprint for debugging
        write!(
            f,
            "PublicKey({:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}...)",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5], self.0[6], self.0[7]
        )
    }
}

impl From<X25519PublicKey> for PublicKey {
    fn from(pk: X25519PublicKey) -> Self {
        Self(*pk.as_bytes())
    }
}

impl From<&StaticSecret> for PublicKey {
    fn from(secret: &StaticSecret) -> Self {
        PublicKey::from(X25519PublicKey::from(secret))
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = <[u8; 32]>::deserialize(deserializer)?;
        Ok(Self::from_bytes(bytes))
    }
}

/// X25519 secret key with automatic zeroization on drop.
///
/// 32-byte scalar for Curve25519 ECDH. Memory is securely erased when
/// the key goes out of scope to prevent key material leakage.
#[derive(Zeroize, ZeroizeOnDrop)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SecretKey(StaticSecret);

impl SecretKey {
    /// Generates a new random secret key from a cryptographically secure RNG.
    pub fn generate<R: CryptoRngCore>(rng: &mut R) -> Self {
        Self(StaticSecret::random_from_rng(rng))
    }

    /// Creates a secret key from raw bytes.
    #[must_use]
    pub fn from_bytes(bytes: [u8; KEY_SIZE_32]) -> Self {
        Self(StaticSecret::from(bytes))
    }

    /// Derives the corresponding X25519 public key.
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        PublicKey::from(&self.0)
    }

    /// Performs X25519 Diffie-Hellman key agreement.
    ///
    /// Computes the shared secret `DH(sk, PK)` where `sk` is this secret key
    /// and `PK` is the remote public key. The result is a 32-byte shared secret.
    ///
    /// The output must be passed through a KDF (e.g., HKDF) before use as a
    /// symmetric key. Raw DH output should never be used directly as a key.
    #[must_use]
    pub fn diffie_hellman(&self, public: &PublicKey) -> DhOutput {
        let shared = self.0.diffie_hellman(&public.to_x25519());
        DhOutput(*shared.as_bytes())
    }
}

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretKey([REDACTED])")
    }
}

/// Output of X25519 Diffie-Hellman key agreement.
///
/// 32-byte shared secret derived from ECDH. Automatically zeroized on drop.
/// Must be passed through a KDF before use as a symmetric key.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DhOutput(pub(crate) [u8; KEY_SIZE_32]);

impl DhOutput {
    /// Returns the raw DH output as a byte array reference.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; KEY_SIZE_32] {
        &self.0
    }
}

impl std::fmt::Debug for DhOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DhOutput([REDACTED])")
    }
}

/// Ed25519 signing keypair for identity authentication.
///
/// Contains both signing (private) and verifying (public) keys.
/// Used to sign prekey bundles in X3DH protocol.
pub struct SigningKeyPair {
    signing: SigningKey,
    verifying: VerifyingKey,
}

impl SigningKeyPair {
    /// Generates a new random Ed25519 signing keypair.
    pub fn generate<R: CryptoRngCore>(rng: &mut R) -> Self {
        let signing = SigningKey::generate(rng);
        let verifying = signing.verifying_key();
        Self { signing, verifying }
    }

    /// Returns the verifying (public) key.
    #[must_use]
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying
    }

    /// Signs a message producing a 64-byte Ed25519 signature.
    ///
    /// The signature can be verified by anyone with the corresponding
    /// verifying key, proving the signer possessed the signing key.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.signing.sign(message)
    }

    /// Returns the verifying key as raw bytes.
    #[must_use]
    pub fn verifying_key_bytes(&self) -> [u8; KEY_SIZE_32] {
        self.verifying.to_bytes()
    }
}

impl std::fmt::Debug for SigningKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SigningKeyPair {{ verifying: {:?} }}", self.verifying)
    }
}

/// Verifies an Ed25519 signature in constant time.
///
/// # Arguments
/// * `public_key` - 32-byte Ed25519 public key
/// * `message` - Message that was signed
/// * `signature` - 64-byte Ed25519 signature
///
/// # Errors
/// Returns error if:
/// - Public key encoding is invalid
/// - Signature verification fails (wrong key or corrupted signature)
pub fn verify_signature(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> Result<()> {
    let verifying_key =
        VerifyingKey::from_bytes(public_key).map_err(|_| Error::InvalidPublicKey)?;
    let sig = Signature::from_bytes(signature);
    verifying_key
        .verify(message, &sig)
        .map_err(|_| Error::InvalidSignature)
}

/// Combined identity keypair for X3DH protocol.
///
/// Contains both an X25519 key for DH key agreement and an Ed25519 key
/// for signing prekey bundles. Represents a long-term identity.
#[derive(Debug)]
pub struct IdentityKeyPair {
    /// X25519 secret key for Diffie-Hellman key agreement
    pub dh_key: SecretKey,

    /// Ed25519 keypair for signing prekey bundles
    pub signing_key: SigningKeyPair,
}

impl IdentityKeyPair {
    /// Generates a new random identity keypair.
    ///
    /// Creates independent X25519 and Ed25519 keypairs from the provided RNG.
    pub fn generate<R: CryptoRngCore>(rng: &mut R) -> Self {
        Self {
            dh_key: SecretKey::generate(rng),
            signing_key: SigningKeyPair::generate(rng),
        }
    }

    /// Returns the X25519 public key component.
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        self.dh_key.public_key()
    }

    /// Returns the Ed25519 verifying key component.
    #[must_use]
    pub fn verifying_key(&self) -> &VerifyingKey {
        self.signing_key.verifying_key()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn test_key_generation() {
        let secret = SecretKey::generate(&mut OsRng);
        let public = secret.public_key();
        assert_eq!(public.as_bytes().len(), KEY_SIZE_32);
    }

    #[test]
    fn test_diffie_hellman() {
        let alice = SecretKey::generate(&mut OsRng);
        let bob = SecretKey::generate(&mut OsRng);

        let alice_public = alice.public_key();
        let bob_public = bob.public_key();

        let shared1 = alice.diffie_hellman(&bob_public);
        let shared2 = bob.diffie_hellman(&alice_public);

        assert_eq!(shared1.as_bytes(), shared2.as_bytes());
    }

    #[test]
    fn test_signing() {
        let keypair = SigningKeyPair::generate(&mut OsRng);
        let message = b"test message";
        let signature = keypair.sign(message);

        verify_signature(
            &keypair.verifying_key_bytes(),
            message,
            &signature.to_bytes(),
        )
        .expect("signature should verify");
    }

    #[test]
    fn test_invalid_signature() {
        let keypair = SigningKeyPair::generate(&mut OsRng);
        let message = b"test message";
        let wrong_message = b"wrong message";
        let signature = keypair.sign(message);

        let result = verify_signature(
            &keypair.verifying_key_bytes(),
            wrong_message,
            &signature.to_bytes(),
        );
        assert!(result.is_err());
    }
}
