//! Cryptographic key types with memory safety guarantees.

use crate::{
    crypto::KEY_SIZE_32,
    error::{Error, Result},
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::CryptoRngCore;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// X25519 public key (32 bytes)
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(bincode::Decode, bincode::Encode))]
pub struct PublicKey([u8; KEY_SIZE_32]);

impl PublicKey {
    /// Size in bytes
    pub const SIZE: usize = KEY_SIZE_32;

    /// Create from raw bytes
    #[must_use]
    pub fn from_bytes(bytes: [u8; KEY_SIZE_32]) -> Self {
        Self(bytes)
    }

    /// Get raw bytes
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; KEY_SIZE_32] {
        &self.0
    }

    /// Convert to X25519 public key
    pub(crate) fn to_x25519(&self) -> X25519PublicKey {
        X25519PublicKey::from(self.0)
    }
}

impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PublicKey([REDACTED])")
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

/// X25519 secret key with automatic zeroization
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretKey(StaticSecret);

impl SecretKey {
    /// Generate a new random secret key
    pub fn generate<R: CryptoRngCore>(rng: &mut R) -> Self {
        Self(StaticSecret::random_from_rng(rng))
    }

    /// Create from raw bytes (must be 32 bytes)
    #[must_use]
    pub fn from_bytes(bytes: [u8; KEY_SIZE_32]) -> Self {
        Self(StaticSecret::from(bytes))
    }

    /// Get the corresponding public key
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        PublicKey::from(&self.0)
    }

    /// Perform Diffie-Hellman key agreement
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

/// Output of Diffie-Hellman operation (32 bytes)
/// Automatically zeroized on drop
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DhOutput([u8; KEY_SIZE_32]);

impl DhOutput {
    /// Returns a byte slice of the Diffie-Hellman operation output
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

/// Ed25519 signing key for identity signatures
pub struct SigningKeyPair {
    signing: SigningKey,
    verifying: VerifyingKey,
}

impl SigningKeyPair {
    /// Generate a new random signing key pair
    pub fn generate<R: CryptoRngCore>(rng: &mut R) -> Self {
        let signing = SigningKey::generate(rng);
        let verifying = signing.verifying_key();
        Self { signing, verifying }
    }

    /// Get the verifying (public) key
    #[must_use]
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying
    }

    /// Sign a message
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.signing.sign(message)
    }

    /// Get verifying key as bytes
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

/// Verify an Ed25519 signature
pub fn verify_signature(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> Result<()> {
    let verifying_key =
        VerifyingKey::from_bytes(public_key).map_err(|_| Error::InvalidPublicKey)?;
    let sig = Signature::from_bytes(signature);
    verifying_key
        .verify(message, &sig)
        .map_err(|_| Error::InvalidSignature)
}

/// Identity key pair combining X25519 and Ed25519
#[derive(Debug)]
pub struct IdentityKeyPair {
    /// X25519 key for key agreement
    pub dh_key: SecretKey,
    /// Ed25519 key for signing
    pub signing_key: SigningKeyPair,
}

impl IdentityKeyPair {
    /// Generate a new identity key pair
    pub fn generate<R: CryptoRngCore>(rng: &mut R) -> Self {
        Self {
            dh_key: SecretKey::generate(rng),
            signing_key: SigningKeyPair::generate(rng),
        }
    }

    /// Get the public identity key
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        self.dh_key.public_key()
    }

    /// Get the verifying key
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
