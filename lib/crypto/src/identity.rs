//! Cryptographic key types with automatic memory safety and zeroization.

use crate::constants::KEY_SIZE_32;
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
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
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

#[cfg(feature = "expose-secrets")]
impl SecretKey {
    /// Returns the raw secret key bytes (for `XEdDSA` conversion).
    ///
    /// # Security
    /// Handle with care - exposes raw key material.
    /// Used internally for `XEdDSA` key conversion.
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
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

/// 256-bit symmetric key with automatic zeroization on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SymmetricKey([u8; KEY_SIZE_32]);

impl SymmetricKey {
    /// Creates a symmetric key from raw bytes.
    #[must_use]
    pub fn from_bytes(bytes: [u8; KEY_SIZE_32]) -> Self {
        Self(bytes)
    }

    /// Returns the key as a byte array reference.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; KEY_SIZE_32] {
        &self.0
    }

    /// Returns the key as a byte array reference.
    #[must_use]
    pub fn as_bytes_mut(&mut self) -> &mut [u8; KEY_SIZE_32] {
        &mut self.0
    }
}

impl std::fmt::Debug for SymmetricKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SymmetricKey([REDACTED])")
    }
}

/// Identity keypair for X3DH protocol.
///
/// Contains a single X25519 keypair that serves dual purposes:
/// 1. Diffie-Hellman key agreement (via X25519)
/// 2. Digital signatures (via `XEdDSA` - X25519-derived `EdDSA`)
///
/// This unified approach eliminates the need for separate signing keys
/// while maintaining security properties of both ECDH and `EdDSA`.
#[derive(Clone, Debug)]
pub struct IdentityKeyPair {
    /// X25519 secret key (used for both DH and `XEdDSA` signing)
    secret: SecretKey,
    /// Cached X25519 public key
    public: PublicKey,
}

impl IdentityKeyPair {
    /// Generates a new random identity keypair.
    ///
    /// Creates a single X25519 keypair that can be used for both
    /// Diffie-Hellman key agreement and `XEdDSA` signatures.
    pub fn generate<R: CryptoRngCore>(rng: &mut R) -> Self {
        let secret = SecretKey::generate(rng);
        let public = secret.public_key();
        Self { secret, public }
    }

    /// Returns the X25519 public key.
    #[must_use]
    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }

    /// Returns a reference to the secret key.
    ///
    /// Used for Diffie-Hellman operations and `XEdDSA` signing.
    #[must_use]
    pub fn secret_key(&self) -> &SecretKey {
        &self.secret
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
    fn test_identity_keypair() {
        let identity = IdentityKeyPair::generate(&mut OsRng);

        // Public key should match derived key
        let derived_public = identity.secret_key().public_key();
        assert_eq!(identity.public_key().as_bytes(), derived_public.as_bytes());
    }

    #[test]
    fn test_dh_symmetry() {
        let alice_secret = SecretKey::generate(&mut OsRng);
        let bob_secret = SecretKey::generate(&mut OsRng);

        let alice_public = alice_secret.public_key();
        let bob_public = bob_secret.public_key();

        let dh1 = alice_secret.diffie_hellman(&bob_public);
        let dh2 = bob_secret.diffie_hellman(&alice_public);

        assert_eq!(dh1.as_bytes(), dh2.as_bytes(), "DH must be symmetric!");
    }
}
