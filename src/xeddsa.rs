//! XEdDSA signature scheme for X25519 keys.
//!
//! Implements the XEdDSA signature scheme from:
//! "The XEdDSA and VXEdDSA Signature Schemes" by Trevor Perrin
//! Revision 1, 2016-10-20

use crate::error::{Error, Result};
use crate::keys::PublicKey;
use curve25519_dalek::MontgomeryPoint;
use curve25519_dalek::{
    constants::ED25519_BASEPOINT_TABLE,
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
};
use sha2::{Digest, Sha512};
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// XEdDSA signature: 64 bytes (R point + s scalar)
pub const SIGNATURE_LENGTH: usize = 64;

/// XEd25519 signing key derived from X25519 private key
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct XEdDSAPrivateKey {
    /// X25519 private scalar k (clamped)
    k: [u8; 32],
    /// Ed25519 private scalar a (derived from k)
    a: Scalar,
    /// Ed25519 public key A = aB
    #[zeroize(skip)]
    public: XEdDSAPublicKey,
}

/// XEd25519 public key (Ed25519 point derived from X25519)
#[derive(Clone, Copy, Debug)]
pub struct XEdDSAPublicKey {
    /// Compressed Ed25519 point
    compressed: CompressedEdwardsY,
}

impl XEdDSAPrivateKey {
    /// Creates XEdDSA signing key from X25519 private key bytes.
    ///
    /// Takes raw secret bytes and derives both the X25519 public key and EdDSA signing key.
    pub fn from_x25519_private(k_bytes: &[u8; 32]) -> Result<Self> {
        // Create a StaticSecret to leverage x25519-dalek's key derivation
        let secret = StaticSecret::from(*k_bytes);
        let x25519_public = X25519PublicKey::from(&secret);

        // Convert X25519 public key to EdDSA public key
        let public = XEdDSAPublicKey::from_x25519_public_bytes(x25519_public.as_bytes())?;

        // Apply X25519 clamping for scalar operations
        let mut k_clamped = *k_bytes;
        k_clamped[0] &= 248;
        k_clamped[31] &= 127;
        k_clamped[31] |= 64;

        let k_scalar = Scalar::from_bytes_mod_order(k_clamped);

        // Compute E = kB to determine sign
        let e_point = &k_scalar * ED25519_BASEPOINT_TABLE;
        let e_compressed = e_point.compress();
        let sign_bit = (e_compressed.as_bytes()[31] >> 7) & 1;

        // Compute private scalar a based on sign bit
        let a = if sign_bit == 1 { -k_scalar } else { k_scalar };

        Ok(Self {
            k: k_clamped,
            a,
            public,
        })
    }

    /// Returns the XEdDSA public key.
    pub fn public_key(&self) -> &XEdDSAPublicKey {
        &self.public
    }

    /// Signs a message with XEdDSA.
    pub fn sign(&self, message: &[u8], random: &[u8; 64]) -> [u8; SIGNATURE_LENGTH] {
        // r = hash1(a || M || Z) (mod q)
        let r = self.hash1_scalar(message, random);

        // R = rB
        let r_point = &r * ED25519_BASEPOINT_TABLE;
        let r_compressed = r_point.compress();

        // h = hash(R || A || M) (mod q)
        let h = self.hash_scalar(&r_compressed, message);

        // s = r + ha (mod q)
        let s = r + (h * self.a);

        // Build signature: R || s
        let mut signature = [0u8; SIGNATURE_LENGTH];
        signature[..32].copy_from_slice(r_compressed.as_bytes());
        signature[32..].copy_from_slice(s.as_bytes());

        signature
    }

    /// Computes hash1(a || M || Z) mod q for nonce generation
    fn hash1_scalar(&self, message: &[u8], random: &[u8; 64]) -> Scalar {
        let mut hasher = Sha512::new();

        // Domain separation: hash1 = hash(0xFE || 0xFF^31 || ...)
        hasher.update(&[0xFE]);
        hasher.update(&[0xFF; 31]);

        // a || M || Z
        hasher.update(self.a.as_bytes());
        hasher.update(message);
        hasher.update(random);

        let hash = hasher.finalize();
        Scalar::from_bytes_mod_order_wide(&hash.into())
    }

    /// Computes hash(R || A || M) mod q for challenge
    fn hash_scalar(&self, r_point: &CompressedEdwardsY, message: &[u8]) -> Scalar {
        let mut hasher = Sha512::new();
        hasher.update(r_point.as_bytes());
        hasher.update(self.public.compressed.as_bytes());
        hasher.update(message);

        let hash = hasher.finalize();
        Scalar::from_bytes_mod_order_wide(&hash.into())
    }
}

impl XEdDSAPublicKey {
    /// Creates XEdDSA public key from X25519 public key.
    pub fn from_x25519_public(public_key: &PublicKey) -> Result<Self> {
        Self::from_x25519_public_bytes(public_key.as_bytes())
    }

    /// Creates XEdDSA public key from X25519 public key bytes.
    fn from_x25519_public_bytes(u_bytes: &[u8; 32]) -> Result<Self> {
        // Mask high bits per XEdDSA spec
        let mut u_masked = *u_bytes;
        u_masked[31] &= 0x7F;

        // Convert to MontgomeryPoint and apply birational map
        let montgomery = MontgomeryPoint(u_masked);
        // Convert to Edwards with sign bit = 0
        // to_edwards(sign) applies the map: y = (u - 1) / (u + 1)
        let edwards = montgomery.to_edwards(0).ok_or(Error::InvalidPublicKey)?;

        // Compress and ensure sign bit is 0
        let compressed = edwards.compress();
        let mut bytes = *compressed.as_bytes();
        bytes[31] &= 0x7F;

        Ok(Self {
            compressed: CompressedEdwardsY(bytes),
        })
    }

    /// Returns the compressed Edwards Y coordinate.
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.compressed.as_bytes()
    }

    /// Verifies an XEdDSA signature.
    pub fn verify(&self, message: &[u8], signature: &[u8; SIGNATURE_LENGTH]) -> Result<()> {
        // Parse signature R || s
        let mut r_bytes = [0u8; 32];
        let mut s_bytes = [0u8; 32];
        r_bytes.copy_from_slice(&signature[..32]);
        s_bytes.copy_from_slice(&signature[32..]);

        let r_compressed = CompressedEdwardsY(r_bytes);
        let _r_point = r_compressed.decompress().ok_or(Error::InvalidSignature)?;

        // Check s < 2^|q| (for Curve25519, |q| = 253)
        if (s_bytes[31] & 0xE0) != 0 {
            return Err(Error::InvalidSignature);
        }

        let s = Scalar::from_bytes_mod_order(s_bytes);

        // Decompress A (public key)
        let a_point = self
            .compressed
            .decompress()
            .ok_or(Error::InvalidPublicKey)?;

        if !a_point.is_torsion_free() {
            return Err(Error::InvalidPublicKey);
        }

        // h = hash(R || A || M) (mod q)
        let h = self.hash_scalar(&r_compressed, message);

        // Rcheck = sB - hA
        let r_check = EdwardsPoint::vartime_double_scalar_mul_basepoint(&h, &-a_point, &s);

        // Constant-time comparison
        if r_check.compress().as_bytes().ct_eq(&r_bytes).into() {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    }

    /// Computes hash(R || A || M) mod q
    fn hash_scalar(&self, r_point: &CompressedEdwardsY, message: &[u8]) -> Scalar {
        let mut hasher = Sha512::new();
        hasher.update(r_point.as_bytes());
        hasher.update(self.compressed.as_bytes());
        hasher.update(message);

        let hash = hasher.finalize();
        Scalar::from_bytes_mod_order_wide(&hash.into())
    }
}

impl std::fmt::Debug for XEdDSAPrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "XEdDSAPrivateKey([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        IdentityKeyPair, PreKeyState,
        keys::SecretKey,
        x3dh::{initiate, respond},
    };
    use rand::RngCore;
    use rand_core::OsRng;

    #[test]
    fn test_xeddsa_sign_verify() {
        let x25519_secret = SecretKey::generate(&mut OsRng);
        let x25519_public = x25519_secret.public_key();

        // Convert to XEdDSA
        let xeddsa_private =
            XEdDSAPrivateKey::from_x25519_private(x25519_secret.as_bytes()).unwrap();

        // Derive public key from X25519 public key
        let xeddsa_public = XEdDSAPublicKey::from_x25519_public(&x25519_public).unwrap();

        // Sign message
        let message = b"Test message for XEdDSA";
        let mut random = [0u8; 64];
        OsRng.fill_bytes(&mut random);

        let signature = xeddsa_private.sign(message, &random);

        // Verify with public key derived from X25519
        xeddsa_public.verify(message, &signature).unwrap();

        // Also verify with public key from private key
        xeddsa_private
            .public_key()
            .verify(message, &signature)
            .unwrap();
    }

    #[test]
    fn test_xeddsa_invalid_signature() {
        let x25519_secret = SecretKey::generate(&mut OsRng);
        let x25519_public = x25519_secret.public_key();

        let xeddsa_private =
            XEdDSAPrivateKey::from_x25519_private(x25519_secret.as_bytes()).unwrap();
        let xeddsa_public = XEdDSAPublicKey::from_x25519_public(&x25519_public).unwrap();

        let message = b"Original message";
        let mut random = [0u8; 64];
        OsRng.fill_bytes(&mut random);

        let signature = xeddsa_private.sign(message, &random);

        // Wrong message
        let wrong_message = b"Different message";
        assert!(xeddsa_public.verify(wrong_message, &signature).is_err());
    }

    #[test]
    fn test_x3dh_shared_secret_consistency() {
        let alice_identity = IdentityKeyPair::generate(&mut OsRng);
        let bob_identity = IdentityKeyPair::generate(&mut OsRng);

        let mut bob_prekeys = PreKeyState::generate(&mut OsRng, &bob_identity);
        let bundle = bob_prekeys.public_bundle();

        assert!(
            bundle.verify_signature().is_ok(),
            "Bundle signature must verify"
        );

        let alice_result = initiate(&mut OsRng, &alice_identity, &bundle).unwrap();

        let bob_result = respond(
            &mut bob_prekeys,
            &bob_identity,
            &alice_result.initial_message,
        )
        .unwrap();

        assert_eq!(
            alice_result.shared_secret.as_bytes(),
            bob_result.shared_secret.as_bytes(),
            "X3DH shared secrets must match!"
        );
    }

    #[test]
    fn test_signature_bounds_check() {
        let x25519_secret = SecretKey::generate(&mut OsRng);
        let x25519_public = x25519_secret.public_key();
        let xeddsa_public = XEdDSAPublicKey::from_x25519_public(&x25519_public).unwrap();

        // Create invalid signature with s >= 2^253
        let mut invalid_sig = [0u8; SIGNATURE_LENGTH];
        // Valid R point (any compressed point)
        invalid_sig[31] = 0x20; // Valid y-coordinate
        // Invalid s with high bits set
        invalid_sig[32 + 31] = 0xFF; // s >= 2^253

        let result = xeddsa_public.verify(b"test", &invalid_sig);
        assert!(result.is_err(), "Should reject s >= 2^253");
    }
}
