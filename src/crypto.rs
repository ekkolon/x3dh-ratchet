//! Cryptographic primitives for X3DH and Double Ratchet protocols.
//!
//! Provides key derivation functions (KDF), AEAD encryption/decryption,
//! and symmetric key management with automatic zeroization.

use crate::error::{Error, Result};
use crate::keys::DhOutput;

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

const X3DH_INFO: &[u8] = b"Signal_X3DH_v1";
const ROOT_INFO: &[u8] = b"Signal_DoubleRatchet_Root";

#[allow(unused)]
const SEND_INFO: &[u8] = b"Signal_DoubleRatchet_Send";

#[allow(unused)]
const RECV_INFO: &[u8] = b"Signal_DoubleRatchet_Recv";

pub const KEY_SIZE_32: usize = 32;
pub const KEY_SIZE_64: usize = 64;
pub const TAG_SIZE: usize = 16;
pub const NONCE_SIZE: usize = 12;

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
}

impl std::fmt::Debug for SymmetricKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SymmetricKey([REDACTED])")
    }
}

/// X3DH key derivation function per specification Section 2.2.
///
/// Computes `SK = HKDF(F || DH1 || DH2 || DH3 || [DH4])` where:
/// - `F = 0xFF^32` (domain separation constant for X25519/XEdDSA)
/// - `salt = 0x00^32` (32 zero bytes)
/// - `info = "Signal_X3DH_v1"`
/// - Output length is 32 bytes
///
/// The optional fourth DH output provides additional forward secrecy when
/// a one-time prekey is available.
///
/// # Panics
///
/// Never panics in practice. The internal `expect()` is only a safeguard
/// for the HKDF expand operation with a fixed 32-byte output length,
/// which is always valid.
#[must_use]
pub fn derive_x3dh_secret(
    dh1: &DhOutput,
    dh2: &DhOutput,
    dh3: &DhOutput,
    dh4: Option<&DhOutput>,
) -> SymmetricKey {
    const F: [u8; 32] = [0xFF; 32];

    let mut ikm = [0u8; 32 + 32 * 4]; // F + 4 DH outputs
    let mut len = 0;

    ikm[len..len + 32].copy_from_slice(&F);
    len += 32;

    ikm[len..len + 32].copy_from_slice(dh1.as_bytes());
    len += 32;

    ikm[len..len + 32].copy_from_slice(dh2.as_bytes());
    len += 32;

    ikm[len..len + 32].copy_from_slice(dh3.as_bytes());
    len += 32;

    if let Some(dh4) = dh4 {
        ikm[len..len + 32].copy_from_slice(dh4.as_bytes());
        len += 32;
    }

    let salt = [0u8; 32];
    let hkdf = Hkdf::<Sha256>::new(Some(&salt), &ikm[..len]);

    let mut output = [0u8; KEY_SIZE_32];
    // SAFETY: 32-byte output is always valid for HKDF-SHA256
    hkdf.expand(X3DH_INFO, &mut output)
        .expect("32-byte HKDF output is always valid");

    ikm.zeroize();
    SymmetricKey(output)
}

/// KDF chain state for symmetric ratcheting in Double Ratchet protocol.
///
/// Maintains a chain key that is advanced with each step, deriving new keys
/// while updating internal state for forward secrecy.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct KdfChain {
    key: SymmetricKey,
}

impl KdfChain {
    /// Creates a new KDF chain from a symmetric key.
    #[must_use]
    pub fn new(key: SymmetricKey) -> Self {
        Self { key }
    }

    /// Initializes a root chain from X3DH output.
    #[must_use]
    pub fn from_x3dh(x3dh_output: SymmetricKey) -> Self {
        Self::new(x3dh_output)
    }

    /// Advances the KDF chain by one step.
    ///
    /// Computes `(CK', K) = KDF(CK)` where `CK'` becomes the new chain key
    /// and `K` is returned as the derived output.
    ///
    /// # Arguments
    /// * `info` - Domain separation string for HKDF
    ///
    /// # Panics
    ///
    /// Never panics in practice. The internal `expect()` is only a safeguard
    /// for the HKDF expand operation with a fixed 64-byte output length,
    /// which is always valid.
    pub fn step(&mut self, info: &[u8]) -> Result<SymmetricKey> {
        let hkdf = Hkdf::<Sha256>::new(None, self.key.as_bytes());

        let mut output = [0u8; KEY_SIZE_64];
        // SAFETY: 64-byte output is always valid for HKDF-SHA256
        hkdf.expand(info, &mut output)
            .expect("64-byte HKDF output is always valid");

        self.key.0.copy_from_slice(&output[..KEY_SIZE_32]);
        let derived = SymmetricKey::from_bytes(
            output[KEY_SIZE_32..]
                .try_into()
                .map_err(|_| crate::Error::CryptoError)?,
        );

        output.zeroize();
        Ok(derived)
    }

    /// Returns the current chain key without advancing the chain.
    #[must_use]
    pub fn current_key(&self) -> &SymmetricKey {
        &self.key
    }
}

impl std::fmt::Debug for KdfChain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "KdfChain([REDACTED])")
    }
}

/// Root KDF for Double Ratchet DH ratchet step.
///
/// Computes `(RK', CK) = KDF_RK(RK, DH_out)` where:
/// - `RK` is the current root key
/// - `DH_out` is a Diffie-Hellman shared secret
/// - `RK'` is the new root key (first 32 bytes of output)
/// - `CK` is the new chain key (second 32 bytes of output)
///
/// Used when performing a DH ratchet step to derive new symmetric ratchet chains.
///
/// # Panics
///
/// Never panics in practice. The internal `expect()` is only a safeguard
/// for the HKDF expand operation with a fixed 64-byte output length,
/// which is always valid.
pub fn kdf_root(
    root_key: &SymmetricKey,
    dh_output: &DhOutput,
) -> Result<(SymmetricKey, SymmetricKey)> {
    let hkdf = Hkdf::<Sha256>::new(Some(root_key.as_bytes()), dh_output.as_bytes());

    let mut output = [0u8; KEY_SIZE_64];
    // SAFETY: 64-byte output is always valid for HKDF-SHA256
    hkdf.expand(ROOT_INFO, &mut output)
        .expect("64-byte HKDF output is always valid");

    let new_root = SymmetricKey::from_bytes(
        output[..KEY_SIZE_32]
            .try_into()
            .map_err(|_| crate::Error::CryptoError)?,
    );

    let new_chain = SymmetricKey::from_bytes(
        output[KEY_SIZE_32..]
            .try_into()
            .map_err(|_| crate::Error::CryptoError)?,
    );

    output.zeroize();
    Ok((new_root, new_chain))
}

/// Chain KDF for Double Ratchet symmetric ratchet step.
///
/// Computes `(CK', MK) = KDF_CK(CK)` where:
/// - `MK = HMAC(CK, 0x01)` is the message key
/// - `CK' = HMAC(CK, 0x02)` is the new chain key
///
/// Returns `(new_chain_key, message_key)` tuple.
///
/// # Panics
///
/// Never panics in practice. HMAC-SHA256 accepts keys of any size,
/// so the internal `expect()` calls are only defensive safeguards.
#[must_use]
pub fn kdf_chain(chain_key: &SymmetricKey) -> (SymmetricKey, SymmetricKey) {
    type HmacSha256 = Hmac<Sha256>;

    // Derive message key: MK = HMAC(CK, 0x01)
    let mut mac =
        HmacSha256::new_from_slice(chain_key.as_bytes()).expect("HMAC-SHA256 accepts any key size");
    mac.update(&[0x01]);
    let message_key = SymmetricKey::from_bytes(mac.finalize().into_bytes().into());

    // Derive new chain key: CK' = HMAC(CK, 0x02)
    let mut mac =
        HmacSha256::new_from_slice(chain_key.as_bytes()).expect("HMAC-SHA256 accepts any key size");
    mac.update(&[0x02]);
    let new_chain_key = SymmetricKey::from_bytes(mac.finalize().into_bytes().into());

    (new_chain_key, message_key)
}

/// Encrypts a message using ChaCha20-Poly1305 AEAD.
///
/// # Security Requirements
/// - Nonce must be unique per (key, message) pair
/// - Nonce reuse with the same key completely breaks security
/// - Associated data is authenticated but not encrypted
/// - Returns ciphertext with appended 16-byte authentication tag
///
/// # Arguments
/// * `key` - 256-bit encryption key
/// * `nonce` - 96-bit nonce (must be unique per key)
/// * `plaintext` - Data to encrypt
/// * `associated_data` - Additional authenticated data (can be empty)
///
/// # Errors
/// Returns `Error::CryptoError` if encryption fails (should not occur in practice).
pub fn encrypt(
    key: &SymmetricKey,
    nonce: &[u8; NONCE_SIZE],
    plaintext: &[u8],
    associated_data: &[u8],
) -> Result<Vec<u8>> {
    use chacha20poly1305::{
        ChaCha20Poly1305, Key, KeyInit, Nonce,
        aead::{Aead, Payload},
    };

    let cipher = ChaCha20Poly1305::new(Key::from_slice(key.as_bytes()));
    let nonce_obj = Nonce::from_slice(nonce);

    let payload = Payload {
        msg: plaintext,
        aad: associated_data,
    };

    cipher
        .encrypt(nonce_obj, payload)
        .map_err(|_| Error::CryptoError)
}

/// Decrypts a message using ChaCha20-Poly1305 AEAD.
///
/// Verifies the authentication tag in constant time before decryption.
/// Returns error if authentication fails (wrong key, corrupted data, or mismatched AAD).
///
/// # Arguments
/// * `key` - 256-bit decryption key (must match encryption key)
/// * `nonce` - 96-bit nonce (must match encryption nonce)
/// * `ciphertext` - Encrypted data with appended authentication tag
/// * `associated_data` - Additional authenticated data (must match encryption AAD)
///
/// # Errors
/// Returns `Error::DecryptionFailed` if:
/// - Authentication tag is invalid (wrong key or corrupted ciphertext)
/// - Associated data doesn't match what was used during encryption
/// - Ciphertext has been tampered with
pub fn decrypt(
    key: &SymmetricKey,
    nonce: &[u8; NONCE_SIZE],
    ciphertext: &[u8],
    associated_data: &[u8],
) -> Result<Vec<u8>> {
    use chacha20poly1305::{
        ChaCha20Poly1305, Key, KeyInit, Nonce,
        aead::{Aead, Payload},
    };

    let cipher = ChaCha20Poly1305::new(Key::from_slice(key.as_bytes()));
    let nonce_obj = Nonce::from_slice(nonce);

    let payload = Payload {
        msg: ciphertext,
        aad: associated_data,
    };

    cipher
        .decrypt(nonce_obj, payload)
        .map_err(|_| Error::DecryptionFailed)
}

/// Generates a deterministic nonce from message number and chain identifier.
///
/// Format: `nonce = msg_num (4 bytes, LE) || chain_id[0..7] (8 bytes)`
///
/// # Security
///
/// Safe for use with ChaCha20-Poly1305 because each message uses a unique key
/// derived from the KDF chain, preventing nonce reuse with the same key.
/// The nonce construction ensures uniqueness across all messages in a session.
///
/// # Arguments
/// * `message_number` - Monotonically increasing message counter
/// * `chain_id` - 32-byte chain identifier (typically a public key)
#[must_use]
pub fn generate_nonce(message_number: u32, chain_id: &[u8; 32]) -> [u8; NONCE_SIZE] {
    let mut nonce = [0u8; NONCE_SIZE];
    nonce[..4].copy_from_slice(&message_number.to_le_bytes());
    nonce[4..12].copy_from_slice(&chain_id[..8]);
    nonce
}

#[cfg(test)]
mod tests {
    use chacha20poly1305::aead::OsRng;

    use super::*;
    use crate::keys::SecretKey;

    #[test]
    fn test_x3dh_derivation() {
        let sk1 = SecretKey::generate(&mut OsRng);
        let sk2 = SecretKey::generate(&mut OsRng);
        let pk1 = sk1.public_key();
        let pk2 = sk2.public_key();

        let dh1 = sk1.diffie_hellman(&pk2);
        let dh2 = sk2.diffie_hellman(&pk1);
        let dh3 = sk1.diffie_hellman(&pk2);

        let secret = derive_x3dh_secret(&dh1, &dh2, &dh3, None);
        assert_eq!(secret.as_bytes().len(), KEY_SIZE_32);
    }

    #[test]
    fn test_kdf_chain() {
        let key = SymmetricKey::from_bytes([42u8; KEY_SIZE_32]);
        let mut chain = KdfChain::new(key);

        let derived1 = chain.step(ROOT_INFO).unwrap();
        let derived2 = chain.step(ROOT_INFO).unwrap();

        assert_ne!(derived1.as_bytes(), derived2.as_bytes());
    }

    #[test]
    fn test_encrypt_decrypt() {
        let key = SymmetricKey::from_bytes([1u8; KEY_SIZE_32]);
        let nonce = [2u8; NONCE_SIZE];
        let plaintext = b"Hello, World!";
        let ad = b"additional data";

        let ciphertext = encrypt(&key, &nonce, plaintext, ad).unwrap();
        let decrypted = decrypt(&key, &nonce, &ciphertext, ad).unwrap();

        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn test_decrypt_wrong_key() {
        let key1 = SymmetricKey::from_bytes([1u8; KEY_SIZE_32]);
        let key2 = SymmetricKey::from_bytes([2u8; KEY_SIZE_32]);
        let nonce = [3u8; NONCE_SIZE];
        let plaintext = b"secret";
        let ad = b"";

        let ciphertext = encrypt(&key1, &nonce, plaintext, ad).unwrap();
        let result = decrypt(&key2, &nonce, &ciphertext, ad);

        assert!(result.is_err());
    }

    #[test]
    fn test_kdf_domain_separation() {
        let dh1 = DhOutput([1u8; 32]);
        let dh2 = DhOutput([2u8; 32]);
        let dh3 = DhOutput([3u8; 32]);

        let sk = derive_x3dh_secret(&dh1, &dh2, &dh3, None);

        let mut expected_ikm = vec![0xFF; 32];
        expected_ikm.extend_from_slice(&[1u8; 32]);
        expected_ikm.extend_from_slice(&[2u8; 32]);
        expected_ikm.extend_from_slice(&[3u8; 32]);

        let salt = [0u8; 32];
        let hkdf = Hkdf::<Sha256>::new(Some(&salt), &expected_ikm);
        let mut expected = [0u8; 32];
        hkdf.expand(X3DH_INFO, &mut expected).unwrap();

        assert_eq!(sk.as_bytes(), &expected);
    }

    #[test]
    fn test_kdf_opk_independence() {
        let dh1 = DhOutput([1u8; 32]);
        let dh2 = DhOutput([2u8; 32]);
        let dh3 = DhOutput([3u8; 32]);
        let dh4 = DhOutput([4u8; 32]);

        let sk_3dh = derive_x3dh_secret(&dh1, &dh2, &dh3, None);
        let sk_4dh = derive_x3dh_secret(&dh1, &dh2, &dh3, Some(&dh4));

        assert_ne!(sk_3dh.as_bytes(), sk_4dh.as_bytes());
    }
}
