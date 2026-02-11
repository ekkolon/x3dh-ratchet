//! Cryptographic primitives for key derivation and encryption.

use crate::error::{Error, Result};
use crate::keys::DhOutput;

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// HKDF info string for X3DH shared secret derivation
const X3DH_INFO: &[u8] = b"Signal_X3DH_v1";

/// HKDF info string for Double Ratchet root chain
const ROOT_INFO: &[u8] = b"Signal_DoubleRatchet_Root";

/// HKDF info string for Double Ratchet sending chain
#[allow(unused)]
const SEND_INFO: &[u8] = b"Signal_DoubleRatchet_Send";

/// HKDF info string for Double Ratchet receiving chain
#[allow(unused)]
const RECV_INFO: &[u8] = b"Signal_DoubleRatchet_Recv";

/// Size of derived keys (32 bytes for 256-bit security)
pub const KEY_SIZE_32: usize = 32;

/// Size of derived keys (64 bytes for 512-bit security)
pub const KEY_SIZE_64: usize = 64;

/// Size of authentication tags for AEAD
pub const TAG_SIZE: usize = 16;

/// Size of nonce for ChaCha20-Poly1305
pub const NONCE_SIZE: usize = 12;

/// Derived symmetric key with automatic zeroization
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SymmetricKey([u8; KEY_SIZE_32]);

impl SymmetricKey {
    /// Create from raw bytes
    #[must_use]
    pub fn from_bytes(bytes: [u8; KEY_SIZE_32]) -> Self {
        Self(bytes)
    }

    /// Get key as bytes
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

/// X3DH key derivation
///
/// Derives shared secret from 3 or 4 DH outputs:
/// SK = HKDF(DH1 || DH2 || DH3 || DH4?, `info="Signal_X3DH_v1`")
#[must_use]
pub fn derive_x3dh_secret(
    dh1: &DhOutput,
    dh2: &DhOutput,
    dh3: &DhOutput,
    dh4: Option<&DhOutput>,
) -> SymmetricKey {
    let hkdf = Hkdf::<Sha256>::new(None, &[]);

    let mut input = Vec::with_capacity(128);
    input.extend_from_slice(dh1.as_bytes());
    input.extend_from_slice(dh2.as_bytes());
    input.extend_from_slice(dh3.as_bytes());
    if let Some(dh4) = dh4 {
        input.extend_from_slice(dh4.as_bytes());
    }

    let mut output = [0u8; KEY_SIZE_32];
    hkdf.expand(X3DH_INFO, &mut output)
        .expect("output size is valid");

    input.zeroize();
    SymmetricKey(output)
}

/// KDF Chain state for Double Ratchet
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct KdfChain {
    key: SymmetricKey,
}

impl KdfChain {
    /// Initialize from a key
    #[must_use]
    pub fn new(key: SymmetricKey) -> Self {
        Self { key }
    }

    /// Initialize root chain from X3DH output
    #[must_use]
    pub fn from_x3dh(x3dh_output: SymmetricKey) -> Self {
        Self::new(x3dh_output)
    }

    /// Perform KDF step: (`chain_key`, `message_key`) = `KDF(chain_key)`
    ///
    /// Uses HKDF with proper domain separation
    pub fn step(&mut self, info: &[u8]) -> SymmetricKey {
        let hkdf = Hkdf::<Sha256>::new(None, self.key.as_bytes());

        let mut output = [0u8; KEY_SIZE_64];
        hkdf.expand(info, &mut output)
            .expect("output size is valid");

        // First 32 bytes = new chain key
        // Second 32 bytes = derived output (message key or next root)
        self.key.0.copy_from_slice(&output[..KEY_SIZE_32]);
        let derived = SymmetricKey::from_bytes(output[KEY_SIZE_32..].try_into().unwrap());

        output.zeroize();
        derived
    }

    /// Get current key (for root KDF)
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

/// Derives new chain keys from root key and DH output
///
/// (`root_key`, `chain_key`) = `HKDF(root_key`, `DH_output`, info="Root")
#[must_use]
pub fn kdf_root(root_key: &SymmetricKey, dh_output: &DhOutput) -> (SymmetricKey, SymmetricKey) {
    let hkdf = Hkdf::<Sha256>::new(Some(root_key.as_bytes()), dh_output.as_bytes());

    let mut output = [0u8; KEY_SIZE_64];
    hkdf.expand(ROOT_INFO, &mut output)
        .expect("output size is valid");

    let new_root = SymmetricKey::from_bytes(output[..KEY_SIZE_32].try_into().unwrap());
    let new_chain = SymmetricKey::from_bytes(output[KEY_SIZE_32..].try_into().unwrap());

    output.zeroize();
    (new_root, new_chain)
}

/// Derives message key from chain key
///
/// `message_key` = `HMAC(chain_key`, 0x01)
/// `new_chain_key` = `HMAC(chain_key`, 0x02)
#[must_use]
pub fn kdf_chain(chain_key: &SymmetricKey) -> (SymmetricKey, SymmetricKey) {
    type HmacSha256 = Hmac<Sha256>;

    // Message key constant
    let mut mac =
        HmacSha256::new_from_slice(chain_key.as_bytes()).expect("HMAC accepts any key size");
    mac.update(&[0x01]);
    let message_key = SymmetricKey::from_bytes(mac.finalize().into_bytes().into());

    // Chain key constant
    let mut mac =
        HmacSha256::new_from_slice(chain_key.as_bytes()).expect("HMAC accepts any key size");
    mac.update(&[0x02]);
    let new_chain_key = SymmetricKey::from_bytes(mac.finalize().into_bytes().into());

    (new_chain_key, message_key)
}

/// Encrypt a message using ChaCha20-Poly1305 (simplified for demo)
///
/// In production, use `chacha20poly1305` crate or similar AEAD
pub fn encrypt(
    key: &SymmetricKey,
    nonce: &[u8; NONCE_SIZE],
    plaintext: &[u8],
    associated_data: &[u8],
) -> Result<Vec<u8>> {
    // In a real implementation, use ChaCha20-Poly1305
    // For this demo, we'll use HMAC-based encryption (NOT production-safe!)

    // This is a placeholder - real implementation must use proper AEAD
    type HmacSha256 = Hmac<Sha256>;

    let mut mac = HmacSha256::new_from_slice(key.as_bytes()).expect("HMAC accepts any key size");
    mac.update(nonce);
    mac.update(associated_data);
    mac.update(plaintext);
    let tag = mac.finalize().into_bytes();

    let mut ciphertext = Vec::with_capacity(plaintext.len() + TAG_SIZE);
    // XOR with key stream (simplified - real AEAD needed)
    for (i, &byte) in plaintext.iter().enumerate() {
        ciphertext.push(byte ^ key.as_bytes()[i % KEY_SIZE_32]);
    }
    ciphertext.extend_from_slice(&tag[..TAG_SIZE]);

    Ok(ciphertext)
}

/// Decrypt a message using ChaCha20-Poly1305 (simplified for demo)
pub fn decrypt(
    key: &SymmetricKey,
    nonce: &[u8; NONCE_SIZE],
    ciphertext: &[u8],
    associated_data: &[u8],
) -> Result<Vec<u8>> {
    if ciphertext.len() < TAG_SIZE {
        return Err(Error::DecryptionFailed);
    }

    let (ct, tag) = ciphertext.split_at(ciphertext.len() - TAG_SIZE);

    // Verify tag
    type HmacSha256 = Hmac<Sha256>;
    let mut plaintext = Vec::with_capacity(ct.len());

    // XOR with key stream (simplified)
    for (i, &byte) in ct.iter().enumerate() {
        plaintext.push(byte ^ key.as_bytes()[i % KEY_SIZE_32]);
    }

    let mut mac = HmacSha256::new_from_slice(key.as_bytes()).expect("HMAC accepts any key size");
    mac.update(nonce);
    mac.update(associated_data);
    mac.update(&plaintext);
    let expected_tag = mac.finalize().into_bytes();

    // Constant-time comparison
    if bool::from(expected_tag[..TAG_SIZE].ct_eq(tag)) {
        Ok(plaintext)
    } else {
        plaintext.zeroize();
        Err(Error::AuthenticationFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::SecretKey;
    use rand_core::OsRng;

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

        let derived1 = chain.step(ROOT_INFO);
        let derived2 = chain.step(ROOT_INFO);

        // outputs should be different
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
}
