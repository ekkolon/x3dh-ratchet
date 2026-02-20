use crate::constants::NONCE_SIZE;
use crate::error::{Error, Result};
use crate::identity::SymmetricKey;

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
