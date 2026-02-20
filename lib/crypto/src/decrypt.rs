use crate::constants::NONCE_SIZE;
use crate::error::{Error, Result};
use crate::identity::SymmetricKey;

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
