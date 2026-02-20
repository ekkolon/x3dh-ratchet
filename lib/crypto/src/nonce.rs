use crate::constants::NONCE_SIZE;

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
