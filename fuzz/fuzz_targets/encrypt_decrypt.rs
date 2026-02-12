//! Fuzz target for encryption/decryption with corrupted inputs
//!
//! Ensures decryption failures don't cause panics or memory unsafety

#![no_main]

use libfuzzer_sys::fuzz_target;
use signal_protocol::crypto::{encrypt, decrypt, SymmetricKey};

const NONCE_SIZE: usize = 12;

fuzz_target!(|data: &[u8]| {
    if data.len() < 32 + NONCE_SIZE + 1 {
        return;
    }

    // Extract components from fuzz data
    let key = SymmetricKey::from_bytes(data[..32].try_into().unwrap());
    let nonce: [u8; NONCE_SIZE] = data[32..32 + NONCE_SIZE].try_into().unwrap();
    let plaintext = &data[32 + NONCE_SIZE..];

    // Encryption should never panic
    if let Ok(ciphertext) = encrypt(&key, &nonce, plaintext, b"") {
        // Decryption with correct parameters should succeed
        let decrypted = decrypt(&key, &nonce, &ciphertext, b"").expect("decryption should succeed");
        assert_eq!(&decrypted, plaintext);

        // Corrupted ciphertext should fail gracefully
        if ciphertext.len() > 0 {
            let mut corrupted = ciphertext.clone();
            corrupted[0] ^= 1;
            
            let _ = decrypt(&key, &nonce, &corrupted, b"");
        }

        // Wrong associated data should fail
        let _ = decrypt(&key, &nonce, &ciphertext, b"wrong");
    }
});