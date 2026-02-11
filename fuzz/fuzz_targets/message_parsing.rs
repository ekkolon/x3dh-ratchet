//! Fuzz target for Double Ratchet message parsing
//!
//! Tests that arbitrary message data doesn't cause panics or undefined behavior

#![no_main]

use libfuzzer_sys::fuzz_target;
use signal_protocol::double_ratchet::Message;

fuzz_target!(|data: &[u8]| {
    // Try to deserialize arbitrary data as a message
    let _ = Message::from_bytes(data);

    // If it parses successfully, try serialization roundtrip
    if let Ok(message) = Message::from_bytes(data) {
        let serialized = message.to_bytes();
        
        // Roundtrip should succeed
        if let Ok(roundtrip) = Message::from_bytes(&serialized) {
            // Header fields should match
            assert_eq!(
                message.header.message_number,
                roundtrip.header.message_number
            );
            assert_eq!(
                message.header.previous_chain_length,
                roundtrip.header.previous_chain_length
            );
            assert_eq!(message.ciphertext, roundtrip.ciphertext);
        }
    }
});