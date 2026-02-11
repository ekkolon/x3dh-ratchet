//! Fuzz target for X3DH bundle parsing
//!
//! Tests that arbitrary bundle data doesn't cause panics

#![no_main]

use libfuzzer_sys::fuzz_target;
use signal_protocol::keys::PublicKey;

fuzz_target!(|data: &[u8]| {
    // Try to parse as public key
    if data.len() >= 32 {
        let _ = PublicKey::from_bytes(data[..32].try_into().unwrap());
    }

    // Try to create bundle with arbitrary data
    if data.len() >= 32 + 32 + 64 + 32 {
        let identity_key = PublicKey::from_bytes(data[0..32].try_into().unwrap());
        let signed_prekey = PublicKey::from_bytes(data[32..64].try_into().unwrap());
        let signature = data[64..128].try_into().unwrap();
        let verifying_key = data[128..160].try_into().unwrap();

        let bundle = signal_protocol::x3dh::PreKeyBundle {
            identity_key,
            signed_prekey,
            signed_prekey_signature: signature,
            verifying_key,
            one_time_prekey: None,
        };

        // Verification should not panic, may fail
        let _ = bundle.verify_signature();
    }
});
