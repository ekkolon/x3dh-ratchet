#![no_main]

use libfuzzer_sys::fuzz_target;
use signal_protocol::keys::PublicKey;
use signal_protocol::xeddsa::SIGNATURE_LENGTH;

fuzz_target!(|data: &[u8]| {
    // Try to parse as public key
    if data.len() >= 32 {
        let _ = PublicKey::from_bytes(data[..32].try_into().unwrap());
    }

    // Try to create bundle with arbitrary data
    // Bundle structure: identity_key (32) || signed_prekey (32) || signature (64)
    // Optional: opk_id (4) || one_time_prekey (32)
    if data.len() >= 32 + 32 + SIGNATURE_LENGTH {
        let identity_key = PublicKey::from_bytes(data[0..32].try_into().unwrap());
        let signed_prekey = PublicKey::from_bytes(data[32..64].try_into().unwrap());
        let signature = data[64..64 + SIGNATURE_LENGTH].try_into().unwrap();

        // Try to parse optional one-time prekey
        let one_time_prekey = if data.len() >= 64 + SIGNATURE_LENGTH + 4 + 32 {
            let opk_id = u32::from_le_bytes(
                data[64 + SIGNATURE_LENGTH..64 + SIGNATURE_LENGTH + 4]
                    .try_into()
                    .unwrap(),
            );
            let opk_public = PublicKey::from_bytes(
                data[64 + SIGNATURE_LENGTH + 4..64 + SIGNATURE_LENGTH + 4 + 32]
                    .try_into()
                    .unwrap(),
            );
            Some((opk_id, opk_public))
        } else {
            None
        };

        let bundle = signal_protocol::x3dh::PreKeyBundle {
            identity_key,
            signed_prekey,
            signed_prekey_signature: signature,
            one_time_prekey,
        };

        // Verification should not panic, may fail
        // XEdDSA verification converts X25519 key to Edwards and verifies
        let _ = bundle.verify_signature();
    }
});
