#![no_main]

use libfuzzer_sys::fuzz_target;
use signal_protocol::keys::PublicKey;
use signal_protocol::xeddsa::{SIGNATURE_LENGTH, XEdDSAPublicKey};

fuzz_target!(|data: &[u8]| {
    // Try to verify arbitrary signatures with arbitrary public keys
    if data.len() >= 32 + SIGNATURE_LENGTH {
        let public_bytes: [u8; 32] = data[0..32].try_into().unwrap();
        let signature: [u8; SIGNATURE_LENGTH] = data[32..32 + SIGNATURE_LENGTH].try_into().unwrap();

        let x25519_public = PublicKey::from_bytes(public_bytes);

        // Convert to XEdDSA public key - may fail for invalid points
        if let Ok(xeddsa_public) = XEdDSAPublicKey::from_x25519_public(&x25519_public) {
            // Use remaining data as message
            let message = if data.len() > 32 + SIGNATURE_LENGTH {
                &data[32 + SIGNATURE_LENGTH..]
            } else {
                b"test"
            };

            // Verification should not panic, will likely fail
            let _ = xeddsa_public.verify(message, &signature);
        }
    }

    // Test public key conversion from X25519
    if data.len() >= 32 {
        let public_bytes: [u8; 32] = data[0..32].try_into().unwrap();
        let x25519_public = PublicKey::from_bytes(public_bytes);

        // Conversion should not panic, may fail for invalid points
        let _ = XEdDSAPublicKey::from_x25519_public(&x25519_public);
    }
});
