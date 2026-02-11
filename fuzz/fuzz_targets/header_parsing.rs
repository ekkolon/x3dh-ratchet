//! Fuzz target for message header parsing

#![no_main]

use libfuzzer_sys::fuzz_target;
use signal_protocol::double_ratchet::Header;

fuzz_target!(|data: &[u8]| {
    // Try to parse header from arbitrary data
    let _ = Header::from_bytes(data);

    // If parsing succeeds, verify roundtrip
    if let Ok(header) = Header::from_bytes(data) {
        let serialized = header.to_bytes();
        let roundtrip = Header::from_bytes(&serialized).expect("roundtrip should succeed");

        assert_eq!(header.message_number, roundtrip.message_number);
        assert_eq!(header.previous_chain_length, roundtrip.previous_chain_length);
        assert_eq!(header.dh_public.as_bytes(), roundtrip.dh_public.as_bytes());
    }
});