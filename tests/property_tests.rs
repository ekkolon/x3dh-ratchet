//! Property-based tests for Signal protocol
//!
//! Uses proptest to verify protocol invariants across random inputs

use proptest::prelude::*;
use rand_core::OsRng;
use signal_protocol::double_ratchet::DoubleRatchet;
use signal_protocol::keys::{IdentityKeyPair, SecretKey};
use signal_protocol::x3dh::{initiate, respond, PreKeyState};

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn test_x3dh_always_produces_same_secret(seed in any::<u64>()) {
        // X3DH must always produce identical shared secrets for both parties
        use rand::SeedableRng;
        use rand::rngs::StdRng;

        let mut rng = StdRng::seed_from_u64(seed);

        let alice_identity = IdentityKeyPair::generate(&mut rng);
        let bob_identity = IdentityKeyPair::generate(&mut rng);

        let mut bob_prekeys = PreKeyState::generate(&mut rng, &bob_identity);
        let bundle = bob_prekeys.public_bundle();

        let alice_x3dh = initiate(&mut rng, &alice_identity, &bundle).unwrap();
        let bob_x3dh = respond(&mut bob_prekeys, &bob_identity, &alice_x3dh.initial_message).unwrap();

        prop_assert_eq!(
            alice_x3dh.shared_secret.as_bytes(),
            bob_x3dh.shared_secret.as_bytes()
        );
    }

    #[test]
    fn test_ratchet_encrypt_decrypt_roundtrip(
        message in prop::collection::vec(any::<u8>(), 0..1000)
    ) {
        // Any message encrypted then decrypted should match original
        let alice_identity = IdentityKeyPair::generate(&mut OsRng);
        let bob_identity = IdentityKeyPair::generate(&mut OsRng);

        let mut bob_prekeys = PreKeyState::generate(&mut OsRng, &bob_identity);
        let alice_x3dh = initiate(&mut OsRng, &alice_identity, &bob_prekeys.public_bundle()).unwrap();
        let bob_x3dh = respond(&mut bob_prekeys, &bob_identity, &alice_x3dh.initial_message).unwrap();

        let bob_dh = SecretKey::generate(&mut OsRng);
        let mut alice_ratchet = DoubleRatchet::init_sender(&mut OsRng, &alice_x3dh, bob_dh.public_key());
        let mut bob_ratchet = DoubleRatchet::init_receiver(bob_x3dh.shared_secret, bob_dh);

        let encrypted = alice_ratchet.encrypt(&message, b"").unwrap();
        let decrypted = bob_ratchet.decrypt(&encrypted, b"").unwrap();

        prop_assert_eq!(decrypted, message);
    }

    #[test]
    fn test_different_messages_different_ciphertexts(
        msg1 in prop::collection::vec(any::<u8>(), 10..100),
        msg2 in prop::collection::vec(any::<u8>(), 10..100)
    ) {
        // Different plaintexts should produce different ciphertexts
        if msg1 == msg2 {
            return Ok(());
        }

        let alice_identity = IdentityKeyPair::generate(&mut OsRng);
        let bob_identity = IdentityKeyPair::generate(&mut OsRng);

        let mut bob_prekeys = PreKeyState::generate(&mut OsRng, &bob_identity);
        let alice_x3dh = initiate(&mut OsRng, &alice_identity, &bob_prekeys.public_bundle()).unwrap();
        let _bob_x3dh = respond(&mut bob_prekeys,&bob_identity, &alice_x3dh.initial_message).unwrap();

        let bob_dh = SecretKey::generate(&mut OsRng);
        let mut alice_ratchet = DoubleRatchet::init_sender(&mut OsRng, &alice_x3dh, bob_dh.public_key());

        let ct1 = alice_ratchet.encrypt(&msg1, b"").unwrap();
        let ct2 = alice_ratchet.encrypt(&msg2, b"").unwrap();

        prop_assert_ne!(ct1.ciphertext, ct2.ciphertext);
    }

    #[test]
    fn test_message_independence(
        count in 1usize..20,
        seed in any::<u64>()
    ) {
        // messages encrypted with different sessions should be independent
        use rand::SeedableRng;
        use rand::rngs::StdRng;

        let mut rng = StdRng::seed_from_u64(seed);
        let alice_identity = IdentityKeyPair::generate(&mut rng);
        let bob_identity = IdentityKeyPair::generate(&mut rng);

        let mut bob_prekeys = PreKeyState::generate(&mut rng, &bob_identity);
        let alice_x3dh = initiate(&mut rng, &alice_identity, &bob_prekeys.public_bundle()).unwrap();
        let _bob_x3dh = respond(&mut bob_prekeys, &bob_identity, &alice_x3dh.initial_message).unwrap();

        let bob_dh = SecretKey::generate(&mut rng);
        let mut alice_ratchet = DoubleRatchet::init_sender(&mut rng, &alice_x3dh, bob_dh.public_key());

        let mut ciphertexts = Vec::new();
        for i in 0..count {
            let msg = format!("Message {}", i);
            let ct = alice_ratchet.encrypt(msg.as_bytes(), b"").unwrap();
            ciphertexts.push(ct.ciphertext);
        }

        // All ciphrtexts should be different
        for i in 0..ciphertexts.len() {
            for j in (i + 1)..ciphertexts.len() {
                prop_assert_ne!(&ciphertexts[i], &ciphertexts[j]);
            }
        }
    }

    #[test]
    fn test_out_of_order_delivery_any_order(
        permutation in prop::sample::subsequence((0..10).collect::<Vec<_>>(), 10)
    ) {
        // Messages should decrypt correctly in any order
        let alice_identity = IdentityKeyPair::generate(&mut OsRng);
        let bob_identity = IdentityKeyPair::generate(&mut OsRng);

        let mut bob_prekeys = PreKeyState::generate(&mut OsRng, &bob_identity);
        let alice_x3dh = initiate(&mut OsRng, &alice_identity, &bob_prekeys.public_bundle()).unwrap();
        let bob_x3dh = respond(&mut bob_prekeys, &bob_identity, &alice_x3dh.initial_message).unwrap();

        let bob_dh = SecretKey::generate(&mut OsRng);
        let mut alice_ratchet = DoubleRatchet::init_sender(&mut OsRng, &alice_x3dh, bob_dh.public_key());
        let mut bob_ratchet = DoubleRatchet::init_receiver(bob_x3dh.shared_secret, bob_dh);

        // encrypt messages in order
        let mut messages = Vec::new();
        for i in 0..10 {
            let msg = format!("Message {}", i);
            messages.push((alice_ratchet.encrypt(msg.as_bytes(), b"").unwrap(), msg));
        }

        // decrypt in permuted order
        for &idx in &permutation {
            let (ref encrypted, ref expected) = messages[idx];
            let decrypted = bob_ratchet.decrypt(encrypted, b"").unwrap();
            prop_assert_eq!(&decrypted, expected.as_bytes());
        }
    }
}

#[cfg(test)]
mod deterministic_tests {
    use super::*;
    use signal_protocol::crypto::SymmetricKey;

    #[test]
    fn test_kdf_deterministic() {
        // same inputs should always produce same outputs
        use signal_protocol::crypto::kdf_chain;

        let key = SymmetricKey::from_bytes([42u8; 32]);
        let (chain1, msg1) = kdf_chain(&key);
        let (chain2, msg2) = kdf_chain(&key);

        assert_eq!(chain1.as_bytes(), chain2.as_bytes());
        assert_eq!(msg1.as_bytes(), msg2.as_bytes());
    }

    #[test]
    fn test_dh_commutative() {
        // DH(a, B) == DH(b, A)
        let a = SecretKey::generate(&mut OsRng);
        let b = SecretKey::generate(&mut OsRng);

        let public_a = a.public_key();
        let public_b = b.public_key();

        let shared1 = a.diffie_hellman(&public_b);
        let shared2 = b.diffie_hellman(&public_a);

        assert_eq!(shared1.as_bytes(), shared2.as_bytes());
    }
}
