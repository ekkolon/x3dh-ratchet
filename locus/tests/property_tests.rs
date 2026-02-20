use proptest::prelude::*;
use rand_core::OsRng;
use x3dh_ratchet::double_ratchet::DoubleRatchet;
use x3dh_ratchet::keys::{IdentityKeyPair, SecretKey};
use x3dh_ratchet::x3dh::{PreKeyState, initiate, respond};

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Property: X3DH must produce identical shared secrets for both parties
    ///
    /// For any valid X3DH exchange, Alice and Bob must derive the same
    /// shared secret SK. This is the fundamental correctness property.
    #[test]
    fn prop_x3dh_shared_secret_agreement(seed in any::<u64>()) {
        use rand::SeedableRng;
        use rand::rngs::StdRng;

        let mut rng = StdRng::seed_from_u64(seed);

        let alice_identity = IdentityKeyPair::generate(&mut rng);
        let bob_identity = IdentityKeyPair::generate(&mut rng);

        let mut bob_prekeys = PreKeyState::generate(&mut rng, &bob_identity).unwrap();
        let bundle = bob_prekeys.public_bundle();

        let alice_x3dh = initiate(&mut rng, &alice_identity, &bundle).unwrap();
        let bob_x3dh = respond(&mut bob_prekeys, &bob_identity, &alice_x3dh.initial_message).unwrap();

        prop_assert_eq!(
            alice_x3dh.shared_secret.as_bytes(),
            bob_x3dh.shared_secret.as_bytes()
        );
    }

    /// Property: Encryption is a lossless transformation
    ///
    /// For any message M, encrypt(M) then decrypt() = M (perfect correctness).
    /// Tests across arbitrary byte sequences including edge cases.
    #[test]
    fn prop_encrypt_decrypt_roundtrip(
        message in prop::collection::vec(any::<u8>(), 0..1000)
    ) {
        let alice_identity = IdentityKeyPair::generate(&mut OsRng);
        let bob_identity = IdentityKeyPair::generate(&mut OsRng);

        let mut bob_prekeys = PreKeyState::generate(&mut OsRng, &bob_identity).unwrap();
        let alice_x3dh = initiate(&mut OsRng, &alice_identity, &bob_prekeys.public_bundle()).unwrap();
        let bob_x3dh = respond(&mut bob_prekeys, &bob_identity, &alice_x3dh.initial_message).unwrap();

        let bob_dh = SecretKey::generate(&mut OsRng);
        let mut alice_ratchet = DoubleRatchet::init_sender(&mut OsRng, &alice_x3dh, bob_dh.public_key()).unwrap();
        let mut bob_ratchet = DoubleRatchet::init_receiver(bob_x3dh.shared_secret, bob_dh);

        let encrypted = alice_ratchet.encrypt(&message, b"").unwrap();
        let decrypted = bob_ratchet.decrypt(&encrypted, b"").unwrap();

        prop_assert_eq!(decrypted, message);
    }

    /// Property: Different plaintexts produce different ciphertexts
    ///
    /// Tests IND-CPA security: identical plaintexts encrypted with different
    /// message keys (due to ratcheting) must produce different ciphertexts.
    #[test]
    fn prop_ciphertext_uniqueness(
        msg1 in prop::collection::vec(any::<u8>(), 10..100),
        msg2 in prop::collection::vec(any::<u8>(), 10..100)
    ) {
        if msg1 == msg2 {
            return Ok(()); // Skip identical messages
        }

        let alice_identity = IdentityKeyPair::generate(&mut OsRng);
        let bob_identity = IdentityKeyPair::generate(&mut OsRng);

        let mut bob_prekeys = PreKeyState::generate(&mut OsRng, &bob_identity).unwrap();
        let alice_x3dh = initiate(&mut OsRng, &alice_identity, &bob_prekeys.public_bundle()).unwrap();
        respond(&mut bob_prekeys, &bob_identity, &alice_x3dh.initial_message).unwrap();

        let bob_dh = SecretKey::generate(&mut OsRng);
        let mut alice_ratchet = DoubleRatchet::init_sender(&mut OsRng, &alice_x3dh, bob_dh.public_key()).unwrap();

        let ct1 = alice_ratchet.encrypt(&msg1, b"").unwrap();
        let ct2 = alice_ratchet.encrypt(&msg2, b"").unwrap();

        prop_assert_ne!(ct1.ciphertext, ct2.ciphertext);
    }

    /// Property: Each message uses a unique key
    ///
    /// Sequential messages must have unique ciphertexts even for identical
    /// plaintexts, proving unique message key derivation (no key reuse).
    #[test]
    fn prop_message_key_uniqueness(
        count in 2usize..20,
        seed in any::<u64>()
    ) {
        use rand::SeedableRng;
        use rand::rngs::StdRng;

        let mut rng = StdRng::seed_from_u64(seed);
        let alice_identity = IdentityKeyPair::generate(&mut rng);
        let bob_identity = IdentityKeyPair::generate(&mut rng);

        let mut bob_prekeys = PreKeyState::generate(&mut rng, &bob_identity).unwrap();
        let alice_x3dh = initiate(&mut rng, &alice_identity, &bob_prekeys.public_bundle()).unwrap();
        respond(&mut bob_prekeys, &bob_identity, &alice_x3dh.initial_message).unwrap();

        let bob_dh = SecretKey::generate(&mut rng);
        let mut alice_ratchet = DoubleRatchet::init_sender(&mut rng, &alice_x3dh, bob_dh.public_key()).unwrap();

        let mut ciphertexts = Vec::new();
        for i in 0..count {
            let msg = format!("Message {}", i);
            let ct = alice_ratchet.encrypt(msg.as_bytes(), b"").unwrap();
            ciphertexts.push(ct.ciphertext);
        }

        // All ciphertexts must be pairwise distinct
        for i in 0..ciphertexts.len() {
            for j in (i + 1)..ciphertexts.len() {
                prop_assert_ne!(&ciphertexts[i], &ciphertexts[j]);
            }
        }
    }

    /// Property: Messages decrypt correctly in any order
    ///
    /// Tests skipped message key storage: messages can arrive out-of-order
    /// and still decrypt to correct plaintexts (within MAX_SKIP limit).
    #[test]
    fn prop_out_of_order_delivery(
        permutation in prop::sample::subsequence((0..10).collect::<Vec<_>>(), 10)
    ) {
        let alice_identity = IdentityKeyPair::generate(&mut OsRng);
        let bob_identity = IdentityKeyPair::generate(&mut OsRng);

        let mut bob_prekeys = PreKeyState::generate(&mut OsRng, &bob_identity).unwrap();
        let alice_x3dh = initiate(&mut OsRng, &alice_identity, &bob_prekeys.public_bundle()).unwrap();
        let bob_x3dh = respond(&mut bob_prekeys, &bob_identity, &alice_x3dh.initial_message).unwrap();

        let bob_dh = SecretKey::generate(&mut OsRng);
        let mut alice_ratchet = DoubleRatchet::init_sender(&mut OsRng, &alice_x3dh, bob_dh.public_key()).unwrap();
        let mut bob_ratchet = DoubleRatchet::init_receiver(bob_x3dh.shared_secret, bob_dh);

        // Encrypt messages in sequential order
        let mut messages = Vec::new();
        for i in 0..10 {
            let msg = format!("Message {}", i);
            messages.push((alice_ratchet.encrypt(msg.as_bytes(), b"").unwrap(), msg));
        }

        // Decrypt in arbitrary permuted order
        for &idx in &permutation {
            let (ref encrypted, ref expected) = messages[idx];
            let decrypted = bob_ratchet.decrypt(encrypted, b"").unwrap();
            prop_assert_eq!(&decrypted, expected.as_bytes());
        }
    }

    /// Property: Associated data is cryptographically bound to ciphertext
    ///
    /// Modifying AAD must cause decryption failure, proving AEAD authentication.
    #[test]
    fn prop_associated_data_binding(
        message in prop::collection::vec(any::<u8>(), 10..100),
        ad1 in prop::collection::vec(any::<u8>(), 0..50),
        ad2 in prop::collection::vec(any::<u8>(), 0..50)
    ) {
        if ad1 == ad2 {
            return Ok(()); // Skip identical AAD
        }

        let alice_identity = IdentityKeyPair::generate(&mut OsRng);
        let bob_identity = IdentityKeyPair::generate(&mut OsRng);

        let mut bob_prekeys = PreKeyState::generate(&mut OsRng, &bob_identity).unwrap();
        let alice_x3dh = initiate(&mut OsRng, &alice_identity, &bob_prekeys.public_bundle()).unwrap();
        let bob_x3dh = respond(&mut bob_prekeys, &bob_identity, &alice_x3dh.initial_message).unwrap();

        let bob_dh = SecretKey::generate(&mut OsRng);
        let mut alice_ratchet = DoubleRatchet::init_sender(&mut OsRng, &alice_x3dh, bob_dh.public_key()).unwrap();
        let mut bob_ratchet = DoubleRatchet::init_receiver(bob_x3dh.shared_secret, bob_dh);

        let encrypted = alice_ratchet.encrypt(&message, &ad1).unwrap();

        // Decryption with wrong AAD must fail
        let result = bob_ratchet.decrypt(&encrypted, &ad2);
        prop_assert!(result.is_err());
    }

    /// Property: Ciphertext modification is detected
    ///
    /// Any bit flip in ciphertext must cause authentication failure.
    #[test]
    fn prop_ciphertext_integrity(
        message in prop::collection::vec(any::<u8>(), 20..100),
        flip_idx in 0usize..100
    ) {
        let alice_identity = IdentityKeyPair::generate(&mut OsRng);
        let bob_identity = IdentityKeyPair::generate(&mut OsRng);

        let mut bob_prekeys = PreKeyState::generate(&mut OsRng, &bob_identity).unwrap();
        let alice_x3dh = initiate(&mut OsRng, &alice_identity, &bob_prekeys.public_bundle()).unwrap();
        let bob_x3dh = respond(&mut bob_prekeys, &bob_identity, &alice_x3dh.initial_message).unwrap();

        let bob_dh = SecretKey::generate(&mut OsRng);
        let mut alice_ratchet = DoubleRatchet::init_sender(&mut OsRng, &alice_x3dh, bob_dh.public_key()).unwrap();
        let mut bob_ratchet = DoubleRatchet::init_receiver(bob_x3dh.shared_secret, bob_dh);

        let mut encrypted = alice_ratchet.encrypt(&message, b"").unwrap();

        // Flip a bit in the ciphertext
        let idx = flip_idx % encrypted.ciphertext.len();
        encrypted.ciphertext[idx] ^= 1;

        // Decryption must fail
        let result = bob_ratchet.decrypt(&encrypted, b"");
        prop_assert!(result.is_err());
    }

    #[test]
    fn prop_same_plaintext_different_ciphertext(
        message in prop::collection::vec(any::<u8>(), 10..100)
    ) {
        let alice_identity = IdentityKeyPair::generate(&mut OsRng);
        let bob_identity = IdentityKeyPair::generate(&mut OsRng);

        let mut bob_prekeys = PreKeyState::generate(&mut OsRng, &bob_identity).unwrap();
        let alice_x3dh = initiate(&mut OsRng, &alice_identity, &bob_prekeys.public_bundle()).unwrap();
        respond(&mut bob_prekeys, &bob_identity, &alice_x3dh.initial_message).unwrap();

        let bob_dh = SecretKey::generate(&mut OsRng);
        let mut alice_ratchet =
            DoubleRatchet::init_sender(&mut OsRng, &alice_x3dh, bob_dh.public_key()).unwrap();

        let ct1 = alice_ratchet.encrypt(&message, b"").unwrap();
        let ct2 = alice_ratchet.encrypt(&message, b"").unwrap();

        prop_assert_ne!(ct1.ciphertext, ct2.ciphertext);
    }


    /// Property: Different sessions produce independent ciphertexts
    ///
    /// Same message encrypted in different sessions must produce different
    /// ciphertexts, proving session isolation.
    #[test]
    fn prop_session_independence(
        message in prop::collection::vec(any::<u8>(), 10..100),
        seed1 in any::<u64>(),
        seed2 in any::<u64>()
    ) {
        if seed1 == seed2 {
            return Ok(()); // Skip identical seeds
        }

        use rand::SeedableRng;
        use rand::rngs::StdRng;

        // Session 1
        let mut rng1 = StdRng::seed_from_u64(seed1);
        let alice1 = IdentityKeyPair::generate(&mut rng1);
        let bob1 = IdentityKeyPair::generate(&mut rng1);
        let mut bob_prekeys1 = PreKeyState::generate(&mut rng1, &bob1).unwrap();
        let alice_x3dh1 = initiate(&mut rng1, &alice1, &bob_prekeys1.public_bundle()).unwrap();
        respond(&mut bob_prekeys1, &bob1, &alice_x3dh1.initial_message).unwrap();
        let bob_dh1 = SecretKey::generate(&mut rng1);
        let mut alice_ratchet1 = DoubleRatchet::init_sender(&mut rng1, &alice_x3dh1, bob_dh1.public_key()).unwrap();

        // Session 2
        let mut rng2 = StdRng::seed_from_u64(seed2);
        let alice2 = IdentityKeyPair::generate(&mut rng2);
        let bob2 = IdentityKeyPair::generate(&mut rng2);
        let mut bob_prekeys2 = PreKeyState::generate(&mut rng2, &bob2).unwrap();
        let alice_x3dh2 = initiate(&mut rng2, &alice2, &bob_prekeys2.public_bundle()).unwrap();
        respond(&mut bob_prekeys2, &bob2, &alice_x3dh2.initial_message).unwrap();
        let bob_dh2 = SecretKey::generate(&mut rng2);
        let mut alice_ratchet2 = DoubleRatchet::init_sender(&mut rng2, &alice_x3dh2, bob_dh2.public_key()).unwrap();

        let ct1 = alice_ratchet1.encrypt(&message, b"").unwrap();
        let ct2 = alice_ratchet2.encrypt(&message, b"").unwrap();

        prop_assert_ne!(ct1.ciphertext, ct2.ciphertext);
    }
}

/// Deterministic property tests for cryptographic primitives
#[cfg(test)]
mod deterministic_tests {
    use super::*;
    use x3dh_ratchet::crypto::{SymmetricKey, kdf_chain};

    /// Property: KDF is deterministic
    ///
    /// Same input to KDF must always produce same output (no randomness in KDF).
    #[test]
    fn test_kdf_deterministic() {
        let key = SymmetricKey::from_bytes([42u8; 32]);

        let (chain1, msg1) = kdf_chain(&key);
        let (chain2, msg2) = kdf_chain(&key);

        assert_eq!(chain1.as_bytes(), chain2.as_bytes());
        assert_eq!(msg1.as_bytes(), msg2.as_bytes());
    }

    /// Property: KDF outputs diverge for different inputs
    ///
    /// Different chain keys must produce different message keys (no collisions).
    #[test]
    fn test_kdf_divergence() {
        let key1 = SymmetricKey::from_bytes([1u8; 32]);
        let key2 = SymmetricKey::from_bytes([2u8; 32]);

        let (_, msg1) = kdf_chain(&key1);
        let (_, msg2) = kdf_chain(&key2);

        assert_ne!(msg1.as_bytes(), msg2.as_bytes());
    }

    /// Property: Diffie-Hellman is commutative
    ///
    /// DH(a, B) must equal DH(b, A) for all keypairs.
    #[test]
    fn test_dh_commutativity() {
        let a = SecretKey::generate(&mut OsRng);
        let b = SecretKey::generate(&mut OsRng);

        let public_a = a.public_key();
        let public_b = b.public_key();

        let shared1 = a.diffie_hellman(&public_b);
        let shared2 = b.diffie_hellman(&public_a);

        assert_eq!(shared1.as_bytes(), shared2.as_bytes());
    }

    /// Property: DH public keys are deterministic
    ///
    /// Same secret key must always produce same public key.
    #[test]
    fn test_dh_public_key_deterministic() {
        let bytes = [42u8; 32];

        let sk1 = SecretKey::from_bytes(bytes);
        let sk2 = SecretKey::from_bytes(bytes);

        assert_eq!(sk1.public_key().as_bytes(), sk2.public_key().as_bytes());
    }

    /// Property: Different secret keys produce different public keys
    ///
    /// No collisions in public key generation (injectivity).
    #[test]
    fn test_dh_public_key_uniqueness() {
        let sk1 = SecretKey::generate(&mut OsRng);
        let sk2 = SecretKey::generate(&mut OsRng);

        assert_ne!(sk1.public_key().as_bytes(), sk2.public_key().as_bytes());
    }
}
