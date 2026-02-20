// tests/integration_tests.rs (or similar)

use chacha20poly1305::aead::OsRng;
use x3dh_ratchet::Error;
use x3dh_ratchet::double_ratchet::{DoubleRatchet, Header, Message};
use x3dh_ratchet::keys::{IdentityKeyPair, SecretKey};
use x3dh_ratchet::x3dh::{PreKeyState, initiate, respond};

/// X3DH key agreement + Double Ratchet messaging
#[test]
fn test_full_protocol_flow() {
    let alice_identity = IdentityKeyPair::generate(&mut OsRng);
    let bob_identity = IdentityKeyPair::generate(&mut OsRng);

    let mut bob_prekeys = PreKeyState::generate(&mut OsRng, &bob_identity).unwrap();
    let bob_bundle = bob_prekeys.public_bundle();

    let alice_x3dh =
        initiate(&mut OsRng, &alice_identity, &bob_bundle).expect("X3DH initiation should succeed");

    let bob_x3dh = respond(&mut bob_prekeys, &bob_identity, &alice_x3dh.initial_message)
        .expect("X3DH response should succeed");

    assert_eq!(
        alice_x3dh.shared_secret.as_bytes(),
        bob_x3dh.shared_secret.as_bytes(),
        "X3DH shared secrets must match"
    );

    let bob_dh = SecretKey::generate(&mut OsRng);
    let mut alice_ratchet =
        DoubleRatchet::init_sender(&mut OsRng, &alice_x3dh, bob_dh.public_key()).unwrap();
    let mut bob_ratchet = DoubleRatchet::init_receiver(bob_x3dh.shared_secret, bob_dh);

    let messages = vec![
        b"Hello Bob!".as_slice(),
        b"How are you?".as_slice(),
        b"This is a secure message".as_slice(),
    ];

    for msg in &messages {
        let encrypted = alice_ratchet.encrypt(msg, b"").unwrap();
        let decrypted = bob_ratchet.decrypt(&encrypted, b"").unwrap();
        assert_eq!(&decrypted, msg);
    }

    let response = b"Hello Alice! I'm good!";
    let encrypted = bob_ratchet.encrypt(response, b"").unwrap();
    let decrypted = alice_ratchet.decrypt(&encrypted, b"").unwrap();
    assert_eq!(&decrypted, response);
}

#[test]
fn test_x3dh_without_one_time_prekey() {
    let alice_identity = IdentityKeyPair::generate(&mut OsRng);
    let bob_identity = IdentityKeyPair::generate(&mut OsRng);

    let bob_prekeys = PreKeyState::generate_with_count(&mut OsRng, &bob_identity, 0).unwrap();
    let bundle = bob_prekeys.public_bundle();

    assert!(
        bundle.one_time_prekey.is_none(),
        "Bundle should have no OPK"
    );

    let alice_x3dh = initiate(&mut OsRng, &alice_identity, &bundle)
        .expect("X3DH should work without one-time prekey");

    assert!(
        alice_x3dh.initial_message.one_time_prekey_id.is_none(),
        "Should not use OPK in 3-DH mode"
    );
}

#[test]
fn test_out_of_order_messages() {
    let alice_identity = IdentityKeyPair::generate(&mut OsRng);
    let bob_identity = IdentityKeyPair::generate(&mut OsRng);

    let mut bob_prekeys = PreKeyState::generate(&mut OsRng, &bob_identity).unwrap();
    let alice_x3dh = initiate(&mut OsRng, &alice_identity, &bob_prekeys.public_bundle()).unwrap();
    let bob_x3dh = respond(&mut bob_prekeys, &bob_identity, &alice_x3dh.initial_message).unwrap();

    let bob_dh = SecretKey::generate(&mut OsRng);
    let mut alice_ratchet =
        DoubleRatchet::init_sender(&mut OsRng, &alice_x3dh, bob_dh.public_key()).unwrap();
    let mut bob_ratchet = DoubleRatchet::init_receiver(bob_x3dh.shared_secret, bob_dh);

    let msg1 = alice_ratchet.encrypt(b"Message 1", b"").unwrap();
    let msg2 = alice_ratchet.encrypt(b"Message 2", b"").unwrap();
    let msg3 = alice_ratchet.encrypt(b"Message 3", b"").unwrap();

    // Bob receives out of order: 3, 1, 2
    let plain3 = bob_ratchet.decrypt(&msg3, b"").unwrap();
    assert_eq!(&plain3, b"Message 3");

    let plain1 = bob_ratchet.decrypt(&msg1, b"").unwrap();
    assert_eq!(&plain1, b"Message 1");

    let plain2 = bob_ratchet.decrypt(&msg2, b"").unwrap();
    assert_eq!(&plain2, b"Message 2");
}

#[test]
fn test_bidirectional_messaging() {
    let alice_identity = IdentityKeyPair::generate(&mut OsRng);
    let bob_identity = IdentityKeyPair::generate(&mut OsRng);

    let mut bob_prekeys = PreKeyState::generate(&mut OsRng, &bob_identity).unwrap();
    let alice_x3dh = initiate(&mut OsRng, &alice_identity, &bob_prekeys.public_bundle()).unwrap();
    let bob_x3dh = respond(&mut bob_prekeys, &bob_identity, &alice_x3dh.initial_message).unwrap();

    let bob_dh = SecretKey::generate(&mut OsRng);
    let mut alice_ratchet =
        DoubleRatchet::init_sender(&mut OsRng, &alice_x3dh, bob_dh.public_key()).unwrap();
    let mut bob_ratchet = DoubleRatchet::init_receiver(bob_x3dh.shared_secret, bob_dh);

    let a1 = alice_ratchet.encrypt(b"Alice 1", b"").unwrap();
    assert_eq!(&bob_ratchet.decrypt(&a1, b"").unwrap(), b"Alice 1");

    // Bob's first message triggers DH ratchet step
    let b1 = bob_ratchet.encrypt(b"Bob 1", b"").unwrap();
    assert_eq!(&alice_ratchet.decrypt(&b1, b"").unwrap(), b"Bob 1");

    let a2 = alice_ratchet.encrypt(b"Alice 2", b"").unwrap();
    assert_eq!(&bob_ratchet.decrypt(&a2, b"").unwrap(), b"Alice 2");
}

#[test]
fn test_dh_ratchet_rotation() {
    let alice_identity = IdentityKeyPair::generate(&mut OsRng);
    let bob_identity = IdentityKeyPair::generate(&mut OsRng);

    let mut bob_prekeys = PreKeyState::generate(&mut OsRng, &bob_identity).unwrap();
    let alice_x3dh = initiate(&mut OsRng, &alice_identity, &bob_prekeys.public_bundle()).unwrap();
    let bob_x3dh = respond(&mut bob_prekeys, &bob_identity, &alice_x3dh.initial_message).unwrap();

    let bob_dh = SecretKey::generate(&mut OsRng);
    let mut alice_ratchet =
        DoubleRatchet::init_sender(&mut OsRng, &alice_x3dh, bob_dh.public_key()).unwrap();
    let mut bob_ratchet = DoubleRatchet::init_receiver(bob_x3dh.shared_secret, bob_dh);

    let msg1 = alice_ratchet.encrypt(b"test", b"").unwrap();
    let alice_dh_1 = msg1.header.dh_public;

    bob_ratchet.decrypt(&msg1, b"").unwrap();

    // Bob sends - triggers DH ratchet on Bob's side
    let msg2 = bob_ratchet.encrypt(b"response", b"").unwrap();
    let _bob_dh_1 = msg2.header.dh_public;

    // Alice receives - triggers DH ratchet on Alice's side
    alice_ratchet.decrypt(&msg2, b"").unwrap();

    // Alice sends again - should have new DH key
    let msg3 = alice_ratchet.encrypt(b"test2", b"").unwrap();
    let alice_dh_2 = msg3.header.dh_public;

    assert_ne!(
        alice_dh_1, alice_dh_2,
        "DH public key should rotate after ratchet step"
    );
}

#[test]
fn test_excessive_skipped_messages() {
    let alice_identity = IdentityKeyPair::generate(&mut OsRng);
    let bob_identity = IdentityKeyPair::generate(&mut OsRng);

    let mut bob_prekeys = PreKeyState::generate(&mut OsRng, &bob_identity).unwrap();
    let alice_x3dh = initiate(&mut OsRng, &alice_identity, &bob_prekeys.public_bundle()).unwrap();
    let bob_x3dh = respond(&mut bob_prekeys, &bob_identity, &alice_x3dh.initial_message).unwrap();

    let bob_dh = SecretKey::generate(&mut OsRng);
    let mut alice_ratchet =
        DoubleRatchet::init_sender(&mut OsRng, &alice_x3dh, bob_dh.public_key()).unwrap();
    let mut bob_ratchet = DoubleRatchet::init_receiver(bob_x3dh.shared_secret, bob_dh);

    // Encrypt 1002 messages (MAX_SKIP is 1000)
    let mut messages = Vec::new();
    for i in 0..1002 {
        messages.push(
            alice_ratchet
                .encrypt(format!("Msg {}", i).as_bytes(), b"")
                .unwrap(),
        );
    }

    // Bob is at recv_count = 0
    // Trying to decrypt message 1001 requires skipping 1001 messages
    // This exceeds MAX_SKIP = 1000
    let result = bob_ratchet.decrypt(&messages[1001], b"");
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), Error::TooManySkippedMessages);

    // But message 1000 should work (skips exactly 1000 messages)
    let result = bob_ratchet.decrypt(&messages[1000], b"");
    assert!(result.is_ok());
}

#[test]
fn test_message_replay_rejected() {
    let alice_identity = IdentityKeyPair::generate(&mut OsRng);
    let bob_identity = IdentityKeyPair::generate(&mut OsRng);

    let mut bob_prekeys = PreKeyState::generate(&mut OsRng, &bob_identity).unwrap();
    let alice_x3dh = initiate(&mut OsRng, &alice_identity, &bob_prekeys.public_bundle()).unwrap();
    let bob_x3dh = respond(&mut bob_prekeys, &bob_identity, &alice_x3dh.initial_message).unwrap();

    let bob_dh = SecretKey::generate(&mut OsRng);
    let mut alice_ratchet =
        DoubleRatchet::init_sender(&mut OsRng, &alice_x3dh, bob_dh.public_key()).unwrap();
    let mut bob_ratchet = DoubleRatchet::init_receiver(bob_x3dh.shared_secret, bob_dh);

    let msg = alice_ratchet.encrypt(b"test", b"").unwrap();

    // First decryption succeeds
    assert!(bob_ratchet.decrypt(&msg, b"").is_ok());

    // Replay should fail (key already consumed)
    let result = bob_ratchet.decrypt(&msg, b"");
    assert!(result.is_err());
}

#[test]
fn test_corrupted_ciphertext_rejected() {
    let alice_identity = IdentityKeyPair::generate(&mut OsRng);
    let bob_identity = IdentityKeyPair::generate(&mut OsRng);

    let mut bob_prekeys = PreKeyState::generate(&mut OsRng, &bob_identity).unwrap();
    let alice_x3dh = initiate(&mut OsRng, &alice_identity, &bob_prekeys.public_bundle()).unwrap();
    let bob_x3dh = respond(&mut bob_prekeys, &bob_identity, &alice_x3dh.initial_message).unwrap();

    let bob_dh = SecretKey::generate(&mut OsRng);
    let mut alice_ratchet =
        DoubleRatchet::init_sender(&mut OsRng, &alice_x3dh, bob_dh.public_key()).unwrap();
    let mut bob_ratchet = DoubleRatchet::init_receiver(bob_x3dh.shared_secret, bob_dh);

    let mut msg = alice_ratchet.encrypt(b"test", b"").unwrap();

    // Corrupt ciphertext
    msg.ciphertext[10] ^= 1;

    let result = bob_ratchet.decrypt(&msg, b"");
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), Error::DecryptionFailed);
}

#[test]
fn test_invalid_signature_rejected() {
    let bob_identity = IdentityKeyPair::generate(&mut OsRng);
    let bob_prekeys = PreKeyState::generate(&mut OsRng, &bob_identity).unwrap();
    let mut bundle = bob_prekeys.public_bundle();

    // Corrupt XEdDSA signature
    bundle.signed_prekey_signature[0] ^= 1;

    let alice_identity = IdentityKeyPair::generate(&mut OsRng);
    let result = initiate(&mut OsRng, &alice_identity, &bundle);

    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), Error::InvalidSignature);
}

#[test]
fn test_one_time_prekey_consumption() {
    let bob_identity = IdentityKeyPair::generate(&mut OsRng);
    let mut bob_prekeys = PreKeyState::generate(&mut OsRng, &bob_identity).unwrap();

    let count_before = bob_prekeys.one_time_prekey_count();
    assert!(count_before > 0);

    // Consume via actual X3DH flow
    let alice_identity = IdentityKeyPair::generate(&mut OsRng);
    let bundle = bob_prekeys.public_bundle();
    let alice_x3dh = initiate(&mut OsRng, &alice_identity, &bundle).unwrap();

    // Respond consumes the OPK
    let _ = respond(&mut bob_prekeys, &bob_identity, &alice_x3dh.initial_message).unwrap();

    assert_eq!(bob_prekeys.one_time_prekey_count(), count_before - 1);
}

#[test]
fn test_missing_one_time_prekey() {
    let bob_identity = IdentityKeyPair::generate(&mut OsRng);
    let bob_prekeys = PreKeyState::generate_with_count(&mut OsRng, &bob_identity, 0).unwrap();

    assert_eq!(bob_prekeys.one_time_prekey_count(), 0);

    let bundle = bob_prekeys.public_bundle();
    assert!(
        bundle.one_time_prekey.is_none(),
        "Bundle should not have OPK when none available"
    );
}

#[test]
fn test_message_serialization() {
    let header = Header {
        dh_public: SecretKey::generate(&mut OsRng).public_key(),
        previous_chain_length: 10,
        message_number: 5,
    };

    let message = Message {
        header: header.clone(),
        ciphertext: vec![1, 2, 3, 4, 5],
    };

    let bytes = message.to_bytes();
    let deserialized = Message::from_bytes(&bytes).expect("Deserialization should succeed");

    assert_eq!(deserialized.header.dh_public, header.dh_public);
    assert_eq!(
        deserialized.header.previous_chain_length,
        header.previous_chain_length
    );
    assert_eq!(deserialized.header.message_number, header.message_number);
    assert_eq!(deserialized.ciphertext, message.ciphertext);
}

#[test]
fn test_associated_data_integrity() {
    let alice_identity = IdentityKeyPair::generate(&mut OsRng);
    let bob_identity = IdentityKeyPair::generate(&mut OsRng);

    let mut bob_prekeys = PreKeyState::generate(&mut OsRng, &bob_identity).unwrap();
    let alice_x3dh = initiate(&mut OsRng, &alice_identity, &bob_prekeys.public_bundle()).unwrap();
    let bob_x3dh = respond(&mut bob_prekeys, &bob_identity, &alice_x3dh.initial_message).unwrap();

    let bob_dh = SecretKey::generate(&mut OsRng);
    let mut alice_ratchet =
        DoubleRatchet::init_sender(&mut OsRng, &alice_x3dh, bob_dh.public_key()).unwrap();
    let mut bob_ratchet = DoubleRatchet::init_receiver(bob_x3dh.shared_secret, bob_dh);

    let ad = b"important context";
    let encrypted = alice_ratchet.encrypt(b"secret", ad).unwrap();

    // Correct AD works
    assert!(bob_ratchet.decrypt(&encrypted, ad).is_ok());

    // Wrong AD fails
    let encrypted2 = alice_ratchet.encrypt(b"secret2", ad).unwrap();
    let result = bob_ratchet.decrypt(&encrypted2, b"wrong AD");
    assert!(result.is_err());
}

#[test]
fn test_forward_secrecy() {
    let alice_identity = IdentityKeyPair::generate(&mut OsRng);
    let bob_identity = IdentityKeyPair::generate(&mut OsRng);

    let mut bob_prekeys = PreKeyState::generate(&mut OsRng, &bob_identity).unwrap();
    let alice_x3dh = initiate(&mut OsRng, &alice_identity, &bob_prekeys.public_bundle()).unwrap();
    let bob_x3dh = respond(&mut bob_prekeys, &bob_identity, &alice_x3dh.initial_message).unwrap();

    let bob_dh = SecretKey::generate(&mut OsRng);
    let mut alice_ratchet =
        DoubleRatchet::init_sender(&mut OsRng, &alice_x3dh, bob_dh.public_key()).unwrap();
    let mut bob_ratchet = DoubleRatchet::init_receiver(bob_x3dh.shared_secret, bob_dh);

    let old_msg = alice_ratchet.encrypt(b"old", b"").unwrap();
    bob_ratchet.decrypt(&old_msg, b"").unwrap();

    // Advance ratchet many times
    for i in 0..10 {
        let msg = alice_ratchet
            .encrypt(format!("msg{}", i).as_bytes(), b"")
            .unwrap();
        bob_ratchet.decrypt(&msg, b"").unwrap();
    }

    // Old message should not be decryptable (key deleted)
    let result = bob_ratchet.decrypt(&old_msg, b"");
    assert!(result.is_err(), "Old message keys should be deleted");
}

/// Recovery after key compromise
#[test]
fn test_post_compromise_security() {
    let alice_identity = IdentityKeyPair::generate(&mut OsRng);
    let bob_identity = IdentityKeyPair::generate(&mut OsRng);

    let mut bob_prekeys = PreKeyState::generate(&mut OsRng, &bob_identity).unwrap();
    let alice_x3dh = initiate(&mut OsRng, &alice_identity, &bob_prekeys.public_bundle()).unwrap();
    let bob_x3dh = respond(&mut bob_prekeys, &bob_identity, &alice_x3dh.initial_message).unwrap();

    let bob_dh = SecretKey::generate(&mut OsRng);
    let mut alice_ratchet =
        DoubleRatchet::init_sender(&mut OsRng, &alice_x3dh, bob_dh.public_key()).unwrap();
    let mut bob_ratchet = DoubleRatchet::init_receiver(bob_x3dh.shared_secret, bob_dh);

    // Normal exchange
    let msg1 = alice_ratchet.encrypt(b"before", b"").unwrap();
    bob_ratchet.decrypt(&msg1, b"").unwrap();

    // [Simulated compromise here - attacker gets state]
    // In real attack, attacker could decrypt messages at this point

    // Bob sends response - triggers DH ratchet with new ephemeral key
    let msg2 = bob_ratchet.encrypt(b"recovery", b"").unwrap();
    alice_ratchet.decrypt(&msg2, b"").unwrap();

    // After DH ratchet, security is restored
    // New messages use fresh key material unknown to attacker
    let msg3 = alice_ratchet.encrypt(b"secure again", b"").unwrap();
    let decrypted = bob_ratchet.decrypt(&msg3, b"").unwrap();
    assert_eq!(&decrypted, b"secure again");
}

#[test]
fn test_large_messages() {
    let alice_identity = IdentityKeyPair::generate(&mut OsRng);
    let bob_identity = IdentityKeyPair::generate(&mut OsRng);

    let mut bob_prekeys = PreKeyState::generate(&mut OsRng, &bob_identity).unwrap();
    let alice_x3dh = initiate(&mut OsRng, &alice_identity, &bob_prekeys.public_bundle()).unwrap();
    let bob_x3dh = respond(&mut bob_prekeys, &bob_identity, &alice_x3dh.initial_message).unwrap();

    let bob_dh = SecretKey::generate(&mut OsRng);
    let mut alice_ratchet =
        DoubleRatchet::init_sender(&mut OsRng, &alice_x3dh, bob_dh.public_key()).unwrap();
    let mut bob_ratchet = DoubleRatchet::init_receiver(bob_x3dh.shared_secret, bob_dh);

    // 1 MB message
    let large_message = vec![42u8; 1_000_000];
    let encrypted = alice_ratchet.encrypt(&large_message, b"").unwrap();
    let decrypted = bob_ratchet.decrypt(&encrypted, b"").unwrap();

    assert_eq!(decrypted, large_message);
}

#[test]
fn test_empty_messages() {
    let alice_identity = IdentityKeyPair::generate(&mut OsRng);
    let bob_identity = IdentityKeyPair::generate(&mut OsRng);

    let mut bob_prekeys = PreKeyState::generate(&mut OsRng, &bob_identity).unwrap();
    let alice_x3dh = initiate(&mut OsRng, &alice_identity, &bob_prekeys.public_bundle()).unwrap();
    let bob_x3dh = respond(&mut bob_prekeys, &bob_identity, &alice_x3dh.initial_message).unwrap();

    let bob_dh = SecretKey::generate(&mut OsRng);
    let mut alice_ratchet =
        DoubleRatchet::init_sender(&mut OsRng, &alice_x3dh, bob_dh.public_key()).unwrap();
    let mut bob_ratchet = DoubleRatchet::init_receiver(bob_x3dh.shared_secret, bob_dh);

    let encrypted = alice_ratchet.encrypt(b"", b"").unwrap();
    let decrypted = bob_ratchet.decrypt(&encrypted, b"").unwrap();
    assert_eq!(&decrypted, b"");
}
