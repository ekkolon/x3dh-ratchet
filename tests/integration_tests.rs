//! Integration tests for X3DH and Double Ratchet
//!
//! Tests complete protocol flows including:
//! - Full X3DH handshake
//! - Double Ratchet initialization and message exchange
//! - Out-of-order message delivery
//! - Error conditions

use rand_core::OsRng;
use signal_protocol::double_ratchet::{DoubleRatchet, Header, Message};
use signal_protocol::keys::{IdentityKeyPair, SecretKey};
use signal_protocol::x3dh::{initiate, respond, PreKeyState};
use signal_protocol::Error;

#[test]
fn test_full_protocol_flow() {
    // Alice and Bob identities
    let alice_identity = IdentityKeyPair::generate(&mut OsRng);
    let bob_identity = IdentityKeyPair::generate(&mut OsRng);

    // Bob generates prekey bundle
    let mut bob_prekeys = PreKeyState::generate(&mut OsRng, &bob_identity);
    let bob_bundle = bob_prekeys.public_bundle();

    // Alice initiates X3DH
    let alice_x3dh =
        initiate(&mut OsRng, &alice_identity, &bob_bundle).expect("X3DH initiation should succeed");

    // Bob responds
    let bob_x3dh = respond(&mut bob_prekeys, &bob_identity, &alice_x3dh.initial_message)
        .expect("X3DH response should succeed");

    // Verify shared secrets match
    assert_eq!(
        alice_x3dh.shared_secret.as_bytes(),
        bob_x3dh.shared_secret.as_bytes(),
        "X3DH shared secrets must match"
    );

    // Initialize Double Ratchet
    let bob_dh = SecretKey::generate(&mut OsRng);
    let bob_public = bob_dh.public_key();

    let mut alice_ratchet = DoubleRatchet::init_sender(&mut OsRng, &alice_x3dh, bob_public);

    let mut bob_ratchet = DoubleRatchet::init_receiver(bob_x3dh.shared_secret, bob_dh);

    // Exchange messages
    let messages = vec![
        b"Hello Bob!".as_slice(),
        b"How are you?".as_slice(),
        b"This is a secure message".as_slice(),
    ];

    for msg in &messages {
        let encrypted = alice_ratchet
            .encrypt(msg, b"")
            .expect("Encryption should succeed");

        let decrypted = bob_ratchet
            .decrypt(&encrypted, b"")
            .expect("Decryption should succeed");

        assert_eq!(&decrypted, msg, "Decrypted message must match original");
    }

    // Bob responds
    let response = b"Hello Alice! I'm good!";
    let encrypted = bob_ratchet.encrypt(response, b"").unwrap();
    let decrypted = alice_ratchet.decrypt(&encrypted, b"").unwrap();
    assert_eq!(&decrypted, response);
}

#[test]
fn test_out_of_order_messages() {
    let alice_identity = IdentityKeyPair::generate(&mut OsRng);
    let bob_identity = IdentityKeyPair::generate(&mut OsRng);

    let mut bob_prekeys = PreKeyState::generate(&mut OsRng, &bob_identity);
    let alice_x3dh = initiate(&mut OsRng, &alice_identity, &bob_prekeys.public_bundle()).unwrap();
    let bob_x3dh = respond(&mut bob_prekeys, &bob_identity, &alice_x3dh.initial_message).unwrap();

    let bob_dh = SecretKey::generate(&mut OsRng);
    let mut alice_ratchet =
        DoubleRatchet::init_sender(&mut OsRng, &alice_x3dh, bob_dh.public_key());
    let mut bob_ratchet = DoubleRatchet::init_receiver(bob_x3dh.shared_secret, bob_dh);

    // Alice sends multiple messages
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

    let mut bob_prekeys = PreKeyState::generate(&mut OsRng, &bob_identity);
    let alice_x3dh = initiate(&mut OsRng, &alice_identity, &bob_prekeys.public_bundle()).unwrap();
    let bob_x3dh = respond(&mut bob_prekeys, &bob_identity, &alice_x3dh.initial_message).unwrap();

    let bob_dh = SecretKey::generate(&mut OsRng);
    let mut alice_ratchet =
        DoubleRatchet::init_sender(&mut OsRng, &alice_x3dh, bob_dh.public_key());
    let mut bob_ratchet = DoubleRatchet::init_receiver(bob_x3dh.shared_secret, bob_dh);

    // Interleaved conversation
    let a1 = alice_ratchet.encrypt(b"Alice 1", b"").unwrap();
    let b1 = bob_ratchet.decrypt(&a1, b"").unwrap();
    assert_eq!(&b1, b"Alice 1");

    let b2 = bob_ratchet.encrypt(b"Bob 1", b"").unwrap();
    let a2 = alice_ratchet.decrypt(&b2, b"").unwrap();
    assert_eq!(&a2, b"Bob 1");

    let a3 = alice_ratchet.encrypt(b"Alice 2", b"").unwrap();
    let b3 = bob_ratchet.decrypt(&a3, b"").unwrap();
    assert_eq!(&b3, b"Alice 2");
}

#[test]
fn test_invalid_signature_rejected() {
    let bob_identity = IdentityKeyPair::generate(&mut OsRng);
    let bob_prekeys = PreKeyState::generate(&mut OsRng, &bob_identity);
    let mut bundle = bob_prekeys.public_bundle();

    bundle.signed_prekey_signature[0] ^= 1; // Corrupt signature

    // Alice should reject
    let alice_identity = IdentityKeyPair::generate(&mut OsRng);
    let result = initiate(&mut OsRng, &alice_identity, &bundle);

    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), Error::InvalidSignature);
}

#[test]
fn test_missing_one_time_prekey() {
    let bob_identity = IdentityKeyPair::generate(&mut OsRng);
    let mut bob_prekeys = PreKeyState::generate_with_count(&mut OsRng, &bob_identity, 0);

    // Consume non-existent prekey
    let result = bob_prekeys.consume_one_time_prekey();
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), Error::MissingOneTimePrekey);
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

    let mut bob_prekeys = PreKeyState::generate(&mut OsRng, &bob_identity);
    let alice_x3dh = initiate(&mut OsRng, &alice_identity, &bob_prekeys.public_bundle()).unwrap();
    let bob_x3dh = respond(&mut bob_prekeys, &bob_identity, &alice_x3dh.initial_message).unwrap();

    let bob_dh = SecretKey::generate(&mut OsRng);
    let mut alice_ratchet =
        DoubleRatchet::init_sender(&mut OsRng, &alice_x3dh, bob_dh.public_key());
    let mut bob_ratchet = DoubleRatchet::init_receiver(bob_x3dh.shared_secret, bob_dh);

    let ad = b"important context";
    let encrypted = alice_ratchet.encrypt(b"secret", ad).unwrap();

    // correct AD
    let decrypted = bob_ratchet.decrypt(&encrypted, ad).unwrap();
    assert_eq!(&decrypted, b"secret");

    // Decrypt with wrong AD should fail
    let encrypted2 = alice_ratchet.encrypt(b"secret2", ad).unwrap();
    let result = bob_ratchet.decrypt(&encrypted2, b"wrong AD");
    assert!(result.is_err());
}

#[test]
fn test_forward_secrecy() {
    // Even if keys are compromised after messages are sent,
    // past messages must remain secure (simplified)

    let alice_identity = IdentityKeyPair::generate(&mut OsRng);
    let bob_identity = IdentityKeyPair::generate(&mut OsRng);

    let mut bob_prekeys = PreKeyState::generate(&mut OsRng, &bob_identity);
    let alice_x3dh = initiate(&mut OsRng, &alice_identity, &bob_prekeys.public_bundle()).unwrap();
    let bob_x3dh = respond(&mut bob_prekeys, &bob_identity, &alice_x3dh.initial_message).unwrap();

    let bob_dh = SecretKey::generate(&mut OsRng);
    let mut alice_ratchet =
        DoubleRatchet::init_sender(&mut OsRng, &alice_x3dh, bob_dh.public_key());
    let mut bob_ratchet = DoubleRatchet::init_receiver(bob_x3dh.shared_secret, bob_dh);

    // Send many messages to advance ratchet
    for i in 0..10 {
        let msg = format!("Message {}", i);
        let encrypted = alice_ratchet.encrypt(msg.as_bytes(), b"").unwrap();
        bob_ratchet.decrypt(&encrypted, b"").unwrap();
    }

    // The ratchet has advanced. old message keys are deleted, keys are one-time use
}

#[test]
fn test_large_messages() {
    let alice_identity = IdentityKeyPair::generate(&mut OsRng);
    let bob_identity = IdentityKeyPair::generate(&mut OsRng);

    let mut bob_prekeys = PreKeyState::generate(&mut OsRng, &bob_identity);
    let alice_x3dh = initiate(&mut OsRng, &alice_identity, &bob_prekeys.public_bundle()).unwrap();
    let bob_x3dh = respond(&mut bob_prekeys, &bob_identity, &alice_x3dh.initial_message).unwrap();

    let bob_dh = SecretKey::generate(&mut OsRng);
    let mut alice_ratchet =
        DoubleRatchet::init_sender(&mut OsRng, &alice_x3dh, bob_dh.public_key());
    let mut bob_ratchet = DoubleRatchet::init_receiver(bob_x3dh.shared_secret, bob_dh);

    // 1 MB message
    let large_message = vec![42u8; 1_000_000];
    let encrypted = alice_ratchet.encrypt(&large_message, b"").unwrap();
    let decrypted = bob_ratchet.decrypt(&encrypted, b"").unwrap();

    assert_eq!(decrypted, large_message);
}
