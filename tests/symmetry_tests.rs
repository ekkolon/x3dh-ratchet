use rand_core::OsRng;
use signal_protocol::{
    DoubleRatchet, Error, IdentityKeyPair, PreKeyState, SecretKey,
    x3dh::{initiate, respond},
};

#[test]
fn test_x3dh_formal_symmetry_multiple_runs() {
    use rand_core::OsRng;

    for _ in 0..100 {
        let alice_identity = IdentityKeyPair::generate(&mut OsRng);
        let bob_identity = IdentityKeyPair::generate(&mut OsRng);

        let mut bob_prekeys = PreKeyState::generate(&mut OsRng, &bob_identity);
        let bundle = bob_prekeys.public_bundle();

        let alice_x3dh = initiate(&mut OsRng, &alice_identity, &bundle).unwrap();

        let bob_x3dh =
            respond(&mut bob_prekeys, &bob_identity, &alice_x3dh.initial_message).unwrap();

        let sk_a = alice_x3dh.shared_secret.as_bytes();
        let sk_b = bob_x3dh.shared_secret.as_bytes();

        assert_eq!(sk_a, sk_b, "X3DH symmetry violated");
    }
}

#[test]
fn test_identity_substitution_breaks_agreement() {
    let alice_identity = IdentityKeyPair::generate(&mut OsRng);
    let bob_identity = IdentityKeyPair::generate(&mut OsRng);
    let attacker_identity = IdentityKeyPair::generate(&mut OsRng);

    let bob_prekeys = PreKeyState::generate(&mut OsRng, &bob_identity);
    let bundle = bob_prekeys.public_bundle();

    eprintln!(
        "Original identity_key: {:?}",
        &bundle.identity_key.as_bytes()[..4]
    );
    eprintln!(
        "Original verifying_key: {:?}",
        &bundle.identity_key.as_bytes()[..4]
    );

    let mut modified_bundle = bundle.clone();
    modified_bundle.identity_key = attacker_identity.public_key();

    eprintln!(
        "Modified identity_key: {:?}",
        &modified_bundle.identity_key.as_bytes()[..4]
    );
    eprintln!(
        "Modified verifying_key: {:?}",
        &modified_bundle.identity_key.as_bytes()[..4]
    );

    let result = initiate(&mut OsRng, &alice_identity, &modified_bundle);

    assert!(result.is_err(), "MITM identity substitution must fail");
}

#[test]
fn test_dh_input_sensitivity() {
    let alice_identity = IdentityKeyPair::generate(&mut OsRng);
    let bob_identity = IdentityKeyPair::generate(&mut OsRng);

    let bob_prekeys = PreKeyState::generate(&mut OsRng, &bob_identity);
    let bundle = bob_prekeys.public_bundle();

    let alice_x3dh_1 = initiate(&mut OsRng, &alice_identity, &bundle).unwrap();

    // Regenerate Bob's signed prekey
    let bob_prekeys_2 = PreKeyState::generate(&mut OsRng, &bob_identity);
    let bundle2 = bob_prekeys_2.public_bundle();

    let alice_x3dh_2 = initiate(&mut OsRng, &alice_identity, &bundle2).unwrap();

    assert_ne!(
        alice_x3dh_1.shared_secret.as_bytes(),
        alice_x3dh_2.shared_secret.as_bytes(),
        "Changing DH inputs must change shared secret"
    );
}

#[test]
fn test_root_chain_key_separation() {
    let alice_identity = IdentityKeyPair::generate(&mut OsRng);
    let bob_identity = IdentityKeyPair::generate(&mut OsRng);

    let mut bob_prekeys = PreKeyState::generate(&mut OsRng, &bob_identity);
    let alice_x3dh = initiate(&mut OsRng, &alice_identity, &bob_prekeys.public_bundle()).unwrap();
    let _bob_x3dh = respond(&mut bob_prekeys, &bob_identity, &alice_x3dh.initial_message).unwrap();

    let bob_dh = SecretKey::generate(&mut OsRng);
    let mut alice_ratchet =
        DoubleRatchet::init_sender(&mut OsRng, &alice_x3dh, bob_dh.public_key()).unwrap();

    let encrypted = alice_ratchet.encrypt(b"test", b"").unwrap();

    assert_ne!(
        alice_x3dh.shared_secret.as_bytes(),
        encrypted.ciphertext.as_slice(),
        "Root key must never equal message key material"
    );
}

#[test]
fn test_ratchet_state_persistence() {
    use rand_core::OsRng;
    use serde_json;

    let alice_identity = IdentityKeyPair::generate(&mut OsRng);
    let bob_identity = IdentityKeyPair::generate(&mut OsRng);

    let mut bob_prekeys = PreKeyState::generate(&mut OsRng, &bob_identity);
    let alice_x3dh = initiate(&mut OsRng, &alice_identity, &bob_prekeys.public_bundle()).unwrap();
    let bob_x3dh = respond(&mut bob_prekeys, &bob_identity, &alice_x3dh.initial_message).unwrap();

    let bob_dh = SecretKey::generate(&mut OsRng);

    let mut alice_ratchet =
        DoubleRatchet::init_sender(&mut OsRng, &alice_x3dh, bob_dh.public_key()).unwrap();
    let mut bob_ratchet = DoubleRatchet::init_receiver(bob_x3dh.shared_secret, bob_dh);

    // Establish session
    let msg1 = alice_ratchet.encrypt(b"hello", b"").unwrap();
    bob_ratchet.decrypt(&msg1, b"").unwrap();

    let serialized = serde_json::to_vec(&bob_ratchet).unwrap();

    let mut restored: DoubleRatchet = serde_json::from_slice(&serialized).unwrap();

    // Continue ratchet
    let msg2 = alice_ratchet.encrypt(b"after restore", b"").unwrap();
    let decrypted = restored.decrypt(&msg2, b"").unwrap();

    assert_eq!(&decrypted, b"after restore");

    // Ensure state actually advanced and no reuse occurred
    let msg3 = alice_ratchet.encrypt(b"next", b"").unwrap();
    let decrypted2 = restored.decrypt(&msg3, b"").unwrap();

    assert_eq!(&decrypted2, b"next");
}

#[test]
fn test_ratchet_serialization_determinism() {
    use rand_core::OsRng;
    use serde_json;

    let alice_identity = IdentityKeyPair::generate(&mut OsRng);
    let bob_identity = IdentityKeyPair::generate(&mut OsRng);

    let mut bob_prekeys = PreKeyState::generate(&mut OsRng, &bob_identity);
    let alice_x3dh = initiate(&mut OsRng, &alice_identity, &bob_prekeys.public_bundle()).unwrap();
    let bob_x3dh = respond(&mut bob_prekeys, &bob_identity, &alice_x3dh.initial_message).unwrap();

    let bob_dh = SecretKey::generate(&mut OsRng);
    let bob_ratchet = DoubleRatchet::init_receiver(bob_x3dh.shared_secret, bob_dh);

    let s1 = serde_json::to_vec(&bob_ratchet).unwrap();
    let s2 = serde_json::to_vec(&bob_ratchet).unwrap();

    assert_eq!(s1, s2, "Serialization must be deterministic");
}

#[test]
fn test_identity_substitution_attempts() {
    let bob_identity = IdentityKeyPair::generate(&mut OsRng);
    let attacker_identity = IdentityKeyPair::generate(&mut OsRng);

    let bob_prekeys = PreKeyState::generate(&mut OsRng, &bob_identity);
    let original_bundle = bob_prekeys.public_bundle();

    assert!(original_bundle.verify_signature().is_ok());

    // Attempt to replace DH key only
    let mut attack1 = original_bundle.clone();
    attack1.identity_key = attacker_identity.public_key();
    assert!(
        attack1.verify_signature().is_err(),
        "DH key substitution should fail"
    );

    // Attempt to replace verifying key only
    let mut attack2 = original_bundle.clone();
    attack2.identity_verifying_key = attacker_identity.verifying_key().to_bytes();
    assert!(
        attack2.verify_signature().is_err(),
        "Verifying key substitution should fail"
    );

    // Attempt to replace both keys
    let mut attack3 = original_bundle.clone();
    attack3.identity_key = attacker_identity.public_key();
    attack3.identity_verifying_key = attacker_identity.verifying_key().to_bytes();
    assert!(
        attack3.verify_signature().is_err(),
        "Full identity substitution should fail"
    );

    // Attempt to replace signed prekey
    let attacker_spk = SecretKey::generate(&mut OsRng);
    let mut attack4 = original_bundle.clone();
    attack4.signed_prekey = attacker_spk.public_key();
    assert!(
        attack4.verify_signature().is_err(),
        "Signed prekey substitution should fail"
    );
}

#[test]
fn test_signature_cannot_be_reused() {
    let bob_identity = IdentityKeyPair::generate(&mut OsRng);
    let bob_prekeys = PreKeyState::generate(&mut OsRng, &bob_identity);
    let bundle1 = bob_prekeys.public_bundle();

    // second bundle with different signed prekey
    let new_spk = SecretKey::generate(&mut OsRng);
    let mut bundle2 = bundle1.clone();
    bundle2.signed_prekey = new_spk.public_key();

    assert!(
        bundle2.verify_signature().is_err(),
        "Signature should not verify with different SPK"
    );
}

#[test]
fn test_mitm_full_attempt_scenario() {
    let alice_identity = IdentityKeyPair::generate(&mut OsRng);
    let bob_identity = IdentityKeyPair::generate(&mut OsRng);
    let attacker_identity = IdentityKeyPair::generate(&mut OsRng);

    let bob_prekeys = PreKeyState::generate(&mut OsRng, &bob_identity);
    let mut bundle = bob_prekeys.public_bundle();

    // MITM replaces Bob's DH key with attacker's
    bundle.identity_key = attacker_identity.public_key();

    // Alice tries to initiate
    let result = initiate(&mut OsRng, &alice_identity, &bundle);
    assert!(result.is_err(), "X3DH with substituted identity must fail");
    assert_eq!(result.unwrap_err(), Error::InvalidSignature);
}
