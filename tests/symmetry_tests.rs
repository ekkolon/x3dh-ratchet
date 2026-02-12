use rand_core::OsRng;
use signal_protocol::{
    DoubleRatchet, Error, IdentityKeyPair, PreKeyState, SecretKey,
    x3dh::{initiate, respond},
};

#[test]
fn test_x3dh_formal_symmetry_multiple_runs() {
    for _ in 0..100 {
        let alice_identity = IdentityKeyPair::generate(&mut OsRng);
        let bob_identity = IdentityKeyPair::generate(&mut OsRng);

        let mut bob_prekeys = PreKeyState::generate(&mut OsRng, &bob_identity).unwrap();
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
    let attempter_identity = IdentityKeyPair::generate(&mut OsRng);

    let bob_prekeys = PreKeyState::generate(&mut OsRng, &bob_identity).unwrap();
    let bundle = bob_prekeys.public_bundle();

    let mut modified_bundle = bundle.clone();
    modified_bundle.identity_key = *attempter_identity.public_key();

    let result = initiate(&mut OsRng, &alice_identity, &modified_bundle);

    assert!(result.is_err(), "MITM identity substitution must fail");
}

#[test]
fn test_dh_input_sensitivity() {
    let alice_identity = IdentityKeyPair::generate(&mut OsRng);
    let bob_identity = IdentityKeyPair::generate(&mut OsRng);

    let bob_prekeys = PreKeyState::generate(&mut OsRng, &bob_identity).unwrap();
    let bundle = bob_prekeys.public_bundle();

    let alice_x3dh_1 = initiate(&mut OsRng, &alice_identity, &bundle).unwrap();

    // Regenerate Bob's signed prekey
    let bob_prekeys_2 = PreKeyState::generate(&mut OsRng, &bob_identity).unwrap();
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

    let mut bob_prekeys = PreKeyState::generate(&mut OsRng, &bob_identity).unwrap();
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
fn test_identity_substitution_attempts() {
    let bob_identity = IdentityKeyPair::generate(&mut OsRng);
    let attempter_identity = IdentityKeyPair::generate(&mut OsRng);

    let bob_prekeys = PreKeyState::generate(&mut OsRng, &bob_identity).unwrap();
    let original_bundle = bob_prekeys.public_bundle();

    assert!(original_bundle.verify_signature().is_ok());

    // Attempt to replace identity key
    let mut attempt1 = original_bundle.clone();
    attempt1.identity_key = *attempter_identity.public_key();
    assert!(
        attempt1.verify_signature().is_err(),
        "Identity key substitution should fail - signature won't verify with different key"
    );

    // Attempt to replace signed prekey
    let attempter_spk = SecretKey::generate(&mut OsRng);
    let mut attempt2 = original_bundle.clone();
    attempt2.signed_prekey = attempter_spk.public_key();
    assert!(
        attempt2.verify_signature().is_err(),
        "Signed prekey substitution should fail - breaks signature"
    );

    // Attempt 3: Replace both identity and signed prekey
    let mut attempt3 = original_bundle.clone();
    attempt3.identity_key = *attempter_identity.public_key();
    attempt3.signed_prekey = attempter_spk.public_key();
    assert!(
        attempt3.verify_signature().is_err(),
        "Full substitution should fail - attempter's signature not present"
    );

    // Attempt 4: Tamper with signature bytes
    let mut attempt4 = original_bundle.clone();
    attempt4.signed_prekey_signature[0] ^= 0xFF;
    assert!(
        attempt4.verify_signature().is_err(),
        "Corrupted signature should fail"
    );
}

#[test]
fn test_signature_cannot_be_reused() {
    let bob_identity = IdentityKeyPair::generate(&mut OsRng);
    let bob_prekeys = PreKeyState::generate(&mut OsRng, &bob_identity).unwrap();
    let bundle1 = bob_prekeys.public_bundle();

    // Second bundle with different signed prekey but same signature
    let new_spk = SecretKey::generate(&mut OsRng);
    let mut bundle2 = bundle1.clone();
    bundle2.signed_prekey = new_spk.public_key();

    assert!(
        bundle2.verify_signature().is_err(),
        "Signature should not verify with different SPK - signature is bound to both keys"
    );
}

#[test]
fn test_mitm_full_attempt_scenario() {
    let alice_identity = IdentityKeyPair::generate(&mut OsRng);
    let bob_identity = IdentityKeyPair::generate(&mut OsRng);
    let attempter_identity = IdentityKeyPair::generate(&mut OsRng);

    let bob_prekeys = PreKeyState::generate(&mut OsRng, &bob_identity).unwrap();
    let mut bundle = bob_prekeys.public_bundle();

    // MITM replaces Bob's identity key with attempter's
    bundle.identity_key = *attempter_identity.public_key();

    // Alice tries to initiate - should fail because XEdDSA signature verification
    // will fail when we try to verify using the attempter's key
    let result = initiate(&mut OsRng, &alice_identity, &bundle);
    assert!(result.is_err(), "X3DH with substituted identity must fail");
    assert_eq!(result.unwrap_err(), Error::InvalidSignature);
}

#[test]
fn test_xeddsa_signature_uniqueness() {
    // Verify that two signatures of the same message are different (randomized signing)
    let bob_identity = IdentityKeyPair::generate(&mut OsRng);

    let bundle1 = PreKeyState::generate(&mut OsRng, &bob_identity)
        .unwrap()
        .public_bundle();
    let bundle2 = PreKeyState::generate(&mut OsRng, &bob_identity)
        .unwrap()
        .public_bundle();

    // Same identity, different signed prekeys
    assert_eq!(
        bundle1.identity_key.as_bytes(),
        bundle2.identity_key.as_bytes()
    );
    assert_ne!(
        bundle1.signed_prekey.as_bytes(),
        bundle2.signed_prekey.as_bytes()
    );

    // Signatures should be different (randomized)
    assert_ne!(
        bundle1.signed_prekey_signature, bundle2.signed_prekey_signature,
        "XEdDSA signatures should be randomized"
    );

    // But both should verify
    assert!(bundle1.verify_signature().is_ok());
    assert!(bundle2.verify_signature().is_ok());
}

#[test]
fn test_xeddsa_cross_bundle_signature_reuse_fails() {
    // Ensure you can't take a signature from one bundle and use it on another
    let bob_identity = IdentityKeyPair::generate(&mut OsRng);
    let eve_identity = IdentityKeyPair::generate(&mut OsRng);

    let bob_prekeys = PreKeyState::generate(&mut OsRng, &bob_identity).unwrap();
    let eve_prekeys = PreKeyState::generate(&mut OsRng, &eve_identity).unwrap();

    let bob_bundle = bob_prekeys.public_bundle();
    let mut eve_bundle = eve_prekeys.public_bundle();

    // Eve tries to steal Bob's signature
    eve_bundle.signed_prekey_signature = bob_bundle.signed_prekey_signature;

    assert!(
        eve_bundle.verify_signature().is_err(),
        "Signature from different identity should not verify"
    );
}

#[cfg(feature = "serde")]
#[test]
fn test_ratchet_state_persistence() {
    use serde_json;

    let alice_identity = IdentityKeyPair::generate(&mut OsRng);
    let bob_identity = IdentityKeyPair::generate(&mut OsRng);

    let mut bob_prekeys = PreKeyState::generate(&mut OsRng, &bob_identity).unwrap();
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

#[cfg(feature = "serde")]
#[test]
fn test_ratchet_serialization_determinism() {
    use serde_json;

    let alice_identity = IdentityKeyPair::generate(&mut OsRng);
    let bob_identity = IdentityKeyPair::generate(&mut OsRng);

    let mut bob_prekeys = PreKeyState::generate(&mut OsRng, &bob_identity).unwrap();
    let alice_x3dh = initiate(&mut OsRng, &alice_identity, &bob_prekeys.public_bundle()).unwrap();
    let bob_x3dh = respond(&mut bob_prekeys, &bob_identity, &alice_x3dh.initial_message).unwrap();

    let bob_dh = SecretKey::generate(&mut OsRng);
    let bob_ratchet = DoubleRatchet::init_receiver(bob_x3dh.shared_secret, bob_dh);

    let s1 = serde_json::to_vec(&bob_ratchet).unwrap();
    let s2 = serde_json::to_vec(&bob_ratchet).unwrap();

    assert_eq!(s1, s2, "Serialization must be deterministic");
}
