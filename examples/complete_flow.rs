//! Complete example of X3DH + Double Ratchet usage
//!
//! This demonstrates a simple, yet realistic scenario where two parties establish
//! a secure channel and exchange messages.

use rand_core::OsRng;
use signal_protocol::Result;
use signal_protocol::double_ratchet::DoubleRatchet;
use signal_protocol::keys::{IdentityKeyPair, SecretKey};
use signal_protocol::x3dh::{PreKeyState, initiate, respond};

fn main() -> Result<()> {
    println!("=== Signal Protocol Complete Example ===\n");

    // Both parties generate identity keys
    println!("1. Generating identity keys...");
    let alice_identity = IdentityKeyPair::generate(&mut OsRng);
    let bob_identity = IdentityKeyPair::generate(&mut OsRng);
    println!("   ✓ Alice and Bob have identity keys\n");

    // Bob publishes prekey bundle
    println!("2. Bob generates and publishes prekey bundle...");
    let mut bob_prekeys = PreKeyState::generate(&mut OsRng, &bob_identity).unwrap();
    let bob_bundle = bob_prekeys.public_bundle();
    println!("   ✓ Bob's bundle ready for distribution");
    println!("   - Identity key: {:?}", bob_bundle.identity_key);
    println!("   - Signed prekey: {:?}", bob_bundle.signed_prekey);
    println!(
        "   - One-time prekeys: {}\n",
        if bob_bundle.one_time_prekey.is_some() {
            "available"
        } else {
            "none"
        }
    );

    // Alice performs X3DH handshake
    println!("3. Alice initiates X3DH handshake...");
    let alice_x3dh = initiate(&mut OsRng, &alice_identity, &bob_bundle)?;
    println!("   ✓ Alice computed shared secret");
    println!("   ✓ Initial message created\n");

    // Bob responds to handshake
    println!("4. Bob responds to handshake...");
    let bob_x3dh = respond(&mut bob_prekeys, &bob_identity, &alice_x3dh.initial_message)?;
    println!("   ✓ Bob computed shared secret");

    // Verify shared secrets match
    assert_eq!(
        alice_x3dh.shared_secret.as_bytes(),
        bob_x3dh.shared_secret.as_bytes(),
        "Shared secrets must match!"
    );
    println!("   ✓ Shared secrets verified identical\n");

    // Initialize Double Ratchet for messaging
    println!("5. Initializing Double Ratchet...");

    // Bob needs a DH keypair for ratchet
    let bob_ratchet_dh = SecretKey::generate(&mut OsRng);
    let bob_ratchet_public = bob_ratchet_dh.public_key();

    let mut alice_ratchet =
        DoubleRatchet::init_sender(&mut OsRng, &alice_x3dh, bob_ratchet_public)?;

    let mut bob_ratchet = DoubleRatchet::init_receiver(bob_x3dh.shared_secret, bob_ratchet_dh);
    println!("   ✓ Alice and Bob have initialized ratchets\n");

    // Exchange encrypted messages
    println!("6. Exchanging encrypted messages...\n");

    // Alice sends first message
    let msg1 = b"Hello Bob! This is Alice.";
    println!("   Alice → Bob: {:?}", std::str::from_utf8(msg1).unwrap());
    let encrypted1 = alice_ratchet.encrypt(msg1, b"")?;
    println!("   Encrypted size: {} bytes", encrypted1.to_bytes().len());

    let decrypted1 = bob_ratchet.decrypt(&encrypted1, b"")?;
    println!(
        "   Bob received: {:?}\n",
        std::str::from_utf8(&decrypted1).unwrap()
    );
    assert_eq!(&decrypted1, msg1);

    // Bob replies
    let msg2 = b"Hi Alice! How are you?";
    println!("   Bob → Alice: {:?}", std::str::from_utf8(msg2).unwrap());
    let encrypted2 = bob_ratchet.encrypt(msg2, b"")?;
    println!("   Encrypted size: {} bytes", encrypted2.to_bytes().len());

    let decrypted2 = alice_ratchet.decrypt(&encrypted2, b"")?;
    println!(
        "   Alice received: {:?}\n",
        std::str::from_utf8(&decrypted2).unwrap()
    );
    assert_eq!(&decrypted2, msg2);

    // Alice sends multiple messages
    let messages = [b"I'm doing great!".as_slice(),
        b"How about you?".as_slice(),
        b"Want to meet up later?".as_slice()];

    for (i, msg) in messages.iter().enumerate() {
        println!(
            "   Alice → Bob ({}): {:?}",
            i + 1,
            std::str::from_utf8(msg).unwrap()
        );
        let encrypted = alice_ratchet.encrypt(msg, b"")?;
        let decrypted = bob_ratchet.decrypt(&encrypted, b"")?;
        assert_eq!(&decrypted, msg);
    }

    println!("\n   ✓ All messages successfully exchanged\n");

    // Demonstrate out-of-order delivery
    println!("7. Testing out-of-order message delivery...\n");

    // Alice sends 3 messages
    let m1 = alice_ratchet.encrypt(b"Message 1", b"")?;
    let m2 = alice_ratchet.encrypt(b"Message 2", b"")?;
    let m3 = alice_ratchet.encrypt(b"Message 3", b"")?;

    // Bob receives them out of order: 3, 1, 2
    println!("   Messages sent in order: 1, 2, 3");
    println!("   Messages received in order: 3, 1, 2");

    let d3 = bob_ratchet.decrypt(&m3, b"")?;
    println!(
        "   ✓ Decrypted message 3: {:?}",
        std::str::from_utf8(&d3).unwrap()
    );

    let d1 = bob_ratchet.decrypt(&m1, b"")?;
    println!(
        "   ✓ Decrypted message 1: {:?}",
        std::str::from_utf8(&d1).unwrap()
    );

    let d2 = bob_ratchet.decrypt(&m2, b"")?;
    println!(
        "   ✓ Decrypted message 2: {:?}",
        std::str::from_utf8(&d2).unwrap()
    );

    println!("\n   ✓ Out-of-order delivery works correctly\n");

    // Security properties
    println!("=== Security Properties ===\n");
    println!("✓ Forward Secrecy: Old message keys deleted after use");
    println!("✓ Post-Compromise Security: New DH ratchet steps provide fresh secrets");
    println!("✓ Deniable Authentication: No proof of who sent messages");
    println!("✓ Asynchronous: Alice could send without Bob being online");
    println!("\n=== Example Complete ===");

    Ok(())
}
