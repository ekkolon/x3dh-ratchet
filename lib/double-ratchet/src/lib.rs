//! Double Ratchet protocol for forward-secure bidirectional communication.
//!
//! Implements the Signal protocol's Double Ratchet providing:
//! - Forward secrecy: past messages remain secure if current keys are compromised
//! - Post-compromise security: future messages become secure after compromise
//! - Out-of-order message delivery via skipped message key storage
//!
//! # Protocol Overview
//!
//! The Double Ratchet combines two ratcheting mechanisms:
//!
//! 1. **Symmetric-key ratchet**: Advances chain keys for each message using KDF
//! 2. **DH ratchet**: Performs new Diffie-Hellman exchanges to refresh root key
//!
//! # State Management
//!
//! Each party maintains:
//! - Root key `RK`: updated on DH ratchet steps
//! - Sending chain key `CK_s`: updated per sent message
//! - Receiving chain key `CK_r`: updated per received message  
//! - DH keypair: rotated on DH ratchet steps

mod error;
mod message;
mod kdf;

use chacha20poly1305::aead::OsRng;
pub use error::{Error, Result};
use locus_crypto::{
    PublicKey, SecretKey, SymmetricKey, decrypt, encrypt, generate_nonce, kdf_chain, kdf_root,
};
use rand_core::CryptoRngCore;
use std::collections::HashMap;
use zeroize::Zeroize;

pub use message::{Message, MessageHeader};

const MAX_SKIP: usize = 1000;

/// Double Ratchet session state.
///
/// Maintains cryptographic state for bidirectional ratcheting encryption.
/// All sensitive key material is automatically zeroized on drop.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DoubleRatchet {
    root_key: SymmetricKey,
    send_chain_key: Option<SymmetricKey>,
    recv_chain_key: Option<SymmetricKey>,
    dh_send: SecretKey,
    dh_recv: Option<PublicKey>,
    send_count: u32,
    recv_count: u32,
    prev_chain_length: u32,
    skipped_message_keys: HashMap<(PublicKey, u32), SymmetricKey>,
}

impl DoubleRatchet {
    /// Initializes Double Ratchet as the initiating party (sender).
    ///
    /// Called by Alice after completing X3DH key agreement. Performs the initial
    /// DH ratchet step using the responder's DH public key.
    ///
    /// # Arguments
    /// * `rng` - Cryptographically secure random number generator
    /// * `x3dh_result` - Output from X3DH initiation
    /// * `remote_dh_public` - Responder's initial DH public key
    pub fn new_sender<R: CryptoRngCore>(
        rng: &mut R,
        shared_secret_x3dh: &SymmetricKey,
        remote_dh_public: PublicKey,
    ) -> Result<Self> {
        let dh_send = SecretKey::generate(rng);

        let dh_output = dh_send.diffie_hellman(&remote_dh_public);
        let (new_root, send_chain_key) = kdf_root(shared_secret_x3dh, &dh_output)?;

        Ok(Self {
            root_key: new_root,
            send_chain_key: Some(send_chain_key),
            recv_chain_key: None,
            dh_send,
            dh_recv: Some(remote_dh_public),
            send_count: 0,
            recv_count: 0,
            prev_chain_length: 0,
            skipped_message_keys: HashMap::new(),
        })
    }

    /// Initializes Double Ratchet as the responding party (receiver).
    ///
    /// Called by Bob after completing X3DH key agreement. Does not perform
    /// initial DH ratchet; waits for first message from initiator.
    ///
    /// # Arguments
    /// * `shared_secret` - Output from X3DH response
    /// * `local_dh_keypair` - Bob's DH keypair for receiving first message
    #[must_use]
    pub fn new_receiver(shared_secret: SymmetricKey, local_dh_keypair: SecretKey) -> Self {
        Self {
            root_key: shared_secret,
            send_chain_key: None,
            recv_chain_key: None,
            dh_send: local_dh_keypair,
            dh_recv: None,
            send_count: 0,
            recv_count: 0,
            prev_chain_length: 0,
            skipped_message_keys: HashMap::new(),
        }
    }
}

impl DoubleRatchet {
    /// Encrypts a message using the current sending chain.
    ///
    /// Advances the sending chain key: `(CK_s', MK) = KDF_CK(CK_s)`.
    /// The message key `MK` is used for AEAD encryption with the header
    /// included in associated data.
    ///
    /// # Arguments
    /// * `plaintext` - Message to encrypt
    /// * `associated_data` - Additional authenticated data (can be empty)
    ///
    /// # Errors
    /// Returns error if sending chain is not initialized (receiver-only state).
    pub fn encrypt(&mut self, plaintext: &[u8], associated_data: &[u8]) -> Result<Message> {
        if self.send_chain_key.is_none() {
            return Err(Error::InvalidSessionState);
        }

        let chain_key = self
            .send_chain_key
            .as_ref()
            .ok_or(Error::InvalidSessionState)?;

        let (new_chain_key, message_key) = kdf_chain(chain_key);
        self.send_chain_key = Some(new_chain_key);

        let header = MessageHeader {
            dh_public: self.dh_send.public_key(),
            previous_chain_length: self.prev_chain_length,
            message_number: self.send_count,
        };

        let nonce = generate_nonce(self.send_count, self.dh_send.public_key().as_bytes());

        let mut ad = Vec::from(associated_data);
        ad.extend_from_slice(&header.to_bytes());

        let ciphertext = encrypt(&message_key, &nonce, plaintext, &ad)?;

        self.send_count += 1;

        Ok(Message { header, ciphertext })
    }

    /// Decrypt a received message.
    ///
    /// Handles out-of-order delivery by checking skipped message keys.
    /// Performs DH ratchet step if header contains new DH public key.
    /// Advances receiving chain and stores skipped keys for missing messages.
    ///
    /// # Arguments
    /// * `message` - Received encrypted message
    /// * `associated_data` - Additional authenticated data (must match encryption)
    ///
    /// # Errors
    /// Returns error if:
    /// - Message authentication fails
    /// - Message is too far out of order (exceeds `MAX_SKIP`)
    /// - DH ratchet step fails
    pub fn decrypt(&mut self, message: &Message, associated_data: &[u8]) -> Result<Vec<u8>> {
        let key = (message.header.dh_public, message.header.message_number);
        if let Some(message_key) = self.skipped_message_keys.remove(&key) {
            return self.try_decrypt(message, &message_key, associated_data);
        }

        if Some(message.header.dh_public) != self.dh_recv {
            self.skip_message_keys_old_chain(message.header.previous_chain_length)?;
            self.dh_ratchet(&message.header)?;
        }

        self.skip_message_keys(message.header.message_number)?;

        let chain_key = self.recv_chain_key.as_ref().ok_or(Error::CryptoError)?;
        let (new_chain_key, message_key) = kdf_chain(chain_key);
        self.recv_chain_key = Some(new_chain_key);
        self.recv_count += 1;

        self.try_decrypt(message, &message_key, associated_data)
    }

    fn dh_ratchet(&mut self, header: &MessageHeader) -> Result<()> {
        self.prev_chain_length = self.send_count;
        self.send_count = 0;
        self.recv_count = 0;

        let dh_output = self.dh_send.diffie_hellman(&header.dh_public);
        let (new_root, recv_chain_key) = kdf_root(&self.root_key, &dh_output)?;
        self.root_key = new_root;
        self.recv_chain_key = Some(recv_chain_key);
        self.dh_recv = Some(header.dh_public);

        self.dh_send = SecretKey::generate(&mut OsRng);

        let dh_output = self.dh_send.diffie_hellman(&header.dh_public);
        let (new_root, send_chain_key) = kdf_root(&self.root_key, &dh_output)?;
        self.root_key = new_root;
        self.send_chain_key = Some(send_chain_key);
        Ok(())
    }

    fn skip_message_keys(&mut self, until: u32) -> Result<()> {
        if until < self.recv_count {
            return Err(Error::OutOfOrderMessage);
        }

        let to_skip = until - self.recv_count;
        if to_skip as usize > MAX_SKIP {
            return Err(Error::TooManySkippedMessages);
        }

        let chain_key = self.recv_chain_key.as_ref().ok_or(Error::CryptoError)?;
        let mut current_key = chain_key.clone();

        for i in self.recv_count..until {
            let (new_chain_key, message_key) = kdf_chain(&current_key);

            let dh_public = self.dh_recv.ok_or(Error::CryptoError)?;
            self.skipped_message_keys
                .insert((dh_public, i), message_key);

            current_key = new_chain_key;
        }

        self.recv_chain_key = Some(current_key);
        self.recv_count = until;

        Ok(())
    }

    /// Skip message keys from the OLD receiving chain before DH ratchet.
    ///
    /// When receiving a message that triggers a DH ratchet, we must store
    /// all remaining keys from the previous chain (from `recv_count` to
    /// `previous_chain_length`) to handle out-of-order delivery.
    fn skip_message_keys_old_chain(&mut self, until: u32) -> Result<()> {
        if until < self.recv_count {
            // Previous chain length is less than current count - normal case when
            // sender performed DH ratchet before we received all their messages
            return Ok(());
        }

        let to_skip = until - self.recv_count;
        if to_skip as usize > MAX_SKIP {
            return Err(Error::TooManySkippedMessages);
        }

        // Skip keys from OLD receiving chain
        if let Some(recv_chain_key) = self.recv_chain_key.as_ref() {
            let mut current_key = recv_chain_key.clone();
            let old_dh_public = self.dh_recv.ok_or(Error::CryptoError)?;

            for i in self.recv_count..until {
                let (new_chain_key, message_key) = kdf_chain(&current_key);

                // Store with OLD DH public key
                self.skipped_message_keys
                    .insert((old_dh_public, i), message_key);

                current_key = new_chain_key;
            }
        }

        Ok(())
    }

    #[allow(clippy::unused_self)]
    fn try_decrypt(
        &self,
        message: &Message,
        message_key: &SymmetricKey,
        associated_data: &[u8],
    ) -> Result<Vec<u8>> {
        let mut ad = Vec::from(associated_data);
        ad.extend_from_slice(&message.header.to_bytes());

        let nonce = generate_nonce(
            message.header.message_number,
            message.header.dh_public.as_bytes(),
        );

        decrypt(message_key, &nonce, &message.ciphertext, &ad)
    }
}

impl std::fmt::Debug for DoubleRatchet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DoubleRatchet")
            .field("send_count", &self.send_count)
            .field("recv_count", &self.recv_count)
            .field("skipped_keys", &self.skipped_message_keys.len())
            .finish()
    }
}

impl Zeroize for DoubleRatchet {
    fn zeroize(&mut self) {
        self.root_key.zeroize();
        self.send_chain_key.zeroize();
        self.recv_chain_key.zeroize();
        self.skipped_message_keys.clear();
    }
}

impl Drop for DoubleRatchet {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use rand::RngCore;

    use super::*;
    use crate::keys::IdentityKeyPair;
    use crate::x3dh::{PreKeyState, initiate, respond};

    #[test]
    fn test_xeddsa_roundtrip() {
        use crate::xeddsa::{XEdDSAPrivateKey, XEdDSAPublicKey};

        let secret = SecretKey::generate(&mut OsRng);
        let public = secret.public_key();

        // Derive XEdDSA keys
        let xeddsa_priv = XEdDSAPrivateKey::from_x25519_private(secret.as_bytes()).unwrap();
        let xeddsa_pub_from_priv = xeddsa_priv.public_key();
        let xeddsa_pub_from_x25519 = XEdDSAPublicKey::from_x25519_public(&public).unwrap();

        assert_eq!(
            xeddsa_pub_from_priv.as_bytes(),
            xeddsa_pub_from_x25519.as_bytes(),
            "XEdDSA public keys must match!"
        );

        // Try signing and verifying
        let message = b"test";
        let mut random = [0u8; 64];
        OsRng.fill_bytes(&mut random);

        let signature = xeddsa_priv.sign(message, &random);

        xeddsa_pub_from_priv.verify(message, &signature).unwrap();
        xeddsa_pub_from_x25519.verify(message, &signature).unwrap();
    }

    #[test]
    fn test_basic_exchange() {
        let alice_identity = IdentityKeyPair::generate(&mut OsRng);
        let bob_identity = IdentityKeyPair::generate(&mut OsRng);

        let mut bob_prekeys = PreKeyState::generate(&mut OsRng, &bob_identity).unwrap();
        let bundle = bob_prekeys.public_bundle();

        let alice_x3dh = initiate(&mut OsRng, &alice_identity, &bundle).unwrap();

        // Use Bob's signed prekey for consistency
        let bob_dh = bob_prekeys.signed_prekey().clone();

        let mut alice_ratchet =
            DoubleRatchet::new_sender(&mut OsRng, &alice_x3dh, bob_dh.public_key()).unwrap();

        let bob_x3dh =
            respond(&mut bob_prekeys, &bob_identity, &alice_x3dh.initial_message).unwrap();
        let mut bob_ratchet = DoubleRatchet::new_receiver(bob_x3dh.shared_secret, bob_dh);

        let msg1 = alice_ratchet.encrypt(b"Hello Bob!", b"").unwrap();
        let plaintext = bob_ratchet.decrypt(&msg1, b"").unwrap();
        assert_eq!(&plaintext, b"Hello Bob!");

        let msg2 = bob_ratchet.encrypt(b"Hello Alice!", b"").unwrap();
        let plaintext = alice_ratchet.decrypt(&msg2, b"").unwrap();
        assert_eq!(&plaintext, b"Hello Alice!");
    }

    #[test]
    fn test_multiple_messages() {
        let alice_identity = IdentityKeyPair::generate(&mut OsRng);
        let bob_identity = IdentityKeyPair::generate(&mut OsRng);

        let bob_prekeys = PreKeyState::generate(&mut OsRng, &bob_identity).unwrap();
        let bundle = bob_prekeys.public_bundle();
        let alice_x3dh = initiate(&mut OsRng, &alice_identity, &bundle).unwrap();

        let bob_dh = SecretKey::generate(&mut OsRng);
        let mut alice_ratchet =
            DoubleRatchet::new_sender(&mut OsRng, &alice_x3dh, bob_dh.public_key()).unwrap();

        for i in 0..10 {
            let msg = format!("Message {i}");
            let encrypted = alice_ratchet.encrypt(msg.as_bytes(), b"").unwrap();
            assert!(encrypted.ciphertext.len() > msg.len());
        }
    }

    /// Tests out-of-order delivery across DH ratchet boundaries
    ///
    /// This is the critical case where messages from the OLD receiving chain
    /// arrive AFTER a DH ratchet has occurred. The protocol must store
    /// skipped keys from the old chain to handle this.
    #[test]
    fn test_out_of_order_across_ratchet() {
        let alice_identity = IdentityKeyPair::generate(&mut OsRng);
        let bob_identity = IdentityKeyPair::generate(&mut OsRng);

        let mut bob_prekeys = PreKeyState::generate(&mut OsRng, &bob_identity).unwrap();
        let alice_x3dh =
            initiate(&mut OsRng, &alice_identity, &bob_prekeys.public_bundle()).unwrap();
        let bob_x3dh =
            respond(&mut bob_prekeys, &bob_identity, &alice_x3dh.initial_message).unwrap();

        let bob_dh = SecretKey::generate(&mut OsRng);
        let mut alice_ratchet =
            DoubleRatchet::new_sender(&mut OsRng, &alice_x3dh, bob_dh.public_key()).unwrap();
        let mut bob_ratchet = DoubleRatchet::new_receiver(bob_x3dh.shared_secret, bob_dh);

        // Alice sends 3 messages in chain A
        let msg0 = alice_ratchet.encrypt(b"Chain A - Message 0", b"").unwrap();
        let msg1 = alice_ratchet.encrypt(b"Chain A - Message 1", b"").unwrap();
        let msg2 = alice_ratchet.encrypt(b"Chain A - Message 2", b"").unwrap();

        // Bob receives only msg0
        let plain0 = bob_ratchet.decrypt(&msg0, b"").unwrap();
        assert_eq!(&plain0, b"Chain A - Message 0");

        // Bob sends a message, triggering DH ratchet on both sides
        let bob_msg = bob_ratchet.encrypt(b"Bob's response", b"").unwrap();
        alice_ratchet.decrypt(&bob_msg, b"").unwrap();

        // Alice sends message in NEW chain B
        let msg3 = alice_ratchet.encrypt(b"Chain B - Message 0", b"").unwrap();

        // Bob receives msg3 BEFORE msg1 and msg2 (triggers DH ratchet on Bob's side)
        let plain3 = bob_ratchet.decrypt(&msg3, b"").unwrap();
        assert_eq!(&plain3, b"Chain B - Message 0");

        // NOW msg1 and msg2 from OLD chain A arrive
        // These MUST still decrypt correctly (keys stored during ratchet)
        let plain1 = bob_ratchet.decrypt(&msg1, b"").unwrap();
        assert_eq!(&plain1, b"Chain A - Message 1");

        let plain2 = bob_ratchet.decrypt(&msg2, b"").unwrap();
        assert_eq!(&plain2, b"Chain A - Message 2");
    }
}
