//! Double Ratchet protocol for forward-secure encryption
//!
//! Implements the Signal protocol's Double Ratchet algorithm providing:
//! - Forward secrecy: Past messages secure even if current keys compromised
//! - Post-compromise security: Security restored after key compromise
//! - Out-of-order message delivery
//!
//! ## Algorithm Overview
//!
//! The Double Ratchet combines:
//! 1. **Symmetric-key ratchet**: Derives new keys for each message
//! 2. **DH ratchet**: Periodically refreshes shared secret via new DH exchanges
//!
//! ## State
//!
//! Each party maintains:
//! - Root key (RK): Updated on DH ratchet step
//! - Sending chain key (`CK_s)`: Updated on each sent message
//! - Receiving chain key (`CK_r)`: Updated on each received message
//! - DH key pair: Rotated on DH ratchet step

use crate::crypto::{decrypt, encrypt, kdf_chain, kdf_root, SymmetricKey, NONCE_SIZE};
use crate::error::{Error, Result};
use crate::keys::{PublicKey, SecretKey};
use crate::x3dh::InitiatorResult;
use rand_core::CryptoRngCore;
use std::collections::HashMap;
use zeroize::Zeroize;

/// Maximum number of skipped message keys to store
/// todo(ekkolon): This should be configurable
const MAX_SKIP: usize = 1000;

/// Message header containing ratchet public key and message number
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Header {
    /// Current DH ratchet public key
    pub dh_public: PublicKey,

    /// Previous chain length (number of messages in previous sending chain)
    pub previous_chain_length: u32,

    /// Message number in current sending chain
    pub message_number: u32,
}

impl Header {
    /// Serialize header for authenticated data
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(32 + 8);
        bytes.extend_from_slice(self.dh_public.as_bytes());
        bytes.extend_from_slice(&self.previous_chain_length.to_le_bytes());
        bytes.extend_from_slice(&self.message_number.to_le_bytes());
        bytes
    }

    /// Deserialize header
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 40 {
            return Err(Error::InvalidHeader);
        }

        let dh_public =
            PublicKey::from_bytes(bytes[..32].try_into().map_err(|_| Error::InvalidHeader)?);
        let previous_chain_length =
            u32::from_le_bytes(bytes[32..36].try_into().map_err(|_| Error::InvalidHeader)?);
        let message_number =
            u32::from_le_bytes(bytes[36..40].try_into().map_err(|_| Error::InvalidHeader)?);

        Ok(Self {
            dh_public,
            previous_chain_length,
            message_number,
        })
    }
}

/// Encrypted message with header and ciphertext
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Message {
    /// Message header (not encrypted, but authenticated)
    pub header: Header,

    /// Encrypted payload
    pub ciphertext: Vec<u8>,
}

impl Message {
    /// Serialize message for transmission
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let header_bytes = self.header.to_bytes();
        let capacity = header_bytes.len() + self.ciphertext.len() + 4;
        let mut bytes = Vec::with_capacity(capacity);

        // Length prefix for header
        bytes.extend_from_slice(&(header_bytes.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&header_bytes);
        bytes.extend_from_slice(&self.ciphertext);

        bytes
    }

    /// Deserialize message
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 4 {
            return Err(Error::InvalidMessageFormat);
        }

        let header_len = u32::from_le_bytes(
            bytes[..4]
                .try_into()
                .map_err(|_| Error::InvalidMessageFormat)?,
        ) as usize;

        if bytes.len() < 4 + header_len {
            return Err(Error::InvalidMessageFormat);
        }

        let header = Header::from_bytes(&bytes[4..4 + header_len])?;
        let ciphertext = bytes[4 + header_len..].to_vec();

        Ok(Self { header, ciphertext })
    }
}

/// Double Ratchet state
pub struct DoubleRatchet {
    /// Current root key
    root_key: SymmetricKey,

    /// Current sending chain key (None if never sent)
    send_chain_key: Option<SymmetricKey>,

    /// Current receiving chain key (None if never received)
    recv_chain_key: Option<SymmetricKey>,

    /// Current DH key pair for sending
    dh_send: SecretKey,

    /// Remote DH public key for receiving
    dh_recv: Option<PublicKey>,

    /// Number of messages sent in current chain
    send_count: u32,

    /// Number of messages received in current chain
    recv_count: u32,

    /// Previous sending chain length
    prev_chain_length: u32,

    /// Skipped message keys indexed by (`dh_public`, `message_number`)
    skipped_message_keys: HashMap<(PublicKey, u32), SymmetricKey>,
}

impl DoubleRatchet {
    /// Initialize as sender (after X3DH initiation)
    pub fn init_sender<R: CryptoRngCore>(
        rng: &mut R,
        x3dh_result: &InitiatorResult,
        remote_dh_public: PublicKey,
    ) -> Self {
        let root_key = &x3dh_result.shared_secret;
        let dh_send = SecretKey::generate(rng);

        // Perform initial DH ratchet step
        let dh_output = dh_send.diffie_hellman(&remote_dh_public);
        let (new_root, send_chain_key) = kdf_root(root_key, &dh_output);

        Self {
            root_key: new_root,
            send_chain_key: Some(send_chain_key),
            recv_chain_key: None,
            dh_send,
            dh_recv: Some(remote_dh_public),
            send_count: 0,
            recv_count: 0,
            prev_chain_length: 0,
            skipped_message_keys: HashMap::new(),
        }
    }

    /// Initialize as receiver (after X3DH response)
    #[must_use]
    pub fn init_receiver(shared_secret: SymmetricKey, local_dh_keypair: SecretKey) -> Self {
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

    /// Encrypt a message
    pub fn encrypt(&mut self, plaintext: &[u8], associated_data: &[u8]) -> Result<Message> {
        // Ensure we have a sending chain key
        if self.send_chain_key.is_none() {
            return Err(Error::CryptoError);
        }

        let chain_key = self.send_chain_key.as_ref().unwrap();
        let (new_chain_key, message_key) = kdf_chain(chain_key);
        self.send_chain_key = Some(new_chain_key);

        // Create header
        let header = Header {
            dh_public: self.dh_send.public_key(),
            previous_chain_length: self.prev_chain_length,
            message_number: self.send_count,
        };

        // Derive nonce from message number (simplified)
        let mut nonce = [0u8; NONCE_SIZE];
        nonce[..4].copy_from_slice(&self.send_count.to_le_bytes());

        // Encrypt with header as additional data
        let mut ad = Vec::from(associated_data);
        ad.extend_from_slice(&header.to_bytes());

        let ciphertext = encrypt(&message_key, &nonce, plaintext, &ad)?;

        self.send_count += 1;

        Ok(Message { header, ciphertext })
    }

    /// Decrypt a message
    pub fn decrypt(&mut self, message: &Message, associated_data: &[u8]) -> Result<Vec<u8>> {
        // Try skipped message keys first
        let key = (message.header.dh_public, message.header.message_number);
        if let Some(message_key) = self.skipped_message_keys.remove(&key) {
            return self.try_decrypt(message, &message_key, associated_data);
        }

        // Check if we need to perform DH ratchet step
        if Some(message.header.dh_public) != self.dh_recv {
            self.dh_ratchet(&message.header)?;
        }

        // Skip messages if needed
        self.skip_message_keys(message.header.message_number)?;

        // Decrypt current message
        let chain_key = self.recv_chain_key.as_ref().ok_or(Error::CryptoError)?;
        let (new_chain_key, message_key) = kdf_chain(chain_key);
        self.recv_chain_key = Some(new_chain_key);
        self.recv_count += 1;

        self.try_decrypt(message, &message_key, associated_data)
    }

    /// Perform DH ratchet step when receiving new DH public key
    fn dh_ratchet(&mut self, header: &Header) -> Result<()> {
        // Save previous chain length
        self.prev_chain_length = self.send_count;
        self.send_count = 0;
        self.recv_count = 0;

        // Update receiving chain
        let dh_output = self.dh_send.diffie_hellman(&header.dh_public);
        let (new_root, recv_chain_key) = kdf_root(&self.root_key, &dh_output);
        self.root_key = new_root;
        self.recv_chain_key = Some(recv_chain_key);
        self.dh_recv = Some(header.dh_public);

        // Generate new DH keypair for sending
        // Note: In real implementation, use proper RNG injection
        use rand_core::OsRng;
        self.dh_send = SecretKey::generate(&mut OsRng);

        // Update sending chain
        let dh_output = self.dh_send.diffie_hellman(&header.dh_public);
        let (new_root, send_chain_key) = kdf_root(&self.root_key, &dh_output);
        self.root_key = new_root;
        self.send_chain_key = Some(send_chain_key);

        Ok(())
    }

    /// Skip message keys and store them for out-of-order delivery
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

    /// Try to decrypt with a specific message key
    fn try_decrypt(
        &self,
        message: &Message,
        message_key: &SymmetricKey,
        associated_data: &[u8],
    ) -> Result<Vec<u8>> {
        let mut nonce = [0u8; NONCE_SIZE];
        nonce[..4].copy_from_slice(&message.header.message_number.to_le_bytes());

        let mut ad = Vec::from(associated_data);
        ad.extend_from_slice(&message.header.to_bytes());

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
    use super::*;
    use crate::keys::IdentityKeyPair;
    use crate::x3dh::{initiate, PreKeyState};
    use rand_core::OsRng;

    #[test]
    fn test_basic_exchange() {
        // Setup X3DH
        let alice_identity = IdentityKeyPair::generate(&mut OsRng);
        let bob_identity = IdentityKeyPair::generate(&mut OsRng);

        let mut bob_prekeys = PreKeyState::generate(&mut OsRng, &bob_identity);
        let bundle = bob_prekeys.public_bundle();

        let alice_x3dh = initiate(&mut OsRng, &alice_identity, &bundle).unwrap();

        // Initialize ratchets
        let bob_dh = SecretKey::generate(&mut OsRng);
        let bob_public = bob_dh.public_key();

        let mut alice_ratchet = DoubleRatchet::init_sender(&mut OsRng, &alice_x3dh, bob_public);

        let bob_x3dh =
            crate::x3dh::respond(&mut bob_prekeys, &bob_identity, &alice_x3dh.initial_message)
                .unwrap();
        let mut bob_ratchet = DoubleRatchet::init_receiver(bob_x3dh.shared_secret, bob_dh);

        // Alice sends message
        let msg1 = alice_ratchet.encrypt(b"Hello Bob!", b"").unwrap();

        // Bob receives
        let plaintext = bob_ratchet.decrypt(&msg1, b"").unwrap();
        assert_eq!(&plaintext, b"Hello Bob!");

        // Bob replies
        let msg2 = bob_ratchet.encrypt(b"Hello Alice!", b"").unwrap();
        let plaintext = alice_ratchet.decrypt(&msg2, b"").unwrap();
        assert_eq!(&plaintext, b"Hello Alice!");
    }

    #[test]
    fn test_multiple_messages() {
        let alice_identity = IdentityKeyPair::generate(&mut OsRng);
        let bob_identity = IdentityKeyPair::generate(&mut OsRng);

        let bob_prekeys = PreKeyState::generate(&mut OsRng, &bob_identity);
        let bundle = bob_prekeys.public_bundle();
        let alice_x3dh = initiate(&mut OsRng, &alice_identity, &bundle).unwrap();

        let bob_dh = SecretKey::generate(&mut OsRng);
        let mut alice_ratchet =
            DoubleRatchet::init_sender(&mut OsRng, &alice_x3dh, bob_dh.public_key());

        // Send multiple messages
        for i in 0..10 {
            let msg = format!("Message {}", i);
            let encrypted = alice_ratchet.encrypt(msg.as_bytes(), b"").unwrap();
            assert!(encrypted.ciphertext.len() > msg.len());
        }
    }
}
