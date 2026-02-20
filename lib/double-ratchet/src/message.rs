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

use crate::error::{Error, Result};
use locus_crypto::{PublicKey, generate_nonce, kdf_chain, kdf_root};

const MAX_SKIP: usize = 1000;

/// Message header containing ratchet metadata.
///
/// The header is transmitted in plaintext but authenticated via AEAD.
/// Contains the sender's current DH public key and message sequencing information.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MessageHeader {
    /// Current DH ratchet public key for this sending chain
    pub dh_public: PublicKey,

    /// Number of messages in the previous sending chain
    pub previous_chain_length: u32,

    /// Message number in current sending chain (starts at 0)
    pub message_number: u32,
}

impl MessageHeader {
    /// Serializes header to bytes for inclusion in authenticated data.
    ///
    /// Format: `dh_public (32) || prev_chain_len (4, LE) || msg_num (4, LE)`
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(40);
        bytes.extend_from_slice(self.dh_public.as_bytes());
        bytes.extend_from_slice(&self.previous_chain_length.to_le_bytes());
        bytes.extend_from_slice(&self.message_number.to_le_bytes());
        bytes
    }

    /// Deserializes header from byte representation.
    ///
    /// Returns error if input is malformed (wrong length or invalid encoding).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 40 {
            return Err(Error::InvalidMessageHeader);
        }

        let dh_public = PublicKey::from_bytes(
            bytes[..32]
                .try_into()
                .map_err(|_| Error::InvalidMessageHeader)?,
        );
        let previous_chain_length = u32::from_le_bytes(
            bytes[32..36]
                .try_into()
                .map_err(|_| Error::InvalidMessageHeader)?,
        );
        let message_number = u32::from_le_bytes(
            bytes[36..40]
                .try_into()
                .map_err(|_| Error::InvalidMessageHeader)?,
        );

        Ok(Self {
            dh_public,
            previous_chain_length,
            message_number,
        })
    }
}

/// Double Ratchet encrypted message.
///
/// Contains a plaintext header (authenticated but not encrypted) and
/// AEAD-encrypted ciphertext. The header is included in the AEAD associated data.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Message {
    /// Message header (plaintext, but authenticated)
    pub header: MessageHeader,

    /// AEAD ciphertext with appended authentication tag
    pub ciphertext: Vec<u8>,
}

impl Message {
    /// Serializes message for network transmission.
    ///
    /// Format: `header_len (4, LE) || header || ciphertext`
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let header_bytes = self.header.to_bytes();
        let mut bytes = Vec::with_capacity(4 + header_bytes.len() + self.ciphertext.len());

        #[allow(clippy::cast_possible_truncation)]
        bytes.extend_from_slice(&(header_bytes.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&header_bytes);
        bytes.extend_from_slice(&self.ciphertext);

        bytes
    }

    /// Deserializes message from wire format.
    ///
    /// Returns error if input is malformed or truncated.
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

        let header = MessageHeader::from_bytes(&bytes[4..4 + header_len])?;
        let ciphertext = bytes[4 + header_len..].to_vec();

        Ok(Self { header, ciphertext })
    }
}
