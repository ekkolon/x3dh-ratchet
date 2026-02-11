//! Error types for the Signal protocol implementation.

use thiserror::Error;

/// Result type alias for Signal protocol operations
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur during protocol operations
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Invalid signature detected
    #[error("invalid signature")]
    InvalidSignature,

    /// Invalid public key encoding
    #[error("invalid public key")]
    InvalidPublicKey,

    /// Invalid secret key encoding  
    #[error("invalid secret key")]
    InvalidSecretKey,

    /// Missing required one-time prekey
    #[error("missing one-time prekey")]
    MissingOneTimePrekey,

    /// One-time prekey already consumed
    #[error("one-time prekey already used")]
    OneTimePreKeyConsumed,

    /// DH key agreement failed
    #[error("key agreement failed")]
    KeyAgreementFailed,

    /// Invalid message format
    #[error("invalid message format")]
    InvalidMessageFormat,

    /// Message authentication failed
    #[error("authentication failed")]
    AuthenticationFailed,

    /// Message decryption failed
    #[error("decryption failed")]
    DecryptionFailed,

    /// Message number out of sequence
    #[error("out of order message")]
    OutOfOrderMessage,

    /// Skipped too many messages in chain
    #[error("too many skipped messages")]
    TooManySkippedMessages,

    /// Invalid header in ratchet message
    #[error("invalid message header")]
    InvalidHeader,

    /// Serialization failed
    #[error("serialization error")]
    SerializationError,

    /// Deserialization failed
    #[error("deserialization error")]
    DeserializationError,

    /// Internal cryptographic error
    #[error("cryptographic error")]
    CryptoError,

    /// Storage operation failed
    #[error("storage error")]
    StorageError,
}

impl From<ed25519_dalek::SignatureError> for Error {
    fn from(_: ed25519_dalek::SignatureError) -> Self {
        Error::InvalidSignature
    }
}

#[cfg(feature = "serde")]
impl From<bincode::error::EncodeError> for Error {
    fn from(_: bincode::error::EncodeError) -> Self {
        Error::SerializationError
    }
}

#[cfg(feature = "serde")]
impl From<bincode::error::DecodeError> for Error {
    fn from(_: bincode::error::DecodeError) -> Self {
        Error::DeserializationError
    }
}
