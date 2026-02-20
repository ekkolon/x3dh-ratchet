//! Error types for X3DH and Double Ratchet protocol operations.

use thiserror::Error;

/// Result type alias for protocol operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur during X3DH and Double Ratchet operations.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Ed25519 signature verification failed.
    ///
    /// Indicates either a corrupted signature or signature created with
    /// a different signing key than expected.
    #[error("signature verification failed")]
    InvalidSignature,

    /// Public key has invalid encoding or format.
    ///
    /// X25519 or Ed25519 public key does not conform to expected encoding.
    #[error("invalid public key encoding")]
    InvalidPublicKey,

    /// Secret key has invalid encoding or format.
    #[error("invalid secret key encoding")]
    InvalidSecretKey,

    /// Session state is invalid for the requested operation.
    ///
    /// Occurs when trying to encrypt without a sending chain or decrypt
    /// without a receiving chain.
    #[error("invalid session state")]
    InvalidSessionState,

    /// One-time prekey not available.
    ///
    /// Server has no remaining one-time prekeys for the requested user.
    /// X3DH will fall back to 3-DH mode without the fourth DH operation.
    #[error("no one-time prekeys available")]
    MissingOneTimePrekey,

    /// One-time prekey already consumed.
    ///
    /// Attempted to use a one-time prekey that was already consumed by
    /// a previous protocol run. This may indicate a replay attack.
    #[error("one-time prekey already consumed")]
    OneTimePreKeyConsumed,

    /// Diffie-Hellman key agreement failed.
    ///
    /// DH operation produced invalid output or computation failed.
    #[error("key agreement failed")]
    KeyAgreementFailed,

    /// Message wire format is malformed.
    ///
    /// Received message has invalid structure, truncated data, or
    /// incorrect length prefixes.
    #[error("malformed message format")]
    InvalidMessageFormat,

    /// AEAD authentication tag verification failed.
    ///
    /// Message was tampered with, encrypted with wrong key, or
    /// associated data does not match.
    #[error("message authentication failed")]
    AuthenticationFailed,

    /// AEAD decryption failed.
    ///
    /// Could not decrypt message ciphertext. Implies authentication
    /// failure as AEAD verifies before decrypting.
    #[error("message decryption failed")]
    DecryptionFailed,

    /// Received message number is less than expected.
    ///
    /// Message arrived out-of-order and its key was already deleted.
    /// This prevents backwards message replay.
    #[error("message number out of sequence")]
    OutOfOrderMessage,

    /// Too many skipped messages in ratchet chain.
    ///
    /// Gap between received and expected message number exceeds maximum.
    /// Protects against `DoS` via forced key storage exhaustion.
    #[error("exceeded maximum skipped message limit")]
    TooManySkippedMessages,

    /// Double Ratchet message header is invalid.
    ///
    /// Header has wrong size, malformed fields, or invalid encoding.
    #[error("invalid Double Ratchet header")]
    InvalidHeader,

    /// Failed to serialize data structure.
    #[error("serialization failed")]
    SerializationError,

    /// Failed to deserialize data structure.
    #[error("deserialization failed")]
    DeserializationError,

    /// Internal cryptographic operation failed.
    ///
    /// Unexpected failure in a cryptographic primitive. Should not occur
    /// under normal operation.
    #[error("internal cryptographic error")]
    CryptoError,

    /// Storage backend operation failed.
    ///
    /// Failure accessing prekey storage or skipped message key storage.
    /// May indicate database errors or lock poisoning.
    #[error("storage backend error")]
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
