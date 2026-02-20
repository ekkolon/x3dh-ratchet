use hkdf::Hkdf;
use locus_crypto::{
    SymmetricKey,
    constants::{KEY_SIZE_32, KEY_SIZE_64},
};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::Result;

/// KDF chain state for symmetric ratcheting in Double Ratchet protocol.
///
/// Maintains a chain key that is advanced with each step, deriving new keys
/// while updating internal state for forward secrecy.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct KdfChain {
    key: SymmetricKey,
}

impl KdfChain {
    /// Creates a new KDF chain from a symmetric key.
    #[must_use]
    pub fn new(key: SymmetricKey) -> Self {
        Self { key }
    }

    /// Initializes a root chain from X3DH output.
    #[must_use]
    pub fn from_x3dh(x3dh_output: SymmetricKey) -> Self {
        Self::new(x3dh_output)
    }

    /// Advances the KDF chain by one step.
    ///
    /// Computes `(CK', K) = KDF(CK)` where `CK'` becomes the new chain key
    /// and `K` is returned as the derived output.
    ///
    /// # Arguments
    /// * `info` - Domain separation string for HKDF
    ///
    /// # Panics
    ///
    /// Never panics in practice. The internal `expect()` is only a safeguard
    /// for the HKDF expand operation with a fixed 64-byte output length,
    /// which is always valid.
    pub fn step(&mut self, info: &[u8]) -> Result<SymmetricKey> {
        let hkdf = Hkdf::<Sha256>::new(None, self.key.as_bytes());

        let mut output = [0u8; KEY_SIZE_64];
        // SAFETY: 64-byte output is always valid for HKDF-SHA256
        hkdf.expand(info, &mut output)
            .expect("64-byte HKDF output is always valid");

        self.key
            .as_bytes_mut()
            .copy_from_slice(&output[..KEY_SIZE_32]);

        let derived = SymmetricKey::from_bytes(
            output[KEY_SIZE_32..]
                .try_into()
                .map_err(|_| crate::Error::CryptoError)?,
        );

        output.zeroize();
        Ok(derived)
    }

    /// Returns the current chain key without advancing the chain.
    #[must_use]
    pub fn current_key(&self) -> &SymmetricKey {
        &self.key
    }
}

impl std::fmt::Debug for KdfChain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "KdfChain([REDACTED])")
    }
}

/// Root KDF for Double Ratchet DH ratchet step.
///
/// Computes `(RK', CK) = KDF_RK(RK, DH_out)` where:
/// - `RK` is the current root key
/// - `DH_out` is a Diffie-Hellman shared secret
/// - `RK'` is the new root key (first 32 bytes of output)
/// - `CK` is the new chain key (second 32 bytes of output)
///
/// Used when performing a DH ratchet step to derive new symmetric ratchet chains.
///
/// # Panics
///
/// Never panics in practice. The internal `expect()` is only a safeguard
/// for the HKDF expand operation with a fixed 64-byte output length,
/// which is always valid.
pub fn kdf_root(
    root_key: &SymmetricKey,
    dh_output: &DhOutput,
) -> Result<(SymmetricKey, SymmetricKey)> {
    let hkdf = Hkdf::<Sha256>::new(Some(root_key.as_bytes()), dh_output.as_bytes());

    let mut output = [0u8; KEY_SIZE_64];
    // SAFETY: 64-byte output is always valid for HKDF-SHA256
    hkdf.expand(ROOT_INFO, &mut output)
        .expect("64-byte HKDF output is always valid");

    let new_root = SymmetricKey::from_bytes(
        output[..KEY_SIZE_32]
            .try_into()
            .map_err(|_| crate::Error::CryptoError)?,
    );

    let new_chain = SymmetricKey::from_bytes(
        output[KEY_SIZE_32..]
            .try_into()
            .map_err(|_| crate::Error::CryptoError)?,
    );

    output.zeroize();
    Ok((new_root, new_chain))
}
