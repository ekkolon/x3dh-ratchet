//! Storage abstractions for one-time prekeys and skipped message keys.
//!
//! Provides trait-based storage backends supporting both in-memory and
//! persistent implementations. Thread-safe by design with interior mutability.

use crate::error::{Error, Result};
use crate::keys::{PublicKey, SecretKey};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Storage backend for one-time prekeys.
///
/// Implementations must be thread-safe (`Send + Sync`) to support concurrent
/// access from multiple protocol sessions. Keys are consumed atomically when
/// retrieved to prevent reuse.
pub trait PreKeyStore: Send + Sync {
    /// Stores a one-time prekey with the given ID.
    ///
    /// If a prekey with the same ID already exists, it is replaced.
    fn store_one_time_prekey(&mut self, id: u32, key: SecretKey) -> Result<()>;

    /// Retrieves and removes a one-time prekey by ID.
    ///
    /// Returns `None` if no prekey exists with the given ID. This operation
    /// must be atomic to prevent double-spending of prekeys.
    fn consume_one_time_prekey(&mut self, id: u32) -> Result<Option<SecretKey>>;

    /// Lists all available one-time prekey IDs.
    ///
    /// Useful for inventory management and monitoring prekey depletion.
    fn list_one_time_prekeys(&self) -> Result<Vec<u32>>;

    /// Returns the number of one-time prekeys currently stored.
    fn one_time_prekey_count(&self) -> Result<usize>;
}

/// Thread-safe in-memory prekey storage.
///
/// Suitable for testing and applications that don't require persistence.
/// Uses `Arc<Mutex<_>>` for safe concurrent access across threads.
///
/// # Example
/// ```no_run
/// # use x3dh_ratchet::storage::InMemoryPreKeyStore;
/// let mut store = InMemoryPreKeyStore::new();
/// // Store prekeys generated during setup...
/// ```
#[derive(Clone, Debug)]
pub struct InMemoryPreKeyStore {
    one_time_prekeys: Arc<Mutex<HashMap<u32, SecretKey>>>,
}

impl InMemoryPreKeyStore {
    /// Creates a new empty prekey store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            one_time_prekeys: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Bulk-inserts multiple prekeys into the store.
    ///
    /// Useful for initializing a store with a batch of freshly generated
    /// prekeys. If any ID already exists, its prekey is replaced.
    ///
    /// # Errors
    /// Returns error if the internal mutex is poisoned.
    pub fn populate(&mut self, keys: Vec<(u32, SecretKey)>) -> Result<()> {
        let mut store = self
            .one_time_prekeys
            .lock()
            .map_err(|_| Error::StorageError)?;

        for (id, key) in keys {
            store.insert(id, key);
        }
        Ok(())
    }
}

impl Default for InMemoryPreKeyStore {
    fn default() -> Self {
        Self::new()
    }
}

impl PreKeyStore for InMemoryPreKeyStore {
    fn store_one_time_prekey(&mut self, id: u32, key: SecretKey) -> Result<()> {
        let mut store = self
            .one_time_prekeys
            .lock()
            .map_err(|_| Error::StorageError)?;
        store.insert(id, key);
        Ok(())
    }

    fn consume_one_time_prekey(&mut self, id: u32) -> Result<Option<SecretKey>> {
        let mut store = self
            .one_time_prekeys
            .lock()
            .map_err(|_| Error::StorageError)?;
        Ok(store.remove(&id))
    }

    fn list_one_time_prekeys(&self) -> Result<Vec<u32>> {
        let store = self
            .one_time_prekeys
            .lock()
            .map_err(|_| Error::StorageError)?;
        Ok(store.keys().copied().collect())
    }

    fn one_time_prekey_count(&self) -> Result<usize> {
        let store = self
            .one_time_prekeys
            .lock()
            .map_err(|_| Error::StorageError)?;
        Ok(store.len())
    }
}

/// Storage for skipped message keys in Double Ratchet.
///
/// Stores message keys for out-of-order messages indexed by
/// `(dh_public, message_number)`. Enforces a maximum capacity to prevent
/// unbounded memory growth from malicious message patterns.
///
/// # Security
/// Keys are automatically zeroized when removed or when storage is dropped.
#[derive(Clone, Debug)]
pub struct SkippedMessageKeyStorage {
    keys: Arc<Mutex<HashMap<(PublicKey, u32), crate::crypto::SymmetricKey>>>,
    max_keys: usize,
}

impl SkippedMessageKeyStorage {
    /// Creates new storage with the specified maximum capacity.
    ///
    /// # Arguments
    /// * `max_keys` - Maximum number of skipped keys to store. Attempting to
    ///   store more returns `Error::TooManySkippedMessages`.
    #[must_use]
    pub fn new(max_keys: usize) -> Self {
        Self {
            keys: Arc::new(Mutex::new(HashMap::new())),
            max_keys,
        }
    }

    /// Stores a skipped message key.
    ///
    /// # Arguments
    /// * `dh_public` - DH public key from the message header
    /// * `msg_num` - Message number from the message header
    /// * `key` - Derived message key for decrypting this message
    ///
    /// # Errors
    /// Returns `Error::TooManySkippedMessages` if capacity is exceeded.
    pub fn store(
        &mut self,
        dh_public: PublicKey,
        msg_num: u32,
        key: crate::crypto::SymmetricKey,
    ) -> Result<()> {
        let mut store = self.keys.lock().map_err(|_| Error::StorageError)?;

        if store.len() >= self.max_keys {
            return Err(Error::TooManySkippedMessages);
        }

        store.insert((dh_public, msg_num), key);
        Ok(())
    }

    /// Retrieves and removes a skipped message key.
    ///
    /// Returns `None` if no key exists for the given `(dh_public, msg_num)` pair.
    pub fn consume(
        &mut self,
        dh_public: &PublicKey,
        msg_num: u32,
    ) -> Result<Option<crate::crypto::SymmetricKey>> {
        let mut store = self.keys.lock().map_err(|_| Error::StorageError)?;
        Ok(store.remove(&(*dh_public, msg_num)))
    }

    /// Returns the current number of stored skipped keys.
    pub fn count(&self) -> Result<usize> {
        let store = self.keys.lock().map_err(|_| Error::StorageError)?;
        Ok(store.len())
    }

    /// Removes all stored skipped message keys.
    ///
    /// Keys are zeroized before removal for security.
    pub fn clear(&mut self) -> Result<()> {
        let mut store = self.keys.lock().map_err(|_| Error::StorageError)?;
        store.clear();
        Ok(())
    }
}

impl Default for SkippedMessageKeyStorage {
    fn default() -> Self {
        Self::new(1000)
    }
}

#[cfg(test)]
mod tests {
    use chacha20poly1305::aead::OsRng;

    use crate::crypto::KEY_SIZE_32;

    use super::*;

    #[test]
    fn test_in_memory_storage() {
        let mut storage = InMemoryPreKeyStore::new();

        let key1 = SecretKey::generate(&mut OsRng);
        let key2 = SecretKey::generate(&mut OsRng);

        storage.store_one_time_prekey(1, key1).unwrap();
        storage.store_one_time_prekey(2, key2).unwrap();

        assert_eq!(storage.one_time_prekey_count().unwrap(), 2);

        let retrieved = storage.consume_one_time_prekey(1).unwrap();
        assert!(retrieved.is_some());

        assert_eq!(storage.one_time_prekey_count().unwrap(), 1);
    }

    #[test]
    fn test_skipped_key_storage() {
        let mut storage = SkippedMessageKeyStorage::new(10);

        let dh_public = SecretKey::generate(&mut OsRng).public_key();
        let key = crate::crypto::SymmetricKey::from_bytes([42u8; KEY_SIZE_32]);

        storage.store(dh_public, 5, key.clone()).unwrap();
        assert_eq!(storage.count().unwrap(), 1);

        let retrieved = storage.consume(&dh_public, 5).unwrap();
        assert!(retrieved.is_some());
        assert_eq!(storage.count().unwrap(), 0);
    }

    #[test]
    fn test_storage_capacity() {
        let mut storage = SkippedMessageKeyStorage::new(2);
        let dh_public = SecretKey::generate(&mut OsRng).public_key();

        storage
            .store(
                dh_public,
                1,
                crate::crypto::SymmetricKey::from_bytes([1u8; KEY_SIZE_32]),
            )
            .unwrap();
        storage
            .store(
                dh_public,
                2,
                crate::crypto::SymmetricKey::from_bytes([2u8; KEY_SIZE_32]),
            )
            .unwrap();

        let result = storage.store(
            dh_public,
            3,
            crate::crypto::SymmetricKey::from_bytes([3u8; KEY_SIZE_32]),
        );
        assert!(result.is_err());
    }
}
