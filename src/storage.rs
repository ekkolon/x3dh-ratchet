//! Storage abstraction for prekey management
//!
//! Provides trait-based storage allowing in-memory or persistent backends

use crate::error::{Error, Result};
use crate::keys::{PublicKey, SecretKey};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Trait for prekey storage backends
pub trait PreKeyStore: Send + Sync {
    /// Store a one-time prekey
    fn store_one_time_prekey(&mut self, id: u32, key: SecretKey) -> Result<()>;

    /// Retrieve and consume a one-time prekey
    fn consume_one_time_prekey(&mut self, id: u32) -> Result<Option<SecretKey>>;

    /// List available one-time prekey IDs
    fn list_one_time_prekeys(&self) -> Result<Vec<u32>>;

    /// Get count of remaining one-time prekeys
    fn one_time_prekey_count(&self) -> Result<usize>;
}

/// Thread-safe, in-memory prekey storage
#[derive(Clone, Debug)]
pub struct InMemoryPreKeyStore {
    one_time_prekeys: Arc<Mutex<HashMap<u32, SecretKey>>>,
}

impl InMemoryPreKeyStore {
    /// Create new in-memory prekey storage
    #[must_use]
    pub fn new() -> Self {
        Self {
            one_time_prekeys: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Populate with prekeys
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

/// Skipped message key storage for out-of-order messages
#[derive(Clone, Debug)]
pub struct SkippedMessageKeyStorage {
    keys: Arc<Mutex<HashMap<(PublicKey, u32), crate::crypto::SymmetricKey>>>,
    max_keys: usize,
}

impl SkippedMessageKeyStorage {
    /// Create new storage with maximum capacity
    #[must_use]
    pub fn new(max_keys: usize) -> Self {
        Self {
            keys: Arc::new(Mutex::new(HashMap::new())),
            max_keys,
        }
    }

    /// Store a skipped message key
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

    /// Retrieve and remove a skipped message key
    pub fn consume(
        &mut self,
        dh_public: &PublicKey,
        msg_num: u32,
    ) -> Result<Option<crate::crypto::SymmetricKey>> {
        let mut store = self.keys.lock().map_err(|_| Error::StorageError)?;
        Ok(store.remove(&(*dh_public, msg_num)))
    }

    /// Get current message keys count
    pub fn count(&self) -> Result<usize> {
        let store = self.keys.lock().map_err(|_| Error::StorageError)?;
        Ok(store.len())
    }

    /// Clear all stored keys
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
    use crate::crypto::KEY_SIZE_32;

    use super::*;
    use rand_core::OsRng;

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

        // Should fail when capacity exceeded
        let result = storage.store(
            dh_public,
            3,
            crate::crypto::SymmetricKey::from_bytes([3u8; KEY_SIZE_32]),
        );
        assert!(result.is_err());
    }
}
