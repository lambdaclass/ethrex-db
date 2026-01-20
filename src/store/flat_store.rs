//! Flat Storage - Key-value storage with bucket-based iteration.
//!
//! This module provides flat (non-trie) storage for accounts and storage slots,
//! designed to work with the StackTrie algorithm for efficient root computation.
//!
//! ## Design Principles
//!
//! 1. **Flat storage**: No trie structure on disk, just raw key-value pairs
//! 2. **Bucket iteration**: Group entries by 4-nibble prefix for efficient iteration
//! 3. **Lazy access**: Only load entries when needed (not entire database)
//!
//! ## Key Features
//!
//! - Store raw RLP-encoded values, no intermediate nodes
//! - Efficient iteration by bucket (first 4 nibbles of key)
//! - Support for dirty tracking per-bucket

use hashbrown::HashMap;
use rustc_hash::FxBuildHasher;

use super::subtree_cache::SubtreeHashCache;

/// Type alias for our fast HashMap with FxHash.
type FastHashMap<K, V> = HashMap<K, V, FxBuildHasher>;

/// Flat storage for account data.
///
/// Keys are 32-byte keccak256 hashes of addresses.
/// Values are RLP-encoded account data.
pub struct FlatAccountStore {
    /// In-memory key-value store.
    /// For production, this would be backed by a memory-mapped file.
    data: FastHashMap<[u8; 32], Vec<u8>>,

    /// Index: bucket -> list of keys in that bucket.
    /// Enables efficient iteration by bucket for StackTrie.
    bucket_index: FastHashMap<u16, Vec<[u8; 32]>>,

    /// Dirty tracking: which keys have been modified.
    dirty_keys: FastHashMap<[u8; 32], DirtyState>,
}

/// State of a dirty entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DirtyState {
    /// Entry was inserted or updated.
    Modified,
    /// Entry was deleted.
    Deleted,
}

impl FlatAccountStore {
    /// Creates a new empty flat store.
    pub fn new() -> Self {
        Self {
            data: FastHashMap::with_hasher(FxBuildHasher),
            bucket_index: FastHashMap::with_hasher(FxBuildHasher),
            dirty_keys: FastHashMap::with_hasher(FxBuildHasher),
        }
    }

    /// Creates a new flat store with expected capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            data: FastHashMap::with_capacity_and_hasher(capacity, FxBuildHasher),
            bucket_index: FastHashMap::with_capacity_and_hasher(capacity / 100, FxBuildHasher),
            dirty_keys: FastHashMap::with_hasher(FxBuildHasher),
        }
    }

    /// Returns the number of entries.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns true if the store is empty.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Gets a value by key.
    pub fn get(&self, key: &[u8; 32]) -> Option<&Vec<u8>> {
        // Check if deleted
        if matches!(self.dirty_keys.get(key), Some(DirtyState::Deleted)) {
            return None;
        }
        self.data.get(key)
    }

    /// Inserts a key-value pair.
    pub fn insert(&mut self, key: [u8; 32], value: Vec<u8>) {
        let bucket = SubtreeHashCache::key_to_bucket(&key);

        // Update bucket index if this is a new key
        if !self.data.contains_key(&key) {
            self.bucket_index
                .entry(bucket)
                .or_default()
                .push(key);
        }

        self.data.insert(key, value);
        self.dirty_keys.insert(key, DirtyState::Modified);
    }

    /// Removes a key-value pair.
    pub fn remove(&mut self, key: &[u8; 32]) -> Option<Vec<u8>> {
        self.dirty_keys.insert(*key, DirtyState::Deleted);
        self.data.remove(key)
    }

    /// Batch insert multiple key-value pairs.
    pub fn insert_batch(&mut self, entries: impl IntoIterator<Item = ([u8; 32], Vec<u8>)>) {
        for (key, value) in entries {
            self.insert(key, value);
        }
    }

    /// Returns an iterator over all entries in a bucket.
    ///
    /// The bucket is determined by the first 4 nibbles (2 bytes) of the key.
    pub fn entries_in_bucket(&self, bucket: u16) -> BucketIter<'_> {
        BucketIter {
            store: self,
            bucket,
            keys: self.bucket_index.get(&bucket).map(|v| v.as_slice()),
            pos: 0,
        }
    }

    /// Returns all keys in a bucket.
    pub fn keys_in_bucket(&self, bucket: u16) -> Option<&[[u8; 32]]> {
        self.bucket_index.get(&bucket).map(|v| v.as_slice())
    }

    /// Returns an iterator over all entries.
    pub fn iter(&self) -> impl Iterator<Item = (&[u8; 32], &Vec<u8>)> {
        self.data.iter()
    }

    /// Returns an iterator over dirty keys.
    pub fn dirty_iter(&self) -> impl Iterator<Item = (&[u8; 32], &DirtyState)> {
        self.dirty_keys.iter()
    }

    /// Returns true if there are dirty entries.
    pub fn has_dirty(&self) -> bool {
        !self.dirty_keys.is_empty()
    }

    /// Clears dirty tracking.
    pub fn clear_dirty(&mut self) {
        self.dirty_keys.clear();
    }

    /// Collects all entries sorted by key for StackTrie processing.
    ///
    /// This is used when computing the full root hash.
    pub fn sorted_entries(&self) -> Vec<([u8; 32], Vec<u8>)> {
        let mut entries: Vec<_> = self.data.iter()
            .map(|(k, v)| (*k, v.clone()))
            .collect();
        entries.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        entries
    }

    /// Collects entries from dirty buckets, sorted by key.
    ///
    /// This is used for incremental root computation.
    pub fn sorted_entries_in_buckets(&self, buckets: &[u16]) -> Vec<([u8; 32], Vec<u8>)> {
        let mut entries = Vec::new();

        for &bucket in buckets {
            if let Some(keys) = self.bucket_index.get(&bucket) {
                for key in keys {
                    // Skip deleted entries
                    if matches!(self.dirty_keys.get(key), Some(DirtyState::Deleted)) {
                        continue;
                    }
                    if let Some(value) = self.data.get(key) {
                        entries.push((*key, value.clone()));
                    }
                }
            }
        }

        entries.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        entries
    }

    /// Rebuilds the bucket index from scratch.
    ///
    /// Called after loading data or when index is corrupted.
    pub fn rebuild_bucket_index(&mut self) {
        self.bucket_index.clear();

        for key in self.data.keys() {
            let bucket = SubtreeHashCache::key_to_bucket(key);
            self.bucket_index.entry(bucket).or_default().push(*key);
        }
    }
}

impl Default for FlatAccountStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Iterator over entries in a bucket.
pub struct BucketIter<'a> {
    store: &'a FlatAccountStore,
    bucket: u16,
    keys: Option<&'a [[u8; 32]]>,
    pos: usize,
}

impl<'a> Iterator for BucketIter<'a> {
    type Item = ([u8; 32], &'a Vec<u8>);

    fn next(&mut self) -> Option<Self::Item> {
        let keys = self.keys?;

        while self.pos < keys.len() {
            let key = keys[self.pos];
            self.pos += 1;

            // Skip deleted entries
            if matches!(self.store.dirty_keys.get(&key), Some(DirtyState::Deleted)) {
                continue;
            }

            if let Some(value) = self.store.data.get(&key) {
                return Some((key, value));
            }
        }

        None
    }
}

/// Flat storage for contract storage slots.
///
/// Keys are (address_hash, slot_hash) pairs.
/// Values are RLP-encoded storage values (trimmed of leading zeros).
pub struct FlatStorageStore {
    /// In-memory key-value store.
    /// Key: (address_hash, slot_hash), Value: trimmed storage value
    data: FastHashMap<([u8; 32], [u8; 32]), Vec<u8>>,

    /// Index: (address_hash, bucket) -> list of slot_hashes in that bucket.
    /// Enables efficient iteration by bucket within an account's storage.
    bucket_index: FastHashMap<([u8; 32], u16), Vec<[u8; 32]>>,

    /// Dirty tracking per account.
    dirty_accounts: FastHashMap<[u8; 32], FastHashMap<[u8; 32], DirtyState>>,
}

impl FlatStorageStore {
    /// Creates a new empty flat storage store.
    pub fn new() -> Self {
        Self {
            data: FastHashMap::with_hasher(FxBuildHasher),
            bucket_index: FastHashMap::with_hasher(FxBuildHasher),
            dirty_accounts: FastHashMap::with_hasher(FxBuildHasher),
        }
    }

    /// Creates a new flat storage store with expected capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            data: FastHashMap::with_capacity_and_hasher(capacity, FxBuildHasher),
            bucket_index: FastHashMap::with_capacity_and_hasher(capacity / 100, FxBuildHasher),
            dirty_accounts: FastHashMap::with_hasher(FxBuildHasher),
        }
    }

    /// Gets a storage value.
    pub fn get(&self, address_hash: &[u8; 32], slot_hash: &[u8; 32]) -> Option<&Vec<u8>> {
        // Check if deleted
        if let Some(account_dirty) = self.dirty_accounts.get(address_hash) {
            if matches!(account_dirty.get(slot_hash), Some(DirtyState::Deleted)) {
                return None;
            }
        }
        self.data.get(&(*address_hash, *slot_hash))
    }

    /// Sets a storage value.
    pub fn insert(&mut self, address_hash: [u8; 32], slot_hash: [u8; 32], value: Vec<u8>) {
        let bucket = SubtreeHashCache::key_to_bucket(&slot_hash);
        let key = (address_hash, slot_hash);

        // Update bucket index if this is a new slot
        if !self.data.contains_key(&key) {
            self.bucket_index
                .entry((address_hash, bucket))
                .or_default()
                .push(slot_hash);
        }

        self.data.insert(key, value);
        self.dirty_accounts
            .entry(address_hash)
            .or_default()
            .insert(slot_hash, DirtyState::Modified);
    }

    /// Removes a storage value.
    pub fn remove(&mut self, address_hash: &[u8; 32], slot_hash: &[u8; 32]) -> Option<Vec<u8>> {
        self.dirty_accounts
            .entry(*address_hash)
            .or_default()
            .insert(*slot_hash, DirtyState::Deleted);
        self.data.remove(&(*address_hash, *slot_hash))
    }

    /// Returns an iterator over all storage entries for an account.
    pub fn iter_account(&self, address_hash: &[u8; 32]) -> impl Iterator<Item = (&[u8; 32], &Vec<u8>)> {
        let addr = *address_hash;
        self.data.iter()
            .filter(move |((a, _), _)| *a == addr)
            .map(|((_, s), v)| (s, v))
    }

    /// Returns sorted entries for an account's storage.
    pub fn sorted_entries_for_account(&self, address_hash: &[u8; 32]) -> Vec<([u8; 32], Vec<u8>)> {
        let account_dirty = self.dirty_accounts.get(address_hash);

        let mut entries: Vec<_> = self.data.iter()
            .filter(|((a, s), _)| {
                if *a != *address_hash {
                    return false;
                }
                // Skip deleted entries
                if let Some(dirty) = account_dirty {
                    if matches!(dirty.get(s), Some(DirtyState::Deleted)) {
                        return false;
                    }
                }
                true
            })
            .map(|((_, s), v)| (*s, v.clone()))
            .collect();

        entries.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        entries
    }

    /// Returns true if an account has dirty storage.
    pub fn is_account_dirty(&self, address_hash: &[u8; 32]) -> bool {
        self.dirty_accounts.get(address_hash).map_or(false, |m| !m.is_empty())
    }

    /// Clears dirty tracking for an account.
    pub fn clear_account_dirty(&mut self, address_hash: &[u8; 32]) {
        self.dirty_accounts.remove(address_hash);
    }

    /// Clears all dirty tracking.
    pub fn clear_dirty(&mut self) {
        self.dirty_accounts.clear();
    }
}

impl Default for FlatStorageStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::keccak256;

    #[test]
    fn test_flat_account_store_basic() {
        let mut store = FlatAccountStore::new();

        let key = keccak256(b"address1");
        let value = b"account_data".to_vec();

        assert!(store.is_empty());
        store.insert(key, value.clone());

        assert_eq!(store.len(), 1);
        assert_eq!(store.get(&key), Some(&value));
    }

    #[test]
    fn test_flat_account_store_remove() {
        let mut store = FlatAccountStore::new();

        let key = keccak256(b"address1");
        let value = b"account_data".to_vec();

        store.insert(key, value.clone());
        assert!(store.get(&key).is_some());

        store.remove(&key);
        assert!(store.get(&key).is_none());
    }

    #[test]
    fn test_bucket_iteration() {
        let mut store = FlatAccountStore::new();

        // Insert entries that will hash to different buckets
        for i in 0..100u32 {
            let key = keccak256(&i.to_le_bytes());
            let value = format!("account_{}", i).into_bytes();
            store.insert(key, value);
        }

        // Count entries via bucket iteration
        let mut total = 0;
        for bucket in 0..=0xFFFFu16 {
            total += store.entries_in_bucket(bucket).count();
        }

        assert_eq!(total, 100);
    }

    #[test]
    fn test_sorted_entries() {
        let mut store = FlatAccountStore::new();

        for i in 0..10u32 {
            let key = keccak256(&i.to_le_bytes());
            let value = format!("value_{}", i).into_bytes();
            store.insert(key, value);
        }

        let sorted = store.sorted_entries();
        assert_eq!(sorted.len(), 10);

        // Verify sorted order
        for i in 1..sorted.len() {
            assert!(sorted[i-1].0 < sorted[i].0);
        }
    }

    #[test]
    fn test_flat_storage_store() {
        let mut store = FlatStorageStore::new();

        let addr = keccak256(b"contract1");
        let slot = keccak256(b"slot1");
        let value = vec![0x42];

        store.insert(addr, slot, value.clone());
        assert_eq!(store.get(&addr, &slot), Some(&value));

        store.remove(&addr, &slot);
        assert!(store.get(&addr, &slot).is_none());
    }

    #[test]
    fn test_storage_sorted_entries() {
        let mut store = FlatStorageStore::new();

        let addr = keccak256(b"contract1");

        for i in 0..10u32 {
            let slot = keccak256(&i.to_le_bytes());
            let value = vec![i as u8];
            store.insert(addr, slot, value);
        }

        let sorted = store.sorted_entries_for_account(&addr);
        assert_eq!(sorted.len(), 10);

        // Verify sorted order
        for i in 1..sorted.len() {
            assert!(sorted[i-1].0 < sorted[i].0);
        }
    }
}
