//! Paged Flat Store - PagedDb-backed persistent flat storage.
//!
//! This module provides flat key-value storage backed by the PagedDb infrastructure,
//! designed for the Paprika-style sparse trie architecture.
//!
//! ## Design
//!
//! Instead of storing MPT nodes on disk, we store:
//! 1. **Flat key-value data**: Raw account/storage values (lazy page access)
//! 2. **Bucket index**: Keys organized by first 2 bytes (4 nibbles) for efficient iteration
//!
//! ## Memory Efficiency
//!
//! - Data is memory-mapped through PagedDb
//! - Only accessed pages are loaded into memory
//! - Bucket-based iteration enables streaming sorted access

use std::path::Path;

use hashbrown::HashMap;
use rustc_hash::FxBuildHasher;

use super::paged_db::{PagedDb, DbError, BatchContext};
use super::page_types::{LeafPage, DataPage, BUCKET_COUNT};
use super::{DbAddress, Page, PageHeader, PageType, PAGE_SIZE};
use super::subtree_cache::SubtreeHashCache;

/// Type alias for fast HashMap with FxHash.
type FastHashMap<K, V> = HashMap<K, V, FxBuildHasher>;

/// Flat account storage backed by PagedDb.
///
/// Keys are 32-byte keccak256 hashes of addresses.
/// Values are RLP-encoded account data.
pub struct PagedFlatStore {
    /// The underlying PagedDb instance.
    db: PagedDb,

    /// In-memory write buffer for pending changes.
    /// This is flushed to disk on commit.
    write_buffer: FastHashMap<[u8; 32], Option<Vec<u8>>>,

    /// Bucket index address (root of bucket tree).
    bucket_root: DbAddress,

    /// Dirty tracking: which buckets have been modified.
    dirty_buckets: Vec<bool>,

    /// Cache of bucket page addresses.
    bucket_cache: FastHashMap<u16, DbAddress>,
}

impl PagedFlatStore {
    /// Opens or creates a paged flat store at the given path.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, DbError> {
        let db = PagedDb::open(path)?;
        let bucket_root = DbAddress::page(1); // Reserve page 1 for bucket index

        Ok(Self {
            db,
            write_buffer: FastHashMap::with_hasher(FxBuildHasher),
            bucket_root,
            dirty_buckets: vec![false; 65536],
            bucket_cache: FastHashMap::with_hasher(FxBuildHasher),
        })
    }

    /// Creates a new in-memory paged flat store.
    pub fn in_memory() -> Self {
        Self {
            db: PagedDb::in_memory(),
            write_buffer: FastHashMap::with_hasher(FxBuildHasher),
            bucket_root: DbAddress::NULL,
            dirty_buckets: vec![false; 65536],
            bucket_cache: FastHashMap::with_hasher(FxBuildHasher),
        }
    }

    /// Gets a value by key.
    ///
    /// First checks the write buffer, then falls back to disk.
    pub fn get(&self, key: &[u8; 32]) -> Option<Vec<u8>> {
        // Check write buffer first
        if let Some(maybe_value) = self.write_buffer.get(key) {
            return maybe_value.clone();
        }

        // Check disk
        self.get_from_disk(key)
    }

    /// Gets a value from disk storage.
    fn get_from_disk(&self, key: &[u8; 32]) -> Option<Vec<u8>> {
        if self.bucket_root.is_null() {
            return None;
        }

        let bucket = SubtreeHashCache::key_to_bucket(key);
        let bucket_addr = self.get_bucket_addr(bucket)?;

        // Read the bucket page and search for the key
        self.search_bucket_for_key(bucket_addr, key)
    }

    /// Gets the page address for a bucket.
    fn get_bucket_addr(&self, bucket: u16) -> Option<DbAddress> {
        // Check cache
        if let Some(&addr) = self.bucket_cache.get(&bucket) {
            return if addr.is_null() { None } else { Some(addr) };
        }

        // Read from bucket index (stored as a B-tree or flat array)
        // For simplicity, we use a two-level index: first byte -> page, second byte -> slot
        let high = (bucket >> 8) as usize;
        let low = (bucket & 0xFF) as usize;

        // Read top-level index page
        let index_page = self.db.read_page(self.bucket_root)?;
        let data_page = DataPage::wrap(index_page);

        // Get second-level index address
        let second_addr = data_page.get_bucket(high);
        if second_addr.is_null() {
            return None;
        }

        // Read second-level index page
        let second_page = self.db.read_page(second_addr)?;
        let second_data = DataPage::wrap(second_page);

        let bucket_addr = second_data.get_bucket(low);
        if bucket_addr.is_null() {
            None
        } else {
            Some(bucket_addr)
        }
    }

    /// Searches a bucket page for a specific key.
    fn search_bucket_for_key(&self, bucket_addr: DbAddress, key: &[u8; 32]) -> Option<Vec<u8>> {
        let page = self.db.read_page(bucket_addr)?;
        let leaf = LeafPage::wrap(page);

        // Linear search through the bucket (could be optimized with binary search)
        let data = leaf.data();
        let mut offset = 0;

        while offset + 36 <= data.len() {
            // Each entry: key (32 bytes) + value_len (4 bytes) + value
            let entry_key = &data[offset..offset + 32];
            if entry_key == key {
                let value_len = u32::from_le_bytes([
                    data[offset + 32],
                    data[offset + 33],
                    data[offset + 34],
                    data[offset + 35],
                ]) as usize;

                if offset + 36 + value_len <= data.len() {
                    return Some(data[offset + 36..offset + 36 + value_len].to_vec());
                }
            }

            // Skip to next entry
            let value_len = u32::from_le_bytes([
                data[offset + 32],
                data[offset + 33],
                data[offset + 34],
                data[offset + 35],
            ]) as usize;
            offset += 36 + value_len;
        }

        None
    }

    /// Inserts a key-value pair.
    ///
    /// The change is buffered until commit().
    pub fn insert(&mut self, key: [u8; 32], value: Vec<u8>) {
        let bucket = SubtreeHashCache::key_to_bucket(&key);
        self.dirty_buckets[bucket as usize] = true;
        self.write_buffer.insert(key, Some(value));
    }

    /// Removes a key.
    ///
    /// The change is buffered until commit().
    pub fn remove(&mut self, key: &[u8; 32]) {
        let bucket = SubtreeHashCache::key_to_bucket(key);
        self.dirty_buckets[bucket as usize] = true;
        self.write_buffer.insert(*key, None);
    }

    /// Returns the number of buffered changes.
    pub fn pending_count(&self) -> usize {
        self.write_buffer.len()
    }

    /// Returns true if there are pending changes.
    pub fn has_pending(&self) -> bool {
        !self.write_buffer.is_empty()
    }

    /// Commits all pending changes to disk.
    pub fn commit(&mut self) -> Result<(), DbError> {
        if self.write_buffer.is_empty() {
            return Ok(());
        }

        // Group changes by bucket
        let mut buckets: FastHashMap<u16, Vec<([u8; 32], Option<Vec<u8>>)>> =
            FastHashMap::with_hasher(FxBuildHasher);

        for (key, value) in self.write_buffer.drain() {
            let bucket = SubtreeHashCache::key_to_bucket(&key);
            buckets.entry(bucket).or_default().push((key, value));
        }

        // Apply changes bucket by bucket
        let mut batch = self.db.begin_batch();

        for (bucket, changes) in buckets {
            self.apply_bucket_changes(&mut batch, bucket, changes)?;
        }

        // Commit the batch
        self.db.commit_batch(batch)?;

        // Clear dirty tracking
        self.dirty_buckets.fill(false);

        Ok(())
    }

    /// Applies changes to a single bucket.
    fn apply_bucket_changes(
        &mut self,
        batch: &mut BatchContext,
        bucket: u16,
        changes: Vec<([u8; 32], Option<Vec<u8>>)>,
    ) -> Result<(), DbError> {
        // Get or create bucket page
        let bucket_addr = self.ensure_bucket_page(batch, bucket)?;

        // Read existing entries
        let mut entries: FastHashMap<[u8; 32], Vec<u8>> =
            FastHashMap::with_hasher(FxBuildHasher);

        if let Some(page) = self.db.read_page(bucket_addr) {
            let leaf = LeafPage::wrap(page);
            let data = leaf.data();
            let mut offset = 0;

            while offset + 36 <= data.len() {
                let mut key = [0u8; 32];
                key.copy_from_slice(&data[offset..offset + 32]);

                let value_len = u32::from_le_bytes([
                    data[offset + 32],
                    data[offset + 33],
                    data[offset + 34],
                    data[offset + 35],
                ]) as usize;

                if offset + 36 + value_len <= data.len() {
                    entries.insert(key, data[offset + 36..offset + 36 + value_len].to_vec());
                }

                offset += 36 + value_len;
            }
        }

        // Apply changes
        for (key, value) in changes {
            match value {
                Some(v) => {
                    entries.insert(key, v);
                }
                None => {
                    entries.remove(&key);
                }
            }
        }

        // Write back to page
        let mut leaf = LeafPage::new(batch.batch_id(), 0);
        let data = leaf.data_mut();
        let mut offset = 0;

        for (key, value) in entries {
            let entry_size = 36 + value.len();
            if offset + entry_size > data.len() {
                // Page overflow - would need overflow handling
                // For now, just truncate (production would use multiple pages)
                break;
            }

            data[offset..offset + 32].copy_from_slice(&key);
            data[offset + 32..offset + 36].copy_from_slice(&(value.len() as u32).to_le_bytes());
            data[offset + 36..offset + 36 + value.len()].copy_from_slice(&value);
            offset += entry_size;
        }

        // Write the page
        batch.write_page(bucket_addr, leaf.into_page());

        Ok(())
    }

    /// Ensures a bucket page exists, creating it if necessary.
    fn ensure_bucket_page(&mut self, batch: &mut BatchContext, bucket: u16) -> Result<DbAddress, DbError> {
        // Check cache
        if let Some(&addr) = self.bucket_cache.get(&bucket) {
            if !addr.is_null() {
                return Ok(addr);
            }
        }

        // Ensure bucket index exists
        if self.bucket_root.is_null() {
            self.bucket_root = batch.allocate_page();
            let index_page = DataPage::new(batch.batch_id(), 0);
            batch.write_page(self.bucket_root, index_page.into_page());
        }

        let high = (bucket >> 8) as usize;
        let low = (bucket & 0xFF) as usize;

        // Ensure top-level index page exists
        let index_page = self.db.read_page(self.bucket_root)
            .unwrap_or_else(|| {
                let p = DataPage::new(batch.batch_id(), 0);
                p.into_page()
            });
        let mut data_page = DataPage::wrap(index_page);

        // Ensure second-level index exists
        let mut second_addr = data_page.get_bucket(high);
        if second_addr.is_null() {
            second_addr = batch.allocate_page();
            let second_page = DataPage::new(batch.batch_id(), 1);
            batch.write_page(second_addr, second_page.into_page());

            data_page.set_bucket(high, second_addr);
            batch.write_page(self.bucket_root, data_page.into_page());
        }

        // Ensure bucket page exists
        let second_page = self.db.read_page(second_addr)
            .unwrap_or_else(|| {
                let p = DataPage::new(batch.batch_id(), 1);
                p.into_page()
            });
        let mut second_data = DataPage::wrap(second_page);

        let mut bucket_addr = second_data.get_bucket(low);
        if bucket_addr.is_null() {
            bucket_addr = batch.allocate_page();
            let leaf_page = LeafPage::new(batch.batch_id(), 2);
            batch.write_page(bucket_addr, leaf_page.into_page());

            second_data.set_bucket(low, bucket_addr);
            batch.write_page(second_addr, second_data.into_page());
        }

        // Update cache
        self.bucket_cache.insert(bucket, bucket_addr);

        Ok(bucket_addr)
    }

    /// Returns an iterator over all entries in sorted order.
    ///
    /// This streams from disk, loading pages as needed.
    pub fn sorted_iter(&self) -> SortedEntryIter<'_> {
        SortedEntryIter::new(self)
    }

    /// Returns sorted entries from specific buckets only.
    ///
    /// This is used for incremental root computation.
    pub fn sorted_entries_in_buckets(&self, buckets: &[u16]) -> Vec<([u8; 32], Vec<u8>)> {
        let mut entries = Vec::new();

        for &bucket in buckets {
            entries.extend(self.entries_in_bucket(bucket));
        }

        // Include buffered entries for these buckets
        for (key, value) in &self.write_buffer {
            let bucket = SubtreeHashCache::key_to_bucket(key);
            if buckets.contains(&bucket) {
                if let Some(v) = value {
                    entries.push((*key, v.clone()));
                }
            }
        }

        entries.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        entries
    }

    /// Returns all entries in a specific bucket.
    fn entries_in_bucket(&self, bucket: u16) -> Vec<([u8; 32], Vec<u8>)> {
        let mut entries = Vec::new();

        // Get from disk
        if let Some(bucket_addr) = self.get_bucket_addr(bucket) {
            if let Some(page) = self.db.read_page(bucket_addr) {
                let leaf = LeafPage::wrap(page);
                let data = leaf.data();
                let mut offset = 0;

                while offset + 36 <= data.len() {
                    let mut key = [0u8; 32];
                    key.copy_from_slice(&data[offset..offset + 32]);

                    let value_len = u32::from_le_bytes([
                        data[offset + 32],
                        data[offset + 33],
                        data[offset + 34],
                        data[offset + 35],
                    ]) as usize;

                    if value_len == 0 || offset + 36 + value_len > data.len() {
                        break;
                    }

                    entries.push((key, data[offset + 36..offset + 36 + value_len].to_vec()));
                    offset += 36 + value_len;
                }
            }
        }

        // Apply buffered changes
        for (key, value) in &self.write_buffer {
            let key_bucket = SubtreeHashCache::key_to_bucket(key);
            if key_bucket == bucket {
                // Remove old entry if it exists
                entries.retain(|(k, _)| k != key);

                // Add new entry if not a deletion
                if let Some(v) = value {
                    entries.push((*key, v.clone()));
                }
            }
        }

        entries
    }

    /// Returns dirty bucket indices.
    pub fn dirty_buckets(&self) -> Vec<u16> {
        self.dirty_buckets.iter()
            .enumerate()
            .filter(|(_, &dirty)| dirty)
            .map(|(i, _)| i as u16)
            .collect()
    }

    /// Clears dirty tracking.
    pub fn clear_dirty(&mut self) {
        self.dirty_buckets.fill(false);
    }

    /// Returns true if there are dirty buckets.
    pub fn has_dirty(&self) -> bool {
        self.dirty_buckets.iter().any(|&d| d)
    }

    /// Closes the store, flushing any pending data.
    pub fn close(mut self) -> Result<(), DbError> {
        self.commit()?;
        Ok(())
    }
}

/// Iterator over all entries in sorted order.
pub struct SortedEntryIter<'a> {
    store: &'a PagedFlatStore,
    current_bucket: u16,
    bucket_entries: Vec<([u8; 32], Vec<u8>)>,
    entry_index: usize,
}

impl<'a> SortedEntryIter<'a> {
    fn new(store: &'a PagedFlatStore) -> Self {
        let mut iter = Self {
            store,
            current_bucket: 0,
            bucket_entries: Vec::new(),
            entry_index: 0,
        };
        iter.load_bucket(0);
        iter
    }

    fn load_bucket(&mut self, bucket: u16) {
        self.current_bucket = bucket;
        self.entry_index = 0;
        self.bucket_entries = self.store.entries_in_bucket(bucket);
        self.bucket_entries.sort_unstable_by(|a, b| a.0.cmp(&b.0));
    }

    fn advance_bucket(&mut self) -> bool {
        while self.current_bucket < 65535 {
            self.load_bucket(self.current_bucket + 1);
            if !self.bucket_entries.is_empty() {
                return true;
            }
        }
        false
    }
}

impl<'a> Iterator for SortedEntryIter<'a> {
    type Item = ([u8; 32], Vec<u8>);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.entry_index < self.bucket_entries.len() {
                let entry = self.bucket_entries[self.entry_index].clone();
                self.entry_index += 1;
                return Some(entry);
            }

            if !self.advance_bucket() {
                return None;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::keccak256;

    #[test]
    fn test_in_memory_basic() {
        let mut store = PagedFlatStore::in_memory();

        let key = keccak256(b"test_key");
        let value = b"test_value".to_vec();

        store.insert(key, value.clone());
        assert_eq!(store.get(&key), Some(value));
    }

    #[test]
    fn test_remove() {
        let mut store = PagedFlatStore::in_memory();

        let key = keccak256(b"test_key");
        let value = b"test_value".to_vec();

        store.insert(key, value);
        assert!(store.get(&key).is_some());

        store.remove(&key);
        assert!(store.get(&key).is_none());
    }

    #[test]
    fn test_sorted_entries_in_buckets() {
        let mut store = PagedFlatStore::in_memory();

        // Insert entries into different buckets
        for i in 0..100u32 {
            let key = keccak256(&i.to_le_bytes());
            let value = format!("value_{}", i).into_bytes();
            store.insert(key, value);
        }

        // Get dirty buckets
        let dirty = store.dirty_buckets();
        assert!(!dirty.is_empty());

        // Get sorted entries
        let entries = store.sorted_entries_in_buckets(&dirty);

        // Verify sorted order
        for i in 1..entries.len() {
            assert!(entries[i - 1].0 < entries[i].0);
        }
    }

    #[test]
    fn test_dirty_tracking() {
        let mut store = PagedFlatStore::in_memory();

        assert!(!store.has_dirty());

        let key = keccak256(b"test");
        store.insert(key, b"value".to_vec());

        assert!(store.has_dirty());

        store.clear_dirty();
        assert!(!store.has_dirty());
    }
}
