//! Subtree Hash Cache - 65536-bucket cache for incremental root computation.
//!
//! This module implements a cache of subtree hashes at depth 4 (65536 buckets).
//! Each bucket covers all keys starting with a given 4-nibble prefix.
//!
//! ## Design
//!
//! - 65536 buckets (16^4) indexed by first 4 nibbles of key
//! - Each bucket stores: hash (32 bytes) + dirty flag
//! - Total storage: ~2MB (65536 * 32 bytes) + 8KB bitmap
//!
//! ## Performance
//!
//! With 1K changes per block across random keys:
//! - ~1K dirty buckets (1.5% of 65536)
//! - Skip 64K+ clean buckets with cached hashes
//! - Only recompute dirty subtrees

use std::io::{self, Read, Write};
use std::fs::File;
use std::path::Path;

use crate::merkle::HASH_SIZE;

/// Number of buckets (depth 4 = 16^4 = 65536).
pub const NUM_BUCKETS: usize = 65536;

/// Size of the hash array in bytes (65536 * 32 = 2MB).
#[allow(dead_code)]
pub const HASH_ARRAY_SIZE: usize = NUM_BUCKETS * HASH_SIZE;

/// Size of the dirty bitmap in bytes (65536 / 8 = 8KB).
pub const DIRTY_BITMAP_SIZE: usize = NUM_BUCKETS / 8;

/// Size of the count array in bytes (65536 * 4 = 256KB).
#[allow(dead_code)]
pub const COUNT_ARRAY_SIZE: usize = NUM_BUCKETS * 4;

/// Cache of subtree hashes at depth 4 (65536 buckets).
///
/// Each bucket covers all keys starting with a given 4-nibble prefix.
/// When entries are modified, the corresponding bucket is marked dirty.
/// During root computation, only dirty buckets need recomputation.
pub struct SubtreeHashCache {
    /// Hash of subtree rooted at each 4-nibble prefix.
    /// Index = nibble[0]*4096 + nibble[1]*256 + nibble[2]*16 + nibble[3]
    /// Using Vec to avoid stack overflow during initialization (2MB array)
    hashes: Vec<[u8; HASH_SIZE]>,

    /// Bitmap of dirty buckets (1 = dirty, needs recomputation).
    dirty: Vec<u8>,

    /// Bitmap of non-empty buckets (1 = has entries).
    non_empty: Vec<u8>,

    /// Number of dirty buckets (for quick check).
    dirty_count: usize,
}

impl SubtreeHashCache {
    /// Creates a new empty cache.
    pub fn new() -> Self {
        Self {
            hashes: vec![[0u8; HASH_SIZE]; NUM_BUCKETS],
            dirty: vec![0u8; DIRTY_BITMAP_SIZE],
            non_empty: vec![0u8; DIRTY_BITMAP_SIZE],
            dirty_count: 0,
        }
    }

    /// Creates a cache with all buckets marked as dirty.
    /// Use this when starting fresh without any cached state.
    pub fn all_dirty() -> Self {
        Self {
            hashes: vec![[0u8; HASH_SIZE]; NUM_BUCKETS],
            dirty: vec![0xFF; DIRTY_BITMAP_SIZE], // All bits set
            non_empty: vec![0u8; DIRTY_BITMAP_SIZE],
            dirty_count: NUM_BUCKETS,
        }
    }

    /// Converts a key to its bucket index (first 4 nibbles).
    #[inline]
    pub fn key_to_bucket(key: &[u8; 32]) -> u16 {
        // First 4 nibbles: key[0] (2 nibbles) + key[1] (2 nibbles)
        ((key[0] as u16) << 8) | (key[1] as u16)
    }

    /// Converts a bucket index to its 4-nibble prefix.
    #[inline]
    pub fn bucket_to_prefix(bucket: u16) -> [u8; 4] {
        [
            ((bucket >> 12) & 0xF) as u8,
            ((bucket >> 8) & 0xF) as u8,
            ((bucket >> 4) & 0xF) as u8,
            (bucket & 0xF) as u8,
        ]
    }

    /// Marks a bucket as dirty.
    #[inline]
    pub fn mark_dirty(&mut self, bucket: u16) {
        let byte_idx = bucket as usize / 8;
        let bit_idx = bucket as usize % 8;
        let mask = 1u8 << bit_idx;

        if self.dirty[byte_idx] & mask == 0 {
            self.dirty[byte_idx] |= mask;
            self.dirty_count += 1;
        }
    }

    /// Marks a bucket as non-empty.
    #[inline]
    pub fn mark_non_empty(&mut self, bucket: u16) {
        let byte_idx = bucket as usize / 8;
        let bit_idx = bucket as usize % 8;
        self.non_empty[byte_idx] |= 1u8 << bit_idx;
    }

    /// Marks a bucket as empty.
    #[inline]
    pub fn mark_empty(&mut self, bucket: u16) {
        let byte_idx = bucket as usize / 8;
        let bit_idx = bucket as usize % 8;
        self.non_empty[byte_idx] &= !(1u8 << bit_idx);
    }

    /// Checks if a bucket is dirty.
    #[inline]
    pub fn is_dirty(&self, bucket: u16) -> bool {
        let byte_idx = bucket as usize / 8;
        let bit_idx = bucket as usize % 8;
        (self.dirty[byte_idx] >> bit_idx) & 1 == 1
    }

    /// Checks if a bucket is non-empty.
    #[inline]
    pub fn is_non_empty(&self, bucket: u16) -> bool {
        let byte_idx = bucket as usize / 8;
        let bit_idx = bucket as usize % 8;
        (self.non_empty[byte_idx] >> bit_idx) & 1 == 1
    }

    /// Returns the number of dirty buckets.
    #[inline]
    pub fn dirty_count(&self) -> usize {
        self.dirty_count
    }

    /// Returns true if any buckets are dirty.
    #[inline]
    pub fn has_dirty(&self) -> bool {
        self.dirty_count > 0
    }

    /// Gets the cached hash for a bucket.
    /// Returns None if the bucket is empty.
    #[inline]
    pub fn get_hash(&self, bucket: u16) -> Option<[u8; HASH_SIZE]> {
        if self.is_non_empty(bucket) {
            Some(self.hashes[bucket as usize])
        } else {
            None
        }
    }

    /// Sets the hash for a bucket and marks it as non-empty and clean.
    #[inline]
    pub fn set_hash(&mut self, bucket: u16, hash: [u8; HASH_SIZE]) {
        self.hashes[bucket as usize] = hash;
        self.mark_non_empty(bucket);

        // Clear dirty flag
        let byte_idx = bucket as usize / 8;
        let bit_idx = bucket as usize % 8;
        let mask = 1u8 << bit_idx;
        if self.dirty[byte_idx] & mask != 0 {
            self.dirty[byte_idx] &= !mask;
            self.dirty_count -= 1;
        }
    }

    /// Clears all dirty flags.
    pub fn clear_dirty(&mut self) {
        self.dirty.fill(0);
        self.dirty_count = 0;
    }

    /// Returns an iterator over dirty bucket indices.
    pub fn dirty_iter(&self) -> DirtyBucketIter<'_> {
        DirtyBucketIter {
            cache: self,
            byte_idx: 0,
            bit_idx: 0,
        }
    }

    /// Returns an iterator over non-empty bucket indices.
    pub fn non_empty_iter(&self) -> NonEmptyBucketIter<'_> {
        NonEmptyBucketIter {
            cache: self,
            byte_idx: 0,
            bit_idx: 0,
        }
    }

    /// Returns an iterator over clean (non-dirty), non-empty bucket indices.
    pub fn clean_non_empty_iter(&self) -> CleanNonEmptyBucketIter<'_> {
        CleanNonEmptyBucketIter {
            cache: self,
            byte_idx: 0,
            bit_idx: 0,
        }
    }

    /// Saves the cache to a file.
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> io::Result<()> {
        let mut file = File::create(path)?;

        // Write hashes (2MB)
        for hash in self.hashes.iter() {
            file.write_all(hash)?;
        }

        // Write dirty bitmap (8KB)
        file.write_all(&*self.dirty)?;

        // Write non-empty bitmap (8KB)
        file.write_all(&*self.non_empty)?;

        file.sync_all()?;
        Ok(())
    }

    /// Loads the cache from a file.
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let mut file = File::open(path)?;

        // Read hashes
        let mut hashes = vec![[0u8; HASH_SIZE]; NUM_BUCKETS];
        for hash in hashes.iter_mut() {
            file.read_exact(hash)?;
        }

        // Read dirty bitmap
        let mut dirty = vec![0u8; DIRTY_BITMAP_SIZE];
        file.read_exact(&mut dirty)?;

        // Read non-empty bitmap
        let mut non_empty = vec![0u8; DIRTY_BITMAP_SIZE];
        file.read_exact(&mut non_empty)?;

        // Count dirty buckets
        let dirty_count = dirty.iter().map(|b| b.count_ones() as usize).sum();

        Ok(Self {
            hashes,
            dirty,
            non_empty,
            dirty_count,
        })
    }

    /// Resets the cache to empty state.
    pub fn clear(&mut self) {
        self.hashes.fill([0u8; HASH_SIZE]);
        self.dirty.fill(0);
        self.non_empty.fill(0);
        self.dirty_count = 0;
    }
}

impl Default for SubtreeHashCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Iterator over dirty bucket indices.
pub struct DirtyBucketIter<'a> {
    cache: &'a SubtreeHashCache,
    byte_idx: usize,
    bit_idx: usize,
}

impl<'a> Iterator for DirtyBucketIter<'a> {
    type Item = u16;

    fn next(&mut self) -> Option<Self::Item> {
        while self.byte_idx < DIRTY_BITMAP_SIZE {
            let byte = self.cache.dirty[self.byte_idx];

            while self.bit_idx < 8 {
                let bucket = (self.byte_idx * 8 + self.bit_idx) as u16;
                self.bit_idx += 1;

                if (byte >> (self.bit_idx - 1)) & 1 == 1 {
                    return Some(bucket);
                }
            }

            self.byte_idx += 1;
            self.bit_idx = 0;
        }
        None
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, Some(self.cache.dirty_count))
    }
}

/// Iterator over non-empty bucket indices.
pub struct NonEmptyBucketIter<'a> {
    cache: &'a SubtreeHashCache,
    byte_idx: usize,
    bit_idx: usize,
}

impl<'a> Iterator for NonEmptyBucketIter<'a> {
    type Item = u16;

    fn next(&mut self) -> Option<Self::Item> {
        while self.byte_idx < DIRTY_BITMAP_SIZE {
            let byte = self.cache.non_empty[self.byte_idx];

            while self.bit_idx < 8 {
                let bucket = (self.byte_idx * 8 + self.bit_idx) as u16;
                self.bit_idx += 1;

                if (byte >> (self.bit_idx - 1)) & 1 == 1 {
                    return Some(bucket);
                }
            }

            self.byte_idx += 1;
            self.bit_idx = 0;
        }
        None
    }
}

/// Iterator over clean (non-dirty), non-empty bucket indices.
pub struct CleanNonEmptyBucketIter<'a> {
    cache: &'a SubtreeHashCache,
    byte_idx: usize,
    bit_idx: usize,
}

impl<'a> Iterator for CleanNonEmptyBucketIter<'a> {
    type Item = u16;

    fn next(&mut self) -> Option<Self::Item> {
        while self.byte_idx < DIRTY_BITMAP_SIZE {
            // Non-empty AND NOT dirty
            let byte = self.cache.non_empty[self.byte_idx] & !self.cache.dirty[self.byte_idx];

            while self.bit_idx < 8 {
                let bucket = (self.byte_idx * 8 + self.bit_idx) as u16;
                self.bit_idx += 1;

                if (byte >> (self.bit_idx - 1)) & 1 == 1 {
                    return Some(bucket);
                }
            }

            self.byte_idx += 1;
            self.bit_idx = 0;
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_cache() {
        let cache = SubtreeHashCache::new();
        assert_eq!(cache.dirty_count(), 0);
        assert!(!cache.has_dirty());
    }

    #[test]
    fn test_all_dirty_cache() {
        let cache = SubtreeHashCache::all_dirty();
        assert_eq!(cache.dirty_count(), NUM_BUCKETS);
        assert!(cache.has_dirty());
    }

    #[test]
    fn test_key_to_bucket() {
        let mut key = [0u8; 32];

        // Test key 0x1234...
        key[0] = 0x12;
        key[1] = 0x34;
        let bucket = SubtreeHashCache::key_to_bucket(&key);
        assert_eq!(bucket, 0x1234);

        // Test key 0xABCD...
        key[0] = 0xAB;
        key[1] = 0xCD;
        let bucket = SubtreeHashCache::key_to_bucket(&key);
        assert_eq!(bucket, 0xABCD);
    }

    #[test]
    fn test_bucket_to_prefix() {
        let prefix = SubtreeHashCache::bucket_to_prefix(0x1234);
        assert_eq!(prefix, [0x1, 0x2, 0x3, 0x4]);

        let prefix = SubtreeHashCache::bucket_to_prefix(0xABCD);
        assert_eq!(prefix, [0xA, 0xB, 0xC, 0xD]);
    }

    #[test]
    fn test_mark_dirty() {
        let mut cache = SubtreeHashCache::new();

        assert!(!cache.is_dirty(0));
        assert_eq!(cache.dirty_count(), 0);

        cache.mark_dirty(0);
        assert!(cache.is_dirty(0));
        assert_eq!(cache.dirty_count(), 1);

        cache.mark_dirty(0); // Should not increment count
        assert_eq!(cache.dirty_count(), 1);

        cache.mark_dirty(100);
        assert!(cache.is_dirty(100));
        assert_eq!(cache.dirty_count(), 2);
    }

    #[test]
    fn test_set_hash() {
        let mut cache = SubtreeHashCache::new();
        let hash = [0xAB; 32];

        cache.mark_dirty(42);
        assert!(cache.is_dirty(42));

        cache.set_hash(42, hash);
        assert!(!cache.is_dirty(42));
        assert!(cache.is_non_empty(42));
        assert_eq!(cache.get_hash(42), Some(hash));
    }

    #[test]
    fn test_dirty_iter() {
        let mut cache = SubtreeHashCache::new();
        cache.mark_dirty(5);
        cache.mark_dirty(100);
        cache.mark_dirty(65535);

        let dirty: Vec<u16> = cache.dirty_iter().collect();
        assert_eq!(dirty.len(), 3);
        assert!(dirty.contains(&5));
        assert!(dirty.contains(&100));
        assert!(dirty.contains(&65535));
    }

    #[test]
    fn test_clear_dirty() {
        let mut cache = SubtreeHashCache::new();
        cache.mark_dirty(5);
        cache.mark_dirty(100);

        assert_eq!(cache.dirty_count(), 2);

        cache.clear_dirty();
        assert_eq!(cache.dirty_count(), 0);
        assert!(!cache.is_dirty(5));
        assert!(!cache.is_dirty(100));
    }
}
