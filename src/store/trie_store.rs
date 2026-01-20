//! TrieStore - Persistent trie storage using page-based storage with lazy loading.
//!
//! This module bridges the in-memory MerkleTrie with the PagedDb storage,
//! providing a persistent key-value store optimized for trie operations.
//!
//! ## Lazy Loading Architecture
//!
//! Instead of eagerly loading all entries into memory, PagedStateTrie traverses
//! pages on-demand and computes Merkle roots incrementally. This dramatically
//! reduces memory usage and startup time for large state.

use std::cell::RefCell;
use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::Arc;

use lru::LruCache;
use tracing::warn;

use crate::data::{NibblePath, SlottedArray, PAGE_SIZE};
use crate::merkle::{keccak256, MerkleTrie, EMPTY_ROOT};
use crate::store::{DbAddress, PageType, LeafPage, DataPage, BatchContext, PagedDb, DbError};

/// Default LRU cache size for values (1024 entries).
const DEFAULT_VALUE_CACHE_SIZE: usize = 1024;

// ============================================================================
// Core Data Structures for Lazy Loading
// ============================================================================

/// Entry state for dirty tracking.
#[derive(Clone, Debug)]
pub enum DirtyEntry {
    /// Insert or update with new value
    Modified(Vec<u8>),
    /// Deleted
    Deleted,
}

impl DirtyEntry {
    /// Returns the value if this is a Modified entry.
    pub fn value(&self) -> Option<&[u8]> {
        match self {
            DirtyEntry::Modified(v) => Some(v),
            DirtyEntry::Deleted => None,
        }
    }
}

/// Cached subtree hash with validity tracking.
#[derive(Clone, Debug)]
pub struct SubtreeHash {
    /// The cached hash value
    pub hash: [u8; 32],
    /// True if this subtree has dirty descendants
    pub invalidated: bool,
}

// ============================================================================
// PersistentTrie - Still used for eager operations
// ============================================================================

/// Standalone trie that persists to PagedDb on commit.
///
/// This is a simpler approach: keep an in-memory trie and flush to pages
/// when committing. The pages store raw key-value data, and the merkle
/// tree is recomputed on load.
pub struct PersistentTrie {
    /// In-memory trie for operations and root computation
    trie: MerkleTrie,
    /// Pending changes to write on commit
    pending: HashMap<Vec<u8>, Option<Vec<u8>>>, // None = deletion
}

impl PersistentTrie {
    /// Creates a new empty persistent trie.
    pub fn new() -> Self {
        Self {
            trie: MerkleTrie::new(),
            pending: HashMap::new(),
        }
    }

    /// Loads a trie from a LeafPage's data.
    ///
    /// The page contains key-value pairs in a slotted array format.
    pub fn load_from_page(page_data: &[u8]) -> Self {
        let arr = SlottedArray::from_bytes(Self::page_data_to_array(page_data));
        let mut trie = MerkleTrie::new();

        // Reconstruct trie from stored entries using the new iterator
        for (path, value) in arr.iter() {
            // Convert NibblePath back to bytes
            let key = Self::nibble_path_to_bytes(&path);
            trie.insert(&key, value);
        }

        Self {
            trie,
            pending: HashMap::new(),
        }
    }

    /// Converts a NibblePath to its original byte representation.
    pub fn nibble_path_to_bytes(path: &NibblePath) -> Vec<u8> {
        let mut bytes = Vec::with_capacity((path.len() + 1) / 2);
        let mut i = 0;
        while i < path.len() {
            let high = path.get(i);
            let low = if i + 1 < path.len() { path.get(i + 1) } else { 0 };
            bytes.push((high << 4) | low);
            i += 2;
        }
        bytes
    }

    /// Inserts or updates a key-value pair.
    pub fn insert(&mut self, key: &[u8], value: Vec<u8>) {
        self.trie.insert(key, value.clone());
        self.pending.insert(key.to_vec(), Some(value));
    }

    /// Batch insert multiple key-value pairs.
    /// More efficient than individual inserts for bulk operations.
    pub fn insert_batch(&mut self, entries: impl IntoIterator<Item = (Vec<u8>, Vec<u8>)>) {
        let entries: Vec<_> = entries.into_iter().collect();
        for (key, value) in &entries {
            self.pending.insert(key.clone(), Some(value.clone()));
        }
        self.trie.insert_batch(entries);
    }

    /// Batch insert key-value pairs where keys are already 32-byte hashes.
    ///
    /// Optimized for snap sync - skips redundant hashing in bloom filter
    /// since keys are already keccak256 hashes.
    pub fn insert_batch_prehashed(&mut self, entries: impl IntoIterator<Item = ([u8; 32], Vec<u8>)>) {
        let entries: Vec<_> = entries.into_iter().collect();
        for (key, value) in &entries {
            self.pending.insert(key.to_vec(), Some(value.clone()));
        }
        self.trie.insert_batch_prehashed(entries);
    }

    /// Gets a value by key.
    pub fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.trie.get(key).map(|v| v.to_vec())
    }

    /// Removes a key.
    pub fn remove(&mut self, key: &[u8]) {
        self.trie.remove(key);
        self.pending.insert(key.to_vec(), None);
    }

    /// Computes and returns the root hash.
    pub fn root_hash(&mut self) -> [u8; 32] {
        self.trie.root_hash()
    }

    /// Checks if the trie is empty.
    pub fn is_empty(&mut self) -> bool {
        self.root_hash() == EMPTY_ROOT
    }

    /// Returns the number of entries.
    pub fn len(&self) -> usize {
        self.trie.len()
    }

    /// Writes the trie contents to a LeafPage.
    ///
    /// Returns the serialized data that can be stored in a page.
    pub fn to_page_data(&self) -> Vec<u8> {
        let mut arr = SlottedArray::new();

        // Insert all entries from the trie
        for (key, value) in self.trie.iter() {
            let path = NibblePath::from_bytes(key);
            arr.try_insert(&path, value);
        }

        arr.as_bytes().to_vec()
    }

    /// Writes the trie to multiple pages if needed.
    ///
    /// Returns a list of (key_prefix, page_data) pairs for entries that didn't fit.
    pub fn to_pages(&self) -> Vec<Vec<u8>> {
        let mut pages = Vec::new();
        let mut current_arr = SlottedArray::new();

        for (key, value) in self.trie.iter() {
            let path = NibblePath::from_bytes(key);
            if !current_arr.try_insert(&path, value) {
                // Page is full, start a new one
                pages.push(current_arr.as_bytes().to_vec());
                current_arr = SlottedArray::new();
                current_arr.try_insert(&path, value);
            }
        }

        // Don't forget the last page
        if current_arr.live_count() > 0 {
            pages.push(current_arr.as_bytes().to_vec());
        }

        pages
    }

    fn page_data_to_array(data: &[u8]) -> [u8; PAGE_SIZE] {
        let mut arr = [0u8; PAGE_SIZE];
        let len = data.len().min(PAGE_SIZE);
        arr[..len].copy_from_slice(&data[..len]);
        arr
    }

    /// Returns an iterator over all key-value pairs.
    pub fn iter(&self) -> impl Iterator<Item = (&[u8], &[u8])> {
        self.trie.iter()
    }

    /// Clears pending changes after commit.
    pub fn clear_pending(&mut self) {
        self.pending.clear();
    }
}

impl Default for PersistentTrie {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// StateTrie - State trie with storage tries (used for backward compatibility)
// ============================================================================

/// State trie that stores account data.
///
/// Keys are keccak256(address), values are RLP-encoded accounts.
pub struct StateTrie {
    /// The underlying trie
    pub trie: PersistentTrie,
    /// Storage tries per account (keyed by address hash)
    storage_tries: HashMap<[u8; 32], StorageTrie>,
}

impl StateTrie {
    /// Creates a new empty state trie.
    pub fn new() -> Self {
        Self {
            trie: PersistentTrie::new(),
            storage_tries: HashMap::new(),
        }
    }

    /// Gets or creates a storage trie for an account.
    pub fn storage_trie(&mut self, address: &[u8; 20]) -> &mut StorageTrie {
        let key = keccak256(address);
        self.storage_tries.entry(key).or_insert_with(StorageTrie::new)
    }

    /// Gets or creates a storage trie for an account using a pre-hashed address.
    /// Used by snap sync which already has hashed addresses.
    pub fn storage_trie_by_hash(&mut self, address_hash: &[u8; 32]) -> &mut StorageTrie {
        self.storage_tries.entry(*address_hash).or_insert_with(StorageTrie::new)
    }

    /// Gets an account by address.
    pub fn get_account(&self, address: &[u8; 20]) -> Option<AccountData> {
        let key = keccak256(address);
        self.get_account_by_hash(&key)
    }

    /// Gets an account by pre-hashed address.
    /// Used by snap sync which already has hashed addresses.
    pub fn get_account_by_hash(&self, address_hash: &[u8; 32]) -> Option<AccountData> {
        self.trie.get(address_hash).map(|data| AccountData::decode(&data))
    }

    /// Gets a storage value for an account using pre-hashed keys.
    /// Returns None if the account or storage slot doesn't exist.
    pub fn get_storage_by_hash(&self, address_hash: &[u8; 32], slot_hash: &[u8; 32]) -> Option<[u8; 32]> {
        self.storage_tries.get(address_hash)?.get_by_hash(slot_hash)
    }

    /// Sets an account.
    pub fn set_account(&mut self, address: &[u8; 20], account: AccountData) {
        let key = keccak256(address);
        self.set_account_by_hash(&key, account);
    }

    /// Sets an account using a pre-hashed address.
    /// Used by snap sync which already has hashed addresses.
    pub fn set_account_by_hash(&mut self, address_hash: &[u8; 32], account: AccountData) {
        self.trie.insert(address_hash, account.encode());
    }

    /// Sets an account using raw RLP-encoded data (as received from snap sync).
    /// Used by snap sync to avoid re-encoding account data.
    pub fn set_account_raw(&mut self, address_hash: &[u8; 32], rlp_encoded: Vec<u8>) {
        self.trie.insert(address_hash, rlp_encoded);
    }

    /// Batch insert accounts using pre-hashed addresses.
    /// More efficient than individual inserts for bulk operations like snap sync.
    ///
    /// Uses optimized insertion path that:
    /// - Skips redundant keccak256 in bloom filter (keys are already hashes)
    /// - Batches bloom filter updates for better cache locality
    /// - Pre-reserves HashMap capacity
    pub fn set_accounts_batch(&mut self, accounts: impl IntoIterator<Item = ([u8; 32], AccountData)>) {
        let entries = accounts.into_iter().map(|(hash, account)| {
            (hash, account.encode())
        });
        self.trie.insert_batch_prehashed(entries);
    }

    /// Computes the state root hash.
    ///
    /// This first updates all account storage roots, then computes the state root.
    pub fn root_hash(&mut self) -> [u8; 32] {
        // Update storage roots in accounts
        // Collect keys to avoid borrow conflict
        let addr_hashes: Vec<[u8; 32]> = self.storage_tries.keys().cloned().collect();

        for addr_hash in addr_hashes {
            let storage_root = self.storage_tries.get_mut(&addr_hash).unwrap().root_hash();
            if let Some(account_data) = self.trie.get(&addr_hash) {
                let mut account = AccountData::decode(&account_data);
                if account.storage_root != storage_root {
                    account.storage_root = storage_root;
                    self.trie.insert(&addr_hash, account.encode());
                }
            }
        }

        self.trie.root_hash()
    }

    /// Flushes all storage tries to free memory.
    ///
    /// This computes the storage root for each account's storage trie,
    /// updates the account's storage_root field, and then clears the
    /// storage tries from memory. This is essential for memory-efficient
    /// snap sync with large state.
    ///
    /// Returns the number of storage tries that were flushed.
    pub fn flush_storage_tries(&mut self) -> usize {
        let count = self.storage_tries.len();

        // Drain all storage tries, computing roots and updating accounts
        for (addr_hash, mut storage_trie) in self.storage_tries.drain() {
            let storage_root = storage_trie.root_hash();

            // Update the account's storage_root if we have the account
            if let Some(account_data) = self.trie.get(&addr_hash) {
                let mut account = AccountData::decode(&account_data);
                if account.storage_root != storage_root {
                    account.storage_root = storage_root;
                    self.trie.insert(&addr_hash, account.encode());
                }
            } else {
                // This indicates a data inconsistency - we have storage for an account that
                // doesn't exist in the state trie. The storage data will be lost.
                warn!(
                    "flush_storage_tries: orphaned storage trie for missing account {:?}, storage root: {:?}",
                    addr_hash, storage_root
                );
            }
            // storage_trie is dropped here, freeing its memory
        }

        count
    }

    /// Returns the number of storage tries currently in memory.
    pub fn storage_trie_count(&self) -> usize {
        self.storage_tries.len()
    }

    /// Checks if a storage trie exists for an account.
    pub fn has_storage_trie(&self, address_hash: &[u8; 32]) -> bool {
        self.storage_tries.contains_key(address_hash)
    }

    /// Updates an account's storage_root field.
    ///
    /// Used after storage healing to set EMPTY_TRIE_HASH for accounts
    /// that had no storage returned during healing.
    pub fn update_account_storage_root(&mut self, address_hash: &[u8; 32], storage_root: [u8; 32]) {
        if let Some(account_data) = self.trie.get(address_hash) {
            let mut account = AccountData::decode(&account_data);
            if account.storage_root != storage_root {
                account.storage_root = storage_root;
                self.trie.insert(address_hash, account.encode());
            }
        }
    }
}

impl Default for StateTrie {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// StorageTrie - Storage trie for a single account
// ============================================================================

/// Storage trie for a single account's storage.
///
/// Keys are keccak256(slot), values are RLP-encoded storage values.
pub struct StorageTrie {
    trie: PersistentTrie,
}

impl StorageTrie {
    /// Creates a new empty storage trie.
    pub fn new() -> Self {
        Self {
            trie: PersistentTrie::new(),
        }
    }

    /// Gets a storage value.
    pub fn get(&self, slot: &[u8; 32]) -> Option<[u8; 32]> {
        let key = keccak256(slot);
        self.get_by_hash(&key)
    }

    /// Gets a storage value using a pre-hashed slot key.
    /// Used by snap sync which already has hashed keys.
    pub fn get_by_hash(&self, slot_hash: &[u8; 32]) -> Option<[u8; 32]> {
        self.trie.get(slot_hash).map(|v| {
            let mut arr = [0u8; 32];
            let len = v.len().min(32);
            arr[32 - len..].copy_from_slice(&v[v.len() - len..]);
            arr
        })
    }

    /// Sets a storage value.
    pub fn set(&mut self, slot: &[u8; 32], value: [u8; 32]) {
        let key = keccak256(slot);
        self.set_by_hash(&key, value);
    }

    /// Sets a storage value using a pre-hashed slot key.
    /// Used by snap sync which already has hashed keys.
    pub fn set_by_hash(&mut self, slot_hash: &[u8; 32], value: [u8; 32]) {
        // RLP encode the value (strip leading zeros)
        let trimmed: Vec<u8> = value.iter().skip_while(|&&b| b == 0).copied().collect();
        if trimmed.is_empty() {
            self.trie.remove(slot_hash);
        } else {
            self.trie.insert(slot_hash, trimmed);
        }
    }

    /// Batch set storage values using pre-hashed slot keys.
    /// More efficient than individual sets for bulk operations like snap sync.
    ///
    /// Uses optimized insertion path that:
    /// - Skips redundant keccak256 in bloom filter (keys are already hashes)
    /// - Batches bloom filter updates for better cache locality
    /// - Pre-reserves HashMap capacity
    pub fn set_batch_by_hash(&mut self, entries: impl IntoIterator<Item = ([u8; 32], [u8; 32])>) {
        let trie_entries: Vec<_> = entries.into_iter().filter_map(|(slot_hash, value)| {
            let trimmed: Vec<u8> = value.iter().skip_while(|&&b| b == 0).copied().collect();
            if trimmed.is_empty() {
                None // Skip zero values (they're deletions)
            } else {
                Some((slot_hash, trimmed))
            }
        }).collect();
        self.trie.insert_batch_prehashed(trie_entries);
    }

    /// Sets a storage value using raw RLP-encoded data (as received from snap sync).
    /// Used by snap sync to avoid re-encoding storage values.
    pub fn set_raw(&mut self, slot_hash: &[u8; 32], rlp_encoded: Vec<u8>) {
        if rlp_encoded.is_empty() {
            self.trie.remove(slot_hash);
        } else {
            self.trie.insert(slot_hash, rlp_encoded);
        }
    }

    /// Computes the storage root hash.
    pub fn root_hash(&mut self) -> [u8; 32] {
        self.trie.root_hash()
    }
}

impl Default for StorageTrie {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// AccountData - Account data stored in the state trie
// ============================================================================

/// Account data stored in the state trie.
#[derive(Clone, Debug, Default)]
pub struct AccountData {
    pub nonce: u64,
    pub balance: [u8; 32], // U256 as big-endian bytes
    pub storage_root: [u8; 32],
    pub code_hash: [u8; 32],
}

impl AccountData {
    /// Empty account code hash (keccak256 of empty bytes).
    pub const EMPTY_CODE_HASH: [u8; 32] = [
        0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c,
        0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7, 0x03, 0xc0,
        0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b,
        0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85, 0xa4, 0x70,
    ];

    /// Creates a new empty account.
    pub fn empty() -> Self {
        Self {
            nonce: 0,
            balance: [0u8; 32],
            storage_root: EMPTY_ROOT,
            code_hash: Self::EMPTY_CODE_HASH,
        }
    }

    /// RLP encodes the account data.
    pub fn encode(&self) -> Vec<u8> {
        use crate::merkle::RlpEncoder;
        let mut enc = RlpEncoder::new();
        enc.encode_list(|e| {
            e.encode_u64(self.nonce);
            // Encode balance (trim leading zeros)
            let balance_trimmed: Vec<u8> = self.balance.iter().skip_while(|&&b| b == 0).copied().collect();
            if balance_trimmed.is_empty() {
                e.encode_empty();
            } else {
                e.encode_bytes(&balance_trimmed);
            }
            e.encode_bytes(&self.storage_root);
            e.encode_bytes(&self.code_hash);
        });
        enc.into_bytes()
    }

    /// Decodes account data from RLP bytes.
    pub fn decode(data: &[u8]) -> Self {
        // Simple RLP decoder for account
        // Format: [nonce, balance, storage_root, code_hash]
        // This is a simplified decoder - a production version would be more robust

        if data.is_empty() || data[0] < 0xc0 {
            return Self::empty();
        }

        // Skip list header
        let (header_len, _list_len) = Self::decode_length(data);
        let mut pos = header_len;

        // Decode nonce
        let (nonce, len) = Self::decode_u64(&data[pos..]);
        pos += len;

        // Decode balance
        let (balance, len) = Self::decode_bytes(&data[pos..]);
        pos += len;
        let mut balance_arr = [0u8; 32];
        let offset = 32 - balance.len().min(32);
        balance_arr[offset..].copy_from_slice(&balance[..balance.len().min(32)]);

        // Decode storage_root
        let (storage, len) = Self::decode_bytes(&data[pos..]);
        pos += len;
        let mut storage_root = [0u8; 32];
        if storage.len() == 32 {
            storage_root.copy_from_slice(&storage);
        }

        // Decode code_hash
        let (code, _len) = Self::decode_bytes(&data[pos..]);
        let mut code_hash = Self::EMPTY_CODE_HASH;
        if code.len() == 32 {
            code_hash.copy_from_slice(&code);
        }

        Self {
            nonce,
            balance: balance_arr,
            storage_root,
            code_hash,
        }
    }

    fn decode_length(data: &[u8]) -> (usize, usize) {
        if data.is_empty() {
            return (0, 0);
        }
        let prefix = data[0];
        if prefix <= 0xbf {
            if prefix < 0x80 {
                (0, 1)
            } else if prefix <= 0xb7 {
                (1, (prefix - 0x80) as usize)
            } else {
                let len_of_len = (prefix - 0xb7) as usize;
                let mut len = 0usize;
                for i in 0..len_of_len {
                    len = (len << 8) | data[1 + i] as usize;
                }
                (1 + len_of_len, len)
            }
        } else if prefix <= 0xf7 {
            (1, (prefix - 0xc0) as usize)
        } else {
            let len_of_len = (prefix - 0xf7) as usize;
            let mut len = 0usize;
            for i in 0..len_of_len {
                len = (len << 8) | data[1 + i] as usize;
            }
            (1 + len_of_len, len)
        }
    }

    fn decode_u64(data: &[u8]) -> (u64, usize) {
        if data.is_empty() {
            return (0, 0);
        }
        let prefix = data[0];
        if prefix < 0x80 {
            (prefix as u64, 1)
        } else if prefix == 0x80 {
            (0, 1)
        } else if prefix <= 0xb7 {
            let len = (prefix - 0x80) as usize;
            let mut value = 0u64;
            for i in 0..len {
                value = (value << 8) | data[1 + i] as u64;
            }
            (value, 1 + len)
        } else {
            (0, 1)
        }
    }

    fn decode_bytes(data: &[u8]) -> (Vec<u8>, usize) {
        if data.is_empty() {
            return (vec![], 0);
        }
        let (header_len, content_len) = Self::decode_length(data);
        if content_len == 0 {
            return (vec![], header_len.max(1));
        }
        let start = header_len;
        let end = start + content_len;
        if end > data.len() {
            return (vec![], header_len);
        }
        (data[start..end].to_vec(), header_len + content_len)
    }
}

// ============================================================================
// LazyStorageTrie - Lazy loading storage trie
// ============================================================================

/// Lazy loading storage trie for a single account.
///
/// Instead of loading all storage slots into memory, this traverses
/// pages on demand and tracks dirty entries for incremental updates.
pub struct LazyStorageTrie {
    /// Database reference for page access
    db: Arc<PagedDb>,
    /// Root page address
    root_addr: DbAddress,
    /// LRU cache for recently accessed values
    value_cache: RefCell<LruCache<[u8; 32], Vec<u8>>>,
    /// Dirty entries tracking modifications
    dirty: HashMap<[u8; 32], DirtyEntry>,
    /// Cached subtree hashes per page address
    subtree_hashes: HashMap<DbAddress, SubtreeHash>,
    /// Cached root hash
    root_hash_cache: Option<[u8; 32]>,
}

impl LazyStorageTrie {
    /// Creates a new empty lazy storage trie.
    pub fn new(db: Arc<PagedDb>) -> Self {
        Self {
            db,
            root_addr: DbAddress::NULL,
            value_cache: RefCell::new(LruCache::new(
                NonZeroUsize::new(DEFAULT_VALUE_CACHE_SIZE).unwrap()
            )),
            dirty: HashMap::new(),
            subtree_hashes: HashMap::new(),
            root_hash_cache: Some(EMPTY_ROOT),
        }
    }

    /// Creates a lazy storage trie from an existing root address.
    pub fn from_root(db: Arc<PagedDb>, root_addr: DbAddress) -> Self {
        Self {
            db,
            root_addr,
            value_cache: RefCell::new(LruCache::new(
                NonZeroUsize::new(DEFAULT_VALUE_CACHE_SIZE).unwrap()
            )),
            dirty: HashMap::new(),
            subtree_hashes: HashMap::new(),
            root_hash_cache: None,
        }
    }

    /// Gets a storage value using a pre-hashed slot key.
    pub fn get_by_hash(&self, slot_hash: &[u8; 32]) -> Option<[u8; 32]> {
        // Check dirty map first
        if let Some(entry) = self.dirty.get(slot_hash) {
            return match entry {
                DirtyEntry::Modified(v) => {
                    let mut arr = [0u8; 32];
                    let len = v.len().min(32);
                    arr[32 - len..].copy_from_slice(&v[v.len() - len..]);
                    Some(arr)
                }
                DirtyEntry::Deleted => None,
            };
        }

        // Check cache
        if let Some(v) = self.value_cache.borrow_mut().get(slot_hash) {
            let mut arr = [0u8; 32];
            let len = v.len().min(32);
            arr[32 - len..].copy_from_slice(&v[v.len() - len..]);
            return Some(arr);
        }

        // Traverse pages to find value
        let value = self.traverse_for_key(slot_hash)?;

        // Cache the result
        self.value_cache.borrow_mut().put(*slot_hash, value.clone());

        let mut arr = [0u8; 32];
        let len = value.len().min(32);
        arr[32 - len..].copy_from_slice(&value[value.len() - len..]);
        Some(arr)
    }

    /// Sets a storage value using a pre-hashed slot key.
    pub fn set_by_hash(&mut self, slot_hash: &[u8; 32], value: [u8; 32]) {
        let trimmed: Vec<u8> = value.iter().skip_while(|&&b| b == 0).copied().collect();

        if trimmed.is_empty() {
            self.dirty.insert(*slot_hash, DirtyEntry::Deleted);
        } else {
            self.dirty.insert(*slot_hash, DirtyEntry::Modified(trimmed.clone()));
            self.value_cache.borrow_mut().put(*slot_hash, trimmed);
        }

        // Invalidate root hash and subtree hashes along the path
        self.root_hash_cache = None;
        self.invalidate_path(slot_hash);
    }

    /// Traverses pages to find a value by key hash.
    fn traverse_for_key(&self, key_hash: &[u8; 32]) -> Option<Vec<u8>> {
        if self.root_addr.is_null() {
            return None;
        }

        let nibbles = Self::key_to_nibbles(key_hash);
        let mut current_addr = self.root_addr;
        let mut nibble_idx = 0;

        while !current_addr.is_null() {
            let page = self.db.get_page(current_addr).ok()?;

            match page.header().get_page_type() {
                Some(PageType::Leaf) => {
                    let leaf = LeafPage::wrap(page);
                    let arr = SlottedArray::from_bytes(Self::payload_to_array(leaf.data()));
                    return self.find_in_slotted_array(&arr, &nibbles[nibble_idx..]);
                }
                Some(PageType::Data) => {
                    let data = DataPage::wrap(page);
                    let bucket_idx = if data.consumed_nibbles() == 2 && nibble_idx + 1 < nibbles.len() {
                        ((nibbles[nibble_idx] as usize) << 4) | (nibbles[nibble_idx + 1] as usize)
                    } else {
                        nibbles[nibble_idx] as usize
                    };
                    current_addr = data.get_bucket(bucket_idx);
                    nibble_idx += data.consumed_nibbles();
                }
                _ => return None,
            }
        }

        None
    }

    /// Finds a value in a slotted array by remaining nibble path.
    fn find_in_slotted_array(&self, arr: &SlottedArray, remaining_nibbles: &[u8]) -> Option<Vec<u8>> {
        // Create a nibble path from the remaining nibbles
        let mut bytes = Vec::with_capacity((remaining_nibbles.len() + 1) / 2);
        let mut i = 0;
        while i < remaining_nibbles.len() {
            let high = remaining_nibbles[i];
            let low = if i + 1 < remaining_nibbles.len() { remaining_nibbles[i + 1] } else { 0 };
            bytes.push((high << 4) | low);
            i += 2;
        }

        let path = NibblePath::from_bytes(&bytes);
        if remaining_nibbles.len() % 2 == 1 {
            // Odd number of nibbles - need to adjust
            let adjusted_path = path.slice_to(remaining_nibbles.len());
            arr.get(&adjusted_path)
        } else {
            arr.get(&path)
        }
    }

    /// Invalidates subtree hashes along the path to a key.
    fn invalidate_path(&mut self, key_hash: &[u8; 32]) {
        if self.root_addr.is_null() {
            return;
        }

        let nibbles = Self::key_to_nibbles(key_hash);
        let mut addr = self.root_addr;
        let mut depth = 0;

        while !addr.is_null() {
            if let Some(cached) = self.subtree_hashes.get_mut(&addr) {
                cached.invalidated = true;
            }

            // Navigate to next page
            if let Ok(page) = self.db.get_page(addr) {
                match page.header().get_page_type() {
                    Some(PageType::Data) => {
                        let data = DataPage::wrap(page);
                        let consumed = data.consumed_nibbles();
                        if depth + consumed <= nibbles.len() {
                            let bucket_idx = if consumed == 2 && depth + 1 < nibbles.len() {
                                ((nibbles[depth] as usize) << 4) | (nibbles[depth + 1] as usize)
                            } else {
                                nibbles[depth] as usize
                            };
                            addr = data.get_bucket(bucket_idx);
                            depth += consumed;
                        } else {
                            break;
                        }
                    }
                    _ => break,
                }
            } else {
                break;
            }
        }
    }

    /// Converts a key hash to nibbles.
    fn key_to_nibbles(key: &[u8; 32]) -> Vec<u8> {
        let mut nibbles = Vec::with_capacity(64);
        for byte in key {
            nibbles.push(byte >> 4);
            nibbles.push(byte & 0x0F);
        }
        nibbles
    }

    fn payload_to_array(data: &[u8]) -> [u8; PAGE_SIZE] {
        let mut arr = [0u8; PAGE_SIZE];
        let len = data.len().min(PAGE_SIZE);
        arr[..len].copy_from_slice(&data[..len]);
        arr
    }

    /// Computes the storage root hash.
    pub fn root_hash(&mut self) -> [u8; 32] {
        if self.dirty.is_empty() {
            if let Some(cached) = self.root_hash_cache {
                return cached;
            }
        }

        // For now, use a simpler approach: collect all entries and compute hash
        let hash = self.compute_full_root_hash();
        self.root_hash_cache = Some(hash);
        hash
    }

    /// Computes the full root hash by collecting all entries.
    fn compute_full_root_hash(&self) -> [u8; 32] {
        // Collect all entries from pages
        let mut entries: HashMap<[u8; 32], Vec<u8>> = HashMap::new();

        if !self.root_addr.is_null() {
            self.collect_entries_from_pages(self.root_addr, &[], &mut entries);
        }

        // Apply dirty entries
        for (key, entry) in &self.dirty {
            match entry {
                DirtyEntry::Modified(v) => {
                    entries.insert(*key, v.clone());
                }
                DirtyEntry::Deleted => {
                    entries.remove(key);
                }
            }
        }

        if entries.is_empty() {
            return EMPTY_ROOT;
        }

        // Build merkle trie and compute root
        let mut trie = MerkleTrie::new();
        for (key, value) in entries {
            trie.insert(&key, value);
        }
        trie.root_hash()
    }

    /// Collects all entries from pages recursively.
    fn collect_entries_from_pages(
        &self,
        addr: DbAddress,
        prefix_nibbles: &[u8],
        entries: &mut HashMap<[u8; 32], Vec<u8>>,
    ) {
        if addr.is_null() {
            return;
        }

        let page = match self.db.get_page(addr) {
            Ok(p) => p,
            Err(_) => return,
        };

        match page.header().get_page_type() {
            Some(PageType::Leaf) => {
                let leaf = LeafPage::wrap(page);
                let arr = SlottedArray::from_bytes(Self::payload_to_array(leaf.data()));

                for (path, value) in arr.iter() {
                    // Reconstruct full key from prefix + path
                    let key_bytes = PersistentTrie::nibble_path_to_bytes(&path);
                    if key_bytes.len() == 32 {
                        let mut key = [0u8; 32];
                        key.copy_from_slice(&key_bytes);
                        entries.insert(key, value);
                    }
                }
            }
            Some(PageType::Data) => {
                let data = DataPage::wrap(page);
                let consumed = data.consumed_nibbles();

                for i in 0..256 {
                    let child_addr = data.get_bucket(i);
                    if !child_addr.is_null() {
                        let mut child_prefix = prefix_nibbles.to_vec();
                        if consumed == 2 {
                            child_prefix.push((i >> 4) as u8);
                            child_prefix.push((i & 0x0F) as u8);
                        } else {
                            child_prefix.push(i as u8);
                        }
                        self.collect_entries_from_pages(child_addr, &child_prefix, entries);
                    }
                }
            }
            _ => {}
        }
    }

    /// Returns whether the trie has dirty entries.
    pub fn is_dirty(&self) -> bool {
        !self.dirty.is_empty()
    }

    /// Clears dirty entries after save.
    pub fn clear_dirty(&mut self) {
        self.dirty.clear();
        self.subtree_hashes.clear();
    }
}

// ============================================================================
// PagedStateTrie - Full integration with PagedDb (Lazy Loading)
// ============================================================================

/// A state trie that persists to PagedDb with lazy loading.
///
/// Uses DataPage for fanout navigation and LeafPage for actual data storage.
/// Instead of loading all entries eagerly, traverses pages on demand and
/// tracks dirty entries for incremental updates.
pub struct PagedStateTrie {
    /// Database reference for page access
    db: Arc<PagedDb>,
    /// Root page address
    root_addr: DbAddress,
    /// LRU cache for recently accessed account values (key_hash -> encoded_value)
    value_cache: RefCell<LruCache<[u8; 32], Vec<u8>>>,
    /// Dirty entries tracking account modifications
    dirty: HashMap<[u8; 32], DirtyEntry>,
    /// Cached subtree hashes per page address (for incremental root)
    subtree_hashes: HashMap<DbAddress, SubtreeHash>,
    /// Lazy storage tries per account (keyed by address hash)
    storage_tries: HashMap<[u8; 32], LazyStorageTrie>,
    /// Cached root hash
    root_hash_cache: Option<[u8; 32]>,
    /// Fallback eager state trie for compatibility (used when db is None)
    eager_state: Option<StateTrie>,
}

impl PagedStateTrie {
    /// Creates a new empty paged state trie.
    pub fn new() -> Self {
        Self {
            db: Arc::new(PagedDb::in_memory(100).unwrap()),
            root_addr: DbAddress::NULL,
            value_cache: RefCell::new(LruCache::new(
                NonZeroUsize::new(DEFAULT_VALUE_CACHE_SIZE).unwrap()
            )),
            dirty: HashMap::new(),
            subtree_hashes: HashMap::new(),
            storage_tries: HashMap::new(),
            root_hash_cache: Some(EMPTY_ROOT),
            eager_state: Some(StateTrie::new()),
        }
    }

    /// Creates a new lazy paged state trie with a database reference.
    pub fn new_lazy(db: Arc<PagedDb>) -> Self {
        Self {
            db,
            root_addr: DbAddress::NULL,
            value_cache: RefCell::new(LruCache::new(
                NonZeroUsize::new(DEFAULT_VALUE_CACHE_SIZE).unwrap()
            )),
            dirty: HashMap::new(),
            subtree_hashes: HashMap::new(),
            storage_tries: HashMap::new(),
            root_hash_cache: Some(EMPTY_ROOT),
            eager_state: None,
        }
    }

    /// Creates a lazy paged state trie from an existing root address.
    pub fn from_root(db: Arc<PagedDb>, root_addr: DbAddress) -> Self {
        Self {
            db,
            root_addr,
            value_cache: RefCell::new(LruCache::new(
                NonZeroUsize::new(DEFAULT_VALUE_CACHE_SIZE).unwrap()
            )),
            dirty: HashMap::new(),
            subtree_hashes: HashMap::new(),
            storage_tries: HashMap::new(),
            root_hash_cache: None,
            eager_state: None,
        }
    }

    /// Loads a state trie from PagedDb.
    ///
    /// With lazy loading, this just stores the root address - no eager loading.
    pub fn load(db: &PagedDb, root_addr: DbAddress) -> Result<Self, DbError> {
        if root_addr.is_null() {
            return Ok(Self::new());
        }

        // For now, maintain backward compatibility with eager loading
        // TODO: Return lazy trie once all callers are updated
        let mut state = StateTrie::new();

        // Load the root page
        let root_page = db.get_page(root_addr)?;
        let page_type = root_page.header().get_page_type();

        match page_type {
            Some(PageType::Leaf) => {
                // Simple case: all data in a single leaf page
                let leaf = LeafPage::wrap(root_page);
                let arr = SlottedArray::from_bytes(Self::payload_to_array(leaf.data()));

                for (path, value) in arr.iter() {
                    let key = PersistentTrie::nibble_path_to_bytes(&path);
                    // Decode as account data
                    let _account = AccountData::decode(&value);
                    // Convert key back to address (it's keccak256 of address, but we store the hash)
                    let mut addr_hash = [0u8; 32];
                    let copy_len = key.len().min(32);
                    addr_hash[..copy_len].copy_from_slice(&key[..copy_len]);
                    // Insert directly into the underlying trie
                    state.trie.insert(&addr_hash, value);
                }
            }
            Some(PageType::Data) => {
                // Complex case: fanout structure
                Self::load_from_data_page(db, &root_page, &mut state)?;
            }
            Some(PageType::StateRoot) => {
                // StateRoot page contains references to account and storage tries
                Self::load_from_state_root_page(db, &root_page, &mut state)?;
            }
            _ => {
                // Unknown or empty page type
            }
        }

        Ok(Self {
            db: Arc::new(PagedDb::in_memory(100).unwrap()),
            root_addr: Some(root_addr).unwrap_or(DbAddress::NULL),
            value_cache: RefCell::new(LruCache::new(
                NonZeroUsize::new(DEFAULT_VALUE_CACHE_SIZE).unwrap()
            )),
            dirty: HashMap::new(),
            subtree_hashes: HashMap::new(),
            storage_tries: HashMap::new(),
            root_hash_cache: None,
            eager_state: Some(state),
        })
    }

    fn load_from_data_page(db: &PagedDb, page: &crate::store::Page, state: &mut StateTrie) -> Result<(), DbError> {
        let data_page = DataPage::wrap(page.clone());

        // Iterate through all buckets
        for i in 0..256 {
            let child_addr = data_page.get_bucket(i);
            if !child_addr.is_null() {
                let child_page = db.get_page(child_addr)?;
                let child_type = child_page.header().get_page_type();

                match child_type {
                    Some(PageType::Leaf) => {
                        let leaf = LeafPage::wrap(child_page);
                        let arr = SlottedArray::from_bytes(Self::payload_to_array(leaf.data()));

                        for (path, value) in arr.iter() {
                            let key = PersistentTrie::nibble_path_to_bytes(&path);
                            let mut addr_hash = [0u8; 32];
                            let copy_len = key.len().min(32);
                            addr_hash[..copy_len].copy_from_slice(&key[..copy_len]);
                            state.trie.insert(&addr_hash, value);
                        }
                    }
                    Some(PageType::Data) => {
                        // Recursive fanout
                        Self::load_from_data_page(db, &child_page, state)?;
                    }
                    _ => {}
                }
            }
        }

        Ok(())
    }

    fn load_from_state_root_page(db: &PagedDb, page: &crate::store::Page, state: &mut StateTrie) -> Result<(), DbError> {
        // StateRoot page layout:
        // - First 4 bytes: address of accounts trie root
        // - Remaining: list of (address_hash, storage_trie_addr) pairs
        let data = page.payload();

        if data.len() < 4 {
            return Ok(());
        }

        // Read accounts trie address
        let accounts_addr = DbAddress::read(data);
        if !accounts_addr.is_null() {
            let accounts_page = db.get_page(accounts_addr)?;
            let page_type = accounts_page.header().get_page_type();

            match page_type {
                Some(PageType::Leaf) => {
                    let leaf = LeafPage::wrap(accounts_page);
                    let arr = SlottedArray::from_bytes(Self::payload_to_array(leaf.data()));

                    for (path, value) in arr.iter() {
                        let key = PersistentTrie::nibble_path_to_bytes(&path);
                        let mut addr_hash = [0u8; 32];
                        let copy_len = key.len().min(32);
                        addr_hash[..copy_len].copy_from_slice(&key[..copy_len]);
                        state.trie.insert(&addr_hash, value);
                    }
                }
                Some(PageType::Data) => {
                    Self::load_from_data_page(db, &accounts_page, state)?;
                }
                _ => {}
            }
        }

        Ok(())
    }

    fn payload_to_array(data: &[u8]) -> [u8; PAGE_SIZE] {
        let mut arr = [0u8; PAGE_SIZE];
        let len = data.len().min(PAGE_SIZE);
        arr[..len].copy_from_slice(&data[..len]);
        arr
    }

    // ========================================================================
    // Lazy Get Operations
    // ========================================================================

    /// Gets an account by address.
    pub fn get_account(&self, address: &[u8; 20]) -> Option<AccountData> {
        let key_hash = keccak256(address);
        self.get_account_by_hash(&key_hash)
    }

    /// Gets an account by pre-hashed address.
    pub fn get_account_by_hash(&self, address_hash: &[u8; 32]) -> Option<AccountData> {
        // Use eager state if available (backward compatibility)
        if let Some(ref state) = self.eager_state {
            return state.get_account_by_hash(address_hash);
        }

        // Check dirty map first (pending writes)
        if let Some(entry) = self.dirty.get(address_hash) {
            return match entry {
                DirtyEntry::Modified(v) => Some(AccountData::decode(v)),
                DirtyEntry::Deleted => None,
            };
        }

        // Check value cache
        if let Some(value) = self.value_cache.borrow_mut().get(address_hash) {
            return Some(AccountData::decode(value));
        }

        // Traverse pages to find value
        let value = self.traverse_for_key(address_hash)?;

        // Cache the result
        self.value_cache.borrow_mut().put(*address_hash, value.clone());

        Some(AccountData::decode(&value))
    }

    /// Traverses pages to find a value by key hash.
    fn traverse_for_key(&self, key_hash: &[u8; 32]) -> Option<Vec<u8>> {
        if self.root_addr.is_null() {
            return None;
        }

        let nibbles = Self::key_to_nibbles(key_hash);
        let mut current_addr = self.root_addr;
        let mut nibble_idx = 0;

        while !current_addr.is_null() {
            let page = self.db.get_page(current_addr).ok()?;

            match page.header().get_page_type() {
                Some(PageType::Leaf) => {
                    let leaf = LeafPage::wrap(page);
                    let arr = SlottedArray::from_bytes(Self::payload_to_array(leaf.data()));
                    return self.find_in_slotted_array(&arr, &nibbles[nibble_idx..]);
                }
                Some(PageType::Data) => {
                    let data = DataPage::wrap(page);
                    let consumed = data.consumed_nibbles();
                    if nibble_idx >= nibbles.len() {
                        return None;
                    }
                    let bucket_idx = if consumed == 2 && nibble_idx + 1 < nibbles.len() {
                        ((nibbles[nibble_idx] as usize) << 4) | (nibbles[nibble_idx + 1] as usize)
                    } else {
                        nibbles[nibble_idx] as usize
                    };
                    current_addr = data.get_bucket(bucket_idx);
                    nibble_idx += consumed;
                }
                Some(PageType::StateRoot) => {
                    // Get accounts trie address
                    current_addr = DbAddress::read(&page.payload()[0..4]);
                }
                _ => return None,
            }
        }

        None
    }

    /// Finds a value in a slotted array by remaining nibble path.
    fn find_in_slotted_array(&self, arr: &SlottedArray, remaining_nibbles: &[u8]) -> Option<Vec<u8>> {
        // Create a nibble path from the remaining nibbles
        let mut bytes = Vec::with_capacity((remaining_nibbles.len() + 1) / 2);
        let mut i = 0;
        while i < remaining_nibbles.len() {
            let high = remaining_nibbles[i];
            let low = if i + 1 < remaining_nibbles.len() { remaining_nibbles[i + 1] } else { 0 };
            bytes.push((high << 4) | low);
            i += 2;
        }

        let path = NibblePath::from_bytes(&bytes);
        if remaining_nibbles.len() % 2 == 1 {
            let adjusted_path = path.slice_to(remaining_nibbles.len());
            arr.get(&adjusted_path)
        } else {
            arr.get(&path)
        }
    }

    /// Converts a key hash to nibbles.
    fn key_to_nibbles(key: &[u8; 32]) -> Vec<u8> {
        let mut nibbles = Vec::with_capacity(64);
        for byte in key {
            nibbles.push(byte >> 4);
            nibbles.push(byte & 0x0F);
        }
        nibbles
    }

    /// Gets a storage value for an account using pre-hashed keys.
    pub fn get_storage_by_hash(&self, address_hash: &[u8; 32], slot_hash: &[u8; 32]) -> Option<[u8; 32]> {
        // Use eager state if available
        if let Some(ref state) = self.eager_state {
            return state.get_storage_by_hash(address_hash, slot_hash);
        }

        // Check lazy storage tries
        self.storage_tries.get(address_hash)?.get_by_hash(slot_hash)
    }

    // ========================================================================
    // Write Operations with Dirty Tracking
    // ========================================================================

    /// Sets an account.
    pub fn set_account(&mut self, address: &[u8; 20], account: AccountData) {
        let key_hash = keccak256(address);
        self.set_account_by_hash(&key_hash, account);
    }

    /// Sets an account using a pre-hashed address.
    pub fn set_account_by_hash(&mut self, address_hash: &[u8; 32], account: AccountData) {
        // Use eager state if available
        if let Some(ref mut state) = self.eager_state {
            state.set_account_by_hash(address_hash, account);
            return;
        }

        let encoded = account.encode();

        // Mark as dirty (will be written on save)
        self.dirty.insert(*address_hash, DirtyEntry::Modified(encoded.clone()));

        // Update cache
        self.value_cache.borrow_mut().put(*address_hash, encoded);

        // Invalidate root hash and subtree hashes
        self.root_hash_cache = None;
        self.invalidate_path(address_hash);
    }

    /// Sets an account using raw RLP-encoded data.
    pub fn set_account_raw(&mut self, address_hash: &[u8; 32], rlp_encoded: Vec<u8>) {
        if let Some(ref mut state) = self.eager_state {
            state.set_account_raw(address_hash, rlp_encoded);
            return;
        }

        self.dirty.insert(*address_hash, DirtyEntry::Modified(rlp_encoded.clone()));
        self.value_cache.borrow_mut().put(*address_hash, rlp_encoded);
        self.root_hash_cache = None;
        self.invalidate_path(address_hash);
    }

    /// Batch insert accounts using pre-hashed addresses.
    pub fn set_accounts_batch(&mut self, accounts: impl IntoIterator<Item = ([u8; 32], AccountData)>) {
        if let Some(ref mut state) = self.eager_state {
            state.set_accounts_batch(accounts);
            return;
        }

        for (address_hash, account) in accounts {
            let encoded = account.encode();
            self.dirty.insert(address_hash, DirtyEntry::Modified(encoded.clone()));
            self.value_cache.borrow_mut().put(address_hash, encoded);
        }
        self.root_hash_cache = None;
    }

    /// Invalidates subtree hashes along the path to a key.
    fn invalidate_path(&mut self, key_hash: &[u8; 32]) {
        if self.root_addr.is_null() {
            return;
        }

        let nibbles = Self::key_to_nibbles(key_hash);
        let mut addr = self.root_addr;
        let mut depth = 0;

        while !addr.is_null() {
            if let Some(cached) = self.subtree_hashes.get_mut(&addr) {
                cached.invalidated = true;
            }

            // Navigate to next page
            if let Ok(page) = self.db.get_page(addr) {
                match page.header().get_page_type() {
                    Some(PageType::Data) => {
                        let data = DataPage::wrap(page);
                        let consumed = data.consumed_nibbles();
                        if depth + consumed <= nibbles.len() {
                            let bucket_idx = if consumed == 2 && depth + 1 < nibbles.len() {
                                ((nibbles[depth] as usize) << 4) | (nibbles[depth + 1] as usize)
                            } else {
                                nibbles[depth] as usize
                            };
                            addr = data.get_bucket(bucket_idx);
                            depth += consumed;
                        } else {
                            break;
                        }
                    }
                    _ => break,
                }
            } else {
                break;
            }
        }
    }

    /// Gets the storage trie for an account.
    pub fn storage_trie(&mut self, address: &[u8; 20]) -> &mut StorageTrie {
        if let Some(ref mut state) = self.eager_state {
            return state.storage_trie(address);
        }
        // For lazy mode, we need to return a StorageTrie
        // This is a compatibility issue - we'll use the eager state for now
        panic!("storage_trie() not supported in lazy mode - use storage_trie_by_hash() instead");
    }

    /// Gets the storage trie for an account using a pre-hashed address.
    pub fn storage_trie_by_hash(&mut self, address_hash: &[u8; 32]) -> &mut StorageTrie {
        if let Some(ref mut state) = self.eager_state {
            return state.storage_trie_by_hash(address_hash);
        }
        panic!("storage_trie_by_hash() not supported in lazy mode");
    }

    /// Gets or creates a lazy storage trie for an account.
    pub fn lazy_storage_trie(&mut self, address_hash: &[u8; 32]) -> &mut LazyStorageTrie {
        self.storage_tries.entry(*address_hash).or_insert_with(|| {
            LazyStorageTrie::new(Arc::clone(&self.db))
        })
    }

    // ========================================================================
    // Root Hash Computation
    // ========================================================================

    /// Computes the state root hash.
    pub fn root_hash(&mut self) -> [u8; 32] {
        // Use eager state if available
        if let Some(ref mut state) = self.eager_state {
            return state.root_hash();
        }

        if self.dirty.is_empty() && self.storage_tries.iter().all(|(_, t)| !t.is_dirty()) {
            if let Some(cached) = self.root_hash_cache {
                return cached;
            }
        }

        // Update storage roots in accounts
        let addr_hashes: Vec<[u8; 32]> = self.storage_tries.keys().cloned().collect();
        for addr_hash in addr_hashes {
            let storage_root = self.storage_tries.get_mut(&addr_hash).unwrap().root_hash();

            // Get current account, update storage root if changed
            if let Some(DirtyEntry::Modified(ref data)) = self.dirty.get(&addr_hash) {
                let mut account = AccountData::decode(data);
                if account.storage_root != storage_root {
                    account.storage_root = storage_root;
                    let encoded = account.encode();
                    self.dirty.insert(addr_hash, DirtyEntry::Modified(encoded));
                }
            } else if let Some(value) = self.traverse_for_key(&addr_hash) {
                let mut account = AccountData::decode(&value);
                if account.storage_root != storage_root {
                    account.storage_root = storage_root;
                    self.dirty.insert(addr_hash, DirtyEntry::Modified(account.encode()));
                }
            }
        }

        // Compute full root hash
        let hash = self.compute_full_root_hash();
        self.root_hash_cache = Some(hash);
        hash
    }

    /// Computes the full root hash by collecting all entries.
    fn compute_full_root_hash(&self) -> [u8; 32] {
        // Collect all entries from pages
        let mut entries: HashMap<[u8; 32], Vec<u8>> = HashMap::new();

        if !self.root_addr.is_null() {
            self.collect_entries_from_pages(self.root_addr, &mut entries);
        }

        // Apply dirty entries
        for (key, entry) in &self.dirty {
            match entry {
                DirtyEntry::Modified(v) => {
                    entries.insert(*key, v.clone());
                }
                DirtyEntry::Deleted => {
                    entries.remove(key);
                }
            }
        }

        if entries.is_empty() {
            return EMPTY_ROOT;
        }

        // Build merkle trie and compute root
        let mut trie = MerkleTrie::new();
        for (key, value) in entries {
            trie.insert(&key, value);
        }
        trie.root_hash()
    }

    /// Collects all entries from pages recursively.
    fn collect_entries_from_pages(
        &self,
        addr: DbAddress,
        entries: &mut HashMap<[u8; 32], Vec<u8>>,
    ) {
        if addr.is_null() {
            return;
        }

        let page = match self.db.get_page(addr) {
            Ok(p) => p,
            Err(_) => return,
        };

        match page.header().get_page_type() {
            Some(PageType::Leaf) => {
                let leaf = LeafPage::wrap(page);
                let arr = SlottedArray::from_bytes(Self::payload_to_array(leaf.data()));

                for (path, value) in arr.iter() {
                    let key_bytes = PersistentTrie::nibble_path_to_bytes(&path);
                    if key_bytes.len() == 32 {
                        let mut key = [0u8; 32];
                        key.copy_from_slice(&key_bytes);
                        entries.insert(key, value);
                    }
                }
            }
            Some(PageType::Data) => {
                let data = DataPage::wrap(page);

                for i in 0..256 {
                    let child_addr = data.get_bucket(i);
                    if !child_addr.is_null() {
                        self.collect_entries_from_pages(child_addr, entries);
                    }
                }
            }
            Some(PageType::StateRoot) => {
                let accounts_addr = DbAddress::read(page.payload());
                if !accounts_addr.is_null() {
                    self.collect_entries_from_pages(accounts_addr, entries);
                }
            }
            _ => {}
        }
    }

    // ========================================================================
    // Save Operations
    // ========================================================================

    /// Saves the state trie to PagedDb.
    ///
    /// Returns the root address that can be stored in the RootPage.
    pub fn save(&mut self, batch: &mut BatchContext) -> Result<DbAddress, DbError> {
        // Use eager state if available
        if let Some(ref mut state) = self.eager_state {
            // Compute root hash first (this updates storage roots in accounts)
            let _root_hash = state.root_hash();

            // Collect all account entries (clone to avoid borrow issues)
            let entries: Vec<(Vec<u8>, Vec<u8>)> = state.trie.iter()
                .map(|(k, v)| (k.to_vec(), v.to_vec()))
                .collect();

            if entries.is_empty() {
                return Ok(DbAddress::NULL);
            }

            // Try to fit everything in a single leaf page
            let mut arr = SlottedArray::new();
            let mut all_fit = true;

            for (key, value) in &entries {
                let path = NibblePath::from_bytes(key);
                if !arr.try_insert(&path, value) {
                    all_fit = false;
                    break;
                }
            }

            if all_fit {
                // Everything fits in one page
                let (addr, _page) = batch.allocate_page(PageType::Leaf, 0)?;
                let arr_bytes = arr.as_bytes();

                // Get a mutable copy and write
                let mut leaf_page = batch.get_writable_copy(addr)?;
                let payload = leaf_page.payload_mut();
                let copy_len = payload.len().min(arr_bytes.len());
                payload[..copy_len].copy_from_slice(&arr_bytes[..copy_len]);
                batch.mark_dirty(addr, leaf_page);

                self.root_addr = addr;
                return Ok(addr);
            }

            // Need to use fanout structure
            return Self::save_with_fanout_static(&mut self.root_addr, batch, &entries);
        }

        // Lazy mode save
        if self.dirty.is_empty() && !self.root_addr.is_null() {
            return Ok(self.root_addr);
        }

        // Collect all entries
        let mut entries: HashMap<[u8; 32], Vec<u8>> = HashMap::new();

        if !self.root_addr.is_null() {
            self.collect_entries_from_pages(self.root_addr, &mut entries);
        }

        // Apply dirty entries
        for (key, entry) in &self.dirty {
            match entry {
                DirtyEntry::Modified(v) => {
                    entries.insert(*key, v.clone());
                }
                DirtyEntry::Deleted => {
                    entries.remove(key);
                }
            }
        }

        if entries.is_empty() {
            self.dirty.clear();
            self.subtree_hashes.clear();
            return Ok(DbAddress::NULL);
        }

        // Convert to Vec for saving
        let entries_vec: Vec<(Vec<u8>, Vec<u8>)> = entries
            .into_iter()
            .map(|(k, v)| (k.to_vec(), v))
            .collect();

        // Try to fit everything in a single leaf page
        let mut arr = SlottedArray::new();
        let mut all_fit = true;

        for (key, value) in &entries_vec {
            let path = NibblePath::from_bytes(key);
            if !arr.try_insert(&path, value) {
                all_fit = false;
                break;
            }
        }

        let addr = if all_fit {
            let (addr, _page) = batch.allocate_page(PageType::Leaf, 0)?;
            let arr_bytes = arr.as_bytes();
            let mut leaf_page = batch.get_writable_copy(addr)?;
            let payload = leaf_page.payload_mut();
            let copy_len = payload.len().min(arr_bytes.len());
            payload[..copy_len].copy_from_slice(&arr_bytes[..copy_len]);
            batch.mark_dirty(addr, leaf_page);
            addr
        } else {
            Self::save_with_fanout_static(&mut self.root_addr, batch, &entries_vec)?
        };

        // Clear dirty state
        self.dirty.clear();
        self.subtree_hashes.clear();
        self.root_addr = addr;

        Ok(addr)
    }

    fn save_with_fanout_static(root_addr: &mut DbAddress, batch: &mut BatchContext, entries: &[(Vec<u8>, Vec<u8>)]) -> Result<DbAddress, DbError> {
        // Group entries by first byte (256 buckets)
        let mut buckets: Vec<Vec<(&[u8], &[u8])>> = vec![Vec::new(); 256];

        for (key, value) in entries {
            if !key.is_empty() {
                let bucket_idx = key[0] as usize;
                buckets[bucket_idx].push((key.as_slice(), value.as_slice()));
            }
        }

        // Allocate root data page
        let (addr, _) = batch.allocate_page(PageType::Data, 0)?;
        let root_page = batch.get_writable_copy(addr)?;
        let mut data_page = DataPage::wrap(root_page);

        // Process each bucket
        for (i, bucket_entries) in buckets.iter().enumerate() {
            if bucket_entries.is_empty() {
                continue;
            }

            // Try to fit bucket in a leaf page
            let mut arr = SlottedArray::new();
            let mut all_fit = true;

            for (key, value) in bucket_entries {
                // Skip first byte since it's encoded in the bucket index
                let remaining = if key.len() > 1 { &key[1..] } else { &[] };
                let path = NibblePath::from_bytes(remaining);
                if !arr.try_insert(&path, value) {
                    all_fit = false;
                    break;
                }
            }

            if all_fit {
                // Create leaf page for this bucket
                let (leaf_addr, _) = batch.allocate_page(PageType::Leaf, 1)?;
                let mut leaf_page = batch.get_writable_copy(leaf_addr)?;
                let arr_bytes = arr.as_bytes();
                let payload = leaf_page.payload_mut();
                let copy_len = payload.len().min(arr_bytes.len());
                payload[..copy_len].copy_from_slice(&arr_bytes[..copy_len]);
                batch.mark_dirty(leaf_addr, leaf_page);

                data_page.set_bucket(i, leaf_addr);
            } else {
                // Need recursive fanout (for very large buckets)
                // For now, just split across multiple leaf pages
                let first_leaf = Self::save_bucket_multi_page_static(batch, bucket_entries)?;
                data_page.set_bucket(i, first_leaf);
            }
        }

        batch.mark_dirty(addr, data_page.into_page());
        *root_addr = addr;
        Ok(addr)
    }

    fn save_bucket_multi_page_static(batch: &mut BatchContext, entries: &[(&[u8], &[u8])]) -> Result<DbAddress, DbError> {
        // Simple approach: just create multiple leaf pages and link them
        // In a production implementation, this would use a proper tree structure
        let mut first_addr = DbAddress::NULL;
        let mut arr = SlottedArray::new();

        for (key, value) in entries {
            let remaining = if key.len() > 1 { &key[1..] } else { &[] };
            let path = NibblePath::from_bytes(remaining);

            if !arr.try_insert(&path, value) {
                // Save current page and start new one
                let (addr, _) = batch.allocate_page(PageType::Leaf, 1)?;
                let mut page = batch.get_writable_copy(addr)?;
                let arr_bytes = arr.as_bytes();
                let payload = page.payload_mut();
                let copy_len = payload.len().min(arr_bytes.len());
                payload[..copy_len].copy_from_slice(&arr_bytes[..copy_len]);
                batch.mark_dirty(addr, page);

                if first_addr.is_null() {
                    first_addr = addr;
                }

                arr = SlottedArray::new();
                arr.try_insert(&path, value);
            }
        }

        // Save last page if non-empty
        if arr.live_count() > 0 {
            let (addr, _) = batch.allocate_page(PageType::Leaf, 1)?;
            let mut page = batch.get_writable_copy(addr)?;
            let arr_bytes = arr.as_bytes();
            let payload = page.payload_mut();
            let copy_len = payload.len().min(arr_bytes.len());
            payload[..copy_len].copy_from_slice(&arr_bytes[..copy_len]);
            batch.mark_dirty(addr, page);

            if first_addr.is_null() {
                first_addr = addr;
            }
        }

        Ok(first_addr)
    }

    // ========================================================================
    // Utility Methods
    // ========================================================================

    /// Returns the root address in PagedDb.
    pub fn root_addr(&self) -> Option<DbAddress> {
        if self.root_addr.is_null() {
            None
        } else {
            Some(self.root_addr)
        }
    }

    /// Returns the number of accounts.
    pub fn account_count(&self) -> usize {
        if let Some(ref state) = self.eager_state {
            return state.trie.len();
        }

        // For lazy mode, we need to count all entries
        let mut count = 0;
        if !self.root_addr.is_null() {
            let mut entries = HashMap::new();
            self.collect_entries_from_pages(self.root_addr, &mut entries);
            count = entries.len();
        }

        // Add dirty entries that are new
        for (_key, entry) in &self.dirty {
            match entry {
                DirtyEntry::Modified(_) if count == 0 => count += 1,
                DirtyEntry::Deleted => {
                    if count > 0 {
                        count -= 1;
                    }
                }
                _ => {}
            }
        }

        count
    }

    /// Flushes all storage tries to free memory.
    pub fn flush_storage_tries(&mut self) -> usize {
        if let Some(ref mut state) = self.eager_state {
            return state.flush_storage_tries();
        }

        let count = self.storage_tries.len();

        // Update storage roots in accounts before clearing
        for (addr_hash, storage_trie) in self.storage_tries.iter_mut() {
            let storage_root = storage_trie.root_hash();

            if let Some(DirtyEntry::Modified(ref data)) = self.dirty.get(addr_hash) {
                let mut account = AccountData::decode(data);
                if account.storage_root != storage_root {
                    account.storage_root = storage_root;
                    self.dirty.insert(*addr_hash, DirtyEntry::Modified(account.encode()));
                }
            }
        }

        self.storage_tries.clear();
        count
    }

    /// Returns the number of storage tries currently in memory.
    pub fn storage_trie_count(&self) -> usize {
        if let Some(ref state) = self.eager_state {
            return state.storage_trie_count();
        }
        self.storage_tries.len()
    }

    /// Checks if a storage trie exists for an account.
    pub fn has_storage_trie(&self, address_hash: &[u8; 32]) -> bool {
        if let Some(ref state) = self.eager_state {
            return state.has_storage_trie(address_hash);
        }
        self.storage_tries.contains_key(address_hash)
    }

    /// Updates an account's storage_root field.
    pub fn update_account_storage_root(&mut self, address_hash: &[u8; 32], storage_root: [u8; 32]) {
        if let Some(ref mut state) = self.eager_state {
            state.update_account_storage_root(address_hash, storage_root);
            return;
        }

        if let Some(DirtyEntry::Modified(ref data)) = self.dirty.get(address_hash) {
            let mut account = AccountData::decode(data);
            if account.storage_root != storage_root {
                account.storage_root = storage_root;
                self.dirty.insert(*address_hash, DirtyEntry::Modified(account.encode()));
            }
        } else if let Some(value) = self.traverse_for_key(address_hash) {
            let mut account = AccountData::decode(&value);
            if account.storage_root != storage_root {
                account.storage_root = storage_root;
                self.dirty.insert(*address_hash, DirtyEntry::Modified(account.encode()));
            }
        }
    }
}

impl Default for PagedStateTrie {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// DiskMptStateTrie - Memory-Efficient State Trie using Disk-Based MPT
// ============================================================================

use super::DiskMpt;

/// Memory-efficient state trie that stores actual MPT structure on disk.
///
/// This implementation uses O(log N) memory per operation instead of O(N),
/// making it suitable for large state databases.
///
/// ## Key Features
///
/// - Only loads pages along the access path (root to leaf)
/// - Caches node hashes on disk to avoid recomputation
/// - Supports incremental root hash computation (only dirty paths recomputed)
/// - Compatible with existing PagedStateTrie API
///
/// ## Usage Pattern
///
/// Unlike PagedStateTrie which manages its own batch contexts internally,
/// DiskMptStateTrie requires the caller to pass batch contexts for operations
/// that modify the trie. This gives more control over transaction boundaries.
pub struct DiskMptStateTrie {
    /// The disk-based MPT for account data
    account_mpt: DiskMpt,
    /// Storage tries per account (using DiskMpt)
    storage_tries: HashMap<[u8; 32], DiskMpt>,
    /// Value cache for recently accessed accounts
    value_cache: RefCell<LruCache<[u8; 32], Vec<u8>>>,
}

impl DiskMptStateTrie {
    /// Creates a new empty DiskMptStateTrie.
    pub fn new() -> Self {
        Self {
            account_mpt: DiskMpt::new(),
            storage_tries: HashMap::new(),
            value_cache: RefCell::new(LruCache::new(
                NonZeroUsize::new(DEFAULT_VALUE_CACHE_SIZE).unwrap()
            )),
        }
    }

    /// Creates a DiskMptStateTrie from an existing root address.
    pub fn from_root(root_addr: DbAddress) -> Self {
        Self {
            account_mpt: DiskMpt::from_root(root_addr),
            storage_tries: HashMap::new(),
            value_cache: RefCell::new(LruCache::new(
                NonZeroUsize::new(DEFAULT_VALUE_CACHE_SIZE).unwrap()
            )),
        }
    }

    /// Returns the root address of the account MPT.
    pub fn root_addr(&self) -> DbAddress {
        self.account_mpt.root_addr()
    }

    /// Returns true if the trie is empty.
    pub fn is_empty(&self) -> bool {
        self.account_mpt.is_empty()
    }

    // ========================================================================
    // Account Operations
    // ========================================================================

    /// Gets an account by address.
    pub fn get_account(&self, batch: &BatchContext, address: &[u8; 20]) -> Option<AccountData> {
        let key_hash = keccak256(address);
        self.get_account_by_hash(batch, &key_hash)
    }

    /// Gets an account by pre-hashed address.
    pub fn get_account_by_hash(&self, batch: &BatchContext, address_hash: &[u8; 32]) -> Option<AccountData> {
        // Check cache first
        if let Some(value) = self.value_cache.borrow_mut().get(address_hash) {
            return Some(AccountData::decode(value));
        }

        // Query disk MPT
        match self.account_mpt.get(batch, address_hash).ok().flatten() {
            Some(value) => {
                self.value_cache.borrow_mut().put(*address_hash, value.clone());
                Some(AccountData::decode(&value))
            }
            None => None,
        }
    }

    /// Sets an account.
    pub fn set_account(&mut self, batch: &mut BatchContext, address: &[u8; 20], account: AccountData) {
        let key_hash = keccak256(address);
        self.set_account_by_hash(batch, &key_hash, account);
    }

    /// Sets an account using a pre-hashed address.
    pub fn set_account_by_hash(&mut self, batch: &mut BatchContext, address_hash: &[u8; 32], account: AccountData) {
        let encoded = account.encode();
        self.value_cache.borrow_mut().put(*address_hash, encoded.clone());

        // Insert into the MPT
        if let Err(e) = self.account_mpt.insert(batch, address_hash, encoded) {
            warn!("Failed to insert account: {:?}", e);
        }
    }

    /// Sets an account using raw RLP-encoded data.
    pub fn set_account_raw(&mut self, batch: &mut BatchContext, address_hash: &[u8; 32], rlp_encoded: Vec<u8>) {
        self.value_cache.borrow_mut().put(*address_hash, rlp_encoded.clone());

        if let Err(e) = self.account_mpt.insert(batch, address_hash, rlp_encoded) {
            warn!("Failed to insert account: {:?}", e);
        }
    }

    /// Batch insert accounts.
    pub fn set_accounts_batch(&mut self, batch: &mut BatchContext, accounts: impl IntoIterator<Item = ([u8; 32], AccountData)>) {
        for (address_hash, account) in accounts {
            let encoded = account.encode();
            self.value_cache.borrow_mut().put(address_hash, encoded.clone());
            if let Err(e) = self.account_mpt.insert(batch, &address_hash, encoded) {
                warn!("Failed to insert account in batch: {:?}", e);
            }
        }
    }

    // ========================================================================
    // Storage Operations
    // ========================================================================

    /// Gets a storage value for an account.
    pub fn get_storage_by_hash(&self, batch: &BatchContext, address_hash: &[u8; 32], slot_hash: &[u8; 32]) -> Option<[u8; 32]> {
        let storage_mpt = self.storage_tries.get(address_hash)?;
        let value = storage_mpt.get(batch, slot_hash).ok()??;

        if value.len() >= 32 {
            let mut result = [0u8; 32];
            result.copy_from_slice(&value[..32]);
            Some(result)
        } else {
            None
        }
    }

    /// Gets or creates a storage trie for an account.
    pub fn storage_trie_mut(&mut self, address_hash: &[u8; 32]) -> &mut DiskMpt {
        self.storage_tries.entry(*address_hash).or_insert_with(DiskMpt::new)
    }

    /// Sets a storage value.
    pub fn set_storage(&mut self, batch: &mut BatchContext, address_hash: &[u8; 32], slot_hash: &[u8; 32], value: [u8; 32]) {
        let storage_mpt = self.storage_tries.entry(*address_hash).or_insert_with(DiskMpt::new);

        // Zero value means delete
        if value == [0u8; 32] {
            let _ = storage_mpt.remove(batch, slot_hash);
        } else {
            let _ = storage_mpt.insert(batch, slot_hash, value.to_vec());
        }
    }

    // ========================================================================
    // Root Hash Computation
    // ========================================================================

    /// Computes the state root hash.
    ///
    /// This uses the disk-based MPT's incremental hash computation,
    /// only recomputing hashes for dirty nodes.
    pub fn root_hash(&mut self, batch: &mut BatchContext) -> [u8; 32] {
        // First, update storage roots in accounts
        let addr_hashes: Vec<[u8; 32]> = self.storage_tries.keys().cloned().collect();
        for addr_hash in addr_hashes {
            let storage_root = self.storage_tries.get_mut(&addr_hash)
                .map(|mpt| mpt.root_hash(batch).unwrap_or(EMPTY_ROOT))
                .unwrap_or(EMPTY_ROOT);

            // Get current account and update storage root if needed
            if let Some(value) = self.value_cache.borrow().peek(&addr_hash).cloned() {
                let mut account = AccountData::decode(&value);
                if account.storage_root != storage_root {
                    account.storage_root = storage_root;
                    let encoded = account.encode();
                    self.value_cache.borrow_mut().put(addr_hash, encoded.clone());
                    let _ = self.account_mpt.insert(batch, &addr_hash, encoded);
                }
            }
        }

        // Compute account MPT root
        self.account_mpt.root_hash(batch).unwrap_or(EMPTY_ROOT)
    }

    // ========================================================================
    // Save/Commit Operations
    // ========================================================================

    /// Saves the state trie to disk.
    ///
    /// Returns the root address that can be stored in the database metadata.
    pub fn save(&mut self, batch: &mut BatchContext) -> Result<DbAddress, DbError> {
        // Compute root hash (this finalizes all dirty nodes)
        let _ = self.root_hash(batch);

        Ok(self.account_mpt.root_addr())
    }

    /// Returns the number of accounts (approximate for DiskMpt).
    pub fn account_count(&self) -> usize {
        // DiskMpt doesn't track count directly, return cache size as estimate
        self.value_cache.borrow().len()
    }

    /// Clears the value cache.
    pub fn clear_cache(&mut self) {
        self.value_cache.borrow_mut().clear();
    }
}

impl Default for DiskMptStateTrie {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_persistent_trie_basic() {
        let mut trie = PersistentTrie::new();
        assert!(trie.is_empty());

        trie.insert(b"key1", b"value1".to_vec());
        assert_eq!(trie.get(b"key1"), Some(b"value1".to_vec()));
        assert!(!trie.is_empty());

        trie.remove(b"key1");
        assert!(trie.get(b"key1").is_none());
    }

    #[test]
    fn test_persistent_trie_root_changes() {
        let mut trie = PersistentTrie::new();
        let empty_root = trie.root_hash();

        trie.insert(b"key", b"value".to_vec());
        let root1 = trie.root_hash();
        assert_ne!(root1, empty_root);

        trie.insert(b"key", b"different".to_vec());
        let root2 = trie.root_hash();
        assert_ne!(root2, root1);
    }

    #[test]
    fn test_storage_trie() {
        let mut storage = StorageTrie::new();

        let slot = [1u8; 32];
        let value = [0u8; 31].into_iter().chain([42u8]).collect::<Vec<_>>();
        let mut value_arr = [0u8; 32];
        value_arr.copy_from_slice(&value);

        storage.set(&slot, value_arr);
        let retrieved = storage.get(&slot);
        assert_eq!(retrieved, Some(value_arr));

        // Setting to zero removes
        storage.set(&slot, [0u8; 32]);
        assert!(storage.get(&slot).is_none() || storage.get(&slot) == Some([0u8; 32]));
    }

    #[test]
    fn test_account_data_encode_decode() {
        let account = AccountData {
            nonce: 42,
            balance: {
                let mut b = [0u8; 32];
                b[31] = 100;
                b
            },
            storage_root: EMPTY_ROOT,
            code_hash: AccountData::EMPTY_CODE_HASH,
        };

        let encoded = account.encode();
        let decoded = AccountData::decode(&encoded);

        assert_eq!(decoded.nonce, 42);
        assert_eq!(decoded.balance[31], 100);
    }

    #[test]
    fn test_state_trie() {
        let mut state = StateTrie::new();

        let address = [1u8; 20];
        let account = AccountData {
            nonce: 1,
            balance: [0u8; 32],
            storage_root: EMPTY_ROOT,
            code_hash: AccountData::EMPTY_CODE_HASH,
        };

        state.set_account(&address, account);
        let retrieved = state.get_account(&address).unwrap();
        assert_eq!(retrieved.nonce, 1);
    }

    #[test]
    fn test_paged_state_trie_basic() {
        use crate::store::{PagedDb, CommitOptions};

        let mut db = PagedDb::in_memory(1000).unwrap();
        let mut trie = PagedStateTrie::new();

        // Add some accounts
        let address1 = [1u8; 20];
        let account1 = AccountData {
            nonce: 10,
            balance: {
                let mut b = [0u8; 32];
                b[31] = 100;
                b
            },
            storage_root: EMPTY_ROOT,
            code_hash: AccountData::EMPTY_CODE_HASH,
        };
        trie.set_account(&address1, account1);

        let address2 = [2u8; 20];
        let account2 = AccountData {
            nonce: 20,
            balance: {
                let mut b = [0u8; 32];
                b[31] = 200;
                b
            },
            storage_root: EMPTY_ROOT,
            code_hash: AccountData::EMPTY_CODE_HASH,
        };
        trie.set_account(&address2, account2);

        // Save to database
        let mut batch = db.begin_batch();
        let root_addr = trie.save(&mut batch).unwrap();
        batch.set_state_root(root_addr);
        batch.commit(CommitOptions::DangerNoFlush).unwrap();

        assert!(!root_addr.is_null());
        assert_eq!(trie.account_count(), 2);
    }

    #[test]
    fn test_paged_state_trie_save_load() {
        use crate::store::{PagedDb, CommitOptions};

        let mut db = PagedDb::in_memory(1000).unwrap();
        let root_addr;

        // Create and save a trie
        {
            let mut trie = PagedStateTrie::new();

            for i in 0..5u8 {
                let mut address = [0u8; 20];
                address[0] = i;
                let account = AccountData {
                    nonce: i as u64,
                    balance: {
                        let mut b = [0u8; 32];
                        b[31] = i * 10;
                        b
                    },
                    storage_root: EMPTY_ROOT,
                    code_hash: AccountData::EMPTY_CODE_HASH,
                };
                trie.set_account(&address, account);
            }

            let _root_hash_original = trie.root_hash();

            let mut batch = db.begin_batch();
            root_addr = trie.save(&mut batch).unwrap();
            batch.set_state_root(root_addr);
            batch.commit(CommitOptions::DangerNoFlush).unwrap();
        }

        // Load the trie back
        {
            let loaded = PagedStateTrie::load(&db, root_addr).unwrap();
            assert_eq!(loaded.account_count(), 5);

            // Verify accounts
            for i in 0..5u8 {
                let mut address = [0u8; 20];
                address[0] = i;
                let account = loaded.get_account(&address);
                assert!(account.is_some(), "Account {} not found", i);
                assert_eq!(account.unwrap().nonce, i as u64);
            }
        }
    }

    #[test]
    fn test_paged_state_trie_root_hash() {
        let mut trie = PagedStateTrie::new();

        let empty_root = trie.root_hash();
        assert_eq!(empty_root, EMPTY_ROOT);

        let address = [42u8; 20];
        let account = AccountData {
            nonce: 1,
            balance: [0u8; 32],
            storage_root: EMPTY_ROOT,
            code_hash: AccountData::EMPTY_CODE_HASH,
        };
        trie.set_account(&address, account);

        let new_root = trie.root_hash();
        assert_ne!(new_root, EMPTY_ROOT);
    }

    #[test]
    fn test_persistent_trie_page_roundtrip() {
        let mut trie = PersistentTrie::new();

        // Insert some data
        trie.insert(b"key1", b"value1".to_vec());
        trie.insert(b"key2", b"value2".to_vec());
        trie.insert(b"another_key", b"another_value".to_vec());

        let _original_root = trie.root_hash();

        // Convert to page data
        let page_data = trie.to_page_data();

        // Load from page data
        let loaded = PersistentTrie::load_from_page(&page_data);

        // Verify data
        assert_eq!(loaded.get(b"key1"), Some(b"value1".to_vec()));
        assert_eq!(loaded.get(b"key2"), Some(b"value2".to_vec()));
        assert_eq!(loaded.get(b"another_key"), Some(b"another_value".to_vec()));
    }

    #[test]
    fn test_dirty_entry() {
        let modified = DirtyEntry::Modified(vec![1, 2, 3]);
        assert_eq!(modified.value(), Some(&[1, 2, 3][..]));

        let deleted = DirtyEntry::Deleted;
        assert_eq!(deleted.value(), None);
    }

    #[test]
    fn test_lazy_storage_trie() {
        let db = Arc::new(PagedDb::in_memory(100).unwrap());
        let mut trie = LazyStorageTrie::new(db);

        // Test empty trie
        assert_eq!(trie.root_hash(), EMPTY_ROOT);

        // Set a value
        let slot_hash = [1u8; 32];
        let mut value = [0u8; 32];
        value[31] = 42;
        trie.set_by_hash(&slot_hash, value);

        // Get it back
        let retrieved = trie.get_by_hash(&slot_hash);
        assert_eq!(retrieved, Some(value));

        // Root should change
        let root = trie.root_hash();
        assert_ne!(root, EMPTY_ROOT);

        // Delete and verify
        trie.set_by_hash(&slot_hash, [0u8; 32]);
        assert!(trie.get_by_hash(&slot_hash).is_none() || trie.get_by_hash(&slot_hash) == Some([0u8; 32]));
    }

    // ========================================================================
    // DiskMptStateTrie Tests
    // ========================================================================

    #[test]
    fn test_disk_mpt_state_trie_basic() {
        use crate::store::PagedDb;

        let mut db = PagedDb::in_memory(1000).unwrap();
        let mut trie = DiskMptStateTrie::new();
        let mut batch = db.begin_batch();

        // Test empty trie
        assert!(trie.is_empty());
        assert_eq!(trie.root_hash(&mut batch), EMPTY_ROOT);

        // Add an account
        let address = [1u8; 20];
        let account = AccountData {
            nonce: 10,
            balance: {
                let mut b = [0u8; 32];
                b[31] = 100;
                b
            },
            storage_root: EMPTY_ROOT,
            code_hash: AccountData::EMPTY_CODE_HASH,
        };

        trie.set_account(&mut batch, &address, account);

        // Verify we can get it back
        let retrieved = trie.get_account(&batch, &address);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().nonce, 10);

        // Root hash should change
        let root = trie.root_hash(&mut batch);
        assert_ne!(root, EMPTY_ROOT);
    }

    #[test]
    fn test_disk_mpt_state_trie_multiple_accounts() {
        use crate::store::PagedDb;

        let mut db = PagedDb::in_memory(1000).unwrap();
        let mut trie = DiskMptStateTrie::new();
        let mut batch = db.begin_batch();

        // Add multiple accounts
        for i in 0..10u8 {
            let mut address = [0u8; 20];
            address[0] = i;
            let account = AccountData {
                nonce: i as u64,
                balance: {
                    let mut b = [0u8; 32];
                    b[31] = i * 10;
                    b
                },
                storage_root: EMPTY_ROOT,
                code_hash: AccountData::EMPTY_CODE_HASH,
            };
            trie.set_account(&mut batch, &address, account);
        }

        // Verify all accounts
        for i in 0..10u8 {
            let mut address = [0u8; 20];
            address[0] = i;
            let retrieved = trie.get_account(&batch, &address);
            assert!(retrieved.is_some(), "Account {} not found", i);
            assert_eq!(retrieved.unwrap().nonce, i as u64);
        }
    }

    #[test]
    fn test_disk_mpt_state_trie_storage() {
        use crate::store::PagedDb;

        let mut db = PagedDb::in_memory(1000).unwrap();
        let mut trie = DiskMptStateTrie::new();
        let mut batch = db.begin_batch();

        let address_hash = keccak256(&[1u8; 20]);

        // Set storage value
        let slot_hash = [2u8; 32];
        let mut value = [0u8; 32];
        value[31] = 42;
        trie.set_storage(&mut batch, &address_hash, &slot_hash, value);

        // Get it back
        let retrieved = trie.get_storage_by_hash(&batch, &address_hash, &slot_hash);
        assert_eq!(retrieved, Some(value));

        // Delete (set to zero)
        trie.set_storage(&mut batch, &address_hash, &slot_hash, [0u8; 32]);
        // After deletion, should be None
        let after_delete = trie.get_storage_by_hash(&batch, &address_hash, &slot_hash);
        assert!(after_delete.is_none() || after_delete == Some([0u8; 32]));
    }

    #[test]
    fn test_disk_mpt_state_trie_deterministic_hash() {
        use crate::store::PagedDb;

        let mut db1 = PagedDb::in_memory(1000).unwrap();
        let mut trie1 = DiskMptStateTrie::new();
        let mut batch1 = db1.begin_batch();

        let mut db2 = PagedDb::in_memory(1000).unwrap();
        let mut trie2 = DiskMptStateTrie::new();
        let mut batch2 = db2.begin_batch();

        // Insert same accounts in different order
        let address1 = [1u8; 20];
        let address2 = [2u8; 20];
        let account1 = AccountData {
            nonce: 1,
            balance: [0u8; 32],
            storage_root: EMPTY_ROOT,
            code_hash: AccountData::EMPTY_CODE_HASH,
        };
        let account2 = AccountData {
            nonce: 2,
            balance: [0u8; 32],
            storage_root: EMPTY_ROOT,
            code_hash: AccountData::EMPTY_CODE_HASH,
        };

        // Trie 1: insert in order 1, 2
        trie1.set_account(&mut batch1, &address1, account1.clone());
        trie1.set_account(&mut batch1, &address2, account2.clone());

        // Trie 2: insert in order 2, 1
        trie2.set_account(&mut batch2, &address2, account2);
        trie2.set_account(&mut batch2, &address1, account1);

        // Root hashes should be identical
        let root1 = trie1.root_hash(&mut batch1);
        let root2 = trie2.root_hash(&mut batch2);
        assert_eq!(root1, root2, "Root hashes should be deterministic regardless of insertion order");
    }
}
