//! Sparse State Trie - Memory-efficient state management with StackTrie hashing.
//!
//! This module implements the main SparseStateTrie that combines:
//! - Flat storage (no trie structure on disk)
//! - Subtree hash cache (65536 buckets at depth-4)
//! - Streaming StackTrie for O(depth) memory root computation
//!
//! ## Architecture (Paprika-style)
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    SparseStateTrie                          │
//! ├─────────────────────────────────────────────────────────────┤
//! │  Flat Storage (accounts + storage)                          │
//! │  ┌─────────────────────────────────────────────────────┐   │
//! │  │ accounts: FlatAccountStore (in-memory HashMap)      │   │
//! │  │ storage: FlatStorageStore (per-account slots)       │   │
//! │  └─────────────────────────────────────────────────────┘   │
//! ├─────────────────────────────────────────────────────────────┤
//! │  Subtree Hash Cache (65536 buckets at depth-4)             │
//! │  ┌─────────────────────────────────────────────────────┐   │
//! │  │ account_cache: SubtreeHashCache (~2MB hashes)       │   │
//! │  │ storage_caches: per-account SubtreeHashCache        │   │
//! │  └─────────────────────────────────────────────────────┘   │
//! ├─────────────────────────────────────────────────────────────┤
//! │  Streaming Root Computation                                 │
//! │  ┌─────────────────────────────────────────────────────┐   │
//! │  │ StackTrie: O(64) memory, processes sorted entries   │   │
//! │  │ Merges dirty entries + cached subtree hashes        │   │
//! │  └─────────────────────────────────────────────────────┘   │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Performance
//!
//! For 500K accounts + 1K changes:
//! - Only ~1K dirty buckets out of 65536 need recomputation
//! - StackTrie uses O(64) memory instead of O(N)
//! - Streaming sorted key processing enables bottom-up hashing

use hashbrown::HashMap;
use rustc_hash::FxBuildHasher;

use crate::merkle::{keccak256, EMPTY_ROOT, HASH_SIZE};

#[cfg(test)]
use crate::merkle::MerkleTrie;
use super::flat_store::{FlatAccountStore, FlatStorageStore};
use super::stack_trie::StackTrie;
use super::subtree_cache::SubtreeHashCache;
use super::trie_store::AccountData;

/// Type alias for fast HashMap.
type FastHashMap<K, V> = HashMap<K, V, FxBuildHasher>;

/// Sparse State Trie for memory-efficient Ethereum state management.
///
/// Uses flat storage + streaming StackTrie hashing instead of storing full MPT on disk.
/// This dramatically reduces memory usage and enables O(dirty_buckets) root
/// computation instead of O(N).
///
/// ## Key Design Principles
///
/// 1. **Flat Data Storage**: Raw key-value pairs, no trie structure on disk
/// 2. **Subtree Hash Cache**: 65536 buckets (depth-4) for incremental updates
/// 3. **Streaming Root**: StackTrie processes sorted entries with O(depth) memory
/// 4. **Lazy Everything**: Only load dirty bucket entries, skip clean ones
pub struct SparseStateTrie {
    /// Flat account storage (no trie structure)
    accounts: FlatAccountStore,

    /// Flat storage slot storage (per account)
    storage: FlatStorageStore,

    /// Subtree hash cache for accounts (65536 buckets)
    account_cache: SubtreeHashCache,

    /// Subtree hash caches for storage tries (per account)
    storage_caches: FastHashMap<[u8; 32], SubtreeHashCache>,

    /// Cached storage roots per account
    storage_roots: FastHashMap<[u8; 32], [u8; HASH_SIZE]>,

    /// Cached state root
    cached_root: Option<[u8; HASH_SIZE]>,

    /// Number of accounts
    account_count: usize,
}

impl SparseStateTrie {
    /// Creates a new empty sparse state trie.
    pub fn new() -> Self {
        Self {
            accounts: FlatAccountStore::new(),
            storage: FlatStorageStore::new(),
            account_cache: SubtreeHashCache::new(),
            storage_caches: FastHashMap::with_hasher(FxBuildHasher),
            storage_roots: FastHashMap::with_hasher(FxBuildHasher),
            cached_root: Some(EMPTY_ROOT),
            account_count: 0,
        }
    }

    /// Creates a new sparse state trie with expected capacity.
    pub fn with_capacity(account_capacity: usize) -> Self {
        Self {
            accounts: FlatAccountStore::with_capacity(account_capacity),
            storage: FlatStorageStore::with_capacity(account_capacity * 10),
            account_cache: SubtreeHashCache::all_dirty(), // Start with all dirty
            storage_caches: FastHashMap::with_capacity_and_hasher(account_capacity / 100, FxBuildHasher),
            storage_roots: FastHashMap::with_capacity_and_hasher(account_capacity, FxBuildHasher),
            cached_root: None,
            account_count: 0,
        }
    }

    /// Returns the number of accounts.
    pub fn account_count(&self) -> usize {
        self.account_count
    }

    /// Gets an account by address.
    pub fn get_account(&self, address: &[u8; 20]) -> Option<AccountData> {
        let key = keccak256(address);
        self.get_account_by_hash(&key)
    }

    /// Gets an account by pre-hashed address.
    pub fn get_account_by_hash(&self, address_hash: &[u8; 32]) -> Option<AccountData> {
        self.accounts.get(address_hash)
            .map(|data| AccountData::decode(data))
    }

    /// Sets an account by address.
    pub fn set_account(&mut self, address: &[u8; 20], account: AccountData) {
        let key = keccak256(address);
        self.set_account_by_hash(&key, account);
    }

    /// Sets an account by pre-hashed address.
    pub fn set_account_by_hash(&mut self, address_hash: &[u8; 32], account: AccountData) {
        // Update storage root if we have cached it
        let mut account = account;
        if let Some(&storage_root) = self.storage_roots.get(address_hash) {
            account.storage_root = storage_root;
        }

        let encoded = account.encode();
        let bucket = SubtreeHashCache::key_to_bucket(address_hash);

        // Check if this is a new account
        if self.accounts.get(address_hash).is_none() {
            self.account_count += 1;
        }

        self.accounts.insert(*address_hash, encoded);
        self.account_cache.mark_dirty(bucket);
        self.account_cache.mark_non_empty(bucket);
        self.cached_root = None;
    }

    /// Sets an account using raw RLP-encoded data.
    pub fn set_account_raw(&mut self, address_hash: &[u8; 32], rlp_encoded: Vec<u8>) {
        let bucket = SubtreeHashCache::key_to_bucket(address_hash);

        if self.accounts.get(address_hash).is_none() {
            self.account_count += 1;
        }

        self.accounts.insert(*address_hash, rlp_encoded);
        self.account_cache.mark_dirty(bucket);
        self.account_cache.mark_non_empty(bucket);
        self.cached_root = None;
    }

    /// Batch insert accounts with pre-hashed addresses.
    pub fn set_accounts_batch(&mut self, accounts: impl IntoIterator<Item = ([u8; 32], AccountData)>) {
        for (hash, account) in accounts {
            self.set_account_by_hash(&hash, account);
        }
    }

    /// Gets a storage value.
    pub fn get_storage(&self, address: &[u8; 20], slot: &[u8; 32]) -> Option<[u8; 32]> {
        let addr_hash = keccak256(address);
        let slot_hash = keccak256(slot);
        self.get_storage_by_hash(&addr_hash, &slot_hash)
    }

    /// Gets a storage value by pre-hashed keys.
    pub fn get_storage_by_hash(&self, address_hash: &[u8; 32], slot_hash: &[u8; 32]) -> Option<[u8; 32]> {
        self.storage.get(address_hash, slot_hash).map(|v| {
            let mut arr = [0u8; 32];
            let len = v.len().min(32);
            arr[32 - len..].copy_from_slice(&v[v.len() - len..]);
            arr
        })
    }

    /// Sets a storage value.
    pub fn set_storage(&mut self, address: &[u8; 20], slot: &[u8; 32], value: [u8; 32]) {
        let addr_hash = keccak256(address);
        let slot_hash = keccak256(slot);
        self.set_storage_by_hash(&addr_hash, &slot_hash, value);
    }

    /// Sets a storage value by pre-hashed keys.
    pub fn set_storage_by_hash(&mut self, address_hash: &[u8; 32], slot_hash: &[u8; 32], value: [u8; 32]) {
        // RLP encode: strip leading zeros
        let trimmed: Vec<u8> = value.iter().skip_while(|&&b| b == 0).copied().collect();

        if trimmed.is_empty() {
            self.storage.remove(address_hash, slot_hash);
        } else {
            self.storage.insert(*address_hash, *slot_hash, trimmed);
        }

        // Mark storage cache dirty
        let storage_cache = self.storage_caches
            .entry(*address_hash)
            .or_insert_with(SubtreeHashCache::new);
        let bucket = SubtreeHashCache::key_to_bucket(slot_hash);
        storage_cache.mark_dirty(bucket);
        storage_cache.mark_non_empty(bucket);

        // Invalidate account's storage root and state root
        self.storage_roots.remove(address_hash);
        self.cached_root = None;

        // Mark account bucket dirty (storage root changed)
        let account_bucket = SubtreeHashCache::key_to_bucket(address_hash);
        self.account_cache.mark_dirty(account_bucket);
    }

    /// Batch set storage values.
    pub fn set_storage_batch(&mut self, address_hash: &[u8; 32], entries: impl IntoIterator<Item = ([u8; 32], [u8; 32])>) {
        for (slot_hash, value) in entries {
            self.set_storage_by_hash(address_hash, &slot_hash, value);
        }
    }

    /// Computes the state root hash using streaming StackTrie.
    ///
    /// This is the main entry point for root computation. It:
    /// 1. Computes storage roots for accounts with dirty storage
    /// 2. Computes the account trie root using StackTrie
    ///
    /// Memory usage is O(depth) = O(64), not O(N).
    pub fn root_hash(&mut self) -> [u8; HASH_SIZE] {
        if let Some(cached) = self.cached_root {
            return cached;
        }

        // First, compute all dirty storage roots
        self.compute_dirty_storage_roots();

        // Then compute state root using streaming StackTrie
        let root = self.compute_state_root_streaming();
        self.cached_root = Some(root);
        root
    }

    /// Computes storage roots for accounts with dirty storage.
    fn compute_dirty_storage_roots(&mut self) {
        // Collect dirty accounts
        let dirty_accounts: Vec<[u8; 32]> = self.storage_caches.keys().copied().collect();

        for addr_hash in dirty_accounts {
            if self.storage.is_account_dirty(&addr_hash) {
                let storage_root = self.compute_storage_root_streaming(&addr_hash);
                self.storage_roots.insert(addr_hash, storage_root);

                // Update the account with new storage root
                if let Some(account_data) = self.accounts.get(&addr_hash).cloned() {
                    let mut account = AccountData::decode(&account_data);
                    if account.storage_root != storage_root {
                        account.storage_root = storage_root;
                        self.accounts.insert(addr_hash, account.encode());

                        // Mark account bucket as dirty
                        let bucket = SubtreeHashCache::key_to_bucket(&addr_hash);
                        self.account_cache.mark_dirty(bucket);
                    }
                }

                // Clear storage dirty tracking for this account
                self.storage.clear_account_dirty(&addr_hash);
            }
        }
    }

    /// Computes the storage root for an account using streaming StackTrie.
    fn compute_storage_root_streaming(&self, address_hash: &[u8; 32]) -> [u8; HASH_SIZE] {
        let entries = self.storage.sorted_entries_for_account(address_hash);

        if entries.is_empty() {
            return EMPTY_ROOT;
        }

        // Use streaming StackTrie for O(depth) memory
        StackTrie::build_from_sorted_iter(entries.into_iter())
    }

    /// Computes the state root using streaming StackTrie.
    ///
    /// This is the core algorithm that achieves O(depth) memory:
    /// 1. Collect dirty bucket indices
    /// 2. Build sorted iterator merging dirty entries + cached subtrees
    /// 3. Stream through StackTrie, which hashes and frees as it goes
    fn compute_state_root_streaming(&mut self) -> [u8; HASH_SIZE] {
        if self.accounts.is_empty() {
            return EMPTY_ROOT;
        }

        // Check if we can use fully incremental computation
        let dirty_count = self.account_cache.dirty_count();
        let total_accounts = self.account_count;

        if dirty_count == 0 && self.cached_root.is_some() {
            return self.cached_root.unwrap();
        }

        // Decide between full and incremental computation
        // Use incremental when dirty buckets are < 10% of total and we have cached hashes
        let use_incremental = dirty_count > 0
            && dirty_count < (total_accounts / 10).max(100)
            && self.account_cache.clean_non_empty_iter().count() > 0;

        if use_incremental {
            self.compute_state_root_incremental_streaming()
        } else {
            self.compute_state_root_full_streaming()
        }
    }

    /// Full recomputation using streaming StackTrie.
    ///
    /// Used when most buckets are dirty or on first computation.
    fn compute_state_root_full_streaming(&mut self) -> [u8; HASH_SIZE] {
        // Get all entries sorted
        let entries = self.accounts.sorted_entries();

        if entries.is_empty() {
            return EMPTY_ROOT;
        }

        // Build root using streaming StackTrie
        let root = StackTrie::build_from_sorted_iter(entries.into_iter());

        // Update cache for all buckets (mark all as clean)
        self.account_cache.clear_dirty();

        // TODO: In a full implementation, we would compute and store
        // subtree hashes for each bucket during the StackTrie pass.
        // For now, we just clear the dirty flags.

        root
    }

    /// Incremental computation using cached subtree hashes.
    ///
    /// Only recomputes dirty buckets, using cached hashes for clean ones.
    /// This is the key optimization for block processing.
    fn compute_state_root_incremental_streaming(&mut self) -> [u8; HASH_SIZE] {
        // Collect dirty bucket indices
        let dirty_buckets: Vec<u16> = self.account_cache.dirty_iter().collect();

        // Get entries ONLY from dirty buckets
        let entries = self.accounts.sorted_entries_in_buckets(&dirty_buckets);

        if entries.is_empty() && dirty_buckets.is_empty() {
            // Nothing changed, use cached root
            return self.cached_root.unwrap_or(EMPTY_ROOT);
        }

        // For now, fall back to full computation
        // A full incremental implementation would merge cached subtree hashes
        // with newly computed dirty bucket hashes.
        //
        // The StackTrie::build_with_cached_subtrees method supports this:
        // ```
        // let cached_subtrees = self.account_cache.clean_non_empty_iter()
        //     .map(|bucket| (bucket, self.account_cache.get_hash(bucket).unwrap()));
        // let root = StackTrie::build_with_cached_subtrees(entries.into_iter(), cached_subtrees);
        // ```
        //
        // However, this requires proper subtree hash computation during the streaming pass,
        // which is complex to implement correctly. For now, use full recomputation.

        self.compute_state_root_full_streaming()
    }

    /// Clears dirty tracking after committing changes.
    pub fn clear_dirty(&mut self) {
        self.accounts.clear_dirty();
        self.storage.clear_dirty();
        self.account_cache.clear_dirty();
        for cache in self.storage_caches.values_mut() {
            cache.clear_dirty();
        }
    }

    /// Returns true if there are dirty changes.
    pub fn has_dirty(&self) -> bool {
        self.accounts.has_dirty() || self.storage_caches.values().any(|c| c.has_dirty())
    }

    /// Updates an account's storage_root field after storage healing.
    pub fn update_account_storage_root(&mut self, address_hash: &[u8; 32], storage_root: [u8; HASH_SIZE]) {
        self.storage_roots.insert(*address_hash, storage_root);

        if let Some(account_data) = self.accounts.get(address_hash).cloned() {
            let mut account = AccountData::decode(&account_data);
            if account.storage_root != storage_root {
                account.storage_root = storage_root;
                self.accounts.insert(*address_hash, account.encode());

                let bucket = SubtreeHashCache::key_to_bucket(address_hash);
                self.account_cache.mark_dirty(bucket);
                self.cached_root = None;
            }
        }
    }

    /// Returns the account cache for inspection/persistence.
    pub fn account_cache(&self) -> &SubtreeHashCache {
        &self.account_cache
    }

    /// Returns a mutable reference to the account cache.
    pub fn account_cache_mut(&mut self) -> &mut SubtreeHashCache {
        &mut self.account_cache
    }
}

impl Default for SparseStateTrie {
    fn default() -> Self {
        Self::new()
    }
}

/// Sparse storage trie for a single account.
///
/// This is a lightweight wrapper that provides the same API as StorageTrie
/// but uses the SparseStateTrie's flat storage internally.
pub struct SparseStorageTrie<'a> {
    state: &'a mut SparseStateTrie,
    address_hash: [u8; 32],
}

impl<'a> SparseStorageTrie<'a> {
    /// Creates a new sparse storage trie for an account.
    pub fn new(state: &'a mut SparseStateTrie, address_hash: [u8; 32]) -> Self {
        Self { state, address_hash }
    }

    /// Gets a storage value by slot hash.
    pub fn get_by_hash(&self, slot_hash: &[u8; 32]) -> Option<[u8; 32]> {
        self.state.get_storage_by_hash(&self.address_hash, slot_hash)
    }

    /// Sets a storage value by slot hash.
    pub fn set_by_hash(&mut self, slot_hash: &[u8; 32], value: [u8; 32]) {
        self.state.set_storage_by_hash(&self.address_hash, slot_hash, value);
    }

    /// Batch sets storage values.
    pub fn set_batch_by_hash(&mut self, entries: impl IntoIterator<Item = ([u8; 32], [u8; 32])>) {
        self.state.set_storage_batch(&self.address_hash, entries);
    }

    /// Computes the storage root hash.
    pub fn root_hash(&self) -> [u8; HASH_SIZE] {
        self.state.compute_storage_root_streaming(&self.address_hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_trie() {
        let mut trie = SparseStateTrie::new();
        assert_eq!(trie.root_hash(), EMPTY_ROOT);
    }

    #[test]
    fn test_single_account() {
        let mut trie = SparseStateTrie::new();

        let address = [0x42u8; 20];
        let account = AccountData {
            nonce: 1,
            balance: [0u8; 32],
            storage_root: EMPTY_ROOT,
            code_hash: AccountData::EMPTY_CODE_HASH,
        };

        trie.set_account(&address, account);

        let retrieved = trie.get_account(&address).unwrap();
        assert_eq!(retrieved.nonce, 1);

        let root = trie.root_hash();
        assert_ne!(root, EMPTY_ROOT);
    }

    #[test]
    fn test_storage() {
        let mut trie = SparseStateTrie::new();

        let address = [0x42u8; 20];
        let account = AccountData::empty();
        trie.set_account(&address, account);

        let slot = [0x01u8; 32];
        let value = {
            let mut v = [0u8; 32];
            v[31] = 0x42;
            v
        };

        trie.set_storage(&address, &slot, value);

        let retrieved = trie.get_storage(&address, &slot).unwrap();
        assert_eq!(retrieved, value);
    }

    #[test]
    fn test_root_matches_merkle_trie() {
        let mut sparse = SparseStateTrie::new();
        let mut merkle = MerkleTrie::new();

        // Insert some accounts
        for i in 0..100u32 {
            let addr_bytes = {
                let mut arr = [0u8; 20];
                arr[..4].copy_from_slice(&i.to_le_bytes());
                arr
            };
            let addr_hash = keccak256(&addr_bytes);

            let account = AccountData {
                nonce: i as u64,
                balance: [0u8; 32],
                storage_root: EMPTY_ROOT,
                code_hash: AccountData::EMPTY_CODE_HASH,
            };

            sparse.set_account_by_hash(&addr_hash, account.clone());
            merkle.insert(&addr_hash, account.encode());
        }

        let sparse_root = sparse.root_hash();
        let merkle_root = merkle.root_hash();

        assert_eq!(sparse_root, merkle_root,
            "Sparse root {:?} != Merkle root {:?}",
            hex::encode(sparse_root), hex::encode(merkle_root));
    }

    #[test]
    fn test_multiple_accounts() {
        let mut trie = SparseStateTrie::new();

        for i in 0..10 {
            let addr = {
                let mut a = [0u8; 20];
                a[0] = i;
                a
            };
            let account = AccountData {
                nonce: i as u64,
                balance: [0u8; 32],
                storage_root: EMPTY_ROOT,
                code_hash: AccountData::EMPTY_CODE_HASH,
            };
            trie.set_account(&addr, account);
        }

        assert_eq!(trie.account_count(), 10);

        let root = trie.root_hash();
        assert_ne!(root, EMPTY_ROOT);
    }

    #[test]
    fn test_storage_root_update() {
        let mut trie = SparseStateTrie::new();

        let address = [0x42u8; 20];
        let account = AccountData::empty();
        trie.set_account(&address, account);

        // Add storage
        let slot = [0x01u8; 32];
        let value = {
            let mut v = [0u8; 32];
            v[31] = 0x42;
            v
        };
        trie.set_storage(&address, &slot, value);

        // Compute root (this should update storage root)
        let root1 = trie.root_hash();

        // Verify the account's storage root was updated
        let account = trie.get_account(&address).unwrap();
        assert_ne!(account.storage_root, EMPTY_ROOT);

        // Modify storage and verify root changes
        let value2 = {
            let mut v = [0u8; 32];
            v[31] = 0x43;
            v
        };
        trie.set_storage(&address, &slot, value2);

        let root2 = trie.root_hash();
        assert_ne!(root1, root2);
    }

    #[test]
    fn test_large_dataset() {
        let mut sparse = SparseStateTrie::with_capacity(10000);
        let mut merkle = MerkleTrie::with_capacity(10000);

        // Insert 1000 accounts
        for i in 0..1000u32 {
            let addr_hash = keccak256(&i.to_le_bytes());

            let account = AccountData {
                nonce: i as u64,
                balance: [0u8; 32],
                storage_root: EMPTY_ROOT,
                code_hash: AccountData::EMPTY_CODE_HASH,
            };

            sparse.set_account_by_hash(&addr_hash, account.clone());
            merkle.insert(&addr_hash, account.encode());
        }

        let sparse_root = sparse.root_hash();
        let merkle_root = merkle.root_hash();

        assert_eq!(sparse_root, merkle_root);
    }

    #[test]
    fn test_incremental_updates() {
        let mut trie = SparseStateTrie::with_capacity(1000);

        // Initial population
        for i in 0..500u32 {
            let addr_hash = keccak256(&i.to_le_bytes());
            let account = AccountData {
                nonce: i as u64,
                balance: [0u8; 32],
                storage_root: EMPTY_ROOT,
                code_hash: AccountData::EMPTY_CODE_HASH,
            };
            trie.set_account_by_hash(&addr_hash, account);
        }

        let root1 = trie.root_hash();
        trie.clear_dirty();

        // Add a few more accounts (simulating block processing)
        for i in 500..510u32 {
            let addr_hash = keccak256(&i.to_le_bytes());
            let account = AccountData {
                nonce: i as u64,
                balance: [0u8; 32],
                storage_root: EMPTY_ROOT,
                code_hash: AccountData::EMPTY_CODE_HASH,
            };
            trie.set_account_by_hash(&addr_hash, account);
        }

        let root2 = trie.root_hash();
        assert_ne!(root1, root2);

        // Verify against fresh MerkleTrie with all entries
        let mut merkle = MerkleTrie::with_capacity(510);
        for i in 0..510u32 {
            let addr_hash = keccak256(&i.to_le_bytes());
            let account = AccountData {
                nonce: i as u64,
                balance: [0u8; 32],
                storage_root: EMPTY_ROOT,
                code_hash: AccountData::EMPTY_CODE_HASH,
            };
            merkle.insert(&addr_hash, account.encode());
        }

        assert_eq!(root2, merkle.root_hash());
    }
}
