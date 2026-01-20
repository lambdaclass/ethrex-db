//! Page-based persistent storage.
//!
//! This module implements memory-mapped file storage with Copy-on-Write
//! concurrency, inspired by LMDB and Paprika.

mod db_address;
mod disk_mpt;
mod flat_store;
mod metrics;
mod page;
mod page_header;
mod page_types;
mod paged_db;
mod paged_flat_store;
mod proof_generator;
mod sparse_state_trie;
mod stack_trie;
mod subtree_cache;
mod trie_store;

pub use db_address::DbAddress;
pub use metrics::{DbMetrics, MetricsSnapshot};
pub use page::{Page, PAGE_SIZE};
pub use page_header::{PageHeader, PageType};
pub use disk_mpt::DiskMpt;
pub use page_types::{DataPage, RootPage, LeafPage, AbandonedPage, MptBranchPage, MptExtensionPage, MptLeafPage};
pub use paged_db::{PagedDb, DbError, BatchContext, ReadOnlyBatch, CommitOptions, Snapshot};
pub use trie_store::{PersistentTrie, StateTrie, StorageTrie, AccountData, PagedStateTrie, DirtyEntry, SubtreeHash, LazyStorageTrie, DiskMptStateTrie};

// New SparseStateTrie components
pub use stack_trie::StackTrie;
pub use subtree_cache::SubtreeHashCache;
pub use flat_store::{FlatAccountStore, FlatStorageStore};
pub use paged_flat_store::PagedFlatStore;
pub use sparse_state_trie::{SparseStateTrie, SparseStorageTrie};
pub use proof_generator::{MerkleProof, ProofGenerator};
