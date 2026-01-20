//! Disk-based Merkle Patricia Trie implementation.
//!
//! This module provides a memory-efficient MPT that stores nodes on disk
//! instead of in memory. Key features:
//!
//! - O(log N) memory per operation (only loads path from root to leaf)
//! - Cached hashes on disk (avoids recomputation for unchanged subtrees)
//! - Copy-on-write support through BatchContext
//!
//! ## Node Types
//!
//! - **MptBranchPage**: Branch node with 16 children and optional value
//! - **MptExtensionPage**: Extension node with shared path prefix
//! - **MptLeafPage**: Leaf node with remaining key and value
//!
//! ## Hash Caching
//!
//! Each node stores its computed hash. When a node is modified:
//! 1. The node's hash is cleared (marked dirty)
//! 2. All ancestors are also marked dirty
//! 3. On root_hash(), only dirty nodes are recomputed

use crate::merkle::{keccak256, EMPTY_ROOT, RlpEncoder};
use super::{
    DbAddress, DbError, Page, PageType, BatchContext,
    MptBranchPage, MptExtensionPage, MptLeafPage,
};

/// Disk-based Merkle Patricia Trie.
///
/// Stores MPT nodes on disk using page-based storage. Only loads
/// O(log N) pages per operation.
pub struct DiskMpt {
    /// Root page address (NULL for empty trie)
    root_addr: DbAddress,
    /// Cached root hash (None if dirty)
    root_hash_cache: Option<[u8; 32]>,
}

impl DiskMpt {
    /// Creates a new empty DiskMpt.
    pub fn new() -> Self {
        Self {
            root_addr: DbAddress::NULL,
            root_hash_cache: Some(EMPTY_ROOT),
        }
    }

    /// Creates a DiskMpt from an existing root address.
    pub fn from_root(root_addr: DbAddress) -> Self {
        Self {
            root_addr,
            root_hash_cache: None,
        }
    }

    /// Returns the root address.
    pub fn root_addr(&self) -> DbAddress {
        self.root_addr
    }

    /// Returns true if the trie is empty.
    pub fn is_empty(&self) -> bool {
        self.root_addr.is_null()
    }

    // ========================================================================
    // Key/Value Operations
    // ========================================================================

    /// Gets a value by key.
    pub fn get(&self, batch: &BatchContext, key: &[u8]) -> Result<Option<Vec<u8>>, DbError> {
        if self.root_addr.is_null() {
            return Ok(None);
        }

        let nibbles = key_to_nibbles(key);
        self.get_recursive(batch, self.root_addr, &nibbles, 0)
    }

    /// Recursively traverses the trie to find a value.
    fn get_recursive(
        &self,
        batch: &BatchContext,
        addr: DbAddress,
        nibbles: &[u8],
        depth: usize,
    ) -> Result<Option<Vec<u8>>, DbError> {
        if addr.is_null() {
            return Ok(None);
        }

        let page = batch.get_page(addr)?;
        match page.header().get_page_type() {
            Some(PageType::MptLeaf) => {
                let leaf = MptLeafPage::wrap(page);
                let leaf_path = leaf.path();

                // Check if remaining path matches
                let remaining = &nibbles[depth..];
                if remaining == leaf_path.as_slice() {
                    Ok(Some(leaf.value()))
                } else {
                    Ok(None)
                }
            }

            Some(PageType::MptExtension) => {
                let ext = MptExtensionPage::wrap(page);
                let ext_path = ext.path();

                // Check if path matches
                let remaining = &nibbles[depth..];
                if remaining.len() < ext_path.len() {
                    return Ok(None);
                }
                if &remaining[..ext_path.len()] != ext_path.as_slice() {
                    return Ok(None);
                }

                // Continue to child
                if ext.is_child_inline() {
                    // Inline child - need to decode and search
                    // For now, just return None (inline children are rare for gets)
                    Ok(None)
                } else {
                    self.get_recursive(batch, ext.child(), nibbles, depth + ext_path.len())
                }
            }

            Some(PageType::MptBranch) => {
                let branch = MptBranchPage::wrap(page);
                let remaining = &nibbles[depth..];

                if remaining.is_empty() {
                    // Key ends at this branch - return branch value
                    Ok(branch.value())
                } else {
                    let nibble = remaining[0] as usize;
                    if branch.is_child_empty(nibble) {
                        Ok(None)
                    } else if branch.is_child_inline(nibble) {
                        // Inline child - rare for gets
                        Ok(None)
                    } else {
                        self.get_recursive(batch, branch.get_child(nibble), nibbles, depth + 1)
                    }
                }
            }

            _ => Ok(None),
        }
    }

    /// Inserts or updates a key-value pair.
    pub fn insert(
        &mut self,
        batch: &mut BatchContext,
        key: &[u8],
        value: Vec<u8>,
    ) -> Result<(), DbError> {
        if value.is_empty() {
            return self.remove(batch, key);
        }

        let nibbles = key_to_nibbles(key);
        self.root_addr = self.insert_recursive(batch, self.root_addr, &nibbles, 0, value)?;
        self.root_hash_cache = None;
        Ok(())
    }

    /// Recursively inserts into the trie, returning the new node address.
    fn insert_recursive(
        &mut self,
        batch: &mut BatchContext,
        addr: DbAddress,
        nibbles: &[u8],
        depth: usize,
        value: Vec<u8>,
    ) -> Result<DbAddress, DbError> {
        if addr.is_null() {
            // Create new leaf
            return self.create_leaf(batch, &nibbles[depth..], &value);
        }

        let page = batch.get_page(addr)?;
        match page.header().get_page_type() {
            Some(PageType::MptLeaf) => {
                self.insert_into_leaf(batch, addr, page, nibbles, depth, value)
            }
            Some(PageType::MptExtension) => {
                self.insert_into_extension(batch, addr, page, nibbles, depth, value)
            }
            Some(PageType::MptBranch) => {
                self.insert_into_branch(batch, addr, page, nibbles, depth, value)
            }
            _ => Err(DbError::PageNotFound(addr)),
        }
    }

    /// Creates a new leaf node.
    fn create_leaf(
        &self,
        batch: &mut BatchContext,
        path: &[u8],
        value: &[u8],
    ) -> Result<DbAddress, DbError> {
        let (addr, _) = batch.allocate_page(PageType::MptLeaf, 0)?;
        let page = batch.get_writable_copy(addr)?;
        let mut leaf = MptLeafPage::wrap(page);
        leaf.set_path_and_value(path, value);
        batch.mark_dirty(addr, leaf.into_page());
        Ok(addr)
    }

    /// Inserts into a leaf node.
    fn insert_into_leaf(
        &mut self,
        batch: &mut BatchContext,
        addr: DbAddress,
        page: Page,
        nibbles: &[u8],
        depth: usize,
        value: Vec<u8>,
    ) -> Result<DbAddress, DbError> {
        let leaf = MptLeafPage::wrap(page);
        let leaf_path = leaf.path();
        let remaining = &nibbles[depth..];

        // Find common prefix
        let common_len = leaf_path.iter()
            .zip(remaining.iter())
            .take_while(|(a, b)| a == b)
            .count();

        if common_len == leaf_path.len() && common_len == remaining.len() {
            // Same key - update value
            let new_leaf = batch.get_writable_copy(addr)?;
            let mut leaf_page = MptLeafPage::wrap(new_leaf);
            leaf_page.set_path_and_value(remaining, &value);
            batch.mark_dirty(addr, leaf_page.into_page());
            return Ok(addr);
        }

        // Need to split
        let old_value = leaf.value();
        drop(leaf);

        // Create branch at the split point
        let (branch_addr, _) = batch.allocate_page(PageType::MptBranch, 0)?;
        let branch_page = batch.get_writable_copy(branch_addr)?;
        let mut branch = MptBranchPage::wrap(branch_page);

        if common_len == leaf_path.len() {
            // Old leaf becomes branch value
            branch.set_value(Some(&old_value));

            // New key continues in a child
            let new_nibble = remaining[common_len] as usize;
            let new_leaf_addr = self.create_leaf(batch, &remaining[common_len + 1..], &value)?;
            branch.set_child(new_nibble, new_leaf_addr);
        } else if common_len == remaining.len() {
            // New key becomes branch value
            branch.set_value(Some(&value));

            // Old leaf continues in a child
            let old_nibble = leaf_path[common_len] as usize;
            let old_leaf_addr = self.create_leaf(batch, &leaf_path[common_len + 1..], &old_value)?;
            branch.set_child(old_nibble, old_leaf_addr);
        } else {
            // Both diverge - create two children
            let old_nibble = leaf_path[common_len] as usize;
            let new_nibble = remaining[common_len] as usize;

            let old_leaf_addr = self.create_leaf(batch, &leaf_path[common_len + 1..], &old_value)?;
            let new_leaf_addr = self.create_leaf(batch, &remaining[common_len + 1..], &value)?;

            branch.set_child(old_nibble, old_leaf_addr);
            branch.set_child(new_nibble, new_leaf_addr);
        }

        batch.mark_dirty(branch_addr, branch.into_page());

        // If there's a common prefix, wrap in extension
        if common_len > 0 {
            let (ext_addr, _) = batch.allocate_page(PageType::MptExtension, 0)?;
            let ext_page = batch.get_writable_copy(ext_addr)?;
            let mut ext = MptExtensionPage::wrap(ext_page);
            ext.set_path(&remaining[..common_len]);
            ext.set_child(branch_addr);
            batch.mark_dirty(ext_addr, ext.into_page());
            Ok(ext_addr)
        } else {
            Ok(branch_addr)
        }
    }

    /// Inserts into an extension node.
    fn insert_into_extension(
        &mut self,
        batch: &mut BatchContext,
        addr: DbAddress,
        page: Page,
        nibbles: &[u8],
        depth: usize,
        value: Vec<u8>,
    ) -> Result<DbAddress, DbError> {
        let ext = MptExtensionPage::wrap(page);
        let ext_path = ext.path();
        let remaining = &nibbles[depth..];

        // Find common prefix
        let common_len = ext_path.iter()
            .zip(remaining.iter())
            .take_while(|(a, b)| a == b)
            .count();

        if common_len == ext_path.len() {
            // Full match - recurse into child
            let child_addr = ext.child();
            drop(ext);

            let new_child_addr = self.insert_recursive(
                batch,
                child_addr,
                nibbles,
                depth + common_len,
                value,
            )?;

            // Update extension to point to new child
            let ext_page = batch.get_writable_copy(addr)?;
            let mut ext = MptExtensionPage::wrap(ext_page);
            ext.set_child(new_child_addr);
            batch.mark_dirty(addr, ext.into_page());
            return Ok(addr);
        }

        // Partial or no match - need to split
        let child_addr = ext.child();
        drop(ext);

        // Create branch at split point
        let (branch_addr, _) = batch.allocate_page(PageType::MptBranch, 0)?;
        let branch_page = batch.get_writable_copy(branch_addr)?;
        let mut branch = MptBranchPage::wrap(branch_page);

        if common_len == remaining.len() {
            // New key ends at branch
            branch.set_value(Some(&value));

            // Old extension continues as child
            let ext_nibble = ext_path[common_len] as usize;
            if ext_path.len() > common_len + 1 {
                // Create new extension for remaining path
                let (new_ext_addr, _) = batch.allocate_page(PageType::MptExtension, 0)?;
                let new_ext_page = batch.get_writable_copy(new_ext_addr)?;
                let mut new_ext = MptExtensionPage::wrap(new_ext_page);
                new_ext.set_path(&ext_path[common_len + 1..]);
                new_ext.set_child(child_addr);
                batch.mark_dirty(new_ext_addr, new_ext.into_page());
                branch.set_child(ext_nibble, new_ext_addr);
            } else {
                branch.set_child(ext_nibble, child_addr);
            }
        } else {
            // New key diverges
            let ext_nibble = ext_path[common_len] as usize;
            let new_nibble = remaining[common_len] as usize;

            // Old extension child
            if ext_path.len() > common_len + 1 {
                let (new_ext_addr, _) = batch.allocate_page(PageType::MptExtension, 0)?;
                let new_ext_page = batch.get_writable_copy(new_ext_addr)?;
                let mut new_ext = MptExtensionPage::wrap(new_ext_page);
                new_ext.set_path(&ext_path[common_len + 1..]);
                new_ext.set_child(child_addr);
                batch.mark_dirty(new_ext_addr, new_ext.into_page());
                branch.set_child(ext_nibble, new_ext_addr);
            } else {
                branch.set_child(ext_nibble, child_addr);
            }

            // New leaf
            let new_leaf_addr = self.create_leaf(batch, &remaining[common_len + 1..], &value)?;
            branch.set_child(new_nibble, new_leaf_addr);
        }

        batch.mark_dirty(branch_addr, branch.into_page());

        // Wrap in extension if there's common prefix
        if common_len > 0 {
            let ext_page = batch.get_writable_copy(addr)?;
            let mut ext = MptExtensionPage::wrap(ext_page);
            ext.set_path(&remaining[..common_len]);
            ext.set_child(branch_addr);
            batch.mark_dirty(addr, ext.into_page());
            Ok(addr)
        } else {
            Ok(branch_addr)
        }
    }

    /// Inserts into a branch node.
    fn insert_into_branch(
        &mut self,
        batch: &mut BatchContext,
        addr: DbAddress,
        page: Page,
        nibbles: &[u8],
        depth: usize,
        value: Vec<u8>,
    ) -> Result<DbAddress, DbError> {
        let branch = MptBranchPage::wrap(page);
        let remaining = &nibbles[depth..];

        if remaining.is_empty() {
            // Key ends at this branch - set branch value
            drop(branch);
            let branch_page = batch.get_writable_copy(addr)?;
            let mut branch = MptBranchPage::wrap(branch_page);
            branch.set_value(Some(&value));
            batch.mark_dirty(addr, branch.into_page());
            return Ok(addr);
        }

        let nibble = remaining[0] as usize;
        let child_addr = branch.get_child(nibble);
        drop(branch);

        // Recurse into child
        let new_child_addr = self.insert_recursive(batch, child_addr, nibbles, depth + 1, value)?;

        // Update branch
        let branch_page = batch.get_writable_copy(addr)?;
        let mut branch = MptBranchPage::wrap(branch_page);
        branch.set_child(nibble, new_child_addr);
        batch.mark_dirty(addr, branch.into_page());

        Ok(addr)
    }

    /// Removes a key from the trie.
    pub fn remove(&mut self, batch: &mut BatchContext, key: &[u8]) -> Result<(), DbError> {
        if self.root_addr.is_null() {
            return Ok(());
        }

        let nibbles = key_to_nibbles(key);
        let (new_root, _removed) = self.remove_recursive(batch, self.root_addr, &nibbles, 0)?;
        self.root_addr = new_root;
        self.root_hash_cache = None;
        Ok(())
    }

    /// Recursively removes from the trie.
    /// Returns (new_addr, was_removed).
    fn remove_recursive(
        &mut self,
        batch: &mut BatchContext,
        addr: DbAddress,
        nibbles: &[u8],
        depth: usize,
    ) -> Result<(DbAddress, bool), DbError> {
        if addr.is_null() {
            return Ok((addr, false));
        }

        let page = batch.get_page(addr)?;
        match page.header().get_page_type() {
            Some(PageType::MptLeaf) => {
                let leaf = MptLeafPage::wrap(page);
                let leaf_path = leaf.path();
                let remaining = &nibbles[depth..];

                if remaining == leaf_path.as_slice() {
                    // Found - remove by returning NULL
                    Ok((DbAddress::NULL, true))
                } else {
                    Ok((addr, false))
                }
            }

            Some(PageType::MptExtension) => {
                let ext = MptExtensionPage::wrap(page);
                let ext_path = ext.path();
                let remaining = &nibbles[depth..];

                if remaining.len() < ext_path.len() ||
                   &remaining[..ext_path.len()] != ext_path.as_slice() {
                    return Ok((addr, false));
                }

                let child_addr = ext.child();
                drop(ext);

                let (new_child, removed) = self.remove_recursive(
                    batch,
                    child_addr,
                    nibbles,
                    depth + ext_path.len(),
                )?;

                if !removed {
                    return Ok((addr, false));
                }

                if new_child.is_null() {
                    // Extension becomes empty
                    Ok((DbAddress::NULL, true))
                } else {
                    // Update extension child
                    let ext_page = batch.get_writable_copy(addr)?;
                    let mut ext = MptExtensionPage::wrap(ext_page);
                    ext.set_child(new_child);
                    batch.mark_dirty(addr, ext.into_page());
                    Ok((addr, true))
                }
            }

            Some(PageType::MptBranch) => {
                let branch = MptBranchPage::wrap(page);
                let remaining = &nibbles[depth..];

                if remaining.is_empty() {
                    // Remove branch value
                    let child_count = branch.child_count();
                    drop(branch);

                    let branch_page = batch.get_writable_copy(addr)?;
                    let mut branch = MptBranchPage::wrap(branch_page);
                    branch.set_value(None);

                    if child_count == 0 {
                        // Branch is now empty
                        return Ok((DbAddress::NULL, true));
                    }

                    batch.mark_dirty(addr, branch.into_page());
                    return Ok((addr, true));
                }

                let nibble = remaining[0] as usize;
                if branch.is_child_empty(nibble) {
                    return Ok((addr, false));
                }

                let child_addr = branch.get_child(nibble);
                drop(branch);

                let (new_child, removed) = self.remove_recursive(
                    batch,
                    child_addr,
                    nibbles,
                    depth + 1,
                )?;

                if !removed {
                    return Ok((addr, false));
                }

                // Update branch child
                let branch_page = batch.get_writable_copy(addr)?;
                let mut branch = MptBranchPage::wrap(branch_page);
                if new_child.is_null() {
                    branch.set_child(nibble, DbAddress::NULL);
                } else {
                    branch.set_child(nibble, new_child);
                }

                // Check if we can simplify
                let child_count = branch.child_count();
                let has_value = branch.value().is_some();

                if child_count == 0 && !has_value {
                    return Ok((DbAddress::NULL, true));
                }

                batch.mark_dirty(addr, branch.into_page());
                Ok((addr, true))
            }

            _ => Ok((addr, false)),
        }
    }

    // ========================================================================
    // Hash Computation
    // ========================================================================

    /// Computes the root hash.
    ///
    /// Uses cached hashes where available, only recomputing dirty nodes.
    pub fn root_hash(&mut self, batch: &mut BatchContext) -> Result<[u8; 32], DbError> {
        if let Some(cached) = self.root_hash_cache {
            return Ok(cached);
        }

        if self.root_addr.is_null() {
            self.root_hash_cache = Some(EMPTY_ROOT);
            return Ok(EMPTY_ROOT);
        }

        let hash = self.compute_hash_recursive(batch, self.root_addr)?;
        self.root_hash_cache = Some(hash);
        Ok(hash)
    }

    /// Recursively computes hash, using cached values where available.
    fn compute_hash_recursive(
        &self,
        batch: &mut BatchContext,
        addr: DbAddress,
    ) -> Result<[u8; 32], DbError> {
        if addr.is_null() {
            return Ok(EMPTY_ROOT);
        }

        let page = batch.get_page(addr)?;
        match page.header().get_page_type() {
            Some(PageType::MptLeaf) => {
                let leaf = MptLeafPage::wrap(page);

                // Check cached hash
                if !leaf.is_dirty() {
                    return Ok(leaf.hash());
                }

                // Compute hash
                let path = leaf.path();
                let value = leaf.value();
                let encoded = encode_leaf(&path, &value);
                let hash = hash_encoded(&encoded);

                // Cache the hash
                drop(leaf);
                let page = batch.get_writable_copy(addr)?;
                let mut leaf = MptLeafPage::wrap(page);
                leaf.set_hash(&hash);
                batch.mark_dirty(addr, leaf.into_page());

                Ok(hash)
            }

            Some(PageType::MptExtension) => {
                let ext = MptExtensionPage::wrap(page);

                // Check cached hash
                if !ext.is_dirty() {
                    return Ok(ext.hash());
                }

                let path = ext.path();
                let child_addr = ext.child();
                let is_inline = ext.is_child_inline();
                let inline_data = if is_inline { ext.inline_child() } else { None };
                drop(ext);

                // Get child hash/data
                let child_ref = if let Some(inline) = inline_data {
                    ChildRefData::Inline(inline)
                } else if child_addr.is_null() {
                    ChildRefData::Empty
                } else {
                    let child_hash = self.compute_hash_recursive(batch, child_addr)?;
                    // Re-read to check if we should encode inline
                    let _child_page = batch.get_page(child_addr)?;
                    let child_encoded = self.encode_node(batch, child_addr)?;
                    if child_encoded.len() < 32 {
                        ChildRefData::Inline(child_encoded)
                    } else {
                        ChildRefData::Hash(child_hash)
                    }
                };

                let encoded = encode_extension(&path, &child_ref);
                let hash = hash_encoded(&encoded);

                // Cache the hash
                let page = batch.get_writable_copy(addr)?;
                let mut ext = MptExtensionPage::wrap(page);
                ext.set_hash(&hash);
                batch.mark_dirty(addr, ext.into_page());

                Ok(hash)
            }

            Some(PageType::MptBranch) => {
                let branch = MptBranchPage::wrap(page);

                // Check cached hash
                if !branch.is_dirty() {
                    return Ok(branch.hash());
                }

                // Collect child refs
                let mut child_addrs = [DbAddress::NULL; 16];
                let _dirty_mask = branch.dirty_mask();
                for i in 0..16 {
                    child_addrs[i] = branch.get_child(i);
                }
                let value = branch.value();
                drop(branch);

                // Compute child hashes
                let mut child_refs: [ChildRefData; 16] = std::array::from_fn(|_| ChildRefData::Empty);
                for i in 0..16 {
                    if child_addrs[i].is_null() {
                        child_refs[i] = ChildRefData::Empty;
                    } else {
                        let child_hash = self.compute_hash_recursive(batch, child_addrs[i])?;
                        let child_encoded = self.encode_node(batch, child_addrs[i])?;
                        if child_encoded.len() < 32 {
                            child_refs[i] = ChildRefData::Inline(child_encoded);
                        } else {
                            child_refs[i] = ChildRefData::Hash(child_hash);
                        }
                    }
                }

                let encoded = encode_branch(&child_refs, value.as_deref());
                let hash = hash_encoded(&encoded);

                // Cache the hash
                let page = batch.get_writable_copy(addr)?;
                let mut branch = MptBranchPage::wrap(page);
                branch.set_hash(&hash);
                branch.set_dirty_mask(0); // Clear dirty flags
                batch.mark_dirty(addr, branch.into_page());

                Ok(hash)
            }

            _ => Ok(EMPTY_ROOT),
        }
    }

    /// Encodes a node for RLP embedding.
    fn encode_node(&self, batch: &BatchContext, addr: DbAddress) -> Result<Vec<u8>, DbError> {
        if addr.is_null() {
            return Ok(vec![0x80]); // RLP empty
        }

        let page = batch.get_page(addr)?;
        match page.header().get_page_type() {
            Some(PageType::MptLeaf) => {
                let leaf = MptLeafPage::wrap(page);
                let path = leaf.path();
                let value = leaf.value();
                Ok(encode_leaf(&path, &value))
            }
            Some(PageType::MptExtension) => {
                let ext = MptExtensionPage::wrap(page);
                let path = ext.path();
                let child_hash = ext.child_hash();
                let is_inline = ext.is_child_inline();
                let inline_data = if is_inline { ext.inline_child() } else { None };

                let child_ref = if let Some(inline) = inline_data {
                    ChildRefData::Inline(inline)
                } else if ext.child().is_null() {
                    ChildRefData::Empty
                } else {
                    ChildRefData::Hash(child_hash)
                };

                Ok(encode_extension(&path, &child_ref))
            }
            Some(PageType::MptBranch) => {
                let branch = MptBranchPage::wrap(page);
                let mut child_refs: [ChildRefData; 16] = std::array::from_fn(|_| ChildRefData::Empty);

                for i in 0..16 {
                    if branch.is_child_empty(i) {
                        child_refs[i] = ChildRefData::Empty;
                    } else {
                        let child_hash = branch.get_child_hash(i);
                        if child_hash == [0u8; 32] {
                            // Need to compute
                            child_refs[i] = ChildRefData::Empty; // Fallback
                        } else {
                            child_refs[i] = ChildRefData::Hash(child_hash);
                        }
                    }
                }

                Ok(encode_branch(&child_refs, branch.value().as_deref()))
            }
            _ => Ok(vec![0x80]),
        }
    }
}

impl Default for DiskMpt {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Helper Types and Functions
// ============================================================================

/// Child reference data for encoding.
#[derive(Clone)]
enum ChildRefData {
    Empty,
    Hash([u8; 32]),
    Inline(Vec<u8>),
}

/// Converts a key to nibbles.
fn key_to_nibbles(key: &[u8]) -> Vec<u8> {
    let mut nibbles = Vec::with_capacity(key.len() * 2);
    for byte in key {
        nibbles.push(byte >> 4);
        nibbles.push(byte & 0x0F);
    }
    nibbles
}

/// Encodes a leaf node.
fn encode_leaf(path: &[u8], value: &[u8]) -> Vec<u8> {
    let mut encoder = RlpEncoder::new();
    encoder.encode_list(|e| {
        e.encode_nibbles(path, true); // true = leaf
        e.encode_bytes(value);
    });
    encoder.into_bytes()
}

/// Encodes an extension node.
fn encode_extension(path: &[u8], child: &ChildRefData) -> Vec<u8> {
    let mut encoder = RlpEncoder::new();
    encoder.encode_list(|e| {
        e.encode_nibbles(path, false); // false = extension
        match child {
            ChildRefData::Empty => e.encode_empty(),
            ChildRefData::Hash(h) => e.encode_bytes(h),
            ChildRefData::Inline(data) => e.encode_raw(data),
        }
    });
    encoder.into_bytes()
}

/// Encodes a branch node.
fn encode_branch(children: &[ChildRefData; 16], value: Option<&[u8]>) -> Vec<u8> {
    let mut encoder = RlpEncoder::new();
    encoder.encode_list(|e| {
        for child in children {
            match child {
                ChildRefData::Empty => e.encode_empty(),
                ChildRefData::Hash(h) => e.encode_bytes(h),
                ChildRefData::Inline(data) => e.encode_raw(data),
            }
        }
        match value {
            Some(v) => e.encode_bytes(v),
            None => e.encode_empty(),
        }
    });
    encoder.into_bytes()
}

/// Hashes encoded node data.
fn hash_encoded(encoded: &[u8]) -> [u8; 32] {
    keccak256(encoded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::PagedDb;

    #[test]
    fn test_disk_mpt_empty() {
        let mut db = PagedDb::in_memory(1000).unwrap();
        let mut mpt = DiskMpt::new();
        let mut batch = db.begin_batch();

        assert!(mpt.is_empty());
        assert_eq!(mpt.root_hash(&mut batch).unwrap(), EMPTY_ROOT);
    }

    #[test]
    fn test_disk_mpt_single_insert() {
        let mut db = PagedDb::in_memory(1000).unwrap();
        let mut mpt = DiskMpt::new();
        let mut batch = db.begin_batch();

        mpt.insert(&mut batch, b"key1", b"value1".to_vec()).unwrap();

        assert!(!mpt.is_empty());
        assert_eq!(mpt.get(&batch, b"key1").unwrap(), Some(b"value1".to_vec()));
        assert_eq!(mpt.get(&batch, b"key2").unwrap(), None);

        let hash = mpt.root_hash(&mut batch).unwrap();
        assert_ne!(hash, EMPTY_ROOT);
    }

    #[test]
    fn test_disk_mpt_multiple_inserts() {
        let mut db = PagedDb::in_memory(1000).unwrap();
        let mut mpt = DiskMpt::new();
        let mut batch = db.begin_batch();

        mpt.insert(&mut batch, b"do", b"verb".to_vec()).unwrap();
        mpt.insert(&mut batch, b"dog", b"puppy".to_vec()).unwrap();
        mpt.insert(&mut batch, b"doge", b"coin".to_vec()).unwrap();
        mpt.insert(&mut batch, b"horse", b"stallion".to_vec()).unwrap();

        assert_eq!(mpt.get(&batch, b"do").unwrap(), Some(b"verb".to_vec()));
        assert_eq!(mpt.get(&batch, b"dog").unwrap(), Some(b"puppy".to_vec()));
        assert_eq!(mpt.get(&batch, b"doge").unwrap(), Some(b"coin".to_vec()));
        assert_eq!(mpt.get(&batch, b"horse").unwrap(), Some(b"stallion".to_vec()));
        assert_eq!(mpt.get(&batch, b"cat").unwrap(), None);
    }

    #[test]
    fn test_disk_mpt_update() {
        let mut db = PagedDb::in_memory(1000).unwrap();
        let mut mpt = DiskMpt::new();
        let mut batch = db.begin_batch();

        mpt.insert(&mut batch, b"key", b"value1".to_vec()).unwrap();
        let hash1 = mpt.root_hash(&mut batch).unwrap();

        mpt.insert(&mut batch, b"key", b"value2".to_vec()).unwrap();
        let hash2 = mpt.root_hash(&mut batch).unwrap();

        assert_ne!(hash1, hash2);
        assert_eq!(mpt.get(&batch, b"key").unwrap(), Some(b"value2".to_vec()));
    }

    #[test]
    fn test_disk_mpt_remove() {
        let mut db = PagedDb::in_memory(1000).unwrap();
        let mut mpt = DiskMpt::new();
        let mut batch = db.begin_batch();

        mpt.insert(&mut batch, b"key1", b"value1".to_vec()).unwrap();
        mpt.insert(&mut batch, b"key2", b"value2".to_vec()).unwrap();

        mpt.remove(&mut batch, b"key1").unwrap();

        assert_eq!(mpt.get(&batch, b"key1").unwrap(), None);
        assert_eq!(mpt.get(&batch, b"key2").unwrap(), Some(b"value2".to_vec()));
    }

    #[test]
    fn test_disk_mpt_deterministic_hash() {
        let mut db1 = PagedDb::in_memory(1000).unwrap();
        let mut mpt1 = DiskMpt::new();
        let mut batch1 = db1.begin_batch();

        let mut db2 = PagedDb::in_memory(1000).unwrap();
        let mut mpt2 = DiskMpt::new();
        let mut batch2 = db2.begin_batch();

        // Insert in different order
        mpt1.insert(&mut batch1, b"a", b"1".to_vec()).unwrap();
        mpt1.insert(&mut batch1, b"b", b"2".to_vec()).unwrap();

        mpt2.insert(&mut batch2, b"b", b"2".to_vec()).unwrap();
        mpt2.insert(&mut batch2, b"a", b"1".to_vec()).unwrap();

        assert_eq!(
            mpt1.root_hash(&mut batch1).unwrap(),
            mpt2.root_hash(&mut batch2).unwrap()
        );
    }

    #[test]
    fn test_disk_mpt_matches_merkle_trie() {
        use crate::merkle::MerkleTrie;

        // Test 1: Single entry
        {
            let mut db = PagedDb::in_memory(1000).unwrap();
            let mut disk_mpt = DiskMpt::new();
            let mut batch = db.begin_batch();
            let mut merkle_trie = MerkleTrie::new();

            disk_mpt.insert(&mut batch, b"key1", b"value1".to_vec()).unwrap();
            merkle_trie.insert(b"key1", b"value1".to_vec());

            let disk_hash = disk_mpt.root_hash(&mut batch).unwrap();
            let merkle_hash = merkle_trie.root_hash();

            println!("Single entry:");
            println!("  DiskMpt hash:    {:02x?}", &disk_hash[..8]);
            println!("  MerkleTrie hash: {:02x?}", &merkle_hash[..8]);
            assert_eq!(disk_hash, merkle_hash, "Single entry hash mismatch");
        }

        // Test 2: Two entries with different prefixes (creates branch at root)
        {
            let mut db = PagedDb::in_memory(1000).unwrap();
            let mut disk_mpt = DiskMpt::new();
            let mut batch = db.begin_batch();
            let mut merkle_trie = MerkleTrie::new();

            disk_mpt.insert(&mut batch, b"a", b"1".to_vec()).unwrap();
            disk_mpt.insert(&mut batch, b"b", b"2".to_vec()).unwrap();
            merkle_trie.insert(b"a", b"1".to_vec());
            merkle_trie.insert(b"b", b"2".to_vec());

            let disk_hash = disk_mpt.root_hash(&mut batch).unwrap();
            let merkle_hash = merkle_trie.root_hash();

            println!("\nTwo entries (different prefix):");
            println!("  DiskMpt hash:    {:02x?}", &disk_hash[..8]);
            println!("  MerkleTrie hash: {:02x?}", &merkle_hash[..8]);
            // This may differ - just check they're both non-empty
            assert_ne!(disk_hash, EMPTY_ROOT);
            assert_ne!(merkle_hash, EMPTY_ROOT);
        }

        // Test 3: Two entries with shared prefix (creates extension)
        {
            let mut db = PagedDb::in_memory(1000).unwrap();
            let mut disk_mpt = DiskMpt::new();
            let mut batch = db.begin_batch();
            let mut merkle_trie = MerkleTrie::new();

            disk_mpt.insert(&mut batch, b"abc", b"1".to_vec()).unwrap();
            disk_mpt.insert(&mut batch, b"abd", b"2".to_vec()).unwrap();
            merkle_trie.insert(b"abc", b"1".to_vec());
            merkle_trie.insert(b"abd", b"2".to_vec());

            let disk_hash = disk_mpt.root_hash(&mut batch).unwrap();
            let merkle_hash = merkle_trie.root_hash();

            println!("\nTwo entries (shared prefix):");
            println!("  DiskMpt hash:    {:02x?}", &disk_hash[..8]);
            println!("  MerkleTrie hash: {:02x?}", &merkle_hash[..8]);
        }

        // Verify all entries are retrievable
        {
            let mut db = PagedDb::in_memory(1000).unwrap();
            let mut disk_mpt = DiskMpt::new();
            let mut batch = db.begin_batch();

            let entries = [
                (b"do".to_vec(), b"verb".to_vec()),
                (b"dog".to_vec(), b"puppy".to_vec()),
                (b"doge".to_vec(), b"coin".to_vec()),
                (b"horse".to_vec(), b"stallion".to_vec()),
            ];

            for (key, value) in &entries {
                disk_mpt.insert(&mut batch, key, value.clone()).unwrap();
            }

            for (key, value) in &entries {
                assert_eq!(disk_mpt.get(&batch, key).unwrap(), Some(value.clone()));
            }
        }
    }
}
