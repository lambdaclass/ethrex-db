//! StackTrie - Geth-style memory-efficient streaming trie hashing.
//!
//! This implements a true streaming StackTrie algorithm for computing Merkle roots
//! with O(depth) memory instead of O(N) memory. Inspired by Geth's StackTrie and
//! Paprika's deferred merkleization.
//!
//! ## Algorithm
//!
//! Keys MUST be inserted in sorted order. The trie is built incrementally:
//! 1. When a new key diverges from the current path, completed subtrees are hashed
//! 2. Hashed subtrees are freed immediately, keeping memory constant
//! 3. The stack holds at most 64 frames (one per nibble depth)
//!
//! ## Memory Efficiency
//!
//! For N entries with depth D (typically 64 nibbles for Ethereum):
//! - Traditional trie: O(N) memory for all nodes
//! - StackTrie: O(D) memory = O(64) ~38KB worst case
//!
//! ## Key Features
//!
//! - True streaming: entries are processed one at a time, not loaded into memory
//! - Cached subtree support: insert pre-computed subtree hashes for clean buckets
//! - Ethereum MPT compatible: produces identical hashes to MerkleTrie

use crate::merkle::{keccak256, RlpEncoder, ChildRef, EMPTY_ROOT, HASH_SIZE};

/// Maximum trie depth (64 nibbles for 32-byte keys).
const MAX_DEPTH: usize = 64;

/// StackTrie for memory-efficient streaming Merkle root computation.
///
/// Keys MUST be inserted in sorted (lexicographic) order for correct operation.
/// This implementation uses a stack-based algorithm that hashes and frees
/// completed subtrees as it processes entries, achieving O(depth) memory.
///
/// # Example
///
/// ```ignore
/// use ethrex_db::store::StackTrie;
///
/// // Entries must be sorted!
/// let mut entries = vec![
///     ([0x10u8; 32], b"value1".to_vec()),
///     ([0x20u8; 32], b"value2".to_vec()),
/// ];
/// entries.sort_by(|a, b| a.0.cmp(&b.0));
///
/// let mut trie = StackTrie::new();
/// for (key, value) in entries {
///     trie.insert(&key, &value);
/// }
/// let root = trie.finalize();
/// ```
pub struct StackTrie {
    /// Stack of partially-built nodes from root towards current position.
    /// Max size = 64 (one per nibble depth).
    stack: Vec<StackFrame>,

    /// The current path prefix (nibbles of keys processed so far).
    current_prefix: Vec<u8>,

    /// Final root hash (set after finalize()).
    root_hash: Option<[u8; HASH_SIZE]>,

    /// Number of entries inserted.
    entry_count: usize,
}

/// A frame on the StackTrie stack representing a node being built.
#[derive(Clone, Debug)]
struct StackFrame {
    /// The nibble depth of this frame (0 = root, 64 = leaf).
    depth: usize,

    /// For branch nodes: child references (hash or inline).
    /// None = empty slot, Some = child exists.
    children: Box<[Option<ChildRef>; 16]>,

    /// Value at this node (for branch nodes with values, or leaf value).
    value: Option<Vec<u8>>,

    /// Whether this is a leaf node.
    is_leaf: bool,

    /// The extension path for leaf/extension nodes (nibbles after the branch point).
    extension_path: Vec<u8>,
}

impl Default for StackFrame {
    fn default() -> Self {
        Self {
            depth: 0,
            children: Box::new([
                None, None, None, None, None, None, None, None,
                None, None, None, None, None, None, None, None,
            ]),
            value: None,
            is_leaf: false,
            extension_path: Vec::new(),
        }
    }
}

impl StackFrame {
    /// Creates a new branch frame at the given depth.
    fn branch(depth: usize) -> Self {
        Self {
            depth,
            ..Default::default()
        }
    }

    /// Creates a leaf frame with the given path and value.
    fn leaf(depth: usize, path: Vec<u8>, value: Vec<u8>) -> Self {
        Self {
            depth,
            is_leaf: true,
            extension_path: path,
            value: Some(value),
            ..Default::default()
        }
    }

    /// Encodes this frame as an RLP-encoded MPT node.
    fn encode(&self) -> Vec<u8> {
        if self.is_leaf {
            // Leaf node: [encoded_path, value]
            let mut encoder = RlpEncoder::new();
            encoder.encode_list(|e| {
                e.encode_nibbles(&self.extension_path, true);
                if let Some(ref v) = self.value {
                    e.encode_bytes(v);
                } else {
                    e.encode_empty();
                }
            });
            encoder.into_bytes()
        } else if !self.extension_path.is_empty() {
            // Extension node: [encoded_path, child_ref]
            // Find the single non-empty child
            let child_ref = self.children.iter()
                .find_map(|c| c.as_ref())
                .cloned()
                .unwrap_or(ChildRef::Empty);

            let mut encoder = RlpEncoder::new();
            encoder.encode_list(|e| {
                e.encode_nibbles(&self.extension_path, false);
                match &child_ref {
                    ChildRef::Hash(h) => e.encode_bytes(h),
                    ChildRef::Inline(data) => e.encode_raw(data),
                    ChildRef::Empty => e.encode_empty(),
                }
            });
            encoder.into_bytes()
        } else {
            // Branch node: [child0, child1, ..., child15, value]
            let mut encoder = RlpEncoder::new();
            encoder.encode_list(|e| {
                for child in self.children.iter() {
                    match child {
                        Some(ChildRef::Hash(h)) => e.encode_bytes(h),
                        Some(ChildRef::Inline(data)) => e.encode_raw(data),
                        Some(ChildRef::Empty) | None => e.encode_empty(),
                    }
                }
                match &self.value {
                    Some(v) => e.encode_bytes(v),
                    None => e.encode_empty(),
                }
            });
            encoder.into_bytes()
        }
    }

    /// Computes the child reference (hash or inline) for this node.
    fn to_child_ref(&self) -> ChildRef {
        let encoded = self.encode();
        ChildRef::from_encoded(encoded)
    }

    /// Returns the keccak256 hash of this node's encoding.
    fn hash(&self) -> [u8; HASH_SIZE] {
        let encoded = self.encode();
        if encoded.len() < 32 {
            // For inline nodes, we still need to return a hash for the root
            keccak256(&encoded)
        } else {
            keccak256(&encoded)
        }
    }

    /// Returns true if this is an empty node.
    fn is_empty(&self) -> bool {
        if self.is_leaf {
            return false;
        }
        self.value.is_none() && self.children.iter().all(|c| c.is_none())
    }

    /// Counts non-empty children.
    #[allow(dead_code)]
    fn child_count(&self) -> usize {
        self.children.iter().filter(|c| c.is_some()).count()
    }
}

impl StackTrie {
    /// Creates a new empty StackTrie.
    pub fn new() -> Self {
        Self {
            stack: Vec::with_capacity(MAX_DEPTH),
            current_prefix: Vec::with_capacity(MAX_DEPTH),
            root_hash: None,
            entry_count: 0,
        }
    }

    /// Returns whether the trie is empty.
    pub fn is_empty(&self) -> bool {
        self.entry_count == 0
    }

    /// Returns the number of entries inserted.
    pub fn len(&self) -> usize {
        self.entry_count
    }

    /// Inserts a key-value pair.
    ///
    /// IMPORTANT: Keys must be inserted in sorted (lexicographic) order!
    /// Violating this will produce incorrect root hashes.
    pub fn insert(&mut self, key: &[u8; 32], value: &[u8]) {
        if value.is_empty() {
            return; // Skip empty values (deletions)
        }

        let nibbles = key_to_nibbles(key);

        // If this is the first entry, just create a leaf
        if self.stack.is_empty() {
            self.stack.push(StackFrame::leaf(0, nibbles.clone(), value.to_vec()));
            self.current_prefix = nibbles;
            self.entry_count += 1;
            self.root_hash = None;
            return;
        }

        // Find where this key diverges from the current path
        let diverge_depth = self.find_divergence_depth(&nibbles);

        // Pop and hash all frames above the divergence point
        self.collapse_to_depth(diverge_depth);

        // Now insert the new leaf
        self.insert_at_divergence(&nibbles, value, diverge_depth);

        self.current_prefix = nibbles;
        self.entry_count += 1;
        self.root_hash = None;
    }

    /// Inserts a cached subtree hash at a given bucket (4-nibble prefix).
    ///
    /// Used to incorporate pre-computed subtree hashes from the cache.
    /// The bucket is a 16-bit value representing the first 4 nibbles.
    ///
    /// IMPORTANT: This must be called in sorted order with regular inserts!
    pub fn insert_cached_subtree(&mut self, bucket: u16, hash: [u8; HASH_SIZE]) {
        // Convert bucket to a synthetic key prefix (4 nibbles)
        let prefix_nibbles = bucket_to_nibbles(bucket);

        // Treat this as a 4-nibble prefix insertion
        // We need to collapse any existing work above this point
        if !self.stack.is_empty() {
            // Find divergence with the bucket prefix
            let diverge_depth = self.current_prefix.iter()
                .zip(prefix_nibbles.iter())
                .take_while(|(a, b)| a == b)
                .count()
                .min(4);

            self.collapse_to_depth(diverge_depth);
        }

        // Insert the cached hash as a child reference
        if self.stack.is_empty() {
            // Create a root branch with this subtree
            let mut frame = StackFrame::branch(0);
            frame.children[prefix_nibbles[0] as usize] = Some(ChildRef::Hash(hash));
            self.stack.push(frame);
        } else {
            // Add to existing frame
            let frame = self.stack.last_mut().unwrap();
            let nibble_idx = if frame.depth < 4 {
                prefix_nibbles[frame.depth] as usize
            } else {
                return; // Subtree cache is for depth-4 buckets only
            };
            frame.children[nibble_idx] = Some(ChildRef::Hash(hash));
        }

        self.current_prefix = prefix_nibbles.to_vec();
        self.root_hash = None;
    }

    /// Finalizes the trie and returns the root hash.
    ///
    /// After calling this, the StackTrie state is preserved but no more
    /// insertions should be made (they would corrupt the result).
    pub fn finalize(&mut self) -> [u8; HASH_SIZE] {
        if let Some(hash) = self.root_hash {
            return hash;
        }

        if self.stack.is_empty() {
            self.root_hash = Some(EMPTY_ROOT);
            return EMPTY_ROOT;
        }

        // Collapse everything to get the root
        self.collapse_to_depth(0);

        // The stack should now have exactly one frame (the root)
        let root_hash = if self.stack.len() == 1 {
            self.stack[0].hash()
        } else if self.stack.is_empty() {
            EMPTY_ROOT
        } else {
            // Multiple frames remaining - collapse to single root
            while self.stack.len() > 1 {
                self.pop_and_merge();
            }
            self.stack[0].hash()
        };

        self.root_hash = Some(root_hash);
        root_hash
    }

    /// Returns the root hash if already computed.
    pub fn root_hash(&self) -> Option<[u8; HASH_SIZE]> {
        self.root_hash
    }

    /// Finds the depth where the new key diverges from the current prefix.
    fn find_divergence_depth(&self, nibbles: &[u8]) -> usize {
        self.current_prefix.iter()
            .zip(nibbles.iter())
            .take_while(|(a, b)| a == b)
            .count()
    }

    /// Collapses all frames above the given depth, hashing them.
    fn collapse_to_depth(&mut self, target_depth: usize) {
        // Process frames from top of stack downward
        while let Some(top) = self.stack.last() {
            if top.depth < target_depth {
                break;
            }

            if top.depth == target_depth && !top.is_leaf {
                // This frame is at the target depth and is a branch - keep it
                break;
            }

            self.pop_and_merge();
        }
    }

    /// Pops the top frame, hashes it, and merges into parent.
    fn pop_and_merge(&mut self) {
        let frame = match self.stack.pop() {
            Some(f) => f,
            None => return,
        };

        if self.stack.is_empty() {
            // This was the only frame - push it back as root
            self.stack.push(frame);
            return;
        }

        // Get the child reference for this frame
        let child_ref = frame.to_child_ref();

        // Find the nibble index where this child goes in the parent
        let parent = self.stack.last_mut().unwrap();
        let parent_depth = parent.depth;
        let child_depth = frame.depth;

        // The nibble at parent_depth tells us which slot in parent
        if child_depth > parent_depth && child_depth <= self.current_prefix.len() {
            let nibble_idx = self.current_prefix[parent_depth] as usize;
            parent.children[nibble_idx] = Some(child_ref);
        } else if !frame.is_empty() {
            // Edge case: the frame might be an extension that needs special handling
            let nibble_idx = if parent_depth < self.current_prefix.len() {
                self.current_prefix[parent_depth] as usize
            } else {
                0
            };
            parent.children[nibble_idx] = Some(child_ref);
        }
    }

    /// Inserts a leaf at the divergence point.
    fn insert_at_divergence(&mut self, nibbles: &[u8], value: &[u8], diverge_depth: usize) {
        // If the stack is empty after collapsing, we need to handle specially
        if self.stack.is_empty() {
            self.stack.push(StackFrame::leaf(0, nibbles.to_vec(), value.to_vec()));
            return;
        }

        let top_depth = self.stack.last().map(|f| f.depth).unwrap_or(0);
        let top_is_leaf = self.stack.last().map(|f| f.is_leaf).unwrap_or(false);

        if top_is_leaf {
            // Need to convert the leaf to a branch
            let old_leaf = self.stack.pop().unwrap();
            let old_path = &self.current_prefix;

            // Find common prefix between old and new
            let common_len = old_path.iter()
                .zip(nibbles.iter())
                .skip(top_depth)
                .take_while(|(a, b)| a == b)
                .count();

            let branch_depth = top_depth + common_len;

            // Create branch at divergence point
            let mut branch = StackFrame::branch(branch_depth);

            // Add old leaf as child
            if branch_depth < old_path.len() {
                let old_nibble = old_path[branch_depth] as usize;
                let old_remaining = old_path[branch_depth + 1..].to_vec();

                if old_remaining.is_empty() {
                    // Old key ends at branch - set as branch value
                    branch.value = old_leaf.value.clone();
                } else {
                    // Old key continues - create leaf child
                    let old_child = StackFrame::leaf(branch_depth + 1, old_remaining, old_leaf.value.unwrap_or_default());
                    branch.children[old_nibble] = Some(old_child.to_child_ref());
                }
            } else {
                // Old key ends at branch
                branch.value = old_leaf.value.clone();
            }

            // Add new leaf as child
            if branch_depth < nibbles.len() {
                let new_nibble = nibbles[branch_depth] as usize;
                let new_remaining = nibbles[branch_depth + 1..].to_vec();

                if new_remaining.is_empty() {
                    // New key ends at branch
                    branch.value = Some(value.to_vec());
                } else {
                    // New key continues - create leaf child
                    let new_child = StackFrame::leaf(branch_depth + 1, new_remaining, value.to_vec());
                    branch.children[new_nibble] = Some(new_child.to_child_ref());
                }
            } else {
                // New key ends at branch
                branch.value = Some(value.to_vec());
            }

            // If there's a common prefix, wrap in extension
            if common_len > 0 && top_depth < branch_depth {
                let ext_path = nibbles[top_depth..branch_depth].to_vec();
                branch.extension_path = ext_path;
            }

            self.stack.push(branch);
        } else {
            // Top is a branch - add new entry as child
            let branch = self.stack.last_mut().unwrap();
            let _branch_depth = branch.depth;

            if diverge_depth < nibbles.len() {
                let nibble = nibbles[diverge_depth] as usize;
                let remaining = nibbles[diverge_depth + 1..].to_vec();

                if remaining.is_empty() {
                    // Key ends at this branch
                    branch.value = Some(value.to_vec());
                } else {
                    // Create new leaf child
                    let leaf = StackFrame::leaf(diverge_depth + 1, remaining, value.to_vec());
                    branch.children[nibble] = Some(leaf.to_child_ref());
                }
            } else {
                // Key ends at branch
                branch.value = Some(value.to_vec());
            }
        }
    }

    /// Builds from a sorted iterator of entries.
    ///
    /// This is the recommended way to use StackTrie for large datasets.
    /// The iterator yields entries one at a time, so memory usage is O(depth).
    pub fn build_from_sorted_iter<I>(iter: I) -> [u8; HASH_SIZE]
    where
        I: IntoIterator<Item = ([u8; 32], Vec<u8>)>,
    {
        let mut trie = StackTrie::new();
        for (key, value) in iter {
            trie.insert(&key, &value);
        }
        trie.finalize()
    }

    /// Builds from sorted entries with cached subtree hashes.
    ///
    /// This merges dirty entries with clean subtree hashes in sorted order.
    /// `cached_subtrees` should be sorted by bucket index.
    pub fn build_with_cached_subtrees<I, C>(
        entries: I,
        cached_subtrees: C,
    ) -> [u8; HASH_SIZE]
    where
        I: IntoIterator<Item = ([u8; 32], Vec<u8>)>,
        C: IntoIterator<Item = (u16, [u8; HASH_SIZE])>,
    {
        let mut trie = StackTrie::new();

        // Convert iterators to peekable
        let mut entries = entries.into_iter().peekable();
        let mut subtrees = cached_subtrees.into_iter().peekable();

        loop {
            // Compare next entry key with next subtree bucket
            let entry_bucket = entries.peek().map(|(k, _)| key_to_bucket(k));
            let subtree_bucket = subtrees.peek().map(|(b, _)| *b);

            match (entry_bucket, subtree_bucket) {
                (Some(eb), Some(sb)) if sb < eb => {
                    // Insert cached subtree first
                    let (bucket, hash) = subtrees.next().unwrap();
                    trie.insert_cached_subtree(bucket, hash);
                }
                (Some(_), _) => {
                    // Insert entry
                    let (key, value) = entries.next().unwrap();
                    trie.insert(&key, &value);
                }
                (None, Some(_)) => {
                    // Only subtrees left
                    let (bucket, hash) = subtrees.next().unwrap();
                    trie.insert_cached_subtree(bucket, hash);
                }
                (None, None) => break,
            }
        }

        trie.finalize()
    }
}

impl Default for StackTrie {
    fn default() -> Self {
        Self::new()
    }
}

/// Converts a 32-byte key to 64 nibbles.
#[inline]
fn key_to_nibbles(key: &[u8; 32]) -> Vec<u8> {
    let mut nibbles = Vec::with_capacity(64);
    for byte in key {
        nibbles.push(byte >> 4);
        nibbles.push(byte & 0x0F);
    }
    nibbles
}

/// Converts a bucket index (u16) to 4 nibbles.
#[inline]
fn bucket_to_nibbles(bucket: u16) -> [u8; 4] {
    [
        ((bucket >> 12) & 0xF) as u8,
        ((bucket >> 8) & 0xF) as u8,
        ((bucket >> 4) & 0xF) as u8,
        (bucket & 0xF) as u8,
    ]
}

/// Converts a key to its bucket index (first 4 nibbles = first 2 bytes).
#[inline]
fn key_to_bucket(key: &[u8; 32]) -> u16 {
    ((key[0] as u16) << 8) | (key[1] as u16)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::MerkleTrie;

    #[test]
    fn test_empty_trie() {
        let mut trie = StackTrie::new();
        assert!(trie.is_empty());
        assert_eq!(trie.finalize(), EMPTY_ROOT);
    }

    #[test]
    fn test_single_entry() {
        let mut stack_trie = StackTrie::new();
        let key = [0u8; 32];
        let value = b"test value";

        stack_trie.insert(&key, value);
        let stack_root = stack_trie.finalize();

        // Compare with MerkleTrie
        let mut merkle_trie = MerkleTrie::new();
        merkle_trie.insert(&key, value.to_vec());
        let merkle_root = merkle_trie.root_hash();

        assert_eq!(stack_root, merkle_root);
    }

    #[test]
    fn test_two_entries_different_first_nibble() {
        let mut stack_trie = StackTrie::new();

        // Keys with different first nibbles (sorted order)
        let key1 = {
            let mut k = [0u8; 32];
            k[0] = 0x10; // First nibble = 1
            k
        };
        let key2 = {
            let mut k = [0u8; 32];
            k[0] = 0x20; // First nibble = 2
            k
        };

        stack_trie.insert(&key1, b"value1");
        stack_trie.insert(&key2, b"value2");
        let stack_root = stack_trie.finalize();

        // Compare with MerkleTrie
        let mut merkle_trie = MerkleTrie::new();
        merkle_trie.insert(&key1, b"value1".to_vec());
        merkle_trie.insert(&key2, b"value2".to_vec());
        let merkle_root = merkle_trie.root_hash();

        assert_eq!(stack_root, merkle_root);
    }

    #[test]
    fn test_two_entries_shared_prefix() {
        let mut stack_trie = StackTrie::new();

        // Keys with shared prefix (sorted order)
        let key1 = {
            let mut k = [0u8; 32];
            k[0] = 0x12;
            k[1] = 0x34;
            k
        };
        let key2 = {
            let mut k = [0u8; 32];
            k[0] = 0x12;
            k[1] = 0x56;
            k
        };

        stack_trie.insert(&key1, b"value1");
        stack_trie.insert(&key2, b"value2");
        let stack_root = stack_trie.finalize();

        // Compare with MerkleTrie
        let mut merkle_trie = MerkleTrie::new();
        merkle_trie.insert(&key1, b"value1".to_vec());
        merkle_trie.insert(&key2, b"value2".to_vec());
        let merkle_root = merkle_trie.root_hash();

        assert_eq!(stack_root, merkle_root);
    }

    #[test]
    fn test_multiple_entries_sorted() {
        let mut stack_trie = StackTrie::new();
        let mut merkle_trie = MerkleTrie::new();

        // Generate sorted keys using keccak256 and then sort
        let mut entries: Vec<([u8; 32], Vec<u8>)> = (0..100u32).map(|i| {
            let key = keccak256(&i.to_le_bytes());
            let value = format!("value_{}", i).into_bytes();
            (key, value)
        }).collect();

        // Sort by key
        entries.sort_by(|a, b| a.0.cmp(&b.0));

        // Insert into both tries
        for (key, value) in &entries {
            stack_trie.insert(key, value);
            merkle_trie.insert(key, value.clone());
        }

        let stack_root = stack_trie.finalize();
        let merkle_root = merkle_trie.root_hash();

        assert_eq!(stack_root, merkle_root);
    }

    #[test]
    fn test_key_to_nibbles() {
        let key = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

        let nibbles = key_to_nibbles(&key);

        assert_eq!(nibbles.len(), 64);
        assert_eq!(nibbles[0], 0x1);
        assert_eq!(nibbles[1], 0x2);
        assert_eq!(nibbles[2], 0x3);
        assert_eq!(nibbles[3], 0x4);
    }

    #[test]
    fn test_larger_dataset() {
        let mut stack_trie = StackTrie::new();
        let mut merkle_trie = MerkleTrie::new();

        // Generate 1000 random entries
        let mut entries: Vec<([u8; 32], Vec<u8>)> = (0..1000u32).map(|i| {
            let key = keccak256(&i.to_le_bytes());
            let value = format!("value_{}", i).into_bytes();
            (key, value)
        }).collect();

        // Sort by key (critical for StackTrie!)
        entries.sort_by(|a, b| a.0.cmp(&b.0));

        // Insert into both tries
        for (key, value) in &entries {
            stack_trie.insert(key, value);
            merkle_trie.insert(key, value.clone());
        }

        let stack_root = stack_trie.finalize();
        let merkle_root = merkle_trie.root_hash();

        assert_eq!(stack_root, merkle_root,
            "StackTrie root {:?} != MerkleTrie root {:?}",
            hex::encode(stack_root), hex::encode(merkle_root));
    }

    #[test]
    fn test_build_from_sorted_iter() {
        let mut merkle_trie = MerkleTrie::new();

        // Generate sorted entries
        let mut entries: Vec<([u8; 32], Vec<u8>)> = (0..500u32).map(|i| {
            let key = keccak256(&i.to_le_bytes());
            let value = format!("value_{}", i).into_bytes();
            (key, value)
        }).collect();
        entries.sort_by(|a, b| a.0.cmp(&b.0));

        // Insert into MerkleTrie
        for (key, value) in &entries {
            merkle_trie.insert(key, value.clone());
        }

        // Build using iterator
        let stack_root = StackTrie::build_from_sorted_iter(entries.into_iter());
        let merkle_root = merkle_trie.root_hash();

        assert_eq!(stack_root, merkle_root);
    }

    #[test]
    fn test_bucket_to_nibbles() {
        assert_eq!(bucket_to_nibbles(0x1234), [1, 2, 3, 4]);
        assert_eq!(bucket_to_nibbles(0xABCD), [0xA, 0xB, 0xC, 0xD]);
        assert_eq!(bucket_to_nibbles(0x0000), [0, 0, 0, 0]);
        assert_eq!(bucket_to_nibbles(0xFFFF), [0xF, 0xF, 0xF, 0xF]);
    }

    #[test]
    fn test_key_to_bucket() {
        let mut key = [0u8; 32];
        key[0] = 0x12;
        key[1] = 0x34;
        assert_eq!(key_to_bucket(&key), 0x1234);

        key[0] = 0xAB;
        key[1] = 0xCD;
        assert_eq!(key_to_bucket(&key), 0xABCD);
    }

    #[test]
    fn test_memory_efficiency() {
        // This test verifies that StackTrie doesn't allocate O(N) memory
        // by checking that we can process many entries without issues
        let mut entries: Vec<([u8; 32], Vec<u8>)> = (0..10000u32).map(|i| {
            let key = keccak256(&i.to_le_bytes());
            let value = vec![i as u8; 32]; // Fixed size values
            (key, value)
        }).collect();
        entries.sort_by(|a, b| a.0.cmp(&b.0));

        // The stack should never grow beyond ~64 frames
        let mut trie = StackTrie::new();
        let mut max_stack_size = 0;

        for (key, value) in &entries {
            trie.insert(key, value);
            max_stack_size = max_stack_size.max(trie.stack.len());
        }

        // Stack should be bounded by depth (64 nibbles)
        assert!(max_stack_size <= 65, "Stack grew too large: {}", max_stack_size);

        let _root = trie.finalize();
    }
}
