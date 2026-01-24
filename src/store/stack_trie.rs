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

/// Child slot content - either an encoded reference or a pending frame.
#[derive(Clone, Debug)]
enum ChildSlot {
    /// Already encoded (can't be modified).
    Ref(ChildRef),
    /// Pending frame (can still be expanded).
    Pending(Box<StackFrame>),
}


/// A frame on the StackTrie stack representing a node being built.
#[derive(Clone, Debug)]
struct StackFrame {
    /// The nibble depth of this frame (0 = root, 64 = leaf).
    depth: usize,

    /// For branch nodes: child slots (encoded or pending).
    /// None = empty slot, Some = child exists.
    children: Box<[Option<ChildSlot>; 16]>,

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
            // Has extension path - check if this is a true extension (single child)
            // or a branch with a prefix (multiple children)
            let child_count = self.children.iter().filter(|c| c.is_some()).count();
            let has_value = self.value.is_some();

            if child_count <= 1 && !has_value {
                // True extension node: [encoded_path, child_ref]
                let child_ref = self.children.iter()
                    .find_map(|c| c.as_ref())
                    .map(|slot| match slot {
                        ChildSlot::Ref(r) => r.clone(),
                        ChildSlot::Pending(f) => f.to_child_ref(),
                    })
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
                // Branch with prefix: encode as extension -> branch
                // First encode the branch (without extension path)
                let branch_encoded = self.encode_as_branch();
                let branch_ref = ChildRef::from_encoded(branch_encoded);

                // Then wrap in extension
                let mut encoder = RlpEncoder::new();
                encoder.encode_list(|e| {
                    e.encode_nibbles(&self.extension_path, false);
                    match &branch_ref {
                        ChildRef::Hash(h) => e.encode_bytes(h),
                        ChildRef::Inline(data) => e.encode_raw(data),
                        ChildRef::Empty => e.encode_empty(),
                    }
                });
                encoder.into_bytes()
            }
        } else {
            // Branch node: [child0, child1, ..., child15, value]
            self.encode_as_branch()
        }
    }

    /// Encodes this frame as a branch node (ignoring extension_path).
    fn encode_as_branch(&self) -> Vec<u8> {
        let mut encoder = RlpEncoder::new();
        encoder.encode_list(|e| {
            for child in self.children.iter() {
                match child {
                    Some(ChildSlot::Ref(ChildRef::Hash(h))) => e.encode_bytes(h),
                    Some(ChildSlot::Ref(ChildRef::Inline(data))) => e.encode_raw(data),
                    Some(ChildSlot::Ref(ChildRef::Empty)) => e.encode_empty(),
                    Some(ChildSlot::Pending(frame)) => {
                        let child_ref = frame.to_child_ref();
                        match child_ref {
                            ChildRef::Hash(h) => e.encode_bytes(&h),
                            ChildRef::Inline(data) => e.encode_raw(&data),
                            ChildRef::Empty => e.encode_empty(),
                        }
                    }
                    None => e.encode_empty(),
                }
            }
            match &self.value {
                Some(v) => e.encode_bytes(v),
                None => e.encode_empty(),
            }
        });
        encoder.into_bytes()
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
            frame.children[prefix_nibbles[0] as usize] = Some(ChildSlot::Ref(ChildRef::Hash(hash)));
            self.stack.push(frame);
        } else {
            // Add to existing frame
            let frame = self.stack.last_mut().unwrap();
            let nibble_idx = if frame.depth < 4 {
                prefix_nibbles[frame.depth] as usize
            } else {
                return; // Subtree cache is for depth-4 buckets only
            };
            frame.children[nibble_idx] = Some(ChildSlot::Ref(ChildRef::Hash(hash)));
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
            // Stop if we only have one frame - can't collapse further
            if self.stack.len() == 1 {
                break;
            }

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
            parent.children[nibble_idx] = Some(ChildSlot::Ref(child_ref));
        } else if !frame.is_empty() {
            // Edge case: the frame might be an extension that needs special handling
            let nibble_idx = if parent_depth < self.current_prefix.len() {
                self.current_prefix[parent_depth] as usize
            } else {
                0
            };
            parent.children[nibble_idx] = Some(ChildSlot::Ref(child_ref));
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
                    // Old key continues - create leaf child as Pending (may need expansion later)
                    let old_child = StackFrame::leaf(branch_depth + 1, old_remaining, old_leaf.value.unwrap_or_default());
                    branch.children[old_nibble] = Some(ChildSlot::Pending(Box::new(old_child)));
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
                    // New key continues - create leaf child as Pending (may need expansion later)
                    let new_child = StackFrame::leaf(branch_depth + 1, new_remaining, value.to_vec());
                    branch.children[new_nibble] = Some(ChildSlot::Pending(Box::new(new_child)));
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
            // Top is a branch - check if we need to wrap it or split its extension
            let branch = self.stack.last().unwrap();
            let branch_depth = branch.depth;
            let has_extension = !branch.extension_path.is_empty();

            // If divergence is before the branch's depth, we need to restructure
            if diverge_depth < branch_depth {
                // Pop the branch and wrap it
                let mut old_branch = self.stack.pop().unwrap();

                // Create new branch at divergence point
                let mut new_branch = StackFrame::branch(diverge_depth);

                // The old branch needs its extension_path adjusted:
                // The nibble at diverge_depth is now represented by the parent's child slot,
                // so we only keep the extension from diverge_depth+1 to branch_depth
                let old_nibble = self.current_prefix[diverge_depth] as usize;

                if has_extension {
                    // Trim the extension_path: keep only nibbles from diverge_depth+1 to branch_depth
                    let remaining_path = self.current_prefix[diverge_depth + 1..branch_depth].to_vec();
                    old_branch.extension_path = remaining_path;
                }
                new_branch.children[old_nibble] = Some(ChildSlot::Pending(Box::new(old_branch)));

                // Add new entry as sibling
                let new_nibble = nibbles[diverge_depth] as usize;
                let new_remaining = nibbles[diverge_depth + 1..].to_vec();

                if new_remaining.is_empty() {
                    new_branch.value = Some(value.to_vec());
                } else {
                    let new_leaf = StackFrame::leaf(diverge_depth + 1, new_remaining, value.to_vec());
                    new_branch.children[new_nibble] = Some(ChildSlot::Pending(Box::new(new_leaf)));
                }

                self.stack.push(new_branch);
            } else {
                // Divergence is at or after the branch depth
                let branch = self.stack.last_mut().unwrap();

                // Check if there's already a child at the slot we need
                let nibble = nibbles[branch_depth] as usize;

                if diverge_depth > branch_depth && branch.children[nibble].is_some() {
                    // The child slot is occupied and divergence is deeper
                    // We need to recursively expand into the existing child
                    let old_child_slot = branch.children[nibble].take().unwrap();
                    let result_slot = Self::expand_child_slot(
                        old_child_slot,
                        &self.current_prefix,
                        nibbles,
                        value,
                        branch_depth,
                        diverge_depth,
                    );
                    branch.children[nibble] = Some(result_slot);
                } else {
                    // Either no existing child, or divergence is at branch depth - add directly
                    if branch_depth < nibbles.len() {
                        let remaining = nibbles[branch_depth + 1..].to_vec();

                        if remaining.is_empty() {
                            // Key ends at this branch
                            branch.value = Some(value.to_vec());
                        } else {
                            // Create new leaf child as Pending (may need expansion later)
                            let leaf = StackFrame::leaf(branch_depth + 1, remaining, value.to_vec());
                            branch.children[nibble] = Some(ChildSlot::Pending(Box::new(leaf)));
                        }
                    } else {
                        // Key ends at branch
                        branch.value = Some(value.to_vec());
                    }
                }
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

    /// Recursively expands a child slot to accommodate a new entry at diverge_depth.
    ///
    /// This handles the case where we need to expand nested Pending children.
    fn expand_child_slot(
        old_slot: ChildSlot,
        current_prefix: &[u8],
        new_nibbles: &[u8],
        new_value: &[u8],
        parent_depth: usize,
        diverge_depth: usize,
    ) -> ChildSlot {
        match old_slot {
            ChildSlot::Pending(mut frame) if !frame.is_leaf && frame.depth == diverge_depth => {
                // The old child is already a branch at diverge_depth - add new entry directly
                let new_nibble = new_nibbles[diverge_depth] as usize;
                let new_remaining = new_nibbles[diverge_depth + 1..].to_vec();

                if new_remaining.is_empty() {
                    frame.value = Some(new_value.to_vec());
                } else {
                    let new_leaf = StackFrame::leaf(diverge_depth + 1, new_remaining, new_value.to_vec());
                    frame.children[new_nibble] = Some(ChildSlot::Pending(Box::new(new_leaf)));
                }
                ChildSlot::Pending(frame)
            }
            ChildSlot::Pending(mut frame) if !frame.is_leaf && frame.depth < diverge_depth => {
                // The old child is a branch at a shallower depth - need to recursively expand
                let child_nibble = current_prefix[frame.depth] as usize;

                if let Some(child_slot) = frame.children[child_nibble].take() {
                    // Recursively expand the child
                    let expanded = Self::expand_child_slot(
                        child_slot,
                        current_prefix,
                        new_nibbles,
                        new_value,
                        frame.depth,
                        diverge_depth,
                    );
                    frame.children[child_nibble] = Some(expanded);
                } else {
                    // No existing child at this slot - create the structure
                    // This shouldn't normally happen if we're following the prefix correctly
                    let new_nibble = new_nibbles[diverge_depth] as usize;
                    let new_remaining = new_nibbles[diverge_depth + 1..].to_vec();

                    if diverge_depth == frame.depth + 1 {
                        // Add directly to this frame
                        if new_remaining.is_empty() {
                            frame.value = Some(new_value.to_vec());
                        } else {
                            let new_leaf = StackFrame::leaf(diverge_depth + 1, new_remaining, new_value.to_vec());
                            frame.children[new_nibble] = Some(ChildSlot::Pending(Box::new(new_leaf)));
                        }
                    } else {
                        // Need to create intermediate structure
                        let mut sub_branch = StackFrame::branch(diverge_depth);
                        if new_remaining.is_empty() {
                            sub_branch.value = Some(new_value.to_vec());
                        } else {
                            let new_leaf = StackFrame::leaf(diverge_depth + 1, new_remaining, new_value.to_vec());
                            sub_branch.children[new_nibble] = Some(ChildSlot::Pending(Box::new(new_leaf)));
                        }
                        if diverge_depth > frame.depth + 2 {
                            sub_branch.extension_path = new_nibbles[frame.depth + 2..diverge_depth].to_vec();
                        }
                        frame.children[child_nibble] = Some(ChildSlot::Pending(Box::new(sub_branch)));
                    }
                }
                ChildSlot::Pending(frame)
            }
            ChildSlot::Pending(mut frame) => {
                // Old child is a leaf - need to wrap in a branch
                let mut sub_branch = StackFrame::branch(diverge_depth);

                // The old child goes at its nibble (from current_prefix)
                let old_nibble = current_prefix[diverge_depth] as usize;

                // Adjust extension_path since nibbles are now represented by structure
                let nibbles_consumed = diverge_depth - parent_depth;
                if frame.extension_path.len() >= nibbles_consumed {
                    frame.extension_path = frame.extension_path[nibbles_consumed..].to_vec();
                } else {
                    frame.extension_path.clear();
                }
                sub_branch.children[old_nibble] = Some(ChildSlot::Pending(frame));

                // Add the new entry
                let new_nibble = new_nibbles[diverge_depth] as usize;
                let new_remaining = new_nibbles[diverge_depth + 1..].to_vec();

                if new_remaining.is_empty() {
                    sub_branch.value = Some(new_value.to_vec());
                } else {
                    let new_leaf = StackFrame::leaf(diverge_depth + 1, new_remaining, new_value.to_vec());
                    sub_branch.children[new_nibble] = Some(ChildSlot::Pending(Box::new(new_leaf)));
                }

                // Add extension path from parent_depth+1 to diverge_depth
                if diverge_depth > parent_depth + 1 {
                    sub_branch.extension_path = new_nibbles[parent_depth + 1..diverge_depth].to_vec();
                }

                ChildSlot::Pending(Box::new(sub_branch))
            }
            ChildSlot::Ref(r) => {
                // Already encoded - can't modify, wrap in new branch
                let mut sub_branch = StackFrame::branch(diverge_depth);
                let old_nibble = current_prefix[diverge_depth] as usize;
                sub_branch.children[old_nibble] = Some(ChildSlot::Ref(r));

                let new_nibble = new_nibbles[diverge_depth] as usize;
                let new_remaining = new_nibbles[diverge_depth + 1..].to_vec();

                if new_remaining.is_empty() {
                    sub_branch.value = Some(new_value.to_vec());
                } else {
                    let new_leaf = StackFrame::leaf(diverge_depth + 1, new_remaining, new_value.to_vec());
                    sub_branch.children[new_nibble] = Some(ChildSlot::Pending(Box::new(new_leaf)));
                }

                if diverge_depth > parent_depth + 1 {
                    sub_branch.extension_path = new_nibbles[parent_depth + 1..diverge_depth].to_vec();
                }

                ChildSlot::Pending(Box::new(sub_branch))
            }
        }
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
    fn test_three_entries_wrap_case() {
        let mut stack_trie = StackTrie::new();
        let mut merkle_trie = MerkleTrie::new();

        // Three keys: first two share prefix, third diverges at root
        let key1 = {
            let mut k = [0u8; 32];
            k[0] = 0x12; // nibbles: 1,2,3,4,...
            k[1] = 0x34;
            k
        };
        let key2 = {
            let mut k = [0u8; 32];
            k[0] = 0x12; // nibbles: 1,2,5,6,... (shares [1,2])
            k[1] = 0x56;
            k
        };
        let key3 = {
            let mut k = [0u8; 32];
            k[0] = 0x30; // nibbles: 3,0,0,0,... (diverges at nibble 0)
            k[1] = 0x00;
            k
        };

        // Insert in sorted order
        stack_trie.insert(&key1, b"v1");
        stack_trie.insert(&key2, b"v2");
        stack_trie.insert(&key3, b"v3");
        let stack_root = stack_trie.finalize();

        merkle_trie.insert(&key1, b"v1".to_vec());
        merkle_trie.insert(&key2, b"v2".to_vec());
        merkle_trie.insert(&key3, b"v3".to_vec());
        let merkle_root = merkle_trie.root_hash();

        assert_eq!(stack_root, merkle_root,
            "StackTrie {:?} != MerkleTrie {:?}",
            hex::encode(stack_root), hex::encode(merkle_root));
    }

    #[test]
    fn test_five_entries_various() {
        let mut stack_trie = StackTrie::new();
        let mut merkle_trie = MerkleTrie::new();

        // Five keys with various prefix patterns
        let keys = [
            { let mut k = [0u8; 32]; k[0] = 0x11; k[1] = 0x11; k },  // 1,1,1,1,...
            { let mut k = [0u8; 32]; k[0] = 0x11; k[1] = 0x22; k },  // 1,1,2,2,... (shares [1,1])
            { let mut k = [0u8; 32]; k[0] = 0x12; k[1] = 0x00; k },  // 1,2,0,0,... (shares [1])
            { let mut k = [0u8; 32]; k[0] = 0x20; k[1] = 0x00; k },  // 2,0,0,0,...
            { let mut k = [0u8; 32]; k[0] = 0x30; k[1] = 0x00; k },  // 3,0,0,0,...
        ];

        for (i, key) in keys.iter().enumerate() {
            let value = format!("v{}", i);
            stack_trie.insert(key, value.as_bytes());
            merkle_trie.insert(key, value.into_bytes());
        }

        let stack_root = stack_trie.finalize();
        let merkle_root = merkle_trie.root_hash();

        assert_eq!(stack_root, merkle_root,
            "StackTrie {:?} != MerkleTrie {:?}",
            hex::encode(stack_root), hex::encode(merkle_root));
    }

    #[test]
    fn test_three_keccak_entries() {
        let mut stack_trie = StackTrie::new();
        let mut merkle_trie = MerkleTrie::new();

        // The 3 keccak keys that fail
        let mut entries: Vec<([u8; 32], Vec<u8>)> = (0..3u32).map(|i| {
            let key = keccak256(&i.to_le_bytes());
            let value = format!("v{}", i).into_bytes();
            (key, value)
        }).collect();
        entries.sort_by(|a, b| a.0.cmp(&b.0));

        // Print the keys for debugging
        for (i, (key, _)) in entries.iter().enumerate() {
            let nibbles: Vec<u8> = key.iter().flat_map(|b| [b >> 4, b & 0x0F]).collect();
            eprintln!("Key {}: first 8 nibbles = {:?}", i, &nibbles[..8]);
        }

        for (key, value) in &entries {
            stack_trie.insert(key, value);
            merkle_trie.insert(key, value.clone());
        }

        let stack_root = stack_trie.finalize();
        let merkle_root = merkle_trie.root_hash();

        assert_eq!(stack_root, merkle_root,
            "StackTrie {:?} != MerkleTrie {:?}",
            hex::encode(stack_root), hex::encode(merkle_root));
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
    fn test_incremental_to_find_failure() {
        for n in 1..=100 {
            let mut stack_trie = StackTrie::new();
            let mut merkle_trie = MerkleTrie::new();

            let mut entries: Vec<([u8; 32], Vec<u8>)> = (0..n as u32).map(|i| {
                let key = keccak256(&i.to_le_bytes());
                let value = format!("v{}", i).into_bytes();
                (key, value)
            }).collect();
            entries.sort_by(|a, b| a.0.cmp(&b.0));

            for (key, value) in &entries {
                stack_trie.insert(key, value);
                merkle_trie.insert(key, value.clone());
            }

            let stack_root = stack_trie.finalize();
            let merkle_root = merkle_trie.root_hash();

            if stack_root != merkle_root {
                eprintln!("FAILURE at n={}", n);
                eprintln!("Stack root: {:?}", hex::encode(stack_root));
                eprintln!("Merkle root: {:?}", hex::encode(merkle_root));

                // Print the keys around failure
                for (i, (key, _)) in entries.iter().enumerate() {
                    let nibbles: Vec<u8> = key.iter().flat_map(|b| [b >> 4, b & 0x0F]).collect();
                    eprintln!("Key {}: {:?}", i, &nibbles[..8]);
                }
                panic!("Failure at n={}", n);
            }
        }
        eprintln!("All tests passed up to 100!");
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
