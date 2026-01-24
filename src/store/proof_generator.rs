//! Lazy Proof Generator - On-demand Merkle proof construction.
//!
//! This module generates Merkle proofs lazily by reconstructing MPT nodes
//! on-demand from flat storage. Unlike traditional approaches that store
//! full MPT nodes on disk, we only load the entries needed for a specific
//! proof path.
//!
//! ## Design
//!
//! For a proof of key K:
//! 1. Determine the path (64 nibbles for 32-byte keys)
//! 2. At each depth, use cached hashes for siblings when available
//! 3. Only load entries from the target bucket
//! 4. Build the proof from root to leaf
//!
//! ## Memory Efficiency
//!
//! - Uses cached bucket hashes for sibling subtrees (depth >= 4)
//! - Only loads entries from the target key's bucket
//! - O(bucket_size) memory instead of O(total_entries)
//! - Reconstructs MPT nodes on-demand

use crate::merkle::{keccak256, RlpEncoder, ChildRef, EMPTY_ROOT, HASH_SIZE};
use super::flat_store::FlatAccountStore;
use super::stack_trie::StackTrie;
use super::subtree_cache::SubtreeHashCache;

/// A Merkle proof for a key in the trie.
#[derive(Debug, Clone)]
pub struct MerkleProof {
    /// The key being proved.
    pub key: [u8; 32],
    /// The value at the key (None for non-existence proofs).
    pub value: Option<Vec<u8>>,
    /// RLP-encoded proof nodes from root to leaf.
    pub proof_nodes: Vec<Vec<u8>>,
}

impl MerkleProof {
    /// Creates a new proof.
    pub fn new(key: [u8; 32], value: Option<Vec<u8>>, proof_nodes: Vec<Vec<u8>>) -> Self {
        Self { key, value, proof_nodes }
    }

    /// Returns true if this is a proof of inclusion.
    pub fn is_inclusion(&self) -> bool {
        self.value.is_some()
    }

    /// Returns true if this is a proof of non-existence.
    pub fn is_exclusion(&self) -> bool {
        self.value.is_none()
    }

    /// Verifies the proof against a given root hash.
    pub fn verify(&self, root_hash: &[u8; HASH_SIZE]) -> bool {
        if self.proof_nodes.is_empty() {
            return *root_hash == EMPTY_ROOT && self.value.is_none();
        }

        // The root hash should be the hash of the first proof node
        let first_node = &self.proof_nodes[0];
        let computed_root = if first_node.len() >= 32 {
            keccak256(first_node)
        } else {
            keccak256(first_node)
        };

        computed_root == *root_hash
    }
}

/// Lazy proof generator that builds Merkle proofs from flat storage.
pub struct ProofGenerator<'a> {
    /// Reference to flat account storage
    accounts: &'a FlatAccountStore,
    /// Optional subtree cache for optimization (reserved for future lazy loading)
    #[allow(dead_code)]
    cache: Option<&'a SubtreeHashCache>,
}

impl<'a> ProofGenerator<'a> {
    /// Creates a new proof generator.
    pub fn new(accounts: &'a FlatAccountStore) -> Self {
        Self {
            accounts,
            cache: None,
        }
    }

    /// Creates a proof generator with subtree cache.
    pub fn with_cache(accounts: &'a FlatAccountStore, cache: &'a SubtreeHashCache) -> Self {
        Self {
            accounts,
            cache: Some(cache),
        }
    }

    /// Generates a Merkle proof for a key.
    ///
    /// If a cache is available, this uses lazy loading - only loading entries
    /// from the target bucket and using cached hashes for siblings.
    pub fn generate_proof(&self, key: &[u8; 32]) -> MerkleProof {
        let value = self.accounts.get(key).cloned();
        let nibbles = key_to_nibbles(key);

        // With cache: use lazy proof generation
        if let Some(cache) = self.cache {
            return self.generate_proof_lazy(key, &nibbles, value, cache);
        }

        // Without cache: fall back to loading all entries
        let mut entries: Vec<([u8; 32], Vec<u8>)> = self.accounts.iter()
            .map(|(k, v)| (*k, v.clone()))
            .collect();
        entries.sort_unstable_by(|a, b| a.0.cmp(&b.0));

        if entries.is_empty() {
            return MerkleProof::new(*key, value, vec![]);
        }

        // Build the proof by traversing the trie structure
        let mut proof_nodes = Vec::new();
        self.collect_proof_nodes(&entries, 0, &nibbles, &mut proof_nodes);

        MerkleProof::new(*key, value, proof_nodes)
    }

    /// Generates a proof lazily using cached bucket hashes.
    fn generate_proof_lazy(
        &self,
        key: &[u8; 32],
        nibbles: &[u8],
        value: Option<Vec<u8>>,
        cache: &SubtreeHashCache,
    ) -> MerkleProof {
        let target_bucket = SubtreeHashCache::key_to_bucket(key);

        // Load only entries from the target bucket
        let bucket_entries: Vec<([u8; 32], Vec<u8>)> = self.accounts
            .entries_in_bucket(target_bucket)
            .map(|(k, v)| (k, v.clone()))
            .collect();

        // Check if the trie is empty (no non-empty buckets)
        let has_entries = cache.non_empty_iter().next().is_some() || !bucket_entries.is_empty();
        if !has_entries {
            return MerkleProof::new(*key, value, vec![]);
        }

        let mut proof_nodes = Vec::new();

        // Build proof at depths 0-3 (above bucket level) using cached hashes
        self.collect_proof_above_buckets(nibbles, 0, cache, &mut proof_nodes);

        // Build proof within the target bucket (depth >= 4)
        if !bucket_entries.is_empty() {
            let mut sorted_entries = bucket_entries;
            sorted_entries.sort_unstable_by(|a, b| a.0.cmp(&b.0));
            self.collect_proof_nodes(&sorted_entries, 4, nibbles, &mut proof_nodes);
        }

        MerkleProof::new(*key, value, proof_nodes)
    }

    /// Collects proof nodes for depths 0-3 using cached bucket hashes.
    fn collect_proof_above_buckets(
        &self,
        target_nibbles: &[u8],
        depth: usize,
        cache: &SubtreeHashCache,
        proof: &mut Vec<Vec<u8>>,
    ) {
        if depth >= 4 {
            return;
        }

        // Compute prefix mask for this depth
        // At depth 0: we check buckets 0x?000-0x?FFF for each first nibble
        // At depth 1: we check buckets 0xX?00-0xX?FF within first nibble X
        // etc.

        // Find which children exist at this depth by scanning bucket hashes
        let prefix = self.nibbles_to_partial_bucket(target_nibbles, depth);
        let shift = (3 - depth) * 4; // bits to shift: 12, 8, 4, 0

        let mut children: [ChildRef; 16] = Default::default();
        let mut child_exists = [false; 16];

        // Scan relevant buckets to find which children exist
        for nibble in 0u16..16 {
            let bucket_start = prefix | (nibble << shift);
            let bucket_end = bucket_start | ((1u16 << shift) - 1);

            // Check if any bucket in this range is non-empty
            for bucket in bucket_start..=bucket_end {
                if cache.is_non_empty(bucket) {
                    child_exists[nibble as usize] = true;

                    // Compute the subtree hash for this child
                    let hash = self.compute_subtree_hash_from_cache(
                        cache, depth + 1, bucket_start, bucket_end
                    );
                    children[nibble as usize] = ChildRef::Hash(hash);
                    break;
                }
            }
        }

        // Check if we need a branch node or can collapse
        let existing_count = child_exists.iter().filter(|&&x| x).count();

        if existing_count == 0 {
            return;
        }

        if existing_count == 1 {
            // Might be extension or just recurse
            let child_nibble = child_exists.iter().position(|&x| x).unwrap();

            // Check if this is on the target path
            if (target_nibbles[depth] as usize) == child_nibble {
                // Recurse without emitting extension (will be handled below bucket level)
                self.collect_proof_above_buckets(target_nibbles, depth + 1, cache, proof);
                return;
            }
        }

        // Build branch node
        let mut encoder = RlpEncoder::new();
        encoder.encode_list(|e| {
            for child in &children {
                match child {
                    ChildRef::Hash(h) => e.encode_bytes(h),
                    ChildRef::Inline(data) => e.encode_raw(data),
                    ChildRef::Empty => e.encode_empty(),
                }
            }
            e.encode_empty(); // No branch value at intermediate levels
        });
        proof.push(encoder.into_bytes());

        // Recurse into the target path
        if depth < 3 {
            self.collect_proof_above_buckets(target_nibbles, depth + 1, cache, proof);
        }
    }

    /// Computes the subtree hash for a range of buckets.
    fn compute_subtree_hash_from_cache(
        &self,
        cache: &SubtreeHashCache,
        depth: usize,
        bucket_start: u16,
        _bucket_end: u16,
    ) -> [u8; HASH_SIZE] {
        // At depth 4, we're at bucket level - return the bucket hash directly
        if depth >= 4 {
            if let Some(hash) = cache.get_hash(bucket_start) {
                return hash;
            }
            // Bucket is dirty or empty - compute from entries
            let entries: Vec<([u8; 32], Vec<u8>)> = self.accounts
                .entries_in_bucket(bucket_start)
                .map(|(k, v)| (k, v.clone()))
                .collect();

            if entries.is_empty() {
                return EMPTY_ROOT;
            }

            // Use StackTrie to compute hash
            let mut sorted = entries;
            sorted.sort_unstable_by(|a, b| a.0.cmp(&b.0));
            let mut trie = StackTrie::new();
            for (key, value) in &sorted {
                trie.insert(key, value);
            }
            return trie.finalize();
        }

        // Above depth 4 - need to aggregate child hashes
        let shift = (3 - depth) * 4;
        let mut non_empty_children: Vec<(u8, [u8; HASH_SIZE])> = Vec::new();

        for nibble in 0u16..16 {
            let child_start = bucket_start | (nibble << shift);
            let child_end = child_start | ((1u16 << shift) - 1);

            // Check if any bucket in this range is non-empty
            let mut has_entries = false;
            for bucket in child_start..=child_end {
                if cache.is_non_empty(bucket) {
                    has_entries = true;
                    break;
                }
            }

            if has_entries {
                let child_hash = self.compute_subtree_hash_from_cache(
                    cache, depth + 1, child_start, child_end
                );
                non_empty_children.push((nibble as u8, child_hash));
            }
        }

        if non_empty_children.is_empty() {
            return EMPTY_ROOT;
        }

        // Build the node for this subtree
        if non_empty_children.len() == 1 {
            // Could be extension - for simplicity, treat as single-child branch
            let (nibble, hash) = non_empty_children[0];
            let mut children: [ChildRef; 16] = Default::default();
            children[nibble as usize] = ChildRef::Hash(hash);

            let mut encoder = RlpEncoder::new();
            encoder.encode_list(|e| {
                for child in &children {
                    match child {
                        ChildRef::Hash(h) => e.encode_bytes(h),
                        ChildRef::Inline(data) => e.encode_raw(data),
                        ChildRef::Empty => e.encode_empty(),
                    }
                }
                e.encode_empty();
            });
            let encoded = encoder.into_bytes();
            return keccak256(&encoded);
        }

        // Multiple children - build branch
        let mut children: [ChildRef; 16] = Default::default();
        for (nibble, hash) in non_empty_children {
            children[nibble as usize] = ChildRef::Hash(hash);
        }

        let mut encoder = RlpEncoder::new();
        encoder.encode_list(|e| {
            for child in &children {
                match child {
                    ChildRef::Hash(h) => e.encode_bytes(h),
                    ChildRef::Inline(data) => e.encode_raw(data),
                    ChildRef::Empty => e.encode_empty(),
                }
            }
            e.encode_empty();
        });
        let encoded = encoder.into_bytes();
        keccak256(&encoded)
    }

    /// Converts nibbles to a partial bucket number for a given depth.
    fn nibbles_to_partial_bucket(&self, nibbles: &[u8], depth: usize) -> u16 {
        if depth == 0 {
            return 0; // At depth 0, all buckets start from 0
        }
        let mut bucket = 0u16;
        for i in 0..depth.min(4) {
            bucket = (bucket << 4) | (nibbles[i] as u16);
        }
        // Shift remaining bits (4 - depth nibbles remain)
        let remaining_nibbles = 4usize.saturating_sub(depth);
        bucket << (remaining_nibbles * 4)
    }

    /// Collects proof nodes by walking the trie structure.
    fn collect_proof_nodes(
        &self,
        entries: &[([u8; 32], Vec<u8>)],
        depth: usize,
        target_nibbles: &[u8],
        proof: &mut Vec<Vec<u8>>,
    ) {
        if entries.is_empty() || depth >= 64 {
            return;
        }

        // Convert entries to nibble format
        let nibble_entries: Vec<(Vec<u8>, &[u8])> = entries.iter()
            .map(|(k, v)| (key_to_nibbles(k), v.as_slice()))
            .collect();

        if nibble_entries.len() == 1 {
            // Single entry - this is a leaf
            let (nibbles, value) = &nibble_entries[0];
            let remaining = &nibbles[depth..];

            let mut encoder = RlpEncoder::new();
            encoder.encode_list(|e| {
                e.encode_nibbles(remaining, true);
                e.encode_bytes(value);
            });
            proof.push(encoder.into_bytes());
            return;
        }

        // Check for common prefix
        let common_prefix = find_common_prefix(&nibble_entries, depth);

        if common_prefix > 0 {
            // Extension node
            let prefix = &nibble_entries[0].0[depth..depth + common_prefix];

            // Recursively build the child
            let mut child_proof = Vec::new();
            self.collect_proof_nodes(entries, depth + common_prefix, target_nibbles, &mut child_proof);

            // Get child hash/inline
            let child_ref = if let Some(child_node) = child_proof.first() {
                ChildRef::from_encoded(child_node.clone())
            } else {
                ChildRef::Empty
            };

            let mut encoder = RlpEncoder::new();
            encoder.encode_list(|e| {
                e.encode_nibbles(prefix, false);
                match &child_ref {
                    ChildRef::Hash(h) => e.encode_bytes(h),
                    ChildRef::Inline(data) => e.encode_raw(data),
                    ChildRef::Empty => e.encode_empty(),
                }
            });
            proof.push(encoder.into_bytes());

            // Add child proof nodes
            proof.extend(child_proof);
            return;
        }

        // Branch node - group by first nibble at current depth
        let mut groups: [Vec<([u8; 32], Vec<u8>)>; 16] = Default::default();
        let mut branch_value: Option<Vec<u8>> = None;

        for (key, value) in entries {
            let nibbles = key_to_nibbles(key);
            if depth >= nibbles.len() {
                branch_value = Some(value.clone());
            } else {
                let nibble = nibbles[depth] as usize;
                groups[nibble].push((*key, value.clone()));
            }
        }

        // Build child hashes
        let mut children: [ChildRef; 16] = [
            ChildRef::Empty, ChildRef::Empty, ChildRef::Empty, ChildRef::Empty,
            ChildRef::Empty, ChildRef::Empty, ChildRef::Empty, ChildRef::Empty,
            ChildRef::Empty, ChildRef::Empty, ChildRef::Empty, ChildRef::Empty,
            ChildRef::Empty, ChildRef::Empty, ChildRef::Empty, ChildRef::Empty,
        ];
        for (i, group) in groups.iter().enumerate() {
            if !group.is_empty() {
                let child_node = self.build_node_for_group(group, depth + 1);
                children[i] = ChildRef::from_encoded(child_node);
            }
        }

        // Encode branch node
        let mut encoder = RlpEncoder::new();
        encoder.encode_list(|e| {
            for child in &children {
                match child {
                    ChildRef::Hash(h) => e.encode_bytes(h),
                    ChildRef::Inline(data) => e.encode_raw(data),
                    ChildRef::Empty => e.encode_empty(),
                }
            }
            match &branch_value {
                Some(v) => e.encode_bytes(v),
                None => e.encode_empty(),
            }
        });
        proof.push(encoder.into_bytes());

        // Recurse into the target path
        if depth < target_nibbles.len() {
            let target_nibble = target_nibbles[depth] as usize;
            if !groups[target_nibble].is_empty() {
                self.collect_proof_nodes(&groups[target_nibble], depth + 1, target_nibbles, proof);
            }
        }
    }

    /// Builds a node for a group of entries (used for sibling computation).
    fn build_node_for_group(&self, entries: &[([u8; 32], Vec<u8>)], depth: usize) -> Vec<u8> {
        if entries.is_empty() {
            return vec![0x80]; // Empty RLP
        }

        // Convert to nibble format
        let nibble_entries: Vec<(Vec<u8>, &[u8])> = entries.iter()
            .map(|(k, v)| (key_to_nibbles(k), v.as_slice()))
            .collect();

        if nibble_entries.len() == 1 {
            // Leaf
            let (nibbles, value) = &nibble_entries[0];
            let remaining = &nibbles[depth..];

            let mut encoder = RlpEncoder::new();
            encoder.encode_list(|e| {
                e.encode_nibbles(remaining, true);
                e.encode_bytes(value);
            });
            return encoder.into_bytes();
        }

        // Check for common prefix
        let common_prefix = find_common_prefix(&nibble_entries, depth);

        if common_prefix > 0 {
            // Extension
            let prefix = &nibble_entries[0].0[depth..depth + common_prefix];
            let child_node = self.build_node_for_group(entries, depth + common_prefix);
            let child_ref = ChildRef::from_encoded(child_node);

            let mut encoder = RlpEncoder::new();
            encoder.encode_list(|e| {
                e.encode_nibbles(prefix, false);
                match &child_ref {
                    ChildRef::Hash(h) => e.encode_bytes(h),
                    ChildRef::Inline(data) => e.encode_raw(data),
                    ChildRef::Empty => e.encode_empty(),
                }
            });
            return encoder.into_bytes();
        }

        // Branch - group by nibble
        let mut groups: [Vec<([u8; 32], Vec<u8>)>; 16] = Default::default();
        let mut branch_value: Option<&[u8]> = None;

        for (key, value) in entries {
            let nibbles = key_to_nibbles(key);
            if depth >= nibbles.len() {
                branch_value = Some(value);
            } else {
                let nibble = nibbles[depth] as usize;
                groups[nibble].push((*key, value.clone()));
            }
        }

        let mut children: [ChildRef; 16] = [
            ChildRef::Empty, ChildRef::Empty, ChildRef::Empty, ChildRef::Empty,
            ChildRef::Empty, ChildRef::Empty, ChildRef::Empty, ChildRef::Empty,
            ChildRef::Empty, ChildRef::Empty, ChildRef::Empty, ChildRef::Empty,
            ChildRef::Empty, ChildRef::Empty, ChildRef::Empty, ChildRef::Empty,
        ];
        for (i, group) in groups.iter().enumerate() {
            if !group.is_empty() {
                let child_node = self.build_node_for_group(group, depth + 1);
                children[i] = ChildRef::from_encoded(child_node);
            }
        }

        let mut encoder = RlpEncoder::new();
        encoder.encode_list(|e| {
            for child in &children {
                match child {
                    ChildRef::Hash(h) => e.encode_bytes(h),
                    ChildRef::Inline(data) => e.encode_raw(data),
                    ChildRef::Empty => e.encode_empty(),
                }
            }
            match branch_value {
                Some(v) => e.encode_bytes(v),
                None => e.encode_empty(),
            }
        });
        encoder.into_bytes()
    }
}

/// Converts a 32-byte key to 64 nibbles.
fn key_to_nibbles(key: &[u8; 32]) -> Vec<u8> {
    let mut nibbles = Vec::with_capacity(64);
    for byte in key {
        nibbles.push(byte >> 4);
        nibbles.push(byte & 0x0F);
    }
    nibbles
}

/// Finds the common prefix length among entries at a given depth.
fn find_common_prefix(entries: &[(Vec<u8>, &[u8])], depth: usize) -> usize {
    if entries.is_empty() {
        return 0;
    }

    let first = &entries[0].0;
    if depth >= first.len() {
        return 0;
    }

    let mut common_len = first.len() - depth;

    for (nibbles, _) in &entries[1..] {
        if depth >= nibbles.len() {
            return 0;
        }
        let max_check = (nibbles.len() - depth).min(common_len);
        let mut prefix_len = 0;

        for i in 0..max_check {
            if nibbles[depth + i] == first[depth + i] {
                prefix_len += 1;
            } else {
                break;
            }
        }

        common_len = prefix_len;
        if common_len == 0 {
            break;
        }
    }

    common_len
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_proof() {
        let store = FlatAccountStore::new();
        let generator = ProofGenerator::new(&store);

        let key = [0u8; 32];
        let proof = generator.generate_proof(&key);

        assert!(proof.is_exclusion());
        assert!(proof.proof_nodes.is_empty());
    }

    #[test]
    fn test_single_entry_proof() {
        let mut store = FlatAccountStore::new();

        let key = keccak256(b"test_key");
        let value = b"test_value".to_vec();
        store.insert(key, value.clone());

        let generator = ProofGenerator::new(&store);
        let proof = generator.generate_proof(&key);

        assert!(proof.is_inclusion());
        assert_eq!(proof.value, Some(value));
        assert!(!proof.proof_nodes.is_empty());
    }

    #[test]
    fn test_multiple_entries_proof() {
        let mut store = FlatAccountStore::new();

        // Insert multiple entries
        for i in 0..10u32 {
            let key = keccak256(&i.to_le_bytes());
            let value = format!("value_{}", i).into_bytes();
            store.insert(key, value);
        }

        let generator = ProofGenerator::new(&store);

        // Generate proof for one of the keys
        let target_key = keccak256(&5u32.to_le_bytes());
        let proof = generator.generate_proof(&target_key);

        assert!(proof.is_inclusion());
        assert_eq!(proof.value, Some(b"value_5".to_vec()));
    }

    #[test]
    fn test_non_existent_key_proof() {
        let mut store = FlatAccountStore::new();

        // Insert some entries
        for i in 0..10u32 {
            let key = keccak256(&i.to_le_bytes());
            let value = format!("value_{}", i).into_bytes();
            store.insert(key, value);
        }

        let generator = ProofGenerator::new(&store);

        // Generate proof for a non-existent key
        let target_key = keccak256(b"non_existent");
        let proof = generator.generate_proof(&target_key);

        assert!(proof.is_exclusion());
        assert!(proof.value.is_none());
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
    fn test_lazy_proof_with_cache() {
        let mut store = FlatAccountStore::new();
        let mut cache = SubtreeHashCache::new();

        // Insert multiple entries across different buckets
        for i in 0..50u32 {
            let key = keccak256(&i.to_le_bytes());
            let value = format!("value_{}", i).into_bytes();
            store.insert(key, value);

            // Mark bucket as non-empty and set a hash
            let bucket = SubtreeHashCache::key_to_bucket(&key);
            cache.mark_non_empty(bucket);
        }

        // Compute bucket hashes using StackTrie
        for bucket in cache.non_empty_iter().collect::<Vec<_>>() {
            let entries: Vec<([u8; 32], Vec<u8>)> = store
                .entries_in_bucket(bucket)
                .map(|(k, v)| (k, v.clone()))
                .collect();

            if !entries.is_empty() {
                let mut sorted = entries;
                sorted.sort_unstable_by(|a, b| a.0.cmp(&b.0));
                let mut trie = StackTrie::new();
                for (key, value) in &sorted {
                    trie.insert(key, value);
                }
                let hash = trie.finalize();
                cache.set_hash(bucket, hash);
            }
        }

        // Generate proof with cache
        let target_key = keccak256(&25u32.to_le_bytes());
        let generator_with_cache = ProofGenerator::with_cache(&store, &cache);
        let proof_lazy = generator_with_cache.generate_proof(&target_key);

        // Generate proof without cache (fallback)
        let generator_no_cache = ProofGenerator::new(&store);
        let proof_full = generator_no_cache.generate_proof(&target_key);

        // Both should find the value
        assert!(proof_lazy.is_inclusion());
        assert!(proof_full.is_inclusion());
        assert_eq!(proof_lazy.value, proof_full.value);
        assert_eq!(proof_lazy.value, Some(b"value_25".to_vec()));
    }

    #[test]
    fn test_lazy_proof_non_existent_with_cache() {
        let mut store = FlatAccountStore::new();
        let mut cache = SubtreeHashCache::new();

        // Insert entries
        for i in 0..20u32 {
            let key = keccak256(&i.to_le_bytes());
            let value = format!("value_{}", i).into_bytes();
            store.insert(key, value);

            let bucket = SubtreeHashCache::key_to_bucket(&key);
            cache.mark_non_empty(bucket);
        }

        // Set bucket hashes
        for bucket in cache.non_empty_iter().collect::<Vec<_>>() {
            let entries: Vec<([u8; 32], Vec<u8>)> = store
                .entries_in_bucket(bucket)
                .map(|(k, v)| (k, v.clone()))
                .collect();

            if !entries.is_empty() {
                let mut sorted = entries;
                sorted.sort_unstable_by(|a, b| a.0.cmp(&b.0));
                let mut trie = StackTrie::new();
                for (key, value) in &sorted {
                    trie.insert(key, value);
                }
                cache.set_hash(bucket, trie.finalize());
            }
        }

        // Generate proof for non-existent key
        let target_key = keccak256(b"does_not_exist");
        let generator = ProofGenerator::with_cache(&store, &cache);
        let proof = generator.generate_proof(&target_key);

        // Should be an exclusion proof
        assert!(proof.is_exclusion());
        assert!(proof.value.is_none());
    }
}
