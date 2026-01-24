//! Specialized page types.
//!
//! Each page type provides specific functionality while sharing the common header.

use super::{DbAddress, Page, PageHeader, PageType, PAGE_SIZE};

/// Number of buckets in a data page (256 = 2 nibbles of fanout).
pub const BUCKET_COUNT: usize = 256;

// ============================================================================
// RootPage - Database metadata
// ============================================================================

/// Root page containing database metadata.
///
/// Layout after header:
/// - next_free_page: DbAddress (4 bytes)
/// - account_counter: u32 (4 bytes)
/// - state_root: DbAddress (4 bytes)
/// - block_number: u32 (4 bytes)
/// - block_hash: [u8; 32] (32 bytes)
/// - abandoned_pages: [DbAddress; ...] (remaining space)
pub struct RootPage {
    page: Page,
}

impl RootPage {
    /// Offset for next_free_page field.
    const NEXT_FREE_OFFSET: usize = PageHeader::SIZE;
    /// Offset for account_counter field.
    const ACCOUNT_COUNTER_OFFSET: usize = Self::NEXT_FREE_OFFSET + DbAddress::SIZE;
    /// Offset for state_root field.
    const STATE_ROOT_OFFSET: usize = Self::ACCOUNT_COUNTER_OFFSET + 4;
    /// Offset for block_number field.
    const BLOCK_NUMBER_OFFSET: usize = Self::STATE_ROOT_OFFSET + DbAddress::SIZE;
    /// Offset for block_hash field.
    const BLOCK_HASH_OFFSET: usize = Self::BLOCK_NUMBER_OFFSET + 4;
    /// Offset for abandoned page list head (linked list of AbandonedPages).
    const ABANDONED_HEAD_OFFSET: usize = Self::BLOCK_HASH_OFFSET + 32;
    /// Offset for reorg depth (number of batches before pages can be reused).
    const REORG_DEPTH_OFFSET: usize = Self::ABANDONED_HEAD_OFFSET + DbAddress::SIZE;
    /// Offset where inline abandoned page list starts (for small numbers of pages).
    const ABANDONED_LIST_OFFSET: usize = Self::REORG_DEPTH_OFFSET + 4;
    /// Offset for inline abandoned batch ID (when pages were abandoned).
    const ABANDONED_BATCH_OFFSET: usize = Self::ABANDONED_LIST_OFFSET;
    /// Offset for inline abandoned count.
    const ABANDONED_COUNT_OFFSET: usize = Self::ABANDONED_BATCH_OFFSET + 4;
    /// Offset where inline abandoned addresses start.
    const ABANDONED_ADDRESSES_OFFSET: usize = Self::ABANDONED_COUNT_OFFSET + 2;

    /// Maximum number of abandoned page addresses that can be stored inline.
    pub const MAX_ABANDONED: usize = (PAGE_SIZE - Self::ABANDONED_ADDRESSES_OFFSET) / DbAddress::SIZE;

    /// Default reorg depth (64 batches).
    pub const DEFAULT_REORG_DEPTH: u32 = 64;

    /// Creates a new root page.
    pub fn new(batch_id: u32) -> Self {
        let mut page = Page::new();
        page.set_header(PageHeader::new(batch_id, PageType::Root, 0));
        // Start allocating from page 1 (page 0 is the root)
        let mut root = Self { page };
        root.set_next_free_page(DbAddress::page(1));
        root.set_reorg_depth(Self::DEFAULT_REORG_DEPTH);
        root
    }

    /// Wraps an existing page as a root page.
    pub fn wrap(page: Page) -> Self {
        debug_assert_eq!(page.header().get_page_type(), Some(PageType::Root));
        Self { page }
    }

    /// Returns the underlying page.
    pub fn into_page(self) -> Page {
        self.page
    }

    /// Returns the underlying page reference.
    pub fn page(&self) -> &Page {
        &self.page
    }

    /// Returns mutable underlying page reference.
    pub fn page_mut(&mut self) -> &mut Page {
        &mut self.page
    }

    /// Gets the next free page address.
    pub fn next_free_page(&self) -> DbAddress {
        let data = self.page.as_bytes();
        DbAddress::read(&data[Self::NEXT_FREE_OFFSET..])
    }

    /// Sets the next free page address.
    pub fn set_next_free_page(&mut self, addr: DbAddress) {
        let data = self.page.as_bytes_mut();
        addr.write(&mut data[Self::NEXT_FREE_OFFSET..]);
    }

    /// Allocates a new page and returns its address.
    pub fn allocate_page(&mut self) -> DbAddress {
        let addr = self.next_free_page();
        self.set_next_free_page(addr.next());
        addr
    }

    /// Gets the account counter.
    pub fn account_counter(&self) -> u32 {
        let data = self.page.as_bytes();
        u32::from_le_bytes([
            data[Self::ACCOUNT_COUNTER_OFFSET],
            data[Self::ACCOUNT_COUNTER_OFFSET + 1],
            data[Self::ACCOUNT_COUNTER_OFFSET + 2],
            data[Self::ACCOUNT_COUNTER_OFFSET + 3],
        ])
    }

    /// Increments and returns the account counter.
    pub fn next_account_id(&mut self) -> u32 {
        let current = self.account_counter();
        let next = current + 1;
        let data = self.page.as_bytes_mut();
        data[Self::ACCOUNT_COUNTER_OFFSET..Self::ACCOUNT_COUNTER_OFFSET + 4]
            .copy_from_slice(&next.to_le_bytes());
        next
    }

    /// Gets the state root address.
    pub fn state_root(&self) -> DbAddress {
        let data = self.page.as_bytes();
        DbAddress::read(&data[Self::STATE_ROOT_OFFSET..])
    }

    /// Sets the state root address.
    pub fn set_state_root(&mut self, addr: DbAddress) {
        let data = self.page.as_bytes_mut();
        addr.write(&mut data[Self::STATE_ROOT_OFFSET..]);
    }

    /// Gets the block number.
    pub fn block_number(&self) -> u32 {
        let data = self.page.as_bytes();
        u32::from_le_bytes([
            data[Self::BLOCK_NUMBER_OFFSET],
            data[Self::BLOCK_NUMBER_OFFSET + 1],
            data[Self::BLOCK_NUMBER_OFFSET + 2],
            data[Self::BLOCK_NUMBER_OFFSET + 3],
        ])
    }

    /// Sets the block number.
    pub fn set_block_number(&mut self, number: u32) {
        let data = self.page.as_bytes_mut();
        data[Self::BLOCK_NUMBER_OFFSET..Self::BLOCK_NUMBER_OFFSET + 4]
            .copy_from_slice(&number.to_le_bytes());
    }

    /// Gets the block hash.
    pub fn block_hash(&self) -> [u8; 32] {
        let data = self.page.as_bytes();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&data[Self::BLOCK_HASH_OFFSET..Self::BLOCK_HASH_OFFSET + 32]);
        hash
    }

    /// Sets the block hash.
    pub fn set_block_hash(&mut self, hash: &[u8; 32]) {
        let data = self.page.as_bytes_mut();
        data[Self::BLOCK_HASH_OFFSET..Self::BLOCK_HASH_OFFSET + 32].copy_from_slice(hash);
    }

    /// Gets the head of the abandoned page linked list.
    pub fn abandoned_head(&self) -> DbAddress {
        let data = self.page.as_bytes();
        DbAddress::read(&data[Self::ABANDONED_HEAD_OFFSET..])
    }

    /// Sets the head of the abandoned page linked list.
    pub fn set_abandoned_head(&mut self, addr: DbAddress) {
        let data = self.page.as_bytes_mut();
        addr.write(&mut data[Self::ABANDONED_HEAD_OFFSET..]);
    }

    /// Gets the reorg depth (number of batches before pages can be reused).
    pub fn reorg_depth(&self) -> u32 {
        let data = self.page.as_bytes();
        u32::from_le_bytes([
            data[Self::REORG_DEPTH_OFFSET],
            data[Self::REORG_DEPTH_OFFSET + 1],
            data[Self::REORG_DEPTH_OFFSET + 2],
            data[Self::REORG_DEPTH_OFFSET + 3],
        ])
    }

    /// Sets the reorg depth.
    pub fn set_reorg_depth(&mut self, depth: u32) {
        let data = self.page.as_bytes_mut();
        data[Self::REORG_DEPTH_OFFSET..Self::REORG_DEPTH_OFFSET + 4]
            .copy_from_slice(&depth.to_le_bytes());
    }

    /// Gets the batch ID when inline abandoned pages were abandoned.
    fn abandoned_batch(&self) -> u32 {
        let data = self.page.as_bytes();
        u32::from_le_bytes([
            data[Self::ABANDONED_BATCH_OFFSET],
            data[Self::ABANDONED_BATCH_OFFSET + 1],
            data[Self::ABANDONED_BATCH_OFFSET + 2],
            data[Self::ABANDONED_BATCH_OFFSET + 3],
        ])
    }

    /// Sets the batch ID when inline abandoned pages were abandoned.
    fn set_abandoned_batch(&mut self, batch: u32) {
        let data = self.page.as_bytes_mut();
        data[Self::ABANDONED_BATCH_OFFSET..Self::ABANDONED_BATCH_OFFSET + 4]
            .copy_from_slice(&batch.to_le_bytes());
    }

    /// Gets the inline abandoned page count.
    fn abandoned_count(&self) -> usize {
        let data = self.page.as_bytes();
        u16::from_le_bytes([
            data[Self::ABANDONED_COUNT_OFFSET],
            data[Self::ABANDONED_COUNT_OFFSET + 1],
        ]) as usize
    }

    /// Sets the inline abandoned page count.
    fn set_abandoned_count(&mut self, count: usize) {
        let data = self.page.as_bytes_mut();
        let count16 = count as u16;
        data[Self::ABANDONED_COUNT_OFFSET..Self::ABANDONED_COUNT_OFFSET + 2]
            .copy_from_slice(&count16.to_le_bytes());
    }

    /// Tries to add an abandoned page address inline (fast path).
    /// Returns false if inline storage is full or batch mismatch.
    pub fn try_add_abandoned_inline(&mut self, addr: DbAddress, batch_id: u32) -> bool {
        let count = self.abandoned_count();

        // If first entry, set the batch
        if count == 0 {
            self.set_abandoned_batch(batch_id);
        } else if self.abandoned_batch() != batch_id {
            // Different batch - would need to use AbandonedPage linked list
            return false;
        }

        if count >= Self::MAX_ABANDONED {
            return false;
        }

        let offset = Self::ABANDONED_ADDRESSES_OFFSET + count * DbAddress::SIZE;
        addr.write(&mut self.page.as_bytes_mut()[offset..]);
        self.set_abandoned_count(count + 1);
        true
    }

    /// Pops an abandoned page address from inline storage (fast path).
    /// Only returns pages that are safe to reuse (past reorg depth).
    pub fn pop_abandoned_inline(&mut self, current_batch: u32) -> Option<DbAddress> {
        let count = self.abandoned_count();
        if count == 0 {
            return None;
        }

        // Check if enough batches have passed
        let abandoned_at = self.abandoned_batch();
        let reorg_depth = self.reorg_depth();
        if current_batch < abandoned_at + reorg_depth {
            // Not old enough to reuse
            return None;
        }

        let offset = Self::ABANDONED_ADDRESSES_OFFSET + (count - 1) * DbAddress::SIZE;
        let addr = DbAddress::read(&self.page.as_bytes()[offset..]);
        self.set_abandoned_count(count - 1);
        Some(addr)
    }

    /// Returns true if there are inline abandoned pages that can be reused.
    pub fn has_reusable_abandoned_inline(&self, current_batch: u32) -> bool {
        let count = self.abandoned_count();
        if count == 0 {
            return false;
        }

        let abandoned_at = self.abandoned_batch();
        let reorg_depth = self.reorg_depth();
        current_batch >= abandoned_at + reorg_depth
    }
}

// ============================================================================
// DataPage - Intermediate node with fanout
// ============================================================================

/// Data page with fanout buckets and inline storage.
///
/// Layout after header:
/// - buckets: [DbAddress; 256] (1024 bytes for fanout)
/// - merkle_addr: DbAddress (4 bytes)
/// - child_data_pages: u32 (4 bytes, bitmap for fanout optimization)
/// - data: SlottedArray (remaining space)
pub struct DataPage {
    page: Page,
}

impl DataPage {
    /// Offset for buckets array.
    const BUCKETS_OFFSET: usize = PageHeader::SIZE;
    /// Size of the buckets array (256 * 4 bytes).
    const BUCKETS_SIZE: usize = BUCKET_COUNT * DbAddress::SIZE;
    /// Offset for merkle address.
    const MERKLE_OFFSET: usize = Self::BUCKETS_OFFSET + Self::BUCKETS_SIZE;
    /// Offset for child data pages bitmap.
    const CHILD_BITMAP_OFFSET: usize = Self::MERKLE_OFFSET + DbAddress::SIZE;
    /// Offset where data storage starts.
    const DATA_OFFSET: usize = Self::CHILD_BITMAP_OFFSET + 4;

    /// Creates a new data page.
    pub fn new(batch_id: u32, level: u8) -> Self {
        let mut page = Page::new();
        page.set_header(PageHeader::new(batch_id, PageType::Data, level));
        Self { page }
    }

    /// Wraps an existing page as a data page.
    pub fn wrap(page: Page) -> Self {
        debug_assert_eq!(page.header().get_page_type(), Some(PageType::Data));
        Self { page }
    }

    /// Returns the underlying page.
    pub fn into_page(self) -> Page {
        self.page
    }

    /// Returns a reference to the underlying page.
    pub fn page(&self) -> &Page {
        &self.page
    }

    /// Returns a mutable reference to the underlying page.
    pub fn page_mut(&mut self) -> &mut Page {
        &mut self.page
    }

    /// Gets a bucket address by index.
    pub fn get_bucket(&self, index: usize) -> DbAddress {
        debug_assert!(index < BUCKET_COUNT);
        let offset = Self::BUCKETS_OFFSET + index * DbAddress::SIZE;
        DbAddress::read(&self.page.as_bytes()[offset..])
    }

    /// Sets a bucket address.
    pub fn set_bucket(&mut self, index: usize, addr: DbAddress) {
        debug_assert!(index < BUCKET_COUNT);
        let offset = Self::BUCKETS_OFFSET + index * DbAddress::SIZE;
        addr.write(&mut self.page.as_bytes_mut()[offset..]);
    }

    /// Gets the merkle sidecar page address.
    pub fn merkle_addr(&self) -> DbAddress {
        DbAddress::read(&self.page.as_bytes()[Self::MERKLE_OFFSET..])
    }

    /// Sets the merkle sidecar page address.
    pub fn set_merkle_addr(&mut self, addr: DbAddress) {
        addr.write(&mut self.page.as_bytes_mut()[Self::MERKLE_OFFSET..]);
    }

    /// Returns whether this page uses full fanout (256 buckets consuming 2 nibbles).
    pub fn is_fanout(&self) -> bool {
        let data = self.page.as_bytes();
        let bitmap = u32::from_le_bytes([
            data[Self::CHILD_BITMAP_OFFSET],
            data[Self::CHILD_BITMAP_OFFSET + 1],
            data[Self::CHILD_BITMAP_OFFSET + 2],
            data[Self::CHILD_BITMAP_OFFSET + 3],
        ]);
        bitmap == 0xFFFF
    }

    /// Returns the number of nibbles consumed by this page.
    pub fn consumed_nibbles(&self) -> usize {
        if self.is_fanout() { 2 } else { 1 }
    }

    /// Returns the bucket index for a given nibble path.
    pub fn bucket_for_path(&self, nibble0: u8, nibble1: Option<u8>) -> usize {
        if self.is_fanout() {
            let n1 = nibble1.unwrap_or(0);
            ((nibble0 as usize) << 4) | (n1 as usize)
        } else {
            nibble0 as usize
        }
    }

    /// Returns a slotted array view of the data area.
    pub fn data(&self) -> &[u8] {
        &self.page.as_bytes()[Self::DATA_OFFSET..]
    }

    /// Returns a mutable slotted array view of the data area.
    pub fn data_mut(&mut self) -> &mut [u8] {
        &mut self.page.as_bytes_mut()[Self::DATA_OFFSET..]
    }
}

// ============================================================================
// LeafPage - Bottom of the tree
// ============================================================================

/// Leaf page at the bottom of the tree, using slotted array storage.
///
/// Layout after header:
/// - data: SlottedArray (entire payload)
pub struct LeafPage {
    page: Page,
}

impl LeafPage {
    /// Creates a new leaf page.
    pub fn new(batch_id: u32, level: u8) -> Self {
        let mut page = Page::new();
        page.set_header(PageHeader::new(batch_id, PageType::Leaf, level));
        Self { page }
    }

    /// Wraps an existing page as a leaf page.
    pub fn wrap(page: Page) -> Self {
        debug_assert_eq!(page.header().get_page_type(), Some(PageType::Leaf));
        Self { page }
    }

    /// Returns the underlying page.
    pub fn into_page(self) -> Page {
        self.page
    }

    /// Returns a reference to the underlying page.
    pub fn page(&self) -> &Page {
        &self.page
    }

    /// Returns a mutable reference to the underlying page.
    pub fn page_mut(&mut self) -> &mut Page {
        &mut self.page
    }

    /// Returns the data area for slotted array storage.
    pub fn data(&self) -> &[u8] {
        self.page.payload()
    }

    /// Returns mutable data area.
    pub fn data_mut(&mut self) -> &mut [u8] {
        self.page.payload_mut()
    }
}

// ============================================================================
// AbandonedPage - Tracking reusable pages
// ============================================================================

/// Page tracking abandoned pages that can be reused.
///
/// When a page is COWed, the original is tracked here for later reuse
/// (after the reorg depth has passed).
///
/// Layout after header:
/// - batch_id_abandoned: u32 (4 bytes) - batch when pages were abandoned
/// - next_abandoned: DbAddress (4 bytes) - linked list of abandoned pages
/// - count: u16 (2 bytes) - number of addresses stored
/// - addresses: [DbAddress; ...] (remaining space)
pub struct AbandonedPage {
    page: Page,
}

impl AbandonedPage {
    const BATCH_ABANDONED_OFFSET: usize = PageHeader::SIZE;
    const NEXT_OFFSET: usize = Self::BATCH_ABANDONED_OFFSET + 4;
    const COUNT_OFFSET: usize = Self::NEXT_OFFSET + DbAddress::SIZE;
    const ADDRESSES_OFFSET: usize = Self::COUNT_OFFSET + 2;

    /// Maximum addresses that can be stored.
    pub const MAX_ADDRESSES: usize = (PAGE_SIZE - Self::ADDRESSES_OFFSET) / DbAddress::SIZE;

    /// Creates a new abandoned page.
    pub fn new(batch_id: u32, abandoned_at_batch: u32) -> Self {
        let mut page = Page::new();
        page.set_header(PageHeader::new(batch_id, PageType::Abandoned, 0));
        let mut ap = Self { page };
        ap.set_batch_abandoned(abandoned_at_batch);
        ap
    }

    /// Wraps an existing page.
    pub fn wrap(page: Page) -> Self {
        debug_assert_eq!(page.header().get_page_type(), Some(PageType::Abandoned));
        Self { page }
    }

    /// Returns the underlying page.
    pub fn into_page(self) -> Page {
        self.page
    }

    /// Gets the batch when these pages were abandoned.
    pub fn batch_abandoned(&self) -> u32 {
        let data = self.page.as_bytes();
        u32::from_le_bytes([
            data[Self::BATCH_ABANDONED_OFFSET],
            data[Self::BATCH_ABANDONED_OFFSET + 1],
            data[Self::BATCH_ABANDONED_OFFSET + 2],
            data[Self::BATCH_ABANDONED_OFFSET + 3],
        ])
    }

    /// Sets the batch when these pages were abandoned.
    fn set_batch_abandoned(&mut self, batch: u32) {
        let data = self.page.as_bytes_mut();
        data[Self::BATCH_ABANDONED_OFFSET..Self::BATCH_ABANDONED_OFFSET + 4]
            .copy_from_slice(&batch.to_le_bytes());
    }

    /// Gets the next abandoned page in the linked list.
    pub fn next(&self) -> DbAddress {
        DbAddress::read(&self.page.as_bytes()[Self::NEXT_OFFSET..])
    }

    /// Sets the next abandoned page.
    pub fn set_next(&mut self, addr: DbAddress) {
        addr.write(&mut self.page.as_bytes_mut()[Self::NEXT_OFFSET..]);
    }

    /// Gets the number of addresses stored.
    pub fn count(&self) -> usize {
        let data = self.page.as_bytes();
        u16::from_le_bytes([data[Self::COUNT_OFFSET], data[Self::COUNT_OFFSET + 1]]) as usize
    }

    /// Tries to add an abandoned page address.
    pub fn try_add(&mut self, addr: DbAddress) -> bool {
        let count = self.count();
        if count >= Self::MAX_ADDRESSES {
            return false;
        }

        let offset = Self::ADDRESSES_OFFSET + count * DbAddress::SIZE;
        addr.write(&mut self.page.as_bytes_mut()[offset..]);

        let data = self.page.as_bytes_mut();
        let new_count = (count + 1) as u16;
        data[Self::COUNT_OFFSET..Self::COUNT_OFFSET + 2].copy_from_slice(&new_count.to_le_bytes());

        true
    }

    /// Gets an address at the given index.
    pub fn get(&self, index: usize) -> Option<DbAddress> {
        if index >= self.count() {
            return None;
        }
        let offset = Self::ADDRESSES_OFFSET + index * DbAddress::SIZE;
        Some(DbAddress::read(&self.page.as_bytes()[offset..]))
    }

    /// Pops the last address.
    pub fn pop(&mut self) -> Option<DbAddress> {
        let count = self.count();
        if count == 0 {
            return None;
        }

        let addr = self.get(count - 1)?;

        let data = self.page.as_bytes_mut();
        let new_count = (count - 1) as u16;
        data[Self::COUNT_OFFSET..Self::COUNT_OFFSET + 2].copy_from_slice(&new_count.to_le_bytes());

        Some(addr)
    }
}

// ============================================================================
// MptBranchPage - MPT Branch node
// ============================================================================

/// MPT Branch page with 16 children and optional value.
///
/// Layout after header (8B):
/// - hash: [u8; 32]         - Cached hash (0 if dirty)
/// - dirty_mask: u16        - Bitmask of dirty children
/// - value_len: u16         - Branch value length
/// - children: [DbAddress; 16] - Child page pointers (64B)
/// - child_hashes: [[u8;32]; 16] - Cached child hashes (512B)
/// - inline_flags: u16      - Bitmask indicating which children are inline
/// - inline_data: [u8; ...]  - Inline RLP data for small children
/// - value: [u8; ...]       - Optional branch value (at end of page)
pub struct MptBranchPage {
    page: Page,
}

impl MptBranchPage {
    /// Offset for cached hash.
    const HASH_OFFSET: usize = PageHeader::SIZE;
    /// Offset for dirty mask.
    const DIRTY_MASK_OFFSET: usize = Self::HASH_OFFSET + 32;
    /// Offset for value length.
    const VALUE_LEN_OFFSET: usize = Self::DIRTY_MASK_OFFSET + 2;
    /// Offset for children array.
    const CHILDREN_OFFSET: usize = Self::VALUE_LEN_OFFSET + 2;
    /// Size of children array (16 * 4 = 64 bytes).
    const CHILDREN_SIZE: usize = 16 * DbAddress::SIZE;
    /// Offset for child hashes array.
    const CHILD_HASHES_OFFSET: usize = Self::CHILDREN_OFFSET + Self::CHILDREN_SIZE;
    /// Size of child hashes array (16 * 32 = 512 bytes).
    const CHILD_HASHES_SIZE: usize = 16 * 32;
    /// Offset for inline flags.
    const INLINE_FLAGS_OFFSET: usize = Self::CHILD_HASHES_OFFSET + Self::CHILD_HASHES_SIZE;
    /// Offset for inline data area.
    const INLINE_DATA_OFFSET: usize = Self::INLINE_FLAGS_OFFSET + 2;
    /// Maximum inline data size per child (31 bytes - must be < 32 for inline).
    pub const MAX_INLINE_SIZE: usize = 31;
    /// Maximum total inline data size.
    pub const MAX_INLINE_DATA: usize = PAGE_SIZE - Self::INLINE_DATA_OFFSET - 256; // Leave room for value

    /// Creates a new branch page.
    pub fn new(batch_id: u32, level: u8) -> Self {
        let mut page = Page::new();
        page.set_header(PageHeader::new(batch_id, PageType::MptBranch, level));
        Self { page }
    }

    /// Wraps an existing page as a branch page.
    pub fn wrap(page: Page) -> Self {
        debug_assert_eq!(page.header().get_page_type(), Some(PageType::MptBranch));
        Self { page }
    }

    /// Returns the underlying page.
    pub fn into_page(self) -> Page {
        self.page
    }

    /// Returns a reference to the underlying page.
    pub fn page(&self) -> &Page {
        &self.page
    }

    /// Returns a mutable reference to the underlying page.
    pub fn page_mut(&mut self) -> &mut Page {
        &mut self.page
    }

    /// Gets the cached hash (zeros if dirty).
    pub fn hash(&self) -> [u8; 32] {
        let data = self.page.as_bytes();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&data[Self::HASH_OFFSET..Self::HASH_OFFSET + 32]);
        hash
    }

    /// Sets the cached hash.
    pub fn set_hash(&mut self, hash: &[u8; 32]) {
        let data = self.page.as_bytes_mut();
        data[Self::HASH_OFFSET..Self::HASH_OFFSET + 32].copy_from_slice(hash);
    }

    /// Returns true if the node is dirty (hash is zeros).
    pub fn is_dirty(&self) -> bool {
        self.hash() == [0u8; 32]
    }

    /// Marks the node as dirty (clears the hash).
    pub fn mark_dirty(&mut self) {
        self.set_hash(&[0u8; 32]);
    }

    /// Gets the dirty mask (bitmask of dirty children).
    pub fn dirty_mask(&self) -> u16 {
        let data = self.page.as_bytes();
        u16::from_le_bytes([
            data[Self::DIRTY_MASK_OFFSET],
            data[Self::DIRTY_MASK_OFFSET + 1],
        ])
    }

    /// Sets the dirty mask.
    pub fn set_dirty_mask(&mut self, mask: u16) {
        let data = self.page.as_bytes_mut();
        data[Self::DIRTY_MASK_OFFSET..Self::DIRTY_MASK_OFFSET + 2]
            .copy_from_slice(&mask.to_le_bytes());
    }

    /// Marks a child as dirty.
    pub fn mark_child_dirty(&mut self, index: usize) {
        debug_assert!(index < 16);
        let mask = self.dirty_mask() | (1 << index);
        self.set_dirty_mask(mask);
        self.mark_dirty();
    }

    /// Clears dirty flag for a child.
    pub fn clear_child_dirty(&mut self, index: usize) {
        debug_assert!(index < 16);
        let mask = self.dirty_mask() & !(1 << index);
        self.set_dirty_mask(mask);
    }

    /// Returns true if a child is dirty.
    pub fn is_child_dirty(&self, index: usize) -> bool {
        debug_assert!(index < 16);
        (self.dirty_mask() & (1 << index)) != 0
    }

    /// Gets the value length.
    pub fn value_len(&self) -> usize {
        let data = self.page.as_bytes();
        u16::from_le_bytes([
            data[Self::VALUE_LEN_OFFSET],
            data[Self::VALUE_LEN_OFFSET + 1],
        ]) as usize
    }

    /// Sets the value length.
    fn set_value_len(&mut self, len: usize) {
        let data = self.page.as_bytes_mut();
        data[Self::VALUE_LEN_OFFSET..Self::VALUE_LEN_OFFSET + 2]
            .copy_from_slice(&(len as u16).to_le_bytes());
    }

    /// Gets a child address by index.
    pub fn get_child(&self, index: usize) -> DbAddress {
        debug_assert!(index < 16);
        let offset = Self::CHILDREN_OFFSET + index * DbAddress::SIZE;
        DbAddress::read(&self.page.as_bytes()[offset..])
    }

    /// Sets a child address.
    pub fn set_child(&mut self, index: usize, addr: DbAddress) {
        debug_assert!(index < 16);
        let offset = Self::CHILDREN_OFFSET + index * DbAddress::SIZE;
        addr.write(&mut self.page.as_bytes_mut()[offset..]);
        self.mark_child_dirty(index);
    }

    /// Gets a child's cached hash.
    pub fn get_child_hash(&self, index: usize) -> [u8; 32] {
        debug_assert!(index < 16);
        let offset = Self::CHILD_HASHES_OFFSET + index * 32;
        let data = self.page.as_bytes();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&data[offset..offset + 32]);
        hash
    }

    /// Sets a child's cached hash.
    pub fn set_child_hash(&mut self, index: usize, hash: &[u8; 32]) {
        debug_assert!(index < 16);
        let offset = Self::CHILD_HASHES_OFFSET + index * 32;
        self.page.as_bytes_mut()[offset..offset + 32].copy_from_slice(hash);
        self.clear_child_dirty(index);
    }

    /// Gets the inline flags bitmask.
    pub fn inline_flags(&self) -> u16 {
        let data = self.page.as_bytes();
        u16::from_le_bytes([
            data[Self::INLINE_FLAGS_OFFSET],
            data[Self::INLINE_FLAGS_OFFSET + 1],
        ])
    }

    /// Sets the inline flags bitmask.
    fn set_inline_flags(&mut self, flags: u16) {
        let data = self.page.as_bytes_mut();
        data[Self::INLINE_FLAGS_OFFSET..Self::INLINE_FLAGS_OFFSET + 2]
            .copy_from_slice(&flags.to_le_bytes());
    }

    /// Returns true if a child is inline.
    pub fn is_child_inline(&self, index: usize) -> bool {
        debug_assert!(index < 16);
        (self.inline_flags() & (1 << index)) != 0
    }

    /// Gets the branch value (if any).
    pub fn value(&self) -> Option<Vec<u8>> {
        let len = self.value_len();
        if len == 0 {
            return None;
        }
        // Value is stored at the end of the page
        let data = self.page.as_bytes();
        let start = PAGE_SIZE - len;
        Some(data[start..].to_vec())
    }

    /// Sets the branch value.
    pub fn set_value(&mut self, value: Option<&[u8]>) {
        match value {
            Some(v) => {
                let len = v.len();
                self.set_value_len(len);
                let data = self.page.as_bytes_mut();
                let start = PAGE_SIZE - len;
                data[start..].copy_from_slice(v);
            }
            None => {
                self.set_value_len(0);
            }
        }
        self.mark_dirty();
    }

    /// Checks if a child slot is empty.
    pub fn is_child_empty(&self, index: usize) -> bool {
        !self.is_child_inline(index) && self.get_child(index).is_null()
    }

    /// Counts non-empty children.
    pub fn child_count(&self) -> usize {
        let mut count = 0;
        for i in 0..16 {
            if !self.is_child_empty(i) {
                count += 1;
            }
        }
        count
    }
}

// ============================================================================
// MptExtensionPage - MPT Extension node
// ============================================================================

/// MPT Extension page with shared path prefix.
///
/// Layout after header (8B):
/// - hash: [u8; 32]         - Cached hash (0 if dirty)
/// - path_len: u8           - Number of nibbles in path
/// - flags: u8              - Bit flags (dirty, child_is_inline, etc.)
/// - child: DbAddress       - Child page pointer (4B)
/// - child_hash: [u8; 32]   - Cached child hash
/// - path: [u8; ...]        - Extension path nibbles (packed, 2 per byte)
/// - inline_child: [u8; ...] - If child is inline (< 32B encoded)
pub struct MptExtensionPage {
    page: Page,
}

impl MptExtensionPage {
    /// Offset for cached hash.
    const HASH_OFFSET: usize = PageHeader::SIZE;
    /// Offset for path length.
    const PATH_LEN_OFFSET: usize = Self::HASH_OFFSET + 32;
    /// Offset for flags.
    const FLAGS_OFFSET: usize = Self::PATH_LEN_OFFSET + 1;
    /// Offset for child address.
    const CHILD_OFFSET: usize = Self::FLAGS_OFFSET + 1;
    /// Offset for child hash.
    const CHILD_HASH_OFFSET: usize = Self::CHILD_OFFSET + DbAddress::SIZE;
    /// Offset for path data.
    const PATH_OFFSET: usize = Self::CHILD_HASH_OFFSET + 32;
    /// Maximum path length in nibbles.
    pub const MAX_PATH_LEN: usize = 64; // 32 bytes * 2 nibbles = 64 nibbles
    /// Maximum inline child size.
    pub const MAX_INLINE_SIZE: usize = 31;

    /// Flag: child is inline.
    const FLAG_CHILD_INLINE: u8 = 0x01;

    /// Creates a new extension page.
    pub fn new(batch_id: u32, level: u8) -> Self {
        let mut page = Page::new();
        page.set_header(PageHeader::new(batch_id, PageType::MptExtension, level));
        Self { page }
    }

    /// Wraps an existing page as an extension page.
    pub fn wrap(page: Page) -> Self {
        debug_assert_eq!(page.header().get_page_type(), Some(PageType::MptExtension));
        Self { page }
    }

    /// Returns the underlying page.
    pub fn into_page(self) -> Page {
        self.page
    }

    /// Returns a reference to the underlying page.
    pub fn page(&self) -> &Page {
        &self.page
    }

    /// Returns a mutable reference to the underlying page.
    pub fn page_mut(&mut self) -> &mut Page {
        &mut self.page
    }

    /// Gets the cached hash.
    pub fn hash(&self) -> [u8; 32] {
        let data = self.page.as_bytes();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&data[Self::HASH_OFFSET..Self::HASH_OFFSET + 32]);
        hash
    }

    /// Sets the cached hash.
    pub fn set_hash(&mut self, hash: &[u8; 32]) {
        let data = self.page.as_bytes_mut();
        data[Self::HASH_OFFSET..Self::HASH_OFFSET + 32].copy_from_slice(hash);
    }

    /// Returns true if the node is dirty.
    pub fn is_dirty(&self) -> bool {
        self.hash() == [0u8; 32]
    }

    /// Marks the node as dirty.
    pub fn mark_dirty(&mut self) {
        self.set_hash(&[0u8; 32]);
    }

    /// Gets the path length in nibbles.
    pub fn path_len(&self) -> usize {
        self.page.as_bytes()[Self::PATH_LEN_OFFSET] as usize
    }

    /// Sets the path length.
    fn set_path_len(&mut self, len: usize) {
        self.page.as_bytes_mut()[Self::PATH_LEN_OFFSET] = len as u8;
    }

    /// Gets the flags byte.
    fn flags(&self) -> u8 {
        self.page.as_bytes()[Self::FLAGS_OFFSET]
    }

    /// Sets the flags byte.
    fn set_flags(&mut self, flags: u8) {
        self.page.as_bytes_mut()[Self::FLAGS_OFFSET] = flags;
    }

    /// Returns true if child is inline.
    pub fn is_child_inline(&self) -> bool {
        (self.flags() & Self::FLAG_CHILD_INLINE) != 0
    }

    /// Gets the child address.
    pub fn child(&self) -> DbAddress {
        DbAddress::read(&self.page.as_bytes()[Self::CHILD_OFFSET..])
    }

    /// Sets the child address.
    pub fn set_child(&mut self, addr: DbAddress) {
        addr.write(&mut self.page.as_bytes_mut()[Self::CHILD_OFFSET..]);
        self.set_flags(self.flags() & !Self::FLAG_CHILD_INLINE);
        self.mark_dirty();
    }

    /// Gets the child hash.
    pub fn child_hash(&self) -> [u8; 32] {
        let data = self.page.as_bytes();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&data[Self::CHILD_HASH_OFFSET..Self::CHILD_HASH_OFFSET + 32]);
        hash
    }

    /// Sets the child hash.
    pub fn set_child_hash(&mut self, hash: &[u8; 32]) {
        self.page.as_bytes_mut()[Self::CHILD_HASH_OFFSET..Self::CHILD_HASH_OFFSET + 32]
            .copy_from_slice(hash);
    }

    /// Gets the path as nibbles.
    pub fn path(&self) -> Vec<u8> {
        let len = self.path_len();
        if len == 0 {
            return Vec::new();
        }
        let data = self.page.as_bytes();
        let byte_len = (len + 1) / 2;
        let mut nibbles = Vec::with_capacity(len);
        for i in 0..byte_len {
            let byte = data[Self::PATH_OFFSET + i];
            nibbles.push(byte >> 4);
            if nibbles.len() < len {
                nibbles.push(byte & 0x0F);
            }
        }
        nibbles.truncate(len);
        nibbles
    }

    /// Sets the path (nibbles).
    pub fn set_path(&mut self, nibbles: &[u8]) {
        let len = nibbles.len().min(Self::MAX_PATH_LEN);
        self.set_path_len(len);
        let data = self.page.as_bytes_mut();
        let byte_len = (len + 1) / 2;
        for i in 0..byte_len {
            let high = nibbles[i * 2];
            let low = if i * 2 + 1 < len { nibbles[i * 2 + 1] } else { 0 };
            data[Self::PATH_OFFSET + i] = (high << 4) | low;
        }
        self.mark_dirty();
    }

    /// Gets the inline child data (if child is inline).
    pub fn inline_child(&self) -> Option<Vec<u8>> {
        if !self.is_child_inline() {
            return None;
        }
        // Inline child is stored after the path
        let path_bytes = (self.path_len() + 1) / 2;
        let inline_offset = Self::PATH_OFFSET + path_bytes;
        let data = self.page.as_bytes();
        // First byte is length
        let len = data[inline_offset] as usize;
        if len == 0 || len > Self::MAX_INLINE_SIZE {
            return None;
        }
        Some(data[inline_offset + 1..inline_offset + 1 + len].to_vec())
    }

    /// Sets inline child data.
    pub fn set_inline_child(&mut self, inline_data: &[u8]) {
        debug_assert!(inline_data.len() <= Self::MAX_INLINE_SIZE);
        let path_bytes = (self.path_len() + 1) / 2;
        let inline_offset = Self::PATH_OFFSET + path_bytes;
        let data = self.page.as_bytes_mut();
        data[inline_offset] = inline_data.len() as u8;
        data[inline_offset + 1..inline_offset + 1 + inline_data.len()].copy_from_slice(inline_data);
        self.set_flags(self.flags() | Self::FLAG_CHILD_INLINE);
        self.mark_dirty();
    }
}

// ============================================================================
// MptLeafPage - MPT Leaf node
// ============================================================================

/// MPT Leaf page with remaining key and value.
///
/// Layout after header (8B):
/// - hash: [u8; 32]         - Cached hash (0 if dirty)
/// - path_len: u8           - Number of nibbles in remaining path
/// - flags: u8              - Reserved
/// - value_len: u16         - Value length
/// - path: [u8; ...]        - Remaining key nibbles (packed)
/// - value: [u8; ...]       - RLP encoded value
pub struct MptLeafPage {
    page: Page,
}

impl MptLeafPage {
    /// Offset for cached hash.
    const HASH_OFFSET: usize = PageHeader::SIZE;
    /// Offset for path length.
    const PATH_LEN_OFFSET: usize = Self::HASH_OFFSET + 32;
    /// Offset for flags.
    const FLAGS_OFFSET: usize = Self::PATH_LEN_OFFSET + 1;
    /// Offset for value length.
    const VALUE_LEN_OFFSET: usize = Self::FLAGS_OFFSET + 1;
    /// Offset for path data.
    const PATH_OFFSET: usize = Self::VALUE_LEN_OFFSET + 2;
    /// Maximum path length in nibbles.
    pub const MAX_PATH_LEN: usize = 64;
    /// Maximum value size.
    pub const MAX_VALUE_SIZE: usize = PAGE_SIZE - Self::PATH_OFFSET - 32 - 8; // Leave room for path

    /// Creates a new leaf page.
    pub fn new(batch_id: u32, level: u8) -> Self {
        let mut page = Page::new();
        page.set_header(PageHeader::new(batch_id, PageType::MptLeaf, level));
        Self { page }
    }

    /// Wraps an existing page as a leaf page.
    pub fn wrap(page: Page) -> Self {
        debug_assert_eq!(page.header().get_page_type(), Some(PageType::MptLeaf));
        Self { page }
    }

    /// Returns the underlying page.
    pub fn into_page(self) -> Page {
        self.page
    }

    /// Returns a reference to the underlying page.
    pub fn page(&self) -> &Page {
        &self.page
    }

    /// Returns a mutable reference to the underlying page.
    pub fn page_mut(&mut self) -> &mut Page {
        &mut self.page
    }

    /// Gets the cached hash.
    pub fn hash(&self) -> [u8; 32] {
        let data = self.page.as_bytes();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&data[Self::HASH_OFFSET..Self::HASH_OFFSET + 32]);
        hash
    }

    /// Sets the cached hash.
    pub fn set_hash(&mut self, hash: &[u8; 32]) {
        let data = self.page.as_bytes_mut();
        data[Self::HASH_OFFSET..Self::HASH_OFFSET + 32].copy_from_slice(hash);
    }

    /// Returns true if the node is dirty.
    pub fn is_dirty(&self) -> bool {
        self.hash() == [0u8; 32]
    }

    /// Marks the node as dirty.
    pub fn mark_dirty(&mut self) {
        self.set_hash(&[0u8; 32]);
    }

    /// Gets the path length in nibbles.
    pub fn path_len(&self) -> usize {
        self.page.as_bytes()[Self::PATH_LEN_OFFSET] as usize
    }

    /// Sets the path length.
    fn set_path_len(&mut self, len: usize) {
        self.page.as_bytes_mut()[Self::PATH_LEN_OFFSET] = len as u8;
    }

    /// Gets the value length.
    pub fn value_len(&self) -> usize {
        let data = self.page.as_bytes();
        u16::from_le_bytes([
            data[Self::VALUE_LEN_OFFSET],
            data[Self::VALUE_LEN_OFFSET + 1],
        ]) as usize
    }

    /// Sets the value length.
    fn set_value_len(&mut self, len: usize) {
        let data = self.page.as_bytes_mut();
        data[Self::VALUE_LEN_OFFSET..Self::VALUE_LEN_OFFSET + 2]
            .copy_from_slice(&(len as u16).to_le_bytes());
    }

    /// Gets the path as nibbles.
    pub fn path(&self) -> Vec<u8> {
        let len = self.path_len();
        if len == 0 {
            return Vec::new();
        }
        let data = self.page.as_bytes();
        let byte_len = (len + 1) / 2;
        let mut nibbles = Vec::with_capacity(len);
        for i in 0..byte_len {
            let byte = data[Self::PATH_OFFSET + i];
            nibbles.push(byte >> 4);
            if nibbles.len() < len {
                nibbles.push(byte & 0x0F);
            }
        }
        nibbles.truncate(len);
        nibbles
    }

    /// Sets the path (nibbles).
    pub fn set_path(&mut self, nibbles: &[u8]) {
        let len = nibbles.len().min(Self::MAX_PATH_LEN);
        self.set_path_len(len);
        let data = self.page.as_bytes_mut();
        let byte_len = (len + 1) / 2;
        for i in 0..byte_len {
            let high = nibbles.get(i * 2).copied().unwrap_or(0);
            let low = nibbles.get(i * 2 + 1).copied().unwrap_or(0);
            data[Self::PATH_OFFSET + i] = (high << 4) | low;
        }
        self.mark_dirty();
    }

    /// Gets the value.
    pub fn value(&self) -> Vec<u8> {
        let len = self.value_len();
        if len == 0 {
            return Vec::new();
        }
        let path_bytes = (self.path_len() + 1) / 2;
        let value_offset = Self::PATH_OFFSET + path_bytes;
        let data = self.page.as_bytes();
        data[value_offset..value_offset + len].to_vec()
    }

    /// Sets the path and value together.
    pub fn set_path_and_value(&mut self, nibbles: &[u8], value: &[u8]) {
        // Compute lengths first
        let path_len = nibbles.len().min(Self::MAX_PATH_LEN);
        let path_bytes = (path_len + 1) / 2;
        let value_offset = Self::PATH_OFFSET + path_bytes;
        let value_len = value.len().min(Self::MAX_VALUE_SIZE);

        // Write path length
        self.page.as_bytes_mut()[Self::PATH_LEN_OFFSET] = path_len as u8;

        // Write value length
        self.page.as_bytes_mut()[Self::VALUE_LEN_OFFSET..Self::VALUE_LEN_OFFSET + 2]
            .copy_from_slice(&(value_len as u16).to_le_bytes());

        // Write path and value data
        let data = self.page.as_bytes_mut();
        for i in 0..path_bytes {
            let high = nibbles.get(i * 2).copied().unwrap_or(0);
            let low = nibbles.get(i * 2 + 1).copied().unwrap_or(0);
            data[Self::PATH_OFFSET + i] = (high << 4) | low;
        }
        data[value_offset..value_offset + value_len].copy_from_slice(&value[..value_len]);

        self.mark_dirty();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_root_page() {
        let mut root = RootPage::new(1);
        assert_eq!(root.next_free_page(), DbAddress::page(1));

        let addr = root.allocate_page();
        assert_eq!(addr, DbAddress::page(1));
        assert_eq!(root.next_free_page(), DbAddress::page(2));

        root.set_block_number(42);
        assert_eq!(root.block_number(), 42);
    }

    #[test]
    fn test_data_page() {
        let mut dp = DataPage::new(1, 0);

        dp.set_bucket(0, DbAddress::page(10));
        dp.set_bucket(255, DbAddress::page(20));

        assert_eq!(dp.get_bucket(0), DbAddress::page(10));
        assert_eq!(dp.get_bucket(255), DbAddress::page(20));
        assert_eq!(dp.get_bucket(1), DbAddress::NULL);
    }

    #[test]
    fn test_abandoned_page() {
        let mut ap = AbandonedPage::new(1, 5);
        assert_eq!(ap.batch_abandoned(), 5);
        assert_eq!(ap.count(), 0);

        assert!(ap.try_add(DbAddress::page(10)));
        assert!(ap.try_add(DbAddress::page(20)));
        assert_eq!(ap.count(), 2);

        assert_eq!(ap.pop(), Some(DbAddress::page(20)));
        assert_eq!(ap.count(), 1);
    }

    #[test]
    fn test_mpt_branch_page() {
        let mut branch = MptBranchPage::new(1, 0);

        // Check initial state
        assert!(branch.is_dirty());
        assert_eq!(branch.child_count(), 0);
        assert!(branch.value().is_none());

        // Set children
        branch.set_child(0, DbAddress::page(10));
        branch.set_child(5, DbAddress::page(20));
        assert_eq!(branch.get_child(0), DbAddress::page(10));
        assert_eq!(branch.get_child(5), DbAddress::page(20));
        assert_eq!(branch.get_child(1), DbAddress::NULL);
        assert_eq!(branch.child_count(), 2);

        // Set child hash
        let hash = [42u8; 32];
        branch.set_child_hash(0, &hash);
        assert_eq!(branch.get_child_hash(0), hash);
        assert!(!branch.is_child_dirty(0));
        assert!(branch.is_child_dirty(5));

        // Set value
        branch.set_value(Some(b"test_value"));
        assert_eq!(branch.value(), Some(b"test_value".to_vec()));

        // Clear value
        branch.set_value(None);
        assert!(branch.value().is_none());
    }

    #[test]
    fn test_mpt_extension_page() {
        let mut ext = MptExtensionPage::new(1, 0);

        // Check initial state
        assert!(ext.is_dirty());
        assert_eq!(ext.path_len(), 0);

        // Set path
        let nibbles = vec![1, 2, 3, 4, 5];
        ext.set_path(&nibbles);
        assert_eq!(ext.path(), nibbles);

        // Set child
        ext.set_child(DbAddress::page(42));
        assert_eq!(ext.child(), DbAddress::page(42));
        assert!(!ext.is_child_inline());

        // Set child hash
        let hash = [99u8; 32];
        ext.set_child_hash(&hash);
        assert_eq!(ext.child_hash(), hash);

        // Set inline child
        ext.set_inline_child(&[0xDE, 0xAD, 0xBE, 0xEF]);
        assert!(ext.is_child_inline());
        assert_eq!(ext.inline_child(), Some(vec![0xDE, 0xAD, 0xBE, 0xEF]));
    }

    #[test]
    fn test_mpt_leaf_page() {
        let mut leaf = MptLeafPage::new(1, 0);

        // Check initial state
        assert!(leaf.is_dirty());
        assert_eq!(leaf.path_len(), 0);
        assert_eq!(leaf.value_len(), 0);

        // Set path and value
        let nibbles = vec![10, 11, 12, 13, 14, 15];
        let value = b"leaf_value".to_vec();
        leaf.set_path_and_value(&nibbles, &value);

        assert_eq!(leaf.path(), nibbles);
        assert_eq!(leaf.value(), value);

        // Set hash
        let hash = [123u8; 32];
        leaf.set_hash(&hash);
        assert_eq!(leaf.hash(), hash);
        assert!(!leaf.is_dirty());

        // Mark dirty
        leaf.mark_dirty();
        assert!(leaf.is_dirty());
    }

    #[test]
    fn test_mpt_leaf_page_roundtrip() {
        let mut leaf = MptLeafPage::new(1, 0);

        // Test with various path lengths
        for path_len in [1, 2, 3, 10, 32, 64] {
            let nibbles: Vec<u8> = (0..path_len).map(|i| (i % 16) as u8).collect();
            let value = vec![0xAB; 100];
            leaf.set_path_and_value(&nibbles, &value);

            assert_eq!(leaf.path(), nibbles, "Path mismatch for len {}", path_len);
            assert_eq!(leaf.value(), value, "Value mismatch for len {}", path_len);
        }
    }
}
