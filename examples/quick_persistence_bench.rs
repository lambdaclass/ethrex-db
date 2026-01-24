use ethrex_db::merkle::{keccak256, MerkleTrie};
use std::time::Instant;

fn create_account_value(index: usize) -> Vec<u8> {
    format!("account_data_{}", index).into_bytes()
}

fn main() {
    let size = 100_000; // 100K entries instead of 1M
    let insert_count = 1000;

    println!("Creating {}K entry trie...", size / 1000);
    let mut trie = MerkleTrie::with_capacity(size);
    let entries: Vec<([u8; 32], Vec<u8>)> = (0..size)
        .map(|i| (keccak256(&(i as u64).to_le_bytes()), create_account_value(i)))
        .collect();
    trie.insert_batch_prehashed(entries.clone());

    // First root hash (builds cached trie)
    let start = Instant::now();
    let root1 = trie.root_hash();
    println!("Initial root hash: {:?} ({:.2}ms)", &root1[..4], start.elapsed().as_secs_f64() * 1000.0);

    // Export cached trie
    let cached = trie.export_cached_trie().unwrap();
    println!("Cached trie size: {} bytes ({:.2} MB)", cached.len(), cached.len() as f64 / 1_000_000.0);

    // Test 1: Insert + root hash WITH cached trie (warm)
    let new_entries: Vec<([u8; 32], Vec<u8>)> = (size..size + insert_count)
        .map(|i| (keccak256(&(i as u64).to_le_bytes()), create_account_value(i)))
        .collect();

    let start = Instant::now();
    trie.insert_batch_prehashed(new_entries.clone());
    let root2 = trie.root_hash();
    let warm_time = start.elapsed();
    println!("WARM: Insert {} + root hash: {:.2}ms", insert_count, warm_time.as_secs_f64() * 1000.0);

    // Test 2: Cold load (no cached trie) + insert + root hash
    let mut cold_trie = MerkleTrie::with_capacity(size + insert_count);
    cold_trie.insert_batch_prehashed(entries.iter().cloned());

    let start = Instant::now();
    cold_trie.insert_batch_prehashed(new_entries.clone());
    let root3 = cold_trie.root_hash();
    let cold_time = start.elapsed();
    println!("COLD: Insert {} + root hash: {:.2}ms", insert_count, cold_time.as_secs_f64() * 1000.0);

    // Test 3: Warm load (with imported cached trie) + insert + root hash
    let mut warm_trie = MerkleTrie::with_capacity(size + insert_count);
    warm_trie.insert_batch_prehashed(entries.iter().cloned());
    warm_trie.import_cached_trie(&cached);

    let start = Instant::now();
    warm_trie.insert_batch_prehashed(new_entries.clone());
    let root4 = warm_trie.root_hash();
    let reimport_time = start.elapsed();
    println!("REIMPORT: Insert {} + root hash: {:.2}ms", insert_count, reimport_time.as_secs_f64() * 1000.0);

    // Verify all roots match
    assert_eq!(root2, root3, "Warm and cold roots must match");
    assert_eq!(root2, root4, "Warm and reimport roots must match");
    println!("\nAll roots match!");

    println!("\nSpeedup from warm vs cold: {:.1}x", cold_time.as_secs_f64() / warm_time.as_secs_f64());
    println!("Speedup from reimport vs cold: {:.1}x", cold_time.as_secs_f64() / reimport_time.as_secs_f64());
}
