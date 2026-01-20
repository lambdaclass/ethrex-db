//! Large database benchmarks (>1M entries)
//!
//! Measures insertion and root hash computation performance on large tries.
//!
//! Run with: cargo bench --bench large_db_benchmarks
//!
//! WARNING: These benchmarks require significant memory (~500MB-1GB)
//! and take several minutes to run.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::time::Duration;

use ethrex_db::merkle::{keccak256, MerkleTrie, EMPTY_ROOT};
use ethrex_db::store::{AccountData, CommitOptions, DiskMpt, DiskMptStateTrie, PagedDb};

/// Sizes to benchmark (1M and 2M entries)
const SIZES: [usize; 2] = [1_000_000, 2_000_000];

/// Number of entries to insert in insertion benchmarks
const INSERT_BATCH_SIZE: usize = 1000;

/// Creates a realistic RLP-encoded account value for benchmarking.
fn create_account_value(index: usize) -> Vec<u8> {
    let account = AccountData {
        nonce: index as u64,
        balance: {
            let mut b = [0u8; 32];
            b[24..].copy_from_slice(&(index as u64).to_be_bytes());
            b
        },
        storage_root: EMPTY_ROOT,
        code_hash: AccountData::EMPTY_CODE_HASH,
    };
    account.encode()
}

/// Creates a large trie with the specified number of entries.
/// Uses pre-hashed keys for optimal insertion performance.
fn create_large_trie(size: usize) -> MerkleTrie {
    let mut trie = MerkleTrie::with_capacity(size);

    let entries: Vec<([u8; 32], Vec<u8>)> = (0..size)
        .map(|i| {
            let key = keccak256(&(i as u64).to_le_bytes());
            (key, create_account_value(i))
        })
        .collect();

    trie.insert_batch_prehashed(entries);
    trie
}

/// Generates new entries for insertion benchmarks, starting from a given offset.
fn generate_new_entries(start: usize, count: usize) -> Vec<([u8; 32], Vec<u8>)> {
    (start..start + count)
        .map(|i| {
            let key = keccak256(&(i as u64).to_le_bytes());
            (key, create_account_value(i))
        })
        .collect()
}

/// Benchmark: Insert batch into large database with root hash computation
///
/// Measures the time to insert 1000 entries into an existing large trie
/// and compute the root hash. The base trie has its root pre-computed,
/// so this measures the incremental update scenario.
///
/// This simulates adding new accounts during block execution and finalizing.
fn bench_insert_into_large_db(c: &mut Criterion) {
    let mut group = c.benchmark_group("LargeDb_Insert");
    group.measurement_time(Duration::from_secs(30));
    group.sample_size(10);

    for &size in &SIZES {
        println!(
            "Creating {}M entry trie for insertion benchmark...",
            size / 1_000_000
        );

        group.throughput(Throughput::Elements(INSERT_BATCH_SIZE as u64));
        group.bench_with_input(
            BenchmarkId::new("insert_and_hash", format!("{}M", size / 1_000_000)),
            &size,
            |b, &size| {
                b.iter_batched(
                    || {
                        // Setup: create large trie with root already computed
                        let mut trie = create_large_trie(size);
                        // Pre-compute root hash so subsequent computation is incremental
                        let _ = trie.root_hash();
                        let new_entries = generate_new_entries(size, INSERT_BATCH_SIZE);
                        (trie, new_entries)
                    },
                    |(mut trie, entries)| {
                        // Measured: insert batch and compute root hash (incremental)
                        trie.insert_batch_prehashed(entries);
                        trie.root_hash()
                    },
                    criterion::BatchSize::LargeInput,
                )
            },
        );
    }

    group.finish();
}

/// Benchmark: Root hash computation on large database
///
/// Measures sequential vs parallel root hash computation on large tries.
/// This simulates computing the state root at block finalization.
fn bench_root_hash_large_db(c: &mut Criterion) {
    let mut group = c.benchmark_group("LargeDb_RootHash");
    group.measurement_time(Duration::from_secs(60));
    group.sample_size(10);

    for &size in &SIZES {
        println!(
            "Creating {}M entry trie for root hash benchmark...",
            size / 1_000_000
        );
        let mut trie = create_large_trie(size);

        // Warm up: compute root once to ensure everything is set up
        let _ = trie.root_hash();

        // Sequential root hash
        group.bench_function(
            BenchmarkId::new("sequential", format!("{}M", size / 1_000_000)),
            |b| {
                b.iter(|| {
                    trie.clear_cache();
                    trie.root_hash()
                })
            },
        );

        // Parallel root hash
        group.bench_function(
            BenchmarkId::new("parallel", format!("{}M", size / 1_000_000)),
            |b| {
                b.iter(|| {
                    trie.clear_cache();
                    trie.parallel_root_hash()
                })
            },
        );
    }

    group.finish();
}

/// Benchmark: Incremental insert with root hash after simulated disk persistence
///
/// This benchmark simulates the scenario where:
/// 1. A trie is loaded from disk with its cached trie structure
/// 2. New entries are inserted
/// 3. Root hash is computed incrementally
///
/// Compares: no cache (cold load) vs with cached trie (warm load)
fn bench_insert_after_persistence(c: &mut Criterion) {
    let mut group = c.benchmark_group("LargeDb_Persistence");
    group.measurement_time(Duration::from_secs(30));
    group.sample_size(10);

    for &size in &SIZES {
        println!(
            "Creating {}M entry trie for persistence benchmark...",
            size / 1_000_000
        );

        // Create the base trie and compute root hash to build cached trie
        let mut base_trie = create_large_trie(size);
        let _base_root = base_trie.root_hash();

        // Export the cached trie (simulates saving to disk)
        let cached_trie_bytes = base_trie.export_cached_trie()
            .expect("Should have cached trie after root_hash()");

        println!(
            "Cached trie size for {}M entries: {} bytes ({:.2} MB)",
            size / 1_000_000,
            cached_trie_bytes.len(),
            cached_trie_bytes.len() as f64 / 1_000_000.0
        );

        // Collect the raw entries to simulate reloading
        let entries: Vec<([u8; 32], Vec<u8>)> = (0..size)
            .map(|i| {
                let key = keccak256(&(i as u64).to_le_bytes());
                (key, create_account_value(i))
            })
            .collect();

        group.throughput(Throughput::Elements(INSERT_BATCH_SIZE as u64));

        // Benchmark: Cold load (no cached trie) + insert + root hash
        group.bench_with_input(
            BenchmarkId::new("cold_insert_and_hash", format!("{}M", size / 1_000_000)),
            &(&entries, size),
            |b, &(entries, size)| {
                b.iter_batched(
                    || {
                        // Setup: create new trie WITHOUT cached trie (simulates cold load)
                        let mut trie = MerkleTrie::with_capacity(size);
                        trie.insert_batch_prehashed(entries.iter().cloned());
                        // Don't compute root hash - simulates cold load without cache
                        let new_entries = generate_new_entries(size, INSERT_BATCH_SIZE);
                        (trie, new_entries)
                    },
                    |(mut trie, entries)| {
                        // Measured: insert batch and compute root hash
                        trie.insert_batch_prehashed(entries);
                        trie.root_hash()
                    },
                    criterion::BatchSize::LargeInput,
                )
            },
        );

        // Benchmark: Warm load (with cached trie) + insert + root hash
        group.bench_with_input(
            BenchmarkId::new("warm_insert_and_hash", format!("{}M", size / 1_000_000)),
            &(&entries, &cached_trie_bytes, size),
            |b, &(entries, cached_bytes, size)| {
                b.iter_batched(
                    || {
                        // Setup: create new trie WITH cached trie (simulates warm load)
                        let mut trie = MerkleTrie::with_capacity(size);
                        trie.insert_batch_prehashed(entries.iter().cloned());
                        // Import cached trie (simulates restoring from disk)
                        trie.import_cached_trie(cached_bytes);
                        let new_entries = generate_new_entries(size, INSERT_BATCH_SIZE);
                        (trie, new_entries)
                    },
                    |(mut trie, entries)| {
                        // Measured: insert batch and compute root hash (should be incremental)
                        trie.insert_batch_prehashed(entries);
                        trie.root_hash()
                    },
                    criterion::BatchSize::LargeInput,
                )
            },
        );

        // Verify that both approaches produce the same root hash
        {
            let mut cold_trie = MerkleTrie::with_capacity(size);
            cold_trie.insert_batch_prehashed(entries.iter().cloned());
            let new_entries = generate_new_entries(size, INSERT_BATCH_SIZE);
            cold_trie.insert_batch_prehashed(new_entries.clone());
            let cold_root = cold_trie.root_hash();

            let mut warm_trie = MerkleTrie::with_capacity(size);
            warm_trie.insert_batch_prehashed(entries.iter().cloned());
            warm_trie.import_cached_trie(&cached_trie_bytes);
            warm_trie.insert_batch_prehashed(new_entries);
            let warm_root = warm_trie.root_hash();

            assert_eq!(cold_root, warm_root, "Cold and warm roots must match!");
            println!("Verified: cold and warm root hashes match for {}M entries", size / 1_000_000);
        }
    }

    group.finish();
}

// ============================================================================
// DiskMpt Benchmarks - Memory-Efficient MPT
// ============================================================================

/// Sizes for DiskMpt benchmarks (smaller due to disk I/O overhead)
const DISK_MPT_SIZES: [usize; 2] = [100_000, 500_000];

/// Creates a DiskMpt with the specified number of entries.
fn create_disk_mpt(db: &mut PagedDb, size: usize) -> DiskMpt {
    let mut mpt = DiskMpt::new();
    let mut batch = db.begin_batch();

    for i in 0..size {
        let key = keccak256(&(i as u64).to_le_bytes());
        let value = create_account_value(i);
        mpt.insert(&mut batch, &key, value).unwrap();
    }

    // Compute root hash to finalize structure
    let _ = mpt.root_hash(&mut batch);

    // Commit the batch so pages are persisted for subsequent operations
    batch.commit(CommitOptions::DangerNoFlush).expect("Failed to commit batch");
    mpt
}

/// Benchmark: Compare MerkleTrie vs DiskMpt root hash computation
///
/// This demonstrates the key advantage of DiskMpt: O(log N) root hash
/// computation vs O(N) for MerkleTrie when recomputing after modifications.
fn bench_disk_mpt_vs_merkle_root_hash(c: &mut Criterion) {
    let mut group = c.benchmark_group("DiskMpt_vs_MerkleTrie");
    group.measurement_time(Duration::from_secs(30));
    group.sample_size(10);

    for &size in &DISK_MPT_SIZES {
        println!("\nBenchmarking {}K entries...", size / 1000);

        // MerkleTrie benchmark (baseline)
        {
            println!("  Creating MerkleTrie with {}K entries...", size / 1000);
            let mut trie = MerkleTrie::with_capacity(size);
            let entries: Vec<([u8; 32], Vec<u8>)> = (0..size)
                .map(|i| {
                    let key = keccak256(&(i as u64).to_le_bytes());
                    (key, create_account_value(i))
                })
                .collect();
            trie.insert_batch_prehashed(entries);
            let _ = trie.root_hash(); // Initial computation

            group.bench_function(
                BenchmarkId::new("MerkleTrie_root_hash", format!("{}K", size / 1000)),
                |b| {
                    b.iter(|| {
                        trie.clear_cache();
                        trie.root_hash()
                    })
                },
            );
        }

        // DiskMpt benchmark (memory-efficient)
        {
            println!("  Creating DiskMpt with {}K entries...", size / 1000);
            let mut db = PagedDb::in_memory((size * 2) as u32).expect("Failed to create db");
            let mut mpt = create_disk_mpt(&mut db, size);

            group.bench_function(
                BenchmarkId::new("DiskMpt_root_hash", format!("{}K", size / 1000)),
                |b| {
                    b.iter(|| {
                        let mut batch = db.begin_batch();
                        mpt.root_hash(&mut batch)
                    })
                },
            );
        }
    }

    group.finish();
}

/// Benchmark: DiskMpt incremental insert + root hash
///
/// This shows the real-world advantage: after inserting a batch of entries,
/// DiskMpt only needs to recompute hashes along the modified paths.
fn bench_disk_mpt_incremental(c: &mut Criterion) {
    let mut group = c.benchmark_group("DiskMpt_Incremental");
    group.measurement_time(Duration::from_secs(30));
    group.sample_size(10);

    for &size in &DISK_MPT_SIZES {
        println!("\nBenchmarking incremental insert on {}K entry base...", size / 1000);

        group.throughput(Throughput::Elements(INSERT_BATCH_SIZE as u64));

        // MerkleTrie incremental (must recompute entire tree)
        group.bench_with_input(
            BenchmarkId::new("MerkleTrie_incremental", format!("{}K", size / 1000)),
            &size,
            |b, &size| {
                b.iter_batched(
                    || {
                        let mut trie = MerkleTrie::with_capacity(size + INSERT_BATCH_SIZE);
                        let entries: Vec<([u8; 32], Vec<u8>)> = (0..size)
                            .map(|i| {
                                let key = keccak256(&(i as u64).to_le_bytes());
                                (key, create_account_value(i))
                            })
                            .collect();
                        trie.insert_batch_prehashed(entries);
                        let _ = trie.root_hash();

                        let new_entries = generate_new_entries(size, INSERT_BATCH_SIZE);
                        (trie, new_entries)
                    },
                    |(mut trie, entries)| {
                        trie.insert_batch_prehashed(entries);
                        trie.root_hash()
                    },
                    criterion::BatchSize::LargeInput,
                )
            },
        );

        // DiskMpt incremental (only recomputes dirty paths)
        group.bench_with_input(
            BenchmarkId::new("DiskMpt_incremental", format!("{}K", size / 1000)),
            &size,
            |b, &size| {
                b.iter_batched(
                    || {
                        let mut db = PagedDb::in_memory((size * 3) as u32).expect("Failed to create db");
                        let mpt = create_disk_mpt(&mut db, size);
                        let new_entries: Vec<([u8; 32], Vec<u8>)> = generate_new_entries(size, INSERT_BATCH_SIZE);
                        (db, mpt, new_entries)
                    },
                    |(mut db, mut mpt, entries)| {
                        let mut batch = db.begin_batch();
                        for (key, value) in entries {
                            mpt.insert(&mut batch, &key, value).unwrap();
                        }
                        mpt.root_hash(&mut batch)
                    },
                    criterion::BatchSize::LargeInput,
                )
            },
        );
    }

    group.finish();
}

/// Benchmark: DiskMptStateTrie for realistic state operations
fn bench_disk_mpt_state_trie(c: &mut Criterion) {
    let mut group = c.benchmark_group("DiskMptStateTrie");
    group.measurement_time(Duration::from_secs(20));
    group.sample_size(10);

    let size = 100_000; // 100K accounts
    println!("\nBenchmarking DiskMptStateTrie with {}K accounts...", size / 1000);

    group.throughput(Throughput::Elements(1000));

    // Insert 1000 accounts and compute root
    group.bench_function(
        BenchmarkId::new("insert_1000_and_hash", format!("{}K_base", size / 1000)),
        |b| {
            b.iter_batched(
                || {
                    let mut db = PagedDb::in_memory((size * 2) as u32).expect("Failed to create db");
                    let mut trie = DiskMptStateTrie::new();
                    let mut batch = db.begin_batch();

                    // Pre-populate with base accounts
                    for i in 0..size {
                        let mut addr = [0u8; 20];
                        addr[..8].copy_from_slice(&(i as u64).to_le_bytes());
                        let account = AccountData {
                            nonce: i as u64,
                            balance: {
                                let mut b = [0u8; 32];
                                b[24..].copy_from_slice(&(i as u64).to_be_bytes());
                                b
                            },
                            storage_root: EMPTY_ROOT,
                            code_hash: AccountData::EMPTY_CODE_HASH,
                        };
                        trie.set_account(&mut batch, &addr, account);
                    }
                    let _ = trie.root_hash(&mut batch);

                    // Generate new accounts to insert
                    let new_accounts: Vec<([u8; 20], AccountData)> = (size..size + 1000)
                        .map(|i| {
                            let mut addr = [0u8; 20];
                            addr[..8].copy_from_slice(&(i as u64).to_le_bytes());
                            let account = AccountData {
                                nonce: i as u64,
                                balance: {
                                    let mut b = [0u8; 32];
                                    b[24..].copy_from_slice(&(i as u64).to_be_bytes());
                                    b
                                },
                                storage_root: EMPTY_ROOT,
                                code_hash: AccountData::EMPTY_CODE_HASH,
                            };
                            (addr, account)
                        })
                        .collect();

                    (db, trie, new_accounts)
                },
                |(mut db, mut trie, accounts)| {
                    let mut batch = db.begin_batch();
                    for (addr, account) in accounts {
                        trie.set_account(&mut batch, &addr, account);
                    }
                    trie.root_hash(&mut batch)
                },
                criterion::BatchSize::LargeInput,
            )
        },
    );

    group.finish();
}

criterion_group!(
    large_db_benches,
    bench_insert_into_large_db,
    bench_root_hash_large_db,
    bench_insert_after_persistence,
    bench_disk_mpt_vs_merkle_root_hash,
    bench_disk_mpt_incremental,
    bench_disk_mpt_state_trie,
);

criterion_main!(large_db_benches);
