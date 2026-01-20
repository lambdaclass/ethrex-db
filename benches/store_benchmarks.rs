//! Store module benchmarks for ethrex_db
//!
//! Run with: cargo bench --bench store_benchmarks

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use rand::prelude::*;

use ethrex_db::merkle::keccak256;
use ethrex_db::store::{
    AccountData, CommitOptions, PageType, PagedDb, PagedStateTrie, Snapshot, StateTrie,
    StorageTrie,
};

/// Generate a random 20-byte address
fn random_address() -> [u8; 20] {
    let mut addr = [0u8; 20];
    rand::thread_rng().fill(&mut addr);
    addr
}

/// Generate a random 32-byte hash
fn random_hash() -> [u8; 32] {
    let mut hash = [0u8; 32];
    rand::thread_rng().fill(&mut hash);
    hash
}

/// Generate a random account
fn random_account() -> AccountData {
    let mut rng = rand::thread_rng();
    let mut balance = [0u8; 32];
    rng.fill(&mut balance[24..]); // Random balance in last 8 bytes

    AccountData {
        nonce: rng.gen(),
        balance,
        storage_root: ethrex_db::merkle::EMPTY_ROOT,
        code_hash: AccountData::EMPTY_CODE_HASH,
    }
}

// ============================================================================
// PagedDb Benchmarks
// ============================================================================

fn bench_paged_db_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("PagedDb_Creation");

    for pages in [100, 1000, 10000].iter() {
        group.bench_with_input(
            BenchmarkId::new("in_memory", pages),
            pages,
            |b, &pages| {
                b.iter(|| PagedDb::in_memory(black_box(pages)).unwrap())
            },
        );
    }

    group.finish();
}

fn bench_paged_db_page_allocation(c: &mut Criterion) {
    let mut group = c.benchmark_group("PagedDb_Allocation");

    // Single page allocation
    group.bench_function("single_page", |b| {
        let mut db = PagedDb::in_memory(10000).unwrap();
        b.iter(|| {
            let mut batch = db.begin_batch();
            let result = batch.allocate_page(PageType::Data, 0);
            batch.abort();
            result
        })
    });

    // Batch allocation
    for count in [10, 100, 1000].iter() {
        group.throughput(Throughput::Elements(*count as u64));
        group.bench_with_input(
            BenchmarkId::new("batch_allocation", count),
            count,
            |b, &count| {
                b.iter(|| {
                    let mut db = PagedDb::in_memory(10000).unwrap();
                    let mut batch = db.begin_batch();
                    for _ in 0..count {
                        batch.allocate_page(PageType::Data, 0).unwrap();
                    }
                    batch.commit(CommitOptions::DangerNoFlush).unwrap();
                })
            },
        );
    }

    group.finish();
}

fn bench_paged_db_commit_options(c: &mut Criterion) {
    let mut group = c.benchmark_group("PagedDb_Commit");

    // Compare different commit options
    for (name, option) in [
        ("DangerNoFlush", CommitOptions::DangerNoFlush),
        ("FlushDataOnly", CommitOptions::FlushDataOnly),
        ("FlushDataAndRoot", CommitOptions::FlushDataAndRoot),
    ] {
        group.bench_function(name, |b| {
            b.iter(|| {
                let mut db = PagedDb::in_memory(1000).unwrap();
                let mut batch = db.begin_batch();
                for _ in 0..10 {
                    batch.allocate_page(PageType::Data, 0).unwrap();
                }
                batch.commit(option).unwrap();
            })
        });
    }

    group.finish();
}

fn bench_paged_db_page_cache(c: &mut Criterion) {
    let mut group = c.benchmark_group("PagedDb_Cache");

    // Setup: create database with pages
    let mut db = PagedDb::in_memory(1000).unwrap();
    let mut addrs = Vec::new();

    {
        let mut batch = db.begin_batch();
        for i in 0..100 {
            let (addr, _) = batch.allocate_page(PageType::Data, i as u8).unwrap();
            addrs.push(addr);
        }
        batch.commit(CommitOptions::DangerNoFlush).unwrap();
    }

    let addr = addrs[50];

    // Cache miss (cold read)
    group.bench_function("cache_miss", |b| {
        b.iter(|| {
            db.clear_cache();
            db.get_page(black_box(addr))
        })
    });

    // Cache hit (warm read)
    let _ = db.get_page(addr); // warm up
    group.bench_function("cache_hit", |b| {
        b.iter(|| db.get_page(black_box(addr)))
    });

    // Sequential access pattern
    group.bench_function("sequential_access_100", |b| {
        b.iter(|| {
            for addr in &addrs {
                black_box(db.get_page(*addr).unwrap());
            }
        })
    });

    // Random access pattern
    let mut rng = rand::thread_rng();
    let random_indices: Vec<usize> = (0..100).map(|_| rng.gen_range(0..addrs.len())).collect();

    group.bench_function("random_access_100", |b| {
        b.iter(|| {
            for &idx in &random_indices {
                black_box(db.get_page(addrs[idx]).unwrap());
            }
        })
    });

    group.finish();
}

fn bench_paged_db_batch_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("PagedDb_Batch");

    // Read-only batch creation
    group.bench_function("begin_read_only", |b| {
        let db = PagedDb::in_memory(100).unwrap();
        b.iter(|| {
            let batch = db.begin_read_only();
            black_box(batch.batch_id())
        })
    });

    // Write batch creation
    group.bench_function("begin_batch", |b| {
        let mut db = PagedDb::in_memory(100).unwrap();
        b.iter(|| {
            let batch = db.begin_batch();
            batch.abort();
        })
    });

    // Batch with dirty pages
    for dirty_count in [10, 50, 100].iter() {
        group.throughput(Throughput::Elements(*dirty_count as u64));
        group.bench_with_input(
            BenchmarkId::new("commit_dirty_pages", dirty_count),
            dirty_count,
            |b, &count| {
                b.iter(|| {
                    let mut db = PagedDb::in_memory(1000).unwrap();
                    let mut batch = db.begin_batch();
                    for _ in 0..count {
                        batch.allocate_page(PageType::Data, 0).unwrap();
                    }
                    batch.commit(CommitOptions::DangerNoFlush).unwrap();
                })
            },
        );
    }

    group.finish();
}

fn bench_paged_db_snapshot(c: &mut Criterion) {
    let mut group = c.benchmark_group("PagedDb_Snapshot");

    let mut db = PagedDb::in_memory(1000).unwrap();
    {
        let mut batch = db.begin_batch();
        for _ in 0..100 {
            batch.allocate_page(PageType::Data, 0).unwrap();
        }
        batch.set_metadata(42, &[1u8; 32]);
        batch.commit(CommitOptions::DangerNoFlush).unwrap();
    }

    // Create snapshot
    group.bench_function("create_snapshot", |b| {
        b.iter(|| db.create_snapshot())
    });

    // Restore snapshot
    let snapshot = db.create_snapshot();
    group.bench_function("restore_snapshot", |b| {
        b.iter(|| {
            let mut db = PagedDb::in_memory(1000).unwrap();
            db.restore_snapshot(&snapshot).unwrap();
        })
    });

    // Snapshot serialization
    group.bench_function("snapshot_to_bytes", |b| {
        b.iter(|| snapshot.to_bytes())
    });

    let bytes = snapshot.to_bytes();
    group.bench_function("snapshot_from_bytes", |b| {
        b.iter(|| Snapshot::from_bytes(black_box(&bytes)))
    });

    group.finish();
}

// ============================================================================
// StateTrie Benchmarks
// ============================================================================

fn bench_state_trie_account_ops(c: &mut Criterion) {
    let mut group = c.benchmark_group("StateTrie_Account");

    // Single account insert
    group.bench_function("set_account", |b| {
        let mut state = StateTrie::new();
        let address = random_address();
        let account = random_account();
        b.iter(|| {
            state.set_account(black_box(&address), black_box(account.clone()));
        })
    });

    // Single account insert by hash
    group.bench_function("set_account_by_hash", |b| {
        let mut state = StateTrie::new();
        let hash = random_hash();
        let account = random_account();
        b.iter(|| {
            state.set_account_by_hash(black_box(&hash), black_box(account.clone()));
        })
    });

    // Batch account insert
    for size in [10, 100, 1000].iter() {
        let accounts: Vec<([u8; 32], AccountData)> = (0..*size)
            .map(|i| {
                let hash = keccak256(&(i as u32).to_be_bytes());
                (hash, random_account())
            })
            .collect();

        group.throughput(Throughput::Elements(*size as u64));
        group.bench_with_input(
            BenchmarkId::new("set_accounts_batch", size),
            &accounts,
            |b, accounts| {
                b.iter(|| {
                    let mut state = StateTrie::new();
                    state.set_accounts_batch(accounts.iter().cloned());
                })
            },
        );
    }

    // Account lookup
    let mut state = StateTrie::new();
    let addresses: Vec<[u8; 20]> = (0..100).map(|_| random_address()).collect();
    for addr in &addresses {
        state.set_account(addr, random_account());
    }

    group.bench_function("get_account_existing", |b| {
        let addr = &addresses[50];
        b.iter(|| state.get_account(black_box(addr)))
    });

    group.bench_function("get_account_nonexistent", |b| {
        let addr = random_address();
        b.iter(|| state.get_account(black_box(&addr)))
    });

    group.finish();
}

fn bench_state_trie_root_hash(c: &mut Criterion) {
    let mut group = c.benchmark_group("StateTrie_RootHash");

    for size in [10, 100, 1000].iter() {
        let mut state = StateTrie::new();
        for i in 0..*size {
            let mut addr = [0u8; 20];
            addr[..4].copy_from_slice(&(i as u32).to_be_bytes());
            state.set_account(&addr, random_account());
        }

        group.bench_with_input(BenchmarkId::new("root_hash", size), size, |b, _| {
            b.iter(|| state.root_hash())
        });
    }

    group.finish();
}

fn bench_state_trie_with_storage(c: &mut Criterion) {
    let mut group = c.benchmark_group("StateTrie_WithStorage");

    // Create state with accounts that have storage
    for (accounts, slots_per_account) in [(10, 10), (100, 10), (10, 100)].iter() {
        let id = format!("{}accounts_{}slots", accounts, slots_per_account);

        group.bench_function(BenchmarkId::new("build_and_hash", id), |b| {
            b.iter(|| {
                let mut state = StateTrie::new();
                for i in 0..*accounts {
                    let mut addr = [0u8; 20];
                    addr[..4].copy_from_slice(&(i as u32).to_be_bytes());
                    state.set_account(&addr, random_account());

                    let storage = state.storage_trie(&addr);
                    for j in 0..*slots_per_account {
                        let mut slot = [0u8; 32];
                        slot[..4].copy_from_slice(&(j as u32).to_be_bytes());
                        let mut value = [0u8; 32];
                        value[31] = (j % 256) as u8;
                        storage.set(&slot, value);
                    }
                }
                state.root_hash()
            })
        });
    }

    // Flush storage tries benchmark
    let mut state = StateTrie::new();
    for i in 0..100 {
        let mut addr = [0u8; 20];
        addr[..4].copy_from_slice(&(i as u32).to_be_bytes());
        state.set_account(&addr, random_account());

        let storage = state.storage_trie(&addr);
        for j in 0..50 {
            let mut slot = [0u8; 32];
            slot[..4].copy_from_slice(&(j as u32).to_be_bytes());
            let mut value = [0u8; 32];
            value[31] = (j % 256) as u8;
            storage.set(&slot, value);
        }
    }

    group.bench_function("flush_storage_tries_100x50", |b| {
        b.iter_batched(
            || {
                let mut state = StateTrie::new();
                for i in 0..100 {
                    let mut addr = [0u8; 20];
                    addr[..4].copy_from_slice(&(i as u32).to_be_bytes());
                    state.set_account(&addr, random_account());
                    let storage = state.storage_trie(&addr);
                    for j in 0..50 {
                        let mut slot = [0u8; 32];
                        slot[..4].copy_from_slice(&(j as u32).to_be_bytes());
                        let mut value = [0u8; 32];
                        value[31] = (j % 256) as u8;
                        storage.set(&slot, value);
                    }
                }
                state
            },
            |mut state| state.flush_storage_tries(),
            criterion::BatchSize::SmallInput,
        )
    });

    group.finish();
}

// ============================================================================
// StorageTrie Benchmarks
// ============================================================================

fn bench_storage_trie(c: &mut Criterion) {
    let mut group = c.benchmark_group("StorageTrie");

    // Single slot set
    group.bench_function("set_slot", |b| {
        let mut storage = StorageTrie::new();
        let slot = random_hash();
        let value = random_hash();
        b.iter(|| {
            storage.set(black_box(&slot), black_box(value));
        })
    });

    // Single slot set by hash
    group.bench_function("set_by_hash", |b| {
        let mut storage = StorageTrie::new();
        let slot_hash = random_hash();
        let value = random_hash();
        b.iter(|| {
            storage.set_by_hash(black_box(&slot_hash), black_box(value));
        })
    });

    // Batch set
    for size in [10, 100, 1000].iter() {
        let entries: Vec<([u8; 32], [u8; 32])> = (0..*size)
            .map(|i| {
                let hash = keccak256(&(i as u32).to_be_bytes());
                let mut value = [0u8; 32];
                value[28..].copy_from_slice(&(i as u32).to_be_bytes());
                (hash, value)
            })
            .collect();

        group.throughput(Throughput::Elements(*size as u64));
        group.bench_with_input(
            BenchmarkId::new("set_batch_by_hash", size),
            &entries,
            |b, entries| {
                b.iter(|| {
                    let mut storage = StorageTrie::new();
                    storage.set_batch_by_hash(entries.iter().cloned());
                })
            },
        );
    }

    // Lookup
    let mut storage = StorageTrie::new();
    let slots: Vec<[u8; 32]> = (0..100)
        .map(|i| {
            let mut slot = [0u8; 32];
            slot[..4].copy_from_slice(&(i as u32).to_be_bytes());
            slot
        })
        .collect();
    for slot in &slots {
        storage.set(slot, random_hash());
    }

    group.bench_function("get_existing", |b| {
        let slot = &slots[50];
        b.iter(|| storage.get(black_box(slot)))
    });

    group.bench_function("get_nonexistent", |b| {
        let slot = random_hash();
        b.iter(|| storage.get(black_box(&slot)))
    });

    // Root hash
    group.bench_function("root_hash_100_slots", |b| {
        b.iter(|| storage.root_hash())
    });

    group.finish();
}

// ============================================================================
// AccountData Benchmarks
// ============================================================================

fn bench_account_data(c: &mut Criterion) {
    let mut group = c.benchmark_group("AccountData");

    let account = AccountData {
        nonce: 12345,
        balance: {
            let mut b = [0u8; 32];
            b[24..].copy_from_slice(&1000000u64.to_be_bytes());
            b
        },
        storage_root: ethrex_db::merkle::EMPTY_ROOT,
        code_hash: AccountData::EMPTY_CODE_HASH,
    };

    // Encode
    group.bench_function("encode", |b| {
        b.iter(|| account.encode())
    });

    // Decode
    let encoded = account.encode();
    group.bench_function("decode", |b| {
        b.iter(|| AccountData::decode(black_box(&encoded)))
    });

    // Roundtrip
    group.bench_function("encode_decode", |b| {
        b.iter(|| {
            let encoded = account.encode();
            AccountData::decode(&encoded)
        })
    });

    group.finish();
}

// ============================================================================
// PagedStateTrie Benchmarks
// ============================================================================

fn bench_paged_state_trie(c: &mut Criterion) {
    let mut group = c.benchmark_group("PagedStateTrie");

    // Save small state
    for size in [10, 100, 500].iter() {
        group.bench_with_input(BenchmarkId::new("save", size), size, |b, &size| {
            b.iter_batched(
                || {
                    let db = PagedDb::in_memory(10000).unwrap();
                    let mut trie = PagedStateTrie::new();
                    for i in 0..size {
                        let mut addr = [0u8; 20];
                        addr[..4].copy_from_slice(&(i as u32).to_be_bytes());
                        trie.set_account(&addr, random_account());
                    }
                    (db, trie)
                },
                |(mut db, mut trie)| {
                    let mut batch = db.begin_batch();
                    let addr = trie.save(&mut batch).unwrap();
                    batch.commit(CommitOptions::DangerNoFlush).unwrap();
                    addr
                },
                criterion::BatchSize::SmallInput,
            )
        });
    }

    // Load state
    for size in [10, 100, 500].iter() {
        // Setup: create and save a trie
        let mut db = PagedDb::in_memory(10000).unwrap();
        let root_addr = {
            let mut trie = PagedStateTrie::new();
            for i in 0..*size {
                let mut addr = [0u8; 20];
                addr[..4].copy_from_slice(&(i as u32).to_be_bytes());
                trie.set_account(&addr, random_account());
            }
            let mut batch = db.begin_batch();
            let addr = trie.save(&mut batch).unwrap();
            batch.commit(CommitOptions::DangerNoFlush).unwrap();
            addr
        };

        group.bench_with_input(BenchmarkId::new("load", size), &(db, root_addr), |b, (db, addr)| {
            b.iter(|| PagedStateTrie::load(db, *addr).unwrap())
        });
    }

    group.finish();
}

// ============================================================================
// Export/Import Benchmarks
// ============================================================================

fn bench_export_import(c: &mut Criterion) {
    let mut group = c.benchmark_group("PagedDb_ExportImport");

    // Setup: create database with data
    let mut db = PagedDb::in_memory(1000).unwrap();
    {
        let mut batch = db.begin_batch();
        for _ in 0..100 {
            batch.allocate_page(PageType::Data, 0).unwrap();
        }
        batch.set_metadata(42, &[0xAB; 32]);
        batch.commit(CommitOptions::DangerNoFlush).unwrap();
    }

    // Export
    group.bench_function("export_100_pages", |b| {
        b.iter(|| {
            let mut buffer = Vec::new();
            db.export(&mut buffer).unwrap();
            buffer
        })
    });

    // Import
    let mut buffer = Vec::new();
    db.export(&mut buffer).unwrap();

    group.bench_function("import_100_pages", |b| {
        b.iter(|| {
            let mut new_db = PagedDb::in_memory(1000).unwrap();
            new_db.import(&buffer[..]).unwrap();
        })
    });

    group.finish();
}

// ============================================================================
// Concurrent Access Patterns (simulated)
// ============================================================================

fn bench_concurrent_patterns(c: &mut Criterion) {
    let mut group = c.benchmark_group("ConcurrentPatterns");

    // Simulated concurrent readers with single writer pattern
    let mut db = PagedDb::in_memory(1000).unwrap();
    let mut addrs = Vec::new();

    {
        let mut batch = db.begin_batch();
        for _ in 0..100 {
            let (addr, _) = batch.allocate_page(PageType::Data, 0).unwrap();
            addrs.push(addr);
        }
        batch.commit(CommitOptions::DangerNoFlush).unwrap();
    }

    // Read-only batch access pattern
    group.bench_function("read_only_batch_reads", |b| {
        b.iter(|| {
            let batch = db.begin_read_only();
            for addr in &addrs[..10] {
                black_box(batch.get_page(*addr).unwrap());
            }
        })
    });

    // Mix of metadata reads (lock-free)
    group.bench_function("lock_free_metadata", |b| {
        b.iter(|| {
            black_box(db.batch_id());
            black_box(db.block_number());
            black_box(db.block_hash());
        })
    });

    group.finish();
}

criterion_group!(
    store_benches,
    bench_paged_db_creation,
    bench_paged_db_page_allocation,
    bench_paged_db_commit_options,
    bench_paged_db_page_cache,
    bench_paged_db_batch_operations,
    bench_paged_db_snapshot,
    bench_state_trie_account_ops,
    bench_state_trie_root_hash,
    bench_state_trie_with_storage,
    bench_storage_trie,
    bench_account_data,
    bench_paged_state_trie,
    bench_export_import,
    bench_concurrent_patterns,
);

criterion_main!(store_benches);
