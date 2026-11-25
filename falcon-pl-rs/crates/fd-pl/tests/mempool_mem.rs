// Copyright (c) 2025-2026 BEARTEC. All rights reserved. See LICENSE.
//! Live heap held by the mempool per pending tx, measured with a counting
//! global allocator over real Falcon-512 txs. Own test binary, because the
//! allocator is process-wide. Run with `--nocapture` to see the numbers.
//!
//! The same file builds against older trees (it only uses `Mempool::insert`),
//! so the "before" figure can be taken by running it on a checkout from before the lean pool.

use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicIsize, Ordering};

struct Counting;
static LIVE: AtomicIsize = AtomicIsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        LIVE.fetch_add(l.size() as isize, Ordering::Relaxed);
        System.alloc(l)
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        LIVE.fetch_sub(l.size() as isize, Ordering::Relaxed);
        System.dealloc(p, l)
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        LIVE.fetch_add(n as isize - l.size() as isize, Ordering::Relaxed);
        System.realloc(p, l, n)
    }
}

#[global_allocator]
static A: Counting = Counting;

use fd_pl::crypto::{CryptoScheme, KeyRing};
use fd_pl::{Mempool, Tx, TxBody, NETWORK_ID_PUBLIC_TESTNET_2300};

const N: usize = 400;

fn txs() -> Vec<Tx> {
    let mut keys = KeyRing::new(CryptoScheme::Falcon512);
    (0..N)
        .map(|i| {
            let acct = format!("acct{i:04}");
            keys.generate_id(&acct);
            Tx::sign_body(&keys, &acct, 0, "bob", i as u64 + 1, 1, NETWORK_ID_PUBLIC_TESTNET_2300, TxBody::Pay)
                .unwrap()
        })
        .collect()
}

/// Live bytes added by `f`, with its inputs allocated beforehand.
fn live_delta<T>(f: impl FnOnce() -> T) -> (T, isize) {
    let before = LIVE.load(Ordering::SeqCst);
    let out = f();
    (out, LIVE.load(Ordering::SeqCst) - before)
}

#[test]
fn mempool_live_heap_bytes_per_falcon_tx() {
    let all = txs();
    let sig_hex = all[0].signature.len();
    let pk_hex = all[0].public_key.len();

    // Reference: the pre-lean-pool layout (HashMap<tx_id, Tx> + VecDeque<tx_id>
    // with hex strings), built the way `Mempool::insert` used to.
    let input = all.clone();
    let (old_pool, old_bytes) = live_delta(move || {
        let mut by_id: HashMap<String, Tx> = HashMap::new();
        let mut order: VecDeque<String> = VecDeque::new();
        for tx in input {
            order.push_back(tx.tx_id.clone());
            by_id.insert(tx.tx_id.clone(), tx);
        }
        (by_id, order)
    });
    // `input` is moved in, so its strings are not re-allocated: the delta
    // is what the layout adds on top. Heap owned by the pool = delta + the
    // heap of the txs it was handed (the same `tx_heap` for both layouts;
    // the compact pool frees the hex strings it converts, which the delta
    // already subtracts).
    let tx_heap: isize = all
        .iter()
        .map(|t| (t.account.capacity() + t.destination.capacity() + t.public_key.capacity() + t.signature.capacity() + t.tx_id.capacity()) as isize)
        .sum();
    let old_total = old_bytes + tx_heap;
    drop(old_pool);

    let input = all.clone();
    let (pool, new_bytes) = live_delta(move || {
        let mut mp = Mempool::default();
        for tx in input {
            assert!(mp.insert(tx, 0).unwrap());
        }
        mp
    });
    assert_eq!(pool.len(), N);
    let new_total = new_bytes + tx_heap;

    let per_old = old_total as f64 / N as f64;
    let per_new = new_total as f64 / N as f64;
    eprintln!(
        "MEMPOOL live heap, {N} Falcon-512 txs (sig {sig_hex} hex chars, key {pk_hex} hex chars): \
         hex layout {per_old:.0} B/tx, Mempool {per_new:.0} B/tx ({:.1}%)",
        100.0 * per_new / per_old
    );
    // Holds on any tree: the pool never needs more than the hex layout + 10%.
    assert!(per_new <= per_old * 1.10, "{per_new} vs {per_old}");
    drop(pool);
}
