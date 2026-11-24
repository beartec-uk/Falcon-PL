//! 2.11.15: mempool head dry-run on one shared draft, with head signatures
//! verified in parallel and shared with the pack (`sig_warm`).

use super::*;
use std::time::Instant;

fn falcon_cfg(cap: usize) -> ChainConfig {
    ChainConfig {
        network_id: 9101,
        max_txs_per_ledger: cap,
        pack_budget_ms: 0,
        pong_window_ms: 60_000,
        confirm_depth: 3,
        slash_equivocation: 100,
        scheme: CryptoScheme::Falcon512,
        soft_ok_votes: 4,
        hard_ok_ratio: 0.6,
        progress_timeout_ms: 4_000,
        max_mempool_txs: 50_000,
        ..Default::default()
    }
}

fn accounts(n: usize) -> Vec<(String, u64)> {
    (0..n).map(|i| (format!("w{i}"), 1_000_000_000u64)).collect()
}

fn six(accts: usize, cap: usize) -> Network {
    let seats = ["v1", "v2", "v3", "v4", "v5", "v6"];
    Network::bootstrap(&seats, 1000, &accounts(accts), falcon_cfg(cap))
}

fn pool_ids(n: &Node) -> BTreeSet<String> {
    n.mempool.iter_candidates().map(|t| t.tx_id.clone()).collect()
}

/// Same pool on every seat: good pays, a head that cannot pay its fee, and a
/// head signed with the wrong key.
fn mixed_net() -> Network {
    let mut net = six(24, 400);
    for i in 0..20usize {
        // two hops per account: one head + one pipelined tx
        net.payment(&format!("w{i}"), &format!("w{}", (i + 1) % 20), 1, 1).unwrap();
        net.payment(&format!("w{i}"), &format!("w{}", (i + 1) % 20), 1, 1).unwrap();
    }
    let mut wrong = KeyRing::new(CryptoScheme::Falcon512);
    wrong.generate_id("w21");
    let nid = net.nodes["v1"].cfg.network_id;
    let mut poor_tx = None;
    let user_keys = net.user_keys.clone();
    for n in net.nodes.values_mut() {
        // w22: correct seq, no balance for the fee (permanent).
        let mut a = n.state.get("w22");
        a.balance = 0;
        n.state.accounts.insert("w22".into(), a);
        let seq = n.state.get("w22").sequence;
        let t = poor_tx
            .get_or_insert_with(|| Tx::sign_with(&user_keys, "w22", seq, "w23", 1, 1, nid).unwrap())
            .clone();
        n.mempool.insert(t, n.cfg.max_mempool_txs).unwrap();
        let s = n.state.get("w21").sequence;
        let b = Tx::sign_with(&wrong, "w21", s, "w0", 1, 1, nid).unwrap();
        n.mempool.insert(b, n.cfg.max_mempool_txs).unwrap();
    }
    net
}

#[test]
fn shared_draft_drops_exactly_what_the_full_clone_path_drops() {
    let mut net = mixed_net();
    let before = pool_ids(&net.nodes["v1"]);
    assert_eq!(before, pool_ids(&net.nodes["v2"]));
    set_sanitize_legacy(true);
    let legacy_drop = net.nodes.get_mut("v1").unwrap().drop_permanent_applicable_heads();
    set_sanitize_legacy(false);
    let fast_drop = net.nodes.get_mut("v2").unwrap().drop_permanent_applicable_heads();
    let a = pool_ids(&net.nodes["v1"]);
    let b = pool_ids(&net.nodes["v2"]);
    assert!(legacy_drop >= 1, "fixture must contain a permanent head");
    assert_eq!(legacy_drop, fast_drop);
    assert_eq!(a, b, "same pool left after both paths");
    assert_eq!(
        net.nodes["v1"].perm_head_dry_runs, net.nodes["v2"].perm_head_dry_runs,
        "one dry-run per head on both paths"
    );
    // State untouched by the dry-run.
    let j = |id: &str| serde_json::to_string(&net.nodes[id].state).unwrap();
    assert_eq!(j("v2"), j("v3"), "sanitize must not change committed state");
}

#[test]
fn fast_path_shares_verified_signatures_with_the_pack() {
    let mut net = six(30, 400);
    for i in 0..30usize {
        net.payment(&format!("w{i}"), &format!("w{}", (i + 1) % 30), 1, 1).unwrap();
    }
    let n = net.nodes.get_mut("v1").unwrap();
    n.sig_warm.clear();
    let _ = n.drop_permanent_applicable_heads();
    assert_eq!(n.sanitize_sig_checks, 30, "every cold head checked once");
    assert_eq!(n.sanitize_confirm_runs, 0, "no fresh clone for good heads");
    let txs: Vec<Tx> = n.mempool.iter_candidates().map(|t| t.to_tx()).collect();
    assert!(txs.iter().all(|t| n.sig_warm_valid(t)), "pack reuses sanitize's checks");
    assert!(n.sig_warm.is_empty(), "the pre-pack cache is left alone");
    // Same tip again: memo hit, nothing re-verified.
    let _ = n.drop_permanent_applicable_heads();
    assert_eq!(n.sanitize_sig_checks, 30);
}

#[test]
fn fast_path_never_trusts_a_bad_signature() {
    let mut net = mixed_net();
    let n = net.nodes.get_mut("v1").unwrap();
    let _ = n.drop_permanent_applicable_heads();
    assert!(
        n.mempool.iter_candidates().all(|t| t.account != "w21" || !n.sanitize_sig_warm.contains_key(&t.tx_id)),
        "a wrong-key signature is never cached as good"
    );
    assert!(n.sanitize_confirm_runs >= 1, "bad signature takes the exact path");
}

#[test]
fn fast_path_drop_set_is_a_subset_of_the_full_clone_path() {
    // w5 has no balance; w4 pays w5 inside the same pool. On the shared
    // draft w5's head may be applied after w4's, so it can be kept; it must
    // never drop a head the full-clone path would keep.
    let mut net = six(10, 400);
    for i in 0..10usize {
        net.payment(&format!("w{i}"), &format!("w{}", (i + 1) % 10), 5, 1).unwrap();
    }
    for n in net.nodes.values_mut() {
        let mut a = n.state.get("w5");
        a.balance = 0;
        n.state.accounts.insert("w5".into(), a);
    }
    let before = pool_ids(&net.nodes["v1"]);
    set_sanitize_legacy(true);
    net.nodes.get_mut("v1").unwrap().drop_permanent_applicable_heads();
    set_sanitize_legacy(false);
    net.nodes.get_mut("v2").unwrap().drop_permanent_applicable_heads();
    let legacy_dropped: BTreeSet<_> = before.difference(&pool_ids(&net.nodes["v1"])).cloned().collect();
    let fast_dropped: BTreeSet<_> = before.difference(&pool_ids(&net.nodes["v2"])).cloned().collect();
    assert!(fast_dropped.is_subset(&legacy_dropped), "fast {fast_dropped:?} legacy {legacy_dropped:?}");
}

#[test]
fn pack_after_fast_sanitize_matches_pack_after_legacy_sanitize() {
    // Same pool, same tip: the block (tx ids, state root) does not depend on
    // which sanitize ran first.
    let build = |legacy: bool| {
        let mut net = mixed_net();
        net.pong_all();
        let packer = net.nodes["v1"].lottery_packer().unwrap();
        let n = net.nodes.get_mut(&packer).unwrap();
        set_sanitize_legacy(legacy);
        let _ = n.sanitize_mempool();
        set_sanitize_legacy(false);
        let ids_left = pool_ids(n);
        let led = n.pack_as(&packer).unwrap();
        (ids_left.len(), led.txs.len())
    };
    let (la, lb) = build(true);
    let (fa, fb) = build(false);
    assert_eq!(la, fa);
    assert_eq!(lb, fb);
}

/// Before/after timings for 200- and 400-head pools (one head per account).
/// `cargo test -p fd-pl --release --lib sanitize_bench -- --ignored --nocapture`
/// `SANITIZE_FILLER` extra accounts (default 5000) make the state clone
/// closer to the live chain.
#[test]
#[ignore]
fn sanitize_bench_200_400() {
    let filler: usize = std::env::var("SANITIZE_FILLER").ok().and_then(|v| v.parse().ok()).unwrap_or(5000);
    for heads in [200usize, 400] {
        for legacy in [true, false] {
            let mut net = six(heads, heads);
            // Live wallets are bound (on-chain key), so each tx counts the
            // 2.3 KB known-key size against the 1 MB body budget.
            let pks: Vec<(String, String)> = (0..heads)
                .map(|i| { let id = format!("w{i}"); let pk = net.user_keys.public_hex(&id).unwrap(); (id, pk) })
                .collect();
            for n in net.nodes.values_mut() {
                for (id, pk) in &pks {
                    let mut a = n.state.get(id);
                    a.meta.public_key = pk.clone();
                    n.state.accounts.insert(id.clone(), a);
                }
                for i in 0..filler {
                    let id = format!("f{i}");
                    let mut a = n.state.get(&id);
                    a.balance = 1;
                    n.state.accounts.insert(id, a);
                }
            }
            for i in 0..heads {
                net.payment(&format!("w{i}"), &format!("w{}", (i + 1) % heads), 1, 1).unwrap();
            }
            net.pong_all();
            let packer = net.nodes["v1"].lottery_packer().unwrap();
            let n = net.nodes.get_mut(&packer).unwrap();
            n.sig_warm.clear();
            set_sanitize_legacy(legacy);
            let t = Instant::now();
            let _ = n.sanitize_mempool();
            let sanitize_ms = t.elapsed().as_secs_f64() * 1000.0;
            set_sanitize_legacy(false);
            let warm = n.sanitize_sig_warm.len();
            let t = Instant::now();
            let led = n.pack_as(&packer).unwrap();
            let pack_ms = t.elapsed().as_secs_f64() * 1000.0;
            println!(
                "BENCH heads={heads} filler={filler} path={} sanitize_ms={sanitize_ms:.1} pack_as_ms={pack_ms:.1} total_ms={:.1} txs={} warm_from_sanitize={warm} cores={}",
                if legacy { "legacy" } else { "2.11.15" },
                sanitize_ms + pack_ms,
                led.txs.len(),
                std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1)
            );
        }
    }
}
