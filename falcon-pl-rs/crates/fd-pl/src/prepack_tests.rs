//! 2.11.13 next-builder pre-pack (pipelined pack) tests and pack-cost profile.

use super::*;
use std::time::Instant;

fn falcon_cfg() -> ChainConfig {
    ChainConfig {
        network_id: 9101,
        max_txs_per_ledger: 0,
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

/// A shared ETH exec-header map of about `mb` MB of JSON, like the live
/// bridge state that dominates the commitment-root hash.
fn big_exec_map(mb: usize) -> crate::exec_map::ExecHeaderMap {
    let per = 4_000usize;
    let n = mb * 1_000_000 / (per + 300);
    let mut m = BTreeMap::new();
    for i in 0..n as u64 {
        m.insert(
            i,
            crate::eth_exec::EthExecHeader {
                number: i,
                hash: format!("{:064x}", i + 1),
                parent_hash: format!("{:064x}", i),
                receipts_root: "00".repeat(32),
                rlp_hex: "f9".repeat(per / 2),
            },
        );
    }
    crate::exec_map::ExecHeaderMap::new(m)
}

fn exec_mb() -> usize {
    std::env::var("PREPACK_EXEC_MB").ok().and_then(|v| v.parse().ok()).unwrap_or(100)
}

fn accounts(n: usize) -> Vec<(String, u64)> {
    (0..n).map(|i| (format!("w{i}"), 1_000_000_000u64)).collect()
}

/// Profile: where do the seconds go for one ~300-tx block from 121 accounts?
/// `cargo test -p fd-pl --release --lib prepack_profile -- --ignored --nocapture`
#[test]
#[ignore]
fn prepack_profile_pack_cost_121_accounts() {
    let seats = ["v1", "v2", "v3", "v4", "v5", "v6"];
    let accts = accounts(121);
    let mut net = Network::bootstrap(&seats, 1000, &accts, falcon_cfg());
    let map = big_exec_map(exec_mb());
    for n in net.nodes.values_mut() {
        n.bridge.eth_exec_headers = map.clone();
    }
    let t = Instant::now();
    let _ = map.canonical_json();
    println!("PROFILE exec_json_ms={} bytes={}", t.elapsed().as_millis(), map.canonical_json().len());
    for i in 0..300usize {
        let from = format!("w{}", i % 121);
        let to = format!("w{}", (i + 1) % 121);
        net.payment(&from, &to, 1, 1).unwrap();
    }
    net.pong_all();
    let packer = net.nodes["v1"].lottery_packer().unwrap();
    let n = net.nodes.get_mut(&packer).unwrap();
    {
        let txs: Vec<Tx> = n.mempool.iter_candidates().map(|t| t.to_tx()).collect();
        let refs: Vec<&Tx> = txs.iter().collect();
        let onchain = n.onchain_sig_keys(&refs);
        for w in [1usize, 2, 4] {
            let t = Instant::now();
            let (ok, bad) = Node::preverify_pack_sigs(&n.keys, &onchain, &refs, w);
            println!(
                "PROFILE sig_verify txs={} workers={w} ms={} ok={} bad={}",
                refs.len(),
                t.elapsed().as_millis(),
                ok.len(),
                bad.len()
            );
        }
        let t = Instant::now();
        let draft = n.state.clone();
        let _b = n.bridge.clone();
        println!("PROFILE state_clone_ms={} accounts={}", t.elapsed().as_millis(), draft.accounts.len());
        let t = Instant::now();
        let _r = Node::commitment_root_parts(&n.state, &n.defi, &n.bridge, &n.validators, &n.claimable);
        println!("PROFILE root_ms={}", t.elapsed().as_millis());
    }
    let t = Instant::now();
    let mut led = n.pack_as(&packer).unwrap();
    let pack_ms = t.elapsed().as_millis();
    let t = Instant::now();
    led.attach_merkle_batch_known(&n.keys, &|id| n.account_public_key(id)).unwrap();
    let merkle_ms = t.elapsed().as_millis();
    let t = Instant::now();
    n.accept_ledger(&led).unwrap();
    let self_accept_ms = t.elapsed().as_millis();
    let other = seats.iter().find(|s| **s != packer).unwrap().to_string();
    let t = Instant::now();
    net.nodes.get_mut(&other).unwrap().accept_ledger(&led).unwrap();
    let peer_accept_ms = t.elapsed().as_millis();
    println!(
        "PROFILE txs={} pack_ms={pack_ms} merkle_ms={merkle_ms} self_accept_ms={self_accept_ms} peer_accept_ms={peer_accept_ms}",
        led.txs.len()
    );
}

fn six(accts: usize, cap: usize) -> Network {
    let seats = ["v1", "v2", "v3", "v4", "v5", "v6"];
    let mut cfg = falcon_cfg();
    cfg.max_txs_per_ledger = cap;
    Network::bootstrap(&seats, 1000, &accounts(accts), cfg)
}

/// Pack + stage height N everywhere without voting; returns the ledger.
fn stage_next(net: &mut Network) -> Ledger {
    net.pong_all();
    let packer = net.nodes.values().next().unwrap().lottery_packer().unwrap();
    for n in net.nodes.values_mut() {
        n.pong(&packer);
    }
    let led = net
        .nodes
        .get_mut(&packer)
        .unwrap()
        .pack_or_skip(&packer)
        .unwrap()
        .expect("ledger");
    for n in net.nodes.values_mut() {
        n.accept_ledger(&led).unwrap();
    }
    led
}

fn commit(net: &mut Network, led: &Ledger) {
    let ids: Vec<String> = net.nodes.keys().cloned().collect();
    for n in net.nodes.values_mut() {
        for id in &ids {
            n.vote_ok(&led.ledger_hash, id);
        }
    }
    assert!(net.tip_height() >= led.height, "QC must commit h={}", led.height);
}

#[test]
fn prepack_walk_continues_past_pending_block_and_next_pack_reuses_it() {
    let mut net = six(10, 10);
    for _ in 0..3 {
        for a in 0..10 {
            net.payment(&format!("w{a}"), &format!("w{}", (a + 1) % 10), 1, 1).unwrap();
        }
    }
    let n1 = stage_next(&mut net);
    assert_eq!(n1.txs.len(), 10);
    let in_n1: BTreeSet<String> = n1.txs.iter().map(|t| t.tx_id.clone()).collect();
    for n in net.nodes.values_mut() {
        n.warm_pipeline();
        assert_eq!(n.prepack_txs, 10, "{}: next block walk is a full cap", n.id);
        assert_eq!(n.sig_warm.len(), 10);
        assert!(n.sig_warm.keys().all(|id| !in_n1.contains(id)), "never the pending block's txs");
    }
    commit(&mut net, &n1);
    let r = net.seal_next_height().unwrap();
    assert_eq!(r.n_txs, 10);
    let packer = r.packer.clone();
    let used = net.nodes[&packer].prepack_warm_used;
    assert_eq!(used, 10, "every chosen tx was pre-checked during N's vote window");
    let n2 = net.nodes[&packer].chain.last().unwrap().clone();
    let warm: BTreeSet<String> = net.nodes["v1"].sig_warm.keys().cloned().collect();
    for tx in &n2.txs {
        assert!(warm.contains(&tx.tx_id), "N+1 is exactly the pre-packed walk");
    }
}

#[test]
fn prepack_warm_entry_needs_the_same_key() {
    let mut net = six(3, 0);
    let tx = net.payment("w0", "w1", 1, 1).unwrap();
    let n = net.nodes.get_mut("v1").unwrap();
    let key_now = n.onchain_sig_key(&tx.account);
    n.sig_warm.insert(tx.tx_id.clone(), key_now.clone());
    assert!(n.sig_warm_valid(&tx));
    // Checked against another key (e.g. the pending block rotated it, or a
    // rival block won): the pack must verify again.
    n.sig_warm.insert(tx.tx_id.clone(), Some("ab".repeat(16)));
    assert!(!n.sig_warm_valid(&tx));
    n.sig_warm.clear();
    assert!(!n.sig_warm_valid(&tx), "unknown tx is cold");
}

#[test]
fn prepack_refreshes_only_when_pool_grows() {
    let mut net = six(40, 0);
    for a in 0..40 {
        net.payment(&format!("w{a}"), "w0", 1, 1).unwrap();
    }
    let n1 = stage_next(&mut net);
    let _ = n1;
    let runs0 = {
        let n = net.nodes.get_mut("v2").unwrap();
        n.warm_pipeline();
        n.warm_pipeline();
        n.prepack_runs
    };
    assert_eq!(runs0, 1, "same proposal, same pool: one pass");
    for a in 0..40 {
        net.payment(&format!("w{a}"), "w1", 1, 1).unwrap();
    }
    let n = net.nodes.get_mut("v2").unwrap();
    n.warm_pipeline();
    assert_eq!(n.prepack_runs, 2, "pool grew by >= PREPACK_REFRESH_TXS: refresh");
    assert!(n.prepack_txs >= 40);
}

#[test]
fn prepack_off_lock_result_is_dropped_when_the_pending_block_changes() {
    let mut net = six(10, 10);
    for a in 0..10 {
        net.payment(&format!("w{a}"), "w0", 1, 1).unwrap();
        net.payment(&format!("w{a}"), "w1", 1, 1).unwrap();
    }
    let n1 = stage_next(&mut net);
    // Picked under the lock, checked without it ...
    let plan = net.nodes["v3"].prepack_plan().expect("work to do");
    assert!(plan.todo_len() > 0);
    let done = plan.verify();
    // ... meanwhile N commits: the result describes an old pending block.
    commit(&mut net, &n1);
    let n = net.nodes.get_mut("v3").unwrap();
    assert!(!n.apply_prepack(done), "stale pre-pack is discarded");
    assert!(n.sig_warm.is_empty());
    assert_eq!(n.prepack_runs, 0);
}

#[test]
fn prepack_plan_verify_apply_matches_the_locked_pass() {
    let mut net = six(10, 10);
    for _ in 0..2 {
        for a in 0..10 {
            net.payment(&format!("w{a}"), &format!("w{}", (a + 1) % 10), 1, 1).unwrap();
        }
    }
    let _n1 = stage_next(&mut net);
    let plan = net.nodes["v2"].prepack_plan().unwrap();
    let done = plan.verify();
    assert!(net.nodes.get_mut("v2").unwrap().apply_prepack(done));
    net.nodes.get_mut("v4").unwrap().warm_pipeline();
    let a = &net.nodes["v2"];
    let b = &net.nodes["v4"];
    assert_eq!(a.sig_warm, b.sig_warm);
    assert_eq!(a.prepack_txs, b.prepack_txs);
    assert!(a.prepack_plan().is_none(), "same block, same pool: nothing to redo");
}

#[test]
fn off_lock_key_ring_carries_no_secrets() {
    let net = six(3, 0);
    let n = &net.nodes["v1"];
    let ring = n.keys.publics_only(["w0", "v1"]);
    assert!(ring.has_public("w0") && ring.has_public("v1"));
    assert!(!ring.has_public("w1"));
    assert!(ring.sign("v1", "x").is_err(), "public-only ring cannot sign");
}

#[test]
fn prepack_without_pending_block_warms_the_open_height_for_the_builder() {
    let mut net = six(10, 10);
    for a in 0..10 {
        net.payment(&format!("w{a}"), "w0", 1, 1).unwrap();
    }
    for n in net.nodes.values_mut() {
        assert!(n.pending_proposal.is_none());
        n.warm_pipeline();
        assert_eq!(n.prepack_txs, 10, "{}: open-height walk", n.id);
    }
    let r = net.seal_next_height().unwrap();
    assert_eq!(r.n_txs, 10);
    assert_eq!(net.nodes[&r.packer].prepack_warm_used, 10, "builder packed pre-checked sigs");
    // The tip moved: the next pass is a new anchor but keeps valid entries.
    let n = net.nodes.get_mut("v2").unwrap();
    let before = n.sig_warm.len();
    n.warm_pipeline();
    assert_eq!(n.prepack_runs, 2);
    assert!(n.sig_warm.len() >= before);
}
