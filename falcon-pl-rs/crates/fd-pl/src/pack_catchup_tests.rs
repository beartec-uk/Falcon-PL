// Copyright (c) 2025-2026 BEARTEC. All rights reserved. See LICENSE.
//! v2.9.49 / v2.9.50 / v2.9.51 tests: cheap per-tx pack rollback (same txs + same state
//! root as the old full-clone path), catch-up from any healthy peer (including
//! a hub that fell behind holding its own uncommitted proposal after a fork),
//! and the held-proposal cascade fix (never commit a bare live hold on
//! catch-up; snap adopt clears leftover stall flags).

use super::*;

fn users(n: usize, bal: u64) -> Vec<(String, u64)> {
    (0..n).map(|i| (format!("u{i:03}"), bal)).collect()
}

fn net_with(vals: &[&str], us: &[(String, u64)], cfg: ChainConfig) -> Network {
    let mut net = Network::bootstrap(vals, 1000, us, cfg);
    net.pong_all();
    net
}

fn sign(net: &Network, acct: &str, seq: u64, dest: &str, amount: u64, body: TxBody) -> Tx {
    Tx::sign_body(&net.user_keys, acct, seq, dest, amount, 1, net.cfg.network_id, body).unwrap()
}

fn submit_all(net: &mut Network, tx: &Tx) {
    for n in net.nodes.values_mut() {
        let _ = n.submit_tx(tx.clone());
    }
}

/// Pack the current mempool on `w` twice — old full-clone path, then the new
/// rollback path — re-adding txs the first pack dropped as permanent failures
/// so both see exactly the same candidate set.
fn pack_both(net: &mut Network, w: &str, all: &[Tx]) -> (Ledger, Ledger) {
    let n = net.nodes.get_mut(w).unwrap();
    set_pack_force_full_clone(true);
    let old = n.pack_as(w);
    set_pack_force_full_clone(false);
    let old = old.expect("old-path pack");
    for tx in all {
        let _ = n.submit_tx(tx.clone());
    }
    let new = n.pack_as(w).expect("new-path pack");
    (old, new)
}

fn commit_everywhere(net: &mut Network, led: &Ledger) {
    let ids: Vec<String> = net.nodes.keys().cloned().collect();
    for n in net.nodes.values_mut() {
        n.accept_ledger(led).expect("receivers verify the root with the unchanged path");
    }
    for n in net.nodes.values_mut() {
        for id in &ids {
            n.vote_ok(&led.ledger_hash, id);
        }
    }
    for n in net.nodes.values() {
        assert_eq!(n.tip_height, led.height, "commit h={}", led.height);
        assert_eq!(n.tip_hash, led.ledger_hash);
    }
}

fn base_cfg() -> ChainConfig {
    ChainConfig {
        pack_budget_ms: 0, // unlimited → deterministic selection for equivalence
        max_txs_per_ledger: 0,
        progress_timeout_ms: 0,
        ..Default::default()
    }
}

#[test]
fn pack_undo_capture_is_cheap_for_pay_full_otherwise() {
    let net = net_with(&["v1", "v2", "v3"], &users(3, 1_000), base_cfg());
    let n = &net.nodes["v1"];
    let draft = PackDraft {
        state: n.state.clone(),
        defi: n.defi.clone(),
        bridge: n.bridge.clone(),
        vals: n.validators.clone(),
        claim: n.claimable.clone(),
        work: n.epoch_work.clone(),
    };
    let pay = sign(&net, "u000", 1, "u001", 1, TxBody::Pay);
    let apay = sign(&net, "u000", 1, "u001", 1, TxBody::AssetPay { asset: "BTC".into() });
    let bond = sign(&net, "u000", 1, "", 1, TxBody::Bond { validator: "vx".into() });
    assert!(PackUndo::capture(&draft, &pay).is_cheap());
    assert!(PackUndo::capture(&draft, &apay).is_cheap());
    assert!(!PackUndo::capture(&draft, &bond).is_cheap(), "other bodies keep the full clone");
}

/// Same mempool, failing txs in the middle: identical chosen txs and state
/// root under the old (clone-per-tx) and new (rollback) pack paths.
#[test]
fn pack_undo_matches_full_clone_with_failures_in_the_middle() {
    let mut us = users(8, 10_000);
    us[2].1 = 50; // u002: too poor for its big payment
    let mut net = net_with(&["v1", "v2", "v3"], &us, base_cfg());
    for n in net.nodes.values_mut() {
        n.defi.credit_asset("u004", "BTC", 1_000);
    }
    let mut all: Vec<Tx> = Vec::new();
    // ok, ok
    {
        let t = sign(&net, "u000", 1, "u001", 10, TxBody::Pay);
        submit_all(&mut net, &t);
        all.push(t);
    }
    {
        let t = sign(&net, "u000", 2, "u001", 10, TxBody::Pay);
        submit_all(&mut net, &t);
        all.push(t);
    }
    // u002: seq+fee bumped, then "insufficient balance" → must roll back;
    // its seq 2 then stays future ("bad sequence") in both paths.
    {
        let t = sign(&net, "u002", 1, "u003", 10_000, TxBody::Pay);
        submit_all(&mut net, &t);
        all.push(t);
    }
    {
        let t = sign(&net, "u002", 2, "u003", 1, TxBody::Pay);
        submit_all(&mut net, &t);
        all.push(t);
    }
    // u003 pays itself more than it has (account == destination rollback).
    {
        let t = sign(&net, "u003", 1, "u003", 20_000, TxBody::Pay);
        submit_all(&mut net, &t);
        all.push(t);
    }
    // AssetPay ok (creates u005's asset row) and AssetPay failing after fee.
    {
        let t = sign(&net, "u004", 1, "u005", 7, TxBody::AssetPay { asset: "BTC".into() });
        submit_all(&mut net, &t);
        all.push(t);
    }
    {
        let t = sign(&net, "u006", 1, "u007", 7, TxBody::AssetPay { asset: "BTC".into() });
        submit_all(&mut net, &t);
        all.push(t);
    }
    // Bond below min: full-clone fallback path, fails after debit.
    {
        let t = sign(&net, "u007", 1, "", 1, TxBody::Bond { validator: "vnew".into() });
        submit_all(&mut net, &t);
        all.push(t);
    }
    // more ok after the failures
    {
        let t = sign(&net, "u001", 1, "u000", 5, TxBody::Pay);
        submit_all(&mut net, &t);
        all.push(t);
    }
    {
        let t = sign(&net, "u005", 1, "u006", 5, TxBody::Pay);
        submit_all(&mut net, &t);
        all.push(t);
    }

    let w = net.nodes["v1"].lottery_packer().unwrap();
    let before = net.nodes[&w].state.get("u002");
    let (old, new) = pack_both(&mut net, &w, &all);
    assert_eq!(old.tx_ids, new.tx_ids, "same txs chosen");
    assert_eq!(old.state_root_after, new.state_root_after, "same state root");
    assert_eq!(old.ledger_hash, new.ledger_hash, "byte-identical ledger");
    // failing txs are not in the block
    let ids: BTreeSet<&str> = new.txs.iter().map(|t| t.account.as_str()).collect();
    assert!(!ids.contains("u002") && !ids.contains("u003"), "{ids:?}");
    assert!(new.txs.iter().all(|t| !matches!(t.body, TxBody::Bond { .. })));
    assert!(new.txs.iter().any(|t| t.account == "u004"), "good AssetPay packed");
    commit_everywhere(&mut net, &new);
    for n in net.nodes.values() {
        let after = n.state.get("u002");
        assert_eq!(after.sequence, before.sequence, "rolled-back seq bump");
        assert_eq!(after.balance, before.balance, "rolled-back fee");
        assert_eq!(n.defi.asset_bal("u005", "BTC"), 7);
        assert_eq!(n.defi.asset_bal("u006", "BTC"), 0);
        assert!(n.defi.assets.get("u006").is_none(), "no empty asset row left behind");
    }
}

/// Randomised: several heights of mixed Pay / AssetPay / Bond with random
/// amounts (many fail mid-pack). Every height must pack identically.
#[test]
fn pack_undo_matches_full_clone_randomised() {
    let us = users(12, 2_000);
    let mut net = net_with(&["v1", "v2", "v3"], &us, base_cfg());
    for n in net.nodes.values_mut() {
        for (i, (a, _)) in us.iter().enumerate() {
            if i % 3 == 0 {
                n.defi.credit_asset(a, "ETH", 500);
            }
        }
    }
    let mut seed: u64 = 0x9e37_79b9_7f4a_7c15;
    let mut rnd = move |m: u64| {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed % m.max(1)
    };
    let mut total_failed_seen = 0usize;
    for round in 0..6 {
        let mut all = Vec::new();
        let mut issued: BTreeMap<String, u64> = BTreeMap::new();
        for _ in 0..40 {
            let a = &us[rnd(us.len() as u64) as usize].0;
            let d = &us[rnd(us.len() as u64) as usize].0;
            let committed = net.nodes["v1"].state.get(a).sequence;
            let k = issued.entry(a.clone()).or_insert(0);
            let seq = committed + *k;
            *k += 1;
            let tx = match rnd(10) {
                0..=5 => sign(&net, a, seq, d, rnd(900), TxBody::Pay),
                6..=8 => {
                    let dest = if d == a { &us[(rnd(11) + 1) as usize].0 } else { d };
                    let dest = if dest == a { "z-sink" } else { dest.as_str() };
                    sign(&net, a, seq, dest, rnd(300) + 1, TxBody::AssetPay { asset: "ETH".into() })
                }
                _ => sign(&net, a, seq, "", 1, TxBody::Bond { validator: "vbad".into() }),
            };
            submit_all(&mut net, &tx);
            all.push(tx);
        }
        let w = net.nodes["v1"].lottery_packer().unwrap();
        let (old, new) = pack_both(&mut net, &w, &all);
        assert_eq!(old.tx_ids, new.tx_ids, "round {round}: same txs");
        assert_eq!(old.state_root_after, new.state_root_after, "round {round}: same root");
        total_failed_seen += all.len().saturating_sub(new.txs.len());
        commit_everywhere(&mut net, &new);
        // Clear leftovers so the next round starts from committed seqs.
        for n in net.nodes.values_mut() {
            let ids: Vec<String> = n.mempool.iter_candidates().map(|t| t.tx_id.clone()).collect();
            n.mempool.remove_many(&ids);
        }
    }
    assert!(total_failed_seen > 20, "test must exercise failing txs ({total_failed_seen})");
}

/// "100s of tx per block": with a production-sized draft (150k accounts) the
/// old path clones the whole draft per candidate and runs out of the 1 s
/// budget early; the new path packs 200+ inside the same budget.
#[test]
fn pack_undo_fits_200_plus_txs_in_budget() {
    let us = users(60, 1_000_000);
    let cfg = ChainConfig {
        pack_budget_ms: 1_000,
        max_txs_per_ledger: 0,
        progress_timeout_ms: 0,
        ..Default::default()
    };
    let mut net = net_with(&["v1", "v2", "v3"], &us, cfg);
    let w = net.nodes["v1"].lottery_packer().unwrap();
    {
        let n = net.nodes.get_mut(&w).unwrap();
        for i in 0..150_000u32 {
            n.state.accounts.insert(
                format!("pad{i:06}"),
                AccountState { sequence: 1, balance: 1, meta: Default::default(), external_addrs: Default::default() },
            );
        }
    }
    let mut all = Vec::new();
    for s in 1..=5u64 {
        for (a, _) in &us {
            let tx = sign(&net, a, s, "sink", 1, TxBody::Pay);
            let _ = net.nodes.get_mut(&w).unwrap().submit_tx(tx.clone());
            all.push(tx);
        }
    }
    assert_eq!(all.len(), 300);
    let n = net.nodes.get_mut(&w).unwrap();
    set_pack_force_full_clone(true);
    let t0 = std::time::Instant::now();
    let old = n.pack_as(&w).expect("old pack");
    let old_ms = t0.elapsed().as_millis();
    set_pack_force_full_clone(false);
    let t1 = std::time::Instant::now();
    let new = n.pack_as(&w).expect("new pack");
    let new_ms = t1.elapsed().as_millis();
    eprintln!(
        "pack 300 candidates, 150k-account draft: old {} txs in {old_ms} ms, new {} txs in {new_ms} ms",
        old.txs.len(),
        new.txs.len()
    );
    assert!(new.txs.len() >= 200, "new path packed only {}", new.txs.len());
    assert!(new.txs.len() > old.txs.len(), "new must beat clone-per-tx");
    // Budget is checked between txs; allow one draft clone + root of slack.
    assert!(new_ms < 1_000 + 2_500, "pack took {new_ms} ms");
}

#[test]
fn pack_default_cap_applies_when_unlimited() {
    let us = users(50, 1_000_000);
    let mut net = net_with(&["v1", "v2", "v3"], &us, base_cfg());
    // Pre-bind on-chain public keys so candidate txs use KNOWN_KEY_TX_EST_BYTES (2,300 B)
    // and reach PACK_DEFAULT_MAX_TXS (400) inside PACK_BODY_BUDGET_BYTES (1 MB).
    for n in net.nodes.values_mut() {
        for (a, _) in &us {
            let pk = n.keys.public_hex(a).unwrap();
            n.state.accounts.get_mut(a).unwrap().meta.public_key = pk;
        }
    }
    let w = net.nodes["v1"].lottery_packer().unwrap();
    for s in 1..=10u64 {
        for (a, _) in &us {
            let tx = sign(&net, a, s, "sink", 1, TxBody::Pay);
            let _ = net.nodes.get_mut(&w).unwrap().submit_tx(tx);
        }
    }
    let led = net.nodes.get_mut(&w).unwrap().pack_as(&w).unwrap();
    assert_eq!(led.txs.len(), Node::PACK_DEFAULT_MAX_TXS);
    net.nodes.get_mut(&w).unwrap().cfg.max_txs_per_ledger = 420;
    let led = net.nodes.get_mut(&w).unwrap().pack_as(&w).unwrap();
    assert_eq!(led.txs.len(), 420, "--max-txs overrides the default cap");
}

// ---------------------------------------------------------------------------
// Catch-up from any healthy peer
// ---------------------------------------------------------------------------

fn set_tip(n: &mut Node, id: &str, tip: u64) {
    let now = n.now_ms;
    if let Some(v) = n.validators.get_mut(id) {
        v.last_advertised_tip = Some(tip);
        v.last_pong_ms = now;
    }
}

#[test]
fn catchup_candidates_fall_back_to_any_peer_and_skip_self() {
    let vals = ["v1", "v2", "v3", "v4", "v5", "v6"];
    let mut net = net_with(&vals, &users(2, 10), base_cfg());
    let n = net.nodes.get_mut("v1").unwrap();
    let tip = n.tip_height;
    // v1 is a hub whose --hubs are itself (idx 0) and v3 (idx 1).
    set_tip(n, "v1", tip);
    set_tip(n, "v3", tip); // hub, not ahead → useless
    set_tip(n, "v2", tip + 50);
    n.validators.get_mut("v2").unwrap().jailed = true; // ahead but jailed
    set_tip(n, "v4", tip + 50);
    set_tip(n, "v5", tip + 49);
    let peers: Vec<(usize, String)> = vec![
        (0, "v1".into()),
        (1, "v3".into()),
        (2, "v2".into()),
        (3, "v4".into()),
        (4, "v5".into()),
        (5, String::new()), // no Hello yet
    ];
    let plan = n.catchup_candidates(&peers, &[0, 1]);
    assert_eq!(plan.hub_count, 0);
    assert_eq!(plan.skipped_self, 1);
    assert_eq!(plan.skipped_jailed, 1);
    assert_eq!(plan.skipped_behind, 1);
    let set: BTreeSet<usize> = plan.order.iter().copied().collect();
    assert_eq!(set, [3, 4, 5].into_iter().collect(), "{plan:?}");
    assert_eq!(*plan.order.last().unwrap(), 5, "unknown peer goes last");
    // Old behaviour asked hubs only: nothing usable at all.
    assert!(!n.catchup_peer_usable("v1"), "never ask ourselves");

    // Hub ahead again → hub first, others still listed as fallback.
    set_tip(n, "v3", tip + 50);
    let plan = n.catchup_candidates(&peers, &[0, 1]);
    assert_eq!(plan.hub_count, 1);
    assert_eq!(plan.order[0], 1);
    assert!(plan.order.contains(&3) && plan.order.contains(&4));
}

/// Seal one height on every node except `out` (the lagging hub). If the
/// lottery picks `out`, everyone else skip-QCs it first.
fn seal_without(net: &mut Network, out: &str) -> Ledger {
    let others: Vec<String> = net.nodes.keys().filter(|k| k.as_str() != out).cloned().collect();
    for _ in 0..8 {
        let first = &others[0];
        let h = net.nodes[first].tip_height + 1;
        let tip = net.nodes[first].tip_hash.clone();
        let t = net.nodes[first].now_ms;
        for id in &others {
            let n = net.nodes.get_mut(id).unwrap();
            n.now_ms = t;
            for p in &others {
                n.pong(p);
            }
        }
        let w = net.nodes[first].lottery_packer().unwrap();
        if w == out || !others.contains(&w) {
            for id in &others {
                net.nodes.get_mut(id).unwrap().apply_shared_skip(h, &w, &tip);
            }
            continue;
        }
        let led = net.nodes.get_mut(&w).unwrap().pack_as(&w).expect("peer pack");
        for id in &others {
            net.nodes.get_mut(id).unwrap().accept_ledger(&led).expect("peer accept");
        }
        for id in &others {
            for v in &others {
                net.nodes.get_mut(id).unwrap().vote_ok(&led.ledger_hash, v);
            }
        }
        for id in &others {
            assert_eq!(net.nodes[id].tip_height, h, "peers commit h={h}");
        }
        return led;
    }
    panic!("could not seal without {out}");
}

/// Harness: the hub packs its own proposal at h+1, nobody else sees it, the
/// rest of the mesh skips it and moves on 6 heights. The hub must catch up
/// from a non-hub peer, drop its stale pending and land on the peers' chain;
/// a late copy of its own losing body must not poison catch-up afterwards.
#[test]
fn lagging_hub_recovers_after_fork_from_non_hub_peer() {
    let vals = ["v1", "v2", "v3", "v4", "v5"];
    let us = users(6, 1_000_000);
    let cfg = ChainConfig { soft_ok_votes: 3, ..base_cfg() };
    let mut net = net_with(&vals, &us, cfg);
    for i in 0..3u64 {
        let tx = sign(&net, "u000", i + 1, "u001", 1, TxBody::Pay);
        submit_all(&mut net, &tx);
        net.seal_next_height().unwrap();
    }
    let h0 = net.tip_height();
    let hub = net.nodes["v1"].lottery_packer().unwrap();
    // The hub packs h0+1 and stages it locally; the mesh never sees it.
    let tx = sign(&net, "u001", 1, "u002", 1, TxBody::Pay);
    submit_all(&mut net, &tx);
    let own = {
        let n = net.nodes.get_mut(&hub).unwrap();
        let led = n.pack_as(&hub).unwrap();
        n.accept_ledger(&led).unwrap();
        assert_eq!(n.pending_proposal.as_ref().map(|p| p.ledger_hash.clone()), Some(led.ledger_hash.clone()));
        assert_eq!(n.tip_height, h0, "own proposal never got a QC");
        led
    };
    // Mesh moves on without the hub: a different h0+1, then 5 more.
    for k in 0..6u64 {
        let tx = sign(&net, "u003", k + 1, "u004", 1, TxBody::Pay);
        submit_all(&mut net, &tx);
        seal_without(&mut net, &hub);
    }
    let peer = vals.iter().find(|v| **v != hub.as_str()).unwrap().to_string();
    let peer_tip = net.nodes[&peer].tip_height;
    let peer_hash = net.nodes[&peer].tip_hash.clone();
    assert_eq!(peer_tip, h0 + 6);
    assert_ne!(net.nodes[&peer].ledgers_from(h0 + 1, 1)[0].ledger_hash, own.ledger_hash);

    // Node layer: hub's --hubs are itself + one peer that is *behind*;
    // the old hub-only selection had no candidate at all.
    let lagging_hub_peer = vals.iter().find(|v| **v != hub.as_str() && **v != peer.as_str()).unwrap();
    {
        let n = net.nodes.get_mut(&hub).unwrap();
        set_tip(n, &hub.clone(), h0);
        set_tip(n, lagging_hub_peer, h0);
        set_tip(n, &peer, peer_tip);
        n.note_peer_tip(peer_tip, &peer_hash);
        let peers = vec![(0, hub.clone()), (1, lagging_hub_peer.to_string()), (2, peer.clone())];
        let plan = n.catchup_candidates(&peers, &[0, 1]);
        assert_eq!(plan.order, vec![2], "pull from the healthy non-hub peer: {plan:?}");
        assert!(n.take_catchup_pull().is_some() || n.still_lagging());
    }
    // Pull from that peer.
    let batch = net.nodes[&peer].ledgers_from(h0 + 1, 64);
    let n = net.nodes.get_mut(&hub).unwrap();
    let tip = n.apply_catchup_batch(&batch).expect("hub catch-up");
    assert_eq!(tip, peer_tip);
    assert_eq!(n.tip_hash, peer_hash);
    assert!(n.pending_proposal.is_none(), "stale own pending dropped");
    assert!(!n.still_lagging());
    assert_eq!(n.commitment_root(), net.nodes[&peer].commitment_root(), "same state as peers");

    // Late copy of its own losing body (h0+1 < tip): stale gossip only.
    let n = net.nodes.get_mut(&hub).unwrap();
    n.stall = None;
    let e = n.ingest_ledger(&own).unwrap_err();
    assert!(e.contains("fork at h="), "{e}");
    assert!(n.stall.is_none(), "stale rival must not type an IngestFork stall");
    n.last_catchup_conflict = format!("ingest h={} catchup=false: {e}", own.height);
    assert!(!n.catchup_conflict_is_fork_poison(), "stale rival must not force join-snap");
    // A conflict found by catch-up itself still counts.
    n.last_catchup_conflict = format!("catch-up conflict (no auto hard-resync): h={}: bad parent fork at h={}", tip + 1, tip + 1);
    assert!(n.catchup_conflict_is_fork_poison());
}

/// v2.9.50: a lagging seat receives a live rival proposal at h (held because
/// tip+1 is still missing), then a certified catch-up batch for the canonical
/// chain through h. It must adopt the canonical block — not the held rival —
/// and must not leave an IngestFork stall behind.
#[test]
fn held_live_rival_must_not_win_over_catchup_canonical() {
    let vals = ["v1", "v2", "v3", "v4", "v5"];
    let us = users(8, 1_000_000);
    let cfg = ChainConfig { soft_ok_votes: 3, ..base_cfg() };
    let mut net = net_with(&vals, &us, cfg);
    for i in 0..3u64 {
        let tx = sign(&net, "u000", i + 1, "u001", 1, TxBody::Pay);
        submit_all(&mut net, &tx);
        net.seal_next_height().unwrap();
    }
    let lag = "v1";
    let h0 = net.nodes[lag].tip_height;
    assert_eq!(h0, 3);

    // Peers seal h0+1 without the lagging seat.
    {
        let tx = sign(&net, "u002", 1, "u003", 1, TxBody::Pay);
        submit_all(&mut net, &tx);
        seal_without(&mut net, lag);
    }
    let peer = "v2";
    assert_eq!(net.nodes[peer].tip_height, h0 + 1);
    let parent_hash = net.nodes[peer].tip_hash.clone();

    // Pack a rival at h0+2 on a peer (same parent) but do not commit it.
    let rival = {
        let rtx = sign(&net, "u006", 1, "u007", 7, TxBody::Pay);
        let peer_now = net.nodes[peer].now_ms;
        let n = net.nodes.get_mut("v3").unwrap();
        let _ = n.submit_tx(rtx);
        // Align clock / pongs with the open height.
        n.now_ms = peer_now;
        for id in &vals {
            n.pong(id);
        }
        let w = n.lottery_packer().expect("lottery");
        if w == lag {
            // Skip the lagging seat so a peer can pack the rival body.
            n.apply_shared_skip(h0 + 2, &w, &parent_hash);
        }
        let w = n.lottery_packer().expect("lottery after skip");
        match n.pack_as(&w) {
            Ok(led) => led,
            Err(_) => n.pack_as_admin_force("v3").expect("rival admin pack"),
        }
    };
    assert_eq!(rival.height, h0 + 2);
    assert_eq!(rival.parent_hash, parent_hash);

    // Drop rival txs from peer mempools and seal a *different* canonical h0+2.
    for n in net.nodes.values_mut() {
        let ids: Vec<String> = n.mempool.export_batch(512).into_iter().map(|t| t.tx_id).collect();
        n.mempool.remove_many(&ids);
        n.pending_proposal = None;
    }
    {
        let tx = sign(&net, "u004", 1, "u005", 1, TxBody::Pay);
        submit_all(&mut net, &tx);
        seal_without(&mut net, lag);
    }
    assert_eq!(net.nodes[peer].tip_height, h0 + 2);
    let canon_tip_hash = net.nodes[peer].tip_hash.clone();
    let canon_h = net.nodes[peer].tip_height;
    assert_ne!(
        canon_tip_hash, rival.ledger_hash,
        "canonical h0+2 must differ from the held rival"
    );
    let batch = net.nodes[peer].ledgers_from(h0 + 1, 64);
    assert_eq!(batch.len(), 2);
    assert_eq!(batch[1].ledger_hash, canon_tip_hash);

    // Live gossip of the rival while v1 is still two behind → held, not committed.
    {
        let n = net.nodes.get_mut(lag).unwrap();
        assert_eq!(n.tip_height, h0);
        let r = n.ingest_ledger(&rival).expect("hold future");
        assert!(r.is_none(), "future body must buffer, not commit");
        let held = n.pending_ledgers.get(&(h0 + 2)).expect("held at h0+2");
        assert_eq!(held.ledger_hash, rival.ledger_hash);
        n.stall = Some(ConsensusStall::IngestFork { height: h0 + 2 });
    }

    // Certified catch-up through the canonical chain.
    {
        let n = net.nodes.get_mut(lag).unwrap();
        let tip = n.apply_catchup_batch(&batch).expect("catch-up");
        assert_eq!(tip, canon_h);
        assert_eq!(n.tip_hash, canon_tip_hash, "must land on canonical tip");
        assert_ne!(n.tip_hash, rival.ledger_hash, "held rival must not win");
        assert!(
            n.pending_ledgers.get(&(h0 + 2)).is_none(),
            "held rival must be dropped once canonical commits"
        );
        assert!(
            n.stall.is_none(),
            "successful catch-up commit clears open-height stall"
        );
        assert_eq!(n.commitment_root(), net.nodes[peer].commitment_root());
    }
}

/// v2.9.50: after a successful snapshot adopt onto the canonical tip, any
/// leftover IngestFork / DualProposal stall from the abandoned rival is gone.
#[test]
fn snapshot_adopt_clears_leftover_fork_stall() {
    let vals = ["v1", "v2", "v3"];
    let us = users(4, 1_000_000);
    let cfg = ChainConfig { soft_ok_votes: 2, ..base_cfg() };
    let mut net = net_with(&vals, &us, cfg);
    for i in 0..3u64 {
        let tx = sign(&net, "u000", i + 1, "u001", 1, TxBody::Pay);
        submit_all(&mut net, &tx);
        net.seal_next_height().unwrap();
    }
    let src = net.nodes["v1"].to_snapshot();
    let tmp = std::env::temp_dir().join("pl-adopt-stall-clear.json");
    std::fs::write(&tmp, serde_json::to_vec(&src).unwrap()).unwrap();
    let keys = KeyRing::new(CryptoScheme::HmacDev);
    let loaded = Node::load_snapshot(&tmp, keys).unwrap();
    let tip = loaded.tip_height;
    let hash = loaded.tip_hash.clone();

    let joiner = net.nodes.get_mut("v3").unwrap();
    joiner.stall = Some(ConsensusStall::IngestFork { height: tip });
    joiner.last_catchup_conflict = format!("fork at h={tip}");
    joiner.adopt_peer_snapshot(loaded);
    assert_eq!(joiner.tip_height, tip);
    assert_eq!(joiner.tip_hash, hash);
    assert!(
        joiner.stall.is_none(),
        "snap adopt must clear leftover fork/stall flags"
    );
    assert!(joiner.last_catchup_conflict.is_empty());
    let _ = std::fs::remove_file(&tmp);
}

// ---------------------------------------------------------------------------
// v2.9.58 lean node: cached commitment root == fresh root everywhere.
// (Test builds also cross-check *every* `commitment_root` call internally.)
// ---------------------------------------------------------------------------

fn exec_hdr(i: u64) -> crate::eth_exec::EthExecHeader {
    crate::eth_exec::EthExecHeader {
        number: i,
        hash: format!("{:064x}", i + 1),
        parent_hash: format!("{:064x}", i),
        receipts_root: "00".repeat(32),
        rlp_hex: "f9".repeat(300),
        timestamp: 0,
    }
}

/// Grow the exec header map on every seat identically (as an applied
/// `EthExecHeaders` tx would), so roots still agree across the mesh.
fn grow_exec_headers(net: &mut Network, from: u64, n: u64) {
    for node in net.nodes.values_mut() {
        let m = node.bridge.eth_exec_headers.make_mut();
        for i in from..from + n {
            m.insert(i, exec_hdr(i));
        }
    }
}

fn assert_roots_fresh(net: &Network, ctx: &str) {
    for (id, n) in &net.nodes {
        let fresh = n.commitment_root_fresh();
        assert_eq!(n.commitment_root(), fresh, "{ctx}: {id} cached root");
        // Brief status (commit cache) and full status (computed outside the
        // lock in the node) both report the fresh root.
        let brief = n.status_json_brief();
        assert_eq!(brief["state_root"].as_str(), Some(fresh.as_str()), "{ctx}: {id} brief");
        let full = n.status_json_slim();
        assert_eq!(full["state_root"].as_str(), Some(fresh.as_str()), "{ctx}: {id} full");
        assert_eq!(brief["lc"]["claim_root"], full["lc"]["claim_root"], "{ctx}: {id} claim root");
        assert_eq!(brief["tip_height"], full["tip_height"]);
        let ser = serde_json::to_vec(&n.to_snapshot()).unwrap();
        let split = crate::exec_map::to_vec_split(&n.to_snapshot()).unwrap();
        assert!(ser == split, "{ctx}: {id} snapshot bytes");
    }
}

#[test]
fn v2958_cached_root_matches_fresh_over_many_blocks_reorg_and_catchup() {
    let before = crate::ROOT_CROSSCHECKS.load(std::sync::atomic::Ordering::Relaxed);
    let vals = ["v1", "v2", "v3", "v4", "v5"];
    let us = users(6, 1_000_000);
    let cfg = ChainConfig { soft_ok_votes: 3, ..base_cfg() };
    let mut net = net_with(&vals, &us, cfg);
    grow_exec_headers(&mut net, 0, 40);
    // 1) Many live blocks; the exec map changes every 4th height (first 12).
    //    A snapshot of v5 is taken at h=12 to replay later by catch-up.
    let dir = std::env::temp_dir().join(format!("fpl-2958-root-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let snap_path = dir.join("v5-h12.json");
    let mut snap_root = String::new();
    for i in 0..24u64 {
        if i < 12 && i % 4 == 1 {
            grow_exec_headers(&mut net, 40 + i * 3, 3);
        }
        let tx = sign(&net, "u000", i + 1, "u001", 1, TxBody::Pay);
        submit_all(&mut net, &tx);
        net.seal_next_height().unwrap();
        assert_roots_fresh(&net, &format!("live h={}", net.tip_height()));
        if i == 11 {
            net.nodes["v5"].save_snapshot(&snap_path).unwrap();
            snap_root = net.nodes["v5"].commitment_root_fresh();
        }
    }
    // 1b) Catch-up: v5 misses 10 heights, then pulls them in one batch.
    let before_lag = net.tip_height();
    for k in 0..10u64 {
        let tx = sign(&net, "u005", k + 1, "u000", 1, TxBody::Pay);
        submit_all(&mut net, &tx);
        seal_without(&mut net, "v5");
    }
    {
        let batch = net.nodes["v1"].ledgers_from(before_lag + 1, 64);
        assert_eq!(batch.len(), 10);
        let want_hash = net.nodes["v1"].tip_hash.clone();
        let want_root = net.nodes["v1"].commitment_root_fresh();
        let lag = net.nodes.get_mut("v5").unwrap();
        assert_eq!(lag.tip_height, before_lag);
        lag.apply_catchup_batch(&batch).expect("catch-up 10 heights");
        assert_eq!(lag.tip_hash, want_hash);
        assert_eq!(lag.commitment_root(), want_root);
    }
    assert_roots_fresh(&net, "after catch-up");
    // The h=12 snapshot (written via the split encoder) loads with a fresh
    // exec map / JSON cache and its cached root equals its fresh root.
    {
        let keys = net.nodes["v5"].keys.clone();
        let lag = Node::load_snapshot(&snap_path, keys).unwrap();
        assert_eq!(lag.tip_height, 12);
        assert_eq!(lag.commitment_root(), lag.commitment_root_fresh());
        assert_eq!(lag.bridge.eth_exec_headers.len(), net.nodes["v5"].bridge.eth_exec_headers.len());
        assert!(!snap_root.is_empty());
    }
    let _ = std::fs::remove_dir_all(&dir);
    // Exec map changes right before the fork (new generation on every seat).
    grow_exec_headers(&mut net, 500, 2);
    let h0 = net.tip_height();
    // 2) Fork: the hub stages its own h0+1 the mesh never sees, mesh moves on.
    let hub = net.nodes["v1"].lottery_packer().unwrap();
    let tx = sign(&net, "u001", 1, "u002", 1, TxBody::Pay);
    submit_all(&mut net, &tx);
    let own = {
        let n = net.nodes.get_mut(&hub).unwrap();
        let led = n.pack_as(&hub).unwrap();
        n.accept_ledger(&led).unwrap();
        led
    };
    for k in 0..5u64 {
        let tx = sign(&net, "u003", k + 1, "u004", 1, TxBody::Pay);
        submit_all(&mut net, &tx);
        seal_without(&mut net, &hub);
    }
    // 3) Hub reorgs onto the canonical chain by catch-up.
    let peer = vals.iter().find(|v| **v != hub.as_str()).unwrap().to_string();
    let batch = net.nodes[&peer].ledgers_from(h0 + 1, 64);
    let peer_tip_hash = net.nodes[&peer].tip_hash.clone();
    {
        let n = net.nodes.get_mut(&hub).unwrap();
        n.apply_catchup_batch(&batch).expect("hub catch-up");
        assert_ne!(n.tip_hash, own.ledger_hash);
        assert_eq!(n.tip_hash, peer_tip_hash);
    }
    assert_roots_fresh(&net, "after reorg");
    let after = crate::ROOT_CROSSCHECKS.load(std::sync::atomic::Ordering::Relaxed);
    assert!(after > before + 100, "cross-checked {} roots", after - before);
    let (_full_hashes, hits) = crate::exec_map::root_stats();
    assert!(hits > 0, "verify → commit → status reuse the root");
}

#[test]
fn v2958_brief_status_serves_commit_cache_without_recomputing() {
    let vals = ["v1", "v2", "v3"];
    let us = users(3, 1_000_000);
    let mut net = net_with(&vals, &us, base_cfg());
    grow_exec_headers(&mut net, 0, 10);
    let tx = sign(&net, "u000", 1, "u001", 1, TxBody::Pay);
    submit_all(&mut net, &tx);
    net.seal_next_height().unwrap();
    let n = net.nodes.get_mut("v1").unwrap();
    let (h, hash, root, claim) = n.tip_roots.clone().expect("set at commit");
    assert_eq!((h, hash.clone()), (n.tip_height, n.tip_hash.clone()));
    assert_eq!(root, n.commitment_root_fresh());
    assert_eq!(claim, hex::encode(crate::lc::evm_header_claim_root(&n.bridge)));
    // Brief reads the cache (a sentinel proves nothing was recomputed) ...
    n.tip_roots = Some((h, hash.clone(), "sentinel-root".into(), "sentinel-claim".into()));
    let b = n.status_json_brief();
    assert_eq!(b["state_root"], "sentinel-root");
    assert_eq!(b["lc"]["claim_root"], "sentinel-claim");
    assert_eq!(b["lc"]["claim_leaves"], serde_json::json!([]));
    assert_eq!(b["falcon_qc"]["attestations"], serde_json::json!([]));
    // ... full status always computes (outside the lock in the node).
    assert_eq!(n.status_json_slim()["state_root"].as_str(), Some(root.as_str()));
    // Cache for another tip is ignored → computed.
    n.tip_roots = Some((h, "00".repeat(32), "stale".into(), "stale".into()));
    assert_eq!(n.status_json_brief()["state_root"].as_str(), Some(root.as_str()));
    n.tip_roots = None;
    assert_eq!(n.status_json_brief()["state_root"].as_str(), Some(root.as_str()));
    // The wire handler's variant stores the computed roots (snapshot load /
    // adoption leave the cache empty or stale until the next commit).
    assert!(n.tip_roots.is_none());
    assert_eq!(n.status_json_brief_cached()["state_root"].as_str(), Some(root.as_str()));
    assert_eq!(n.tip_roots.clone().map(|t| (t.0, t.1, t.2, t.3)), Some((h, hash.clone(), root.clone(), claim.clone())));
    n.tip_roots = Some((h, "00".repeat(32), "stale".into(), "stale".into()));
    assert_eq!(n.status_json_brief_cached()["state_root"].as_str(), Some(root.as_str()));
    assert_eq!(n.tip_roots.as_ref().map(|t| t.2.clone()), Some(root.clone()));
    // Join snapshot derived from one capture is byte-identical to the old path.
    assert_eq!(
        serde_json::to_vec(&n.to_join_snapshot()).unwrap(),
        serde_json::to_vec(&Node::trim_to_join(n.to_snapshot())).unwrap()
    );
    // Brief keeps every field of the full status (same key set).
    let full = n.status_json_slim();
    let bk: BTreeSet<_> = n.status_json_brief().as_object().unwrap().keys().cloned().collect();
    let fk: BTreeSet<_> = full.as_object().unwrap().keys().cloned().collect();
    assert_eq!(bk, fk);
}

// ---------------------------------------------------------------------------
// v2.9.59: stage root computed outside node.lock
// ---------------------------------------------------------------------------

#[test]
fn v2959_prestage_warms_the_stage_root_and_changes_nothing_else() {
    let us = users(6, 1_000_000);
    let mut net = net_with(&["v1", "v2", "v3", "v4"], &us, base_cfg());
    // A real-looking exec map so the root takes the spliced/memo path.
    grow_exec_headers(&mut net, 0, 64);
    let tx = sign(&net, "u000", 1, "u001", 1, TxBody::Pay);
    submit_all(&mut net, &tx);
    let tx = sign(&net, "u002", 1, "u003", 2, TxBody::Pay);
    submit_all(&mut net, &tx);
    let w = net.nodes["v1"].lottery_packer().unwrap();
    let led = net.nodes.get_mut(&w).unwrap().pack_or_skip(&w).unwrap().unwrap();
    let recv = ["v1", "v2", "v3", "v4"].iter().find(|id| **id != w).unwrap().to_string();
    let n = net.nodes.get_mut(&recv).unwrap();
    // Wrong height / parent: skip.
    let mut bad = led.clone();
    bad.height += 1;
    assert!(matches!(n.prestage_root_input(&bad), Prestage::Skip));
    let mut bad = led.clone();
    bad.parent_hash = "00".repeat(32);
    assert!(matches!(n.prestage_root_input(&bad), Prestage::Skip));
    // Pre-root gate: schedule for the open height not frozen → no prestage.
    let sched = n.schedule_height;
    n.schedule_height = 0;
    assert!(matches!(n.prestage_root_input(&led), Prestage::Skip));
    n.schedule_height = sched;
    let before = (n.tip_height, n.tip_hash.clone(), n.now_ms, n.commitment_root_fresh());
    let job = match n.prestage_root_input(&led) {
        Prestage::Run(j) => j,
        _ => panic!("expected a prestage job"),
    };
    // Building the job did not touch the node.
    assert_eq!((n.tip_height, n.tip_hash.clone(), n.now_ms, n.commitment_root_fresh()), before);
    assert!(PrestageJob::in_flight(&led.ledger_hash));
    // A re-delivery while in flight waits instead of hashing again.
    assert!(matches!(n.prestage_root_input(&led), Prestage::Wait(_)));
    // A→B→A: another proposal replaced `prestaged_hash`; A is still in
    // flight, so A must wait on the running job, never start a second one.
    let keep = std::mem::replace(&mut n.prestaged_hash, "b".repeat(64));
    assert!(matches!(n.prestage_root_input(&led), Prestage::Wait(_)));
    n.prestaged_hash = keep;
    // Off-lock part (another thread in the node binary).
    let root = std::thread::spawn(move || job.run()).join().unwrap();
    assert!(!PrestageJob::in_flight(&led.ledger_hash));
    PrestageJob::wait(&led.ledger_hash, 10);
    assert_eq!(root, led.state_root_after, "off-lock root == packer's root");
    // The stage under the lock hits the memo: no full map hash on this thread.
    let full0 = crate::exec_map::thread_full_hashes();
    n.accept_ledger(&led).expect("stage");
    assert_eq!(crate::exec_map::thread_full_hashes(), full0, "stage reused the off-lock root");
    assert_eq!(
        n.pending_proposal.as_ref().map(|p| p.ledger_hash.clone()),
        Some(led.ledger_hash.clone())
    );
    assert_eq!(n.prestage_count, 1);
    // Already staged: nothing to warm.
    assert!(matches!(n.prestage_root_input(&led), Prestage::Skip));
    // Without the warm-up the stage hashes once, exactly as before.
    let other = ["v1", "v2", "v3", "v4"]
        .iter()
        .find(|id| **id != w && **id != recv.as_str())
        .unwrap()
        .to_string();
    let n2 = net.nodes.get_mut(&other).unwrap();
    let f0 = crate::exec_map::thread_full_hashes();
    n2.accept_ledger(&led).expect("stage without prestage");
    assert_eq!(crate::exec_map::thread_full_hashes(), f0 + 1);
    // A forged root fails the packer signature → never hashed off-lock, and
    // the stage still rejects it.
    let mut forged = led.clone();
    forged.state_root_after = "11".repeat(32);
    let last = ["v1", "v2", "v3", "v4"]
        .iter()
        .find(|id| **id != w && **id != recv.as_str() && **id != other.as_str())
        .unwrap()
        .to_string();
    let n3 = net.nodes.get_mut(&last).unwrap();
    assert!(matches!(n3.prestage_root_input(&forged), Prestage::Skip));
    assert!(n3.accept_ledger(&forged).is_err());
    assert_eq!(n3.prestage_count, 0);
    // Commit everywhere; roots still agree with a fresh encode.
    let ids: Vec<String> = net.nodes.keys().cloned().collect();
    for (id, node) in net.nodes.iter_mut() {
        if id == &w || id == &recv || id == &other {
            continue;
        }
        node.accept_ledger(&led).unwrap();
    }
    for node in net.nodes.values_mut() {
        for id in &ids {
            node.vote_ok(&led.ledger_hash, id);
        }
    }
    assert_roots_fresh(&net, "after prestaged commit");
}
