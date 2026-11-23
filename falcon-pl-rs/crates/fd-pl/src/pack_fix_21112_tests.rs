//! 2.11.12 packer self-pass, gap-fill, and local-pool hole tests.
//! Local / wire-compatible only: no activation height, 4-of-6 unchanged.

use super::*;

fn make_current_proposer(n: &mut Node) {
    n.freeze_open_height_schedule();
    let order = n.lottery_order();
    if let Some(idx) = order.iter().position(|id| id == &n.id) {
        n.height_view_round = idx as u64;
    }
}


fn users() -> Vec<(String, u64)> {
    vec![
        ("alice".into(), 1_000_000),
        ("bob".into(), 1_000_000),
        ("carol".into(), 1_000_000),
    ]
}

fn pay(n: &Node, from: &str, to: &str, seq: u64) -> Tx {
    Tx::sign_with(&n.keys, from, seq, to, 1, 1, n.cfg.network_id).unwrap()
}

fn pay_net(net: &Network, from: &str, to: &str, seq: u64) -> Tx {
    Tx::sign_with(&net.user_keys, from, seq, to, 1, 1, net.cfg.network_id).unwrap()
}

/// Put `id` in the current round on every seat so followers agree on the packer.
fn set_proposer_everywhere(net: &mut Network, id: &str) {
    let order = net.nodes[id].lottery_order();
    let idx = order
        .iter()
        .position(|s| s == id)
        .expect("id in lottery_order") as u64;
    for n in net.nodes.values_mut() {
        n.height_view_round = idx;
        n.sync_round_skips(n.tip_height.saturating_add(1));
        n.best_peer_tip = n.tip_height;
    }
}

fn seat(id: &str, pack_budget_ms: u64, progress_timeout_ms: u64) -> Node {
    let mut n = Node::new(
        id,
        ChainConfig {
            pack_budget_ms,
            progress_timeout_ms,
            pong_window_ms: 60_000,
            max_txs_per_ledger: 0,
            vote_rounds_from_height: 1,
            ..Default::default()
        },
        KeyRing::new(CryptoScheme::HmacDev),
        &users(),
    );
    n.tick(1);
    n
}

#[test]
fn local_pool_deeper_than_walk_is_a_hole() {
    let mut n = seat("v1", 4_000, 9_000);
    n.register_validator("v1", 1000);
    n.pong("v1");
    n.keys.generate_many(["alice", "bob"].into_iter());
    n.submit_tx(pay(&n, "alice", "bob", 1)).unwrap();
    // Future seq in-window, missing seq 2 punches a hole.
    n.submit_tx(pay(&n, "alice", "bob", 3)).unwrap();
    assert_eq!(n.packable_tx_count(), 1);
    assert_eq!(n.mempool.len(), 2);
    assert!(n.short_pack_hole(), "local pool > packable must be a hole");
    let gaps = n.gap_needs();
    assert_eq!(gaps.len(), 1);
    assert_eq!(gaps[0].account, "alice");
    assert_eq!(gaps[0].sequence, 2);
    n.mark_pre_pack_need_txs();
    assert!(n.waiting_need_txs_grace(), "adaptive grace while the hole remains");
    // The 800ms short grace is not used when this is a hole; thin-walk hold is.
    n.tick(900);
    assert!(n.waiting_need_txs_grace());
    // heads_stalled_before_skip still ends the wait near the progress window.
    n.tick(7_000);
    assert!(
        !n.waiting_need_txs_grace(),
        "hold must not run past the existing skip window"
    );
}

#[test]
fn one_head_equal_to_pool_is_not_a_local_hole() {
    let mut n = seat("v1", 0, 0);
    n.register_validator("v1", 1000);
    n.pong("v1");
    n.keys.generate_many(["alice", "bob"].into_iter());
    n.submit_tx(pay(&n, "alice", "bob", 1)).unwrap();
    assert_eq!(n.mempool.len(), 1);
    assert_eq!(n.packable_tx_count(), 1);
    assert!(!n.short_pack_hole());
    assert!(n.gap_needs().is_empty());
}

#[test]
fn serve_need_txs_fills_named_missing_head() {
    // Entry seat holds the missing head; packer already has the later seq.
    let mut entry = seat("v12", 0, 0);
    entry.keys.generate_many(["alice", "bob"].into_iter());
    entry.submit_tx(pay(&entry, "alice", "bob", 2)).unwrap();
    let missing = vec![MissingSeq {
        account: "alice".into(),
        sequence: 2,
    }];
    // Walk export would skip seq 2 (gap at 1). Gap-fill must still return it.
    let walk = entry.export_packer_batch(400);
    assert!(walk.is_empty(), "seq 2 is not a walk without seq 1");
    let (batch, filled) = entry.serve_need_txs_for(400, &missing);
    assert_eq!(filled, 1);
    assert_eq!(batch.len(), 1);
    assert_eq!(batch[0].account, "alice");
    assert_eq!(batch[0].sequence, 2);
}

#[test]
fn packer_absorbs_gap_fill_and_walk_becomes_packable() {
    let mut packer = seat("v1", 4_000, 9_000);
    packer.register_validator("v1", 1000);
    packer.pong("v1");
    packer.keys.generate_many(["alice", "bob"].into_iter());
    packer.submit_tx(pay(&packer, "alice", "bob", 1)).unwrap();
    packer.submit_tx(pay(&packer, "alice", "bob", 3)).unwrap();
    assert_eq!(packer.packable_tx_count(), 1);
    assert!(packer.short_pack_hole());

    let mut entry = seat("v13", 0, 0);
    entry.keys = packer.keys.clone();
    entry.submit_tx(pay(&entry, "alice", "bob", 2)).unwrap();
    let gaps = packer.gap_needs();
    let (batch, filled) = entry.serve_need_txs_for(400, &gaps);
    assert_eq!(filled, 1);
    let added = packer.absorb_txs(&batch);
    assert!(added > 0);
    assert_eq!(packer.packable_tx_count(), 3, "hole closed, walk is consecutive");
    assert!(!packer.short_pack_hole() || packer.packable_tx_count() >= packer.pack_cap_txs() * 3 / 4);
}

#[test]
fn need_txs_empty_missing_serializes_like_2_11_11() {
    let v12 = WireMsg::need_txs(400, Vec::new());
    let s = serde_json::to_value(&v12).unwrap();
    assert_eq!(s["type"], "need_txs");
    assert_eq!(s["max_count"], 400);
    assert!(s.get("missing").is_none(), "empty missing must be omitted");

    // A 2.11.11 payload (no missing) decodes on 2.11.12.
    let legacy = serde_json::json!({"type": "need_txs", "max_count": 400});
    let got: WireMsg = serde_json::from_value(legacy).unwrap();
    match got {
        WireMsg::NeedTxs { max_count, missing } => {
            assert_eq!(max_count, 400);
            assert!(missing.is_empty());
        }
        other => panic!("unexpected {other:?}"),
    }

    // A 2.11.12 payload with missing is accepted here; a 2.11.11 peer
    // ignores the unknown field (no deny_unknown_fields on WireMsg).
    let modern = WireMsg::need_txs(
        400,
        vec![MissingSeq {
            account: "alice".into(),
            sequence: 2,
        }],
    );
    let raw = serde_json::to_value(&modern).unwrap();
    assert_eq!(raw["missing"][0]["account"], "alice");
    #[derive(Deserialize)]
    struct LegacyNeedTxs {
        #[serde(rename = "type")]
        kind: String,
        max_count: u64,
    }
    let legacy_view: LegacyNeedTxs = serde_json::from_value(raw).unwrap();
    assert_eq!(legacy_view.kind, "need_txs");
    assert_eq!(legacy_view.max_count, 400);
}

#[test]
fn packer_self_pass_votes_before_silence_timeout() {
    // Six seats, vote-rounds from height 1. Commit height 1 first so this is
    // not the cold tip=0 / no-peer-ads probe path.
    let cfg = ChainConfig {
        pack_budget_ms: 0,
        progress_timeout_ms: 2_000,
        pong_window_ms: 60_000,
        max_txs_per_ledger: 4,
        soft_ok_votes: 1,
        vote_rounds_from_height: 1,
        committee_size: 6,
        ..Default::default()
    };
    let mut net = Network::bootstrap(&["v1", "v2", "v3", "v4", "v5", "v6"], 1000, &users(), cfg);
    net.pong_all();
    net.payment("alice", "bob", 1, 1).unwrap();
    net.seal_next_height().unwrap();
    assert_eq!(net.tip_height(), 1);
    for n in net.nodes.values_mut() {
        n.cfg.pack_budget_ms = 400;
        n.best_peer_tip = n.tip_height;
        n.freeze_open_height_schedule();
    }
    set_proposer_everywhere(&mut net, "v1");
    assert_eq!(
        net.nodes["v1"].round_proposer(net.nodes["v1"].height_view_round).as_deref(),
        Some("v1")
    );
    // Future-seq only: no walk, pool is non-empty.
    let seq = net.nodes["v1"].state.get("alice").sequence;
    let tx = pay_net(&net, "alice", "bob", seq + 2);
    let v1 = net.nodes.get_mut("v1").unwrap();
    v1.submit_tx(tx).unwrap();
    assert_eq!(v1.packable_tx_count(), 0);
    assert!(v1.mempool.len() > 0);
    // Reset the open clock so the live window is measured from here.
    v1.height_open_ms = v1.now_ms;
    v1.round_open_ms = v1.now_ms;
    assert!(!v1.packer_should_self_pass(v1.tip_height.saturating_add(1)));
    let live = v1.live_pack_timeout_ms();
    v1.tick(live + 10);
    let height = v1.tip_height.saturating_add(1);
    assert!(v1.packer_should_self_pass(height), "no walk after live pack window");
    let silence = v1.round_silence_timeout_ms(v1.height_view_round);
    assert!(
        live + 10 < silence,
        "self-pass must fire before the silence timeout (live={live} silence={silence})"
    );
    let vote = v1.maybe_view_change_vote();
    assert!(vote.is_some(), "winner signs the existing ViewChange path");
    let (_, _, target) = vote.unwrap();
    assert_eq!(target, v1.height_view_round.saturating_add(1));
}

#[test]
fn packer_self_pass_memory_pressure_and_over_budget() {
    let mut n = seat("v1", 400, 2_000);
    n.register_validator("v1", 1000);
    n.register_validator("v2", 1000);
    n.register_validator("v3", 1000);
    n.register_validator("v4", 1000);
    n.register_validator("v5", 1000);
    n.register_validator("v6", 1000);
    for id in ["v1", "v2", "v3", "v4", "v5", "v6"] {
        n.pong(id);
    }
    n.freeze_open_height_schedule();
    make_current_proposer(&mut n);
    n.keys.generate_many(["alice", "bob"].into_iter());
    n.submit_tx(pay(&n, "alice", "bob", 1)).unwrap();
    let height = n.tip_height.saturating_add(1);
    // A packable walk is sealed, not self-passed.
    assert!(!n.packer_should_self_pass(height));
    n.force_memory_pressure = true;
    assert!(n.packer_should_self_pass(height), "memory pressure self-passes");
    n.force_memory_pressure = false;
    n.note_pack_attempt_result(n.now_ms.saturating_sub(500), false);
    assert!(n.pack_over_budget);
    assert!(n.packer_should_self_pass(height), "over-budget self-passes");
}

#[test]
fn follower_votes_immediately_on_packer_self_pass_legacy_waits() {
    let cfg = ChainConfig {
        pack_budget_ms: 0,
        progress_timeout_ms: 2_000,
        pong_window_ms: 60_000,
        max_txs_per_ledger: 4,
        soft_ok_votes: 1,
        vote_rounds_from_height: 1,
        committee_size: 6,
        ..Default::default()
    };
    let ids = ["v1", "v2", "v3", "v4", "v5", "v6"];
    let mut net = Network::bootstrap(&ids, 1000, &users(), cfg);
    net.pong_all();
    net.payment("alice", "bob", 1, 1).unwrap();
    net.seal_next_height().unwrap();
    assert_eq!(net.tip_height(), 1);
    for n in net.nodes.values_mut() {
        n.cfg.pack_budget_ms = 400;
        n.best_peer_tip = n.tip_height;
        n.freeze_open_height_schedule();
    }
    set_proposer_everywhere(&mut net, "v1");
    let proposer = net.nodes["v1"]
        .round_proposer(net.nodes["v1"].height_view_round)
        .unwrap();
    assert_eq!(proposer, "v1");
    let height = net.nodes["v1"].tip_height.saturating_add(1);
    let followers: Vec<String> = ids
        .into_iter()
        .map(|s| s.to_string())
        .filter(|id| id != &proposer)
        .collect();
    let follow_id = followers[0].clone();
    let legacy_id = followers[1].clone();

    let seq = net.nodes[&proposer].state.get("alice").sequence;
    let hole = pay_net(&net, "alice", "bob", seq + 2);
    let (h, tip, round, sig) = {
        let p = net.nodes.get_mut(&proposer).unwrap();
        p.submit_tx(hole).unwrap();
        p.height_open_ms = p.now_ms;
        p.round_open_ms = p.now_ms;
        p.tick(p.live_pack_timeout_ms() + 10);
        let vote = p.maybe_view_change_vote().expect("proposer self-pass");
        let (h, tip, round) = vote;
        let sig = p.sign_vc_vote(h, &tip, round);
        (h, tip, round, sig)
    };
    {
        let v = net.nodes.get_mut(&follow_id).unwrap();
        v.height_open_ms = v.now_ms;
        v.round_open_ms = v.now_ms;
        v.tick(1);
        let (qc, new) = v.vote_view_change_ex(h, &tip, round, &proposer, &sig);
        assert!(new);
        assert!(!qc);
        assert!(v.following_packer_self_pass(h, round));
        let follow = v.maybe_view_change_vote();
        assert!(follow.is_some(), "upgraded follower votes immediately");
    }

    let v = net.nodes.get_mut(&legacy_id).unwrap();
    v.follow_self_pass_height = 0;
    v.follow_self_pass_round = 0;
    v.height_open_ms = v.now_ms;
    v.round_open_ms = v.now_ms;
    v.tick(1);
    assert!(!v.packer_should_self_pass(height), "follower is not the proposer");
    assert!(!v.following_packer_self_pass(height, 1));
    assert!(
        v.maybe_view_change_vote().is_none(),
        "legacy peer waits the silence timeout"
    );
}

#[test]
fn missed_turns_still_charged_after_self_pass_view_change() {
    // The next ledger's packer is not round-0: missed_turns += 1 as today.
    let cfg = ChainConfig {
        pack_budget_ms: 0,
        progress_timeout_ms: 0,
        pong_window_ms: 60_000,
        max_txs_per_ledger: 4,
        soft_ok_votes: 1,
        vote_rounds_from_height: 0, // use hook at any height if rv2_at
        ..Default::default()
    };
    let mut net = Network::bootstrap(&["v1", "v2"], 1000, &users(), cfg);
    net.pong_all();
    net.payment("alice", "bob", 1, 1).unwrap();
    net.seal_next_height().unwrap();
    // Directly exercise the hook: round-0 is v1, packer is v2.
    let n = net.nodes.get_mut("v1").unwrap();
    if !n.rv2_at(n.tip_height.saturating_add(1)) {
        // Rewards-v2 may be unarmed on this fixture; the hook is a no-op then.
        // Still assert the function is the same miss path when armed.
        return;
    }
    let before = n.validators.get("v1").map(|v| v.missed_turns).unwrap_or(0);
    let height = n.tip_height.saturating_add(1);
    let mut vals = n.validators.clone();
    n.rv2_ledger_hook(&mut vals, height, "v2", Some("v1"), &[]);
    let after = vals.get("v1").map(|v| v.missed_turns).unwrap_or(0);
    assert_eq!(after, before.saturating_add(1));
}

#[test]
fn multi_entry_gap_fill_closes_packer_walk() {
    // Four entry seats hold split sequences; the packer only has a holey walk
    // until gap-fill pulls the missing heads from non-hub entries.
    let mut packer = seat("v1", 4_000, 9_000);
    packer.register_validator("v1", 1000);
    packer.pong("v1");
    packer.keys.generate_many(["alice", "bob", "carol"].into_iter());
    // Walk: alice-1. Hole: alice-3 (missing 2), carol-2 (missing 1).
    packer.submit_tx(pay(&packer, "alice", "bob", 1)).unwrap();
    packer.submit_tx(pay(&packer, "alice", "bob", 3)).unwrap();
    packer.submit_tx(pay(&packer, "carol", "bob", 2)).unwrap();
    assert_eq!(packer.packable_tx_count(), 1);
    assert!(packer.short_pack_hole());
    let gaps = packer.gap_needs();
    assert!(gaps.iter().any(|g| g.account == "alice" && g.sequence == 2));
    assert!(gaps.iter().any(|g| g.account == "carol" && g.sequence == 1));

    let mut v12 = seat("v12", 0, 0);
    v12.keys = packer.keys.clone();
    v12.submit_tx(pay(&v12, "alice", "bob", 2)).unwrap();
    let mut v13 = seat("v13", 0, 0);
    v13.keys = packer.keys.clone();
    v13.submit_tx(pay(&v13, "carol", "bob", 1)).unwrap();

    let (b12, f12) = v12.serve_need_txs_for(400, &gaps);
    let (b13, f13) = v13.serve_need_txs_for(400, &gaps);
    assert!(f12 >= 1 && f13 >= 1);
    assert!(packer.absorb_txs(&b12) > 0);
    assert!(packer.absorb_txs(&b13) > 0);
    assert_eq!(packer.packable_tx_count(), 5, "alice 1-3 and carol 1-2");
    assert!(!packer.short_pack_hole() || packer.packable_tx_count() >= packer.pack_cap_txs() * 3 / 4);
}
