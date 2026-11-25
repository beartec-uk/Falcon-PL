//! 2.11.17 lagging-leader fast view-change. Liveness timing only: the vote is
//! the same signed ViewChange, the quorum and lottery are unchanged.

use super::*;

const G: u64 = 400;

fn users() -> Vec<(String, u64)> {
    vec![("alice".into(), 1_000_000), ("bob".into(), 1_000_000), ("carol".into(), 1_000_000)]
}

const IDS: [&str; 6] = ["v1", "v2", "v3", "v4", "v5", "v6"];

/// Six seats, rounds from height 1, three heights committed, a pending tx on
/// every seat (pack work), every seat in the same round with `leader` proposing,
/// and every round clock opened at the same instant.
fn net_with_leader(leader: &str, knob: u64) -> Network {
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
    let mut net = Network::bootstrap(&IDS, 1000, &users(), cfg);
    net.pong_all();
    for _ in 0..3 {
        net.payment("alice", "bob", 1, 1).unwrap();
        net.seal_next_height().unwrap();
    }
    assert_eq!(net.tip_height(), 3);
    net.payment("alice", "carol", 1, 1).unwrap();
    let order = net.nodes[leader].lottery_order();
    let idx = order.iter().position(|s| s == leader).unwrap() as u64;
    for n in net.nodes.values_mut() {
        n.cfg.pack_budget_ms = 400;
        n.lagging_leader_vc_ms = knob;
        n.best_peer_tip = n.tip_height;
        n.freeze_open_height_schedule();
        n.height_view_round = idx;
        n.sync_round_skips(n.tip_height.saturating_add(1));
        n.height_open_ms = n.now_ms;
        n.round_open_ms = n.now_ms;
        n.work_seen_since_ms = 0;
    }
    net
}

/// The leader's tip ad lands on `seat` now.
fn ad(net: &mut Network, seat: &str, leader: &str, tip: u64) {
    net.nodes.get_mut(seat).unwrap().pong_with_role(leader, tip, 0, false, false, 0);
}

fn tip(net: &Network) -> u64 {
    net.tip_height()
}

#[test]
fn fast_vc_fires_after_grace_when_leader_two_behind() {
    let mut net = net_with_leader("v1", G);
    let t = tip(&net);
    net.nodes.get_mut("v2").unwrap().tick(10);
    ad(&mut net, "v2", "v1", t - 2);
    let v = net.nodes.get_mut("v2").unwrap();
    let h = v.tip_height + 1;
    assert!(v.lagging_leader_fast_vc(h) == false, "inside the grace");
    v.tick(G - 20);
    assert!(v.maybe_view_change_vote().is_none(), "no vote before the grace");
    v.tick(20);
    assert!(v.lagging_leader_fast_vc(h));
    let r = v.height_view_round;
    let vote = v.maybe_view_change_vote().expect("fast vote after grace");
    assert_eq!(vote.0, h);
    assert_eq!(vote.2, r + 1, "same target round as the legacy path");
    assert!(v.last_vc_fast);
    assert_eq!(v.fast_vc_votes, 1);
    let silence = v.round_silence_timeout_ms(r);
    assert!(G < silence, "fires before the silence timeout ({silence} ms)");
    // No second signature for the same (height, round) inside the re-vote interval.
    v.tick(200);
    assert!(v.maybe_view_change_vote().is_none(), "no double vote");
    let mine = v.view_change_votes[&h][&(r + 1)].iter().filter(|s| *s == "v2").count();
    assert_eq!(mine, 1);
}

#[test]
fn knob_off_keeps_legacy_timing() {
    let mut net = net_with_leader("v1", 0);
    let t = tip(&net);
    net.nodes.get_mut("v2").unwrap().tick(10);
    ad(&mut net, "v2", "v1", t - 2);
    let v = net.nodes.get_mut("v2").unwrap();
    let h = v.tip_height + 1;
    v.tick(G + 10);
    assert!(!v.lagging_leader_fast_vc(h));
    assert!(v.maybe_view_change_vote().is_none(), "legacy waits");
    // Legacy: the lagging leader is 'unavailable', so progress_timeout applies.
    let r = v.height_view_round;
    let legacy = v.round_silence_timeout_ms(r);
    v.tick(legacy);
    let vote = v.maybe_view_change_vote().expect("legacy timeout still fires");
    assert_eq!(vote.2, r + 1);
    assert!(!v.last_vc_fast);
    assert_eq!(v.fast_vc_votes, 0);
}

#[test]
fn healthy_leader_never_fast_votes() {
    let mut net = net_with_leader("v1", G);
    let t = tip(&net);
    let silence = net.nodes["v2"].round_silence_timeout_ms(net.nodes["v2"].height_view_round);
    let mut elapsed = 0;
    while elapsed + 200 < silence {
        net.nodes.get_mut("v2").unwrap().tick(200);
        elapsed += 200;
        ad(&mut net, "v2", "v1", t); // at our tip every pong
        let v = net.nodes.get_mut("v2").unwrap();
        assert!(!v.lagging_leader_fast_vc(v.tip_height + 1));
        assert!(v.maybe_view_change_vote().is_none(), "no VC at {elapsed} ms for a healthy leader");
    }
    assert_eq!(net.nodes["v2"].fast_vc_votes, 0);
}

#[test]
fn one_behind_needs_a_late_ad_and_three_graces() {
    let mut net = net_with_leader("v1", G);
    let t = tip(&net);
    // An early lag-1 ad is an in-flight commit, not evidence.
    net.nodes.get_mut("v2").unwrap().tick(50);
    ad(&mut net, "v2", "v1", t - 1);
    net.nodes.get_mut("v2").unwrap().tick(3 * G);
    {
        let v = &net.nodes["v2"];
        assert!(!v.lagging_leader_fast_vc(v.tip_height + 1), "early lag-1 ad");
    }
    // Still one behind well into the round: vote at 3x grace.
    ad(&mut net, "v2", "v1", t - 1);
    let v = net.nodes.get_mut("v2").unwrap();
    assert!(v.lagging_leader_fast_vc(v.tip_height + 1));
    // A newer ad at our tip clears it.
    let _ = v;
    ad(&mut net, "v2", "v1", t);
    let v = &net.nodes["v2"];
    assert!(!v.lagging_leader_fast_vc(v.tip_height + 1), "caught up");
}

#[test]
fn ad_from_before_the_round_is_not_evidence() {
    let mut net = net_with_leader("v1", 0);
    let t = tip(&net);
    ad(&mut net, "v2", "v1", t - 2);
    let v = net.nodes.get_mut("v2").unwrap();
    v.tick(5);
    v.height_open_ms = v.now_ms;
    v.round_open_ms = v.now_ms;
    v.lagging_leader_vc_ms = G;
    v.tick(G + 10);
    assert!(!v.lagging_leader_fast_vc(v.tip_height + 1));
    assert!(v.maybe_view_change_vote().is_none());
}

#[test]
fn no_fast_vote_when_self_lagging_or_body_in_hand_or_self_is_leader() {
    // Self lagging.
    let mut net = net_with_leader("v1", G);
    let t = tip(&net);
    net.nodes.get_mut("v2").unwrap().tick(10);
    ad(&mut net, "v2", "v1", t - 2);
    {
        let v = net.nodes.get_mut("v2").unwrap();
        v.tick(G + 10);
        v.best_peer_tip = v.tip_height + 1;
        assert!(!v.lagging_leader_fast_vc(v.tip_height + 1));
        assert!(v.maybe_view_change_vote().is_none());
    }
    // Body in hand.
    let mut net = net_with_leader("v1", G);
    let led = net.nodes.get_mut("v1").unwrap().pack_as("v1").expect("leader packs");
    net.nodes.get_mut("v2").unwrap().tick(10);
    ad(&mut net, "v2", "v1", t - 2);
    {
        let v = net.nodes.get_mut("v2").unwrap();
        v.pending_proposal = Some(led);
        v.tick(G + 10);
        assert!(!v.lagging_leader_fast_vc(v.tip_height + 1), "proposal in flight");
    }
    // The leader itself never fast-votes against itself.
    let mut net = net_with_leader("v1", G);
    let tip_v1 = net.nodes["v1"].tip_height;
    net.nodes.get_mut("v1").unwrap().tick(10);
    ad(&mut net, "v1", "v1", tip_v1 - 2);
    let v = net.nodes.get_mut("v1").unwrap();
    v.tick(G + 10);
    assert!(!v.lagging_leader_fast_vc(v.tip_height + 1));
}

/// Count how many committee votes it takes to reach the ViewChange QC on one
/// receiving seat, with the leader lagging, given the knob.
fn votes_to_qc(knob: u64) -> (usize, u64) {
    let mut net = net_with_leader("v1", knob);
    let t = tip(&net);
    let voters: Vec<&str> = IDS.iter().copied().filter(|s| *s != "v1").collect();
    for s in &voters {
        net.nodes.get_mut(*s).unwrap().tick(10);
        ad(&mut net, s, "v1", t - 2);
        // Seed the legacy work clock (`work_seen_since_ms`) like the seal loop does.
        assert!(net.nodes.get_mut(*s).unwrap().maybe_view_change_vote().is_none());
    }
    let wait = if knob > 0 {
        knob + 10
    } else {
        let n = &net.nodes["v2"];
        n.round_silence_timeout_ms(n.height_view_round) + 10
    };
    let mut cast = Vec::new();
    for s in &voters {
        let n = net.nodes.get_mut(*s).unwrap();
        n.tick(wait);
        let h0 = n.tip_height + 1;
        let diag = format!(
            "seat={s} knob={knob} fast={} cert={} committee={} lagging={} work={} r={} proposer={:?}",
            n.lagging_leader_fast_vc(h0),
            n.certs.contains_key(&n.tip_height),
            n.in_committee(s),
            n.still_lagging(),
            n.network_has_pack_work(),
            n.height_view_round,
            n.round_proposer(n.height_view_round)
        );
        let (h, tip, round) = n.maybe_view_change_vote().unwrap_or_else(|| panic!("follower did not vote: {diag}"));
        let sig = n.sign_vc_vote(h, &tip, round);
        cast.push((s.to_string(), h, tip, round, sig));
    }
    let recv = "v6";
    let mut count = 1; // its own vote is already in
    let r0 = net.nodes[recv].height_view_round;
    for (voter, h, tip, round, sig) in cast.iter().filter(|c| c.0 != recv) {
        let n = net.nodes.get_mut(recv).unwrap();
        let (qc, new) = n.vote_view_change_ex(*h, tip, *round, voter, sig);
        assert!(new, "a new signed vote");
        count += 1;
        if qc || n.height_view_round > r0 {
            return (count, n.height_view_round - r0);
        }
    }
    panic!("no QC with all five followers");
}

#[test]
fn quorum_is_unchanged_by_the_fast_path() {
    let (fast, adv_fast) = votes_to_qc(G);
    let (legacy, adv_legacy) = votes_to_qc(0);
    assert_eq!(fast, legacy, "same number of votes forms the QC");
    assert!(fast >= 4, "4-of-6 committee quorum");
    assert_eq!(adv_fast, adv_legacy);
    assert_eq!(adv_fast, 1, "advances exactly one round");
}

#[test]
fn forged_or_unsigned_votes_still_rejected() {
    let mut net = net_with_leader("v1", G);
    for n in net.nodes.values_mut() {
        n.cfg.require_vote_sigs = true;
    }
    let t = tip(&net);
    net.nodes.get_mut("v2").unwrap().tick(10);
    ad(&mut net, "v2", "v1", t - 2);
    let v = net.nodes.get_mut("v2").unwrap();
    v.tick(G + 10);
    let (h, tip_hash, round) = v.maybe_view_change_vote().unwrap();
    // A vote claiming to be v3 but signed by v2 does not count.
    let bad = v.sign_vc_vote(h, &tip_hash, round);
    let n = net.nodes.get_mut("v4").unwrap();
    let (_, new) = n.vote_view_change_ex(h, &tip_hash, round, "v3", &bad);
    assert!(!new, "signature must match the voter");
    let (_, new) = n.vote_view_change_ex(h, &tip_hash, round, "v2", &bad);
    assert!(new, "the genuine fast vote verifies like any ViewChange");
    let (_, again) = n.vote_view_change_ex(h, &tip_hash, round, "v2", &bad);
    assert!(!again, "a repeat of the same vote is not counted twice");
}

/// Simulated time from round open to the ViewChange QC with a lagging leader,
/// seat timings as deployed (pack budget 5000, progress timeout 4000, 200 ms
/// seal tick). Deterministic, simulated clock (not wall time).
/// `cargo test -p fd-pl --release --lib lagging_leader_bench -- --ignored --nocapture`
#[test]
#[ignore]
fn lagging_leader_bench() {
    for knob in [0u64, 200, 400, 800] {
        let mut net = net_with_leader("v1", knob);
        for n in net.nodes.values_mut() {
            n.cfg.pack_budget_ms = 5_000;
            n.cfg.progress_timeout_ms = 4_000;
        }
        let t = tip(&net);
        let voters: Vec<String> = IDS.iter().filter(|s| **s != "v1").map(|s| s.to_string()).collect();
        let mut voted: std::collections::BTreeMap<String, u64> = Default::default();
        let mut qc_at = None;
        let mut ms = 0u64;
        while ms <= 20_000 && qc_at.is_none() {
            ms += 200;
            let mut cast = Vec::new();
            for s in &voters {
                let n = net.nodes.get_mut(s).unwrap();
                n.tick(200);
                n.pong_with_role("v1", t - 2, 0, false, false, 0);
                if let Some((h, tip_h, r)) = n.maybe_view_change_vote() {
                    voted.entry(s.clone()).or_insert(ms);
                    let sig = n.sign_vc_vote(h, &tip_h, r);
                    cast.push((s.clone(), h, tip_h, r, sig));
                }
            }
            let recv = net.nodes.get_mut("v6").unwrap();
            let r0 = 0;
            let _ = r0;
            for (v, h, tip_h, r, sig) in cast {
                if v == "v6" { continue; }
                let (qc, _) = recv.vote_view_change_ex(h, &tip_h, r, &v, &sig);
                if qc && qc_at.is_none() { qc_at = Some(ms); }
            }
        }
        let first = voted.values().min().copied().unwrap_or(0);
        println!("BENCH knob={knob} first_vote_ms={first} qc_ms={:?} voters={}", qc_at, voted.len());
    }
}
