//! 2.11.13 (f) CONSENSUS, gated by `redraw_from_height` (2300: release-build
//! placeholder `u64::MAX`). A committee that cannot reach 4-of-6 for a full
//! rotation of view-change time is replaced by a redraw entered with a
//! bonded-set quorum (7 of 10) of seats that never signed an OK at the height.

use super::*;

const TEN: [&str; 10] = ["v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8", "v9", "v10"];

fn users() -> Vec<(String, u64)> {
    vec![("alice".into(), 1_000_000), ("bob".into(), 1_000_000)]
}

/// 10 bonded seats, committee 6, round-scoped votes and v4 headers from h=1,
/// h=1 committed, txs waiting for h=2.
fn ten_after_one() -> Network {
    let cfg = ChainConfig {
        pack_budget_ms: 0,
        progress_timeout_ms: 1_000,
        vote_rounds_from_height: 1,
        committee_size: 6,
        max_txs_per_ledger: 8,
        ..Default::default()
    };
    let mut net = Network::bootstrap(&TEN, 1000, &users(), cfg);
    let gid: Vec<String> = TEN.iter().map(|s| s.to_string()).collect();
    for n in net.nodes.values_mut() {
        n.qc_header_version = 4;
        n.qc_start_height = 1;
        n.init_seat_key_registry_from_genesis(&gid);
    }
    net.pong_all();
    net.payment("alice", "bob", 1, 1).unwrap();
    net.seal_next_height().expect("h=1");
    for _ in 0..3 {
        net.payment("alice", "bob", 1, 1).unwrap();
    }
    net.pong_all();
    for n in net.nodes.values_mut() {
        n.best_peer_tip = n.tip_height;
        n.freeze_open_height_schedule();
        n.sync_round_skips(2);
    }
    net
}

fn arm(net: &mut Network, from: u64) {
    for n in net.nodes.values_mut() {
        n.redraw_from_height = from;
    }
}

/// Run the round-timeout vote on `ids` once (sets the work clock), advance
/// their clocks past the redraw time, run it again; returns redraw voters.
fn redraw_votes(net: &mut Network, ids: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for id in ids {
        let n = net.nodes.get_mut(id).unwrap();
        let _ = n.maybe_view_change_vote();
    }
    for id in ids {
        let n = net.nodes.get_mut(id).unwrap();
        let wait = n.proposal_timeout_ms() * Node::REDRAW_AFTER_ROUNDS + 1_000;
        n.now_ms = n.now_ms.saturating_add(wait);
        if let Some((h, _, target)) = n.maybe_view_change_vote() {
            if target == Node::REDRAW_AFTER_ROUNDS {
                assert_eq!(h, 2);
                out.push(id.clone());
            }
        }
    }
    out
}

fn deliver_vc(net: &mut Network, to: &[String], voters: &[String], round: u64) {
    let tip = net.nodes["v1"].tip_hash.clone();
    for v in voters {
        for id in to {
            let n = net.nodes.get_mut(id).unwrap();
            let _ = n.vote_view_change(2, &tip, round, v);
        }
    }
}

fn split(net: &Network, n_dead: usize) -> (Vec<String>, Vec<String>) {
    let base = net.nodes["v1"].lottery_order();
    let dead: Vec<String> = base[..n_dead].to_vec();
    let live: Vec<String> = TEN.iter().map(|s| s.to_string()).filter(|s| !dead.contains(s)).collect();
    (dead, live)
}

#[test]
fn placeholder_keeps_redraw_off_on_2300() {
    // 2.11.13 release: 2300 activates redraw + bridge slim together at 945364.
    assert_eq!(crate::params_v2::TESTNET_2300_REDRAW_FROM_HEIGHT, 945_364);
    assert_eq!(crate::params_v2::redraw_from_height(2300), 945_364);
    assert_eq!(crate::params_v2::bridge_slim_from_height(2300), 945_364);
    let mut net = ten_after_one();
    let (_dead, live) = split(&net, 3);
    // Not armed (devnet default without FPL_REDRAW_FROM_HEIGHT): no redraw.
    arm(&mut net, u64::MAX);
    assert!(redraw_votes(&mut net, &live).is_empty());
    for n in net.nodes.values() {
        assert_eq!(n.lottery_order(), n.base_lottery_order());
    }
}

#[test]
fn redraw_committee_is_deterministic_and_prefers_outside_seats() {
    let net = ten_after_one();
    let a = net.nodes["v1"].redraw_committee(6);
    for n in net.nodes.values() {
        assert_eq!(n.redraw_committee(6), a, "same tip, same redraw on {}", n.id);
        assert_eq!(n.redraw_committee(11), a, "same epoch for rounds 6..11");
    }
    let base = net.nodes["v1"].base_lottery_order();
    assert_eq!(a.len(), 6);
    let outside: Vec<&String> = a.iter().filter(|id| !base.contains(id)).collect();
    assert_eq!(outside.len(), 4, "all 4 seats outside the base committee come first");
    assert!(a[..4].iter().all(|id| !base.contains(id)));
    assert_ne!(net.nodes["v1"].redraw_committee(12), a, "next epoch redraws again");
}

#[test]
fn dead_committee_recovers_through_redraw_and_catch_up_verifies() {
    let mut net = ten_after_one();
    arm(&mut net, 2);
    let (dead, live) = split(&net, 3); // round-0 proposer + 2 more: no 4-of-6 possible
    let voters = redraw_votes(&mut net, &live);
    assert_eq!(voters.len(), 7, "every live bonded seat votes the redraw");
    deliver_vc(&mut net, &live, &voters, Node::REDRAW_AFTER_ROUNDS);
    let redraw = net.nodes[&live[0]].redraw_committee(Node::REDRAW_AFTER_ROUNDS);
    for id in &live {
        let n = &net.nodes[id];
        assert_eq!(n.height_view_round, Node::REDRAW_AFTER_ROUNDS, "{id} entered the redraw");
        assert_eq!(n.lottery_order(), redraw);
        assert_eq!(n.sealed_committee(), redraw);
    }
    let proposer = net.nodes[&live[0]].round_proposer(Node::REDRAW_AFTER_ROUNDS).unwrap();
    assert!(live.contains(&proposer), "redraw proposer is a live outside seat");
    let ids: Vec<String> = TEN.iter().map(|s| s.to_string()).collect();
    let led = {
        let n = net.nodes.get_mut(&proposer).unwrap();
        for id in &ids {
            n.pong(id);
        }
        n.pack_as(&proposer).expect("redraw proposer packs")
    };
    assert_eq!(led.current_committee, redraw, "header carries the redrawn committee");
    for id in &live {
        net.nodes.get_mut(id).unwrap().accept_ledger(&led).unwrap_or_else(|e| panic!("{id}: {e}"));
    }
    let ok_voters: Vec<String> = redraw.iter().filter(|id| live.contains(id)).cloned().collect();
    assert!(ok_voters.len() >= 4);
    for id in &live {
        let n = net.nodes.get_mut(id).unwrap();
        for v in &ok_voters {
            n.vote_ok(&led.ledger_hash, v);
        }
        assert_eq!(n.tip_height, 2, "{id} committed through the redraw");
    }
    // A seat that was dead (round 0, base committee) catches the block up.
    let d = net.nodes.get_mut(&dead[0]).unwrap();
    assert_eq!(d.tip_height, 1);
    d.accept_ledger_catchup(&led).expect("catch-up accepts the redraw committee");
    assert_eq!(d.tip_height, 2);
}

#[test]
fn seats_that_signed_an_ok_never_vote_the_redraw() {
    let mut net = ten_after_one();
    arm(&mut net, 2);
    let (_dead, live) = split(&net, 3);
    let me = live[0].clone();
    net.nodes
        .get_mut(&me)
        .unwrap()
        .round_votes
        .entry(2)
        .or_default()
        .entry(0)
        .or_default()
        .insert(me.clone(), ("ab".repeat(32), String::new()));
    let voters = redraw_votes(&mut net, &live);
    assert!(!voters.contains(&me), "an OK at this height bars the redraw vote");
    assert_eq!(voters.len(), 6);
    // 6 of 10 is below the bonded-set quorum: nobody enters the redraw.
    deliver_vc(&mut net, &live, &voters, Node::REDRAW_AFTER_ROUNDS);
    for id in &live {
        assert!(net.nodes[id].height_view_round < Node::REDRAW_AFTER_ROUNDS, "{id}");
    }
}

#[test]
fn after_voting_the_redraw_no_base_round_ok() {
    let mut net = ten_after_one();
    arm(&mut net, 2);
    let (_dead, live) = split(&net, 3);
    let voters = redraw_votes(&mut net, &live[..1]);
    assert_eq!(voters.len(), 1);
    let n = &net.nodes[&live[0]];
    assert_eq!(n.redraw_vc_cast_at, 2);
    assert!(n.may_cast_own_ok(2, 0, &"cd".repeat(32)).is_err());
    assert!(n.may_cast_own_ok(2, Node::REDRAW_AFTER_ROUNDS, &"cd".repeat(32)).is_ok());
}

#[test]
fn four_dead_cannot_reach_the_bonded_quorum() {
    let mut net = ten_after_one();
    arm(&mut net, 2);
    let (_dead, live) = split(&net, 4);
    let voters = redraw_votes(&mut net, &live);
    assert_eq!(voters.len(), 6);
    deliver_vc(&mut net, &live, &voters, Node::REDRAW_AFTER_ROUNDS);
    for id in &live {
        assert!(net.nodes[id].height_view_round < Node::REDRAW_AFTER_ROUNDS);
    }
}

/// 2.11.13: a debug build panicked loading a live (more than 6 bonded) v4
/// snapshot: `load_snapshot` freezes the open height before the node applies
/// its QC bridge config, so it drew in v7 mode and the set check against the
/// sealed v8 next-6 failed. The load must succeed and use the sealed set, and
/// the check must still hold once v4 is configured.
#[test]
fn ten_seat_v4_snapshot_loads_with_sealed_next_committee() {
    let mut net = ten_after_one();
    for _ in 0..4 {
        net.payment("alice", "bob", 1, 1).unwrap();
        net.pong_all();
        net.seal_next_height().expect("seal");
    }
    let v1 = &net.nodes["v1"];
    let tip = v1.chain.last().unwrap().clone();
    assert!(tip.is_v4() && tip.next_committee.len() == 6);
    let path = std::env::temp_dir().join(format!("fpl-v4-freeze-{}-{}.json", std::process::id(), v1.tip_height));
    std::fs::write(&path, serde_json::to_vec(&v1.to_snapshot()).unwrap()).unwrap();
    let mut loaded = Node::load_snapshot(path.to_str().unwrap(), v1.keys.clone()).unwrap();
    let _ = std::fs::remove_file(&path);
    assert_eq!(loaded.schedule_committee, tip.next_committee);
    // As the binary does after load: arm v4, then re-freeze (debug check on).
    loaded.qc_header_version = 4;
    loaded.qc_start_height = 1;
    loaded.freeze_open_height_schedule();
    assert_eq!(loaded.schedule_committee, tip.next_committee);
}
