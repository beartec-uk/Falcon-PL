// Copyright (c) 2025-2026 BEARTEC. All rights reserved. See LICENSE.
//! 2.11.4 round-split recovery (testnet 2300, stall at h=891419,
//! 15 Nov 2026 07:07 GMT → 16 Nov 2026 02:41 GMT).
//!
//! Live shape for h=891420: committee of 6, quorum 4. Four seats (v12, v6,
//! crypto-dashboard, v1) applied the round-1 ViewChange QC; v10 (lagging,
//! catch-up lane full) and scottspersonalnode never saw those VC votes and
//! stayed on round 0. v12 proposed `a4c12304…` in round 1; round-1 OKs
//! arrived at different times and each round-1 seat counted only 3 of them
//! (v1's never reached anyone: its pipes were being shed). From then on the
//! round-0 seats voted round 1 (2 votes) and the round-1 seats voted round 2
//! (3 delivered votes): 2 + 3 < 4 forever. Nobody could re-send the round-1
//! QC because `apply_round_advance` dropped it, and OKs are fanned once.
//!
//! These tests drive signed votes through a small in-process mesh that
//! mirrors the wire handlers (`ViewChange`, `LedgerOk`, `ProposeLedger`).

use std::collections::{BTreeSet, VecDeque};

use crate::{ChainConfig, Ledger, Network, Node, RoundRegossip};

const SIX: [&str; 6] = ["v1", "v2", "v3", "v4", "v5", "v6"];

fn users() -> Vec<(String, u64)> {
    vec![
        ("alice".into(), 1_000_000),
        ("bob".into(), 1_000_000),
        ("carol".into(), 1_000_000),
    ]
}

fn signed_cfg() -> ChainConfig {
    ChainConfig {
        pack_budget_ms: 0,
        max_txs_per_ledger: 8,
        progress_timeout_ms: 1_000,
        vote_rounds_from_height: 1,
        require_vote_sigs: true,
        ..Default::default()
    }
}

/// Signed 6-seat chain at tip=1 (round-scoped cert), work in every mempool,
/// schedule frozen for h=2.
fn signed_six_at_tip1() -> Network {
    let mut net = Network::bootstrap(&SIX, 1000, &users(), signed_cfg());
    net.pong_all();
    net.payment("alice", "bob", 1, 1).unwrap();
    let packer = net.nodes["v1"].lottery_packer().expect("packer");
    let led = net.nodes.get_mut(&packer).unwrap().pack_as(&packer).expect("pack h=1");
    for n in net.nodes.values_mut() {
        n.accept_ledger(&led).expect("stage h=1");
    }
    let sigs: Vec<(String, String, u64)> = net
        .nodes
        .iter()
        .map(|(v, n)| {
            let r = n.own_ok_round(led.height);
            (v.clone(), n.sign_ok_vote_round(led.height, r, &led.ledger_hash), r)
        })
        .collect();
    for n in net.nodes.values_mut() {
        for (v, s, r) in &sigs {
            n.vote_ok_round_ex(&led.ledger_hash, v, s, *r);
        }
    }
    assert_eq!(net.tip_height(), 1, "signed h=1 commits");
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

#[derive(Clone, Debug)]
enum Msg {
    Vc { round: u64, voter: String, sig: String },
    Ok { hash: String, voter: String, sig: String, round: u64 },
    Body(Ledger),
}

/// Full mesh with programmable loss. Handlers follow `falcon_pl_node.rs`:
/// a fresh vote is re-fanned (OK only until soft), a VC QC re-votes the
/// staged body, a staged body is OK'd by its own seat.
struct Mesh {
    net: Network,
    /// (from, to) links that drop everything.
    cut: BTreeSet<(String, String)>,
    /// Drop round-`n` ViewChange messages addressed to these seats.
    deaf_to_vc_round: Option<(u64, BTreeSet<String>)>,
    q: VecDeque<(String, String, Msg)>,
    h: u64,
}

impl Mesh {
    fn ids(&self) -> Vec<String> {
        self.net.nodes.keys().cloned().collect()
    }

    fn fan(&mut self, from: &str, m: Msg) {
        for to in self.ids() {
            if to != from {
                self.q.push_back((from.to_string(), to, m.clone()));
            }
        }
    }

    fn lost(&self, from: &str, to: &str, m: &Msg) -> bool {
        if self.cut.contains(&(from.to_string(), to.to_string())) {
            return true;
        }
        if let (Msg::Vc { round, .. }, Some((r, deaf))) = (m, &self.deaf_to_vc_round) {
            if round == r && deaf.contains(to) {
                return true;
            }
        }
        false
    }

    fn own_ok(n: &mut Node, h: u64, hash: &str) -> Option<Msg> {
        let (round, sig) = n.own_ok_vote(h, hash)?;
        let me = n.id.clone();
        let _ = n.vote_ok_round_ex(hash, &me, &sig, round);
        Some(Msg::Ok { hash: hash.to_string(), voter: me, sig, round })
    }

    fn pump(&mut self) {
        let h = self.h;
        let mut guard = 0;
        while let Some((from, to, m)) = self.q.pop_front() {
            guard += 1;
            assert!(guard < 200_000, "message storm");
            if self.lost(&from, &to, &m) {
                continue;
            }
            let mut out: Vec<Msg> = Vec::new();
            {
                let n = self.net.nodes.get_mut(&to).unwrap();
                match &m {
                    Msg::Vc { round, voter, sig } => {
                        let tip = n.tip_hash.clone();
                        let (qc, fresh) = n.vote_view_change_ex(h, &tip, *round, voter, sig);
                        if qc {
                            if let Some(p) = n.pending_proposal.clone().filter(|p| p.height == h) {
                                out.extend(Self::own_ok(n, h, &p.ledger_hash));
                            }
                        }
                        if fresh {
                            out.push(m.clone());
                        }
                    }
                    Msg::Ok { hash, voter, sig, round } => {
                        let (soft, _, fresh) = n.vote_ok_wire(h, hash, voter, sig, *round);
                        if fresh && !soft {
                            out.push(m.clone());
                        }
                    }
                    Msg::Body(b) => {
                        let first = !n.open_bodies.contains_key(&b.ledger_hash)
                            && n.pending_proposal.as_ref().map(|p| p.ledger_hash != b.ledger_hash).unwrap_or(true);
                        if n.tip_height < h && n.accept_ledger(b).is_ok() {
                            n.maybe_switch_target(h);
                            if let Some(hash) = n.pending_proposal.as_ref().map(|p| p.ledger_hash.clone()) {
                                out.extend(Self::own_ok(n, h, &hash));
                            }
                            if first {
                                out.push(m.clone());
                            }
                        }
                    }
                }
            }
            for o in out {
                self.fan(&to, o);
            }
        }
    }

    fn advance(&mut self, ms: u64) {
        for n in self.net.nodes.values_mut() {
            n.now_ms += ms;
            n.pong_all_validators_for_test();
        }
    }

    /// One node-loop tick on every seat: round timer, then (if `regossip`)
    /// the 2.11.4 stalled-round re-gossip.
    fn tick(&mut self, regossip: bool) {
        for id in self.ids() {
            let mut out = Vec::new();
            {
                let n = self.net.nodes.get_mut(&id).unwrap();
                if let Some((h, tip, round)) = n.maybe_view_change_vote() {
                    let sig = n.sign_vc_vote(h, &tip, round);
                    out.push(Msg::Vc { round, voter: id.clone(), sig });
                    if n.height_view_round >= round {
                        if let Some(p) = n.pending_proposal.clone().filter(|p| p.height == h) {
                            out.extend(Self::own_ok(n, h, &p.ledger_hash));
                        }
                    }
                }
                if regossip {
                    for r in n.stalled_round_regossip() {
                        out.push(match r {
                            RoundRegossip::ViewChange { round, voter, signature, .. } => {
                                Msg::Vc { round, voter, sig: signature }
                            }
                            RoundRegossip::Ok { ledger_hash, voter, signature, round, .. } => {
                                Msg::Ok { hash: ledger_hash, voter, sig: signature, round }
                            }
                        });
                    }
                }
            }
            for m in out {
                self.fan(&id, m);
            }
        }
        self.pump();
    }
}

/// Build the exact 891419/891420 split and return the mesh plus
/// (order, round-1 body hash). `order[0]` plays v10 and `order[5]`
/// scottspersonalnode (their live lottery slots), `order[1]` v12 (round-1
/// proposer), `order[4]` v1 (pipes shed: its traffic never arrives).
fn build_891419_split() -> (Mesh, Vec<String>, String) {
    let net = signed_six_at_tip1();
    let h = 2;
    let order = net.nodes["v1"].lottery_order();
    assert_eq!(order.len(), 6);
    assert_eq!(net.nodes["v1"].commit_votes_needed(), 4, "6 members, 4 needed");
    let stuck: BTreeSet<String> = [order[0].clone(), order[5].clone()].into_iter().collect();
    let mut m = Mesh {
        net,
        cut: BTreeSet::new(),
        deaf_to_vc_round: Some((1, stuck.clone())),
        q: VecDeque::new(),
        h,
    };
    // Round 0: the proposer (order[0], lagging) never seals. After the
    // silence timeout the four live seats vote round 1; the two stuck seats
    // never receive any round-1 ViewChange (catch-up lane full / shed pipes).
    for n in m.net.nodes.values_mut() {
        n.note_work_state(); // txs are waiting: the round clock starts now
    }
    let silence = m.net.nodes[&order[1]].round_silence_timeout_ms(0);
    m.advance(silence + 1);
    for id in &order[1..5] {
        let n = m.net.nodes.get_mut(id).unwrap();
        let (hh, tip, round) = n.maybe_view_change_vote().expect("round-0 timeout");
        assert_eq!((hh, round), (h, 1));
        let sig = n.sign_vc_vote(hh, &tip, round);
        m.fan(id, Msg::Vc { round, voter: id.clone(), sig });
    }
    m.pump();
    for id in &order[1..5] {
        assert_eq!(m.net.nodes[id].height_view_round, 1, "{id} applied the round-1 QC");
    }
    for id in &stuck {
        assert_eq!(m.net.nodes[id].height_view_round, 0, "{id} missed the round-1 QC");
    }
    // From here order[4] ("v1") is cut off both ways (shed pipes).
    for other in m.ids() {
        if other != order[4] {
            m.cut.insert((order[4].clone(), other.clone()));
            m.cut.insert((other.clone(), order[4].clone()));
        }
    }
    // Round-1 proposer seals and fans; OKs land seconds apart.
    let body = {
        let p = m.net.nodes.get_mut(&order[1]).unwrap();
        let b = p.pack_as(&order[1]).expect("round-1 body");
        assert_eq!(b.skipped_predecessors.len(), 1);
        b
    };
    let hash = body.ledger_hash.clone();
    {
        let p = m.net.nodes.get_mut(&order[1]).unwrap();
        p.accept_ledger(&body).expect("proposer stages its body");
        let own = Mesh::own_ok(p, h, &hash);
        m.fan(&order[1], Msg::Body(body.clone()));
        if let Some(o) = own {
            m.fan(&order[1], o);
        }
    }
    for step in [2_000u64, 3_000] {
        m.advance(step);
        m.pump();
    }
    (m, order, hash)
}

fn committee_round_ok_count(n: &Node, h: u64, round: u64, hash: &str) -> usize {
    let order = n.lottery_order();
    n.round_votes
        .get(&h)
        .and_then(|r| r.get(&round))
        .map(|v| v.iter().filter(|(id, (x, _))| x == hash && order.contains(id)).count())
        .unwrap_or(0)
}

fn run(m: &mut Mesh, regossip: bool, minutes: u64) {
    for _ in 0..(minutes * 60) {
        m.advance(1_000);
        m.tick(regossip);
        if m.net.nodes.values().filter(|n| n.tip_height >= m.h).count() >= 4 {
            break;
        }
    }
}

/// The incident split, start to finish. Before 2.11.4 (no re-gossip) it never
/// recovers; with re-gossip the round-1 QC reaches the two round-0 seats,
/// they adopt round 1 at a verified 4-of-6, re-vote the round-1 body and it
/// commits with a round-1 cert. The broken seat stays on the same chain.
#[test]
fn round_split_891419_recovers_only_with_regossip() {
    let (mut m, order, hash) = build_891419_split();
    let h = m.h;
    // The stall as observed: 3 committee OKs per round-1 seat, nobody soft.
    for id in &order[1..4] {
        let n = &m.net.nodes[id];
        assert_eq!(committee_round_ok_count(n, h, 1, &hash), 3, "{id}: 3 of 4 round-1 OKs");
        assert_eq!(n.tip_height, 1);
    }
    // Pre-fix behaviour on an identical second copy of the split.
    let (mut pre, _, _) = build_891419_split();
    pre.deaf_to_vc_round = None;
    run(&mut pre, false, 30);
    let pre_tips: Vec<(String, u64, u64)> = pre
        .net
        .nodes
        .iter()
        .map(|(id, n)| (id.clone(), n.tip_height, n.height_view_round))
        .collect();
    assert!(
        pre.net.nodes.values().all(|n| n.tip_height == 1),
        "without re-gossip the split must stay stuck: {pre_tips:?}"
    );
    // ...for the live reason: 2 seats keep voting round 1, the 3 reachable
    // round-1 seats vote round 2, neither reaches 4.
    for id in [&order[0], &order[5]] {
        let n = &pre.net.nodes[id];
        assert_eq!(n.height_view_round, 0, "{id} still on round 0: {pre_tips:?}");
        let r2 = n.view_change_votes.get(&h).and_then(|m| m.get(&2)).map(|s| s.len()).unwrap_or(0);
        assert_eq!(r2, 3, "{id} sees exactly 3 round-2 VC votes");
    }
    for id in &order[1..4] {
        let n = &pre.net.nodes[id];
        assert_eq!(n.height_view_round, 1, "{id} still on round 1: {pre_tips:?}");
        let r1 = n.view_change_votes.get(&h).and_then(|m| m.get(&1)).map(|s| s.len()).unwrap_or(0);
        assert_eq!(r1, 0, "{id} dropped the round-1 QC votes and ignores late round-1 VCs");
    }

    // 30 simulated minutes of round timers above, no re-gossip.
    // With 2.11.4 re-gossip (links to the stuck seats healthy again, the
    // broken seat still cut off).
    m.deaf_to_vc_round = None;
    run(&mut m, true, 30);
    let tips: Vec<(String, u64, u64)> = m
        .net
        .nodes
        .iter()
        .map(|(id, n)| (id.clone(), n.tip_height, n.height_view_round))
        .collect();
    for id in order.iter().filter(|id| **id != order[4]) {
        let n = &m.net.nodes[id];
        assert_eq!(n.tip_height, h, "{id} must commit h=2: {tips:?}");
        assert_eq!(n.tip_hash, hash, "{id} commits the round-1 body");
        let cert = n.certs.get(&h).expect("cert");
        assert_eq!(cert.round, 1, "cert is the round-1 soft QC");
        assert!(cert.voters.len() >= 4);
        assert!(n.pending_slashes.is_empty(), "{id}: no equivocation");
        assert!(n.validators.values().all(|v| !v.jailed));
    }
    // The cut-off seat did not move or fork; it catches up later.
    let b = &m.net.nodes[&order[4]];
    assert_eq!(b.tip_height, 1);
    assert!(!b.certs.contains_key(&h));
}

/// Safety: a re-gossiped round QC moves a seat only at a verified 4-of-6.
/// Three votes, bad or foreign signatures, a wrong tip or a non-committee
/// voter never move it.
#[test]
fn regossiped_round_qc_needs_a_full_verified_quorum() {
    let mut net = signed_six_at_tip1();
    let h = 2;
    let order = net.nodes["v1"].lottery_order();
    let tip = net.nodes["v1"].tip_hash.clone();
    let sigs: Vec<(String, String)> = order
        .iter()
        .take(4)
        .map(|v| (v.clone(), net.nodes[v].sign_vc_vote(h, &tip, 1)))
        .collect();
    // A seat that applied the QC keeps exactly that evidence.
    let holder = order[1].clone();
    {
        let n = net.nodes.get_mut(&holder).unwrap();
        for (v, s) in &sigs {
            n.vote_view_change_ex(h, &tip, 1, v, s);
        }
        assert_eq!(n.height_view_round, 1);
        let q = n.applied_round_qc.clone().expect("applied QC kept");
        assert_eq!((q.height, q.round, q.tip_hash.as_str()), (h, 1, tip.as_str()));
        assert_eq!(q.votes.len(), 4);
        assert!(q.votes.iter().all(|(v, s)| sigs.contains(&(v.clone(), s.clone()))));
    }
    let lag = order[5].clone();
    let n = net.nodes.get_mut(&lag).unwrap();
    // Three genuine votes: not a quorum.
    for (v, s) in sigs.iter().take(3) {
        n.vote_view_change_ex(h, &tip, 1, v, s);
    }
    assert_eq!(n.height_view_round, 0, "3 of 6 never moves a seat");
    let (v4, s4) = sigs[3].clone();
    // 4th voter with somebody else's signature / garbage: rejected.
    n.vote_view_change_ex(h, &tip, 1, &v4, &sigs[0].1);
    n.vote_view_change_ex(h, &tip, 1, &v4, "00");
    // Right signature, wrong tip or wrong height: rejected.
    n.vote_view_change_ex(h, "deadbeef", 1, &v4, &s4);
    n.vote_view_change_ex(h + 1, &tip, 1, &v4, &s4);
    // Non-committee voter: rejected.
    n.vote_view_change_ex(h, &tip, 1, "outsider", &s4);
    assert_eq!(n.height_view_round, 0, "no forged or foreign vote completes the QC");
    assert!(n.applied_round_qc.is_none());
    // The genuine 4th vote completes it.
    n.vote_view_change_ex(h, &tip, 1, &v4, &s4);
    assert_eq!(n.height_view_round, 1);
    // A round entered without signed VC votes (restart realign) is never
    // re-gossiped as a QC.
    let other = net.nodes.get_mut(&order[2]).unwrap();
    other.apply_round_advance(h, 1);
    assert_eq!(other.height_view_round, 1);
    assert!(other.applied_round_qc.is_none());
}

/// Re-gossip only on a stalled round with work, at most once per interval,
/// never while lagging, and only committee votes from the current round.
#[test]
fn round_regossip_waits_for_a_stall_and_is_rate_limited() {
    let (mut m, order, hash) = build_891419_split();
    let h = m.h;
    let id = order[2].clone();
    let n = m.net.nodes.get_mut(&id).unwrap();
    // Fresh round: nothing yet.
    n.round_open_ms = n.now_ms;
    n.last_round_regossip_ms = 0;
    assert!(n.stalled_round_regossip().is_empty(), "round just opened");
    n.now_ms += n.round_regossip_interval_ms();
    let msgs = n.stalled_round_regossip();
    let vcs = msgs.iter().filter(|x| matches!(x, RoundRegossip::ViewChange { .. })).count();
    let oks: Vec<_> = msgs
        .iter()
        .filter_map(|x| match x {
            RoundRegossip::Ok { ledger_hash, round, voter, signature, .. } => {
                Some((ledger_hash.clone(), *round, voter.clone(), signature.clone()))
            }
            _ => None,
        })
        .collect();
    assert_eq!(vcs, 4, "the 4 signed VC votes of the applied round-1 QC");
    assert_eq!(oks.len(), 3);
    assert!(oks.iter().all(|(x, r, v, s)| *x == hash && *r == 1 && !s.is_empty() && order.contains(v)));
    assert!(n.stalled_round_regossip().is_empty(), "rate-limited");
    n.now_ms += n.round_regossip_interval_ms();
    assert!(!n.stalled_round_regossip().is_empty(), "next interval");
    // Lagging: catch-up first, no re-gossip.
    n.now_ms += n.round_regossip_interval_ms();
    n.best_peer_tip = n.tip_height + 50;
    assert!(n.stalled_round_regossip().is_empty(), "lagging seat stays quiet");
    let _ = h;
}

/// Idle chain: no work, nothing re-gossiped (load-driven chain stays silent).
#[test]
fn round_regossip_silent_on_idle_tip() {
    let mut net = Network::bootstrap(&SIX, 1000, &users(), signed_cfg());
    net.pong_all();
    let n = net.nodes.get_mut("v2").unwrap();
    n.best_peer_tip = n.tip_height;
    n.now_ms += 3_600_000;
    assert!(n.stalled_round_regossip().is_empty());
}

/// A seat that entered the round without the wire re-vote (e.g. QC applied
/// on a path that only cast the unsigned in-process vote) signs its missing
/// own OK for the staged body on the next re-gossip, under the normal lock
/// rules, and sends it.
#[test]
fn round_regossip_casts_a_missing_own_ok_for_the_staged_body() {
    let (mut m, order, hash) = build_891419_split();
    let h = m.h;
    let id = order[0].clone();
    let n = m.net.nodes.get_mut(&id).unwrap();
    n.apply_round_advance(h, 1);
    assert_eq!(n.pending_proposal.as_ref().map(|p| p.ledger_hash.clone()), Some(hash.clone()));
    let has_own = |n: &Node| {
        n.round_votes.get(&h).and_then(|r| r.get(&1)).map(|v| v.contains_key(&n.id)).unwrap_or(false)
    };
    assert!(!has_own(n), "unsigned in-process re-vote is not recorded with require_vote_sigs");
    n.now_ms += n.round_regossip_interval_ms();
    let msgs = n.stalled_round_regossip();
    assert!(
        msgs.iter().any(|x| matches!(x, RoundRegossip::Ok { voter, round: 1, ledger_hash, signature, .. }
            if *voter == id && *ledger_hash == hash && !signature.is_empty())),
        "own round-1 OK is signed and sent: {msgs:?}"
    );
    assert!(has_own(n));
    let own_count = msgs
        .iter()
        .filter(|x| matches!(x, RoundRegossip::Ok { voter, .. } if *voter == id))
        .count();
    assert_eq!(own_count, 1, "own OK sent once");
}
