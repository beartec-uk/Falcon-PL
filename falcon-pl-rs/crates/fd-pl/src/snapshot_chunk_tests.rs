//! 2.11.13 (e): periodic snapshot copies the chain tail in short lock holds.

use super::*;
use crate::snapshot::NodeSnapshot;

fn chain_net(heights: usize, max_chain: usize) -> Network {
    let users: Vec<(String, u64)> = vec![("alice".into(), 1_000_000), ("bob".into(), 1_000_000)];
    let cfg = ChainConfig {
        pack_budget_ms: 0,
        pong_window_ms: 60_000,
        max_chain_ledgers: max_chain,
        ..Default::default()
    };
    let mut net = Network::bootstrap(&["v1", "v2", "v3"], 1000, &users, cfg);
    for _ in 0..heights {
        net.payment("alice", "bob", 1, 1).unwrap();
        net.seal_next_height().unwrap();
    }
    net
}

fn chunked(n: &Node, chunk: usize) -> Result<NodeSnapshot, String> {
    let (head, mut after) = n.to_snapshot_head();
    let mut tail = Vec::new();
    while after < head.tip_height {
        let part = n.chain_after(after, chunk);
        let Some(last) = part.last() else { break };
        after = last.height;
        tail.extend(part);
    }
    Node::finish_chunked_snapshot(head, tail, n.cfg.max_chain_ledgers)
}

#[test]
fn chunked_capture_equals_one_lock_capture() {
    let net = chain_net(12, 0);
    let n = &net.nodes["v1"];
    let one = serde_json::to_vec(&n.to_snapshot()).unwrap();
    for chunk in [1usize, 5, 256] {
        let two = serde_json::to_vec(&chunked(n, chunk).unwrap()).unwrap();
        assert_eq!(one, two, "chunk={chunk}: same bytes as the one-lock capture");
    }
}

#[test]
fn chunked_capture_respects_max_chain_ledgers() {
    let net = chain_net(10, 4);
    let n = &net.nodes["v1"];
    let one = n.to_snapshot();
    let two = chunked(n, 3).unwrap();
    assert_eq!(one.chain.len(), two.chain.len());
    assert_eq!(serde_json::to_vec(&one).unwrap(), serde_json::to_vec(&two).unwrap());
}

#[test]
fn later_commits_are_dropped_and_mismatch_falls_back() {
    let mut net = chain_net(6, 0);
    let (head, after) = net.nodes["v1"].to_snapshot_head();
    // Two more heights commit while the tail is being copied.
    for _ in 0..2 {
        net.payment("alice", "bob", 1, 1).unwrap();
        net.seal_next_height().unwrap();
    }
    let n = &net.nodes["v1"];
    let tail = n.chain_after(after, 1_000);
    let snap = Node::finish_chunked_snapshot(head.clone(), tail.clone(), 0).unwrap();
    assert_eq!(snap.chain.last().unwrap().height, head.tip_height);
    assert_eq!(snap.chain.last().unwrap().ledger_hash, head.tip_hash);
    // A tail that does not end at the head's tip (fork switch / adopt) is refused.
    let mut forged = head.clone();
    forged.tip_hash = "00".repeat(32);
    assert!(Node::finish_chunked_snapshot(forged, tail.clone(), 0).is_err());
    // A gap in the tail is refused.
    let mut gap = tail.clone();
    gap.remove(1);
    assert!(Node::finish_chunked_snapshot(head, gap, 0).is_err());
}
