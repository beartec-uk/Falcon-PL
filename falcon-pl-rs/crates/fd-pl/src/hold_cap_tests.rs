//! 2.11.13 (a): the round-0 builder's thin-walk hold is capped at half of
//! peers' round-0 silence timeout, so hold + pack + gossip cannot overrun it.

use super::*;

fn users() -> Vec<(String, u64)> {
    vec![("alice".into(), 1_000_000), ("bob".into(), 1_000_000)]
}

fn thin_walk_seat(pack_budget_ms: u64, progress_timeout_ms: u64) -> Node {
    let mut n = Node::new(
        "v1",
        ChainConfig {
            pack_budget_ms: 0,
            progress_timeout_ms: 0,
            ..Default::default()
        },
        KeyRing::new(CryptoScheme::HmacDev),
        &users(),
    );
    n.tick(1);
    n.register_validator("v1", 1000);
    n.register_validator("v3", 1000);
    n.pong("v1");
    n.pong_with_inventory("v3", 0, 1_400, true);
    n.keys.generate_many(["alice", "bob"].into_iter());
    for seq in 1..=4 {
        let tx = Tx::sign_with(&n.keys, "alice", seq, "bob", 1, 1, n.cfg.network_id).unwrap();
        n.submit_tx(tx).unwrap();
    }
    n.cfg.pack_budget_ms = pack_budget_ms;
    n.cfg.progress_timeout_ms = progress_timeout_ms;
    n.cfg.pong_window_ms = 60_000;
    n
}

#[test]
fn hold_cap_is_half_the_round0_silence_timeout() {
    let n = thin_walk_seat(4_000, 9_000);
    // Round-0 silence timeout peers apply to a live builder.
    let round0 = n.live_pack_timeout_ms() * 2;
    assert_eq!(n.hold_cap_ms(), round0 / 2);
    // Hold + pack budget + slack fits the timeout peers apply.
    assert!(
        n.hold_cap_ms() + n.cfg.pack_budget_ms + Node::LIVE_PACK_SLACK_MS <= round0,
        "cap {} + pack {} + slack must fit round-0 {}",
        n.hold_cap_ms(),
        n.cfg.pack_budget_ms,
        round0
    );
    // The old progress-2s hold is clamped.
    assert!(n.thin_walk_hold_ms() <= n.hold_cap_ms());
    assert!(n.thin_walk_hold_ms() <= 9_000 - 2_000);
}

#[test]
fn thin_walk_seals_at_the_cap_not_at_progress_minus_two() {
    let mut n = thin_walk_seat(4_000, 9_000);
    assert!(n.short_pack_hole());
    assert!(n.should_pre_pack_need_txs());
    n.mark_pre_pack_need_txs();
    assert!(n.waiting_need_txs_grace(), "short hold still allowed");
    let cap = n.hold_cap_ms();
    let open = n.height_open_ms.max(n.round_open_ms);
    // Jump to just past the cap measured from height open.
    n.now_ms = open + cap;
    assert!(n.hold_window_spent());
    assert!(!n.waiting_need_txs_grace(), "seal what is packed at the cap");
    assert!(!n.should_pre_pack_need_txs(), "no more pulls past the cap");
    assert!(!n.pace_wait(), "pacing never outlasts the cap either");
}

#[test]
fn live_timing_values_keep_their_short_hold() {
    // 2.11.13 defaults (progress 4000, pack 5000): the 2 s hold is untouched.
    let n = thin_walk_seat(5_000, 4_000);
    assert_eq!(n.thin_walk_hold_ms(), 2_000);
    assert!(n.hold_cap_ms() >= 2_000);
}
