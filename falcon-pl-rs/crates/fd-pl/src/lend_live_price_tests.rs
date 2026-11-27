// Copyright (c) 2025-2026 BEARTEC. All rights reserved. See LICENSE.
//! Lend reward weighting at the live pool price
//! (`lend_live_price_from_height`). Before the height: stored market price,
//! unchanged bytes. From it: deepest FPL pool spot (the borrow/LTV source),
//! BTC4 value-equivalent whether or not the 2.10.4 rescale is open.
use super::*;

/// 100 USDC supplied; pool at 85 FPL/USDC, stored (stale) price 48.
/// 0.1 BTC4 supplied; pool at 4,067,600 FPL/BTC4, stored (stale) 20,000 per 1e6 sats.
fn node(live_gate: u64, btc4_scale_gate: u64) -> Node {
    let mut n = Node::new(
        "v1",
        ChainConfig { scheme: CryptoScheme::Falcon512, network_id: 0, pack_budget_ms: 0, min_fee: 0, ..ChainConfig::default() },
        KeyRing::new(CryptoScheme::Falcon512),
        &[("alice".into(), 1_000_000), ("bob".into(), 1_000_000)],
    );
    n.lend_live_price_from_height = live_gate;
    n.btc4_lend_scale_from_height = btc4_scale_gate;
    n.tip_height = 100;
    n.create_pool("usdc-fpl", "USDC", "FPL").unwrap();
    let p = n.defi.pools.get_mut("usdc-fpl").unwrap();
    p.reserve_a = 1_000_000_000;
    p.reserve_b = 85_000;
    n.create_pool("btc4-fpl", "BTC4", "FPL").unwrap();
    let p = n.defi.pools.get_mut("btc4-fpl").unwrap();
    p.reserve_a = 10_000_000;
    p.reserve_b = 406_760;
    n.create_market("lend-usdc", "USDC").unwrap();
    n.defi.markets.get_mut("lend-usdc").unwrap().set_price(48);
    n.create_market("lend-btc4", "BTC4").unwrap();
    n.defi.markets.get_mut("lend-btc4").unwrap().set_price(20_000);
    n.defi.credit_asset("alice", "USDC", 100_000_000);
    n.defi.credit_asset("bob", "BTC4", 10_000_000);
    n.lend_supply("lend-usdc", "alice", 100_000_000).unwrap();
    n.lend_supply("lend-btc4", "bob", 10_000_000).unwrap();
    n
}

fn lend_w(n: &Node) -> BTreeMap<String, u64> {
    n.lp_value_weights_v2(&EpochWork::default()).1
}

#[test]
fn gate_is_off_on_2300_until_scott_picks_a_height() {
    assert_eq!(crate::params_v2::TESTNET_2300_LEND_LIVE_PRICE_FROM_HEIGHT, u64::MAX);
    assert_eq!(crate::params_v2::lend_live_price_from_height(NETWORK_ID_PUBLIC_TESTNET_2300), u64::MAX);
}

#[test]
fn pre_activation_uses_stored_price_exactly_as_before() {
    let n = node(u64::MAX, u64::MAX);
    assert!(!n.lend_live_price_open());
    let w = lend_w(&n);
    // 100 USDC * 48 = 4,800; 1e7 sats * 20,000 / 1e6 = 200,000 (stale).
    assert_eq!(w["alice"], 4_800);
    assert_eq!(w["bob"], 200_000);
}

#[test]
fn post_activation_uses_live_pool_price() {
    let n = node(0, u64::MAX);
    assert!(n.lend_live_price_open());
    let w = lend_w(&n);
    assert_eq!(w["alice"], 8_500, "100 USDC at the pool's 85 FPL");
    assert_eq!(w["bob"], 406_760, "0.1 BTC4 at 4,067,600 FPL");
}

#[test]
fn activation_is_exactly_at_the_height() {
    let mut n = node(200, u64::MAX);
    n.tip_height = 198; // applying 199
    assert_eq!(lend_w(&n)["alice"], 4_800);
    n.tip_height = 199; // applying 200
    assert_eq!(lend_w(&n)["alice"], 8_500);
}

#[test]
fn btc4_value_is_the_same_before_and_after_the_rescale() {
    // Live price with BTC4 still per 1e6 sats, and with the 1e8 rescale open.
    let legacy_units = lend_w(&node(0, u64::MAX))["bob"];
    let rescaled = lend_w(&node(0, 0))["bob"];
    assert_eq!(legacy_units, 406_760);
    assert_eq!(rescaled, 406_760);
    // The price/scale pairs really differ by 100x; the value does not.
    let a = node(0, u64::MAX);
    let b = node(0, 0);
    assert_eq!(a.lend_reward_price(&a.defi.markets["lend-btc4"]), (40_676, 1_000_000));
    assert_eq!(b.lend_reward_price(&b.defi.markets["lend-btc4"]), (4_067_600, 100_000_000));
    // Pure: the stored market is not rewritten by weighting.
    assert_eq!(b.defi.markets["lend-btc4"].raw_per_coin, None);
    assert_eq!(b.defi.markets["lend-btc4"].price_native_per_scale, 20_000);
}

#[test]
fn no_pool_falls_back_to_stored_price() {
    let mut n = node(0, u64::MAX);
    n.defi.pools.remove("usdc-fpl");
    assert_eq!(lend_w(&n)["alice"], 4_800);
}

#[test]
fn deepest_pool_wins_like_the_borrow_check() {
    let mut n = node(0, u64::MAX);
    n.create_pool("usdc-fpl-2", "FPL", "USDC").unwrap();
    let p = n.defi.pools.get_mut("usdc-fpl-2").unwrap();
    p.reserve_a = 1_000; // 1 FPL per USDC, but shallow
    p.reserve_b = 1_000_000;
    assert_eq!(lend_w(&n)["alice"], 8_500);
}

#[test]
fn deterministic_across_seats_and_calls() {
    let a = node(0, 0);
    let b = node(0, 0);
    assert_eq!(lend_w(&a), lend_w(&b));
    assert_eq!(lend_w(&a), lend_w(&a));
    let before = serde_json::to_string(&a.defi).unwrap();
    let _ = lend_w(&a);
    assert_eq!(serde_json::to_string(&a.defi).unwrap(), before, "weighting never writes state");
}
