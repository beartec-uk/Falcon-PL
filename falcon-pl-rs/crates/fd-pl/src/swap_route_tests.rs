// Copyright (c) 2025-2026 BEARTEC. All rights reserved. See LICENSE.
//! f-asset -> f-asset `SwapRoute` (USDC -> FPL -> ETH, two hops): value is
//! conserved, and a `min_out` miss on the second hop rolls the whole tx back,
//! first hop included, exactly as the pack loop does it (`PackUndo`).
use super::*;

/// USDC/FPL at 100_000 FPL raw per USDC and ETH/FPL at 1_000_000 FPL per ETH.
fn node() -> Node {
    let mut n = Node::new(
        "v1",
        ChainConfig { scheme: CryptoScheme::Falcon512, network_id: 0, pack_budget_ms: 0, min_fee: 0, ..ChainConfig::default() },
        KeyRing::new(CryptoScheme::Falcon512),
        &[("bob".into(), 1_000_000_000_000)],
    );
    n.tip_height = 100;
    n.create_pool("usdc-fpl", "USDC", "FPL").unwrap();
    let p = n.defi.pools.get_mut("usdc-fpl").unwrap();
    p.reserve_a = 1_000_000_000_000;
    p.reserve_b = 100_000_000_000;
    n.create_pool("eth-fpl", "ETH", "FPL").unwrap();
    let p = n.defi.pools.get_mut("eth-fpl").unwrap();
    p.reserve_a = 5_000_000_000_000_000_000;
    p.reserve_b = 5_000_000_000_000;
    n.defi.credit_asset("bob", "USDC", 10_000_000_000);
    n
}

/// Total of one asset over balances + pools + order-book escrow.
fn total(n: &Node, asset: &str) -> u128 {
    let mut t: u128 = if asset == "FPL" {
        n.state.accounts.values().map(|a| a.balance as u128).sum()
    } else {
        n.defi.assets.values().map(|m| *m.get(asset).unwrap_or(&0) as u128).sum()
    };
    for p in n.defi.pools.values() {
        if p.asset_a == asset {
            t += p.reserve_a as u128;
        }
        if p.asset_b == asset {
            t += p.reserve_b as u128;
        }
    }
    t + n.defi.orderbook.escrow_totals().get(asset).copied().unwrap_or(0)
}

fn totals(n: &Node) -> [u128; 3] {
    [total(n, "FPL"), total(n, "USDC"), total(n, "ETH")]
}

#[test]
fn usdc_to_eth_routes_two_hops_and_conserves_value() {
    let mut n = node();
    assert!(n.find_pool("USDC", "ETH").is_none(), "no direct pool: must route via FPL");
    let t0 = totals(&n);
    let (u0, e0, f0) = (n.defi.asset_bal("bob", "USDC"), n.defi.asset_bal("bob", "ETH"), n.state.get("bob").balance);
    let out = n.swap_route("bob", "USDC", "ETH", 1_000_000_000, 1).unwrap();
    assert!(out > 0);
    assert_eq!(n.defi.asset_bal("bob", "ETH") - e0, out);
    assert_eq!(u0 - n.defi.asset_bal("bob", "USDC"), 1_000_000_000);
    assert_eq!(n.state.get("bob").balance, f0, "the FPL leg nets to zero for the trader");
    assert_eq!(totals(&n), t0);
    // 1_000 USDC ~ 1e8 FPL ~ 1e-4 ETH (1e14 wei) less two 0.3% fees and slippage.
    assert!(out > 99_000_000_000_000 && out < 100_000_000_000_000, "out={out}");
}

#[test]
fn min_out_miss_on_second_hop_rolls_back_the_whole_tx() {
    let mut n = node();
    let mut keys = KeyRing::new(CryptoScheme::Falcon512);
    keys.generate_id("bob");
    let _ = n.keys.insert_public("bob", &keys.public_hex("bob").unwrap());
    let seq = n.state.get("bob").sequence;
    let body = TxBody::SwapRoute { token_in: "USDC".into(), token_out: "ETH".into(), amount_in: 1_000_000_000, min_out: u64::MAX };
    let tx = Tx::sign_body(&keys, "bob", seq, "", 0, 1, 0, body).unwrap();

    let mut draft = PackDraft {
        state: n.state.clone(),
        defi: n.defi.clone(),
        bridge: n.bridge.clone(),
        vals: n.validators.clone(),
        claim: n.claimable.clone(),
        work: n.epoch_work.clone(),
    };
    let root0 = draft.state.root();
    let defi0 = serde_json::to_string(&draft.defi).unwrap();
    let undo = PackUndo::capture(&draft, &tx);
    let r = n.try_protocol_tx_ex(&mut draft.state, &mut draft.defi, &mut draft.bridge, &mut draft.vals, &mut draft.claim, &mut draft.work, &tx, false);
    assert!(r.is_err(), "min_out unreachable");
    assert_ne!(serde_json::to_string(&draft.defi).unwrap(), defi0, "the first hop ran before the second failed");
    undo.restore(&mut draft);
    assert_eq!(draft.state.root(), root0, "fee, sequence and FPL untouched");
    assert_eq!(serde_json::to_string(&draft.defi).unwrap(), defi0, "pools and USDC/ETH balances untouched");
    assert_eq!(draft.state.get("bob").sequence, seq);

    // The same tx with a reachable min_out applies.
    let ok = TxBody::SwapRoute { token_in: "USDC".into(), token_out: "ETH".into(), amount_in: 1_000_000_000, min_out: 1 };
    let tx = Tx::sign_body(&keys, "bob", seq, "", 0, 1, 0, ok).unwrap();
    n.try_protocol_tx_ex(&mut draft.state, &mut draft.defi, &mut draft.bridge, &mut draft.vals, &mut draft.claim, &mut draft.work, &tx, false)
        .unwrap();
    assert!(draft.defi.asset_bal("bob", "ETH") > 0);
}
