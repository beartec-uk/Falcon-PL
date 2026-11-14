//! BTC4 BitVM2 claim tree full (16 leaves, MERKLE_DEPTH=4): a burn must be
//! refused loudly, not accepted and left unpacked forever (14 Nov 2026).
use super::*;
use crate::bridge::{RailState, BITVM2_CLAIM_TREE_FULL, RAIL_BTC4};

fn setup() -> (KeyRing, Node, String) {
    let mut k = KeyRing::new(CryptoScheme::HmacDev);
    k.generate_many(["alice", "v1"]);
    let cfg = ChainConfig { min_fee: 0, first_claim_epoch: 1, ..Default::default() };
    let mut n = Node::new("v1", cfg, k.clone(), &[("alice".into(), 1_000_000)]);
    n.register_validator("v1", 1000);
    n.bitvm2_m1_from_height = 0;
    n.tip_height = 300;
    n.bridge.rails.insert(RAIL_BTC4.into(), RailState::new_btc4());
    n.defi.credit_asset("alice", RAIL_BTC4, 1_000_000);
    let pk = crate::btc_tx::compressed_pubkey_from_secret(&[3u8; 32]).unwrap();
    let dest = crate::vault::p2wpkh_testnet_address(&pk).unwrap();
    (k, n, dest)
}

fn burn(k: &KeyRing, n: &Node, amount: u64, dest: &str) -> Tx {
    let seq = n.state.get("alice").sequence;
    Tx::sign_body(k, "alice", seq, "", 0, 2, n.cfg.network_id, TxBody::RailWithdraw {
        asset: RAIL_BTC4.into(),
        amount,
        external_to: dest.into(),
        vault_sig: String::new(),
        signed_btc_tx: String::new(),
    })
    .unwrap()
}

fn fill_leaves(n: &mut Node, count: usize) {
    let r = n.bridge.rail_mut(RAIL_BTC4).unwrap();
    while r.bitvm2_claim_leaves.len() < count {
        r.bitvm2_claim_leaves.push("00".repeat(32));
    }
}

#[test]
fn last_free_leaf_still_opens_a_claim() {
    let (k, mut n, dest) = setup();
    fill_leaves(&mut n, 15);
    n.apply_protocol_tx(&burn(&k, &n, 10_000, &dest)).unwrap();
    assert_eq!(n.bridge.rail(RAIL_BTC4).unwrap().bitvm2_claim_leaves.len(), 16);
}

#[test]
fn full_tree_refuses_before_debit_and_without_touching_leaves() {
    let (_k, mut n, dest) = setup();
    fill_leaves(&mut n, 16);
    let e = n.btc4_withdraw("alice", 10_000, &dest).unwrap_err();
    assert!(e.contains(BITVM2_CLAIM_TREE_FULL), "{e}");
    assert!(e.contains("16/16"), "{e}");
    assert_eq!(n.defi.asset_bal("alice", RAIL_BTC4), 1_000_000);
    assert_eq!(n.bridge.rail(RAIL_BTC4).unwrap().bitvm2_claim_leaves.len(), 16);
    let e2 = n.bridge.rail_mut(RAIL_BTC4).unwrap()
        .open_bitvm2_withdraw("note-x", "alice", &dest, 10_000, 300).unwrap_err();
    assert!(e2.contains(BITVM2_CLAIM_TREE_FULL), "{e2}");
    assert_eq!(n.bridge.rail(RAIL_BTC4).unwrap().bitvm2_claim_leaves.len(), 16);
}

#[test]
fn full_tree_burn_is_refused_at_submit_with_a_clear_error() {
    let (k, mut n, dest) = setup();
    fill_leaves(&mut n, 16);
    let e = n.submit_tx(burn(&k, &n, 10_000, &dest)).unwrap_err();
    assert!(e.contains(BITVM2_CLAIM_TREE_FULL), "{e}");
    assert_eq!(n.mempool.len(), 0);
}

#[test]
fn full_tree_errors_count_as_permanent_so_heads_get_dropped() {
    assert!(Node::is_permanent_tx_failure(&format!("{BITVM2_CLAIM_TREE_FULL} (16/16) on BTC4")));
    assert!(Node::is_permanent_tx_failure("too many leaves for MERKLE_DEPTH=4"));
}

#[test]
fn non_full_burn_still_admitted() {
    let (k, mut n, dest) = setup();
    fill_leaves(&mut n, 3);
    assert!(n.submit_tx(burn(&k, &n, 10_000, &dest)).unwrap());
}
