//! BTC4 BitVM2 claim tree capacity (16 leaves, MERKLE_DEPTH=4; 14 Nov 2026).
//! Fix A: a burn into a full tree is refused loudly (before debit, at submit).
//! Fix B: from the leaf-prune height, settled leaves are pruned so peg-outs resume.
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
fn full_tree_is_permanent_only_while_no_prune_height_is_scheduled() {
    let (_k, mut n, _dest) = setup();
    let ours = format!("{BITVM2_CLAIM_TREE_FULL} (16/16) on BTC4");
    let old_seat = "too many leaves for MERKLE_DEPTH=4";
    n.bitvm2_leaf_prune_from_height = u64::MAX;
    assert!(n.is_permanent_tx_failure_here(&ours));
    assert!(n.is_permanent_tx_failure_here(old_seat));
    // Scheduled: queued burns are kept and apply once a leaf frees.
    n.bitvm2_leaf_prune_from_height = 10_000;
    assert!(!n.is_permanent_tx_failure_here(&ours));
    assert!(!n.is_permanent_tx_failure_here(old_seat));
    // Other permanent errors are unchanged.
    assert!(n.is_permanent_tx_failure_here("insufficient balance"));
}

/// 16 claims on the BTC4 rail: `n_settled` refunded (settled), one
/// `ClaimPosted` attested at `attest_h`, the rest `AwaitingPegout`.
fn fill_claims(n: &mut Node, dest: &str, n_settled: usize, attest_h: u64) -> String {
    use crate::bitvm2_exit::Bitvm2Status as S;
    let r = n.bridge.rail_mut(RAIL_BTC4).unwrap();
    let mut posted = String::new();
    for i in 0..16 {
        let note = format!("note{i:02}");
        r.open_bitvm2_withdraw(&note, "bob", dest, 1_000 + i as u64, 100).unwrap();
        let c = r.bitvm2_claims.get_mut(&note).unwrap();
        if i < n_settled {
            c.status = S::Refunded;
        } else if i == n_settled {
            c.status = S::ClaimPosted;
            c.attest_height = attest_h;
            posted = note.clone();
        }
    }
    assert_eq!(r.bitvm2_claim_leaves.len(), 16);
    posted
}

#[test]
fn before_activation_nothing_is_pruned_and_state_is_identical() {
    let (_k, mut n, dest) = setup();
    fill_claims(&mut n, &dest, 3, 300);
    n.bitvm2_leaf_prune_from_height = u64::MAX;
    let before = serde_json::to_value(n.bridge.rail(RAIL_BTC4).unwrap()).unwrap();
    n.bridge_finalize_claims();
    let after = serde_json::to_value(n.bridge.rail(RAIL_BTC4).unwrap()).unwrap();
    assert_eq!(before, after);
    // One ledger before the height: still nothing.
    n.bitvm2_leaf_prune_from_height = n.tip_height + 2;
    n.bridge_finalize_claims();
    assert_eq!(n.bridge.rail(RAIL_BTC4).unwrap().bitvm2_claim_leaves.len(), 16);
}

#[test]
fn from_activation_settled_leaves_are_pruned_and_burns_resume() {
    let (k, mut n, dest) = setup();
    fill_claims(&mut n, &dest, 3, 300);
    let root_before = n.bridge.rail(RAIL_BTC4).unwrap().bitvm2_claim_root.clone();
    let e = n.btc4_withdraw("alice", 10_000, &dest).unwrap_err();
    assert!(e.contains(BITVM2_CLAIM_TREE_FULL));
    n.bitvm2_leaf_prune_from_height = n.tip_height + 1;
    n.bridge_finalize_claims();
    let r = n.bridge.rail(RAIL_BTC4).unwrap();
    assert_eq!(r.bitvm2_claim_leaves.len(), 13);
    assert_ne!(r.bitvm2_claim_root, root_before);
    assert_eq!(r.bitvm2_claim_root, crate::bitvm2_exit::mimc_root_from_leaves(&r.bitvm2_claim_leaves).unwrap());
    // Every live claim still has its leaf.
    for c in r.bitvm2_claims.values() {
        let live = !matches!(c.status, crate::bitvm2_exit::Bitvm2Status::Refunded);
        assert_eq!(r.bitvm2_claim_leaves.contains(&c.mimc_leaf_hex), live, "{}", c.note_id);
    }
    // Burns resume until the tree is full again.
    // (Burn note ids hash asset/account/amount/height, so vary the amount.)
    for i in 0..3 {
        n.apply_protocol_tx(&burn(&k, &n, 10_000 + i, &dest)).unwrap();
    }
    assert_eq!(n.bridge.rail(RAIL_BTC4).unwrap().bitvm2_claim_leaves.len(), 16);
    assert_eq!(n.defi.asset_bal("alice", RAIL_BTC4), 1_000_000 - 30_003);
    let e = n.btc4_withdraw("alice", 10_000, &dest).unwrap_err();
    assert!(e.contains(BITVM2_CLAIM_TREE_FULL));
}

#[test]
fn in_window_claim_keeps_its_leaf_until_the_challenge_window_closes() {
    use crate::bitvm2_exit::Bitvm2Status as S;
    let (_k, mut n, dest) = setup();
    let posted = fill_claims(&mut n, &dest, 0, 300);
    n.bitvm2_leaf_prune_from_height = 0;
    let window = crate::bridge_operators::BITVM2_PAYOUT_FINALITY_LEDGERS;
    // Ledger 300 + window - 1: still ClaimPosted -> kept.
    n.tip_height = 300 + window - 2;
    n.bridge_finalize_claims();
    let r = n.bridge.rail(RAIL_BTC4).unwrap();
    assert_eq!(r.bitvm2_claims[&posted].status, S::ClaimPosted);
    assert_eq!(r.bitvm2_claim_leaves.len(), 16);
    // Ledger 300 + window: PaidOptimistic and pruned in the same ledger.
    n.tip_height = 300 + window - 1;
    n.bridge_finalize_claims();
    let r = n.bridge.rail(RAIL_BTC4).unwrap();
    assert_eq!(r.bitvm2_claims[&posted].status, S::PaidOptimistic);
    assert_eq!(r.bitvm2_claim_leaves.len(), 15);
    assert!(!r.bitvm2_claim_leaves.contains(&r.bitvm2_claims[&posted].mimc_leaf_hex));
}

#[test]
fn stuck_burns_apply_once_after_activation_and_never_double_debit() {
    let (k, mut n, dest) = setup();
    fill_claims(&mut n, &dest, 2, 300);
    // Two different burns signed at the same sequence (loadtest03: e4eb466a + 6acd94ca).
    let a = burn(&k, &n, 10_000, &dest);
    let pk2 = crate::btc_tx::compressed_pubkey_from_secret(&[4u8; 32]).unwrap();
    let dest2 = crate::vault::p2wpkh_testnet_address(&pk2).unwrap();
    let b = burn(&k, &n, 10_000, &dest2);
    assert_eq!(a.sequence, b.sequence);
    // Before activation the packer's dry run fails and leaves the queued head
    // (transient, prune scheduled later); nothing is debited.
    n.bitvm2_leaf_prune_from_height = n.tip_height + 5;
    let e = n.dry_run_head(&a).unwrap_err();
    assert!(crate::bridge::is_bitvm2_claim_tree_full(&e), "{e}");
    assert!(!n.is_permanent_tx_failure_here(&e));
    assert_eq!(n.defi.asset_bal("alice", RAIL_BTC4), 1_000_000);
    assert_eq!(n.state.get("alice").sequence, a.sequence);
    n.bitvm2_leaf_prune_from_height = n.tip_height + 1;
    n.bridge_finalize_claims();
    n.apply_protocol_tx(&a).unwrap();
    assert!(n.apply_protocol_tx(&b).is_err(), "same sequence must not apply twice");
    assert_eq!(n.defi.asset_bal("alice", RAIL_BTC4), 1_000_000 - 10_000);
}

#[test]
fn non_full_burn_still_admitted() {
    let (k, mut n, dest) = setup();
    fill_leaves(&mut n, 3);
    assert!(n.submit_tx(burn(&k, &n, 10_000, &dest)).unwrap());
}

/// Replay the live 14 Nov 2026 v1 snapshot (tip 888601, BTC4 tree 16/16) and
/// the stuck mempool burns. Ignored: needs `BURN_SNAP` (snapshot JSON) and
/// `BURN_TXS` (JSON array of the stuck txs), e.g. /workspace/burn-dbg.
#[test]
#[ignore]
fn snapshot_replay_14nov_tree_full() {
    use crate::bitvm2_exit::Bitvm2Status as S;
    let snap = std::env::var("BURN_SNAP").expect("BURN_SNAP");
    let txp = std::env::var("BURN_TXS").expect("BURN_TXS");
    let scheme = {
        let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&snap).unwrap()).unwrap();
        CryptoScheme::parse(v["cfg"]["scheme"].as_str().unwrap()).unwrap()
    };
    let base = Node::load_snapshot(&snap, KeyRing::new(scheme)).unwrap();
    let txs: Vec<Tx> = serde_json::from_str(&std::fs::read_to_string(&txp).unwrap()).unwrap();
    println!("tip {} net {} txs {}", base.tip_height, base.cfg.network_id, txs.len());
    assert_eq!(base.bitvm2_leaf_prune_from_height, u64::MAX, "2300 placeholder: not scheduled");

    // 1. Before activation: consensus unchanged, every burn hits the full tree,
    // and with no prune scheduled the packer may drop it (never debited).
    let mut pre = Node::load_snapshot(&snap, KeyRing::new(scheme)).unwrap();
    let rail0 = serde_json::to_value(pre.bridge.rail(RAIL_BTC4).unwrap()).unwrap();
    for tx in &txs {
        let e = pre.dry_run_head(tx).unwrap_err();
        println!("pre  {} {} seq {}: {e}", &tx.tx_id[..8], tx.account, tx.sequence);
        assert!(crate::bridge::is_bitvm2_claim_tree_full(&e), "{e}");
        assert!(pre.is_permanent_tx_failure_here(&e));
    }
    pre.bridge_finalize_claims();
    assert_eq!(serde_json::to_value(pre.bridge.rail(RAIL_BTC4).unwrap()).unwrap(), rail0);

    // 2. Activation at the next ledger: settled leaves freed, burns apply in
    // mempool order until full again; one debit per account sequence.
    let mut n = Node::load_snapshot(&snap, KeyRing::new(scheme)).unwrap();
    n.bitvm2_leaf_prune_from_height = n.tip_height + 1;
    assert!(!n.is_permanent_tx_failure_here("bitvm2 claim tree full (16/16) on BTC4"));
    n.bridge_finalize_claims();
    let freed = 16 - n.bridge.rail(RAIL_BTC4).unwrap().bitvm2_claim_leaves.len();
    println!("post freed {freed}");
    assert_eq!(freed, 3, "refunded + 2 paid_optimistic");
    let mut applied = Vec::new();
    for tx in &txs {
        let bal0 = n.defi.asset_bal(&tx.account, RAIL_BTC4);
        match n.dry_run_head(tx) {
            Ok(()) => {
                n.apply_protocol_tx(tx).unwrap();
                let TxBody::RailWithdraw { amount, .. } = &tx.body else { panic!() };
                assert_eq!(n.defi.asset_bal(&tx.account, RAIL_BTC4), bal0 - amount);
                println!("post {} {} seq {}: applied", &tx.tx_id[..8], tx.account, tx.sequence);
                applied.push(tx.tx_id.clone());
            }
            Err(e) => println!("post {} {} seq {}: {e}", &tx.tx_id[..8], tx.account, tx.sequence),
        }
    }
    assert_eq!(applied.len(), 3);
    assert_eq!(n.bridge.rail(RAIL_BTC4).unwrap().bitvm2_claim_leaves.len(), 16);

    // 3. Every in-window claim survives Disprove in stored-root mode.
    let vk = base.bitvm2_vk.clone();
    let r = base.bridge.rail(RAIL_BTC4).unwrap();
    let posted: Vec<String> =
        r.bitvm2_claims.values().filter(|c| c.status == S::ClaimPosted).map(|c| c.note_id.clone()).collect();
    let pruned = n.bridge.rail(RAIL_BTC4).unwrap();
    let (mut live_bad, mut stored_bad) = (0, 0);
    for note in &posted {
        if r.clone().disprove_bitvm2_v2_ex(note, &vk, false).unwrap() {
            live_bad += 1;
        }
        if pruned.clone().disprove_bitvm2_v2_ex(note, &vk, true).unwrap() {
            stored_bad += 1;
        }
    }
    println!("claim_posted {}: live-tree disprove {live_bad}, stored-root disprove {stored_bad}", posted.len());
    assert_eq!(posted.len(), 13);
    assert_eq!(stored_bad, 0);
}
