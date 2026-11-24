// Copyright (c) 2025-2026 BEARTEC. All rights reserved. See LICENSE.
//! BRIDGE testnet4 rail (`BTC4`): created at the bridge height, anchored at
//! the hard-coded checkpoint, graph-bound peg-in mint (>= 6 confs, depositor
//! fixed at bind, all active operators), burn -> BitVM2 claim, refund.

use super::*;
use crate::bridge::{RailHeader, RailState, BTC4_CHECKPOINT_HASH, BTC4_CHECKPOINT_HEIGHT, RAIL_BTC4};

const K_OP1: &str = "11111111111111111111111111111111111111111111111111111111111111aa";
const K_OP2: &str = "22222222222222222222222222222222222222222222222222222222222222bb";
/// testnet4 155,232 (retarget, the checkpoint) and 155,233 (min-diff child).
const H155232: &str = "00c01133a4b225a064922585bd9db58ad1cb7127031c8ba15252c0db7a31cc00000000007f6bf7535d4eb0882eb99466ccacdc6f6848c61d4936aec2e67c75e233f7c363e397c36a437e0319e11e4279";
const H155233: &str = "00e0af205b34402d570eb429969799fe0dc8d2228b407501b9c54d31020000000000000011ca71278ff660f87af4e7bdbfe5e36e747bfcfe30328ef12a278f157afa37e0949cc36affff001d16018045";

fn ring() -> KeyRing {
    let mut k = KeyRing::new(CryptoScheme::HmacDev);
    k.generate_many(["alice", "bob", "op1", "op2", "w", "v1"]);
    k
}

fn node(k: &KeyRing) -> Node {
    let cfg = ChainConfig { min_fee: 0, first_claim_epoch: 1, ..Default::default() };
    let mut n = Node::new(
        "v1",
        cfg,
        k.clone(),
        &[("alice".into(), 1_000_000), ("bob".into(), 1_000_000), ("op1".into(), 1_000_000), ("op2".into(), 1_000_000), ("w".into(), 1_000_000)],
    );
    n.register_validator("v1", 1000);
    n
}

fn send(n: &mut Node, k: &KeyRing, who: &str, amount: u64, body: TxBody) -> Result<(), String> {
    let seq = n.state.get(who).sequence;
    let tx = Tx::sign_body(k, who, seq, "", amount, 0, n.cfg.network_id, body).unwrap();
    n.apply_protocol_tx(&tx)
}

fn raw_tx(inputs: &[(&str, u32)], outputs: &[(u64, Vec<u8>)]) -> Vec<u8> {
    let mut b = vec![2, 0, 0, 0];
    b.push(inputs.len() as u8);
    for (txid, vout) in inputs {
        let mut t = hex::decode(txid).unwrap();
        t.reverse();
        b.extend_from_slice(&t);
        b.extend_from_slice(&vout.to_le_bytes());
        b.push(0);
        b.extend_from_slice(&[0xff; 4]);
    }
    b.push(outputs.len() as u8);
    for (v, spk) in outputs {
        b.extend_from_slice(&v.to_le_bytes());
        b.push(spk.len() as u8);
        b.extend_from_slice(spk);
    }
    b.extend_from_slice(&[0; 4]);
    b
}

fn mine4(n: &mut Node, raw: &[u8], h: u64, tip: u64) -> String {
    let tx = crate::btc_spv::parse_tx(raw).unwrap();
    let r = n.bridge.rail_mut(RAIL_BTC4).unwrap();
    for x in h..=tip {
        let root = if x == h { tx.txid_display.clone() } else { "00".repeat(32) };
        let mut hdr = RailHeader::fixture(x, format!("{x:064x}"), format!("{:064x}", x - 1), root);
        hdr.raw = "00".repeat(80);
        r.headers.make_mut().insert(x, hdr);
    }
    r.tip_height = r.tip_height.max(tip);
    tx.txid_display
}

fn pegin(raw: &[u8], h: u64) -> TxBody {
    TxBody::Btc4PegIn { raw_tx_hex: hex::encode(raw), btc_height: h, merkle_path: vec![], merkle_index: 0 }
}

fn bind(dep: &str, k2: &str, af: &str, who: &str) -> TxBody {
    TxBody::OperatorGraphBind {
        deposit_txid: dep.into(),
        kick_off_2_txid: k2.into(),
        assert_final_txid: af.into(),
        depositor_account: who.into(),
        cosign: false,
    }
}

fn armed() -> (KeyRing, Node) {
    let k = ring();
    let mut n = node(&k);
    n.bitvm2_m1_from_height = 0;
    n.tip_height = 300;
    n.bridge.rails.insert(RAIL_BTC4.into(), RailState::new_btc4());
    for (a, x) in [("op1", K_OP1), ("op2", K_OP2)] {
        send(&mut n, &k, a, 5_000, TxBody::OperatorRegister {
            btc_xonly: x.into(),
            reward_spk_hex: String::new(),
            gossip_url: String::new(),
            capacity_sats: 1_000_000,
        })
        .unwrap();
    }
    (k, n)
}

#[test]
fn btc4_rail_absent_and_bodies_refused_before_the_height() {
    let k = ring();
    let mut n = node(&k);
    assert_eq!(n.bitvm2_m1_from_height, u64::MAX);
    let mut b = n.bridge.clone();
    n.prune_eth_exec_for_ledger(&mut b, 301);
    assert!(b.rail(RAIL_BTC4).is_err(), "no BTC4 rail before the bridge height");
    let e = send(&mut n, &k, "w", 0, pegin(&[0], 1)).unwrap_err();
    assert!(e.contains("bridge not active"), "{e}");
    assert!(n.rail_withdraw_full(RAIL_BTC4, "alice", 1, "tb1qxyz", None, None).unwrap_err().contains("bridge not active"));
    let v = serde_json::to_value(&n.bridge).unwrap();
    assert!(!v["rails"].as_object().unwrap().contains_key(RAIL_BTC4));
}

#[test]
fn btc4_rail_created_at_height_and_anchors_only_at_checkpoint() {
    let k = ring();
    let mut n = node(&k);
    n.bitvm2_m1_from_height = 500;
    let mut b = n.bridge.clone();
    n.prune_eth_exec_for_ledger(&mut b, 499);
    assert!(b.rail(RAIL_BTC4).is_err());
    n.prune_eth_exec_for_ledger(&mut b, 500);
    let r = b.rail_mut(RAIL_BTC4).unwrap();
    assert_eq!(r.btc_checkpoint, Some((BTC4_CHECKPOINT_HEIGHT, BTC4_CHECKPOINT_HASH.to_string())));
    let hdr = |h: u64, raw: &str| RailHeader { height: h, hash: String::new(), parent_hash: String::new(), merkle_root: String::new(), raw: raw.into() };
    // wrong height / wrong header refused as first header
    assert!(r.submit_header_ex(hdr(155_233, H155233), true).is_err());
    assert!(r.clone().submit_header_ex(hdr(155_232, H155233), false).is_err());
    r.submit_header_ex(hdr(155_232, H155232), true).unwrap();
    r.submit_header_ex(hdr(155_233, H155233), true).unwrap();
    assert_eq!(r.tip_height, 155_233);
    // (state-reset sanity: the checkpoint header still anchors a cleared rail)
    let mut r2 = r.clone();
    r2.headers.make_mut().clear();
    r2.tip_height = 0;
    r2.submit_header_ex(hdr(155_232, H155232), true).unwrap();
    // legacy BTC rail keeps its frozen-checkpoint rule
    assert!(b.rail(crate::bridge::RAIL_BTC).is_ok());
}

#[test]
fn btc4_peg_in_mints_to_bound_depositor_then_withdraw_and_refund() {
    let (k, mut n) = armed();
    let spk = {
        let mut s = vec![0x00, 0x20];
        s.extend([7u8; 32]);
        s
    };
    let confirm = raw_tx(&[(&"ab".repeat(32), 0)], &[(50_000, spk.clone())]);
    let dep = crate::btc_spv::parse_tx(&confirm).unwrap().txid_display;
    // unbound: refused
    mine4(&mut n, &confirm, 157_000, 157_010);
    assert!(send(&mut n, &k, "w", 0, pegin(&confirm, 157_000)).unwrap_err().contains("not every active operator"));
    // only one operator bound: refused
    send(&mut n, &k, "op1", 0, bind(&dep, &"11".repeat(32), &"12".repeat(32), "alice")).unwrap();
    assert!(send(&mut n, &k, "w", 0, pegin(&confirm, 157_000)).unwrap_err().contains("not every active operator"));
    // depositor must be a Falcon account
    assert!(send(&mut n, &k, "op2", 0, bind(&dep, &"21".repeat(32), &"22".repeat(32), "nobody")).unwrap_err().contains("not a Falcon account"));
    // disagreeing depositor: refused
    send(&mut n, &k, "op2", 0, bind(&dep, &"21".repeat(32), &"22".repeat(32), "bob")).unwrap();
    assert!(send(&mut n, &k, "w", 0, pegin(&confirm, 157_000)).unwrap_err().contains("different depositor"));

    // fresh deposit, both agree
    let confirm2 = raw_tx(&[(&"cd".repeat(32), 1)], &[(60_000, spk.clone())]);
    let dep2 = crate::btc_spv::parse_tx(&confirm2).unwrap().txid_display;
    send(&mut n, &k, "op1", 0, bind(&dep2, &"31".repeat(32), &"32".repeat(32), "alice")).unwrap();
    send(&mut n, &k, "op2", 0, bind(&dep2, &"41".repeat(32), &"42".repeat(32), "alice")).unwrap();
    // 5 confs: refused
    mine4(&mut n, &confirm2, 157_100, 157_104);
    assert!(send(&mut n, &k, "w", 0, pegin(&confirm2, 157_100)).unwrap_err().contains("confirmations"));
    mine4(&mut n, &confirm2, 157_100, 157_105);
    let b0 = n.defi.asset_bal("alice", RAIL_BTC4);
    // submitter (w) is irrelevant: mint goes to the bound depositor
    send(&mut n, &k, "w", 0, pegin(&confirm2, 157_100)).unwrap();
    assert_eq!(n.defi.asset_bal("alice", RAIL_BTC4), b0 + 60_000);
    assert_eq!(n.defi.asset_bal("w", RAIL_BTC4), 0);
    assert_eq!(n.bridge.rail(RAIL_BTC4).unwrap().total_minted, 60_000);
    assert!(send(&mut n, &k, "w", 0, pegin(&confirm2, 157_100)).unwrap_err().contains("already minted"));
    // legacy BTC balance untouched
    assert_eq!(n.defi.asset_bal("alice", crate::bridge::RAIL_BTC), 0);

    // withdraw: burn BTC4 -> AwaitingPegout claim on the BTC4 rail
    let pk = crate::btc_tx::compressed_pubkey_from_secret(&[3u8; 32]).unwrap();
    let dest = crate::vault::p2wpkh_testnet_address(&pk).unwrap();
    send(&mut n, &k, "alice", 0, TxBody::RailWithdraw {
        asset: RAIL_BTC4.into(),
        amount: 20_000,
        external_to: dest.clone(),
        vault_sig: String::new(),
        signed_btc_tx: String::new(),
    })
    .unwrap();
    assert_eq!(n.defi.asset_bal("alice", RAIL_BTC4), b0 + 40_000);
    let note = {
        let r = n.bridge.rail(RAIL_BTC4).unwrap();
        assert_eq!(r.bitvm2_claims.len(), 1);
        let c = r.bitvm2_claims.values().next().unwrap();
        assert_eq!(c.status, crate::bitvm2_exit::Bitvm2Status::AwaitingPegout);
        assert_eq!((c.amount, c.dest.as_str()), (20_000, dest.as_str()));
        c.note_id.clone()
    };
    assert_eq!(n.bitvm2_rail_for_note(&note), RAIL_BTC4);
    assert!(n.bridge.rail(crate::bridge::RAIL_BTC).unwrap().bitvm2_claims.get(&note).is_none());
    // overdraw refused
    assert!(n.btc4_withdraw("alice", 1_000_000, &dest).is_err());
    // unpaid -> refunded in BTC4 after the window
    n.tip_height += crate::bridge_operators::BITVM2_PEGOUT_REFUND_LEDGERS + 1;
    n.bridge_finalize_claims();
    assert_eq!(n.bridge.rail(RAIL_BTC4).unwrap().bitvm2_claims[&note].status, crate::bitvm2_exit::Bitvm2Status::Refunded);
    assert_eq!(n.defi.asset_bal("alice", RAIL_BTC4), b0 + 60_000);
}

/// Real BitVM2 graph from the private-signet Disprove run (sig-disprove-2):
/// peg-in confirm 08926437…, 7 real headers from its block, evidence built by
/// tools/fpl-bridge/slash_evidence.py --pegin (what the kit's peg-in hook runs).
#[test]
fn real_signet_peg_in_confirm_mints_through_the_kit_evidence_path() {
    let fx: serde_json::Value =
        serde_json::from_str(include_str!("../testdata/signet_pegin_0892643760.json")).unwrap();
    let k = ring();
    let mut n = node(&k);
    n.bitvm2_m1_from_height = 0;
    n.tip_height = 300;
    let hdrs = fx["headers"].as_array().unwrap();
    let first = crate::btc_spv::parse_header_hex(hdrs[0]["raw"].as_str().unwrap()).unwrap();
    let mut rail = RailState::new_btc4();
    // signet stands in for testnet4: same rules, checkpoint = the run's block
    rail.btc_checkpoint = Some((hdrs[0]["height"].as_u64().unwrap(), first.hash_display.clone()));
    n.bridge.rails.insert(RAIL_BTC4.into(), rail);
    for h in hdrs {
        send(&mut n, &k, "w", 0, TxBody::RailHeader {
            asset: RAIL_BTC4.into(),
            height: h["height"].as_u64().unwrap(),
            hash: String::new(),
            parent_hash: String::new(),
            merkle_root: String::new(),
            raw: h["raw"].as_str().unwrap().into(),
        })
        .unwrap();
    }
    assert_eq!(n.bridge.rail(RAIL_BTC4).unwrap().tip_height, hdrs[6]["height"].as_u64().unwrap());
    send(&mut n, &k, "op1", 5_000, TxBody::OperatorRegister {
        btc_xonly: fx["operator_xonly"].as_str().unwrap().into(),
        reward_spk_hex: String::new(),
        gossip_url: String::new(),
        capacity_sats: 3_000_000,
    })
    .unwrap();
    let body: TxBody = serde_json::from_value(fx["pegin_body"].clone()).unwrap();
    assert!(send(&mut n, &k, "w", 0, body.clone()).unwrap_err().contains("not every active operator"));
    send(&mut n, &k, "op1", 0, bind(
        fx["deposit_txid"].as_str().unwrap(),
        fx["kick_off_2_txid"].as_str().unwrap(),
        fx["assert_final_txid"].as_str().unwrap(),
        "alice",
    ))
    .unwrap();
    send(&mut n, &k, "w", 0, body.clone()).unwrap();
    assert_eq!(n.defi.asset_bal("alice", RAIL_BTC4), 2_097_152);
    assert!(send(&mut n, &k, "w", 0, body).unwrap_err().contains("already minted"));
}

#[test]
fn btc4_lead_graph_plus_cosigners_mint_and_cosign_not_slashable() {
    let (k, mut n) = armed();
    let spk = {
        let mut s = vec![0x51, 0x20];
        s.extend([9u8; 32]);
        s
    };
    let confirm = raw_tx(&[(&"ef".repeat(32), 0)], &[(30_000, spk)]);
    let dep = crate::btc_spv::parse_tx(&confirm).unwrap().txid_display;
    let (k2, af) = ("51".repeat(32), "52".repeat(32));
    let cosign = |who: &str| TxBody::OperatorGraphBind {
        deposit_txid: dep.clone(),
        kick_off_2_txid: k2.clone(),
        assert_final_txid: af.clone(),
        depositor_account: who.into(),
        cosign: true,
    };
    // cosign before the operator graph is bound: refused
    assert!(send(&mut n, &k, "op2", 0, cosign("alice")).unwrap_err().contains("no operator graph"));
    send(&mut n, &k, "op1", 0, bind(&dep, &k2, &af, "alice")).unwrap();
    // co-signer may not re-bind the same txids as its own graph
    assert!(send(&mut n, &k, "op2", 0, bind(&dep, &k2, &af, "alice")).unwrap_err().contains("already bound"));
    send(&mut n, &k, "op2", 0, cosign("alice")).unwrap();
    mine4(&mut n, &confirm, 157_200, 157_206);
    send(&mut n, &k, "w", 0, pegin(&confirm, 157_200)).unwrap();
    assert_eq!(n.defi.asset_bal("alice", RAIL_BTC4), 30_000);
    // a Disprove of this graph cannot slash the co-signer
    let e = send(&mut n, &k, "w", 0, TxBody::OperatorSlash {
        operator_btc_xonly: K_OP2.into(),
        deposit_txid: dep.clone(),
        raw_tx_hex: hex::encode(&confirm),
        btc_height: 157_200,
        merkle_path: vec![],
        merkle_index: 0,
    })
    .unwrap_err();
    assert!(e.contains("co-signer"), "{e}");
}
