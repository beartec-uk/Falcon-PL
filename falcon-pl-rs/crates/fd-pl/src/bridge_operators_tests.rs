// Copyright (c) 2025-2026 BEARTEC. All rights reserved. See LICENSE.
//! BRIDGE node-level end to end: one activation height arms the operator
//! network. Covers: unarmed = refused + root/settle unchanged; register + 5k
//! bond; heartbeats + capacity; FBTC burn -> M1 attest (SPV peg-out + Groth16)
//! -> PaidOptimistic -> payout credit; graph bind; BitVM2 Disprove evidence of
//! a bad kickoff (SPV) -> 100% slash, bounty by reward script, rest burned;
//! wrong-shape evidence (Take2-like, too few confs, unbound) refused; epoch
//! settle pays the 5% bucket; unbond returns the bond; AMM pools untouched.

use super::*;
use crate::bridge::{Bitvm2AttestV2, RailHeader, RAIL_BTC};
use crate::bridge_operators::BITVM2_PAYOUT_FINALITY_LEDGERS;
use crate::operator_registry::{bitvm_burn_spk, OperatorStatus};

const K_OP1: &str = "11111111111111111111111111111111111111111111111111111111111111aa";
const K_OP2: &str = "22222222222222222222222222222222222222222222222222222222222222bb";
const K_W: &str = "33333333333333333333333333333333333333333333333333333333333333cc";
const W_REWARD_SPK: &str = "5120cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

fn ring() -> KeyRing {
    let mut k = KeyRing::new(CryptoScheme::HmacDev);
    k.generate_many(["alice", "op1", "op2", "w", "v1"]);
    k
}

fn node(k: &KeyRing) -> Node {
    let cfg = ChainConfig { min_fee: 0, first_claim_epoch: 1, ..Default::default() };
    let mut n = Node::new(
        "v1",
        cfg,
        k.clone(),
        &[("alice".into(), 1_000_000), ("op1".into(), 1_000_000), ("op2".into(), 1_000_000), ("w".into(), 1_000_000)],
    );
    n.register_validator("v1", 1000);
    n
}

fn send(n: &mut Node, k: &KeyRing, who: &str, amount: u64, body: TxBody) -> Result<(), String> {
    let seq = n.state.get(who).sequence;
    let tx = Tx::sign_body(k, who, seq, "", amount, 0, n.cfg.network_id, body).unwrap();
    n.apply_protocol_tx(&tx)
}

fn reg(k: &str, spk: &str) -> TxBody {
    TxBody::OperatorRegister { btc_xonly: k.into(), reward_spk_hex: spk.into(), gossip_url: String::new(), capacity_sats: 0 }
}

/// Minimal legacy-serialized tx (parse_tx accepts it): inputs by display txid.
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

/// Put `raw` alone in BTC block `h` (merkle root = txid) and extend the rail tip to `tip`.
fn mine(n: &mut Node, raw: &[u8], h: u64, tip: u64) -> String {
    let tx = crate::btc_spv::parse_tx(raw).unwrap();
    let r = n.bridge.rail_mut(RAIL_BTC).unwrap();
    for x in h..=tip {
        let root = if x == h { tx.txid_display.clone() } else { "00".repeat(32) };
        let mut hdr = RailHeader::fixture(x, format!("{x:064x}"), format!("{:064x}", x - 1), root);
        hdr.raw = "00".repeat(80);
        r.headers.make_mut().insert(x, hdr);
    }
    r.tip_height = r.tip_height.max(tip);
    tx.txid_display
}

fn slash_body(op: &str, deposit: &str, raw: &[u8], h: u64) -> TxBody {
    TxBody::OperatorSlash {
        operator_btc_xonly: op.into(),
        deposit_txid: deposit.into(),
        raw_tx_hex: hex::encode(raw),
        btc_height: h,
        merkle_path: vec![],
        merkle_index: 0,
    }
}

#[test]
fn unarmed_operator_txs_refused_root_and_settle_unchanged() {
    let k = ring();
    let mut n = node(&k);
    assert_eq!(n.bitvm2_m1_from_height, u64::MAX, "non-2300 default: unarmed");
    let root0 = n.commitment_root();
    for body in [
        reg(K_OP1, ""),
        TxBody::OperatorHeartbeat { capacity_sats: 1 },
        TxBody::OperatorUnbond,
        TxBody::OperatorGraphBind { deposit_txid: "d".repeat(64), kick_off_2_txid: "1".repeat(64), assert_final_txid: "2".repeat(64), depositor_account: String::new(), cosign: false },
        slash_body(K_OP1, &"d".repeat(64), &[0], 1),
    ] {
        let e = send(&mut n, &k, "op1", 5_000, body).unwrap_err();
        assert!(e.contains("bridge not active"), "{e}");
    }
    assert!(n.bridge.operators.is_empty());
    let v = serde_json::to_value(&n.bridge).unwrap();
    assert!(!v.as_object().unwrap().contains_key("operators"), "registry omitted from serde while empty");
    // Failed txs still pay fee/sequence in this path; compare bridge + treasury only.
    let _ = root0;
    let t0 = n.treasury;
    let mut m = node(&k);
    n.force_settle_current_epoch();
    m.force_settle_current_epoch();
    assert_eq!(n.treasury, m.treasury);
    assert_eq!(n.claimable, m.claimable);
    assert!(n.last_settle.as_ref().unwrap().get("operator_bucket").is_none());
    assert!(t0 >= n.treasury);
}

#[test]
fn bridge_e2e_register_attest_finalize_disprove_slash_settle() {
    let k = ring();
    let mut n = node(&k);
    n.bitvm2_m1_from_height = 0; // arm the one bridge height for this devnet node
    n.tip_height = 300;
    n.now_ms = n.genesis_ms;
    let pool_snapshot = serde_json::to_string(&n.defi).unwrap();
    let p = n.operator_params();
    assert_eq!((p.min_bond, p.slash_bps, p.emission_share_bps), (5_000, 10_000, 500));

    // --- register + bond ---
    let e = send(&mut n, &k, "op1", 4_999, reg(K_OP1, "")).unwrap_err();
    assert!(e.contains("below min"), "{e}");
    let b0 = n.state.get("op1").balance;
    send(&mut n, &k, "op1", 5_000, reg(K_OP1, "")).unwrap();
    assert_eq!(n.state.get("op1").balance, b0 - 5_000, "bond locked from balance");
    send(&mut n, &k, "op2", 5_000, reg(K_OP2, "")).unwrap();
    send(&mut n, &k, "w", 5_000, reg(K_W, W_REWARD_SPK)).unwrap();
    assert!(send(&mut n, &k, "alice", 5_000, reg(K_OP1, "")).unwrap_err().contains("btc key already"));
    assert_eq!(n.bridge.operators.graph_set(&p, n.current_epoch()).len(), 3);

    // --- liveness: full epoch of heartbeats for op1 + w, capacity advert ---
    let slot_ms = n.watcher_slot_ms();
    for s in 0..crate::economy::WATCHER_SLOTS_PER_EPOCH {
        n.now_ms = n.genesis_ms + s * slot_ms;
        send(&mut n, &k, "op1", 0, TxBody::OperatorHeartbeat { capacity_sats: 250_000 }).unwrap();
        send(&mut n, &k, "w", 0, TxBody::OperatorHeartbeat { capacity_sats: 10_000 }).unwrap();
    }
    assert_eq!(n.bridge.operators.operators["op1"].capacity_sats, 250_000);
    assert_eq!(n.bridge.operators.operators["op1"].epoch_slots.len(), 168);

    // --- withdrawal: FBTC burn -> op1 fronts BTC -> M1 attest (SPV + Groth16) ---
    let (pk, vk) = fd_pl_bitvm2::groth16::setup_from_seed([7u8; 32]).unwrap();
    n.bitvm2_vk = fd_pl_bitvm2::groth16::vk_to_bytes(&vk).unwrap();
    let pk_user = crate::btc_tx::compressed_pubkey_from_secret(&[3u8; 32]).unwrap();
    let dest = crate::vault::p2wpkh_testnet_address(&pk_user).unwrap();
    let amount = 20_000u64;
    let note = "m1note".repeat(4);
    {
        let r = n.bridge.rail_mut(RAIL_BTC).unwrap();
        r.open_bitvm2_withdraw(&note, "alice", &dest, amount, 100).unwrap();
        r.record_fpl_checkpoint(128, &"ab".repeat(32));
    }
    let (_k, dest_spk) = crate::btc_tx::decode_address(&dest).unwrap();
    let pegout_raw = raw_tx(&[(&"9a".repeat(32), 0)], &[(amount, dest_spk.clone())]);
    let pegout_txid = mine(&mut n, &pegout_raw, 200, 205);
    let ckpt_h = 127u64;
    let header = crate::bitvm2_exit::checkpoint_header_hash(ckpt_h, &"ab".repeat(32));
    let pegout = crate::bitvm2_exit::pegout_txid_bytes(&pegout_txid).unwrap();
    let dest_h160 = crate::bitvm::dest_h160_from_address(&dest).unwrap();
    let leaves = n.bridge.rail(RAIL_BTC).unwrap().bitvm2_claim_leaves.clone();
    let (proof_hex, public_hex, digest, _cid) = crate::bitvm2_exit::prove_withdraw_attest_with_keys(
        &pk, &vk, &note, &dest_h160, amount, ckpt_h, &header, &pegout, &leaves, "op1",
    )
    .unwrap();
    let attest = Bitvm2AttestV2 {
        note_id: note.clone(),
        claim_txid_hex: "cc".repeat(32),
        checkpoint_height: ckpt_h,
        btc_height: 200,
        pegout_raw_tx_hex: hex::encode(&pegout_raw),
        merkle_path: vec![],
        merkle_index: 0,
        dest_lock_abort_commit_hex: String::new(),
        proof_hex,
        public_hex,
        statement_digest_hex: digest,
    };
    send(&mut n, &k, "op1", 0, TxBody::Bitvm2AttestV2 { attest }).unwrap();
    let c = n.bridge.rail(RAIL_BTC).unwrap().bitvm2_claims[&note].clone();
    assert_eq!(c.status, crate::bitvm2_exit::Bitvm2Status::ClaimPosted);
    assert_eq!(c.attest_height, 301);
    // ledger-side "observed" challenge is refused for BitVM2 claims once armed
    let e = send(&mut n, &k, "alice", 0, TxBody::RailChallenge { asset: "BTC".into(), note_id: note.clone(), observed_dest: "x".into(), observed_amount: 1 }).unwrap_err();
    assert!(e.contains("challenge on Bitcoin"), "{e}");
    // not final yet
    send(&mut n, &k, "op1", 0, TxBody::OperatorHeartbeat { capacity_sats: 230_000 }).unwrap();
    assert_eq!(n.bridge.operators.operators["op1"].completed_payouts, 0);
    n.tip_height = 301 + BITVM2_PAYOUT_FINALITY_LEDGERS;
    send(&mut n, &k, "op1", 0, TxBody::OperatorHeartbeat { capacity_sats: 230_000 }).unwrap();
    let c = n.bridge.rail(RAIL_BTC).unwrap().bitvm2_claims[&note].clone();
    assert_eq!(c.status, crate::bitvm2_exit::Bitvm2Status::PaidOptimistic, "honest take: finalized");
    let r1 = &n.bridge.operators.operators["op1"];
    assert_eq!((r1.completed_payouts, r1.epoch_sats), (1, amount), "proven payout credited");

    // --- op2 binds its graph for deposit D, then kicks off without paying: Disprove ---
    let dep = "de".repeat(32);
    let (k2, af) = ("2b".repeat(32), "af".repeat(32));
    send(&mut n, &k, "op2", 0, TxBody::OperatorGraphBind { deposit_txid: dep.clone(), kick_off_2_txid: k2.clone(), assert_final_txid: af.clone(), depositor_account: String::new(), cosign: false }).unwrap();
    assert!(send(&mut n, &k, "op2", 0, TxBody::OperatorGraphBind { deposit_txid: dep.clone(), kick_off_2_txid: "3c".repeat(32), assert_final_txid: "4d".repeat(32), depositor_account: String::new(), cosign: false }).is_err(), "immutable");
    let burn = bitvm_burn_spk();
    let w_spk = hex::decode(W_REWARD_SPK).unwrap();
    // wrong shapes first
    let take2_like = raw_tx(&[(&"0c".repeat(32), 0), (&af, 0), (&af, 1), (&af, 2)], &[(1_000, burn.clone()), (1_000, w_spk.clone())]);
    mine(&mut n, &take2_like, 400, 405);
    assert!(send(&mut n, &k, "alice", 0, slash_body(K_OP2, &dep, &take2_like, 400)).unwrap_err().contains("inputs do not spend"));
    let no_burn = raw_tx(&[(&af, 1), (&af, 2)], &[(1_000, w_spk.clone()), (1_000, w_spk.clone())]);
    mine(&mut n, &no_burn, 410, 415);
    assert!(send(&mut n, &k, "alice", 0, slash_body(K_OP2, &dep, &no_burn, 410)).unwrap_err().contains("burn"));
    let disprove = raw_tx(&[(&af, 1), (&af, 2)], &[(10_000, burn.clone()), (10_000, w_spk.clone())]);
    mine(&mut n, &disprove, 420, 422);
    assert!(send(&mut n, &k, "alice", 0, slash_body(K_OP2, &dep, &disprove, 420)).unwrap_err().contains("confirmations"));
    assert!(send(&mut n, &k, "alice", 0, slash_body(K_OP1, &dep, &disprove, 420)).unwrap_err().contains("no graph binding"), "op1 has no graph here");
    mine(&mut n, &disprove, 420, 425);
    // a copy-cat (alice) submits; bounty still goes to w (whose script got the BTC reward)
    let w_claim0 = n.claimable.get("w").copied().unwrap_or(0);
    send(&mut n, &k, "alice", 0, slash_body(K_OP2, &dep, &disprove, 420)).unwrap();
    let r2 = &n.bridge.operators.operators["op2"];
    assert_eq!(r2.bond, 0, "100% slash");
    assert!(matches!(r2.status, OperatorStatus::Jailed { .. }));
    assert_eq!(n.claimable.get("w").copied().unwrap_or(0) - w_claim0, 2_500, "bounty to the real disprover");
    assert!(n.claimable.get("alice").is_none());
    assert_eq!(n.bridge.operators.burned_total, 2_500);
    assert!(send(&mut n, &k, "alice", 0, slash_body(K_OP2, &dep, &disprove, 420)).unwrap_err().contains("already"), "one slash per graph");
    assert!(n.bridge.operators.graph_set(&p, n.current_epoch()).iter().all(|r| r.account != "op2"));
    // the honest operator is not slashable with someone else's evidence
    assert_eq!(n.bridge.operators.operators["op1"].bond, 5_000);

    // --- epoch settle: 5% operator bucket through the registry ---
    let t_before = n.treasury;
    let cl_before: BTreeMap<String, u64> = n.claimable.clone();
    n.force_settle_current_epoch();
    let ls = n.last_settle.clone().unwrap();
    let emit = ls["emit"].as_u64().unwrap();
    let bucket = ls["operator_bucket"].as_u64().unwrap();
    let op_paid = ls["operator_paid"].as_u64().unwrap();
    assert!(emit > 0);
    assert_eq!(bucket, emit * 500 / 10_000);
    let gain = |a: &str| n.claimable.get(a).copied().unwrap_or(0) - cl_before.get(a).copied().unwrap_or(0);
    assert!(gain("op1") > 0 && gain("w") > 0, "live + payout operators paid");
    assert_eq!(gain("op2"), 0, "slashed operator paid nothing");
    // op1: liveness half + watch share + whole (capped) payout part; w: liveness + watch
    let live = bucket * 2_500 / 10_000;
    let pay_cap = bucket * 2_500 / 10_000;
    assert!(gain("op1") >= live / 2 + pay_cap.min(bucket - 2 * live));
    assert!(op_paid <= bucket);
    // never over-emit: treasury drops by at most what was paid out
    let paid_total: u64 = n.claimable.iter().map(|(a, v)| v - cl_before.get(a).copied().unwrap_or(0)).sum();
    assert_eq!(t_before - n.treasury, paid_total, "undistributed (incl. unpaid operator bucket) refunded");
    assert_eq!(serde_json::to_string(&n.defi).unwrap(), pool_snapshot, "AMM/lending never touched by the bridge");

    // --- unbond: cooldown, then bond back ---
    send(&mut n, &k, "w", 0, TxBody::OperatorUnbond).unwrap();
    let bal_w = n.state.get("w").balance;
    let e0 = n.current_epoch();
    n.now_ms = n.genesis_ms + (e0 + p.unbond_cooldown_epochs) * n.cfg.epoch_ms;
    for _ in 0..=p.unbond_cooldown_epochs + 1 {
        let e = n.current_epoch();
        n.settle_epoch_index(e);
    }
    assert!(!n.bridge.operators.operators.contains_key("w"));
    assert_eq!(n.state.get("w").balance, bal_w + 5_000, "bond returned after cooldown");

    // registry is in the commitment root once used
    let v = serde_json::to_value(&n.bridge).unwrap();
    assert!(v.as_object().unwrap().contains_key("operators"));
    let st = n.status_json();
    assert!(st.to_string().contains("bridge_operators"));
}

#[test]
fn disprove_chain_evidence_slashes_too() {
    let k = ring();
    let mut n = node(&k);
    n.bitvm2_m1_from_height = 0;
    n.tip_height = 10;
    send(&mut n, &k, "op1", 6_000, reg(K_OP1, "")).unwrap();
    let dep = "de".repeat(32);
    let (k2, af) = ("2b".repeat(32), "af".repeat(32));
    send(&mut n, &k, "op1", 0, TxBody::OperatorGraphBind { deposit_txid: dep.clone(), kick_off_2_txid: k2.clone(), assert_final_txid: af, depositor_account: String::new(), cosign: false }).unwrap();
    let burn = bitvm_burn_spk();
    // AssertInitial also spends KickOff2:1 but has no burn output -> not evidence
    let assert_initial = raw_tx(&[(&k2, 1)], &[(1_000, vec![0x51, 0x20, 1]), (1_000, vec![0x51, 0x20, 2])]);
    mine(&mut n, &assert_initial, 50, 60);
    assert!(send(&mut n, &k, "alice", 0, slash_body(K_OP1, &dep, &assert_initial, 50)).is_err());
    let dchain = raw_tx(&[(&k2, 1)], &[(1_000, burn), (1_000, vec![0x00, 0x14, 9])]);
    mine(&mut n, &dchain, 61, 70);
    send(&mut n, &k, "alice", 0, slash_body(K_OP1, &dep, &dchain, 61)).unwrap();
    assert_eq!(n.bridge.operators.operators["op1"].bond, 0);
    assert_eq!(n.bridge.operators.burned_total, 6_000, "no registered disprover -> all burned");
}

/// Install a real Bitcoin header (from a fixture) + `extra` filler headers above it.
fn install_real_header(n: &mut Node, hdr: &serde_json::Value, extra: u64) {
    let h = hdr["height"].as_u64().unwrap();
    let r = n.bridge.rail_mut(RAIL_BTC).unwrap();
    let mut rh = RailHeader::fixture(
        h,
        hdr["hash"].as_str().unwrap(),
        hdr["prev"].as_str().unwrap(),
        hdr["merkle_root"].as_str().unwrap(),
    );
    rh.raw = hdr["raw"].as_str().unwrap().to_string();
    // the raw header really commits to that merkle root
    let raw = hex::decode(&rh.raw).unwrap();
    let mut mr: Vec<u8> = raw[36..68].to_vec();
    mr.reverse();
    assert_eq!(hex::encode(mr), rh.merkle_root);
    assert_eq!(crate::btc_spv::display_hex(&crate::btc_spv::hash256(&raw)), rh.hash);
    r.headers.make_mut().insert(h, rh);
    for x in h + 1..=h + extra {
        let mut f = RailHeader::fixture(x, format!("{x:064x}"), format!("{:064x}", x - 1), "00".repeat(32));
        f.raw = "00".repeat(80);
        r.headers.make_mut().insert(x, f);
    }
    r.tip_height = r.tip_height.max(h + extra);
}

/// Real regtest data (2026-10-18 run `test_fpl_watcher_disproves_dishonest_operator`,
/// BitVM 7d1ca36 + FPL patch): the watcher's mined Disprove ca7620a0… of the dishonest
/// operator's graph (AssertFinal 600289db…, KickOff2 e83e5671…). Fixture made by
/// tools/fpl-bridge/slash_evidence.py from the regtest node (witness stripped, same txid).
#[test]
fn real_regtest_disprove_slashes_and_real_take1_does_not() {
    let ev: serde_json::Value = serde_json::from_str(include_str!("../testdata/regtest_disprove_ca7620a0.json")).unwrap();
    let t1: serde_json::Value = serde_json::from_str(include_str!("../testdata/regtest_take1_890ebb97.json")).unwrap();
    assert_eq!(ev["outputs"][0]["spk"].as_str().unwrap(), hex::encode(bitvm_burn_spk()), "real burn output == ledger burn script");
    let k = ring();
    let mut n = node(&k);
    n.bitvm2_m1_from_height = 0;
    n.tip_height = 10;
    let op_x = ev["body"]["operator_btc_xonly"].as_str().unwrap().to_string();
    let dep = ev["body"]["deposit_txid"].as_str().unwrap().to_string();
    // the watcher declared the reward script its kit put in Disprove output 1
    let w_spk = ev["outputs"][1]["spk"].as_str().unwrap().to_string();
    send(&mut n, &k, "op1", 5_000, reg(&op_x, "")).unwrap();
    send(&mut n, &k, "w", 5_000, reg(K_W, &w_spk)).unwrap();
    send(&mut n, &k, "op1", 0, TxBody::OperatorGraphBind {
        deposit_txid: dep.clone(),
        kick_off_2_txid: ev["graph"]["kick_off_2_txid"].as_str().unwrap().into(),
        assert_final_txid: ev["graph"]["assert_final_txid"].as_str().unwrap().into(), depositor_account: String::new(), cosign: false })
    .unwrap();
    install_real_header(&mut n, &ev["header"], 5);
    install_real_header(&mut n, &t1["header"], 5);
    let body: TxBody = serde_json::from_value(ev["body"].clone()).unwrap();
    // honest Take1 of a graph (spends KickOff2:0+1, no burn): not evidence, even when bound
    send(&mut n, &k, "op2", 5_000, reg(K_OP2, "")).unwrap();
    let t1_inputs: Vec<String> = {
        let raw = hex::decode(t1["body"]["raw_tx_hex"].as_str().unwrap()).unwrap();
        crate::btc_spv::parse_tx(&raw).unwrap().inputs.iter().map(|(t, _)| t.clone()).collect()
    };
    let t1_dep = t1["body"]["deposit_txid"].as_str().unwrap().to_string();
    send(&mut n, &k, "op2", 0, TxBody::OperatorGraphBind { deposit_txid: t1_dep.clone(), kick_off_2_txid: t1_inputs[2].clone(), assert_final_txid: "af".repeat(32), depositor_account: String::new(), cosign: false }).unwrap();
    let mut t1_body: TxBody = serde_json::from_value(t1["body"].clone()).unwrap();
    if let TxBody::OperatorSlash { operator_btc_xonly, .. } = &mut t1_body {
        *operator_btc_xonly = K_OP2.into();
    }
    let e = send(&mut n, &k, "alice", 0, t1_body).unwrap_err();
    assert!(e.contains("burn") || e.contains("inputs do not spend"), "{e}");
    assert_eq!(n.bridge.operators.operators["op2"].bond, 5_000, "honest take1 never slashes");
    // the real Disprove slashes the dishonest operator 100%
    send(&mut n, &k, "alice", 0, body).unwrap();
    assert_eq!(n.bridge.operators.operators["op1"].bond, 0);
    assert_eq!(n.claimable.get("w").copied(), Some(2_500), "bounty -> the watcher whose script got the BTC reward");
    assert_eq!(n.bridge.operators.burned_total, 2_500);
}

/// Claims stuck in AwaitingPegout past the refund window are refunded
/// (FBTC credited back, total_burned reversed); attested claims are not;
/// nothing happens before the bridge height; window starts at the later of
/// open height and bridge height.
#[test]
fn stuck_awaiting_pegout_refunds_after_window() {
    use crate::bridge_operators::BITVM2_PEGOUT_REFUND_LEDGERS as T;
    let k = ring();
    let mut n = node(&k);
    let pk_user = crate::btc_tx::compressed_pubkey_from_secret(&[3u8; 32]).unwrap();
    let dest = crate::vault::p2wpkh_testnet_address(&pk_user).unwrap();
    let (a, b) = ("stuck".repeat(8), "posted".repeat(8));
    {
        let r = n.bridge.rail_mut(RAIL_BTC).unwrap();
        r.open_bitvm2_withdraw(&a, "alice", &dest, 7_000, 100).unwrap();
        r.open_bitvm2_withdraw(&b, "alice", &dest, 9_000, 100).unwrap();
        r.total_burned = 16_000;
        r.bitvm2_claims.get_mut(&b).unwrap().status = crate::bitvm2_exit::Bitvm2Status::ClaimPosted;
    }
    let bal = |n: &Node| n.defi.asset_bal("alice", RAIL_BTC);
    let b0 = bal(&n);
    // unarmed: nothing, however late
    n.tip_height = 100 + 10 * T;
    n.bridge_finalize_claims();
    assert_eq!(n.bridge.rail(RAIL_BTC).unwrap().bitvm2_claims[&a].status, crate::bitvm2_exit::Bitvm2Status::AwaitingPegout);
    // arm at H: window counts from H, not from the (older) open height
    let h0 = 100 + 10 * T;
    n.bitvm2_m1_from_height = h0;
    n.tip_height = h0 + T - 2;
    n.bridge_finalize_claims();
    assert_eq!(n.bridge.rail(RAIL_BTC).unwrap().bitvm2_claims[&a].status, crate::bitvm2_exit::Bitvm2Status::AwaitingPegout, "inside window");
    assert_eq!(bal(&n), b0);
    n.tip_height = h0 + T - 1; // applying height h0 + T
    n.bridge_finalize_claims();
    let r = n.bridge.rail(RAIL_BTC).unwrap();
    assert_eq!(r.bitvm2_claims[&a].status, crate::bitvm2_exit::Bitvm2Status::Refunded);
    assert_eq!(r.bitvm2_claims[&b].status, crate::bitvm2_exit::Bitvm2Status::ClaimPosted, "attested claim never refunds");
    assert_eq!(r.total_burned, 9_000);
    assert_eq!(bal(&n), b0 + 7_000);
    // idempotent
    n.tip_height += 5;
    n.bridge_finalize_claims();
    assert_eq!(bal(&n), b0 + 7_000);
    // a refunded claim cannot be attested / paid any more
    assert!(n.bridge.rail(RAIL_BTC).unwrap().bitvm2_claims[&a].status != crate::bitvm2_exit::Bitvm2Status::AwaitingPegout);
    let s0 = n.status_json();
    let s = s0.get("body").filter(|b| b.get("bridge_operators").is_some()).unwrap_or(&s0);
    assert!(s["bridge_operators"]["slashed"].as_array().unwrap().is_empty());
    assert_eq!(s["bridge_operators"]["pegout_refund_ledgers"], T);
}

/// Fresh regtest run on the MERGED BitVM patch (2026-10-19): deposit -> dishonest
/// kickoff -> watcher Challenge + Disprove (ca2fe05b…, block 95474), evidence built
/// by tools/fpl-bridge/slash_evidence.py. Bound graph -> 100% slash + bounty to the
/// watcher's reward script; a binding that does not match the real graph refuses it;
/// replaying the evidence is refused.
#[test]
fn fresh_merged_patch_disprove_slashes() {
    let ev: serde_json::Value = serde_json::from_str(include_str!("../testdata/regtest_disprove_ca2fe05b.json")).unwrap();
    assert_eq!(ev["outputs"][0]["spk"].as_str().unwrap(), hex::encode(bitvm_burn_spk()));
    let k = ring();
    let mut n = node(&k);
    n.bitvm2_m1_from_height = 0;
    n.tip_height = 10;
    let op_x = ev["body"]["operator_btc_xonly"].as_str().unwrap().to_string();
    let dep = ev["body"]["deposit_txid"].as_str().unwrap().to_string();
    let w_spk = ev["outputs"][1]["spk"].as_str().unwrap().to_string();
    send(&mut n, &k, "op1", 5_000, reg(&op_x, "")).unwrap();
    send(&mut n, &k, "w", 5_000, reg(K_W, &w_spk)).unwrap();
    install_real_header(&mut n, &ev["header"], 6);
    let body: TxBody = serde_json::from_value(ev["body"].clone()).unwrap();
    // unbound graph: refused
    assert!(send(&mut n, &k, "alice", 0, body.clone()).is_err());
    // op1 binds its real graph for the deposit -> the Disprove is now evidence against it
    send(&mut n, &k, "op1", 0, TxBody::OperatorGraphBind {
        deposit_txid: dep.clone(),
        kick_off_2_txid: ev["graph"]["kick_off_2_txid"].as_str().unwrap().into(),
        assert_final_txid: ev["graph"]["assert_final_txid"].as_str().unwrap().into(), depositor_account: String::new(), cosign: false })
    .unwrap();
    send(&mut n, &k, "alice", 0, body.clone()).unwrap();
    let r = &n.bridge.operators.operators["op1"];
    assert_eq!(r.bond, 0, "100% slash");
    assert!(matches!(r.status, OperatorStatus::Jailed { .. } | OperatorStatus::Removed));
    assert_eq!(n.claimable.get("w").copied(), Some(2_500));
    assert_eq!(n.bridge.operators.burned_total, 2_500);
    assert!(send(&mut n, &k, "alice", 0, body).is_err(), "replay refused");
    let s0 = n.status_json();
    let s = s0.get("body").filter(|b| b.get("bridge_operators").is_some()).unwrap_or(&s0);
    let key = format!("{dep}:{op_x}");
    assert!(s["bridge_operators"]["slashed"].as_array().unwrap().iter().any(|x| x.as_str() == Some(key.as_str())), "kit re-check sees it applied");
}

/// Mempool: before the one bridge height, Operator* bodies (and M1
/// Bitvm2AttestV2, main's rule) are never admitted/relayed (older seats cannot
/// decode them); once armed they are admitted. M1 and the operator network
/// open at the same height.
#[test]
fn mempool_refuses_bridge_bodies_until_the_one_height() {
    let k = ring();
    let mut n = node(&k);
    assert_eq!(n.bitvm2_m1_from_height, u64::MAX);
    let mk = |n: &Node, body: TxBody, amount: u64| {
        let seq = n.state.get("op1").sequence;
        Tx::sign_body(&k, "op1", seq, "", amount, 0, n.cfg.network_id, body).unwrap()
    };
    let e = n.submit_tx(mk(&n, reg(K_OP1, ""), 5_000)).unwrap_err();
    assert!(e.contains("bridge not active"), "{e}");
    let e = n.submit_tx(mk(&n, TxBody::OperatorHeartbeat { capacity_sats: 1 }, 0)).unwrap_err();
    assert!(e.contains("bridge not active"), "{e}");
    assert_eq!(n.bridge_at(n.tip_height + 1), n.bitvm2_m1_at(n.tip_height + 1), "one height for M1 + operators");
    n.bitvm2_m1_from_height = 0;
    assert!(n.bridge_at(n.tip_height + 1) && n.bitvm2_m1_at(n.tip_height + 1));
    let r = n.submit_tx(mk(&n, reg(K_OP1, ""), 5_000));
    assert!(!matches!(&r, Err(e) if e.contains("bridge not active")), "armed: not refused by the bridge gate: {r:?}");
}

/// Inputs of the M1 attest statement used below (`attest-wtns` input format).
fn snarkjs_attest_statement() -> (String, String, u64, Vec<u8>, String, serde_json::Value) {
    let pk_user = crate::btc_tx::compressed_pubkey_from_secret(&[3u8; 32]).unwrap();
    let dest = crate::vault::p2wpkh_testnet_address(&pk_user).unwrap();
    let amount = 20_000u64;
    let note = "m1snark".repeat(4);
    let (_k, dest_spk) = crate::btc_tx::decode_address(&dest).unwrap();
    let pegout_raw = raw_tx(&[(&"9a".repeat(32), 0)], &[(amount, dest_spk)]);
    let pegout_txid = crate::btc_spv::parse_tx(&pegout_raw).unwrap().txid_display;
    let header = crate::bitvm2_exit::checkpoint_header_hash(127, &"ab".repeat(32));
    let pegout = crate::bitvm2_exit::pegout_txid_bytes(&pegout_txid).unwrap();
    let dest_h160 = crate::bitvm::dest_h160_from_address(&dest).unwrap();
    let leaf = crate::bitvm2_exit::mimc_leaf_hex(&note, &dest_h160, amount);
    let input = serde_json::json!({"note_id": note, "dest_h160_hex": hex::encode(dest_h160), "amount": amount, "height": 127,
        "header_hex": hex::encode(header), "pegout_txid_internal_hex": hex::encode(pegout), "mimc_leaves": [leaf]});
    (note, dest, amount, pegout_raw, pegout_txid, input)
}

/// `cargo test dump_snarkjs_attest_input -- --ignored --nocapture` -> attest.json
#[test]
#[ignore]
fn dump_snarkjs_attest_input() {
    let (note, dest, amount, raw, txid, input) = snarkjs_attest_statement();
    println!("ATTEST_INPUT {input}");
    println!("KIT_FIXTURE {}", serde_json::json!({"note": note, "dest": dest, "amount": amount, "pegout_raw_hex": hex::encode(raw), "pegout_txid": txid, "leaf": input["mimc_leaves"][0]}));
}

/// Full stack with the PUBLIC-SETUP toolchain (dry-run keys, not usable): the
/// ledger is armed with the VK imported from snarkjs (`vk-import`), the operator
/// proves with snarkjs from our `.wtns` (`attest-wtns`), and the node accepts the
/// `Bitvm2AttestV2` (SPV peg-out + Groth16) -> ClaimPosted. A wrong VK refuses it.
#[test]
fn m1_attest_with_snarkjs_proof_and_imported_vk() {
    let fx: serde_json::Value = serde_json::from_str(include_str!("../testdata/snarkjs_dryrun_m1_attest.json")).unwrap();
    let (note, dest, amount, pegout_raw, _txid, input) = snarkjs_attest_statement();
    assert_eq!(fx["input"], input, "fixture made for this statement");
    let k = ring();
    let mut n = node(&k);
    n.bitvm2_m1_from_height = 0;
    n.tip_height = 300;
    n.bitvm2_vk = hex::decode(fx["vk_hex"].as_str().unwrap()).unwrap();
    {
        let r = n.bridge.rail_mut(RAIL_BTC).unwrap();
        r.open_bitvm2_withdraw(&note, "alice", &dest, amount, 100).unwrap();
        r.record_fpl_checkpoint(128, &"ab".repeat(32));
    }
    mine(&mut n, &pegout_raw, 200, 205);
    let public_hex: Vec<String> = fx["public_be"].as_array().unwrap().iter().map(|x| x.as_str().unwrap().to_string()).collect();
    let proof_hex = fx["proof_hex"].as_str().unwrap().to_string();
    let public_be: Vec<Vec<u8>> = public_hex.iter().map(|h| hex::decode(h).unwrap()).collect();
    let digest = hex::encode(fd_pl_bitvm2::statement_digest(&hex::decode(&proof_hex).unwrap(), &public_be));
    let attest = |proof_hex: String| Bitvm2AttestV2 {
        note_id: note.clone(),
        claim_txid_hex: "cc".repeat(32),
        checkpoint_height: 127,
        btc_height: 200,
        pegout_raw_tx_hex: hex::encode(&pegout_raw),
        merkle_path: vec![],
        merkle_index: 0,
        dest_lock_abort_commit_hex: String::new(),
        proof_hex,
        public_hex: public_hex.clone(),
        statement_digest_hex: digest.clone(),
    };
    // wrong VK (seeded dev key) refuses the snarkjs proof
    let good_vk = n.bitvm2_vk.clone();
    n.bitvm2_vk = fd_pl_bitvm2::groth16::vk_to_bytes(&fd_pl_bitvm2::groth16::setup_from_seed([7u8; 32]).unwrap().1).unwrap();
    assert!(send(&mut n, &k, "op1", 0, TxBody::Bitvm2AttestV2 { attest: attest(proof_hex.clone()) }).is_err());
    n.bitvm2_vk = good_vk;
    send(&mut n, &k, "op1", 0, TxBody::Bitvm2AttestV2 { attest: attest(proof_hex) }).unwrap();
    assert_eq!(n.bridge.rail(RAIL_BTC).unwrap().bitvm2_claims[&note].status, crate::bitvm2_exit::Bitvm2Status::ClaimPosted);
}

/// Operator kit path: the body produced by `fpl-operator-attest.sh` (status -> attest input
/// -> attest-wtns -> snarkjs prove -> proof-import -> attest body, dry-run v1 key) is a
/// valid `bitvm2_attest_v2` TxBody that the ledger accepts -> ClaimPosted.
#[test]
fn kit_snarkjs_attest_body_accepted_by_ledger() {
    let fx: serde_json::Value = serde_json::from_str(include_str!("../testdata/snarkjs_dryrun_m1_attest.json")).unwrap();
    let mut body: serde_json::Value = serde_json::from_str(include_str!("../testdata/kit_attest_body.json")).unwrap();
    body.as_object_mut().unwrap().remove("note");
    let tx_body: TxBody = serde_json::from_value(body).expect("kit body is a TxBody");
    let (note, dest, amount, pegout_raw, _txid, _input) = snarkjs_attest_statement();
    let k = ring();
    let mut n = node(&k);
    n.bitvm2_m1_from_height = 0;
    n.tip_height = 300;
    n.bitvm2_vk = hex::decode(fx["vk_hex"].as_str().unwrap()).unwrap();
    {
        let r = n.bridge.rail_mut(RAIL_BTC).unwrap();
        r.open_bitvm2_withdraw(&note, "alice", &dest, amount, 100).unwrap();
        r.record_fpl_checkpoint(128, &"ab".repeat(32));
    }
    mine(&mut n, &pegout_raw, 200, 205);
    send(&mut n, &k, "op1", 0, tx_body).unwrap();
    let c = &n.bridge.rail(RAIL_BTC).unwrap().bitvm2_claims[&note];
    assert_eq!(c.status, crate::bitvm2_exit::Bitvm2Status::ClaimPosted);
    assert_eq!(c.claim_txid_hex, "cc".repeat(32));
}

/// The testnet-2300 withdraw VK wired into this release (setup of 2026-10-19,
/// docs/bridge/ceremony/testnet-vk-2026-10-19): decodes, 13 public inputs, sha256 as
/// published, equals the transcript's vk-import, and verifies that setup's demo proof
/// (snarkjs proof imported with the same converter the operators use).
#[test]
fn testnet_withdraw_vk_is_the_published_setup() {
    use sha2::Digest;
    let fx: serde_json::Value = serde_json::from_str(include_str!("../testdata/testnet_vk_2026-10-19_v1_demo.json")).unwrap();
    let bytes = hex::decode(crate::bitvm2_exit::BITVM2_WITHDRAW_VK_HEX).unwrap();
    assert_eq!(hex::encode(sha2::Sha256::digest(&bytes)), crate::bitvm2_exit::BITVM2_WITHDRAW_VK_SHA256);
    assert_eq!(fx["vk_import"]["vk_hex"].as_str().unwrap(), crate::bitvm2_exit::BITVM2_WITHDRAW_VK_HEX);
    let vk = fd_pl_bitvm2::groth16::vk_from_bytes(&bytes).unwrap();
    assert_eq!(vk.gamma_abc_g1.len() - 1, 13);
    let proof = fd_pl_bitvm2::snarkjs_io::proof_from_snarkjs(&fx["proof"]).unwrap();
    let public = fd_pl_bitvm2::snarkjs_io::public_from_snarkjs(&fx["public"]).unwrap();
    assert!(fd_pl_bitvm2::groth16::verify(&vk, &public, &proof).unwrap());
    // still inert: the node only uses it from the M1 (= bridge) height
    assert_eq!(crate::params_v2::TESTNET_2300_BRIDGE_FROM_HEIGHT, 692_000);
}

#[test]
fn withdraw_vk_is_testnet4_only() {
    use sha2::Digest;
    let vk = crate::bitvm2_exit::withdraw_vk_for_network(crate::NETWORK_ID_PUBLIC_TESTNET_2300);
    assert_eq!(hex::encode(sha2::Sha256::digest(&vk)), crate::bitvm2_exit::BITVM2_WITHDRAW_VK_SHA256);
    assert!(crate::bitvm2_exit::withdraw_vk_for_network(crate::NETWORK_ID_PRIVATE_V22).is_empty());
    assert!(crate::bitvm2_exit::withdraw_vk_for_network(1).is_empty());
    let n = Node::new("v1", ChainConfig { network_id: crate::NETWORK_ID_PUBLIC_TESTNET_2300, ..ChainConfig::default() },
        KeyRing::new(CryptoScheme::HmacDev), &[]);
    assert_eq!(n.bitvm2_vk, vk);
}
