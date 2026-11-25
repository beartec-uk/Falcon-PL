// Copyright (c) 2025-2026 BEARTEC. All rights reserved. See LICENSE.
//! v2.9.61: V3 mint-or-refund. Synthetic receipts and RLP headers only
//! (no beacon network). The V3 bridge is set on the node, never via env.

use super::*;
use crate::bridge::{
    v3_mint_note_id, v3_refund_note_id, BridgeState, V3Resolution, ETH_V3_DEPOSIT_EXPIRY_SECS,
    RAIL_ETH, RAIL_USDC, SEPOLIA_BEACON_GENESIS_UNIX, V1_DEPOSIT_AFTER_V3_ACTIVATION,
    V3_BRIDGE_NOT_CONFIGURED, V3_DEPOSIT_ALREADY_RESOLVED, V3_DEPOSIT_ASSET_MISMATCH,
    V3_DEPOSIT_BAD_TOKEN, V3_DEPOSIT_DEST_UNRESOLVED, V3_DEPOSIT_NOT_IN_RECEIPT,
    V3_DEPOSITS_NOT_ACTIVE, V3_DEPOSIT_ID_MALFORMED,
};
use crate::eth_exec::{
    exec_header_timestamp, keccak256, rlp_bytes, rlp_list, rlp_uint, v3_deposit_id,
    v3_deposits_from_receipt, EthExecHeader, ETH_V3_DEPOSIT_EVENT, ETH_V3_DEPOSIT_TOPIC0,
};
use crate::eth_lc::EthLcState;
use crate::evm_spv::{self, withdraw_leaf};

const BRIDGE: [u8; 20] = [0x11; 20];
const SENDER: [u8; 20] = [0xab; 20];
/// LC-head unix time used by the hand-built headers.
const HEAD_TS: u64 = 1_700_000_000;

fn users() -> Vec<(String, u64)> {
    vec![
        ("alice".into(), 1_000_000),
        ("bob".into(), 1_000_000),
        ("carol".into(), 1_000_000),
    ]
}

fn cfg() -> ChainConfig {
    ChainConfig {
        fee_escalate: false,
        min_fee: 1,
        pack_budget_ms: 0,
        max_txs_per_ledger: 8,
        progress_timeout_ms: 0,
        ..Default::default()
    }
}

fn hp_leaf(nibbles: &[u8]) -> Vec<u8> {
    let mut o = vec![0x20];
    for i in (0..nibbles.len()).step_by(2) {
        o.push((nibbles[i] << 4) | nibbles[i + 1]);
    }
    o
}

fn word_u64(n: u64) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[24..].copy_from_slice(&n.to_be_bytes());
    w
}

fn word_addr(addr: &[u8; 20]) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[12..].copy_from_slice(addr);
    w
}

/// `bytes20` in `abi.encode` is left-aligned.
fn word_bytes20(b: &[u8; 20]) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[..20].copy_from_slice(b);
    w
}

fn rlp_exec(number: u64, parent: [u8; 32], receipts: [u8; 32], timestamp: u64) -> EthExecHeader {
    let items = [
        rlp_bytes(&parent),
        rlp_bytes(&[0u8; 32]),
        rlp_bytes(&[0u8; 20]),
        rlp_bytes(&[0u8; 32]),
        rlp_bytes(&[0u8; 32]),
        rlp_bytes(&receipts),
        rlp_bytes(&[0u8; 256]),
        rlp_uint(0),
        rlp_uint(number),
        rlp_uint(30_000_000),
        rlp_uint(0),
        rlp_uint(timestamp),
        rlp_bytes(&[]),
        rlp_bytes(&[0u8; 32]),
        rlp_bytes(&[0u8; 8]),
        rlp_uint(1),
        rlp_bytes(&[0u8; 32]),
        rlp_uint(0),
        rlp_uint(0),
        rlp_bytes(&[0u8; 32]),
        rlp_bytes(&[0u8; 32]),
    ];
    let rlp = rlp_list(&items);
    let hash = keccak256(&rlp);
    EthExecHeader {
        number,
        hash: hex::encode(hash),
        parent_hash: hex::encode(parent),
        receipts_root: hex::encode(receipts),
        rlp_hex: hex::encode(&rlp),
        timestamp: 0,
    }
}

fn chain(from: u64, to: u64, receipts: [u8; 32], timestamp: u64) -> Vec<EthExecHeader> {
    let mut parent = [3u8; 32];
    let mut out = Vec::with_capacity((to - from + 1) as usize);
    for n in from..=to {
        let h = rlp_exec(n, parent, receipts, timestamp);
        parent = crate::eth_ssz::parse32(&h.hash).unwrap();
        out.push(h);
    }
    out
}

struct Built {
    receipt: Vec<u8>,
    mpt_node: Vec<u8>,
    receipts_root: [u8; 32],
}

fn build_receipt(logs: &[Vec<u8>]) -> Built {
    let logs_rlp = rlp_list(logs);
    let bloom = vec![0u8; 256];
    let body = rlp_list(&[
        rlp_uint(1),
        rlp_uint(21_000),
        rlp_bytes(&bloom),
        logs_rlp,
    ]);
    let mut receipt = vec![0x02];
    receipt.extend_from_slice(&body);
    let key = rlp_uint(0);
    let mut nibs = Vec::new();
    for b in key {
        nibs.push(b >> 4);
        nibs.push(b & 0x0f);
    }
    let mpt_node = rlp_list(&[rlp_bytes(&hp_leaf(&nibs)), rlp_bytes(&receipt)]);
    let receipts_root = keccak256(&mpt_node);
    Built {
        receipt,
        mpt_node,
        receipts_root,
    }
}

/// One V3 Deposit log. Data words match Solidity `abi.encode` exactly.
fn v3_log(
    deposit_id: &[u8; 32],
    sender: &[u8; 20],
    dest20: &[u8; 20],
    token: &[u8; 20],
    amount: u64,
    timestamp: u64,
) -> Vec<u8> {
    let topics = rlp_list(&[
        rlp_bytes(&ETH_V3_DEPOSIT_TOPIC0),
        rlp_bytes(deposit_id),
        rlp_bytes(&word_addr(sender)),
    ]);
    let mut data = Vec::with_capacity(128);
    data.extend_from_slice(&word_bytes20(dest20));
    data.extend_from_slice(&word_addr(token));
    data.extend_from_slice(&word_u64(amount));
    data.extend_from_slice(&word_u64(timestamp));
    rlp_list(&[rlp_bytes(&BRIDGE), topics, rlp_bytes(&data)])
}

fn lc_at(number: u64, hash: &str, receipts: &str) -> EthLcState {
    EthLcState {
        genesis_validators_root: crate::eth_lc::SEPOLIA_GENESIS_VALIDATORS_ROOT.into(),
        finalized_slot: 10,
        finalized_beacon_root: "ab".repeat(32),
        execution_block_hash: hash.into(),
        execution_number: number,
        receipts_root: receipts.into(),
        period: 3,
        current_agg_pk: String::new(),
        current_pks: vec![],
        next_agg_pk: String::new(),
        next_pks: vec![],
    }
}

fn proof_of(header: &EthExecHeader, built: &Built) -> BridgeProof {
    BridgeProof {
        external_txid: "v3".into(),
        block_hash: header.hash.clone(),
        height: header.number,
        merkle_path: vec![hex::encode(&built.mpt_node)],
        merkle_index: 0,
        lock_id: String::new(),
        parent_hash: String::new(),
        merkle_root: String::new(),
        external_to: String::new(),
        raw_tx: hex::encode(&built.receipt),
    }
}

struct Peg {
    node: Node,
    proof: BridgeProof,
}

/// One execution block that is also the LC head. `head_ts` is field 11.
fn open_peg(gate: u64, head_ts: u64, logs: Vec<Vec<u8>>) -> Peg {
    let built = build_receipt(&logs);
    let header = rlp_exec(50, [9u8; 32], built.receipts_root, head_ts);
    let mut node = Node::new(
        "v1",
        cfg(),
        KeyRing::new(CryptoScheme::HmacDev),
        &users(),
    );
    node.eth_v3_from_height = gate;
    node.eth_v3_bridge = Some(BRIDGE);
    node.bridge.eth_lc = Some(lc_at(header.number, &header.hash, &header.receipts_root));
    node.bridge
        .eth_exec_headers
        .make_mut()
        .insert(header.number, header.clone());
    let proof = proof_of(&header, &built);
    Peg { node, proof }
}

/// Replace the single head header's timestamp and point the LC at the new hash.
fn retimes(node: &mut Node, proof: &BridgeProof, timestamp: u64) -> BridgeProof {
    let number = proof.height;
    let old = node.bridge.eth_exec_headers.get(&number).unwrap().clone();
    let parent = crate::eth_ssz::parse32(&old.parent_hash).unwrap();
    let receipts = crate::eth_ssz::parse32(&old.receipts_root).unwrap();
    let header = rlp_exec(number, parent, receipts, timestamp);
    node.bridge.eth_lc.as_mut().unwrap().execution_block_hash = header.hash.clone();
    node.bridge.eth_exec_headers.make_mut().insert(number, header.clone());
    let mut next = proof.clone();
    next.block_hash = header.hash;
    next
}

fn mint_of(res: &V3Resolution) -> Option<(&str, u64)> {
    match res {
        V3Resolution::Mint {
            credit_to, amount, ..
        } => Some((credit_to, *amount)),
        V3Resolution::Refund { .. } => None,
    }
}

fn usdc_token() -> [u8; 20] {
    evm_spv::parse_eth_addr(evm_spv::SEPOLIA_USDC).unwrap()
}

#[test]
fn topic_deposit_id_and_note_vectors_match_abi() {
    assert_eq!(
        ETH_V3_DEPOSIT_TOPIC0,
        keccak256(ETH_V3_DEPOSIT_EVENT.as_bytes())
    );
    assert_eq!(
        hex::encode(ETH_V3_DEPOSIT_TOPIC0),
        "e7783c72791736d4d8af95660d4367bed2f98d8331a095422373e557a4318728"
    );
    assert_eq!(ETH_V3_DEPOSIT_EXPIRY_SECS, 3 * 86_400);
    assert_eq!(crate::bridge::ETH_EXEC_HEADER_WINDOW, 50_400);
    // Release B rollout (2.9.61): H2 armed above the 2.9.60 Gloas height.
    assert_eq!(TESTNET_2300_ETH_V3_FROM_HEIGHT, 414_000);
    assert!(TESTNET_2300_ETH_V3_FROM_HEIGHT > TESTNET_2300_ETH_LC_GLOAS_FROM_HEIGHT);
    // Armed by #30. Release B does not move this height.
    assert_eq!(TESTNET_2300_ETH_LC_GLOAS_FROM_HEIGHT, 409134);
    assert_eq!(
        network_eth_v3_from_height(NETWORK_ID_PUBLIC_TESTNET_2300),
        414_000
    );
    assert_eq!(network_eth_v3_from_height(NETWORK_ID_PRIVATE_V22), u64::MAX);
    assert_eq!(
        evm_spv::DEFAULT_SEPOLIA_QC_V3_BRIDGE,
        Some("0xEd4eE497F21a9255a59e87535FF2A6097592Cfd4")
    );
    let v3 = evm_spv::parse_qc_v3_bridge_env(None).unwrap().unwrap();
    assert_eq!(hex::encode(v3), "ed4ee497f21a9255a59e87535ff2a6097592cfd4");
    let mint_union = evm_spv::sepolia_mint_bridge_addrs();
    assert!(
        !mint_union.contains(&BRIDGE),
        "V3 must not join the V1 mint union"
    );

    // chainid 11155111, bridge 0x11..11, nonce 0. 96-byte abi.encode, not packed.
    let mut buf = [0u8; 96];
    buf[24..32].copy_from_slice(&11_155_111u64.to_be_bytes());
    buf[44..64].copy_from_slice(&BRIDGE);
    let id = v3_deposit_id(11_155_111, &BRIDGE, 0);
    assert_eq!(id, keccak256(&buf));
    assert_eq!(
        hex::encode(id),
        "eac4b38624b36ed38a9df3e40d15f13f7c8b9ed392ea339acdbb03a922a42b48"
    );
    assert_eq!(
        hex::encode(v3_refund_note_id(&id)),
        "8d383292a5c2923872439de201682d84382d95b6ca08b44b659c2539713da86b"
    );
    assert_eq!(
        hex::encode(v3_mint_note_id(&id)),
        "7cbac7631d2c8266cee9c66bf70e68e8472a23cb4485a864073bc56fba6cf1c3"
    );

    let bridge2 = [0xaa; 20];
    let mut buf2 = [0u8; 96];
    buf2[31] = 1;
    buf2[44..64].copy_from_slice(&bridge2);
    buf2[95] = 7;
    let id2 = v3_deposit_id(1, &bridge2, 7);
    assert_eq!(id2, keccak256(&buf2));
    assert_eq!(
        hex::encode(id2),
        "e1f118d73a8c75d91beb856d44e052abb642ff61626bc3a2af0e72fbfe68b5c3"
    );
    assert_eq!(
        hex::encode(v3_refund_note_id(&id2)),
        "caf4379083731cf39b846b1d6351b90ce3323d3ce258520e99690fafde834802"
    );

    let body = TxBody::EthV3Deposit {
        asset: "ETH".into(),
        deposit_id: hex::encode(id),
        credit_to: "sally".into(),
        proof: BridgeProof::default(),
    };
    let v = serde_json::to_value(&body).unwrap();
    assert_eq!(v["kind"], "eth_v3_deposit");
}

#[test]
fn abi_encode_rejects_padding_and_keeps_a_hand_built_log() {
    let id = v3_deposit_id(11_155_111, &BRIDGE, 0);
    let dest = crate::btc_spv::dest_id20("sally");
    let ts = HEAD_TS - 10;
    let log = v3_log(&id, &SENDER, &dest, &[0u8; 20], 1_000, ts);
    let built = build_receipt(&[log]);
    let parsed = v3_deposits_from_receipt(&built.receipt, &BRIDGE);
    assert_eq!(parsed.len(), 1);
    assert_eq!(parsed[0].deposit_id, id);
    assert_eq!(parsed[0].sender, SENDER);
    assert_eq!(parsed[0].dest20, dest, "bytes20 is left-aligned");
    assert_eq!(parsed[0].token, [0u8; 20]);
    assert_eq!(parsed[0].amount, 1_000);
    assert_eq!(parsed[0].timestamp, ts);

    // Any EIP-2718 type byte is stripped (a future type 0x05, or 0x7f); a
    // legacy (untyped) receipt starts with the RLP list prefix.
    let body = &built.receipt[1..];
    for t in [0x05u8, 0x7f] {
        let mut typed = vec![t];
        typed.extend_from_slice(body);
        assert_eq!(v3_deposits_from_receipt(&typed, &BRIDGE).len(), 1, "type {t:#x}");
    }
    assert_eq!(v3_deposits_from_receipt(body, &BRIDGE).len(), 1, "legacy");

    // Right-aligning dest20 (the address convention) is not bytes20. Reject.
    let topics = rlp_list(&[
        rlp_bytes(&ETH_V3_DEPOSIT_TOPIC0),
        rlp_bytes(&id),
        rlp_bytes(&word_addr(&SENDER)),
    ]);
    let mut bad_dest = Vec::new();
    bad_dest.extend_from_slice(&word_addr(&dest));
    bad_dest.extend_from_slice(&word_u64(0));
    bad_dest.extend_from_slice(&word_u64(1_000));
    bad_dest.extend_from_slice(&word_u64(ts));
    let wrong = rlp_list(&[rlp_bytes(&BRIDGE), topics.clone(), rlp_bytes(&bad_dest)]);
    assert!(v3_deposits_from_receipt(&build_receipt(&[wrong]).receipt, &BRIDGE).is_empty());

    // Non-zero pad on the sender topic, and an amount that does not fit u64.
    let mut padded_sender = word_addr(&SENDER);
    padded_sender[0] = 1;
    let topics_pad = rlp_list(&[
        rlp_bytes(&ETH_V3_DEPOSIT_TOPIC0),
        rlp_bytes(&id),
        rlp_bytes(&padded_sender),
    ]);
    let mut data = Vec::new();
    data.extend_from_slice(&word_bytes20(&dest));
    data.extend_from_slice(&word_addr(&[0u8; 20]));
    data.extend_from_slice(&word_u64(1));
    data.extend_from_slice(&word_u64(ts));
    let padded = rlp_list(&[rlp_bytes(&BRIDGE), topics_pad, rlp_bytes(&data)]);
    assert!(v3_deposits_from_receipt(&build_receipt(&[padded]).receipt, &BRIDGE).is_empty());

    data[64] = 1; // high byte of the amount word
    let topics_ok = rlp_list(&[
        rlp_bytes(&ETH_V3_DEPOSIT_TOPIC0),
        rlp_bytes(&id),
        rlp_bytes(&word_addr(&SENDER)),
    ]);
    let wide = rlp_list(&[rlp_bytes(&BRIDGE), topics_ok, rlp_bytes(&data)]);
    assert!(
        v3_deposits_from_receipt(&build_receipt(&[wide]).receipt, &BRIDGE).is_empty(),
        "amount above u64 is skipped"
    );

    let other = [0x22u8; 20];
    let foreign = rlp_list(&[
        rlp_bytes(&other),
        rlp_list(&[
            rlp_bytes(&ETH_V3_DEPOSIT_TOPIC0),
            rlp_bytes(&id),
            rlp_bytes(&word_addr(&SENDER)),
        ]),
        rlp_bytes(&{
            let mut d = Vec::new();
            d.extend_from_slice(&word_bytes20(&dest));
            d.extend_from_slice(&word_addr(&[0u8; 20]));
            d.extend_from_slice(&word_u64(1));
            d.extend_from_slice(&word_u64(ts));
            d
        }),
    ]);
    assert!(v3_deposits_from_receipt(&build_receipt(&[foreign]).receipt, &BRIDGE).is_empty());

    let header = rlp_exec(7, [1u8; 32], [2u8; 32], HEAD_TS);
    let raw = hex::decode(&header.rlp_hex).unwrap();
    assert_eq!(exec_header_timestamp(&raw).unwrap(), HEAD_TS);
    let mut lc = lc_at(7, &header.hash, &header.receipts_root);
    lc.finalized_slot = 10;
    assert_eq!(
        BridgeState::eth_lc_head_unix_time(&lc, "not-hex"),
        SEPOLIA_BEACON_GENESIS_UNIX + 120
    );
    assert_eq!(
        BridgeState::eth_lc_head_unix_time(&lc, &header.rlp_hex),
        HEAD_TS
    );
}

#[test]
fn fresh_state_omits_v3_fields_and_status_reports_the_gate() {
    let st = BridgeState::with_genesis_rails();
    let s = serde_json::to_string(&st).unwrap();
    assert!(!s.contains("eth_v3_deposits"));
    assert!(!s.contains("eth_v1_deposit_cutoff"));
    let back: BridgeState = serde_json::from_str(&s).unwrap();
    assert!(back.eth_v3_deposits.is_empty());
    assert_eq!(back.eth_v1_deposit_cutoff, 0);
    assert_eq!(
        serde_json::to_vec(&st).unwrap(),
        serde_json::to_vec(&back).unwrap()
    );

    let mut n = fresh_node(u64::MAX);
    assert!(!n.eth_v3_at(1));
    // 2.9.61: the bridge address defaults to the deployed V3; the gate keeps it inert.
    assert_eq!(n.eth_v3_bridge, evm_spv::parse_qc_v3_bridge_env(None).unwrap());
    let status = n.status_json();
    assert_eq!(status["eth_v3_bridge"], "0xed4ee497f21a9255a59e87535ff2a6097592cfd4");
    assert_eq!(status["eth_v3_from_height"], u64::MAX);
    assert_eq!(status["eth_v3_expiry_secs"], ETH_V3_DEPOSIT_EXPIRY_SECS);
    assert_eq!(status["eth_v1_deposit_cutoff"], 0);
    assert_eq!(status["eth_v3_resolved_total"], 0);
    assert_eq!(status["eth_v3_resolutions"], serde_json::json!([]));

    assert!(Node::is_permanent_tx_failure(V3_DEPOSIT_ALREADY_RESOLVED));
    assert!(Node::is_permanent_tx_failure(V1_DEPOSIT_AFTER_V3_ACTIVATION));
    assert!(Node::is_permanent_tx_failure(V3_DEPOSIT_NOT_IN_RECEIPT));
    assert!(!Node::is_permanent_tx_failure(V3_DEPOSIT_DEST_UNRESOLVED));
    assert!(!Node::is_permanent_tx_failure(V3_DEPOSITS_NOT_ACTIVE));
    assert!(!Node::is_permanent_tx_failure(V3_BRIDGE_NOT_CONFIGURED));

    let err = n
        .eth_v3_deposit(
            "ETH",
            &hex::encode([1u8; 32]),
            "sally",
            &BridgeProof::default(),
        )
        .unwrap_err();
    assert_eq!(err, V3_DEPOSITS_NOT_ACTIVE);
    assert!(!Node::is_permanent_tx_failure(&err));
}

fn fresh_node(gate: u64) -> Node {
    let mut n = Node::new(
        "v1",
        cfg(),
        KeyRing::new(CryptoScheme::HmacDev),
        &users(),
    );
    n.eth_v3_from_height = gate;
    n
}

fn eth_leaves(n: &Node) -> Vec<String> {
    n.bridge.rail(RAIL_ETH).unwrap().claim_leaves.clone()
}

fn usdc_leaves(n: &Node) -> Vec<String> {
    n.bridge.rail(RAIL_USDC).unwrap().claim_leaves.clone()
}

#[test]
fn mint_inside_e_credits_and_writes_no_leaf() {
    let id = [1u8; 32];
    let amount = 5_000u64;
    let dest = crate::btc_spv::dest_id20("Sally");
    let log_ts = HEAD_TS;
    let log = v3_log(&id, &SENDER, &dest, &[0u8; 20], amount, log_ts);
    let mut peg = open_peg(1, HEAD_TS, vec![log]);
    let before = eth_leaves(&peg.node);
    // Boundary: head time == log time + E still mints.
    let proof = retimes(&mut peg.node, &peg.proof, log_ts + ETH_V3_DEPOSIT_EXPIRY_SECS);
    peg.node
        .eth_v3_deposit("ETH", &hex::encode(id), "Sally", &proof)
        .unwrap();
    assert_eq!(peg.node.defi.asset_bal("sally", "ETH"), amount);
    assert_eq!(peg.node.defi.asset_bal("Sally", "ETH"), 0);
    assert_eq!(
        peg.node.bridge.rail(RAIL_ETH).unwrap().total_minted,
        amount
    );
    assert_eq!(eth_leaves(&peg.node), before);
    assert!(usdc_leaves(&peg.node).is_empty());
    let res = peg.node.bridge.eth_v3_resolution(&hex::encode(id)).unwrap();
    assert_eq!(mint_of(res), Some(("sally", amount)));
    let banned = withdraw_leaf(&v3_mint_note_id(&id), &SENDER, amount, false);
    let banned_dest = withdraw_leaf(&v3_mint_note_id(&id), &dest, amount, false);
    let leaves = crate::lc::evm_claim_leaves(&peg.node.bridge);
    assert!(!leaves.contains(&banned));
    assert!(!leaves.contains(&banned_dest));
    assert!(leaves.is_empty());

    // Reserved genesis name is creditable even though validate_name rejects it.
    let id_b = [8u8; 32];
    let dest_b = crate::btc_spv::dest_id20("Bob");
    let log_b = v3_log(&id_b, &SENDER, &dest_b, &[0u8; 20], 9, HEAD_TS);
    let mut bob = open_peg(1, HEAD_TS, vec![log_b]);
    bob.node
        .eth_v3_deposit("ETH", &hex::encode(id_b), "Bob", &bob.proof)
        .unwrap();
    assert_eq!(bob.node.defi.asset_bal("bob", "ETH"), 9);
    assert_eq!(
        mint_of(bob.node.bridge.eth_v3_resolution(&hex::encode(id_b)).unwrap()),
        Some(("bob", 9))
    );
}

#[test]
fn refund_after_e_appends_withdraw_leaf_and_does_not_credit() {
    let id = [2u8; 32];
    let amount = 8_000u64;
    let token = usdc_token();
    let dest = crate::btc_spv::dest_id20("sally");
    let log_ts = HEAD_TS - ETH_V3_DEPOSIT_EXPIRY_SECS - 1;
    let log = v3_log(&id, &SENDER, &dest, &token, amount, log_ts);
    let mut peg = open_peg(1, HEAD_TS, vec![log]);
    let minted_before = peg.node.bridge.rail(RAIL_USDC).unwrap().total_minted;
    peg.node
        .eth_v3_deposit("USDC", &hex::encode(id), "", &peg.proof)
        .unwrap();
    assert_eq!(peg.node.defi.asset_bal("sally", "USDC"), 0);
    assert_eq!(
        peg.node.bridge.rail(RAIL_USDC).unwrap().total_minted,
        minted_before
    );
    assert_eq!(peg.node.bridge.rail(RAIL_ETH).unwrap().total_minted, 0);
    let note = v3_refund_note_id(&id);
    let leaf = withdraw_leaf(&note, &SENDER, amount, true);
    assert_eq!(usdc_leaves(&peg.node), vec![hex::encode(leaf)]);
    assert!(eth_leaves(&peg.node).is_empty());
    match peg.node.bridge.eth_v3_resolution(&format!("0x{}", hex::encode(id))).unwrap() {
        V3Resolution::Refund {
            asset,
            amount: a,
            refund_to,
            note_id,
            eth_block,
        } => {
            assert_eq!(asset, "USDC");
            assert_eq!(*a, amount);
            assert_eq!(refund_to, &hex::encode(SENDER));
            assert_eq!(note_id, &hex::encode(note));
            assert_eq!(*eth_block, 50);
        }
        V3Resolution::Mint { .. } => panic!("expired deposit must refund"),
    }
    // One second inside the window still refunds; the boundary test is the mint.
    let again = peg
        .node
        .eth_v3_deposit("USDC", &hex::encode(id), "sally", &peg.proof)
        .unwrap_err();
    assert_eq!(again, V3_DEPOSIT_ALREADY_RESOLVED);
    assert!(Node::is_permanent_tx_failure(&again));
    assert_eq!(usdc_leaves(&peg.node).len(), 1);
}

#[test]
fn invalid_dest_refunds_inside_e() {
    let id = [3u8; 32];
    let amount = 77u64;
    let dest = crate::btc_spv::dest_id20("no");
    let log = v3_log(&id, &SENDER, &dest, &[0u8; 20], amount, HEAD_TS);
    let mut peg = open_peg(1, HEAD_TS, vec![log]);
    peg.node
        .eth_v3_deposit("ETH", &hex::encode(id), "no", &peg.proof)
        .unwrap();
    assert_eq!(peg.node.defi.asset_bal("no", "ETH"), 0);
    assert_eq!(peg.node.bridge.rail(RAIL_ETH).unwrap().total_minted, 0);
    let leaf = withdraw_leaf(&v3_refund_note_id(&id), &SENDER, amount, false);
    assert_eq!(eth_leaves(&peg.node), vec![hex::encode(leaf)]);
    assert!(matches!(
        peg.node.bridge.eth_v3_resolution(&hex::encode(id)).unwrap(),
        V3Resolution::Refund { .. }
    ));
}

#[test]
fn missing_or_mismatched_credit_to_is_not_permanent_then_mints() {
    let id = [4u8; 32];
    let amount = 15u64;
    let dest = crate::btc_spv::dest_id20("sally");
    let log = v3_log(&id, &SENDER, &dest, &[0u8; 20], amount, HEAD_TS);
    let mut peg = open_peg(1, HEAD_TS, vec![log]);
    let bridge_before = serde_json::to_vec(&peg.node.bridge).unwrap();
    let err = peg
        .node
        .eth_v3_deposit("ETH", &hex::encode(id), "", &peg.proof)
        .unwrap_err();
    assert_eq!(err, V3_DEPOSIT_DEST_UNRESOLVED);
    assert!(!Node::is_permanent_tx_failure(&err));
    assert_eq!(serde_json::to_vec(&peg.node.bridge).unwrap(), bridge_before);
    assert_eq!(peg.node.defi.asset_bal("sally", "ETH"), 0);

    let wrong = peg
        .node
        .eth_v3_deposit("ETH", &hex::encode(id), "carol", &peg.proof)
        .unwrap_err();
    assert_eq!(wrong, V3_DEPOSIT_DEST_UNRESOLVED);
    assert_eq!(serde_json::to_vec(&peg.node.bridge).unwrap(), bridge_before);

    peg.node
        .eth_v3_deposit("ETH", &hex::encode(id), "sally", &peg.proof)
        .unwrap();
    assert_eq!(peg.node.defi.asset_bal("sally", "ETH"), amount);
    assert_eq!(
        mint_of(peg.node.bridge.eth_v3_resolution(&hex::encode(id)).unwrap()),
        Some(("sally", amount))
    );
}

#[test]
fn double_submit_and_mint_then_refund_are_impossible() {
    let id = [5u8; 32];
    let amount = 100u64;
    let dest = crate::btc_spv::dest_id20("sally");
    let log = v3_log(&id, &SENDER, &dest, &[0u8; 20], amount, HEAD_TS);
    let mut peg = open_peg(1, HEAD_TS, vec![log]);
    peg.node
        .eth_v3_deposit("ETH", &hex::encode(id), "sally", &peg.proof)
        .unwrap();
    let expired = retimes(
        &mut peg.node,
        &peg.proof,
        HEAD_TS + ETH_V3_DEPOSIT_EXPIRY_SECS + 1,
    );
    let err = peg
        .node
        .eth_v3_deposit("ETH", &format!("0x{}", hex::encode(id)), "", &expired)
        .unwrap_err();
    assert_eq!(err, V3_DEPOSIT_ALREADY_RESOLVED);
    assert_eq!(peg.node.defi.asset_bal("sally", "ETH"), amount);
    assert!(eth_leaves(&peg.node).is_empty());
    assert_eq!(peg.node.bridge.rail(RAIL_ETH).unwrap().total_minted, amount);

    // Reverse: refund first, then a later head that would have minted.
    let id_r = [6u8; 32];
    let log_r = v3_log(
        &id_r,
        &SENDER,
        &dest,
        &[0u8; 20],
        amount,
        HEAD_TS - ETH_V3_DEPOSIT_EXPIRY_SECS - 1,
    );
    let mut refunded = open_peg(1, HEAD_TS, vec![log_r]);
    refunded
        .node
        .eth_v3_deposit("ETH", &hex::encode(id_r), "sally", &refunded.proof)
        .unwrap();
    assert_eq!(refunded.node.defi.asset_bal("sally", "ETH"), 0);
    assert_eq!(eth_leaves(&refunded.node).len(), 1);
    // Move the LC head back to the log time so the deposit reads as inside E;
    // the earlier refund must still win.
    let log_ts = HEAD_TS - ETH_V3_DEPOSIT_EXPIRY_SECS - 1;
    let inside = retimes(&mut refunded.node, &refunded.proof, log_ts);
    let err = refunded
        .node
        .eth_v3_deposit("ETH", &hex::encode(id_r), "sally", &inside)
        .unwrap_err();
    assert_eq!(err, V3_DEPOSIT_ALREADY_RESOLVED);
    assert_eq!(refunded.node.defi.asset_bal("sally", "ETH"), 0);
    assert_eq!(eth_leaves(&refunded.node).len(), 1);
    assert_eq!(refunded.node.bridge.rail(RAIL_ETH).unwrap().total_minted, 0);

    let err2 = refunded
        .node
        .eth_v3_deposit("ETH", &hex::encode(id_r), "", &inside)
        .unwrap_err();
    assert_eq!(err2, V3_DEPOSIT_ALREADY_RESOLVED);
}

#[test]
fn refund_leaf_is_merkle_provable_against_the_header_claim_root() {
    let eth_id = [7u8; 32];
    let usdc_id = [8u8; 32];
    let eth_amt = 11u64;
    let usdc_amt = 22u64;
    let dest = crate::btc_spv::dest_id20("sally");
    let log_ts = HEAD_TS - ETH_V3_DEPOSIT_EXPIRY_SECS - 1;
    let logs = vec![
        v3_log(&eth_id, &SENDER, &dest, &[0u8; 20], eth_amt, log_ts),
        v3_log(&usdc_id, &SENDER, &dest, &usdc_token(), usdc_amt, log_ts),
    ];
    let mut peg = open_peg(1, HEAD_TS, logs);
    peg.node
        .eth_v3_deposit("ETH", &hex::encode(eth_id), "", &peg.proof)
        .unwrap();
    peg.node
        .eth_v3_deposit("USDC", &hex::encode(usdc_id), "sally", &peg.proof)
        .unwrap();
    assert_eq!(peg.node.defi.asset_bal("sally", "ETH"), 0);
    assert_eq!(peg.node.defi.asset_bal("sally", "USDC"), 0);
    let leaves = crate::lc::evm_claim_leaves(&peg.node.bridge);
    assert_eq!(leaves.len(), 2);
    assert_eq!(
        leaves[0],
        withdraw_leaf(&v3_refund_note_id(&eth_id), &SENDER, eth_amt, false)
    );
    assert_eq!(
        leaves[1],
        withdraw_leaf(&v3_refund_note_id(&usdc_id), &SENDER, usdc_amt, true)
    );
    let (root, path0) = evm_spv::build_tree(&leaves, 0).unwrap();
    let (root1, path1) = evm_spv::build_tree(&leaves, 1).unwrap();
    assert_eq!(root, root1);
    assert!(!path0.is_empty(), "two leaves need a sibling");
    let claim = crate::lc::evm_header_claim_root(&peg.node.bridge);
    assert_eq!(hex::encode(claim), root);
    assert_eq!(
        evm_spv::merkle_root_binary(&hex::encode(leaves[0]), &path0, 0).unwrap(),
        root
    );
    assert_eq!(
        evm_spv::merkle_root_binary(&hex::encode(leaves[1]), &path1, 1).unwrap(),
        root
    );
    let mint_leaf = withdraw_leaf(&v3_mint_note_id(&eth_id), &SENDER, eth_amt, false);
    assert!(!leaves.contains(&mint_leaf));
}

#[test]
fn fund_pool_receipt_mints_nothing_and_v1_ignores_v3_logs() {
    let topic = keccak256(b"PoolFunded(address,address,uint256)");
    let topics = rlp_list(&[
        rlp_bytes(&topic),
        rlp_bytes(&word_addr(&SENDER)),
        rlp_bytes(&word_addr(&[0u8; 20])),
    ]);
    let log = rlp_list(&[rlp_bytes(&BRIDGE), topics, rlp_bytes(&word_u64(999))]);
    let mut peg = open_peg(1, HEAD_TS, vec![log]);
    let err = peg
        .node
        .eth_v3_deposit("ETH", &hex::encode([9u8; 32]), "sally", &peg.proof)
        .unwrap_err();
    assert_eq!(err, V3_DEPOSIT_NOT_IN_RECEIPT);
    assert!(Node::is_permanent_tx_failure(&err));
    assert_eq!(peg.node.bridge.rail(RAIL_ETH).unwrap().total_minted, 0);
    assert!(peg.node.bridge.eth_v3_deposits.is_empty());
    assert!(eth_leaves(&peg.node).is_empty());
    assert_eq!(peg.node.defi.asset_bal("sally", "ETH"), 0);

    let id = [10u8; 32];
    let dest = crate::btc_spv::dest_id20("bob");
    let v3 = v3_log(&id, &SENDER, &dest, &[0u8; 20], 50, HEAD_TS);
    let mut only_v3 = open_peg(1, HEAD_TS, vec![v3]);
    let v1_err = only_v3
        .node
        .bridge
        .mint_evm_lc(RAIL_ETH, 50, &only_v3.proof, "bob")
        .unwrap_err();
    assert!(
        v1_err.contains("receipt has no matching dest-lock/QC Deposit"),
        "{v1_err}"
    );
    assert_eq!(only_v3.node.bridge.rail(RAIL_ETH).unwrap().total_minted, 0);
    assert!(only_v3.node.bridge.eth_v3_deposits.is_empty());

    let mut bare = fresh_node(1);
    bare.eth_v3_bridge = None;
    let missing = bare
        .eth_v3_deposit("ETH", &hex::encode(id), "sally", &BridgeProof::default())
        .unwrap_err();
    assert_eq!(missing, V3_BRIDGE_NOT_CONFIGURED);
    assert!(!Node::is_permanent_tx_failure(&missing));
}

/// V3 layout under a different topic0, or a different topic count / data
/// length, is not a V3 Deposit. A real V3 log with an unknown token or the
/// wrong `asset` is rejected permanently. Nothing is recorded in any case.
#[test]
fn wrong_topic0_layout_token_or_asset_is_rejected() {
    let id = [12u8; 32];
    let dest = crate::btc_spv::dest_id20("sally");
    let data = |token: &[u8; 20]| {
        let mut d = Vec::new();
        d.extend_from_slice(&word_bytes20(&dest));
        d.extend_from_slice(&word_addr(token));
        d.extend_from_slice(&word_u64(500));
        d.extend_from_slice(&word_u64(HEAD_TS));
        d
    };
    let with = |topics: Vec<Vec<u8>>, data: Vec<u8>| {
        rlp_list(&[rlp_bytes(&BRIDGE), rlp_list(&topics), rlp_bytes(&data)])
    };
    let t_v1 = keccak256(b"Deposit(bytes32,address,uint256,bytes32)");
    // Packed-bytes20 typo of the signature: a different topic0.
    let t_typo = keccak256(b"Deposit(bytes32,address,bytes32,address,uint256,uint64)");
    assert_ne!(t_typo, ETH_V3_DEPOSIT_TOPIC0);
    let sender_w = word_addr(&SENDER);
    let mut long_data = data(&[0u8; 20]);
    long_data.extend_from_slice(&word_u64(0));
    let bad_logs = vec![
        with(
            vec![rlp_bytes(&t_v1), rlp_bytes(&id), rlp_bytes(&sender_w)],
            data(&[0u8; 20]),
        ),
        with(
            vec![rlp_bytes(&t_typo), rlp_bytes(&id), rlp_bytes(&sender_w)],
            data(&[0u8; 20]),
        ),
        // Two topics (sender not indexed).
        with(
            vec![rlp_bytes(&ETH_V3_DEPOSIT_TOPIC0), rlp_bytes(&id)],
            data(&[0u8; 20]),
        ),
        // Four topics.
        with(
            vec![
                rlp_bytes(&ETH_V3_DEPOSIT_TOPIC0),
                rlp_bytes(&id),
                rlp_bytes(&sender_w),
                rlp_bytes(&word_u64(1)),
            ],
            data(&[0u8; 20]),
        ),
        // Five data words.
        with(
            vec![
                rlp_bytes(&ETH_V3_DEPOSIT_TOPIC0),
                rlp_bytes(&id),
                rlp_bytes(&sender_w),
            ],
            long_data,
        ),
        // Three data words (timestamp missing).
        with(
            vec![
                rlp_bytes(&ETH_V3_DEPOSIT_TOPIC0),
                rlp_bytes(&id),
                rlp_bytes(&sender_w),
            ],
            data(&[0u8; 20])[..96].to_vec(),
        ),
    ];
    for (i, log) in bad_logs.into_iter().enumerate() {
        let built = build_receipt(&[log]);
        assert!(
            v3_deposits_from_receipt(&built.receipt, &BRIDGE).is_empty(),
            "case {i} must not parse"
        );
        let mut peg = open_peg(1, HEAD_TS, vec![]);
        let header = rlp_exec(50, [9u8; 32], built.receipts_root, HEAD_TS);
        peg.node.bridge.eth_lc = Some(lc_at(50, &header.hash, &header.receipts_root));
        peg.node
            .bridge
            .eth_exec_headers
            .make_mut()
            .insert(50, header.clone());
        let proof = proof_of(&header, &built);
        let err = peg
            .node
            .eth_v3_deposit("ETH", &hex::encode(id), "sally", &proof)
            .unwrap_err();
        assert_eq!(err, V3_DEPOSIT_NOT_IN_RECEIPT, "case {i}");
        assert!(peg.node.bridge.eth_v3_deposits.is_empty());
        assert_eq!(peg.node.defi.asset_bal("sally", "ETH"), 0);
        assert!(eth_leaves(&peg.node).is_empty());
    }

    // Unknown token: well-formed V3 log, permanent reject.
    let odd = v3_log(&id, &SENDER, &dest, &[0x33; 20], 500, HEAD_TS);
    let mut peg = open_peg(1, HEAD_TS, vec![odd]);
    for asset in ["ETH", "USDC"] {
        let err = peg
            .node
            .eth_v3_deposit(asset, &hex::encode(id), "sally", &peg.proof)
            .unwrap_err();
        assert_eq!(err, V3_DEPOSIT_BAD_TOKEN);
        assert!(Node::is_permanent_tx_failure(&err));
    }
    assert!(peg.node.bridge.eth_v3_deposits.is_empty());

    // ETH log submitted as USDC, and USDC log submitted as ETH.
    let eth_id = [13u8; 32];
    let usdc_id = [14u8; 32];
    let logs = vec![
        v3_log(&eth_id, &SENDER, &dest, &[0u8; 20], 500, HEAD_TS),
        v3_log(&usdc_id, &SENDER, &dest, &usdc_token(), 600, HEAD_TS),
    ];
    let mut peg = open_peg(1, HEAD_TS, logs);
    let e1 = peg
        .node
        .eth_v3_deposit("USDC", &hex::encode(eth_id), "sally", &peg.proof)
        .unwrap_err();
    assert!(e1.starts_with(V3_DEPOSIT_ASSET_MISMATCH), "{e1}");
    assert!(Node::is_permanent_tx_failure(&e1));
    let e2 = peg
        .node
        .eth_v3_deposit("ETH", &hex::encode(usdc_id), "sally", &peg.proof)
        .unwrap_err();
    assert!(e2.starts_with(V3_DEPOSIT_ASSET_MISMATCH), "{e2}");
    assert!(peg.node.bridge.eth_v3_deposits.is_empty());
    assert_eq!(peg.node.defi.asset_bal("sally", "ETH"), 0);
    assert_eq!(peg.node.defi.asset_bal("sally", "USDC"), 0);

    // The right asset on each mints to the matching balance only.
    peg.node
        .eth_v3_deposit("ETH", &hex::encode(eth_id), "sally", &peg.proof)
        .unwrap();
    peg.node
        .eth_v3_deposit("USDC", &hex::encode(usdc_id), "sally", &peg.proof)
        .unwrap();
    assert_eq!(peg.node.defi.asset_bal("sally", "ETH"), 500);
    assert_eq!(peg.node.defi.asset_bal("sally", "USDC"), 600);
    assert_eq!(peg.node.bridge.rail(RAIL_ETH).unwrap().total_minted, 500);
    assert_eq!(peg.node.bridge.rail(RAIL_USDC).unwrap().total_minted, 600);
    assert!(eth_leaves(&peg.node).is_empty());
    assert!(usdc_leaves(&peg.node).is_empty());
}

/// Exact 3-day boundary on both sides for one deposit: head == ts + E mints
/// path is open; head == ts + E + 1 refunds even with a good `credit_to`.
#[test]
fn expiry_boundary_is_strictly_greater_than_three_days() {
    let id = [15u8; 32];
    let amount = 321u64;
    let dest = crate::btc_spv::dest_id20("sally");
    let log_ts = HEAD_TS;
    let log = v3_log(&id, &SENDER, &dest, &usdc_token(), amount, log_ts);
    let mut peg = open_peg(1, HEAD_TS, vec![log]);
    // At ts + E: still inside, so a missing preimage is the non-permanent error.
    let at_e = retimes(&mut peg.node, &peg.proof, log_ts + ETH_V3_DEPOSIT_EXPIRY_SECS);
    let err = peg
        .node
        .eth_v3_deposit("USDC", &hex::encode(id), "", &at_e)
        .unwrap_err();
    assert_eq!(err, V3_DEPOSIT_DEST_UNRESOLVED);
    assert!(peg.node.bridge.eth_v3_deposits.is_empty());
    // One second later: expired, refunds despite the correct preimage.
    let past = retimes(&mut peg.node, &at_e, log_ts + ETH_V3_DEPOSIT_EXPIRY_SECS + 1);
    peg.node
        .eth_v3_deposit("USDC", &hex::encode(id), "sally", &past)
        .unwrap();
    assert_eq!(peg.node.defi.asset_bal("sally", "USDC"), 0);
    let leaf = withdraw_leaf(&v3_refund_note_id(&id), &SENDER, amount, true);
    assert_eq!(usdc_leaves(&peg.node), vec![hex::encode(leaf)]);
    assert!(matches!(
        peg.node.bridge.eth_v3_resolution(&hex::encode(id)).unwrap(),
        V3Resolution::Refund { .. }
    ));
}

fn v1_log(dest: &[u8; 20], token: &[u8; 20], amount: u64, lock: &[u8]) -> Vec<u8> {
    let t0 = keccak256(b"Deposit(bytes32,address,uint256,bytes32)");
    let topics = rlp_list(&[
        rlp_bytes(&t0),
        rlp_bytes(&word_addr(dest)),
        rlp_bytes(&word_addr(token)),
    ]);
    let mut data = [0u8; 64];
    data[24..32].copy_from_slice(&amount.to_be_bytes());
    data[32..64].copy_from_slice(lock);
    let addr = evm_spv::sepolia_qc_bridge_addr().unwrap();
    rlp_list(&[rlp_bytes(&addr), topics, rlp_bytes(&data)])
}

fn v1_proof(header: &EthExecHeader, built: &Built, txid: &str) -> BridgeProof {
    BridgeProof {
        external_txid: txid.into(),
        block_hash: header.hash.clone(),
        height: header.number,
        merkle_path: vec![hex::encode(&built.mpt_node)],
        merkle_index: 0,
        lock_id: String::new(),
        parent_hash: String::new(),
        merkle_root: String::new(),
        external_to: String::new(),
        raw_tx: hex::encode(&built.receipt),
    }
}

#[test]
fn v1_mints_through_h2_then_rejects_only_blocks_above_the_cutoff() {
    let amount = 1_000u64;
    let mut st = BridgeState::with_genesis_rails();
    let lock_hex = st.rail(RAIL_ETH).unwrap().lock_id.clone();
    let lock = hex::decode(&lock_hex).unwrap();
    let dest = crate::eth_exec::dest20_from_account("bob");
    let built = build_receipt(&[v1_log(&dest, &[0u8; 20], amount, &lock)]);
    let headers = chain(111, 114, built.receipts_root, HEAD_TS);
    for h in &headers {
        st.eth_exec_headers.make_mut().insert(h.number, h.clone());
    }
    let head = headers.iter().find(|h| h.number == 113).unwrap();
    st.eth_lc = Some(lc_at(113, &head.hash, &head.receipts_root));

    // execution_number 0 does not arm. Inactive does not arm. Set-once.
    st.eth_lc.as_mut().unwrap().execution_number = 0;
    st.arm_eth_v1_deposit_cutoff(true);
    assert_eq!(st.eth_v1_deposit_cutoff, 0);
    st.eth_lc.as_mut().unwrap().execution_number = 113;
    st.arm_eth_v1_deposit_cutoff(false);
    assert_eq!(st.eth_v1_deposit_cutoff, 0);

    let at = |n: u64, txid: &str| {
        let h = headers.iter().find(|h| h.number == n).unwrap();
        v1_proof(h, &built, txid)
    };
    // Before H2 the cutoff is zero, so a deposit at the head mints.
    st.mint_evm_lc(RAIL_ETH, amount, &at(113, &"11".repeat(32)), "bob")
        .unwrap();
    assert_eq!(st.rail(RAIL_ETH).unwrap().total_minted, amount);

    st.arm_eth_v1_deposit_cutoff(true);
    assert_eq!(st.eth_v1_deposit_cutoff, 113);
    st.eth_lc.as_mut().unwrap().execution_number = 200;
    st.arm_eth_v1_deposit_cutoff(true);
    assert_eq!(st.eth_v1_deposit_cutoff, 113, "cutoff is set once");

    // Amount 0 is still reported before the cutoff check.
    let zero = st
        .mint_evm_lc(RAIL_ETH, 0, &at(114, &"00".repeat(32)), "bob")
        .unwrap_err();
    assert_eq!(zero, "deposit amount 0");

    let above = st
        .mint_evm_lc(RAIL_ETH, amount, &at(114, &"22".repeat(32)), "bob")
        .unwrap_err();
    assert_eq!(above, V1_DEPOSIT_AFTER_V3_ACTIVATION);
    assert!(Node::is_permanent_tx_failure(&above));
    assert_eq!(st.rail(RAIL_ETH).unwrap().total_minted, amount);

    st.mint_evm_lc(RAIL_ETH, amount, &at(113, &"33".repeat(32)), "bob")
        .unwrap();
    st.mint_evm_lc(RAIL_ETH, amount, &at(111, &"44".repeat(32)), "bob")
        .unwrap();
    assert_eq!(st.rail(RAIL_ETH).unwrap().total_minted, amount * 3);

    // A height still allowed by the cutoff, but under the floor, keeps the
    // pre-H2 floor error (the cutoff check does not run first for it).
    st.eth_exec_prune_floor = 112;
    let old = st
        .mint_evm_lc(RAIL_ETH, amount, &at(111, &"55".repeat(32)), "bob")
        .unwrap_err();
    assert_eq!(old, crate::bridge::DEPOSIT_OLDER_THAN_HEADER_WINDOW);

    let not_rail = BridgeState::with_genesis_rails()
        .mint_evm_lc("BTC", 1, &BridgeProof::default(), "bob")
        .unwrap_err();
    assert_eq!(not_rail, "not an EVM rail");
}

fn sign(net: &Network, acct: &str, seq: u64, body: TxBody) -> Tx {
    Tx::sign_body(
        &net.user_keys,
        acct,
        seq,
        "",
        0,
        1,
        net.cfg.network_id,
        body,
    )
    .unwrap()
}

fn submit_all(net: &mut Network, tx: &Tx) {
    for n in net.nodes.values_mut() {
        n.submit_tx(tx.clone()).unwrap();
    }
}

fn install(net: &mut Network, gate: u64, header: &EthExecHeader) {
    for n in net.nodes.values_mut() {
        n.ensure_faucet();
        n.eth_v3_from_height = gate;
        n.eth_v3_bridge = Some(BRIDGE);
        n.bridge.eth_lc = Some(lc_at(header.number, &header.hash, &header.receipts_root));
        n.bridge
            .eth_exec_headers
            .make_mut()
            .insert(header.number, header.clone());
    }
    net.pong_all();
}

fn roots_agree(net: &Network) {
    let first = net.nodes.values().next().unwrap();
    let root = first.commitment_root();
    let bridge = serde_json::to_vec(&first.bridge).unwrap();
    for n in net.nodes.values() {
        assert_eq!(n.tip_hash, first.tip_hash, "{}", n.id);
        assert_eq!(n.commitment_root(), root, "{}", n.id);
        assert_eq!(serde_json::to_vec(&n.bridge).unwrap(), bridge, "{}", n.id);
        assert_eq!(
            n.defi.asset_bal("sally", "ETH"),
            first.defi.asset_bal("sally", "ETH"),
            "{}",
            n.id
        );
    }
}

#[test]
fn replay_below_h2_matches_a_node_that_never_activates() {
    let id = [4u8; 32];
    let amount = 4_200u64;
    let dest = crate::btc_spv::dest_id20("sally");
    let log = v3_log(&id, &SENDER, &dest, &[0u8; 20], amount, HEAD_TS);
    let built = build_receipt(&[log]);
    let header = rlp_exec(50, [9u8; 32], built.receipts_root, HEAD_TS);
    let proof = proof_of(&header, &built);

    let mut off = Network::bootstrap(&["v1", "v2", "v3"], 1000, &users(), cfg());
    let mut net = Network::bootstrap(&["v1", "v2", "v3"], 1000, &users(), cfg());
    install(&mut off, u64::MAX, &header);
    install(&mut net, 3, &header);

    off.payment("bob", "carol", 1, 1).unwrap();
    off.seal_next_height().unwrap();
    net.payment("bob", "carol", 1, 1).unwrap();
    net.seal_next_height().unwrap();
    assert_eq!(net.tip_height(), 1);

    let err = net.nodes.get_mut("v1").unwrap().eth_v3_deposit(
        "ETH",
        &hex::encode(id),
        "sally",
        &proof,
    );
    let err = err.unwrap_err();
    assert_eq!(err, V3_DEPOSITS_NOT_ACTIVE);
    assert!(!Node::is_permanent_tx_failure(&err));

    let tx = sign(
        &net,
        "alice",
        1,
        TxBody::EthV3Deposit {
            asset: "ETH".into(),
            deposit_id: hex::encode(id),
            credit_to: "sally".into(),
            proof: proof.clone(),
        },
    );
    // #34: tip + 1 = 2 < H2 = 3, so every seat refuses it at mempool entry
    // (not kept, not relayed) with the same non-permanent error.
    for n in net.nodes.values_mut() {
        assert_eq!(n.submit_tx(tx.clone()).unwrap_err(), V3_DEPOSITS_NOT_ACTIVE);
        assert!(!n.mempool.by_id.contains_key(&tx.tx_id));
    }
    net.payment("bob", "carol", 1, 1).unwrap();
    off.payment("bob", "carol", 1, 1).unwrap();
    net.seal_next_height().unwrap();
    off.seal_next_height().unwrap();
    assert_eq!(net.tip_height(), 2);
    // tip + 1 = 3 = H2: the same signed tx is admitted now.
    submit_all(&mut net, &tx);
    assert_eq!(
        net.nodes["v1"].commitment_root(),
        off.nodes["v1"].commitment_root(),
        "below H2 the root matches a seat whose V3 gate never opens"
    );
    let js = serde_json::to_string(&net.nodes["v1"].bridge).unwrap();
    assert_eq!(js, serde_json::to_string(&off.nodes["v1"].bridge).unwrap());
    assert!(!js.contains("eth_v1_deposit_cutoff"));
    assert!(!js.contains("eth_v3_deposits"));
    let h2 = net.nodes["v1"]
        .chain
        .iter()
        .find(|l| l.height == 2)
        .unwrap();
    assert!(h2.txs.iter().all(|t| !matches!(t.body, TxBody::EthV3Deposit { .. })));
    assert!(net.nodes["v1"]
        .mempool
        .iter_candidates()
        .any(|t| t.tx_id == tx.tx_id));

    let snap = net.nodes["v1"].to_snapshot();
    let snap_path = std::env::temp_dir().join(format!(
        "pl-eth-v3-replay-{}-{}.json",
        std::process::id(),
        snap.tip_height
    ));
    std::fs::write(&snap_path, serde_json::to_vec(&snap).unwrap()).unwrap();
    let root_at_snap = net.nodes["v1"].commitment_root();

    net.seal_next_height().unwrap();
    assert_eq!(net.tip_height(), 3);
    let v1 = &net.nodes["v1"];
    assert_eq!(v1.defi.asset_bal("sally", "ETH"), amount);
    assert_eq!(v1.bridge.eth_v1_deposit_cutoff, header.number);
    assert_eq!(v1.bridge.eth_v3_resolved_counts(), (1, 0));
    assert!(v1.chain.last().unwrap().txs.iter().any(|t| matches!(t.body, TxBody::EthV3Deposit { .. })));
    assert!(!v1.mempool.iter_candidates().any(|t| t.tx_id == tx.tx_id));
    let status = v1.status_json();
    assert_eq!(status["eth_v3_from_height"], 3);
    assert_eq!(status["eth_v3_bridge"], format!("0x{}", hex::encode(BRIDGE)));
    assert_eq!(status["eth_v1_deposit_cutoff"], header.number);
    assert_eq!(status["eth_v3_resolved_total"], 1);
    roots_agree(&net);

    off.payment("bob", "carol", 1, 1).unwrap();
    off.seal_next_height().unwrap();
    assert_eq!(off.nodes["v1"].bridge.eth_v1_deposit_cutoff, 0);
    assert_ne!(
        off.nodes["v1"].commitment_root(),
        net.nodes["v1"].commitment_root()
    );

    let later: Vec<Ledger> = net.nodes["v1"]
        .chain
        .iter()
        .filter(|l| l.height > 2)
        .cloned()
        .collect();
    let keys = net.nodes["v1"].keys.clone();
    let mut replay = Node::load_snapshot(&snap_path, keys).unwrap();
    let _ = std::fs::remove_file(&snap_path);
    assert_eq!(replay.tip_height, 2);
    assert_eq!(replay.eth_v3_from_height, u64::MAX, "gate is not snapshotted");
    assert_eq!(replay.eth_v3_bridge, evm_spv::parse_qc_v3_bridge_env(None).unwrap(), "bridge address is not snapshotted (binary default)");
    assert_eq!(replay.commitment_root(), root_at_snap);
    replay.eth_v3_from_height = 3;
    replay.eth_v3_bridge = Some(BRIDGE);
    replay.apply_catchup_batch(&later).unwrap();
    assert_eq!(replay.tip_height, 3);
    assert_eq!(replay.commitment_root(), net.nodes["v1"].commitment_root());
    assert_eq!(replay.defi.asset_bal("sally", "ETH"), amount);
    assert_eq!(replay.bridge.eth_v1_deposit_cutoff, header.number);
    assert_eq!(
        replay.bridge.eth_v3_resolution(&hex::encode(id)).map(mint_of),
        Some(Some(("sally", amount)))
    );
}

#[test]
fn three_nodes_agree_on_one_mint_and_one_refund() {
    let mint_id = [1u8; 32];
    let refund_id = [2u8; 32];
    let dest = crate::btc_spv::dest_id20("sally");
    let logs = vec![
        v3_log(&mint_id, &SENDER, &dest, &[0u8; 20], 5_000, HEAD_TS),
        v3_log(
            &refund_id,
            &SENDER,
            &dest,
            &[0u8; 20],
            7_000,
            HEAD_TS - ETH_V3_DEPOSIT_EXPIRY_SECS - 1,
        ),
    ];
    let built = build_receipt(&logs);
    let header = rlp_exec(50, [9u8; 32], built.receipts_root, HEAD_TS);
    let proof = proof_of(&header, &built);
    let mut net = Network::bootstrap(&["v1", "v2", "v3"], 1000, &users(), cfg());
    install(&mut net, 1, &header);
    let tx1 = sign(
        &net,
        "alice",
        1,
        TxBody::EthV3Deposit {
            asset: "ETH".into(),
            deposit_id: hex::encode(mint_id),
            credit_to: "sally".into(),
            proof: proof.clone(),
        },
    );
    let tx2 = sign(
        &net,
        "alice",
        2,
        TxBody::EthV3Deposit {
            asset: "ETH".into(),
            deposit_id: hex::encode(refund_id),
            credit_to: String::new(),
            proof,
        },
    );
    submit_all(&mut net, &tx1);
    submit_all(&mut net, &tx2);
    let sealed = net.seal_next_height().unwrap();
    assert_eq!((sealed.height, sealed.n_txs), (1, 2));
    roots_agree(&net);
    let v1 = &net.nodes["v1"];
    assert_eq!(v1.defi.asset_bal("sally", "ETH"), 5_000);
    assert_eq!(v1.bridge.rail(RAIL_ETH).unwrap().total_minted, 5_000);
    assert_eq!(v1.bridge.eth_v1_deposit_cutoff, 50);
    assert_eq!(v1.bridge.eth_v3_resolved_counts(), (1, 1));
    let leaf = withdraw_leaf(&v3_refund_note_id(&refund_id), &SENDER, 7_000, false);
    assert_eq!(v1.bridge.rail(RAIL_ETH).unwrap().claim_leaves, vec![hex::encode(leaf)]);
    let mint_leaf = withdraw_leaf(&v3_mint_note_id(&mint_id), &SENDER, 5_000, false);
    assert!(!crate::lc::evm_claim_leaves(&v1.bridge).contains(&mint_leaf));
    let status = v1.status_json();
    assert_eq!(status["eth_v3_resolved_total"], 2);
    assert_eq!(status["eth_v3_expiry_secs"], ETH_V3_DEPOSIT_EXPIRY_SECS);
    assert_eq!(status["eth_v1_deposit_cutoff"], 50);
    // F1 (#40): resolutions and refund notes are visible in status, so the claim tool can
    // build a refund proof. Status-only: roots already agreed above.
    let res = status["eth_v3_resolutions"].as_array().unwrap();
    assert_eq!(res.len(), 2);
    let by_id = |id: &[u8; 32]| {
        res.iter()
            .find(|r| r["deposit_id"] == hex::encode(id))
            .cloned()
            .unwrap()
    };
    let m = by_id(&mint_id);
    assert_eq!(m["kind"], "mint");
    assert_eq!(
        (m["asset"].as_str(), m["amount"].as_u64()),
        (Some("ETH"), Some(5_000))
    );
    assert_eq!(m["credit_to"], "sally");
    let r = by_id(&refund_id);
    assert_eq!(r["kind"], "refund");
    assert_eq!(r["amount"], 7_000);
    assert_eq!(r["refund_to"], hex::encode(SENDER));
    assert_eq!(r["note_id"], hex::encode(v3_refund_note_id(&refund_id)));
    // Pinned for scripts/test_pl_walletd_v3_claims.py (REFUND_NOTE_OF_02).
    assert_eq!(
        hex::encode(v3_refund_note_id(&refund_id)),
        "a988c126d89667b997adf6da27e96be12d314e3c0f4222bc06970bbade9af593"
    );
    assert_eq!(r["eth_block"], 50);
    let eth_rail = status["rails"]
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["asset"] == "ETH")
        .unwrap();
    let rows: Vec<_> = eth_rail["withdrawals"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|w| w["kind"] == "v3_refund")
        .collect();
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0]["note_id"],
        hex::encode(v3_refund_note_id(&refund_id))
    );
    assert_eq!(rows[0]["external_to"], format!("0x{}", hex::encode(SENDER)));
    assert_eq!(rows[0]["amount"], 7_000);
    assert_eq!(rows[0]["from"], "");
    assert_eq!(rows[0]["deposit_id"], hex::encode(refund_id));
    // The row's leaf is the claim leaf the refund appended.
    assert_eq!(eth_rail["claim_leaves"][0], hex::encode(leaf));
    assert_eq!(eth_rail["open_withdrawals"], 0);
    let usdc_rail = status["rails"]
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["asset"] == "USDC")
        .unwrap();
    assert!(usdc_rail["withdrawals"]
        .as_array()
        .unwrap()
        .iter()
        .all(|w| w["kind"] != "v3_refund"));

    // Resolved map and cutoff ride the snapshot with BridgeState. The gate
    // and the bridge address do not.
    let snap_path = std::env::temp_dir().join(format!(
        "pl-eth-v3-snap-{}-{}.json",
        std::process::id(),
        v1.tip_height
    ));
    let keys = v1.keys.clone();
    std::fs::write(&snap_path, serde_json::to_vec(&v1.to_snapshot()).unwrap()).unwrap();
    let loaded = Node::load_snapshot(&snap_path, keys).unwrap();
    let _ = std::fs::remove_file(&snap_path);
    assert_eq!(loaded.bridge.eth_v1_deposit_cutoff, 50);
    assert_eq!(loaded.bridge.eth_v3_deposits, v1.bridge.eth_v3_deposits);
    assert_eq!(loaded.commitment_root(), v1.commitment_root());
    assert_eq!(loaded.eth_v3_from_height, u64::MAX);
    assert_eq!(loaded.eth_v3_bridge, evm_spv::parse_qc_v3_bridge_env(None).unwrap());
}


#[test]
fn v3_bridge_env_unset_is_none_set_malformed_is_err() {
    use std::ffi::OsStr;
    let parse = evm_spv::parse_qc_v3_bridge_env;
    // Unset / blank env -> the binary default (the deployed V3 from 2.9.61).
    let default = Some(evm_spv::parse_eth_addr("0xEd4eE497F21a9255a59e87535FF2A6097592Cfd4").unwrap());
    assert_eq!(parse(None).unwrap(), default);
    assert_eq!(parse(Some(OsStr::new(""))).unwrap(), default);
    assert_eq!(parse(Some(OsStr::new("  \n"))).unwrap(), default);
    let good = format!(" 0x{} ", hex::encode(BRIDGE));
    assert_eq!(parse(Some(OsStr::new(&good))).unwrap(), Some(BRIDGE));
    let non_hex = format!("0x{}", "zz".repeat(20));
    let too_long = format!("0x{}00", hex::encode(BRIDGE));
    for bad in ["0x1234", "nope", non_hex.as_str(), too_long.as_str()] {
        let e = parse(Some(OsStr::new(bad))).unwrap_err();
        assert!(e.contains(evm_spv::SEPOLIA_QC_V3_BRIDGE_ENV), "{e}");
        assert!(e.contains("malformed"), "{e}");
    }
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let e = parse(Some(OsStr::from_bytes(b"0x\xff"))).unwrap_err();
        assert!(e.contains("not UTF-8"), "{e}");
    }
    assert_eq!(eth_v3_bridge_or_panic(Ok(None)), None);
    assert_eq!(eth_v3_bridge_or_panic(Ok(Some(BRIDGE))), Some(BRIDGE));
}

#[test]
#[should_panic(expected = "refusing to start: FPL_SEPOLIA_QC_V3_BRIDGE")]
fn v3_bridge_malformed_panics_with_clear_message() {
    let r = evm_spv::parse_qc_v3_bridge_env(Some(std::ffi::OsStr::new("0xnot-an-address")));
    eth_v3_bridge_or_panic(r);
}

const V3_BRIDGE_CHILD: &str = "FPL_TEST_V3_BRIDGE_CHILD";

/// Re-runs this test binary with a malformed `FPL_SEPOLIA_QC_V3_BRIDGE` so the
/// real `Node::new` / `Node::load_snapshot` read it. Done in a child process
/// because setting the env in-process would race every other test's `Node::new`.
#[test]
fn v3_bridge_malformed_env_stops_node_new_and_load_snapshot() {
    let exe = std::env::current_exe().unwrap();
    let out = std::process::Command::new(exe)
        .args([
            "--exact",
            "eth_v3_deposit_tests::v3_bridge_malformed_env_child",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(V3_BRIDGE_CHILD, "1")
        .env(evm_spv::SEPOLIA_QC_V3_BRIDGE_ENV, "0xdeadbeef")
        .env_remove("RUST_TEST_THREADS")
        .output()
        .unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out.status.success(), "{text}");
    assert!(text.contains("V3-BRIDGE-CHILD-OK"), "{text}");
}

/// Child half of the test above; a no-op unless the parent set the marker.
#[test]
fn v3_bridge_malformed_env_child() {
    if std::env::var_os(V3_BRIDGE_CHILD).is_none() {
        return;
    }
    assert!(evm_spv::sepolia_qc_v3_bridge_addr().is_err());
    let r = std::panic::catch_unwind(|| {
        Node::new("v1", cfg(), KeyRing::new(CryptoScheme::HmacDev), &users())
    });
    let msg = match r {
        Ok(_) => panic!("Node::new accepted a malformed FPL_SEPOLIA_QC_V3_BRIDGE"),
        Err(p) => p
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string()))
            .unwrap_or_default(),
    };
    assert!(msg.contains("refusing to start"), "{msg}");
    assert!(msg.contains("FPL_SEPOLIA_QC_V3_BRIDGE"), "{msg}");
    assert!(msg.contains("0xdeadbeef"), "{msg}");

    // Build a snapshot with the env cleared for this process only.
    std::env::remove_var(evm_spv::SEPOLIA_QC_V3_BRIDGE_ENV);
    let n = Node::new("v1", cfg(), KeyRing::new(CryptoScheme::HmacDev), &users());
    let keys = n.keys.clone();
    let snap_path = std::env::temp_dir().join(format!(
        "pl-eth-v3-badenv-{}.json",
        std::process::id()
    ));
    std::fs::write(&snap_path, serde_json::to_vec(&n.to_snapshot()).unwrap()).unwrap();
    std::env::set_var(evm_spv::SEPOLIA_QC_V3_BRIDGE_ENV, "0xdeadbeef");
    let loaded = Node::load_snapshot(&snap_path, keys);
    let _ = std::fs::remove_file(&snap_path);
    let err = match loaded {
        Ok(_) => panic!("load_snapshot accepted a malformed FPL_SEPOLIA_QC_V3_BRIDGE"),
        Err(e) => format!("{e:#}"),
    };
    assert!(err.contains("FPL_SEPOLIA_QC_V3_BRIDGE"), "{err}");
    assert!(err.contains("malformed"), "{err}");
    println!("V3-BRIDGE-CHILD-OK");
}

#[test]
fn reserved_non_genesis_ids_refund_inside_e() {
    // `admin`, `bridge`, seat ids… are reserved and not on the creditable
    // list. They refund even after a Pay has given them a ledger entry.
    for (i, name) in ["admin", "bridge", "pool", "operator", "v3"].iter().enumerate() {
        assert!(crate::names::is_reserved_name(name));
        assert_eq!(crate::bridge::v3_creditable_account(name), None, "{name}");
        let id = [0x60 + i as u8; 32];
        let amount = 9u64;
        let dest = crate::btc_spv::dest_id20(name);
        let log = v3_log(&id, &SENDER, &dest, &[0u8; 20], amount, HEAD_TS);
        let mut peg = open_peg(1, HEAD_TS, vec![log]);
        // What any `Pay` to `name` leaves behind.
        peg.node.state.accounts.insert(name.to_string(), Default::default());
        peg.node
            .eth_v3_deposit("ETH", &hex::encode(id), name, &peg.proof)
            .unwrap();
        assert_eq!(peg.node.defi.asset_bal(name, "ETH"), 0);
        assert_eq!(peg.node.bridge.rail(RAIL_ETH).unwrap().total_minted, 0);
        let leaf = withdraw_leaf(&v3_refund_note_id(&id), &SENDER, amount, false);
        assert_eq!(eth_leaves(&peg.node), vec![hex::encode(leaf)]);
    }
    // The fixed list stays creditable, with or without a ledger entry.
    for name in ["alice", "Bob", "carol", "dave", "faucet", "treasury", "watcher-browser"] {
        assert!(crate::names::is_reserved_name(&name.to_ascii_lowercase()));
        assert_eq!(
            crate::bridge::v3_creditable_account(name),
            Some(name.to_ascii_lowercase()),
            "{name}"
        );
    }
    let id = [0x6fu8; 32];
    let dest = crate::btc_spv::dest_id20("watcher-browser");
    let log = v3_log(&id, &SENDER, &dest, &[0u8; 20], 4, HEAD_TS);
    let mut peg = open_peg(1, HEAD_TS, vec![log]);
    peg.node
        .eth_v3_deposit("ETH", &hex::encode(id), "watcher-browser", &peg.proof)
        .unwrap();
    assert_eq!(peg.node.defi.asset_bal("watcher-browser", "ETH"), 4);
}

#[test]
fn mint_that_would_overflow_the_balance_refunds_instead() {
    let id = [0x70u8; 32];
    let amount = 77u64;
    let dest = crate::btc_spv::dest_id20("sally");
    let log = v3_log(&id, &SENDER, &dest, &[0u8; 20], amount, HEAD_TS);
    let mut peg = open_peg(1, HEAD_TS, vec![log]);
    let near_max = u64::MAX - 10;
    peg.node.defi.credit_asset("sally", "ETH", near_max);
    peg.node
        .eth_v3_deposit("ETH", &hex::encode(id), "sally", &peg.proof)
        .unwrap();
    assert_eq!(peg.node.defi.asset_bal("sally", "ETH"), near_max);
    assert_eq!(peg.node.bridge.rail(RAIL_ETH).unwrap().total_minted, 0);
    let leaf = withdraw_leaf(&v3_refund_note_id(&id), &SENDER, amount, false);
    assert_eq!(eth_leaves(&peg.node), vec![hex::encode(leaf)]);
    assert!(matches!(
        peg.node.bridge.eth_v3_resolution(&hex::encode(id)).unwrap(),
        V3Resolution::Refund { .. }
    ));

    // Exactly u64::MAX after the credit still mints.
    let id2 = [0x71u8; 32];
    let log2 = v3_log(&id2, &SENDER, &dest, &[0u8; 20], 10, HEAD_TS);
    let mut peg2 = open_peg(1, HEAD_TS, vec![log2]);
    peg2.node.defi.credit_asset("sally", "ETH", near_max);
    peg2.node
        .eth_v3_deposit("ETH", &hex::encode(id2), "sally", &peg2.proof)
        .unwrap();
    assert_eq!(peg2.node.defi.asset_bal("sally", "ETH"), u64::MAX);
    assert_eq!(
        mint_of(peg2.node.bridge.eth_v3_resolution(&hex::encode(id2)).unwrap()),
        Some(("sally", 10))
    );
}

#[test]
fn malformed_deposit_id_is_one_permanent_error() {
    let id = [0x72u8; 32];
    let dest = crate::btc_spv::dest_id20("sally");
    let log = v3_log(&id, &SENDER, &dest, &[0u8; 20], 5, HEAD_TS);
    let mut peg = open_peg(1, HEAD_TS, vec![log]);
    let before = serde_json::to_vec(&peg.node.bridge).unwrap();
    for bad in ["zz", "0x1234", "", &"ab".repeat(33), &format!("0x{}g", "a".repeat(63))] {
        let err = peg
            .node
            .eth_v3_deposit("ETH", bad, "sally", &peg.proof)
            .unwrap_err();
        assert_eq!(err, V3_DEPOSIT_ID_MALFORMED, "{bad:?}");
        assert!(Node::is_permanent_tx_failure(&err));
    }
    assert_eq!(serde_json::to_vec(&peg.node.bridge).unwrap(), before);
}

#[test]
fn resolved_id_is_refused_before_the_proof_and_at_admission() {
    let id = [0x73u8; 32];
    let dest = crate::btc_spv::dest_id20("sally");
    let logs = vec![v3_log(&id, &SENDER, &dest, &[0u8; 20], 50, HEAD_TS)];
    let built = build_receipt(&logs);
    let header = rlp_exec(50, [9u8; 32], built.receipts_root, HEAD_TS);
    let proof = proof_of(&header, &built);
    let mut net = Network::bootstrap(&["v1", "v2", "v3"], 1000, &users(), cfg());
    install(&mut net, 1, &header);
    let body = |p: &BridgeProof| TxBody::EthV3Deposit {
        asset: "ETH".into(),
        deposit_id: hex::encode(id),
        credit_to: "sally".into(),
        proof: p.clone(),
    };
    let first = sign(&net, "alice", 1, body(&proof));
    submit_all(&mut net, &first);
    net.seal_next_height().unwrap();
    assert_eq!(net.nodes["v1"].defi.asset_bal("sally", "ETH"), 50);

    // A replay with a junk proof is rejected on the map alone, not the proof.
    let junk = BridgeProof::default();
    let err = net.nodes.get_mut("v1").unwrap().eth_v3_deposit("ETH", &hex::encode(id), "sally", &junk);
    assert_eq!(err.unwrap_err(), V3_DEPOSIT_ALREADY_RESOLVED);

    // Mempool admission refuses it too, and does not evict a pending tx at
    // the same account + sequence on the way.
    let pay = Tx::sign_with(&net.user_keys, "alice", 2, "bob", 1, 1, net.cfg.network_id).unwrap();
    let n = net.nodes.get_mut("v1").unwrap();
    n.submit_tx(pay.clone()).unwrap();
    let replay = sign(&net, "alice", 2, body(&proof));
    let n = net.nodes.get_mut("v1").unwrap();
    assert_eq!(n.submit_tx(replay).unwrap_err(), V3_DEPOSIT_ALREADY_RESOLVED);
    assert!(n.mempool.by_id.contains_key(&pay.tx_id));
}

// ---- #34: mempool entry / relay gate before V3 activation ----------------

fn v3_body(id: &[u8; 32], proof: &BridgeProof) -> TxBody {
    TxBody::EthV3Deposit {
        asset: "ETH".into(),
        deposit_id: hex::encode(id),
        credit_to: "sally".into(),
        proof: proof.clone(),
    }
}

fn v3_fixture(id: &[u8; 32], amount: u64) -> (EthExecHeader, BridgeProof) {
    let dest = crate::btc_spv::dest_id20("sally");
    let logs = vec![v3_log(id, &SENDER, &dest, &[0u8; 20], amount, HEAD_TS)];
    let built = build_receipt(&logs);
    let header = rlp_exec(50, [9u8; 32], built.receipts_root, HEAD_TS);
    let proof = proof_of(&header, &built);
    (header, proof)
}

#[test]
fn pre_activation_v3_deposit_is_refused_at_mempool_entry_then_admitted_from_h2() {
    let id = [0x34u8; 32];
    let (header, proof) = v3_fixture(&id, 900);
    let mut net = Network::bootstrap(&["v1", "v2", "v3"], 1000, &users(), cfg());
    install(&mut net, 2, &header); // H2 = 2, tip = 0
    let tx = sign(&net, "alice", 1, v3_body(&id, &proof));

    // tip + 1 = 1 < H2: refused on every seat, not kept.
    for n in net.nodes.values_mut() {
        assert!(!n.eth_v3_at(n.tip_height + 1));
        assert!(n.v3_deposit_pre_activation(&tx));
        let err = n.submit_tx(tx.clone()).unwrap_err();
        assert_eq!(err, V3_DEPOSITS_NOT_ACTIVE);
        assert!(!Node::is_permanent_tx_failure(&err));
        assert!(!n.mempool.by_id.contains_key(&tx.tx_id));
        assert_eq!(n.mempool.len(), 0);
    }
    net.payment("bob", "carol", 1, 1).unwrap();
    net.seal_next_height().unwrap();
    assert_eq!(net.tip_height(), 1);

    // tip + 1 = 2 = H2: the same signed tx is admitted and mints.
    for n in net.nodes.values_mut() {
        assert!(n.eth_v3_at(n.tip_height + 1));
        assert!(!n.v3_deposit_pre_activation(&tx));
        assert_eq!(n.submit_tx(tx.clone()), Ok(true));
    }
    net.seal_next_height().unwrap();
    assert_eq!(net.tip_height(), 2);
    assert_eq!(net.nodes["v1"].defi.asset_bal("sally", "ETH"), 900);
    roots_agree(&net);
}

#[test]
fn refused_v3_deposit_does_not_hold_or_evict_its_sequence() {
    let id = [0x35u8; 32];
    let (header, proof) = v3_fixture(&id, 900);
    let mut net = Network::bootstrap(&["v1", "v2", "v3"], 1000, &users(), cfg());
    let mut off = Network::bootstrap(&["v1", "v2", "v3"], 1000, &users(), cfg());
    install(&mut net, u64::MAX, &header);
    install(&mut off, u64::MAX, &header);
    let nid = net.cfg.network_id;

    // A pending payment at seq 1 is not evicted by a refused V3 at seq 1.
    let pay1 = Tx::sign_with(&net.user_keys, "alice", 1, "bob", 1, 1, nid).unwrap();
    submit_all(&mut net, &pay1);
    let v3_at_1 = sign(&net, "alice", 1, v3_body(&id, &proof));
    for n in net.nodes.values_mut() {
        assert_eq!(n.submit_tx(v3_at_1.clone()).unwrap_err(), V3_DEPOSITS_NOT_ACTIVE);
        assert!(n.mempool.by_id.contains_key(&pay1.tx_id));
    }
    // A refused V3 at seq 2 does not take seq 2: the next tx there is admitted.
    let v3_at_2 = sign(&net, "alice", 2, v3_body(&id, &proof));
    for n in net.nodes.values_mut() {
        assert_eq!(n.submit_tx(v3_at_2.clone()).unwrap_err(), V3_DEPOSITS_NOT_ACTIVE);
    }
    let pay2 = Tx::sign_with(&net.user_keys, "alice", 2, "carol", 1, 1, nid).unwrap();
    submit_all(&mut net, &pay2);
    let sealed = net.seal_next_height().unwrap();
    assert_eq!(sealed.n_txs, 2);
    assert_eq!(net.nodes["v1"].state.get("alice").sequence, 3);
    assert_eq!(net.nodes["v1"].mempool.len(), 0);

    // State root is the same as a network that never saw the V3 attempts.
    submit_all(&mut off, &pay1);
    submit_all(&mut off, &pay2);
    off.seal_next_height().unwrap();
    assert_eq!(net.nodes["v1"].commitment_root(), off.nodes["v1"].commitment_root());
    assert_eq!(
        serde_json::to_vec(&net.nodes["v1"].bridge).unwrap(),
        serde_json::to_vec(&off.nodes["v1"].bridge).unwrap()
    );
    roots_agree(&net);
}

#[test]
fn peer_batch_pre_activation_v3_deposit_is_not_kept_or_relayed() {
    let id = [0x36u8; 32];
    let (_header, proof) = v3_fixture(&id, 900);
    let net = Network::bootstrap(&["v1", "v2", "v3"], 1000, &users(), cfg());
    let nid = net.cfg.network_id;
    let v3 = sign(&net, "alice", 1, v3_body(&id, &proof));
    let pay = Tx::sign_with(&net.user_keys, "bob", 1, "carol", 1, 1, nid).unwrap();
    let mut n = fresh_node(u64::MAX);

    // Hub TxsBatch / NeedTxs reply: the V3 tx is dropped, the rest absorbed.
    assert_eq!(n.absorb_txs(&[v3.clone(), pay.clone()]), 1);
    assert!(!n.mempool.by_id.contains_key(&v3.tx_id));
    assert!(n.mempool.by_id.contains_key(&pay.tx_id));

    // Even if one were already in the pool, it is never exported to peers.
    n.mempool.insert(v3.clone(), n.cfg.max_mempool_txs).unwrap();
    let ids = |b: Vec<Tx>| b.into_iter().map(|t| t.tx_id).collect::<Vec<_>>();
    assert_eq!(ids(n.serve_need_txs(64)), vec![pay.tx_id.clone()]);
    assert_eq!(ids(n.dish_batch()), vec![pay.tx_id.clone()]);
    assert_eq!(ids(n.export_mempool_batch(64)), vec![pay.tx_id.clone()]);
    // The skipped V3 tx (first in arrival order) does not use up the limit.
    let mut k = fresh_node(u64::MAX);
    k.mempool.insert(v3.clone(), k.cfg.max_mempool_txs).unwrap();
    k.mempool.insert(pay.clone(), k.cfg.max_mempool_txs).unwrap();
    assert_eq!(ids(k.export_mempool_batch(1)), vec![pay.tx_id.clone()]);
    assert_eq!(ids(k.serve_need_txs(1)), vec![pay.tx_id.clone()]);

    // From tip + 1 >= H2 it is relayed and absorbed like any other tx.
    n.eth_v3_from_height = n.tip_height + 1;
    assert!(ids(n.serve_need_txs(64)).contains(&v3.tx_id));
    let mut m = fresh_node(1);
    assert_eq!(m.absorb_txs(&[v3.clone(), pay.clone()]), 2);
}

// ---- 2.11.13 bridge slim (E): compact exec headers ----

/// Deposit block 50 (receipt `built`), then 51..=`head` up to the LC head;
/// every header carries `ts`.
fn deposit_chain(built: &Built, head: u64, ts: u64) -> Vec<EthExecHeader> {
    let mut out = vec![rlp_exec(50, [9u8; 32], built.receipts_root, ts)];
    for n in 51..=head {
        let parent = crate::eth_ssz::parse32(&out.last().unwrap().hash).unwrap();
        out.push(rlp_exec(n, parent, [7u8; 32], ts));
    }
    out
}

fn install_chain(n: &mut Node, chain: &[EthExecHeader]) {
    let head = chain.last().unwrap();
    n.bridge.eth_lc = Some(lc_at(head.number, &head.hash, &head.receipts_root));
    let m = n.bridge.eth_exec_headers.make_mut();
    for h in chain {
        m.insert(h.number, h.clone());
    }
}

#[test]
fn slim_conversion_is_deterministic_idempotent_and_keeps_links() {
    let built = build_receipt(&[]);
    let chain = deposit_chain(&built, 60, HEAD_TS + 7);
    let mut a = fresh_node(1);
    install_chain(&mut a, &chain);
    let before = serde_json::to_vec(&a.bridge).unwrap();
    assert!(!String::from_utf8_lossy(&before).contains("bridge_slim"));
    assert!(!String::from_utf8_lossy(&before).contains("\"timestamp\""));
    let mut b = a.bridge.clone();
    let mut c: BridgeState = serde_json::from_slice(&before).unwrap();
    assert!(b.bridge_slim_convert());
    assert!(c.bridge_slim_convert());
    let after = serde_json::to_vec(&b).unwrap();
    assert_eq!(after, serde_json::to_vec(&c).unwrap(), "same bytes from a clone and a reparse");
    assert!(!b.bridge_slim_convert(), "second run is a no-op");
    assert_eq!(serde_json::to_vec(&b).unwrap(), after, "idempotent");
    assert_eq!(
        crate::exec_map::sha256_hex_split(&b),
        crate::crypto::sha256_hex(&after),
        "split root over the compact map equals the plain root"
    );
    for h in chain.iter() {
        let s = &b.eth_exec_headers[&h.number];
        assert!(s.rlp_hex.is_empty());
        assert_eq!(s.timestamp, HEAD_TS + 7);
        assert_eq!((&s.hash, &s.parent_hash, &s.receipts_root), (&h.hash, &h.parent_hash, &h.receipts_root));
    }
    assert!(after.len() * 2 < before.len(), "compact map is far smaller");
    // The source bridge is untouched (copy-on-write).
    assert_eq!(serde_json::to_vec(&a.bridge).unwrap(), before);
}

#[test]
fn v3_mint_and_refund_verify_the_same_after_conversion() {
    for (log_ts, refund) in [
        (HEAD_TS - ETH_V3_DEPOSIT_EXPIRY_SECS, false),
        (HEAD_TS - ETH_V3_DEPOSIT_EXPIRY_SECS - 1, true),
    ] {
        let id = [5u8; 32];
        let dest = crate::btc_spv::dest_id20("sally");
        let built = build_receipt(&[v3_log(&id, &SENDER, &dest, &[0u8; 20], 3_000, log_ts)]);
        let chain = deposit_chain(&built, 54, HEAD_TS);
        let mk = || {
            let mut n = fresh_node(1);
            n.eth_v3_bridge = Some(BRIDGE);
            install_chain(&mut n, &chain);
            n
        };
        let mut pre = mk();
        let mut post = mk();
        assert!(post.bridge.bridge_slim_convert());
        let proof = proof_of(&chain[0], &built);
        pre.eth_v3_deposit("ETH", &hex::encode(id), "sally", &proof).unwrap();
        post.eth_v3_deposit("ETH", &hex::encode(id), "sally", &proof).unwrap();
        assert_eq!(
            pre.bridge.eth_v3_resolution(&hex::encode(id)),
            post.bridge.eth_v3_resolution(&hex::encode(id))
        );
        assert_eq!(pre.defi.asset_bal("sally", "ETH"), post.defi.asset_bal("sally", "ETH"));
        assert_eq!(post.defi.asset_bal("sally", "ETH") == 0, refund);
        // A wrong block hash / broken link is still refused after conversion.
        let mut bad = proof.clone();
        bad.block_hash = "11".repeat(32);
        let mut post2 = fresh_node(1);
        post2.eth_v3_bridge = Some(BRIDGE);
        install_chain(&mut post2, &chain);
        post2.bridge.bridge_slim_convert();
        assert!(post2.eth_v3_deposit("ETH", &hex::encode([6u8; 32]), "sally", &bad).is_err());
        let mut broken = post2.bridge.clone();
        broken.eth_exec_headers.make_mut().get_mut(&52).unwrap().parent_hash = "22".repeat(32);
        post2.bridge = broken;
        let e = post2.eth_v3_deposit("ETH", &hex::encode(id), "sally", &proof).unwrap_err();
        assert!(e.contains("parent mismatch"), "{e}");
    }
}

#[test]
fn inserts_after_conversion_are_verified_then_compacted() {
    let built = build_receipt(&[]);
    let chain = deposit_chain(&built, 56, HEAD_TS);
    let mut n = fresh_node(1);
    install_chain(&mut n, &chain[..5]);
    let mut b = n.bridge.clone();
    // Pre-slim: a submitted timestamp is ignored (older parsers drop it).
    let mut extra = chain[5].clone();
    extra.timestamp = 99;
    b.eth_lc.as_mut().unwrap().execution_block_hash = chain[5].hash.clone();
    b.eth_lc.as_mut().unwrap().execution_number = 55;
    b.eth_add_exec_headers(vec![extra]).unwrap();
    assert_eq!(b.eth_exec_headers[&55].timestamp, 0);
    assert!(!b.eth_exec_headers[&55].rlp_hex.is_empty());
    // Post-slim: the RLP is still required and verified, then dropped.
    b.bridge_slim_convert();
    let mut tampered = chain[6].clone();
    tampered.receipts_root = "33".repeat(32);
    b.eth_lc.as_mut().unwrap().execution_block_hash = chain[6].hash.clone();
    b.eth_lc.as_mut().unwrap().execution_number = 56;
    assert!(b.eth_add_exec_headers(vec![tampered]).is_err());
    let mut no_rlp = chain[6].clone();
    no_rlp.rlp_hex.clear();
    assert!(b.eth_add_exec_headers(vec![no_rlp]).is_err(), "compact form is never accepted on the wire");
    b.eth_add_exec_headers(vec![chain[6].clone()]).unwrap();
    let s = &b.eth_exec_headers[&56];
    assert!(s.rlp_hex.is_empty());
    assert_eq!(s.timestamp, HEAD_TS);
}

#[test]
fn replay_across_slim_activation_agrees() {
    let id = [9u8; 32];
    let dest = crate::btc_spv::dest_id20("sally");
    let built = build_receipt(&[v3_log(&id, &SENDER, &dest, &[0u8; 20], 2_500, HEAD_TS)]);
    let chain = deposit_chain(&built, 58, HEAD_TS);
    let proof = proof_of(&chain[0], &built);
    let ids = ["v1", "v2", "v3"];
    let mut off = Network::bootstrap(&ids, 1000, &users(), cfg());
    let mut net = Network::bootstrap(&ids, 1000, &users(), cfg());
    for (nw, slim) in [(&mut off, u64::MAX), (&mut net, 3u64)] {
        for n in nw.nodes.values_mut() {
            n.ensure_faucet();
            n.eth_v3_from_height = 1;
            n.eth_v3_bridge = Some(BRIDGE);
            n.bridge_slim_from_height = slim;
            install_chain(n, &chain);
        }
        nw.pong_all();
    }
    // Below the activation: byte-identical to a node that never activates.
    let mut snap2 = None;
    for h in 1..=2u64 {
        off.payment("bob", "carol", 1, 1).unwrap();
        off.seal_next_height().unwrap();
        net.payment("bob", "carol", 1, 1).unwrap();
        net.seal_next_height().unwrap();
        let (o, n) = (&off.nodes["v1"], &net.nodes["v1"]);
        assert_eq!(o.tip_hash, n.tip_hash, "h={h}");
        assert_eq!(o.commitment_root(), n.commitment_root(), "h={h}");
        assert_eq!(
            crate::exec_map::to_vec_split(&o.to_snapshot()).unwrap()
                .len(),
            crate::exec_map::to_vec_split(&n.to_snapshot()).unwrap().len(),
        );
        assert!(!n.bridge.bridge_slim);
        if h == 2 {
            snap2 = Some(n.to_snapshot());
        }
    }
    // Across it: every seat converts in the same block and agrees.
    for _ in 3..=4u64 {
        net.payment("bob", "carol", 1, 1).unwrap();
        net.seal_next_height().unwrap();
    }
    roots_agree(&net);
    assert!(net.nodes["v1"].bridge.bridge_slim);
    assert!(net.nodes["v1"].bridge.eth_exec_headers.values().all(|h| h.rlp_hex.is_empty()));
    // A mint after the conversion verifies on every seat.
    let tx = sign(
        &net,
        "alice",
        1,
        TxBody::EthV3Deposit {
            asset: "ETH".into(),
            deposit_id: hex::encode(id),
            credit_to: "sally".into(),
            proof: proof.clone(),
        },
    );
    submit_all(&mut net, &tx);
    net.seal_next_height().unwrap();
    roots_agree(&net);
    assert_eq!(net.nodes["v1"].defi.asset_bal("sally", "ETH"), 2_500);
    // A node restored from the pre-activation snapshot replays 3..=tip and
    // lands on the same state (converts at 3 like everyone else).
    let dir = std::env::temp_dir().join(format!("fpl-slim-replay-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("h2.json");
    Node::write_snapshot_checked(&path, snap2.as_ref().unwrap(), &|_, _| Ok(())).unwrap();
    let v1 = &net.nodes["v1"];
    let mut r = Node::load_snapshot(&path, v1.keys.clone()).unwrap();
    r.eth_v3_from_height = 1;
    r.eth_v3_bridge = Some(BRIDGE);
    r.bridge_slim_from_height = 3;
    assert_eq!(r.tip_height, 2);
    let tail: Vec<Ledger> = v1.chain.iter().filter(|l| l.height > 2).cloned().collect();
    for l in &tail {
        r.ingest_ledger_catchup(l).unwrap();
    }
    assert_eq!(r.tip_height, v1.tip_height);
    assert_eq!(r.tip_hash, v1.tip_hash);
    assert_eq!(r.commitment_root(), v1.commitment_root());
    let _ = std::fs::remove_dir_all(&dir);
}
