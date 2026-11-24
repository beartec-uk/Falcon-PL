// Copyright (c) 2025-2026 BEARTEC. All rights reserved. See LICENSE.
//! v2.9.60: rolling ETH exec-header prune, same activation height as Gloas.
//!
//! The floor is `max(old, lc.execution_number - ETH_EXEC_HEADER_WINDOW)` once
//! the head number is resolved. It is part of the state root when non-zero,
//! omitted while zero, and identical on every node that applies the same
//! blocks.

use super::*;
use crate::bridge::{
    BridgeState, DEPOSIT_OLDER_THAN_HEADER_WINDOW, ETH_EXEC_HEADER_WINDOW, RAIL_ETH,
};
use crate::eth_exec::EthExecHeader;
use crate::eth_lc::tests::{gloas_fixture, state_period_1378};
use crate::eth_lc::EthLcState;

const H_1379: &str = "9a8acc058dffdb10c5a143b937608aff8eb8d61ae94771a95b319529dbe7543d";
const N_1379: u64 = 11_856_686;

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

fn rlp_exec(number: u64, parent: [u8; 32], receipts: [u8; 32]) -> EthExecHeader {
    use crate::eth_exec::{keccak256, rlp_bytes, rlp_list, rlp_uint};
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
        rlp_uint(1),
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

fn chain(from: u64, to: u64, receipts: [u8; 32]) -> Vec<EthExecHeader> {
    let mut parent = [3u8; 32];
    let mut out = Vec::with_capacity((to - from + 1) as usize);
    for n in from..=to {
        let h = rlp_exec(n, parent, receipts);
        parent = crate::eth_ssz::parse32(&h.hash).unwrap();
        out.push(h);
    }
    out
}

fn fake(n: u64) -> EthExecHeader {
    EthExecHeader {
        number: n,
        hash: format!("{:064x}", n + 1),
        parent_hash: format!("{:064x}", n),
        receipts_root: "00".repeat(32),
        rlp_hex: "aa".into(),
        timestamp: 0,
    }
}

fn put_headers(st: &mut BridgeState, headers: &[EthExecHeader]) {
    let m = st.eth_exec_headers.make_mut();
    for h in headers {
        m.insert(h.number, h.clone());
    }
}

fn lc_at(number: u64, hash: &str) -> EthLcState {
    EthLcState {
        genesis_validators_root: crate::eth_lc::SEPOLIA_GENESIS_VALIDATORS_ROOT.into(),
        finalized_slot: 10,
        finalized_beacon_root: "ab".repeat(32),
        execution_block_hash: hash.into(),
        execution_number: number,
        receipts_root: "cd".repeat(32),
        period: 3,
        current_agg_pk: String::new(),
        current_pks: vec![],
        next_agg_pk: String::new(),
        next_pks: vec![],
    }
}

fn header_numbers(st: &BridgeState) -> Vec<u64> {
    st.eth_exec_headers.keys().copied().collect()
}

fn sign(net: &Network, acct: &str, seq: u64, body: TxBody) -> Tx {
    Tx::sign_body(&net.user_keys, acct, seq, "", 0, 1, net.cfg.network_id, body).unwrap()
}

fn submit_all(net: &mut Network, tx: &Tx) {
    for n in net.nodes.values_mut() {
        n.submit_tx(tx.clone()).unwrap();
    }
}

fn roots_and_maps_agree(net: &Network) {
    let first = net.nodes.values().next().unwrap();
    let root = first.commitment_root();
    let nums = header_numbers(&first.bridge);
    for n in net.nodes.values() {
        assert_eq!(n.tip_hash, first.tip_hash, "{}", n.id);
        assert_eq!(n.commitment_root(), root, "{}", n.id);
        assert_eq!(n.bridge.eth_exec_prune_floor, first.bridge.eth_exec_prune_floor, "{}", n.id);
        assert_eq!(header_numbers(&n.bridge), nums, "{}", n.id);
        assert_eq!(
            &*n.bridge.eth_exec_headers, &*first.bridge.eth_exec_headers,
            "{}",
            n.id
        );
    }
}

fn net_with(gate: u64, live: &EthLcState) -> Network {
    let mut net = Network::bootstrap(&["v1", "v2", "v3"], 1000, &users(), cfg());
    for n in net.nodes.values_mut() {
        n.eth_lc_gloas_from_height = gate;
        n.bridge.eth_lc = Some(live.clone());
        let m = n.bridge.eth_exec_headers.make_mut();
        for i in 1..=4 {
            let h = fake(i);
            m.insert(h.number, h);
        }
        // `load_snapshot` inserts the faucet if it is missing. Seal with it
        // already present so a replayed block hashes the same accounts.
        n.ensure_faucet();
    }
    net.pong_all();
    net
}

#[test]
fn window_constant_and_pre_activation_bytes_omit_the_floor() {
    assert_eq!(ETH_EXEC_HEADER_WINDOW, 50_400);
    assert_eq!(TESTNET_2300_ETH_LC_GLOAS_FROM_HEIGHT, 409134);
    let headers = chain(1, 3, [7u8; 32]);
    let mut st = BridgeState::with_genesis_rails();
    put_headers(&mut st, &headers);
    st.eth_lc = Some(lc_at(headers[2].number + ETH_EXEC_HEADER_WINDOW, &headers[2].hash));
    let before = serde_json::to_vec(&st).unwrap();
    assert!(
        !serde_json::to_string(&st).unwrap().contains("eth_exec_prune_floor"),
        "zero floor is omitted"
    );
    st.prune_eth_exec_headers(false);
    assert_eq!(serde_json::to_vec(&st).unwrap(), before);
    // Hash-only head: number 0 does not arm the floor.
    st.eth_lc.as_mut().unwrap().execution_number = 0;
    st.prune_eth_exec_headers(true);
    assert_eq!(st.eth_exec_prune_floor, 0);
    assert_eq!(header_numbers(&st), vec![1, 2, 3]);
    assert!(!serde_json::to_string(&st).unwrap().contains("eth_exec_prune_floor"));
}

#[test]
fn floor_advances_only_when_the_lc_head_advances_and_never_decreases() {
    let window = ETH_EXEC_HEADER_WINDOW;
    let head = window + 30;
    let mut headers: Vec<EthExecHeader> = (20..=40).map(fake).collect();
    headers.push(fake(head));
    let mut st = BridgeState::with_genesis_rails();
    put_headers(&mut st, &headers);
    st.eth_lc = Some(lc_at(head, &headers.last().unwrap().hash));
    st.prune_eth_exec_headers(true);
    let floor = head - window;
    assert_eq!(floor, 30);
    assert_eq!(st.eth_exec_prune_floor, floor);
    assert!(!header_numbers(&st).contains(&29));
    assert!(header_numbers(&st).contains(&30));
    assert_eq!(*header_numbers(&st).first().unwrap(), 30);
    assert!(header_numbers(&st).contains(&head));

    let gen = st.eth_exec_headers.generation();
    let json = st.eth_exec_headers.canonical_json();
    st.prune_eth_exec_headers(true);
    assert_eq!(st.eth_exec_prune_floor, floor, "static head does not move the floor");
    assert_eq!(st.eth_exec_headers.generation(), gen);
    assert_eq!(st.eth_exec_headers.canonical_json(), json);

    // Head number drops but stays resolved: floor stays.
    st.eth_lc.as_mut().unwrap().execution_number = head - 10;
    st.prune_eth_exec_headers(true);
    assert_eq!(st.eth_exec_prune_floor, floor);
    assert_eq!(*header_numbers(&st).first().unwrap(), 30);

    // Hash-only again: do not lower the floor or delete more.
    st.eth_lc.as_mut().unwrap().execution_number = 0;
    st.prune_eth_exec_headers(true);
    assert_eq!(st.eth_exec_prune_floor, floor);
    assert_eq!(*header_numbers(&st).first().unwrap(), 30);

    // Head moves forward: floor rolls and the newly-stale prefix goes.
    st.eth_lc.as_mut().unwrap().execution_number = head + 10;
    st.prune_eth_exec_headers(true);
    assert_eq!(st.eth_exec_prune_floor, floor + 10);
    assert!(!header_numbers(&st).contains(&(floor + 9)));
    assert_eq!(*header_numbers(&st).first().unwrap(), floor + 10);
}

#[test]
fn headers_below_the_floor_are_not_reinserted() {
    let window = ETH_EXEC_HEADER_WINDOW;
    let floor = 30u64;
    // Head number is WINDOW above the floor so the real constant is what
    // arms it. The stored chain is only the floor boundary plus a short tip
    // whose hash is the LC hash — prune keys off the number, not a full
    // 50_400-header ancestry.
    let head = floor + window;
    let boundary = chain(floor - 1, floor + 2, [2u8; 32]);
    let mut st = BridgeState::with_genesis_rails();
    put_headers(&mut st, &boundary);
    let lc_hash = boundary.last().unwrap().hash.clone();
    st.eth_lc = Some(lc_at(head, &lc_hash));
    st.prune_eth_exec_headers(true);
    assert_eq!(st.eth_exec_prune_floor, floor);
    assert!(!st.eth_exec_headers.contains_key(&(floor - 1)));
    let headers = boundary;

    // Entirely below the floor: rejected, map untouched.
    let below = headers.iter().find(|h| h.number == floor - 1).unwrap().clone();
    let err = st.eth_add_exec_headers(vec![below]).unwrap_err();
    assert_eq!(err, crate::bridge::EXEC_HEADERS_BELOW_PRUNE_FLOOR);
    assert!(!st.eth_exec_headers.contains_key(&(floor - 1)));

    // Prefix under the floor, suffix ends at the LC hash: prefix skipped,
    // suffix accepted, nothing under the floor comes back.
    let err_free = st.eth_add_exec_headers(headers.clone());
    assert!(err_free.is_ok(), "{err_free:?}");
    assert!(!st.eth_exec_headers.contains_key(&(floor - 1)));
    assert!(st.eth_exec_headers.contains_key(&floor));
    assert!(st.eth_exec_headers.contains_key(&(floor + 2)));

    // A new header whose number is the floor, but which is not the stored
    // parent of floor+1 and is not the LC head: connects_down misses the
    // pruned parent, connects_up fails, and it is not inserted.
    let stray = rlp_exec(floor, [9u8; 32], [4u8; 32]);
    let stray_hash = stray.hash.clone();
    let err = st.eth_add_exec_headers(vec![stray]).unwrap_err();
    assert!(
        err.contains("neither reach"),
        "floor header without an upward link must fail connects_down: {err}"
    );
    assert_ne!(
        st.eth_exec_headers.get(&floor).unwrap().hash,
        stray_hash
    );

    // Extending the stored tip still connects downward (parent is stored).
    let tip_n = floor + 2;
    let tip = st.eth_exec_headers.get(&tip_n).unwrap();
    let parent = crate::eth_ssz::parse32(&tip.hash).unwrap();
    let next = rlp_exec(tip_n + 1, parent, [2u8; 32]);
    st.eth_add_exec_headers(vec![next]).unwrap();
    assert!(st.eth_exec_headers.contains_key(&(tip_n + 1)));
    assert_eq!(
        st.eth_exec_prune_floor, floor,
        "a new header above the floor does not roll it"
    );
}

#[test]
fn mint_at_floor_and_floor_plus_one_succeeds_below_fails() {
    use crate::eth_exec::{keccak256, rlp_bytes, rlp_list, rlp_uint};
    let mut st = BridgeState::with_genesis_rails();
    let lock_hex = st.rail(RAIL_ETH).unwrap().lock_id.clone();
    let lock = hex::decode(&lock_hex).unwrap();
    let dest = crate::eth_exec::dest20_from_account("bob");
    let token = [0u8; 20];
    let amount: u64 = 1_000;
    let t0 = keccak256(b"Deposit(bytes32,address,uint256,bytes32)").to_vec();
    let mut t1 = [0u8; 32];
    t1[12..].copy_from_slice(&dest);
    let mut t2 = [0u8; 32];
    t2[12..].copy_from_slice(&token);
    let mut data = [0u8; 64];
    data[24..32].copy_from_slice(&amount.to_be_bytes());
    data[32..64].copy_from_slice(&lock);
    let topics = rlp_list(&[rlp_bytes(&t0), rlp_bytes(&t1), rlp_bytes(&t2)]);
    let addr = crate::evm_spv::sepolia_qc_bridge_addr().unwrap();
    let log = rlp_list(&[rlp_bytes(&addr), topics, rlp_bytes(&data)]);
    let logs = rlp_list(&[log]);
    let bloom = vec![0u8; 256];
    let body = rlp_list(&[rlp_uint(1), rlp_uint(21_000), rlp_bytes(&bloom), logs]);
    let mut receipt = vec![0x02];
    receipt.extend_from_slice(&body);
    let key_nibs = {
        let k = rlp_uint(0);
        let mut ns = Vec::new();
        for b in k {
            ns.push(b >> 4);
            ns.push(b & 0x0f);
        }
        ns
    };
    let leaf = rlp_list(&[rlp_bytes(&hp_leaf(&key_nibs)), rlp_bytes(&receipt)]);
    let receipts_root = keccak256(&leaf);
    // Real window: execution_number sits WINDOW above `floor`, so the cut
    // lands on `floor`. The LC hash is header floor+1, which is where the
    // mint walk stops (hash match), so both in-window deposits prove without
    // a 50_400-header ancestry.
    let floor = 40u64;
    let headers = chain(floor - 1, floor + 1, receipts_root);
    let exec_n = floor + ETH_EXEC_HEADER_WINDOW;
    put_headers(&mut st, &headers);
    st.eth_lc = Some(lc_at(exec_n, &headers[2].hash));
    st.prune_eth_exec_headers(true);
    assert_eq!(st.eth_exec_prune_floor, floor);
    assert!(!st.eth_exec_headers.contains_key(&(floor - 1)));
    assert!(st.eth_exec_headers.contains_key(&floor));
    assert!(st.eth_exec_headers.contains_key(&(floor + 1)));

    let proof_at = |n: u64, txid: &str, block_hash: String| BridgeProof {
        external_txid: txid.into(),
        block_hash,
        height: n,
        merkle_path: vec![hex::encode(&leaf)],
        merkle_index: 0,
        lock_id: String::new(),
        parent_hash: String::new(),
        merkle_root: String::new(),
        external_to: String::new(),
        raw_tx: hex::encode(&receipt),
    };
    let at_floor = proof_at(
        floor,
        &"11".repeat(32),
        st.eth_exec_headers.get(&floor).unwrap().hash.clone(),
    );
    let above = proof_at(
        floor + 1,
        &"22".repeat(32),
        st.eth_exec_headers.get(&(floor + 1)).unwrap().hash.clone(),
    );
    let below = proof_at(floor - 1, &"33".repeat(32), String::new());
    st.mint_evm_lc(RAIL_ETH, amount, &at_floor, "bob").unwrap();
    st.mint_evm_lc(RAIL_ETH, amount, &above, "bob").unwrap();
    assert_eq!(st.rail(RAIL_ETH).unwrap().total_minted, amount * 2);

    let err = st.mint_evm_lc(RAIL_ETH, amount, &below, "bob").unwrap_err();
    assert_eq!(err, DEPOSIT_OLDER_THAN_HEADER_WINDOW);
    assert!(!err.contains("no execution header"), "{err}");
    assert!(!err.contains("missing execution header"), "{err}");
    assert!(
        Node::is_permanent_tx_failure(&err),
        "pruned deposit must leave the mempool"
    );
}

fn hp_leaf(nibbles: &[u8]) -> Vec<u8> {
    let mut o = vec![0x20];
    for i in (0..nibbles.len()).step_by(2) {
        o.push((nibbles[i] << 4) | nibbles[i + 1]);
    }
    o
}

fn exec_headers_1379() -> String {
    let all: Vec<EthExecHeader> =
        serde_json::from_str(&gloas_fixture("exec-headers-amsterdam.json")).unwrap();
    let one: Vec<_> = all.into_iter().filter(|h| h.hash == H_1379).collect();
    assert_eq!(one.len(), 1);
    serde_json::to_string(&one).unwrap()
}

#[test]
fn root_matches_across_nodes_cut_at_activation_then_rolls_and_replays() {
    let live = state_period_1378();
    let e1 = live.execution_number;
    assert!(e1 > ETH_EXEC_HEADER_WINDOW, "period-1378 head {e1}");
    assert!(e1 > 4);
    let floor1 = e1 - ETH_EXEC_HEADER_WINDOW;

    let mut off = net_with(u64::MAX, &live);
    let mut net = net_with(3, &live);
    for _ in 0..2 {
        off.payment("bob", "carol", 1, 1).unwrap();
        off.seal_next_height().unwrap();
        net.payment("bob", "carol", 1, 1).unwrap();
        net.seal_next_height().unwrap();
    }
    assert_eq!(net.tip_height(), 2);
    roots_and_maps_agree(&net);
    roots_and_maps_agree(&off);
    assert_eq!(
        net.nodes["v1"].commitment_root(),
        off.nodes["v1"].commitment_root(),
        "below the gate the root matches a binary that never activates"
    );
    let pre = serde_json::to_string(&net.nodes["v1"].bridge).unwrap();
    assert!(!pre.contains("eth_exec_prune_floor"));
    assert_eq!(header_numbers(&net.nodes["v1"].bridge), vec![1, 2, 3, 4]);
    assert_eq!(net.nodes["v1"].bridge.eth_exec_prune_floor, 0);
    let st = net.nodes["v1"].status_json();
    assert_eq!(st["eth_exec_prune_floor"], 0);
    assert!(st["eth_lc"].get("eth_exec_floor").is_some(), "connected-range low stays");
    assert_eq!(st["eth_exec_window"], ETH_EXEC_HEADER_WINDOW);
    assert_eq!(st["eth_lc"]["eth_exec_window"], ETH_EXEC_HEADER_WINDOW);
    assert_eq!(st["eth_lc_gloas_from_height"], 3);

    let snap = net.nodes["v1"].to_snapshot();
    let snap_path = std::env::temp_dir().join(format!(
        "pl-eth-prune-replay-{}-{}.json",
        std::process::id(),
        snap.tip_height
    ));
    let bytes = serde_json::to_vec(&snap).unwrap();
    std::fs::write(&snap_path, &bytes).unwrap();
    let root_at_snap = net.nodes["v1"].commitment_root();

    // h=3 activation: payment-free ETH update. Start-of-block cut uses the
    // still-resolved period-1378 head, then the Gloas update clears the number.
    let upd = sign(
        &net,
        "alice",
        1,
        TxBody::EthLcUpdate {
            json: gloas_fixture("update-gloas-period-1379.json"),
        },
    );
    submit_all(&mut net, &upd);
    let r = net.seal_next_height().unwrap();
    assert_eq!((r.height, r.n_txs), (3, 1));
    roots_and_maps_agree(&net);
    let v1 = &net.nodes["v1"];
    assert_eq!(v1.bridge.eth_exec_prune_floor, floor1);
    assert!(header_numbers(&v1.bridge).is_empty(), "low headers cut at H");
    assert_eq!(v1.bridge.eth_lc.as_ref().unwrap().execution_number, 0);
    assert!(serde_json::to_string(&v1.bridge).unwrap().contains("eth_exec_prune_floor"));

    // h=4: stored header resolves the hash-only head and the floor rolls.
    let hdrs = sign(
        &net,
        "alice",
        2,
        TxBody::EthExecHeaders {
            headers_json: exec_headers_1379(),
        },
    );
    submit_all(&mut net, &hdrs);
    net.seal_next_height().unwrap();
    roots_and_maps_agree(&net);
    let v1 = &net.nodes["v1"];
    let resolved = v1.bridge.eth_lc.as_ref().unwrap().execution_number;
    assert_eq!(resolved, N_1379);
    assert!(resolved > e1, "Gloas head {resolved} should pass period-1378 {e1}");
    let floor2 = floor1.max(resolved - ETH_EXEC_HEADER_WINDOW);
    assert!(floor2 > floor1, "floor rolls when the LC head moves");
    assert_eq!(v1.bridge.eth_exec_prune_floor, floor2);
    assert_eq!(header_numbers(&v1.bridge), vec![N_1379]);
    let st = v1.status_json();
    assert_eq!(st["eth_exec_prune_floor"], floor2);
    assert!(st["eth_lc"].get("eth_exec_floor").is_some(), "connected-range low stays");
    assert_eq!(st["eth_exec_window"], ETH_EXEC_HEADER_WINDOW);
    assert_eq!(st["eth_lc"]["execution_number"], N_1379);
    assert_eq!(st["eth_lc"]["eth_exec_tip"], N_1379);

    // Static head: another block plus a duplicate header batch does not prune.
    let frozen_floor = v1.bridge.eth_exec_prune_floor;
    let frozen_json = v1.bridge.eth_exec_headers.canonical_json();
    let again = sign(
        &net,
        "carol",
        1,
        TxBody::EthExecHeaders {
            headers_json: exec_headers_1379(),
        },
    );
    submit_all(&mut net, &again);
    let low = rlp_exec(1, [1u8; 32], [1u8; 32]);
    let low_tx = sign(
        &net,
        "alice",
        3,
        TxBody::EthExecHeaders {
            headers_json: serde_json::to_string(&vec![low]).unwrap(),
        },
    );
    submit_all(&mut net, &low_tx);
    net.payment("bob", "carol", 1, 1).unwrap();
    net.seal_next_height().unwrap();
    roots_and_maps_agree(&net);
    let v1 = &net.nodes["v1"];
    assert_eq!(v1.bridge.eth_exec_prune_floor, frozen_floor);
    assert_eq!(v1.bridge.eth_exec_headers.canonical_json(), frozen_json);
    assert!(!v1.bridge.eth_exec_headers.contains_key(&1));
    assert_eq!(
        v1.bridge.eth_lc.as_ref().unwrap().execution_number,
        N_1379
    );

    // Replay from the pre-activation snapshot through the same ledgers.
    let later: Vec<Ledger> = net.nodes["v1"]
        .chain
        .iter()
        .filter(|l| l.height > 2)
        .cloned()
        .collect();
    assert!(later.iter().any(|l| l.height == 3));
    let keys = net.nodes["v1"].keys.clone();
    let mut replay = Node::load_snapshot(&snap_path, keys).unwrap();
    let _ = std::fs::remove_file(&snap_path);
    assert_eq!(replay.tip_height, 2);
    assert_eq!(replay.eth_lc_gloas_from_height, u64::MAX, "snapshot does not store the gate");
    replay.eth_lc_gloas_from_height = 3;
    assert_eq!(
        replay.commitment_root(),
        root_at_snap,
        "snapshot round-trip must match the pre-activation root"
    );
    replay.apply_catchup_batch(&later).unwrap();
    assert_eq!(replay.tip_height, net.nodes["v1"].tip_height);
    assert_eq!(replay.tip_hash, net.nodes["v1"].tip_hash);
    assert_eq!(replay.commitment_root(), net.nodes["v1"].commitment_root());
    assert_eq!(replay.bridge.eth_exec_prune_floor, net.nodes["v1"].bridge.eth_exec_prune_floor);
    assert_eq!(
        &*replay.bridge.eth_exec_headers,
        &*net.nodes["v1"].bridge.eth_exec_headers
    );
}
