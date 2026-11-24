//! 2.11.18 compact block relay, first slice: a sealed lean Merkle-batch body
//! travels as tx ids and is rebuilt from the receiver's mempool,
//! byte-identical to the full body; missing ids are pulled; anything else
//! falls back to the full body.

use super::*;

fn falcon_cfg(cap: usize) -> ChainConfig {
    ChainConfig {
        network_id: 9101,
        max_txs_per_ledger: cap,
        pack_budget_ms: 0,
        pong_window_ms: 60_000,
        confirm_depth: 3,
        slash_equivocation: 100,
        scheme: CryptoScheme::Falcon512,
        soft_ok_votes: 4,
        hard_ok_ratio: 0.6,
        progress_timeout_ms: 4_000,
        max_mempool_txs: 50_000,
        ..Default::default()
    }
}

/// Six seats, `n` bound wallets with one pending pay each, and a sealed
/// Merkle-batch body from the lottery packer. Returns (net, packer, peer, body).
fn sealed(n: usize, bind: bool) -> (Network, String, String, Ledger) {
    let seats = ["v1", "v2", "v3", "v4", "v5", "v6"];
    let accts: Vec<(String, u64)> = (0..n).map(|i| (format!("w{i}"), 1_000_000_000u64)).collect();
    let mut net = Network::bootstrap(&seats, 1000, &accts, falcon_cfg(n));
    if bind {
        let pks: Vec<(String, String)> = (0..n)
            .map(|i| { let id = format!("w{i}"); let pk = net.user_keys.public_hex(&id).unwrap(); (id, pk) })
            .collect();
        for node in net.nodes.values_mut() {
            for (id, pk) in &pks {
                let mut a = node.state.get(id);
                a.meta.public_key = pk.clone();
                node.state.accounts.insert(id.clone(), a);
            }
        }
    }
    for i in 0..n {
        net.payment(&format!("w{i}"), &format!("w{}", (i + 1) % n), 1, 1).unwrap();
    }
    net.pong_all();
    let packer = net.nodes["v1"].lottery_packer().unwrap();
    let peer = seats.iter().find(|s| **s != packer).unwrap().to_string();
    let p = net.nodes.get_mut(&packer).unwrap();
    let mut led = p.pack_as(&packer).unwrap();
    led.attach_merkle_batch_known(&p.keys, &|id| p.account_public_key(id)).unwrap();
    (net, packer, peer, led)
}

fn wire_len(m: &WireMsg) -> usize {
    serde_json::to_string(m).unwrap().len()
}

#[test]
fn compact_body_rebuilds_byte_identical_and_accepts() {
    for bind in [true, false] {
        let (mut net, _packer, peer, led) = sealed(64, bind);
        assert!(!led.batch_sig.is_empty());
        let lean = crate::params_v2::lean_body_active(led.network_id, led.height);
        assert_eq!(Node::compact_relay_eligible(&led), lean || led.batch_paths.is_empty());
        let shell = Node::compact_shell(&led);
        assert!(shell.txs.is_empty());
        assert_eq!(shell.tx_ids, led.tx_ids);
        let n = net.nodes.get_mut(&peer).unwrap();
        let rebuilt = n.assemble_body_by_id(shell).expect("all txs in the peer pool");
        assert_eq!(
            serde_json::to_string(&rebuilt).unwrap(),
            serde_json::to_string(&led).unwrap(),
            "rebuilt body is byte-identical to the packer's (bind={bind}, lean={lean})"
        );
        n.accept_ledger(&rebuilt).expect("peer accepts the rebuilt body");
    }
}

#[test]
fn missing_ids_are_pulled_then_body_completes() {
    let (mut net, packer, peer, led) = sealed(32, true);
    let gone: Vec<String> = led.tx_ids[..3].to_vec();
    let pulled: Vec<Tx> = led.tx_ids[..3]
        .iter()
        .map(|id| net.nodes[&packer].mempool.get_tx(id).expect("packer pool"))
        .collect();
    let n = net.nodes.get_mut(&peer).unwrap();
    n.mempool.remove_many(&gone);
    let (hash, missing) = n.assemble_body_by_id(Node::compact_shell(&led)).unwrap_err();
    assert_eq!(hash, led.ledger_hash);
    assert_eq!(missing, gone, "asks for exactly the missing ids");
    let done = n.supply_body_txs(&hash, pulled).expect("complete after the pull");
    assert_eq!(serde_json::to_string(&done).unwrap(), serde_json::to_string(&led).unwrap());
    n.accept_ledger(&done).unwrap();
}

#[test]
fn incomplete_pull_falls_back_and_tampered_shell_is_rejected() {
    let (mut net, _packer, peer, led) = sealed(16, true);
    let n = net.nodes.get_mut(&peer).unwrap();
    let gone = vec![led.tx_ids[0].clone()];
    n.mempool.remove_many(&gone);
    let (hash, _) = n.assemble_body_by_id(Node::compact_shell(&led)).unwrap_err();
    assert!(n.supply_body_txs(&hash, Vec::new()).is_none(), "still missing: caller pulls the full body");
    // A shell whose id list was reordered no longer matches the signed tx root.
    let (mut net, _packer, peer, led) = sealed(16, true);
    let mut bad = Node::compact_shell(&led);
    bad.tx_ids.swap(0, 1);
    let n = net.nodes.get_mut(&peer).unwrap();
    let rebuilt = n.assemble_body_by_id(bad).unwrap();
    assert!(n.accept_ledger(&rebuilt).is_err(), "tampered shell fails accept like a tampered body");
}

#[test]
fn compact_shell_is_much_smaller() {
    let (_net, _p, _peer, led) = sealed(400, true);
    let full = wire_len(&WireMsg::LedgerBody { ledger: led.clone() });
    let shell = wire_len(&WireMsg::LedgerBodyById { ledger: Node::compact_shell(&led) });
    println!("COMPACT txs={} full_bytes={full} shell_bytes={shell} ratio={:.1}x", led.txs.len(), full as f64 / shell as f64);
    assert!(shell * 5 < full, "shell {shell} vs full {full}");
}
