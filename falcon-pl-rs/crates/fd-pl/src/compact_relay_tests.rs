//! 2.11.18 compact block relay, first slice: a sealed lean Merkle-batch body
//! travels as tx ids and is rebuilt from the receiver's mempool,
//! byte-identical to the full body; missing ids are pulled; anything else
//! falls back to the full body.
//!
//! Run twice: as part of the normal suite (pre-lean rules on the test network)
//! and alone with lean bodies on:
//! `FPL_LEAN_BODY_FROM_HEIGHT=0 cargo test -p fd-pl --release --lib compact_relay -- --nocapture`
//! (the env var is process-wide, so the lean run filters to this module).

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
    let v = serde_json::to_value(Node::compact_shell(&led)).unwrap();
    let mut f: Vec<(usize, String)> = v.as_object().unwrap().iter().map(|(k, x)| (x.to_string().len(), k.clone())).collect();
    f.sort();
    println!("SHELLFIELDS {:?}", f.iter().rev().take(8).collect::<Vec<_>>());
    println!("COMPACT txs={} full_bytes={full} shell_bytes={shell} ratio={:.1}x", led.txs.len(), full as f64 / shell as f64);
    if crate::params_v2::lean_body_active(led.network_id, led.height) {
        assert!(Node::compact_relay_eligible(&led));
        assert!(shell * 5 < full, "lean shell {shell} vs full {full}");
    } else {
        // Pre-lean batch bodies keep per-tx paths and are not sent compact.
        assert!(!Node::compact_relay_eligible(&led));
    }
}

#[test]
fn compact_body_capability_advertised_and_detected() {
    let caps = crate::utc_header::local_hello_capabilities();
    assert!(crate::utc_header::peer_has_compact_body(&caps));
    let old: Vec<String> = vec![crate::utc_header::CAP_UTC_HEADER_V5.to_string()];
    assert!(!crate::utc_header::peer_has_compact_body(&old));
}

// ---- 2.11.19: carry fresh txs, short wait, any-peer pulls ----

#[test]
fn leader_carries_only_fresh_txs_and_rebuild_stays_byte_identical() {
    for bind in [true, false] {
        let (mut net, packer, peer, led) = sealed(64, bind);
        let now = wall_ms();
        // Half the body arrived "long ago" at the packer, half just now.
        {
            let p = net.nodes.get_mut(&packer).unwrap();
            p.compact_carry_ms = 500;
            for (i, id) in led.tx_ids.iter().enumerate() {
                p.mempool.set_arrived_ms(id, if i % 2 == 0 { now - 5_000 } else { now - 100 });
            }
        }
        let (shell, carried) = net.nodes[&packer].compact_shell_fresh(&led, now);
        assert_eq!(carried, 32);
        assert_eq!(shell.txs.len(), 32);
        assert_eq!(shell.tx_ids, led.tx_ids);
        // The peer lacks exactly the fresh (carried) txs.
        let fresh: Vec<String> = led.tx_ids.iter().enumerate().filter(|(i, _)| i % 2 == 1).map(|(_, id)| id.clone()).collect();
        let n = net.nodes.get_mut(&peer).unwrap();
        n.mempool.remove_many(&fresh);
        let rebuilt = n.assemble_body_by_id(shell).expect("carried txs fill the gap");
        assert_eq!(
            serde_json::to_string(&rebuilt).unwrap(),
            serde_json::to_string(&led).unwrap(),
            "byte-identical with carried txs (bind={bind})"
        );
        // carry 0 = 2.11.18 shell
        net.nodes.get_mut(&packer).unwrap().compact_carry_ms = 0;
        let (s0, c0) = net.nodes[&packer].compact_shell_fresh(&led, now);
        assert_eq!(c0, 0);
        assert!(s0.txs.is_empty());
    }
}

#[test]
fn carried_shell_is_much_smaller_than_full_when_little_is_fresh() {
    let (mut net, packer, _peer, led) = sealed(64, true);
    let now = wall_ms();
    let p = net.nodes.get_mut(&packer).unwrap();
    p.compact_carry_ms = 500;
    for (i, id) in led.tx_ids.iter().enumerate() {
        p.mempool.set_arrived_ms(id, if i < 6 { now - 50 } else { now - 9_000 });
    }
    let (shell, carried) = p.compact_shell_fresh(&led, now);
    assert_eq!(carried, 6);
    let full = wire_len(&WireMsg::LedgerBody { ledger: led.clone() });
    let comp = wire_len(&WireMsg::LedgerBodyById { ledger: shell });
    assert!(comp * 3 < full, "compact {comp} vs full {full}");
}

#[test]
fn wait_then_finish_from_mempool_without_pull() {
    let (mut net, packer, peer, led) = sealed(64, true);
    let missing: Vec<Tx> = led.tx_ids[..2].iter().map(|id| net.nodes[&packer].mempool.get_tx(id).unwrap()).collect();
    let ids: Vec<String> = missing.iter().map(|t| t.tx_id.clone()).collect();
    let n = net.nodes.get_mut(&peer).unwrap();
    n.mempool.remove_many(&ids);
    let (hash, miss) = n.assemble_body_by_id(Node::compact_shell(&led)).unwrap_err();
    assert_eq!(miss.len(), 2);
    assert!(n.compact_should_wait(2, 64));
    assert!(!n.compact_should_wait(20, 64), "many missing: pull at once");
    n.park_compact(&hash, 1_000);
    // Not due yet.
    let (d, p) = n.take_compact_due(999);
    assert!(d.is_empty() && p.is_empty());
    // The txs arrive on the tx plane during the wait.
    for t in missing {
        n.mempool.insert(t, 0).unwrap();
    }
    let (done, pulls) = n.take_compact_due(1_000);
    assert!(pulls.is_empty());
    assert_eq!(done.len(), 1);
    assert_eq!(serde_json::to_string(&done[0]).unwrap(), serde_json::to_string(&led).unwrap());
    assert_eq!((n.compact_wait_tries, n.compact_wait_hits), (1, 1));
}

#[test]
fn wait_expires_into_pull_and_adapts_off() {
    let (mut net, packer, peer, led) = sealed(64, true);
    let ids: Vec<String> = led.tx_ids[..3].to_vec();
    let n = net.nodes.get_mut(&peer).unwrap();
    n.mempool.remove_many(&ids);
    let (hash, _) = n.assemble_body_by_id(Node::compact_shell(&led)).unwrap_err();
    n.park_compact(&hash, 10);
    let (done, pulls) = n.take_compact_due(10);
    assert!(done.is_empty());
    assert_eq!(pulls.len(), 1);
    assert_eq!(pulls[0].1, ids);
    assert_eq!(pulls[0].2, packer, "pull names the packer");
    // Waits that never pay off switch the wait off.
    n.compact_wait_tries = 10;
    n.compact_wait_hits = 2;
    assert!(!n.compact_should_wait(2, 64));
    n.compact_wait_hits = 5;
    assert!(n.compact_should_wait(2, 64));
}

#[test]
fn any_peer_answers_id_pull_from_mempool() {
    let (mut net, packer, peer, led) = sealed(64, true);
    let ids: Vec<String> = led.tx_ids[..5].to_vec();
    // A third seat that never saw the body answers from its own pool.
    let third = ["v1", "v2", "v3", "v4", "v5", "v6"]
        .iter()
        .find(|s| **s != packer && **s != peer)
        .unwrap()
        .to_string();
    let txs = net.nodes[&third].txs_for_ids(&led.ledger_hash, &ids);
    assert_eq!(txs.len(), 5);
    let n = net.nodes.get_mut(&peer).unwrap();
    n.mempool.remove_many(&ids);
    let (hash, _) = n.assemble_body_by_id(Node::compact_shell(&led)).unwrap_err();
    assert!(n.has_body_shell(&hash));
    // A partial answer leaves the shell open; the rest finishes it.
    assert!(n.supply_body_txs(&hash, txs[..2].to_vec()).is_none());
    assert!(n.has_body_shell(&hash));
    let done = n.supply_body_txs(&hash, txs[2..].to_vec()).expect("finished");
    assert_eq!(serde_json::to_string(&done).unwrap(), serde_json::to_string(&led).unwrap());
    // A late duplicate reply finds no open shell.
    assert!(!n.has_body_shell(&hash));
    assert!(n.supply_body_txs(&hash, txs).is_none());
}
