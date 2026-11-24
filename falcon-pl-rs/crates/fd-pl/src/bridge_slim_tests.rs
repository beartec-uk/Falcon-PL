//! 2.11.13 bridge slim: a legacy BTC peg-out (vault-signed withdraw) and the
//! spent-deposit guard still work after the activation conversion.

use super::*;
use crate::crypto::sha256_hex;

fn users() -> Vec<(String, u64)> {
    vec![("alice".into(), 1_000_000), ("bob".into(), 1_000_000)]
}

#[test]
fn legacy_btc_pegout_and_double_mint_guard_after_slim() {
        use bridge::{BridgeProof, RailHeader, RAIL_BTC};

        let mut n = Node::new(
            "v1",
            ChainConfig::default(),
            KeyRing::new(CryptoScheme::HmacDev),
            &users(),
        );
        n.bridge.rail_mut(RAIL_BTC).unwrap().min_confirmations = 1;
        let lock = n.bridge.rail(RAIL_BTC).unwrap().lock_id.clone();
        let amount = 50_000u64;
        let secret = {
            let d = sha256_hex(b"test-vault-sk");
            let mut s = [0u8; 32];
            let raw = hex::decode(&d).unwrap();
            s.copy_from_slice(&raw);
            s[0] &= 0x3f;
            s
        };
        let shares = crate::vault::split_secret(&secret, 5, 3, 0, b"tv").unwrap();
        let vp = crate::vault::vault_pub_from_secret(&secret, 0, 5, 3).unwrap();
        n.bridge.rail_mut(RAIL_BTC).unwrap().vault_pub = Some(vp.clone());
        let watch = hex::decode(&vp.spk_hex).unwrap();
        let (raw_tx, tx) = crate::btc_spv::test_deposit_tx(&watch, "bob", amount);
        let hdr = crate::btc_spv::mine_header(
            &"00".repeat(32),
            &tx.txid_display,
            0x207fffff,
            1_700_000_000,
        )
        .unwrap();
        n.submit_rail_header(
            RAIL_BTC,
            RailHeader {
                height: 1,
                hash: String::new(),
                parent_hash: String::new(),
                merkle_root: String::new(),
                raw: hdr.raw_hex.clone(),
            },
            Some("alice"),
        )
        .unwrap();
        let proof = BridgeProof {
            external_txid: tx.txid_display.clone(),
            block_hash: hdr.hash_display.clone(),
            height: 1,
            merkle_path: vec![],
            merkle_index: 0,
            lock_id: lock,
            parent_hash: String::new(),
            merkle_root: hdr.merkle_display.clone(),
            external_to: String::new(),
            raw_tx: crate::btc_spv::hex_encode(&raw_tx),
        };
        n.rail_deposit(RAIL_BTC, "bob", amount, proof.clone(), Some("alice"))
            .unwrap();
        assert_eq!(n.defi.asset_bal("bob", RAIL_BTC), amount);
        assert_eq!(n.bridge.rail(RAIL_BTC).unwrap().total_minted, amount);
        assert!(n.epoch_work.watcher_work.get("alice").copied().unwrap_or(0) >= 2);
        // Grow the legacy rail past the slim keep, then convert: the deposit
        // block (pinned by the vault UTXO) stays, old unpinned headers go.
        {
            let r = n.bridge.rail_mut(RAIL_BTC).unwrap();
            let m = r.headers.make_mut();
            for h in 2..=6_000u64 {
                m.insert(h, RailHeader { height: h, hash: format!("{h:064x}"), parent_hash: format!("{:064x}", h - 1), merkle_root: "00".repeat(32), raw: String::new() });
            }
            r.tip_height = 6_000;
            r.tip_hash = format!("{:064x}", 6_000u64);
        }
        assert!(n.bridge.bridge_slim_convert());
        {
            let r = n.bridge.rail(RAIL_BTC).unwrap();
            assert!(r.headers.contains_key(&1), "vault-pinned deposit block kept");
            assert!(!r.headers.contains_key(&2), "old unpinned header pruned");
            assert_eq!(r.headers.len(), crate::bridge::SLIM_LEGACY_BTC_KEEP + 1);
        }
        let dest = "n1fH7uhaDauQYfuwG6t1aTncvyuBSZtDEY";
        let plan = crate::vault::coin_select(
            &n.bridge.rail(RAIL_BTC).unwrap().vault_utxos,
            10_000,
            dest,
            crate::vault::DEFAULT_FEE_SATS,
        )
        .unwrap();
        let vsig = crate::vault::sign_plan(&shares[0..3], &plan).unwrap();
        let note_id = crate::crypto::sha256_hex(
            format!("wd:BTC:bob:10000:{dest}").as_bytes(),
        );
        let kick = crate::vault::signed_dest_lock_kickoff(
            &shares[0..3],
            &n.bridge.rail(RAIL_BTC).unwrap().vault_utxos,
            dest,
            10_000,
            crate::vault::DEFAULT_FEE_SATS,
            &vp.spk_hex,
            &note_id,
        )
        .unwrap();
        let note = n
            .rail_withdraw_full(RAIL_BTC, "bob", 10_000, dest, Some(&vsig), Some(&kick))
            .unwrap();
        assert!(!note.is_empty());
        assert_eq!(n.defi.asset_bal("bob", RAIL_BTC), amount - 10_000);
        assert_eq!(n.bridge.rail(RAIL_BTC).unwrap().total_burned, 10_000);
        assert!(n.rail_deposit(RAIL_BTC, "bob", amount, proof, None).is_err(), "spent deposit still refused");
}

/// Real data: `FPL_SLIM_SNAPSHOT=/path/to/join-snapshot.json cargo test -p
/// fd-pl --lib real_snapshot_converts -- --ignored`. Two independent loads
/// convert to the same bytes; the split root over the compact maps equals the
/// plain root; mint inputs (links, receipts roots, timestamps) are preserved.
#[test]
#[ignore]
fn real_snapshot_converts_deterministically() {
    let path = std::env::var("FPL_SLIM_SNAPSHOT").expect("FPL_SLIM_SNAPSHOT");
    // A debug-build Node load of a live snapshot (13 bonded) used to trip the
    // v4-freeze check; it must load now.
    {
        let n = Node::load_snapshot(&path, KeyRing::new(CryptoScheme::HmacDev)).unwrap();
        assert_eq!(n.schedule_committee, n.chain.last().unwrap().next_committee);
    }
    let raw = std::fs::read(&path).unwrap();
    let a = crate::snapshot::parse_snapshot_bytes(&raw).unwrap();
    let b = crate::snapshot::parse_snapshot_bytes(&raw).unwrap();
    drop(raw);
    let before = serde_json::to_vec(&a.bridge).unwrap();
    let mut x = a.bridge.clone();
    let mut y = b.bridge.clone();
    assert!(x.bridge_slim_convert());
    assert!(y.bridge_slim_convert());
    let bx = serde_json::to_vec(&x).unwrap();
    assert_eq!(bx, serde_json::to_vec(&y).unwrap());
    assert_eq!(crate::exec_map::sha256_hex_split(&x), sha256_hex(&bx));
    assert!(!x.bridge_slim_convert());
    assert_eq!(serde_json::to_vec(&x).unwrap(), bx, "idempotent");
    assert_eq!(x.eth_exec_headers.len(), a.bridge.eth_exec_headers.len());
    for (n, h) in a.bridge.eth_exec_headers.iter() {
        let c = &x.eth_exec_headers[n];
        assert!(c.rlp_hex.is_empty());
        assert_eq!((&c.hash, &c.parent_hash, &c.receipts_root), (&h.hash, &h.parent_hash, &h.receipts_root));
        let ts = crate::eth_exec::exec_header_timestamp(&hex::decode(&h.rlp_hex).unwrap()).unwrap();
        assert_eq!(c.timestamp, ts);
    }
    let legacy = &x.rails[crate::bridge::RAIL_BTC];
    let pins = crate::vault::vault_header_heights(&legacy.vault_utxos);
    for p in &pins {
        assert!(legacy.headers.contains_key(p));
    }
    assert!(legacy.headers.len() <= crate::bridge::SLIM_LEGACY_BTC_KEEP + pins.len() + 1);
    eprintln!(
        "REAL bridge json {} -> {} bytes, exec {} headers, legacy btc {} -> {} headers, sha {}",
        before.len(),
        bx.len(),
        x.eth_exec_headers.len(),
        a.bridge.rails[crate::bridge::RAIL_BTC].headers.len(),
        legacy.headers.len(),
        sha256_hex(&bx)
    );
}

/// Debug helper for loopback rehearsals: apply a recorded legacy BTC withdraw
/// (`FPL_WD_JSON` = rehearse_btc output) on a recorded snapshot.
#[test]
#[ignore]
fn rehearsal_withdraw_replay() {
    let path = std::env::var("FPL_WD_SNAPSHOT").expect("FPL_WD_SNAPSHOT");
    let wd: serde_json::Value = serde_json::from_str(&std::env::var("FPL_WD_JSON").unwrap()).unwrap();
    let mut n = Node::load_snapshot(&path, KeyRing::new(CryptoScheme::HmacDev)).unwrap();
    let vp: crate::vault::VaultPub = serde_json::from_str(&std::fs::read_to_string(std::env::var("FPL_WD_VAULT").unwrap()).unwrap()).unwrap();
    n.bridge.rail_mut(bridge::RAIL_BTC).unwrap().local_vault_pub = Some(vp);
    let r = n.rail_withdraw_full(
        bridge::RAIL_BTC,
        "faucet",
        50_000,
        "n1fH7uhaDauQYfuwG6t1aTncvyuBSZtDEY",
        wd["vault_sig"].as_str(),
        wd["signed_btc_tx"].as_str(),
    );
    eprintln!("WITHDRAW RESULT {r:?}");
    // The same withdraw as a signed tx through admission, sanitize and apply.
    let k = KeyRing::load_dir(std::env::var("FPL_WD_KEYS").unwrap()).unwrap();
    let mut n = Node::load_snapshot(&path, k.clone()).unwrap();
    let vp: crate::vault::VaultPub = serde_json::from_str(&std::fs::read_to_string(std::env::var("FPL_WD_VAULT").unwrap()).unwrap()).unwrap();
    n.bridge.rail_mut(bridge::RAIL_BTC).unwrap().local_vault_pub = Some(vp);
        let seq = n.state.get("faucet").sequence;
    let body = TxBody::RailWithdraw {
        asset: bridge::RAIL_BTC.into(),
        amount: 50_000,
        external_to: "n1fH7uhaDauQYfuwG6t1aTncvyuBSZtDEY".into(),
        vault_sig: wd["vault_sig"].as_str().unwrap().into(),
        signed_btc_tx: wd["signed_btc_tx"].as_str().unwrap().into(),
    };
    let outer: u64 = std::env::var("FPL_WD_OUTER").ok().and_then(|v| v.parse().ok()).unwrap_or(0);
    let tx = Tx::sign_body(&k, "faucet", seq, "", outer, 2, n.cfg.network_id, body).unwrap();
    let mut n2 = Node::load_snapshot(&path, k.clone()).unwrap();
    n2.bridge.rail_mut(bridge::RAIL_BTC).unwrap().local_vault_pub = n.bridge.rail(bridge::RAIL_BTC).unwrap().local_vault_pub.clone();
    eprintln!("SUBMIT {:?}", n.submit_tx(tx.clone()));
    eprintln!("SANITIZE {:?} pool_after={}", n.sanitize_mempool(), n.mempool.len());
    eprintln!("APPLY {:?}", n2.apply_protocol_tx(&tx));
    n.started_ms = 0;
    for id in ["v1", "v2", "v3", "v4", "v5", "v6"] {
        let mut m = Node::load_snapshot(&path, k.clone()).unwrap();
        m.bridge.rail_mut(bridge::RAIL_BTC).unwrap().local_vault_pub = n.bridge.rail(bridge::RAIL_BTC).unwrap().local_vault_pub.clone();
        m.started_ms = 0;
        m.id = id.into();
        let _ = m.submit_tx(tx.clone());
        let r = m.pack_as_inner(id, true);
        eprintln!("PACK as {id}: {:?} fail={:?} pool={}", r.as_ref().map(|l| (l.tx_ids.len(), l.tx_ids.contains(&tx.tx_id))), m.last_apply_fail_tx, m.mempool.len());
    }
    eprintln!("POOL after pack {}", n.mempool.len());
}
