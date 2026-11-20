// Copyright (c) 2025-2026 BEARTEC. All rights reserved. See LICENSE.
//! Lean mempool + negotiated lean tx gossip.
//!
//! * The mempool keeps tx key/signature as raw bytes ([`PoolTx`]) and always
//!   gives back the exact `Tx` that was inserted.
//! * Tx gossip (`submit_tx`, `txs_batch`, `txs_by_ids`) spells sigs `b64:`
//!   only to a session whose peer advertised `lean-tx-gossip-v1`; receivers
//!   turn them back into the same hex before anything else sees them.

use super::*;
use crate::crypto::{
    b64_encode, gossip_lean_sig, gossip_sig_to_hex, is_canonical_hex, is_lean_sig,
    peer_has_lean_tx_gossip, sig_to_hex, CompactHex, CryptoScheme, KeyRing, CAP_LEAN_TX_GOSSIP_V1,
    LEAN_SIG_PREFIX,
};

fn falcon_txs(n: usize) -> (KeyRing, Vec<Tx>) {
    let mut keys = KeyRing::new(CryptoScheme::Falcon512);
    let mut txs = Vec::with_capacity(n);
    for i in 0..n {
        let acct = format!("acct{i:04}");
        keys.generate_id(&acct);
        txs.push(
            Tx::sign_body(&keys, &acct, 0, "bob", i as u64 + 1, 1, NETWORK_ID_PUBLIC_TESTNET_2300, TxBody::Pay)
                .unwrap(),
        );
    }
    (keys, txs)
}

fn line(m: &WireMsg) -> String {
    serde_json::to_string(m).unwrap() + "\n"
}

/// What a session reader does with one line: parse, then the dispatch-time
/// normalisation every lean-capable node runs.
fn receive(l: &str) -> Result<WireMsg, String> {
    let mut m: WireMsg = serde_json::from_str(l.trim_end()).map_err(|e| e.to_string())?;
    m.normalize_gossip_tx_sigs()?;
    Ok(m)
}

fn txs_of(m: &WireMsg) -> Vec<Tx> {
    match m {
        WireMsg::SubmitTx { tx } => vec![tx.clone()],
        WireMsg::TxsBatch { txs } | WireMsg::TxsByIds { txs, .. } => txs.clone(),
        _ => vec![],
    }
}

// ---------------------------------------------------------------------------
// Compact storage
// ---------------------------------------------------------------------------

#[test]
fn compact_hex_is_lossless_for_every_spelling() {
    for s in ["00", "39aa00ff10", "deadbeef"] {
        let c = CompactHex::new(s);
        assert_eq!(c.bytes().map(|b| b.len()), Some(s.len() / 2), "{s} kept as bytes");
        assert_eq!(c.as_text(), s);
        assert!(c.eq_text(s));
        assert_eq!(c.heap_bytes(), s.len() / 2);
    }
    // Anything that would not survive bytes -> hex::encode stays verbatim.
    for s in ["", "39AA00FF10", "39aA", "abc", "zz", "b64:ZnBs", " 00", "00\n"] {
        let c = CompactHex::new(s);
        assert!(c.bytes().is_none(), "{s:?} kept as text");
        assert_eq!(c.as_text(), s);
        assert!(c.eq_text(s));
    }
    let c = CompactHex::new("39aa00ff10");
    assert!(!c.eq_text("39AA00FF10"), "text compare is exact, not case-folded");
    assert!(!c.eq_text("39aa00ff"));
    assert!(!c.eq_text("39aa00ff11"));
    assert!(is_canonical_hex("00ff") && !is_canonical_hex("00FF") && !is_canonical_hex(""));
}

#[test]
fn pool_tx_round_trips_real_falcon_txs_exactly() {
    let (keys, txs) = falcon_txs(8);
    for tx in &txs {
        let p = PoolTx::from_tx(tx.clone());
        assert!(p.signature_bytes().is_some(), "Falcon sig is canonical hex");
        assert!(p.public_key_eq(&tx.public_key));
        let back = p.to_tx();
        assert_eq!(&back, tx, "same Tx, field for field");
        assert_eq!(back.sig_hex(), tx.signature.as_str());
        back.verify(&keys).expect("rebuilt tx still verifies");
    }
    // A non-canonical (upper-case) sig is kept verbatim, not normalised.
    let mut odd = txs[0].clone();
    odd.signature = odd.signature.to_ascii_uppercase();
    let p = PoolTx::from_tx(odd.clone());
    assert!(p.signature_bytes().is_none());
    assert_eq!(p.to_tx(), odd);
    // Empty key (stripped / known account) stays empty.
    let mut stripped = txs[1].clone();
    stripped.public_key.clear();
    let p = PoolTx::from_tx(stripped.clone());
    assert!(p.public_key_is_empty());
    assert_eq!(p.to_tx(), stripped);
}

#[test]
fn mempool_reads_back_identical_txs_and_roots() {
    let (keys, txs) = falcon_txs(12);
    let mut mp = Mempool::default();
    for tx in &txs {
        assert!(mp.insert(tx.clone(), 0).unwrap());
    }
    assert!(!mp.insert(txs[3].clone(), 0).unwrap(), "dupe by tx_id");
    assert_eq!(mp.len(), txs.len());
    assert_eq!(mp.export_batch(512), txs, "arrival order, exact txs");
    for tx in &txs {
        assert_eq!(mp.get_tx(&tx.tx_id).as_ref(), Some(tx));
        assert!(mp.contains(&tx.tx_id));
    }
    let ids: Vec<&str> = mp.iter_candidates().map(|t| t.tx_id.as_str()).collect();
    assert_eq!(ids, txs.iter().map(|t| t.tx_id.as_str()).collect::<Vec<_>>());
    // A sealed batch from pool txs has the same roots and hash as one from
    // the originals: nothing consensus-visible moved.
    let mut keys = keys;
    keys.generate_id("packer");
    let h = params_v2::TESTNET_2300_MERKLE_SENDER_SIG_FROM_HEIGHT + 10;
    let seal = |t: Vec<Tx>| {
        Ledger::seal(h, "00".into(), NETWORK_ID_PUBLIC_TESTNET_2300, "packer", &keys, t, "root".into(), 1)
            .unwrap()
    };
    let mut a = seal(txs.clone());
    let mut b = seal(mp.export_batch(512));
    a.attach_merkle_batch_known_ex(&keys, &|_| None, false).unwrap();
    b.attach_merkle_batch_known_ex(&keys, &|_| None, false).unwrap();
    assert_eq!(a.batch_root, b.batch_root);
    assert_eq!(a.tx_ids, b.tx_ids);
    assert_eq!(a.txs, b.txs);
    // A `b64:` submission (#44 behaviour) is still stored as hex.
    let mut lean = txs[0].clone();
    lean.signature = gossip_lean_sig(&lean.signature).unwrap();
    let mut mp2 = Mempool::default();
    mp2.insert(lean, 0).unwrap();
    assert_eq!(mp2.get_tx(&txs[0].tx_id).unwrap(), txs[0]);
}

// ---------------------------------------------------------------------------
// Gossip encoding
// ---------------------------------------------------------------------------

#[test]
fn lean_gossip_round_trips_for_every_tx_message() {
    let (keys, txs) = falcon_txs(5);
    let msgs = [
        WireMsg::SubmitTx { tx: txs[0].clone() },
        WireMsg::TxsBatch { txs: txs.clone() },
        WireMsg::TxsByIds { ledger_hash: "ab".repeat(32), txs: txs[1..].to_vec() },
    ];
    for m in &msgs {
        assert!(m.is_tx_gossip());
        let lean = m.to_lean_tx_gossip().expect("tx gossip has hex sigs to rewrite");
        for t in txs_of(&lean) {
            assert!(is_lean_sig(&t.signature));
            assert!(is_lean_sig(&t.public_key), "carried key goes lean too");
        }
        let wire = m.to_wire_line(true).unwrap();
        assert_eq!(wire, line(&lean));
        assert!(is_tx_gossip_line(wire.as_bytes()));
        let got = receive(&wire).unwrap();
        assert_eq!(txs_of(&got), txs_of(m), "receiver sees the sender's exact hex txs");
        for t in txs_of(&got) {
            t.verify(&keys).unwrap();
        }
        // Writer-side rewrite of the queued hex line gives the same bytes.
        assert_eq!(lean_tx_gossip_line(line(m).as_bytes()).as_deref(), Some(wire.as_str()));
        // Already lean: nothing more to do.
        assert_eq!(lean_tx_gossip_line(wire.as_bytes()), None);
        // Not lean session: plain serde line, byte for byte.
        assert_eq!(m.to_wire_line(false).unwrap(), line(m));
    }
}

#[test]
fn non_tx_messages_and_block_bodies_are_never_rewritten() {
    let (mut keys, txs) = falcon_txs(2);
    keys.generate_id("packer");
    let l = Ledger::seal(10, "00".into(), NETWORK_ID_PUBLIC_TESTNET_2300, "packer", &keys, txs.clone(), "root".into(), 1)
        .unwrap();
    let others = [
        WireMsg::LedgerBody { ledger: l.clone() },
        WireMsg::ProposeLedger { ledger: l.clone(), catchup: false },
        WireMsg::LedgersBatch { from_height: 1, ledgers: vec![l.clone()] },
        WireMsg::TxInv { ids: vec!["00".repeat(32)] },
        WireMsg::NeedMempoolTxs { ids: vec!["00".repeat(32)] },
        WireMsg::LedgerOk { height: 1, ledger_hash: "h".into(), voter: "v1".into(), signature: "00ff".into(), round: 0 },
    ];
    for m in &others {
        assert!(!m.is_tx_gossip());
        assert!(m.to_lean_tx_gossip().is_none());
        let hex_line = line(m);
        assert_eq!(m.to_wire_line(true).unwrap(), hex_line, "lean session sends it unchanged");
        assert!(lean_tx_gossip_line(hex_line.as_bytes()).is_none());
        let mut back: WireMsg = serde_json::from_str(hex_line.trim_end()).unwrap();
        assert_eq!(back.normalize_gossip_tx_sigs(), Ok(0));
    }
    // A lean block body is *not* turned back into hex by the gossip rule:
    // its spelling is judged by the #44 activation-height check.
    let mut lb = l.clone();
    lb.txs[0].signature = gossip_lean_sig(&lb.txs[0].signature).unwrap();
    let mut m = WireMsg::LedgerBody { ledger: lb.clone() };
    m.normalize_gossip_tx_sigs().unwrap();
    match m {
        WireMsg::LedgerBody { ledger } => assert_eq!(ledger, lb),
        _ => unreachable!(),
    }
    // Piece lines and anything unparseable pass through.
    assert!(lean_tx_gossip_line(b"{\"type\":\"piece\",\"pid\":1,\"i\":0,\"n\":2,\"d\":\"x\"}\n").is_none());
    assert!(lean_tx_gossip_line(b"{\"type\":\"submit_tx\",\"tx\":").is_none());
}

#[test]
fn old_and_new_peers_interoperate() {
    let (keys, txs) = falcon_txs(3);
    // Capability negotiation.
    assert!(utc_header::local_hello_capabilities().iter().any(|c| c == CAP_LEAN_TX_GOSSIP_V1));
    assert!(peer_has_lean_tx_gossip(&utc_header::local_hello_capabilities()));
    assert!(!peer_has_lean_tx_gossip(&[]), "older peer (no caps)");
    assert!(!peer_has_lean_tx_gossip(&[utc_header::CAP_UTC_HEADER_V5.to_string()]), "2.11.x peer");
    // Old Hello JSON (no `capabilities`) still parses and advertises nothing.
    let old_hello = r#"{"type":"hello","id":"v3","public_key":"","validators":{},"publics":{},"tip_height":5,"tip_hash":"","is_hub":false,"mempool_len":0,"product_version":"2.9","hello_network_id":2300,"archive":false,"snap_height":0}"#;
    match serde_json::from_str::<WireMsg>(old_hello).unwrap() {
        WireMsg::Hello { capabilities, .. } => assert!(!peer_has_lean_tx_gossip(&capabilities)),
        _ => unreachable!(),
    }
    let m = WireMsg::TxsBatch { txs: txs.clone() };
    // new -> old: session not lean, so the old peer gets plain hex it can verify.
    let to_old = m.to_wire_line(false).unwrap();
    assert!(!to_old.contains(LEAN_SIG_PREFIX));
    let old_view: WireMsg = serde_json::from_str(to_old.trim_end()).unwrap();
    for t in txs_of(&old_view) {
        assert!(is_canonical_hex(&t.signature));
        // What a pre-#44 node runs: verify the signature string as hex.
        keys.verify_message(keys.scheme, &t.account, &t.public_key, &Tx::payload(&t.account, t.sequence, &t.destination, t.amount, t.fee, t.network_id, &t.body), &t.signature).unwrap();
    }
    // old -> new: a hex line is accepted unchanged.
    let got = receive(&to_old).unwrap();
    assert_eq!(txs_of(&got), txs);
    // new -> new: lean line, same txs after normalisation.
    let got = receive(&m.to_wire_line(true).unwrap()).unwrap();
    assert_eq!(txs_of(&got), txs);
    // Why negotiation is required: a lean sig handed to a node that verifies
    // the raw string as hex (pre-#44) fails, so it must never get one.
    let lean = gossip_lean_sig(&txs[0].signature).unwrap();
    let t = &txs[0];
    assert!(keys
        .verify_message(keys.scheme, &t.account, &t.public_key, &Tx::payload(&t.account, t.sequence, &t.destination, t.amount, t.fee, t.network_id, &t.body), &lean)
        .is_err());
}

#[test]
fn non_canonical_lean_gossip_is_rejected() {
    let (_k, txs) = falcon_txs(3);
    let good = gossip_lean_sig(&txs[0].signature).unwrap();
    let b64 = good.strip_prefix(LEAN_SIG_PREFIX).unwrap().to_string();
    let bytes = sig_to_hex(&good).map(|h| hex::decode(h).unwrap()).unwrap();
    // Build spellings that decode-ish but are not the one canonical form.
    let mut bad: Vec<String> = vec![
        format!("{LEAN_SIG_PREFIX}"),                               // empty
        format!("{LEAN_SIG_PREFIX}{}", b64.trim_end_matches('=')),   // padding stripped
        format!("{LEAN_SIG_PREFIX}{b64}\n"),                         // trailing newline
        format!("{LEAN_SIG_PREFIX} {b64}"),                          // whitespace
        format!("{LEAN_SIG_PREFIX}{}", b64.replace('+', "-").replace('/', "_")), // url alphabet
        format!("B64:{b64}"),                                        // wrong prefix case
    ];
    // Non-canonical trailing bits: last char before padding nudged by one.
    if b64.ends_with('=') {
        let mut c: Vec<u8> = b64.clone().into_bytes();
        let i = c.iter().position(|&x| x == b'=').unwrap() - 1;
        c[i] = if c[i] == b'A' { b'B' } else { b'A' };
        let s = String::from_utf8(c).unwrap();
        if crate::crypto::b64_decode(&s).is_none() {
            bad.push(format!("{LEAN_SIG_PREFIX}{s}"));
        }
    }
    // The url/space variants only differ if the encoding hit those chars.
    bad.retain(|s| s != &good);
    for s in &bad {
        if !is_lean_sig(s) {
            // "B64:" is not the lean prefix: treated as a (bad) hex sig and
            // left for the normal verifier, which rejects it.
            assert!(gossip_sig_to_hex(s).unwrap() == s.as_str());
            continue;
        }
        assert!(gossip_sig_to_hex(s).is_err(), "{s:?} must be rejected");
        let mut tx = txs[0].clone();
        tx.signature = s.clone();
        let mut m = WireMsg::SubmitTx { tx };
        assert!(m.normalize_gossip_tx_sigs().is_err(), "submit_tx with {s:?} dropped");
    }
    // Same rule for a carried public key.
    let mut tx = txs[0].clone();
    let lk = gossip_lean_sig(&tx.public_key).unwrap();
    tx.public_key = format!("{lk}=");
    let mut m = WireMsg::SubmitTx { tx };
    let e = m.normalize_gossip_tx_sigs().unwrap_err();
    assert!(e.contains("public key"), "{e}");
    let mut tx = txs[0].clone();
    tx.public_key = lk.clone();
    let mut m = WireMsg::SubmitTx { tx };
    assert_eq!(m.normalize_gossip_tx_sigs(), Ok(0));
    assert_eq!(txs_of(&m), vec![txs[0].clone()]);
    // A batch drops only the bad tx and keeps the rest exactly.
    let mut batch = txs.clone();
    // (Falcon sig length varies, so padding may be absent; a space is always
    // outside the alphabet.)
    batch[1].signature = format!("{LEAN_SIG_PREFIX} {b64}");
    batch[2].signature = gossip_lean_sig(&batch[2].signature).unwrap();
    let mut m = WireMsg::TxsBatch { txs: batch };
    assert_eq!(m.normalize_gossip_tx_sigs(), Ok(1));
    assert_eq!(txs_of(&m), vec![txs[0].clone(), txs[2].clone()]);
    // Canonical lean decodes back to the same bytes, and only canonical
    // lower-case hex is ever rewritten by the sender.
    assert_eq!(hex::decode(gossip_sig_to_hex(&good).unwrap().as_ref()).unwrap(), bytes);
    assert_eq!(good, format!("{LEAN_SIG_PREFIX}{}", b64_encode(&bytes)));
    assert_eq!(gossip_lean_sig(&txs[0].signature.to_ascii_uppercase()), None);
    assert_eq!(gossip_lean_sig(""), None);
    assert_eq!(gossip_lean_sig(&good), None, "already lean");
}

// ---------------------------------------------------------------------------
// Measurements (printed with --nocapture; asserted loosely)
// ---------------------------------------------------------------------------

#[test]
fn gossip_bytes_per_tx_before_and_after() {
    let (_k, txs) = falcon_txs(32);
    let one_hex: usize = txs.iter().map(|t| line(&WireMsg::SubmitTx { tx: t.clone() }).len()).sum();
    let one_lean: usize = txs
        .iter()
        .map(|t| WireMsg::SubmitTx { tx: t.clone() }.to_wire_line(true).unwrap().len())
        .sum();
    let b = WireMsg::TxsBatch { txs: txs.clone() };
    let batch_hex = line(&b).len();
    let batch_lean = b.to_wire_line(true).unwrap().len();
    // Same txs with the key stripped (known account: what most relayed
    // traffic from established accounts looks like after key-bind).
    let mut stripped = txs.clone();
    for t in &mut stripped {
        t.public_key.clear();
    }
    let s = WireMsg::TxsBatch { txs: stripped };
    let s_hex = line(&s).len();
    let s_lean = s.to_wire_line(true).unwrap().len();
    let n = txs.len() as f64;
    eprintln!(
        "GOSSIP submit_tx Falcon-512 (key carried): hex {:.0} B/tx, lean {:.0} B/tx ({:.1}%)",
        one_hex as f64 / n,
        one_lean as f64 / n,
        100.0 * one_lean as f64 / one_hex as f64
    );
    eprintln!(
        "GOSSIP txs_batch x32 (key carried): hex {:.0} B/tx, lean {:.0} B/tx ({:.1}%)",
        batch_hex as f64 / n,
        batch_lean as f64 / n,
        100.0 * batch_lean as f64 / batch_hex as f64
    );
    eprintln!(
        "GOSSIP txs_batch x32 (key stripped): hex {:.0} B/tx, lean {:.0} B/tx ({:.1}%)",
        s_hex as f64 / n,
        s_lean as f64 / n,
        100.0 * s_lean as f64 / s_hex as f64
    );
    assert!(one_lean * 100 < one_hex * 80);
    assert!(s_lean * 100 < s_hex * 80);
}

#[test]
fn mempool_estimated_bytes_per_tx_before_and_after() {
    // Field-level count (the allocator-level measurement lives in
    // tests/mempool_mem.rs, which needs its own counting allocator).
    let (_k, txs) = falcon_txs(64);
    let hex_bytes: usize = txs
        .iter()
        .map(|t| t.account.len() + t.destination.len() + t.tx_id.len() + t.public_key.len() + t.signature.len())
        .sum();
    let mut mp = Mempool::default();
    for t in &txs {
        mp.insert(t.clone(), 0).unwrap();
    }
    let compact = mp.approx_heap_bytes();
    eprintln!(
        "MEMPOOL field bytes/tx: hex {} B, compact {} B",
        hex_bytes / txs.len(),
        compact / txs.len()
    );
    assert!(compact * 100 < hex_bytes * 60);
}
