// Copyright (c) 2025-2026 BEARTEC. All rights reserved. See LICENSE.
//! v2.11.6 lean block body: `b64:` tx signatures and no Merkle paths from the
//! activation height; legacy bodies unchanged below it and still valid above.

use super::*;
use crate::crypto::{
    b64_decode, b64_encode, is_lean_sig, sig_bytes, sig_to_hex, sig_to_lean, CryptoScheme,
    KeyRing, LEAN_SIG_PREFIX,
};

fn batch(scheme: CryptoScheme, n: usize) -> (KeyRing, Ledger) {
    let mut keys = KeyRing::new(scheme);
    keys.generate_id("packer");
    let mut txs = Vec::with_capacity(n);
    for i in 0..n {
        let acct = format!("a{i}");
        keys.generate_id(&acct);
        txs.push(
            Tx::sign_body(&keys, &acct, 0, "bob", i as u64 + 1, 1, NETWORK_ID_PUBLIC_TESTNET_2300, TxBody::Pay)
                .unwrap(),
        );
    }
    let ledger = Ledger::seal(
        params_v2::TESTNET_2300_MERKLE_SENDER_SIG_FROM_HEIGHT + 10,
        "00".into(),
        NETWORK_ID_PUBLIC_TESTNET_2300,
        "packer",
        &keys,
        txs,
        "root".into(),
        1,
    )
    .unwrap();
    (keys, ledger)
}

fn verify(l: &Ledger, keys: &KeyRing, lean: bool) -> Result<(), String> {
    l.verify_merkle_batch_reg_ex(keys, &|_| None, false, None, lean)
}

#[test]
fn b64_round_trips_and_is_strict() {
    for len in 0..70usize {
        let data: Vec<u8> = (0..len).map(|i| (i * 37 + 11) as u8).collect();
        let e = b64_encode(&data);
        if len == 0 {
            assert_eq!(b64_decode(&e), None, "empty is not a signature");
        } else {
            assert_eq!(b64_decode(&e).as_deref(), Some(&data[..]), "len {len}");
        }
    }
    assert_eq!(b64_encode(b"fpl"), "ZnBs");
    assert_eq!(b64_encode(b"fp"), "ZnA=");
    assert_eq!(b64_decode("ZnA"), None, "missing padding");
    assert_eq!(b64_decode("ZnB="), None, "non-canonical trailing bits");
    assert_eq!(b64_decode("Zg=="), Some(b"f".to_vec()));
    assert_eq!(b64_decode("Zn=="), None, "non-canonical trailing bits");
    assert_eq!(b64_decode("Z==="), None, "three pad chars");
    assert_eq!(b64_decode("ZnA=ZnBs"), None, "padding mid-string");
    assert_eq!(b64_decode("Zn-s"), None, "url alphabet rejected");
    assert_eq!(b64_decode("Zn s"), None, "whitespace rejected");
}

#[test]
fn sig_spellings_convert_both_ways() {
    let hex_sig = "39aa00ff10";
    let lean = sig_to_lean(hex_sig).unwrap();
    assert!(lean.starts_with(LEAN_SIG_PREFIX) && is_lean_sig(&lean));
    assert_eq!(sig_to_hex(&lean).as_deref(), Some(hex_sig));
    assert_eq!(sig_to_hex(hex_sig).as_deref(), Some(hex_sig));
    assert_eq!(sig_to_hex("39AA00FF10").as_deref(), Some(hex_sig));
    assert_eq!(sig_bytes(&lean), sig_bytes(hex_sig));
    assert_eq!(sig_to_hex("b64:not base64"), None);
    assert_eq!(sig_to_hex("zz"), None);
}

#[test]
fn activation_height_is_923200_on_2300() {
    assert_eq!(params_v2::TESTNET_2300_LEAN_BODY_FROM_HEIGHT, 923_200);
    assert_eq!(params_v2::lean_body_from_height(NETWORK_ID_PUBLIC_TESTNET_2300), 923_200);
    // Armed after every height already on the live chain (tip 920,972 on 20 Nov 2026),
    // and well clear of the BTC4 most-work rail at 930,000.
    assert!(params_v2::TESTNET_2300_LEAN_BODY_FROM_HEIGHT > 920_972);
    assert!(params_v2::TESTNET_2300_LEAN_BODY_FROM_HEIGHT < params_v2::TESTNET_2300_BTC4_MOST_WORK_HEIGHT);
    assert!(!params_v2::lean_body_active(NETWORK_ID_PUBLIC_TESTNET_2300, 0));
    assert!(!params_v2::lean_body_active(NETWORK_ID_PUBLIC_TESTNET_2300, 923_199));
    assert!(params_v2::lean_body_active(NETWORK_ID_PUBLIC_TESTNET_2300, 923_200));
    assert!(params_v2::lean_body_active(NETWORK_ID_PUBLIC_TESTNET_2300, 10_000_000));
}

#[test]
fn legacy_attach_is_unchanged_hex_with_paths() {
    let (keys, mut l) = batch(CryptoScheme::HmacDev, 5);
    let before: Vec<String> = l.txs.iter().map(|t| t.signature.clone()).collect();
    l.attach_merkle_batch_known_ex(&keys, &|_| None, false).unwrap();
    let after: Vec<String> = l.txs.iter().map(|t| t.signature.clone()).collect();
    assert_eq!(before, after, "legacy body keeps the pool's hex sigs byte for byte");
    assert_eq!(l.batch_paths.len(), 5);
    verify(&l, &keys, false).unwrap();
    // A legacy body stays valid after activation too (mixed packers / catch-up).
    verify(&l, &keys, true).unwrap();
}

#[test]
fn lean_body_keeps_roots_and_verifies_with_falcon() {
    let (keys, legacy0) = batch(CryptoScheme::Falcon512, 6);
    let mut legacy = legacy0.clone();
    legacy.attach_merkle_batch_known_ex(&keys, &|_| None, false).unwrap();
    let mut lean = legacy0;
    lean.attach_merkle_batch_known_ex(&keys, &|_| None, true).unwrap();
    assert!(lean.batch_paths.is_empty(), "lean omits Merkle paths");
    assert!(lean.txs.iter().all(|t| is_lean_sig(&t.signature)));
    assert_eq!(lean.batch_root, legacy.batch_root, "root is over canonical hex");
    assert_eq!(lean.ledger_hash, legacy.ledger_hash, "header hash unchanged");
    for (a, b) in lean.txs.iter().zip(&legacy.txs) {
        assert_eq!(a.tx_id, b.tx_id);
        assert_eq!(a.sig_hex(), b.signature.as_str());
        a.verify(&keys).expect("lean tx sig verifies");
    }
    verify(&lean, &keys, true).unwrap();
    // Same body before activation is refused (old nodes cannot read it).
    let e = verify(&lean, &keys, false).unwrap_err();
    assert!(e.contains("before activation"), "{e}");
    assert!(lean.check_lean_encoding(false).is_err());
    assert!(lean.check_lean_encoding(true).is_ok());
}

#[test]
fn lean_body_rejects_tampering_and_non_canonical_sigs() {
    let (keys, mut l) = batch(CryptoScheme::HmacDev, 4);
    l.attach_merkle_batch_known_ex(&keys, &|_| None, true).unwrap();
    let mut t = l.clone();
    t.txs[2].amount += 1;
    assert!(verify(&t, &keys, true).is_err(), "payload change caught without paths");
    let mut t = l.clone();
    t.txs.swap(0, 1);
    assert!(verify(&t, &keys, true).is_err(), "reorder caught without paths");
    let mut t = l.clone();
    let raw = sig_bytes(&t.txs[1].signature).unwrap();
    let mut flipped = raw.clone();
    flipped[0] ^= 1;
    t.txs[1].signature = format!("{LEAN_SIG_PREFIX}{}", b64_encode(&flipped));
    assert!(verify(&t, &keys, true).is_err(), "bad sender sig caught");
    let mut t = l.clone();
    t.txs[0].signature = format!("{}\n", t.txs[0].signature);
    let e = t.check_lean_encoding(true).unwrap_err();
    assert!(e.contains("non-canonical"), "{e}");
    // Partial paths are not allowed: either all or none.
    let mut t = l.clone();
    t.batch_paths = vec![vec![]];
    assert!(verify(&t, &keys, true).is_err());
}

#[test]
fn mempool_stores_hex_for_a_lean_submission() {
    let (_keys, l) = batch(CryptoScheme::HmacDev, 1);
    let mut tx = l.txs[0].clone();
    let hex_sig = tx.signature.clone();
    tx.signature = sig_to_lean(&hex_sig).unwrap();
    let mut mp = Mempool::default();
    assert!(mp.insert(tx.clone(), 0).unwrap());
    let stored = mp.iter_candidates().next().unwrap();
    assert_eq!(stored.signature, hex_sig);
    assert_eq!(stored.tx_id, tx.tx_id);
}

#[test]
fn lean_body_is_smaller_on_the_wire() {
    let (keys, base) = batch(CryptoScheme::Falcon512, 40);
    let mut legacy = base.clone();
    legacy.attach_merkle_batch_known_ex(&keys, &|_| None, false).unwrap();
    let mut lean = base;
    lean.attach_merkle_batch_known_ex(&keys, &|_| None, true).unwrap();
    let a = serde_json::to_vec(&legacy).unwrap().len();
    let b = serde_json::to_vec(&lean).unwrap().len();
    eprintln!("40-tx Falcon body: legacy {a} B, lean {b} B ({:.1}%)", 100.0 * b as f64 / a as f64);
    // Every tx here carries a new Falcon key (hex, unchanged by this PR), so
    // this is the worst case for the saving; known-key bodies save more.
    assert!(b * 100 < a * 85, "lean {b} vs legacy {a}");
    // JSON round trip keeps the lean spelling and still verifies.
    let back: Ledger = serde_json::from_slice(&serde_json::to_vec(&lean).unwrap()).unwrap();
    assert_eq!(back, lean);
    verify(&back, &keys, true).unwrap();
}

/// Offline check against real testnet bodies (JSON, one per file). Skipped
/// unless `FPL_REAL_BODIES_DIR` is set, so the default suite needs no data.
#[test]
fn real_bodies_stay_valid_and_convert_losslessly() {
    let Ok(dir) = std::env::var("FPL_REAL_BODIES_DIR") else {
        return;
    };
    let (mut n, mut legacy_b, mut lean_b) = (0usize, 0usize, 0usize);
    for e in std::fs::read_dir(&dir).unwrap() {
        let raw = std::fs::read(e.unwrap().path()).unwrap();
        let l: Ledger = serde_json::from_slice(&raw).unwrap();
        // Old blocks: accepted both before and after activation.
        l.check_lean_encoding(false).unwrap();
        l.check_lean_encoding(true).unwrap();
        if l.batch_sig.is_empty() {
            continue;
        }
        // The sig root is over the exact hex strings already on chain.
        let sigs: Vec<String> = l.txs.iter().map(|t| t.sig_hex().into_owned()).collect();
        assert!(l.txs.iter().zip(&sigs).all(|(t, s)| &t.signature == s));
        let sig_root = hex::encode(merkle_paths(&sigs).0);
        assert_eq!(l.batch_root.split('|').nth(1), Some(sig_root.as_str()));
        // Lean spelling of the same block keeps both roots.
        let mut lean = l.clone();
        lean.batch_paths.clear();
        for t in &mut lean.txs {
            if !t.signature.is_empty() {
                t.signature = sig_to_lean(&t.signature).unwrap();
            }
        }
        lean.check_lean_encoding(true).unwrap();
        assert!(lean.check_lean_encoding(false).is_err());
        let payloads: Vec<String> = lean
            .txs
            .iter()
            .map(|t| Tx::payload(&t.account, t.sequence, &t.destination, t.amount, t.fee, t.network_id, &t.body))
            .collect();
        assert_eq!(Some(hex::encode(merkle_paths(&payloads).0).as_str()), l.batch_root.split('|').next());
        for (a, b) in l.txs.iter().zip(&lean.txs) {
            assert_eq!(a.signature, b.sig_hex());
        }
        n += 1;
        legacy_b += serde_json::to_vec(&l).unwrap().len();
        lean_b += serde_json::to_vec(&lean).unwrap().len();
    }
    assert!(n > 0, "no batch bodies in {dir}");
    eprintln!(
        "{n} real bodies: legacy {legacy_b} B, lean {lean_b} B ({:.1}%)",
        100.0 * lean_b as f64 / legacy_b as f64
    );
}
