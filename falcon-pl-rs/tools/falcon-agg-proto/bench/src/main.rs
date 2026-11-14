// Copyright (c) 2026 BEARTEC. All rights reserved. See LICENSE.
//! Prototype bench (not used by the node). Usage:
//!   falcon-agg-bench [n_sigs] [threads]
//! Prints measured per-signature verify cost for:
//!   A  pqcrypto-falcon verify on pre-parsed key + sig bytes (raw crypto)
//!   B  the node path today: hex-decode pk (897 B) + parse + hex-decode sig + verify
//!      (mirrors `KeyRing::verify_pop` -> `PublicKey::from_hex` -> `verify_with_public`)
//!   C  pure-Rust falcon512-verify (the code that runs in the zkVM guest)
//!   D  pqcrypto verify split across `threads` workers (std::thread::scope, like
//!      `preverify_pack_sigs`)
use falcon512_verify as fv;
use pqcrypto_falcon::falcon512;
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _};
use std::time::Instant;

struct Item {
    pk: falcon512::PublicKey,
    pk_hex: String,
    msg: Vec<u8>,
    sig: Vec<u8>,
    sig_hex: String,
}

fn per_sig_us(t: Instant, n: usize) -> f64 {
    t.elapsed().as_secs_f64() * 1e6 / n as f64
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let n: usize = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(1000);
    let threads: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(2).max(1);
    let n_keys = 64.min(n);
    let keys: Vec<_> = (0..n_keys).map(|_| falcon512::keypair()).collect();
    let mut items = Vec::with_capacity(n);
    let mut sig_bytes_total = 0usize;
    for i in 0..n {
        let (pk, sk) = &keys[i % n_keys];
        let msg = format!("pl-tx:v2|acct{i}|{i}|bob|{i}|1|2300|\"Pay\"").into_bytes();
        let sig = falcon512::detached_sign(&msg, sk).as_bytes().to_vec();
        sig_bytes_total += sig.len();
        items.push(Item {
            pk: pk.clone(),
            pk_hex: hex::encode(pk.as_bytes()),
            sig_hex: hex::encode(&sig),
            msg,
            sig,
        });
    }
    println!("n={n} keys={n_keys} threads={threads}");
    println!("mean_sig_bytes={:.1}", sig_bytes_total as f64 / n as f64);
    let reps = 3;
    for rep in 0..reps {
        // A: raw pqcrypto verify
        let t = Instant::now();
        for it in &items {
            let s = falcon512::DetachedSignature::from_bytes(&it.sig).unwrap();
            assert!(falcon512::verify_detached_signature(&s, &it.msg, &it.pk).is_ok());
        }
        let a = per_sig_us(t, n);
        // B: node path (hex pk decode + parse + hex sig decode + verify)
        let t = Instant::now();
        for it in &items {
            let pkb = hex::decode(&it.pk_hex).unwrap();
            let pk = falcon512::PublicKey::from_bytes(&pkb).unwrap();
            let sb = hex::decode(&it.sig_hex).unwrap();
            let s = falcon512::DetachedSignature::from_bytes(&sb).unwrap();
            assert!(falcon512::verify_detached_signature(&s, &it.msg, &pk).is_ok());
        }
        let b = per_sig_us(t, n);
        // C: pure-Rust verifier, key parsed per sig (worst case) and cached
        let t = Instant::now();
        for it in &items {
            let pk = fv::PublicKey::from_bytes(it.pk.as_bytes()).unwrap();
            fv::verify(&pk, &it.msg, &it.sig).unwrap();
        }
        let c = per_sig_us(t, n);
        let cached: Vec<_> = keys
            .iter()
            .map(|(pk, _)| fv::PublicKey::from_bytes(pk.as_bytes()).unwrap())
            .collect();
        let t = Instant::now();
        for (i, it) in items.iter().enumerate() {
            fv::verify(&cached[i % n_keys], &it.msg, &it.sig).unwrap();
        }
        let c2 = per_sig_us(t, n);
        // D: threaded pqcrypto verify
        let t = Instant::now();
        let chunk = n.div_ceil(threads);
        std::thread::scope(|sc| {
            for part in items.chunks(chunk) {
                sc.spawn(move || {
                    for it in part {
                        let s = falcon512::DetachedSignature::from_bytes(&it.sig).unwrap();
                        assert!(falcon512::verify_detached_signature(&s, &it.msg, &it.pk).is_ok());
                    }
                });
            }
        });
        let d = per_sig_us(t, n);
        println!(
            "rep={rep} A_pqcrypto_us={a:.2} B_node_path_us={b:.2} C_pure_rust_parse_each_us={c:.2} C_pure_rust_cached_pk_us={c2:.2} D_pqcrypto_{threads}thr_us_per_sig_wall={d:.2}"
        );
    }
}
