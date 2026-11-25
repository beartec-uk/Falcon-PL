// Copyright (c) 2026 BEARTEC. All rights reserved. See LICENSE.
//! Host: build N Falcon-512 signatures (synthetic, or real FPL packer
//! batch_sigs from archived block bodies), execute + prove the guest, print
//! measured cycles, prove time, receipt size and verify time.
//!
//!   falcon-agg-zk synth <n_sigs> <n_keys> [execute|composite|succinct]
//!   falcon-agg-zk chain <bodies_dir> <n_blocks> [execute|composite|succinct]
use falcon_agg_methods::{FALCON_AGG_GUEST_ELF, FALCON_AGG_GUEST_ID};
use pqcrypto_falcon::falcon512;
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _};
use risc0_zkvm::{default_executor, default_prover, ExecutorEnv, ProverOpts};
use std::collections::BTreeMap;
use std::time::Instant;

type Items = (Vec<Vec<u8>>, Vec<(u32, Vec<u8>, Vec<u8>)>);

fn synth(n: usize, n_keys: usize) -> Items {
    let kp: Vec<_> = (0..n_keys).map(|_| falcon512::keypair()).collect();
    let keys = kp.iter().map(|(pk, _)| pk.as_bytes().to_vec()).collect();
    let items = (0..n)
        .map(|i| {
            let k = i % n_keys;
            let msg = format!("pl-ok:v2|2300|{i}|0|ledgerhash|seat{k}").into_bytes();
            let sig = falcon512::detached_sign(&msg, &kp[k].1).as_bytes().to_vec();
            (k as u32, msg, sig)
        })
        .collect();
    (keys, items)
}

/// Real packer `batch_sig`s: sig over `pl-batch:v1|{batch_root}` by `packer_public_key`.
fn chain(dir: &str, n: usize) -> Items {
    let mut files: Vec<_> = std::fs::read_dir(dir).unwrap().flatten().map(|e| e.path()).collect();
    files.sort();
    let mut keys: Vec<Vec<u8>> = Vec::new();
    let mut idx: BTreeMap<Vec<u8>, u32> = BTreeMap::new();
    let mut items = Vec::new();
    for f in files {
        if items.len() >= n {
            break;
        }
        let v: serde_json::Value = serde_json::from_slice(&std::fs::read(&f).unwrap()).unwrap();
        let (Some(pk), Some(root), Some(sig)) = (
            v["packer_public_key"].as_str(),
            v["batch_root"].as_str(),
            v["batch_sig"].as_str(),
        ) else { continue };
        if sig.is_empty() {
            continue;
        }
        let pkb = hex_decode(pk);
        let k = *idx.entry(pkb.clone()).or_insert_with(|| {
            keys.push(pkb.clone());
            (keys.len() - 1) as u32
        });
        items.push((k, format!("pl-batch:v1|{root}").into_bytes(), hex_decode(sig)));
    }
    (keys, items)
}

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let (keys, items, mode) = match a[1].as_str() {
        "synth" => {
            let (k, i) = synth(a[2].parse().unwrap(), a[3].parse().unwrap());
            (k, i, a.get(4).cloned().unwrap_or("execute".into()))
        }
        "chain" => {
            let (k, i) = chain(&a[2], a[3].parse().unwrap());
            (k, i, a.get(4).cloned().unwrap_or("execute".into()))
        }
        _ => panic!("usage"),
    };
    // sanity: host-side native verify with pqcrypto (and count raw bytes)
    let mut raw_sig_bytes = 0usize;
    for (k, m, s) in &items {
        let pk = falcon512::PublicKey::from_bytes(&keys[*k as usize]).unwrap();
        let sig = falcon512::DetachedSignature::from_bytes(s).unwrap();
        assert!(falcon512::verify_detached_signature(&sig, m, &pk).is_ok());
        raw_sig_bytes += s.len();
    }
    println!(
        "n_sigs={} n_keys={} raw_sig_bytes={} raw_pk_bytes={} mode={mode}",
        items.len(),
        keys.len(),
        raw_sig_bytes,
        keys.len() * 897
    );
    let env = || {
        ExecutorEnv::builder()
            .write(&keys).unwrap()
            .write(&items).unwrap()
            .segment_limit_po2(19)
            .build()
            .unwrap()
    };
    let t = Instant::now();
    let s = default_executor().execute(env(), FALCON_AGG_GUEST_ELF).unwrap();
    println!(
        "execute_ms={} cycles_total={} cycles_user={} segments={} cycles_per_sig={}",
        t.elapsed().as_millis(),
        s.cycles(),
        s.segments.iter().map(|x| x.cycles as u64).sum::<u64>(),
        s.segments.len(),
        s.cycles() / items.len().max(1) as u64
    );
    if mode == "execute" {
        return;
    }
    let opts = if mode == "succinct" { ProverOpts::succinct() } else { ProverOpts::composite() };
    let t = Instant::now();
    let info = default_prover().prove_with_opts(env(), FALCON_AGG_GUEST_ELF, &opts).unwrap();
    let prove_ms = t.elapsed().as_millis();
    let receipt = info.receipt;
    let bytes = bincode::serialize(&receipt).unwrap();
    let seal_bytes = receipt.inner.composite().map(|c| c.segments.iter().map(|s| s.seal.len() * 4).sum::<usize>())
        .or_else(|_| receipt.inner.succinct().map(|s| s.seal.len() * 4))
        .unwrap_or(0);
    let t = Instant::now();
    receipt.verify(FALCON_AGG_GUEST_ID).unwrap();
    let verify_ms = t.elapsed().as_secs_f64() * 1e3;
    let (count, _digest): (u32, [u8; 32]) = receipt.journal.decode().unwrap();
    println!(
        "prove_ms={prove_ms} receipt_bytes={} seal_bytes={seal_bytes} verify_ms={verify_ms:.1} journal_count={count} segments={}",
        bytes.len(),
        info.stats.segments
    );
}
