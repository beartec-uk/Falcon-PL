// Copyright (c) 2026 BEARTEC. All rights reserved. See LICENSE.
//! Guest: verify every (pk, msg, sig) with the pure-Rust Falcon-512 verifier
//! and commit (count, sha256 over [sha256(pk) || sha256(msg)]...). Any bad
//! signature panics, so no receipt can exist for an invalid batch.
use risc0_zkvm::guest::env;
use risc0_zkvm::sha::{Impl, Sha256};

fn main() {
    // keys are sent once; items reference a key index (committee / repeat senders)
    let keys: Vec<Vec<u8>> = env::read();
    let items: Vec<(u32, Vec<u8>, Vec<u8>)> = env::read();
    let parsed: Vec<falcon512_verify::PublicKey> = keys
        .iter()
        .map(|k| falcon512_verify::PublicKey::from_bytes(k).expect("pk"))
        .collect();
    let key_digests: Vec<[u8; 32]> = keys
        .iter()
        .map(|k| Impl::hash_bytes(k).as_bytes().try_into().unwrap())
        .collect();
    let mut acc: Vec<u8> = Vec::with_capacity(items.len() * 64);
    for (ki, msg, sig) in &items {
        falcon512_verify::verify(&parsed[*ki as usize], msg, sig).expect("falcon verify");
        acc.extend_from_slice(&key_digests[*ki as usize]);
        acc.extend_from_slice(Impl::hash_bytes(msg).as_bytes());
    }
    let digest: [u8; 32] = Impl::hash_bytes(&acc).as_bytes().try_into().unwrap();
    env::commit(&(items.len() as u32, digest));
}
