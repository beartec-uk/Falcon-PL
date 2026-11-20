// Copyright (c) 2025-2026 BEARTEC. All rights reserved. See LICENSE.
//! SNARK-friendly withdraw leaf + MiMC merkle helpers for Phase B.
//!
//! Semantic fields match legacy `bitvm::withdraw_leaf` (note, dest20, amount).
//! Hash function is MiMC (circuit-friendly), not SHA256 — FPL may later
//! publish this root alongside the SHA256 `claim_root`, or Phase C+ adds
//! SHA256 gadgets.

use crate::abi::{domain_fr, note_id_fr, MERKLE_DEPTH};
use ark_bn254::Fr;
use ark_ff::Zero;
use fd_pl_snark::codec::split_hash;
use fd_pl_snark::mimc::mimc2;

/// Compress dest20 into a 32-byte BE buffer (left-padded).
pub fn dest20_to_bytes32(dest_h160: &[u8; 20]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[12..].copy_from_slice(dest_h160);
    out
}

/// Leaf = MiMC2(MiMC2(MiMC2(domain, note_id), MiMC2(dest_hi, dest_lo)), amount).
pub fn withdraw_leaf_fr(note_id: &str, dest_h160: &[u8; 20], amount: u64) -> Fr {
    let dest = dest20_to_bytes32(dest_h160);
    let (d_hi, d_lo) = split_hash(&dest);
    let inner = mimc2(domain_fr(), note_id_fr(note_id));
    let dest_c = mimc2(d_hi, d_lo);
    let mid = mimc2(inner, dest_c);
    mimc2(mid, Fr::from(amount))
}

pub fn leaf_to_bytes32(leaf: Fr) -> [u8; 32] {
    use ark_ff::{BigInteger, PrimeField};
    let mut le = leaf.into_bigint().to_bytes_le();
    le.resize(32, 0);
    le.reverse();
    let mut out = [0u8; 32];
    out.copy_from_slice(&le);
    out
}

fn capacity() -> usize {
    1usize << MERKLE_DEPTH
}

/// Max leaves the fixed-depth claim tree (and the Groth16 circuit) can hold.
pub fn claim_tree_capacity() -> usize {
    capacity()
}

/// Pad leaves to 2^MERKLE_DEPTH so the circuit path is always exactly MERKLE_DEPTH.
pub fn build_tree(leaves: &[Fr], index: usize) -> Result<(Fr, Vec<Fr>, Vec<bool>), String> {
    if leaves.is_empty() {
        return Err("empty tree".into());
    }
    if index >= leaves.len() {
        return Err("leaf index".into());
    }
    let cap = capacity();
    if leaves.len() > cap {
        return Err(format!("too many leaves for MERKLE_DEPTH={MERKLE_DEPTH}"));
    }
    let mut layer = leaves.to_vec();
    while layer.len() < cap {
        layer.push(Fr::zero());
    }
    let mut idx = index;
    let mut path = Vec::with_capacity(MERKLE_DEPTH);
    let mut bits = Vec::with_capacity(MERKLE_DEPTH);
    for _ in 0..MERKLE_DEPTH {
        let sib = if idx % 2 == 0 {
            layer[idx + 1]
        } else {
            layer[idx - 1]
        };
        path.push(sib);
        bits.push(idx % 2 == 1);
        let mut next = Vec::with_capacity(layer.len() / 2);
        for pair in layer.chunks(2) {
            next.push(mimc2(pair[0], pair[1]));
        }
        idx /= 2;
        layer = next;
    }
    Ok((layer[0], path, bits))
}

/// One MiMC merkle step: left/right ordered by path bit (caller orders).
pub fn verify_path_step(left: Fr, right: Fr) -> Fr {
    mimc2(left, right)
}

/// Verify a path against a root (native).
pub fn verify_path(leaf: Fr, path: &[Fr], bits: &[bool], root: Fr) -> bool {
    if path.len() != MERKLE_DEPTH || bits.len() != MERKLE_DEPTH {
        return false;
    }
    let mut h = leaf;
    for i in 0..MERKLE_DEPTH {
        h = if bits[i] {
            mimc2(path[i], h)
        } else {
            mimc2(h, path[i])
        };
    }
    h == root
}
