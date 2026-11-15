// Copyright (c) 2025-2026 BEARTEC. All rights reserved. See LICENSE.
//! High-level withdraw prove helpers for Phase D integration.

use crate::abi::test_vk_hash;
use crate::circuit::FplWithdrawValid;
use crate::groth16::{proof_to_bytes, prove, setup, verify, vk_from_bytes};
use ark_bn254::Bn254;
use ark_groth16::{ProvingKey, VerifyingKey};
use crate::leaf::{build_tree, leaf_to_bytes32, withdraw_leaf_fr};
use crate::protocol::{claim_id, statement_digest};
use ark_bn254::Fr;
use ark_ff::PrimeField;

pub fn mimc_leaf_hex(note_id: &str, dest_h160: &[u8; 20], amount: u64) -> String {
    hex::encode(leaf_to_bytes32(withdraw_leaf_fr(note_id, dest_h160, amount)))
}

fn fr_from_leaf_hex(h: &str) -> Result<Fr, String> {
    let b = hex::decode(h).map_err(|e| e.to_string())?;
    if b.len() != 32 {
        return Err("leaf not 32 bytes".into());
    }
    Ok(Fr::from_be_bytes_mod_order(&b))
}

pub fn mimc_root_hex_from_leaves(leaves: &[String]) -> Result<String, String> {
    if leaves.is_empty() {
        return Ok(String::new());
    }
    let frs: Result<Vec<Fr>, _> = leaves.iter().map(|h| fr_from_leaf_hex(h)).collect();
    let frs = frs?;
    let idx = frs.len() - 1;
    let (root, _, _) = build_tree(&frs, idx)?;
    Ok(hex::encode(leaf_to_bytes32(root)))
}

pub fn leaf_index(note_id: &str, dest_h160: &[u8; 20], amount: u64, leaves: &[String]) -> Result<usize, String> {
    let want = mimc_leaf_hex(note_id, dest_h160, amount);
    leaves
        .iter()
        .position(|l| l == &want)
        .ok_or_else(|| "note leaf not in mimc tree".into())
}

/// M1: the circuit's public `header_hash` from a consensus FPL checkpoint.
/// `SHA256("fpl-bitvm2-ckpt-v2|" || height_le || lowercase(ledger_hash))`.
/// `ledger_hash` is the hash of the finalized FPL ledger at `height`, recorded
/// in BTC rail state (`fpl_checkpoints`). Replaces [`header_hash_placeholder`]
/// from the M1 activation height.
pub fn checkpoint_header_hash(height: u64, ledger_hash: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"fpl-bitvm2-ckpt-v2|");
    h.update(height.to_le_bytes());
    h.update(ledger_hash.trim().to_ascii_lowercase().as_bytes());
    h.finalize().into()
}

/// Pre-M1 only. Bound to the verifier's *current* tip, and paired with a fresh
/// random setup on every verify (so no proof could ever verify). Kept for
/// replay of pre-activation heights.
pub fn header_hash_placeholder(tip_height: u64, tip_hash: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"fpl-bitvm2-header-v1|");
    h.update(tip_height.to_le_bytes());
    h.update(tip_hash.as_bytes());
    h.finalize().into()
}

pub fn pegout_txid_bytes(display_txid: &str) -> Result<[u8; 32], String> {
    let raw = hex::decode(display_txid.trim()).map_err(|e| e.to_string())?;
    if raw.len() != 32 {
        return Err("txid must be 32 bytes".into());
    }
    let mut internal = raw;
    internal.reverse();
    let mut out = [0u8; 32];
    out.copy_from_slice(&internal);
    Ok(out)
}

/// Prove + verify locally (test setup). Returns proof, publics, digest, claim_id.
pub fn prove_withdraw_attest(
    note_id: &str,
    dest_h160: &[u8; 20],
    amount: u64,
    height: u64,
    header_hash: &[u8; 32],
    pegout_txid: &[u8; 32],
    mimc_leaves: &[String],
    operator: &str,
) -> Result<(String, Vec<String>, String, String), String> {
    let mut rng = rand::rngs::OsRng;
    let (pk, vk) = setup(&mut rng)?;
    prove_withdraw_attest_with_keys(
        &pk, &vk, note_id, dest_h160, amount, height, header_hash, pegout_txid, mimc_leaves, operator,
    )
}

/// The M1 attest statement as a circuit with its witness (used by the arkworks
/// prover below and by the public-setup `.wtns` exporter).
pub fn attest_circuit(
    note_id: &str,
    dest_h160: &[u8; 20],
    amount: u64,
    height: u64,
    header_hash: &[u8; 32],
    pegout_txid: &[u8; 32],
    mimc_leaves: &[String],
) -> Result<FplWithdrawValid, String> {
    let frs: Vec<Fr> = mimc_leaves
        .iter()
        .map(|h| fr_from_leaf_hex(h))
        .collect::<Result<_, _>>()?;
    let leaf_index = leaf_index(note_id, dest_h160, amount, mimc_leaves)?;
    let (root, path, bits) = build_tree(&frs, leaf_index)?;
    FplWithdrawValid::from_withdraw(
        2300,
        amount,
        dest_h160,
        root,
        height,
        header_hash,
        note_id,
        pegout_txid,
        &path,
        &bits,
        test_vk_hash(),
    )
}

/// M1: prove with a fixed proving key (ceremony pk; or `setup_from_seed` in tests).
pub fn prove_withdraw_attest_with_keys(
    pk: &ProvingKey<Bn254>,
    vk: &VerifyingKey<Bn254>,
    note_id: &str,
    dest_h160: &[u8; 20],
    amount: u64,
    height: u64,
    header_hash: &[u8; 32],
    pegout_txid: &[u8; 32],
    mimc_leaves: &[String],
    operator: &str,
) -> Result<(String, Vec<String>, String, String), String> {
    let mut rng = rand::rngs::OsRng;
    let circuit = attest_circuit(note_id, dest_h160, amount, height, header_hash, pegout_txid, mimc_leaves)?;
    let public = circuit.public_values();
    let proof = prove(pk, circuit, &mut rng)?;
    if !verify(vk, &public, &proof)? {
        return Err("local verify failed".into());
    }
    let proof_bytes = proof_to_bytes(&proof)?;
    let public_be: Vec<Vec<u8>> = public
        .iter()
        .map(|f| crate::groth16::fr_to_be32(*f).to_vec())
        .collect();
    let public_hex: Vec<String> = public_be.iter().map(hex::encode).collect();
    let digest = statement_digest(&proof_bytes, &public_be);
    let pegout_display = {
        let mut rev = pegout_txid.to_vec();
        rev.reverse();
        hex::encode(rev)
    };
    let cid = claim_id(operator, note_id, &pegout_display);
    Ok((hex::encode(proof_bytes), public_hex, hex::encode(digest), cid))
}

pub fn verify_withdraw_attest(
    note_id: &str,
    dest_h160: &[u8; 20],
    amount: u64,
    height: u64,
    header_hash: &[u8; 32],
    pegout_txid: &[u8; 32],
    mimc_leaves: &[String],
    proof_hex: &str,
    public_hex: &[String],
    statement_digest_hex: &str,
) -> Result<(), String> {
    // Pre-M1 behaviour (kept for replay): a fresh random VK per call.
    let mut rng = rand::rngs::OsRng;
    let (_pk, vk) = setup(&mut rng)?;
    verify_withdraw_attest_with_vk(
        &vk, note_id, dest_h160, amount, height, header_hash, pegout_txid, mimc_leaves, proof_hex,
        public_hex, statement_digest_hex,
    )
}

/// M1: verify against a fixed verifying key (compressed bytes).
pub fn verify_withdraw_attest_vk_bytes(
    vk_bytes: &[u8],
    note_id: &str,
    dest_h160: &[u8; 20],
    amount: u64,
    height: u64,
    header_hash: &[u8; 32],
    pegout_txid: &[u8; 32],
    mimc_leaves: &[String],
    proof_hex: &str,
    public_hex: &[String],
    statement_digest_hex: &str,
) -> Result<(), String> {
    let vk = vk_from_bytes(vk_bytes)?;
    verify_withdraw_attest_with_vk(
        &vk, note_id, dest_h160, amount, height, header_hash, pegout_txid, mimc_leaves, proof_hex,
        public_hex, statement_digest_hex,
    )
}

/// Public-input positions of the claim-tree root (hi, lo) in
/// [`FplWithdrawValid::public_values`].
pub const PUBLIC_CLAIM_ROOT_IDX: [usize; 2] = [4, 5];

/// Re-verify a **stored** attestation (fix B Disprove): the Groth16 proof, the
/// statement digest and every public input except the claim-tree root, which
/// is taken from the stored public inputs. That root was checked against the
/// consensus claim tree when the attestation was accepted, so this is the same
/// statement the attest verified, and it stays valid after later appends or
/// prunes change the live tree.
pub fn verify_stored_withdraw_attest_vk_bytes(
    vk_bytes: &[u8],
    note_id: &str,
    dest_h160: &[u8; 20],
    amount: u64,
    height: u64,
    header_hash: &[u8; 32],
    pegout_txid: &[u8; 32],
    proof_hex: &str,
    public_hex: &[String],
    statement_digest_hex: &str,
) -> Result<(), String> {
    let vk = vk_from_bytes(vk_bytes)?;
    let proof_bytes = hex::decode(proof_hex.trim()).map_err(|e| e.to_string())?;
    let proof = crate::groth16::proof_from_bytes(&proof_bytes)?;
    let public = crate::groth16::public_from_be_hex(public_hex)?;
    if !verify(&vk, &public, &proof)? {
        return Err("groth16 verify failed".into());
    }
    let public_be: Vec<Vec<u8>> = public
        .iter()
        .map(|f| crate::groth16::fr_to_be32(*f).to_vec())
        .collect();
    let digest = statement_digest(&proof_bytes, &public_be);
    if hex::encode(digest) != statement_digest_hex.to_ascii_lowercase() {
        return Err("statement digest mismatch".into());
    }
    let depth = crate::abi::MERKLE_DEPTH;
    let circuit = FplWithdrawValid::from_withdraw(
        2300,
        amount,
        dest_h160,
        Fr::from(0u64),
        height,
        header_hash,
        note_id,
        pegout_txid,
        &vec![Fr::from(0u64); depth],
        &vec![false; depth],
        test_vk_hash(),
    )?;
    let want = circuit.public_values();
    if public.len() != want.len() {
        return Err("public inputs do not match withdraw".into());
    }
    for (i, (a, b)) in public.iter().zip(want.iter()).enumerate() {
        if PUBLIC_CLAIM_ROOT_IDX.contains(&i) {
            continue;
        }
        if a != b {
            return Err("public inputs do not match withdraw".into());
        }
    }
    Ok(())
}

pub fn verify_withdraw_attest_with_vk(
    vk: &VerifyingKey<Bn254>,
    note_id: &str,
    dest_h160: &[u8; 20],
    amount: u64,
    height: u64,
    header_hash: &[u8; 32],
    pegout_txid: &[u8; 32],
    mimc_leaves: &[String],
    proof_hex: &str,
    public_hex: &[String],
    statement_digest_hex: &str,
) -> Result<(), String> {
    let proof_bytes = hex::decode(proof_hex.trim()).map_err(|e| e.to_string())?;
    let proof = crate::groth16::proof_from_bytes(&proof_bytes)?;
    let public = crate::groth16::public_from_be_hex(public_hex)?;
    if !verify(vk, &public, &proof)? {
        return Err("groth16 verify failed".into());
    }
    let public_be: Vec<Vec<u8>> = public
        .iter()
        .map(|f| crate::groth16::fr_to_be32(*f).to_vec())
        .collect();
    let digest = statement_digest(&proof_bytes, &public_be);
    if hex::encode(digest) != statement_digest_hex.to_ascii_lowercase() {
        return Err("statement digest mismatch".into());
    }
    let frs: Vec<Fr> = mimc_leaves
        .iter()
        .map(|h| fr_from_leaf_hex(h))
        .collect::<Result<_, _>>()?;
    let leaf_index = leaf_index(note_id, dest_h160, amount, mimc_leaves)?;
    let (root, path, bits) = build_tree(&frs, leaf_index)?;
    let circuit = FplWithdrawValid::from_withdraw(
        2300,
        amount,
        dest_h160,
        root,
        height,
        header_hash,
        note_id,
        pegout_txid,
        &path,
        &bits,
        test_vk_hash(),
    )?;
    if public != circuit.public_values() {
        return Err("public inputs do not match withdraw".into());
    }
    Ok(())
}
