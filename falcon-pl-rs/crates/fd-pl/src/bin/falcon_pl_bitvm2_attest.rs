// Copyright (c) 2025-2026 BEARTEC. All rights reserved. See LICENSE.
//! M1 attest assembly for the operator kit (snarkjs prover path; no proving key in Rust).
//!
//!   falcon-pl-bitvm2-attest input --status status.json --note-id N --pegout-txid DISPLAY [--checkpoint-height H] --out attest.json
//!       statement for `falcon-pl-bitvm2-setup attest-wtns` (claim, leaves, final checkpoint >= burn)
//!   falcon-pl-bitvm2-attest body --input attest.json --import import.json --raw-tx HEX --btc-height H
//!        --block-txids txids.json --claim-txid HEX [--vk-hex HEX] --out body.json
//!       `bitvm2_attest_v2` TxBody (Bitcoin merkle path, statement digest); with --vk-hex the
//!       proof is checked exactly as the ledger will before anything is submitted.
//! import.json = output of `falcon-pl-bitvm2-setup proof-import` (proof_hex, public_be).
use fd_pl::bitvm::dest_h160_from_address;
use fd_pl::bitvm2_exit::{checkpoint_header_hash, pegout_txid_bytes, BITVM2_CHECKPOINT_FINALITY};
use fd_pl::btc_spv;
use serde_json::{json, Value};

fn arg(name: &str) -> Option<String> {
    let a: Vec<String> = std::env::args().collect();
    a.iter().position(|x| x == name).and_then(|i| a.get(i + 1).cloned())
}
fn req(name: &str) -> Result<String, String> {
    arg(name).ok_or_else(|| format!("missing {name}"))
}
fn read_json(p: &str) -> Result<Value, String> {
    serde_json::from_slice(&std::fs::read(p).map_err(|e| format!("{p}: {e}"))?).map_err(|e| format!("{p}: {e}"))
}

/// Pick the newest checkpoint that is >= the burn height and final at `ledger_height`.
pub fn pick_checkpoint(cks: &Value, open_height: u64, ledger_height: u64, want: Option<u64>) -> Result<(u64, String), String> {
    let mut best: Option<(u64, String)> = None;
    for (h, x) in cks.as_object().into_iter().flatten() {
        let Ok(h) = h.parse::<u64>() else { continue };
        let Some(x) = x.as_str() else { continue };
        if h < open_height || h + BITVM2_CHECKPOINT_FINALITY > ledger_height || want.map_or(false, |w| w != h) {
            continue;
        }
        if best.as_ref().map_or(true, |(b, _)| h > *b) {
            best = Some((h, x.to_string()));
        }
    }
    best.ok_or_else(|| "no final FPL checkpoint after the burn yet".into())
}

/// Bitcoin merkle siblings (internal byte order, bottom-up) for txids given in display order.
pub fn merkle_path(txids_display: &[String], index: usize) -> Result<Vec<String>, String> {
    let mut level: Vec<[u8; 32]> = txids_display.iter().map(|t| btc_spv::display_to_internal(t)).collect::<Result<_, _>>()?;
    if index >= level.len() {
        return Err("tx index out of range".into());
    }
    let mut i = index;
    let mut path = vec![];
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            level.push(*level.last().unwrap());
        }
        path.push(hex::encode(level[i ^ 1]));
        level = level
            .chunks(2)
            .map(|p| {
                let mut b = [0u8; 64];
                b[..32].copy_from_slice(&p[0]);
                b[32..].copy_from_slice(&p[1]);
                btc_spv::hash256(&b)
            })
            .collect();
        i /= 2;
    }
    Ok(path)
}

fn merkle_root_display(txids_display: &[String]) -> Result<String, String> {
    let mut level: Vec<[u8; 32]> = txids_display.iter().map(|t| btc_spv::display_to_internal(t)).collect::<Result<_, _>>()?;
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            level.push(*level.last().unwrap());
        }
        level = level.chunks(2).map(|p| { let mut b = [0u8; 64]; b[..32].copy_from_slice(&p[0]); b[32..].copy_from_slice(&p[1]); btc_spv::hash256(&b) }).collect();
    }
    Ok(btc_spv::display_hex(&level[0]))
}

/// Bitcoin rail holding `note` (BTC4 = Testnet4 BitVM2 rail, or legacy BTC).
/// Before this fix only the legacy "BTC" rail was searched, so every BTC4
/// claim failed with "claim not in status" and could never be attested.
fn btc_rail<'a>(status: &'a Value, note: &str) -> Result<&'a Value, String> {
    let b = status.get("body").unwrap_or(status);
    let rails: Vec<&Value> = b["rails"].as_array().into_iter().flatten()
        .filter(|r| r["asset"].as_str().map_or(false, |a| a.eq_ignore_ascii_case("btc4") || a.eq_ignore_ascii_case("btc")))
        .collect();
    if rails.is_empty() {
        return Err("no BTC/BTC4 rail in status".into());
    }
    rails.into_iter()
        .find(|r| r["bitvm2_claims"].as_array().into_iter().flatten().any(|c| c["note_id"].as_str() == Some(note)))
        .ok_or_else(|| "claim not in status".into())
}

fn input() -> Result<Value, String> {
    let status = read_json(&req("--status")?)?;
    let note = req("--note-id")?;
    let pegout_display = req("--pegout-txid")?.to_ascii_lowercase();
    let b = status.get("body").unwrap_or(&status);
    let ledger_height = b["height"].as_u64().or(b["tip_height"].as_u64()).ok_or("status has no height")?;
    let rail = btc_rail(&status, &note)?;
    let c = rail["bitvm2_claims"].as_array().into_iter().flatten().find(|c| c["note_id"].as_str() == Some(note.as_str())).ok_or("claim not in status")?;
    let dest = c["dest"].as_str().ok_or("claim.dest")?;
    let amount = c["amount"].as_u64().ok_or("claim.amount")?;
    let open = c["open_height"].as_u64().unwrap_or(0);
    let want = arg("--checkpoint-height").map(|s| s.parse::<u64>().map_err(|e| e.to_string())).transpose()?;
    let (ckh, ckx) = pick_checkpoint(&rail["fpl_checkpoints"], open, ledger_height, want)?;
    let leaves: Vec<String> = rail["bitvm2_claim_leaves"].as_array().ok_or("status has no bitvm2_claim_leaves")?.iter().filter_map(|x| x.as_str().map(String::from)).collect();
    let dest_h160 = dest_h160_from_address(dest)?;
    fd_pl_bitvm2::withdraw_ops::leaf_index(&note, &dest_h160, amount, &leaves)?;
    Ok(json!({
        "note_id": note, "dest": dest, "dest_h160_hex": hex::encode(dest_h160), "amount": amount,
        "height": ckh, "header_hex": hex::encode(checkpoint_header_hash(ckh, &ckx)),
        "pegout_txid_display": pegout_display, "pegout_txid_internal_hex": hex::encode(pegout_txid_bytes(&pegout_display)?),
        "mimc_leaves": leaves,
    }))
}

fn body() -> Result<Value, String> {
    let inp = read_json(&req("--input")?)?;
    let imp = read_json(&req("--import")?)?;
    if imp["verifies"].as_bool() != Some(true) {
        return Err("proof-import did not verify".into());
    }
    let raw = req("--raw-tx")?.trim().to_ascii_lowercase();
    let tx = btc_spv::parse_tx(&btc_spv::hex_decode(&raw)?)?;
    let want = inp["pegout_txid_display"].as_str().unwrap_or("");
    if !tx.txid_display.eq_ignore_ascii_case(want) {
        return Err(format!("raw tx is {} not the peg-out {want}", tx.txid_display));
    }
    let txids: Vec<String> = read_json(&req("--block-txids")?)?.as_array().ok_or("block txids must be a JSON array")?.iter().filter_map(|x| x.as_str().map(String::from)).collect();
    let idx = txids.iter().position(|t| t.eq_ignore_ascii_case(want)).ok_or("peg-out not in that block")?;
    let path = merkle_path(&txids, idx)?;
    let siblings = btc_spv::siblings_from_path(&path)?;
    btc_spv::verify_merkle(want, &siblings, idx as u32, &merkle_root_display(&txids)?)?;
    let proof_hex = imp["proof_hex"].as_str().ok_or("import.proof_hex")?.to_string();
    let public_hex: Vec<String> = imp["public_be"].as_array().ok_or("import.public_be")?.iter().filter_map(|x| x.as_str().map(String::from)).collect();
    let public_be: Vec<Vec<u8>> = public_hex.iter().map(|h| hex::decode(h).map_err(|e| e.to_string())).collect::<Result<_, _>>()?;
    let digest = hex::encode(fd_pl_bitvm2::statement_digest(&hex::decode(&proof_hex).map_err(|e| e.to_string())?, &public_be));
    let s = |k: &str| inp[k].as_str().unwrap_or("").to_string();
    let dest_h160: [u8; 20] = hex::decode(s("dest_h160_hex")).ok().and_then(|v| v.try_into().ok()).ok_or("input.dest_h160_hex")?;
    let header: [u8; 32] = hex::decode(s("header_hex")).ok().and_then(|v| v.try_into().ok()).ok_or("input.header_hex")?;
    let pegout: [u8; 32] = hex::decode(s("pegout_txid_internal_hex")).ok().and_then(|v| v.try_into().ok()).ok_or("input.pegout")?;
    let leaves: Vec<String> = inp["mimc_leaves"].as_array().into_iter().flatten().filter_map(|x| x.as_str().map(String::from)).collect();
    let amount = inp["amount"].as_u64().ok_or("input.amount")?;
    let ckh = inp["height"].as_u64().ok_or("input.height")?;
    if let Some(vk) = arg("--vk-hex") {
        fd_pl::bitvm2_exit::verify_withdraw_attest_vk_bytes(&hex::decode(vk.trim()).map_err(|e| e.to_string())?, &s("note_id"), &dest_h160, amount, ckh, &header, &pegout, &leaves, &proof_hex, &public_hex, &digest)?;
    }
    if !tx.outputs.iter().any(|(sats, _)| *sats == amount) {
        return Err("peg-out has no output of the burn amount".into());
    }
    Ok(json!({"kind": "bitvm2_attest_v2", "attest": {
        "note_id": s("note_id"), "claim_txid_hex": req("--claim-txid")?.to_ascii_lowercase(),
        "checkpoint_height": ckh, "btc_height": req("--btc-height")?.parse::<u64>().map_err(|e| e.to_string())?,
        "pegout_raw_tx_hex": raw, "merkle_path": path, "merkle_index": idx,
        "proof_hex": proof_hex, "public_hex": public_hex, "statement_digest_hex": digest,
    }}))
}

fn main() {
    let r = match std::env::args().nth(1).as_deref() {
        Some("input") => input(),
        Some("body") => body(),
        _ => Err("usage: falcon-pl-bitvm2-attest input|body ... (see source header)".into()),
    };
    match r.and_then(|v| {
        let out = req("--out")?;
        std::fs::write(&out, serde_json::to_vec_pretty(&v).unwrap()).map_err(|e| format!("{out}: {e}"))?;
        Ok(v)
    }) {
        Ok(v) => println!("{}", if v.get("attest").is_some() { json!({"ok": true, "note_id": v["attest"]["note_id"], "checkpoint_height": v["attest"]["checkpoint_height"]}) } else { json!({"ok": true, "checkpoint_height": v["height"]}) }),
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn merkle_path_verifies_for_every_index() {
        for n in 1..9usize {
            let txids: Vec<String> = (0..n).map(|i| format!("{:064x}", i * 7 + 1)).collect();
            let root = merkle_root_display(&txids).unwrap();
            for i in 0..n {
                let p = merkle_path(&txids, i).unwrap();
                btc_spv::verify_merkle(&txids[i], &btc_spv::siblings_from_path(&p).unwrap(), i as u32, &root).unwrap();
            }
        }
    }
    #[test]
    fn body_shape_is_the_ledger_tx_body() {
        let v = json!({"kind": "bitvm2_attest_v2", "attest": {
            "note_id": "n", "claim_txid_hex": "cc".repeat(32), "checkpoint_height": 128, "btc_height": 200,
            "pegout_raw_tx_hex": "00", "merkle_path": ["11".repeat(32)], "merkle_index": 0,
            "proof_hex": "ab", "public_hex": ["01"], "statement_digest_hex": "dd".repeat(32)}});
        let b: fd_pl::TxBody = serde_json::from_value(v).expect("TxBody");
        assert!(matches!(b, fd_pl::TxBody::Bitvm2AttestV2 { .. }));
    }
    #[test]
    fn checkpoint_pick_rules() {
        let c = json!({"64": "aa", "128": "bb", "192": "cc"});
        assert_eq!(pick_checkpoint(&c, 100, 200, None).unwrap().0, 192);
        assert_eq!(pick_checkpoint(&c, 100, 193, None).unwrap().0, 128);
        assert!(pick_checkpoint(&c, 193, 400, None).is_err());
        assert_eq!(pick_checkpoint(&c, 0, 400, Some(64)).unwrap().0, 64);
    }
}

#[cfg(test)]
mod rail_tests {
    use super::btc_rail;
    use serde_json::json;
    #[test]
    fn finds_btc4_claim() {
        let st = json!({"body": {"rails": [
            {"asset": "BTC", "bitvm2_claims": [{"note_id": "old"}]},
            {"asset": "BTC4", "bitvm2_claims": [{"note_id": "n4"}]}]}});
        assert_eq!(btc_rail(&st, "n4").unwrap()["asset"], "BTC4");
        assert_eq!(btc_rail(&st, "old").unwrap()["asset"], "BTC");
        assert!(btc_rail(&st, "missing").is_err());
        assert!(btc_rail(&json!({"rails": [{"asset": "ETH"}]}), "n4").is_err());
    }
}
