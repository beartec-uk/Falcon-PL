// Copyright (c) 2025-2026 BEARTEC. All rights reserved. See LICENSE.
//! Exact BitVM2 PEG_OUT payout script (upstream `generate_pay_to_pubkey_hash_with_inscription_script`):
//!
//!   P2WSH( OP_FALSE OP_IF <RIPEMD160(SHA256(pkh || be32(timestamp) || chain_addr))> OP_ENDIF
//!          OP_DUP OP_HASH160 <pkh> OP_EQUALVERIFY OP_CHECKSIG )
//!
//! With the Falcon adaptor (bridge/src/client/chain/falcon_adaptor.rs) pkh = 20-byte hash of the
//! ledger dest (P2PKH or P2WPKH), timestamp = claim open_height, chain_addr = Falcon note id.
//! A watcher therefore checks the PEG_OUT tx pays THIS scriptPubKey, not the plain dest address.
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

const B58: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

fn base58check(s: &str) -> Option<Vec<u8>> {
    let mut n: Vec<u8> = vec![]; // big-endian bytes
    for c in s.bytes() {
        let mut carry = B58.iter().position(|&b| b == c)? as u32;
        for d in n.iter_mut().rev() {
            carry += (*d as u32) * 58;
            *d = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            n.insert(0, (carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    let zeros = s.bytes().take_while(|&b| b == b'1').count();
    let mut out = vec![0u8; zeros];
    out.extend(n);
    if out.len() < 5 {
        return None;
    }
    let (body, ck) = out.split_at(out.len() - 4);
    let h = Sha256::digest(Sha256::digest(body));
    (h[..4] == *ck).then(|| body.to_vec())
}

/// 20-byte pubkey hash of a P2PKH / P2WPKH address on `network` (regtest|testnet4|testnet|mainnet).
pub fn dest_pubkey_hash(dest: &str, network: &str) -> Result<[u8; 20], String> {
    let (hrp, p2pkh_ver) = match network {
        "mainnet" | "bitcoin" => ("bc", 0x00u8),
        "regtest" => ("bcrt", 0x6f),
        _ => ("tb", 0x6f),
    };
    if dest.to_ascii_lowercase().starts_with(&format!("{hrp}1")) {
        let (h, ver, prog) = bech32::segwit::decode(dest).map_err(|e| format!("dest: {e}"))?;
        if h.as_str() != hrp {
            return Err("dest network mismatch".into());
        }
        if ver.to_u8() != 0 || prog.len() != 20 {
            return Err("dest must be P2PKH or P2WPKH (20-byte hash)".into());
        }
        return Ok(prog.try_into().unwrap());
    }
    let b = base58check(dest).ok_or("dest: bad base58check")?;
    if b.len() != 21 || b[0] != p2pkh_ver {
        return Err("dest must be P2PKH or P2WPKH (20-byte hash)".into());
    }
    Ok(b[1..].try_into().unwrap())
}

pub fn payout_witness_script(pkh: &[u8; 20], timestamp: u32, chain_addr: &str) -> Vec<u8> {
    let mut ins = pkh.to_vec();
    ins.extend_from_slice(&timestamp.to_be_bytes());
    ins.extend_from_slice(chain_addr.as_bytes());
    let ih = Ripemd160::digest(Sha256::digest(&ins));
    let mut s = vec![0x00, 0x63, 0x14];
    s.extend_from_slice(&ih);
    s.extend_from_slice(&[0x68, 0x76, 0xa9, 0x14]);
    s.extend_from_slice(pkh);
    s.extend_from_slice(&[0x88, 0xac]);
    s
}

/// Expected PEG_OUT output scriptPubKey (hex) for a Falcon claim.
pub fn expected_payout_spk(dest: &str, open_height: u64, note_id: &str, network: &str) -> Result<String, String> {
    let pkh = dest_pubkey_hash(dest, network)?;
    let ws = payout_witness_script(&pkh, open_height as u32, note_id);
    let mut spk = vec![0x00, 0x20];
    spk.extend_from_slice(&Sha256::digest(&ws));
    Ok(hex::encode(spk))
}

/// Minimum acceptable PEG_OUT output: withdrawal amount minus the operator fee (bps) and the
/// presigned PEG_OUT relay fee allowance.
pub fn min_payout(amount: u64, max_fee_bps: u64, relay_allow_sats: u64) -> u64 {
    amount.saturating_sub((amount as u128 * max_fee_bps as u128 / 10_000) as u64).saturating_sub(relay_allow_sats)
}

/// Does any output (value, spk_hex) pay the expected script with at least `min` sats?
pub fn payout_matches(outs: &[(u64, String)], spk: &str, min: u64) -> Result<u64, String> {
    match outs.iter().find(|(_, s)| s.eq_ignore_ascii_case(spk)) {
        None => Err("PEG_OUT does not pay the expected withdrawal script (dest hash + Falcon note id)".into()),
        Some((v, _)) if *v < min => Err(format!("PEG_OUT pays {v} sats < minimum {min}")),
        Some((v, _)) => Ok(*v),
    }
}

/// The claim dest's own scriptPubKey (hex): P2WPKH `0014<pkh>` for bech32, P2PKH for base58.
pub fn plain_dest_spk(dest: &str, network: &str) -> Result<String, String> {
    let pkh = dest_pubkey_hash(dest, network)?;
    let l = dest.to_ascii_lowercase();
    let bech = l.starts_with("tb1") || l.starts_with("bc1") || l.starts_with("bcrt1");
    Ok(if bech { format!("0014{}", hex::encode(pkh)) } else { format!("76a914{}88ac", hex::encode(pkh)) })
}

/// PEG_OUT acceptance for watchers. Accepts EITHER
///  * the ledger M1 rule (fd-pl `attest_bitvm2_claim_v2`): an output paying EXACTLY `amount` to the
///    claim dest's own scriptPubKey (current operator kits, PEG_OUT fee paid on top by the operator), or
///  * the legacy upstream inscription script with at least `min` (PEG_OUTs already in flight from
///    older kits; the ledger cannot attest these, but they did pay the withdrawer's key).
pub fn payout_ok(outs: &[(u64, String)], dest: &str, open_height: u64, note_id: &str, amount: u64, min: u64, network: &str) -> Result<u64, String> {
    let plain = plain_dest_spk(dest, network)?;
    if outs.iter().any(|(v, s)| *v == amount && s.eq_ignore_ascii_case(&plain)) {
        return Ok(amount);
    }
    let legacy = expected_payout_spk(dest, open_height, note_id, network)?;
    payout_matches(outs, &legacy, min).map_err(|e| format!("{e}; and no output pays exactly {amount} sats to the dest {dest}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn decodes_both_address_kinds() {
        // same key hash 751e76e8199196d454941c45d1b3a323f1433bd6 (BIP173 vector)
        let w = dest_pubkey_hash("bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080", "regtest").unwrap();
        assert_eq!(hex::encode(w), "751e76e8199196d454941c45d1b3a323f1433bd6");
        let t = dest_pubkey_hash("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx", "testnet4").unwrap();
        assert_eq!(t, w);
        let p = dest_pubkey_hash("mrCDrCybB6J1vRfbwM5hemdJz73FwDBC8r", "testnet4").unwrap();
        assert_eq!(p.len(), 20);
        assert!(dest_pubkey_hash("bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080", "testnet4").is_err());
    }
    #[test]
    fn matches_upstream_bitvm_script() {
        // cross-checked with `fpl_challenge --print-payout-spk` (upstream
        // generate_pay_to_pubkey_hash_with_inscription_script_address + FalconAdaptor)
        let t = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";
        assert_eq!(expected_payout_spk(t, 90, "w1", "testnet4").unwrap(), "0020b42f2780a2bd208b64855e80106bb2a9fef300ccefc16379460176110b107318");
        assert_eq!(expected_payout_spk(t, 90, "note-xyz", "testnet4").unwrap(), "00205974649a01e0eb4cda3c33c018c10a3bf93a576a419041d1a7a1908f627bd58b");
        assert_eq!(expected_payout_spk("mrCDrCybB6J1vRfbwM5hemdJz73FwDBC8r", 614000, "abc", "regtest").unwrap(), "0020dc19458acfae7c9fc9ec888140f4ae77b7342a6823068e61624a2b0429cfc964");
    }
    #[test]
    fn min_and_match() {
        assert_eq!(min_payout(10_000, 30, 61), 10_000 - 30 - 61);
        let spk = expected_payout_spk("bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080", 90, "w1", "regtest").unwrap();
        assert_eq!(spk.len(), 68);
        let other = expected_payout_spk("bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080", 90, "w2", "regtest").unwrap();
        assert_ne!(spk, other, "note id must change the script");
        assert!(payout_matches(&[(9_950, spk.clone())], &spk, 9_909).is_ok());
        assert!(payout_matches(&[(9_000, spk.clone())], &spk, 9_909).is_err());
        assert!(payout_matches(&[(10_000, other)], &spk, 9_909).is_err());
    }
    #[test]
    fn plain_dest_exact_amount_accepted() {
        let d = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";
        let plain = plain_dest_spk(d, "testnet4").unwrap();
        assert_eq!(plain, "0014751e76e8199196d454941c45d1b3a323f1433bd6");
        assert_eq!(plain_dest_spk("mrCDrCybB6J1vRfbwM5hemdJz73FwDBC8r", "testnet4").unwrap().len(), 50);
        // exact amount to the dest: OK (ledger M1 rule)
        assert_eq!(payout_ok(&[(50_000, plain.clone())], d, 90, "w1", 50_000, 49_000, "testnet4").unwrap(), 50_000);
        // 1 sat short to the plain dest: rejected (the ledger would refuse the attest)
        assert!(payout_ok(&[(49_999, plain.clone())], d, 90, "w1", 50_000, 49_000, "testnet4").is_err());
        // legacy inscription script still accepted for in-flight PEG_OUTs
        let legacy = expected_payout_spk(d, 90, "w1", "testnet4").unwrap();
        assert!(payout_ok(&[(49_984, legacy)], d, 90, "w1", 50_000, 49_000, "testnet4").is_ok());
        assert!(payout_ok(&[(50_000, "0014".to_string() + &"00".repeat(20))], d, 90, "w1", 50_000, 49_000, "testnet4").is_err());
    }
}
