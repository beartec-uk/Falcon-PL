// Copyright (c) 2025-2026 BEARTEC. All rights reserved. See LICENSE.
//! Bitcoin SPV primitives for the FPL BTC rail.
//!
//! This is the Bitcoin header / merkle / tx extract — not a port of xrpld.
//! Algorithms match `qXRP` `BTCHeader` / `BTCMerkle` / `BTCTx` and the
//! wallet `btc-merkle.ts` (double-SHA256, display vs internal byte order).

use sha2::{Digest, Sha256};

/// 80-byte Bitcoin block header.
pub const HEADER_LEN: usize = 80;
/// Testnet / mainnet nProofOfWorkLimit compact bits.
pub const POW_LIMIT_BITS: u32 = 0x1d00ffff;
/// Testnet special-min-diff: allow min target if the parent is ≥20 minutes old.
pub const TESTNET_MIN_DIFF_GAP_SEC: u32 = 1_200;
/// Bitcoin difficulty adjustment interval (main and testnet).
pub const DIFF_INTERVAL: u64 = 2016;
/// Protocol shared-reserve P2WSH scriptPubKey (tb1q7dnl… testnet hold).
pub const TESTNET_WATCH_SPK: &str =
    "0020f367f1737ba3ef6cc49ff50647361142d3c541c0772a6ebcf633f0b341ef1b2a";
pub const FALC_MAGIC: &[u8] = b"FALC";

pub fn hash256(data: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(data);
    Sha256::digest(first).into()
}

pub fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    let h = s.trim().trim_start_matches("0x").trim_start_matches("0X");
    if h.len() % 2 != 0 {
        return Err("odd hex length".into());
    }
    hex::decode(h).map_err(|e| format!("hex: {e}"))
}

pub fn hex_encode(b: &[u8]) -> String {
    hex::encode(b)
}

pub fn reverse_32(b: &[u8; 32]) -> [u8; 32] {
    let mut o = [0u8; 32];
    for i in 0..32 {
        o[i] = b[31 - i];
    }
    o
}

/// Display-order 32-byte hash (explorer / RPC) → lowercase hex.
pub fn display_hex(internal: &[u8; 32]) -> String {
    hex_encode(&reverse_32(internal))
}

pub fn parse_display32(s: &str) -> Result<[u8; 32], String> {
    let b = hex_decode(s)?;
    if b.len() != 32 {
        return Err("hash must be 32 bytes".into());
    }
    let mut d = [0u8; 32];
    d.copy_from_slice(&b);
    Ok(d)
}

/// Display hex → Bitcoin internal (byte-reversed) 32 bytes.
pub fn display_to_internal(s: &str) -> Result<[u8; 32], String> {
    Ok(reverse_32(&parse_display32(s)?))
}

fn read_u32_le(b: &[u8], off: usize) -> Result<u32, String> {
    let s = b
        .get(off..off + 4)
        .ok_or_else(|| "header truncated".to_string())?;
    Ok(u32::from_le_bytes(s.try_into().unwrap()))
}

#[derive(Debug, Clone)]
pub struct ParsedHeader {
    pub version: u32,
    pub prev_display: String,
    pub merkle_display: String,
    pub timestamp: u32,
    pub bits: u32,
    pub nonce: u32,
    /// Raw double-SHA256 digest (internal / natural hash256 output).
    pub hash_internal: [u8; 32],
    pub hash_display: String,
    pub raw_hex: String,
}

pub fn parse_header(raw: &[u8]) -> Result<ParsedHeader, String> {
    if raw.len() != HEADER_LEN {
        return Err(format!("Bitcoin header must be {HEADER_LEN} bytes"));
    }
    let hash_internal = hash256(raw);
    let mut prev_int = [0u8; 32];
    prev_int.copy_from_slice(&raw[4..36]);
    let mut merkle_int = [0u8; 32];
    merkle_int.copy_from_slice(&raw[36..68]);
    Ok(ParsedHeader {
        version: read_u32_le(raw, 0)?,
        prev_display: display_hex(&prev_int),
        merkle_display: display_hex(&merkle_int),
        timestamp: read_u32_le(raw, 68)?,
        bits: read_u32_le(raw, 72)?,
        nonce: read_u32_le(raw, 76)?,
        hash_internal,
        hash_display: display_hex(&hash_internal),
        raw_hex: hex_encode(raw),
    })
}

pub fn parse_header_hex(hex_s: &str) -> Result<ParsedHeader, String> {
    let raw = hex_decode(hex_s)?;
    parse_header(&raw)
}

/// Expand compact nBits to a 256-bit big-endian target (Bitcoin SetCompact).
pub fn compact_target(bits: u32) -> Option<[u8; 32]> {
    let size = bits >> 24;
    let word = bits & 0x007f_ffff;
    if bits & 0x0080_0000 != 0 || word == 0 {
        return None;
    }
    let mut target = [0u8; 32];
    if size <= 3 {
        let w = word >> (8 * (3 - size));
        target[31] = (w & 0xff) as u8;
        target[30] = ((w >> 8) & 0xff) as u8;
        target[29] = ((w >> 16) & 0xff) as u8;
        target[28] = ((w >> 24) & 0xff) as u8;
    } else if size <= 32 {
        let pos = 32isize - size as isize;
        if pos >= 0 && pos + 2 < 32 {
            let p = pos as usize;
            target[p] = ((word >> 16) & 0xff) as u8;
            target[p + 1] = ((word >> 8) & 0xff) as u8;
            target[p + 2] = (word & 0xff) as u8;
        } else {
            return None;
        }
    } else {
        return None;
    }
    Some(target)
}

/// Approximate per-header work, 2^256 / target, in integer arithmetic
/// (deterministic across seats). target = word * 256^(size-3), so work is
/// about 2^(256 - 8*(size-3)) / word. Saturates at u128::MAX for targets far
/// harder than testnet (never reached in practice). 0 for an invalid nBits.
pub fn header_work_bits(bits: u32) -> u128 {
    let size = (bits >> 24) as i64;
    let word = (bits & 0x007f_ffff) as u128;
    if bits & 0x0080_0000 != 0 || word == 0 || size > 32 {
        return 0;
    }
    let e = 256 - 8 * (size - 3);
    if e >= 128 {
        return u128::MAX;
    }
    if e < 0 {
        return 0;
    }
    (1u128 << e) / word
}

/// `hash_internal` is the raw hash256 digest. Bitcoin treats it as LE int.
pub fn hash_meets_target(hash_internal: &[u8; 32], bits: u32) -> bool {
    let target = match compact_target(bits) {
        Some(t) => t,
        None => return false,
    };
    let be = reverse_32(hash_internal);
    be <= target
}

/// Verify a Bitcoin merkle proof.
///
/// * `txid_display` / `merkle_root_display` — explorer byte order
/// * `siblings` — 32-byte hashes in **internal** order (same as `btc-merkle.ts`)
pub fn verify_merkle(
    txid_display: &str,
    siblings: &[[u8; 32]],
    mut index: u32,
    merkle_root_display: &str,
) -> Result<(), String> {
    let mut h = display_to_internal(txid_display)?;
    let want = parse_display32(merkle_root_display)?;
    if siblings.len() > 32 {
        return Err("merkle path too deep".into());
    }
    for sib in siblings {
        if index % 2 == 0 {
            let mut buf = [0u8; 64];
            buf[..32].copy_from_slice(&h);
            buf[32..].copy_from_slice(sib);
            h = hash256(&buf);
        } else {
            let mut buf = [0u8; 64];
            buf[..32].copy_from_slice(sib);
            buf[32..].copy_from_slice(&h);
            h = hash256(&buf);
        }
        index /= 2;
    }
    let got = reverse_32(&h);
    if got != want {
        return Err("Bitcoin merkle root mismatch".into());
    }
    Ok(())
}

pub fn siblings_from_path(path: &[String]) -> Result<Vec<[u8; 32]>, String> {
    let mut out = Vec::with_capacity(path.len());
    for s in path {
        let b = hex_decode(s)?;
        if b.len() != 32 {
            return Err("merkle sibling must be 32 bytes".into());
        }
        let mut a = [0u8; 32];
        a.copy_from_slice(&b);
        out.push(a);
    }
    Ok(out)
}

/// Named-account dest id: sha256(lowercase name)[..20], matching `falcOpReturnPayload`.
pub fn dest_id20(account: &str) -> [u8; 20] {
    let d = Sha256::digest(account.trim().to_ascii_lowercase().as_bytes());
    let mut id = [0u8; 20];
    id.copy_from_slice(&d[..20]);
    id
}

#[derive(Debug, Clone)]
pub struct ParsedTx {
    pub txid_display: String,
    /// `(txid_display, vout)` — display byte order, same as vault UTXO ids.
    pub inputs: Vec<(String, u32)>,
    pub outputs: Vec<(u64, Vec<u8>)>,
}

fn read_compact(data: &[u8], i: &mut usize) -> Result<u64, String> {
    if *i >= data.len() {
        return Err("eof compact".into());
    }
    let n = data[*i];
    *i += 1;
    match n {
        0xfd => {
            if *i + 2 > data.len() {
                return Err("eof compact16".into());
            }
            let v = u16::from_le_bytes([data[*i], data[*i + 1]]) as u64;
            *i += 2;
            Ok(v)
        }
        0xfe => {
            if *i + 4 > data.len() {
                return Err("eof compact32".into());
            }
            let v = u32::from_le_bytes(data[*i..*i + 4].try_into().unwrap()) as u64;
            *i += 4;
            Ok(v)
        }
        0xff => {
            if *i + 8 > data.len() {
                return Err("eof compact64".into());
            }
            let v = u64::from_le_bytes(data[*i..*i + 8].try_into().unwrap());
            *i += 8;
            Ok(v)
        }
        _ => Ok(n as u64),
    }
}

fn write_compact(out: &mut Vec<u8>, n: u64) {
    if n < 0xfd {
        out.push(n as u8);
    } else if n <= 0xffff {
        out.push(0xfd);
        out.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n <= 0xffff_ffff {
        out.push(0xfe);
        out.extend_from_slice(&(n as u32).to_le_bytes());
    } else {
        out.push(0xff);
        out.extend_from_slice(&n.to_le_bytes());
    }
}

/// Parse a raw Bitcoin transaction (legacy + BIP141). txid is the non-witness hash.
pub fn parse_tx(raw: &[u8]) -> Result<ParsedTx, String> {
    if raw.len() < 10 {
        return Err("tx too short".into());
    }
    let mut i = 0usize;
    i += 4; // version
    let mut segwit = false;
    if raw.get(i) == Some(&0x00) && raw.get(i + 1) == Some(&0x01) {
        segwit = true;
        i += 2;
    }
    let n_in = read_compact(raw, &mut i)?;
    if n_in > 10_000 {
        return Err("too many inputs".into());
    }
    let mut inputs = Vec::with_capacity(n_in as usize);
    for _ in 0..n_in {
        if i + 36 > raw.len() {
            return Err("eof vin".into());
        }
        let mut txid_int = [0u8; 32];
        txid_int.copy_from_slice(&raw[i..i + 32]);
        i += 32;
        let vout = u32::from_le_bytes(raw[i..i + 4].try_into().unwrap());
        i += 4;
        inputs.push((display_hex(&txid_int), vout));
        let slen = read_compact(raw, &mut i)? as usize;
        i = i.checked_add(slen).ok_or("vin script overflow")?;
        if i + 4 > raw.len() {
            return Err("eof vin seq".into());
        }
        i += 4;
    }
    let n_out = read_compact(raw, &mut i)?;
    if n_out > 10_000 {
        return Err("too many outputs".into());
    }
    let mut outputs = Vec::with_capacity(n_out as usize);
    for _ in 0..n_out {
        if i + 8 > raw.len() {
            return Err("eof vout".into());
        }
        let value = u64::from_le_bytes(raw[i..i + 8].try_into().unwrap());
        i += 8;
        let slen = read_compact(raw, &mut i)? as usize;
        if i + slen > raw.len() {
            return Err("eof vout script".into());
        }
        outputs.push((value, raw[i..i + slen].to_vec()));
        i += slen;
    }
    if segwit {
        for _ in 0..n_in {
            let n_stack = read_compact(raw, &mut i)?;
            for _ in 0..n_stack {
                let n = read_compact(raw, &mut i)? as usize;
                i = i.checked_add(n).ok_or("witness overflow")?;
            }
        }
    }
    if i + 4 > raw.len() {
        return Err("eof locktime".into());
    }
    i += 4;
    if i != raw.len() {
        return Err(format!("tx trailing bytes ({i} vs {})", raw.len()));
    }

    // Non-witness serialization for txid (BIP141).
    let txid_int = if !segwit {
        hash256(raw)
    } else {
        hash256(&strip_witness(raw)?)
    };
    Ok(ParsedTx {
        txid_display: display_hex(&txid_int),
        inputs,
        outputs,
    })
}

/// Witness stacks per input (empty for legacy). Used to reject FROST key-path
/// on a NUMS vault (script-path control block is the last stack item).
pub fn extract_witnesses(raw: &[u8]) -> Result<Vec<Vec<Vec<u8>>>, String> {
    if raw.len() < 10 {
        return Err("tx too short".into());
    }
    let mut i = 4usize;
    if raw.get(i) != Some(&0x00) || raw.get(i + 1) != Some(&0x01) {
        return Ok(Vec::new());
    }
    i += 2;
    let n_in = read_compact(raw, &mut i)? as usize;
    for _ in 0..n_in {
        if i + 36 > raw.len() {
            return Err("eof vin".into());
        }
        i += 36;
        let slen = read_compact(raw, &mut i)? as usize;
        i = i.checked_add(slen).ok_or("vin script overflow")?;
        if i + 4 > raw.len() {
            return Err("eof vin seq".into());
        }
        i += 4;
    }
    let n_out = read_compact(raw, &mut i)? as usize;
    for _ in 0..n_out {
        if i + 8 > raw.len() {
            return Err("eof vout".into());
        }
        i += 8;
        let slen = read_compact(raw, &mut i)? as usize;
        i = i.checked_add(slen).ok_or("vout script overflow")?;
    }
    let mut wits = Vec::with_capacity(n_in);
    for _ in 0..n_in {
        let n_stack = read_compact(raw, &mut i)? as usize;
        let mut stack = Vec::with_capacity(n_stack);
        for _ in 0..n_stack {
            let n = read_compact(raw, &mut i)? as usize;
            if i + n > raw.len() {
                return Err("eof witness item".into());
            }
            stack.push(raw[i..i + n].to_vec());
            i += n;
        }
        wits.push(stack);
    }
    Ok(wits)
}

fn strip_witness(raw: &[u8]) -> Result<Vec<u8>, String> {
    let mut i = 0usize;
    let mut out = Vec::with_capacity(raw.len());
    out.extend_from_slice(&raw[..4]);
    i += 4;
    if raw.get(i) == Some(&0x00) && raw.get(i + 1) == Some(&0x01) {
        i += 2;
    }
    let n_in = read_compact(raw, &mut i)?;
    write_compact(&mut out, n_in);
    for _ in 0..n_in {
        if i + 36 > raw.len() {
            return Err("eof vin".into());
        }
        out.extend_from_slice(&raw[i..i + 36]);
        i += 36;
        let slen = read_compact(raw, &mut i)? as usize;
        write_compact(&mut out, slen as u64);
        if i + slen + 4 > raw.len() {
            return Err("eof vin script".into());
        }
        out.extend_from_slice(&raw[i..i + slen]);
        i += slen;
        out.extend_from_slice(&raw[i..i + 4]);
        i += 4;
    }
    let n_out = read_compact(raw, &mut i)?;
    write_compact(&mut out, n_out);
    for _ in 0..n_out {
        if i + 8 > raw.len() {
            return Err("eof vout".into());
        }
        out.extend_from_slice(&raw[i..i + 8]);
        i += 8;
        let slen = read_compact(raw, &mut i)? as usize;
        write_compact(&mut out, slen as u64);
        if i + slen > raw.len() {
            return Err("eof vout script".into());
        }
        out.extend_from_slice(&raw[i..i + slen]);
        i += slen;
    }
    // skip witness
    if raw.get(4) == Some(&0x00) && raw.get(5) == Some(&0x01) {
        for _ in 0..n_in {
            let n_stack = read_compact(raw, &mut i)?;
            for _ in 0..n_stack {
                let n = read_compact(raw, &mut i)? as usize;
                i = i.checked_add(n).ok_or("witness overflow")?;
            }
        }
    }
    if i + 4 > raw.len() {
        return Err("eof locktime".into());
    }
    out.extend_from_slice(&raw[i..i + 4]);
    Ok(out)
}

#[derive(Debug, Clone)]
pub struct DepositExtract {
    pub value_sats: u64,
    pub dest_id20: [u8; 20],
    /// First output paid to the watch script (vault UTXO vout).
    pub vout: u32,
}

fn is_p2wsh(spk: &[u8]) -> bool {
    spk.len() == 34 && spk[0] == 0x00 && spk[1] == 0x20
}

/// Find FALC‖AccountID20 OP_RETURN + value paid to `watch_spk`.
pub fn extract_deposit(tx: &ParsedTx, watch_spk: &[u8]) -> Result<DepositExtract, String> {
    let mut dest: Option<[u8; 20]> = None;
    let mut paid = 0u64;
    let mut vout = 0u32;
    let mut found = false;
    for (i, (value, spk)) in tx.outputs.iter().enumerate() {
        if spk.first() == Some(&0x6a) {
            let payload = op_return_payload(spk)?;
            if payload.len() == 24 && payload.starts_with(FALC_MAGIC) {
                if dest.is_some() {
                    return Err("multiple FALC OP_RETURNs".into());
                }
                let mut id = [0u8; 20];
                id.copy_from_slice(&payload[4..]);
                dest = Some(id);
            }
        } else if spk.as_slice() == watch_spk {
            paid = paid.saturating_add(*value);
            if !found && *value > 0 {
                vout = i as u32;
                found = true;
            }
        }
    }
    let dest_id20 = dest.ok_or_else(|| "missing FALC OP_RETURN dest".to_string())?;
    if paid == 0 || !found {
        return Err("no output to BTC watch script".into());
    }
    Ok(DepositExtract {
        value_sats: paid,
        dest_id20,
        vout,
    })
}

pub fn op_return_payload(spk: &[u8]) -> Result<Vec<u8>, String> {
    if spk.is_empty() || spk[0] != 0x6a {
        return Err("not OP_RETURN".into());
    }
    if spk.len() == 1 {
        return Ok(Vec::new());
    }
    let n = spk[1] as usize;
    if n <= 75 {
        if spk.len() != 2 + n {
            return Err("bad OP_RETURN push".into());
        }
        return Ok(spk[2..].to_vec());
    }
    Err("OP_RETURN push too large".into())
}

pub fn hex_eq(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

/// Testnet bits rule vs parent.
///
/// Bitcoin Core: at height % 2016 == 0, nBits retargets (POW already checked
/// against the child's compact target). Between retargets, if the child is
/// ≥20 minutes after the parent, min-diff (`POW_LIMIT_BITS`) is allowed.
/// Otherwise the child must use the last **non**-min-diff `nBits`.
pub fn bits_ok_testnet(
    parent: &ParsedHeader,
    child: &ParsedHeader,
    last_real_bits: u32,
    child_height: u64,
) -> bool {
    if child_height > 0 && child_height % DIFF_INTERVAL == 0 {
        return true;
    }
    if child.bits == POW_LIMIT_BITS
        && child
            .timestamp
            .saturating_sub(parent.timestamp)
            >= TESTNET_MIN_DIFF_GAP_SEC
    {
        return true;
    }
    child.bits == last_real_bits
}

/// Mine an 80-byte header that meets `bits` (tests / private fixtures).
pub fn mine_header(
    prev_display: &str,
    merkle_display: &str,
    bits: u32,
    time: u32,
) -> Result<ParsedHeader, String> {
    let prev = display_to_internal(prev_display).unwrap_or([0u8; 32]);
    let merkle = display_to_internal(merkle_display)?;
    let mut raw = [0u8; HEADER_LEN];
    raw[0..4].copy_from_slice(&1u32.to_le_bytes());
    raw[4..36].copy_from_slice(&prev);
    raw[36..68].copy_from_slice(&merkle);
    raw[68..72].copy_from_slice(&time.to_le_bytes());
    raw[72..76].copy_from_slice(&bits.to_le_bytes());
    for nonce in 0u32..=u32::MAX {
        raw[76..80].copy_from_slice(&nonce.to_le_bytes());
        let h = hash256(&raw);
        if hash_meets_target(&h, bits) {
            return parse_header(&raw);
        }
        if nonce == u32::MAX {
            break;
        }
    }
    Err("failed to mine header".into())
}

/// Minimal deposit tx: 1 dummy input, watch payment + FALC OP_RETURN.
pub fn test_deposit_tx(watch_spk: &[u8], dest: &str, sats: u64) -> (Vec<u8>, ParsedTx) {
    let dest20 = dest_id20(dest);
    let mut payload = Vec::with_capacity(24);
    payload.extend_from_slice(FALC_MAGIC);
    payload.extend_from_slice(&dest20);
    let mut opreturn = Vec::with_capacity(26);
    opreturn.push(0x6a);
    opreturn.push(payload.len() as u8);
    opreturn.extend_from_slice(&payload);

    let mut raw = Vec::new();
    raw.extend_from_slice(&1u32.to_le_bytes());
    write_compact(&mut raw, 1);
    raw.extend_from_slice(&[0u8; 32]);
    raw.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
    write_compact(&mut raw, 0);
    raw.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
    write_compact(&mut raw, 2);
    raw.extend_from_slice(&sats.to_le_bytes());
    write_compact(&mut raw, watch_spk.len() as u64);
    raw.extend_from_slice(watch_spk);
    raw.extend_from_slice(&0u64.to_le_bytes());
    write_compact(&mut raw, opreturn.len() as u64);
    raw.extend_from_slice(&opreturn);
    raw.extend_from_slice(&0u32.to_le_bytes());
    let parsed = parse_tx(&raw).expect("test tx parses");
    (raw, parsed)
}

#[allow(dead_code)]
pub fn is_p2wsh_spk(spk: &[u8]) -> bool {
    is_p2wsh(spk)
}

#[cfg(test)]
mod tests {
    use super::*;

    const EASY_BITS: u32 = 0x207fffff;

    #[test]
    fn header_roundtrip_and_pow() {
        let merkle = "11".repeat(32);
        let h = mine_header(&"00".repeat(32), &merkle, EASY_BITS, 1_700_000_000).unwrap();
        assert_eq!(h.merkle_display, merkle);
        assert!(hash_meets_target(&h.hash_internal, EASY_BITS));
        let again = parse_header_hex(&h.raw_hex).unwrap();
        assert_eq!(again.hash_display, h.hash_display);
    }

    #[test]
    fn merkle_single_leaf() {
        let (_, tx) = test_deposit_tx(&hex_decode(TESTNET_WATCH_SPK).unwrap(), "bob", 50_000);
        verify_merkle(&tx.txid_display, &[], 0, &tx.txid_display).unwrap();
    }

    #[test]
    fn merkle_two_leaves() {
        let left = display_to_internal(&"11".repeat(32)).unwrap();
        let right = display_to_internal(&"22".repeat(32)).unwrap();
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(&left);
        buf[32..].copy_from_slice(&right);
        let root_int = hash256(&buf);
        let root_disp = display_hex(&root_int);
        verify_merkle(&"11".repeat(32), &[right], 0, &root_disp).unwrap();
        verify_merkle(&"22".repeat(32), &[left], 1, &root_disp).unwrap();
        assert!(verify_merkle(&"22".repeat(32), &[left], 0, &root_disp).is_err());
    }

    #[test]
    fn testnet_min_diff_then_restore_real_bits() {
        let merkle = "11".repeat(32);
        let real = mine_header(&"00".repeat(32), &merkle, EASY_BITS, 1_700_000_000).unwrap();
        let mut min_d = real.clone();
        min_d.bits = POW_LIMIT_BITS;
        min_d.timestamp = real.timestamp + TESTNET_MIN_DIFF_GAP_SEC;
        assert!(bits_ok_testnet(&real, &min_d, EASY_BITS, 10));
        let mut restored = min_d.clone();
        restored.bits = EASY_BITS;
        restored.timestamp = min_d.timestamp + 60;
        assert!(bits_ok_testnet(&min_d, &restored, EASY_BITS, 11));
        let mut stay_min = min_d.clone();
        stay_min.timestamp = min_d.timestamp + 10;
        assert!(
            !bits_ok_testnet(&min_d, &stay_min, EASY_BITS, 11),
            "min-diff without 20min gap must restore real bits"
        );
        let mut retarget = restored.clone();
        retarget.bits = 0x1a20dc40;
        assert!(
            bits_ok_testnet(&restored, &retarget, EASY_BITS, DIFF_INTERVAL),
            "height % 2016 must accept retarget nBits"
        );
        assert!(
            !bits_ok_testnet(&restored, &retarget, EASY_BITS, DIFF_INTERVAL + 1),
            "non-retarget must not accept a random nBits"
        );
    }

    #[test]
    fn extract_watch_and_falc() {
        let watch = hex_decode(TESTNET_WATCH_SPK).unwrap();
        let (raw, tx) = test_deposit_tx(&watch, "scott.personal", 12_345);
        let again = parse_tx(&raw).unwrap();
        assert_eq!(again.txid_display, tx.txid_display);
        let ex = extract_deposit(&tx, &watch).unwrap();
        assert_eq!(ex.value_sats, 12_345);
        assert_eq!(ex.dest_id20, dest_id20("scott.personal"));
    }
}

// ---------------------------------------------------------------------------
// Testnet4 contextual header rules (Bitcoin Core `GetNextWorkRequired` with
// `fPowAllowMinDifficultyBlocks` + BIP94, `ContextualCheckBlockHeader`).
// Used by the BTC4 most-work rail (`btc4_most_work_from_height`).
// ---------------------------------------------------------------------------

/// Two weeks (`nPowTargetTimespan`).
pub const POW_TARGET_TIMESPAN: u64 = 14 * 24 * 60 * 60;
/// Ten minutes (`nPowTargetSpacing`).
pub const POW_TARGET_SPACING: u32 = 600;
/// BIP94 `MAX_TIMEWARP`: the first header of a period may be at most this
/// many seconds earlier than its parent.
pub const MAX_TIMEWARP_SECS: u32 = 600;
/// `MAX_FUTURE_BLOCK_TIME`: two hours.
pub const MAX_FUTURE_BLOCK_TIME_SECS: u64 = 2 * 60 * 60;
/// Median-time-past window.
pub const MEDIAN_TIME_SPAN: usize = 11;
/// testnet4 is BIP34/65/66 active from genesis: `bad-version` below 4.
pub const MIN_HEADER_VERSION: u32 = 4;

/// 256-bit unsigned integer as 4 little-endian u64 limbs (tiny, no deps).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct U256(pub [u64; 4]);

impl U256 {
    pub fn from_be_bytes(b: &[u8; 32]) -> Self {
        let mut l = [0u64; 4];
        for (i, limb) in l.iter_mut().enumerate() {
            let s = 32 - 8 * (i + 1);
            *limb = u64::from_be_bytes(b[s..s + 8].try_into().unwrap());
        }
        U256(l)
    }
    pub fn bits(&self) -> u32 {
        for i in (0..4).rev() {
            if self.0[i] != 0 {
                return 64 * i as u32 + (64 - self.0[i].leading_zeros());
            }
        }
        0
    }
    pub fn mul_u64(&self, m: u64) -> Option<Self> {
        let mut out = [0u64; 4];
        let mut carry: u128 = 0;
        for i in 0..4 {
            let v = self.0[i] as u128 * m as u128 + carry;
            out[i] = v as u64;
            carry = v >> 64;
        }
        if carry != 0 {
            return None;
        }
        Some(U256(out))
    }
    pub fn div_u64(&self, d: u64) -> Self {
        let mut out = [0u64; 4];
        let mut rem: u128 = 0;
        for i in (0..4).rev() {
            let cur = (rem << 64) | self.0[i] as u128;
            out[i] = (cur / d as u128) as u64;
            rem = cur % d as u128;
        }
        U256(out)
    }
    fn shr_bytes(&self, n: u32) -> Self {
        let bits = n * 8;
        let mut out = [0u64; 4];
        let limb = (bits / 64) as usize;
        let sh = bits % 64;
        for i in 0..4 {
            if i + limb >= 4 {
                break;
            }
            out[i] = self.0[i + limb] >> sh;
            if sh != 0 && i + limb + 1 < 4 {
                out[i] |= self.0[i + limb + 1] << (64 - sh);
            }
        }
        U256(out)
    }
    /// Bitcoin Core `arith_uint256::GetCompact` (non-negative).
    pub fn to_compact(&self) -> u32 {
        let mut size = (self.bits() + 7) / 8;
        let mut compact: u32 = if size <= 3 {
            (self.0[0] << (8 * (3 - size))) as u32
        } else {
            self.shr_bytes(size - 3).0[0] as u32
        };
        if compact & 0x0080_0000 != 0 {
            compact >>= 8;
            size += 1;
        }
        compact | (size << 24)
    }
}

impl PartialOrd for U256 {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for U256 {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        for i in (0..4).rev() {
            match self.0[i].cmp(&other.0[i]) {
                std::cmp::Ordering::Equal => continue,
                o => return o,
            }
        }
        std::cmp::Ordering::Equal
    }
}

/// `nBits` → target, `None` for negative / zero / overflowing encodings.
pub fn target_u256(bits: u32) -> Option<U256> {
    compact_target(bits).map(|t| U256::from_be_bytes(&t))
}

/// Core `CheckProofOfWork` range check: target non-zero and ≤ `pow_limit_bits`'s target.
pub fn bits_within_pow_limit(bits: u32, pow_limit_bits: u32) -> bool {
    match (target_u256(bits), target_u256(pow_limit_bits)) {
        (Some(t), Some(lim)) => t <= lim && t != U256([0; 4]),
        _ => false,
    }
}

/// BIP94 retarget (`CalculateNextWorkRequired` with `enforce_BIP94`): start
/// from the **first** header of the period's nBits, scale by the clamped
/// actual timespan, cap at the pow limit.
pub fn retarget_bip94(first_bits: u32, first_time: u32, last_time: u32, pow_limit_bits: u32) -> Option<u32> {
    let lim = target_u256(pow_limit_bits)?;
    let mut span = last_time as i64 - first_time as i64;
    let t = POW_TARGET_TIMESPAN as i64;
    span = span.clamp(t / 4, t * 4);
    let base = target_u256(first_bits)?;
    // 320-bit product so easy (regtest-style) limits cannot overflow.
    let mut wide = [0u64; 5];
    let mut carry: u128 = 0;
    for i in 0..4 {
        let v = base.0[i] as u128 * span as u128 + carry;
        wide[i] = v as u64;
        carry = v >> 64;
    }
    wide[4] = carry as u64;
    let mut rem: u128 = 0;
    for i in (0..5).rev() {
        let cur = (rem << 64) | wide[i] as u128;
        wide[i] = (cur / POW_TARGET_TIMESPAN as u128) as u64;
        rem = cur % POW_TARGET_TIMESPAN as u128;
    }
    let mut new = if wide[4] != 0 { lim } else { U256([wide[0], wide[1], wide[2], wide[3]]) };
    if new > lim {
        new = lim;
    }
    Some(new.to_compact())
}

/// Median of up to the last 11 timestamps (Core `GetMedianTimePast`).
pub fn median_time_past(times: &[u32]) -> Option<u32> {
    if times.is_empty() {
        return None;
    }
    let mut v: Vec<u32> = times.iter().copied().take(MEDIAN_TIME_SPAN).collect();
    v.sort_unstable();
    Some(v[v.len() / 2])
}

#[cfg(test)]
mod testnet4_rules_tests {
    use super::*;

    #[test]
    fn compact_roundtrip() {
        for b in [0x1d00ffffu32, 0x1902a986, 0x19046aef, 0x190424d1, 0x207fffff, 0x1b0404cb] {
            assert_eq!(target_u256(b).unwrap().to_compact(), b, "{b:08x}");
        }
    }

    #[test]
    fn pow_limit_range() {
        assert!(bits_within_pow_limit(0x1d00ffff, POW_LIMIT_BITS));
        assert!(bits_within_pow_limit(0x1902a986, POW_LIMIT_BITS));
        // Easier than testnet4's limit (regtest-style) and the first value above it.
        assert!(!bits_within_pow_limit(0x207fffff, POW_LIMIT_BITS));
        assert!(!bits_within_pow_limit(0x1d010000, POW_LIMIT_BITS));
        assert!(!bits_within_pow_limit(0x1d00ffff | 0x0080_0000, POW_LIMIT_BITS));
        assert!(!bits_within_pow_limit(0x1d000000, POW_LIMIT_BITS));
    }

    /// Real testnet4 retargets (headers read from Bitcoin Core on falcon1).
    #[test]
    fn bip94_retarget_matches_testnet4() {
        // 159264: first 157248 (190424d1 @1792637587), last 159263 @1793927142.
        assert_eq!(retarget_bip94(0x190424d1, 1_792_637_587, 1_793_927_142, POW_LIMIT_BITS), Some(0x19046aef));
        // 161280: first 159264 (19046aef @1793926558), last 161279 @1794655488.
        assert_eq!(retarget_bip94(0x19046aef, 1_793_926_558, 1_794_655_488, POW_LIMIT_BITS), Some(0x1902a986));
    }

    #[test]
    fn mtp_is_median_of_11() {
        let t: Vec<u32> = (0..11).rev().map(|i| 1000 + i * 10).collect();
        assert_eq!(median_time_past(&t), Some(1050));
        assert_eq!(median_time_past(&[5, 1, 3]), Some(3));
    }
}
