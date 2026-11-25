// Copyright (c) 2025-2026 BEARTEC. All rights reserved. See LICENSE.
//! Execution-layer proofs: header ancestry + receipt MPT + FalconQc Deposit log.
//!
//! keccak256 / RLP. Used after the beacon LC has verified `execution_block_hash`.

use crate::eth_ssz::parse32;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

pub const DEPOSIT_TOPIC0: &str =
    // keccak256("Deposit(bytes32,address,uint256,bytes32)")
    "668b7640365fc09f7ddaf1edfae6911ae7a7701e5bda817da9430723b9b8b021";

/// keccak256("Deposit(bytes32,address,bytes20,address,uint256,uint64)").
/// V3 peg-in. Not the V1/V2 `Deposit(bytes32,address,uint256,bytes32)` topic.
pub const ETH_V3_DEPOSIT_TOPIC0: [u8; 32] = [
    0xe7, 0x78, 0x3c, 0x72, 0x79, 0x17, 0x36, 0xd4, 0xd8, 0xaf, 0x95, 0x66, 0x0d, 0x43, 0x67, 0xbe,
    0xd2, 0xf9, 0x8d, 0x83, 0x31, 0xa0, 0x95, 0x42, 0x23, 0x73, 0xe5, 0x57, 0xa4, 0x31, 0x87, 0x28,
];

pub const ETH_V3_DEPOSIT_EVENT: &str = "Deposit(bytes32,address,bytes20,address,uint256,uint64)";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EthExecHeader {
    pub number: u64,
    pub hash: String,
    pub parent_hash: String,
    pub receipts_root: String,
    /// RLP of the execution header (hex). Hash must be keccak256(rlp).
    ///
    /// 2.11.13 bridge slim: a stored header is compacted after its RLP was
    /// verified on insert (empty here, omitted from serde). Every submitted
    /// header still carries it. Non-empty on every stored header before the
    /// activation, so those bytes are unchanged.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub rlp_hex: String,
    /// 2.11.13 bridge slim: header timestamp (RLP field 11), filled from the
    /// verified RLP when the header is compacted. `0` (omitted) on every
    /// pre-activation header; a submitted value is ignored (zeroed on
    /// insert), as older nodes' parsers drop the unknown field.
    #[serde(default, skip_serializing_if = "ts_is_zero")]
    pub timestamp: u64,
}

fn ts_is_zero(v: &u64) -> bool {
    *v == 0
}

/// 2.11.13 bridge slim: keep (number, hash, parent, receipts_root, timestamp).
/// Only for a header whose RLP was already verified. Deterministic: an RLP
/// whose timestamp does not decode keeps `timestamp = 0` (the LC-head time
/// then uses the slot fallback, as before).
pub fn compact_exec_header(h: &mut EthExecHeader) {
    if h.rlp_hex.is_empty() {
        return;
    }
    let raw = h.rlp_hex.trim().trim_start_matches("0x").trim_start_matches("0X");
    h.timestamp = hex::decode(raw)
        .ok()
        .and_then(|rlp| exec_header_timestamp(&rlp).ok())
        .unwrap_or(0);
    h.rlp_hex = String::new();
}

pub fn keccak256(data: &[u8]) -> [u8; 32] {
    Keccak256::digest(data).into()
}

fn rlp_len_len(len: usize) -> usize {
    if len < 56 {
        1
    } else if len <= 0xff {
        2
    } else if len <= 0xffff {
        3
    } else if len <= 0xff_ffff {
        4
    } else {
        5
    }
}

fn rlp_header(out: &mut Vec<u8>, payload_len: usize, is_list: bool) {
    let offset = if is_list { 0xc0 } else { 0x80 };
    if payload_len < 56 {
        out.push(offset + payload_len as u8);
    } else {
        let lenb = payload_len.to_be_bytes();
        let start = lenb.iter().position(|b| *b != 0).unwrap_or(7);
        let nbytes = 8 - start;
        out.push(offset + 55 + nbytes as u8);
        out.extend_from_slice(&lenb[start..]);
    }
    let _ = rlp_len_len(payload_len);
}

pub fn rlp_bytes(b: &[u8]) -> Vec<u8> {
    let mut o = Vec::new();
    if b.len() == 1 && b[0] < 0x80 {
        o.push(b[0]);
        return o;
    }
    rlp_header(&mut o, b.len(), false);
    o.extend_from_slice(b);
    o
}

pub fn rlp_list(items: &[Vec<u8>]) -> Vec<u8> {
    let payload: usize = items.iter().map(|i| i.len()).sum();
    let mut o = Vec::new();
    rlp_header(&mut o, payload, true);
    for i in items {
        o.extend_from_slice(i);
    }
    o
}

pub fn rlp_uint(n: u64) -> Vec<u8> {
    rlp_bytes(&compact_int(n))
}

fn hex_to_bytes(s: &str) -> Result<Vec<u8>, String> {
    hex::decode(s.trim().trim_start_matches("0x")).map_err(|e| e.to_string())
}

/// Parent hash, receipts root, and block number from an execution header RLP.
pub fn decode_exec_header_meta(rlp: &[u8]) -> Result<([u8; 32], [u8; 32], u64), String> {
    let items = rlp_split_list(rlp)?;
    if items.len() < 15 {
        return Err("execution header fields".into());
    }
    let parent = rlp_payload(items[0])?.1;
    let receipts = rlp_payload(items[5])?.1;
    let number_b = rlp_payload(items[8])?.1;
    if parent.len() != 32 || receipts.len() != 32 {
        return Err("header parent/receipts len".into());
    }
    let mut ph = [0u8; 32];
    ph.copy_from_slice(parent);
    let mut rr = [0u8; 32];
    rr.copy_from_slice(receipts);
    let mut n = 0u64;
    for b in number_b {
        n = n
            .checked_shl(8)
            .and_then(|v| v.checked_add(*b as u64))
            .ok_or("header number overflow")?;
    }
    Ok((ph, rr, n))
}

/// Unix timestamp at execution-header RLP field index 11.
///
/// Post-London layout: parent, ommers, beneficiary, state, txs, receipts,
/// bloom, difficulty, number, gasLimit, gasUsed, **timestamp**. Amsterdam /
/// Gloas append `blockAccessListHash` and `slotNumber` after the Cancun
/// fields; they do not move index 11.
pub fn exec_header_timestamp(rlp: &[u8]) -> Result<u64, String> {
    let items = rlp_split_list(rlp)?;
    if items.len() <= 11 {
        return Err("execution header timestamp field missing".into());
    }
    let raw = rlp_payload(items[11])?.1;
    if raw.len() > 8 {
        return Err("execution header timestamp overflow".into());
    }
    let mut n = 0u64;
    for b in raw {
        n = n
            .checked_shl(8)
            .and_then(|v| v.checked_add(*b as u64))
            .ok_or("execution header timestamp overflow")?;
    }
    Ok(n)
}

/// Verify keccak256(rlp) == hash and parent/receipts/number match the RLP.
pub fn verify_exec_header_rlp(h: &EthExecHeader) -> Result<(), String> {
    let rlp = hex_to_bytes(&h.rlp_hex)?;
    let got = keccak256(&rlp);
    let want = parse32(&h.hash)?;
    if got != want {
        return Err("execution header rlp hash mismatch".into());
    }
    let (ph, rr, n) = decode_exec_header_meta(&rlp)?;
    if parse32(&h.parent_hash)? != ph {
        return Err("parent_hash not in rlp".into());
    }
    if parse32(&h.receipts_root)? != rr {
        return Err("receipts_root not in rlp".into());
    }
    if h.number != n {
        return Err("number not in rlp".into());
    }
    Ok(())
}

/// Walk `headers` so each child's parent is the previous hash, ending at `head_hash`.
pub fn verify_ancestry<'a>(
    headers: &'a [EthExecHeader],
    head_hash: &str,
    deposit_number: u64,
) -> Result<&'a EthExecHeader, String> {
    if headers.is_empty() {
        return Err("no execution headers".into());
    }
    let head = parse32(head_hash)?;
    // headers[0] is the deposit block; last.hash must be the LC execution hash.
    let last = headers.last().unwrap();
    verify_exec_header_rlp(last)?;
    if parse32(&last.hash)? != head {
        return Err("header chain does not end at LC execution hash".into());
    }
    for i in 1..headers.len() {
        verify_exec_header_rlp(&headers[i])?;
        if parse32(&headers[i].parent_hash)? != parse32(&headers[i - 1].hash)? {
            return Err(format!("execution parent mismatch at {}", headers[i].number));
        }
        if headers[i].number != headers[i - 1].number + 1 {
            return Err("execution numbers not consecutive".into());
        }
    }
    let dep = &headers[0];
    verify_exec_header_rlp(dep)?;
    if dep.number != deposit_number {
        return Err("deposit block number mismatch".into());
    }
    Ok(dep)
}

/// [`verify_ancestry`] over stored headers. A compacted header (empty RLP,
/// 2.11.13 bridge slim) was RLP-verified when it was inserted, so only its
/// stored links are checked; a header that still has its RLP is re-verified
/// exactly as before. Before the activation every stored header has its RLP,
/// so this is [`verify_ancestry`].
pub fn verify_ancestry_stored<'a>(
    headers: &'a [EthExecHeader],
    head_hash: &str,
    deposit_number: u64,
) -> Result<&'a EthExecHeader, String> {
    if headers.iter().all(|h| !h.rlp_hex.is_empty()) {
        return verify_ancestry(headers, head_hash, deposit_number);
    }
    if headers.is_empty() {
        return Err("no execution headers".into());
    }
    let check = |h: &EthExecHeader| -> Result<(), String> {
        if h.rlp_hex.is_empty() {
            Ok(())
        } else {
            verify_exec_header_rlp(h)
        }
    };
    let head = parse32(head_hash)?;
    let last = headers.last().unwrap();
    check(last)?;
    if parse32(&last.hash)? != head {
        return Err("header chain does not end at LC execution hash".into());
    }
    for i in 1..headers.len() {
        check(&headers[i])?;
        if parse32(&headers[i].parent_hash)? != parse32(&headers[i - 1].hash)? {
            return Err(format!("execution parent mismatch at {}", headers[i].number));
        }
        if headers[i].number != headers[i - 1].number + 1 {
            return Err("execution numbers not consecutive".into());
        }
    }
    let dep = &headers[0];
    check(dep)?;
    if dep.number != deposit_number {
        return Err("deposit block number mismatch".into());
    }
    Ok(dep)
}

/// Receipt/tx trie key: nibbles of RLP(index). Not keccak (that's state/storage).
fn mpt_key_nibbles(index: u32) -> Vec<u8> {
    let idx = rlp_uint(index as u64);
    let mut ns = Vec::with_capacity(idx.len() * 2);
    for b in idx {
        ns.push(b >> 4);
        ns.push(b & 0x0f);
    }
    ns
}

fn compact_int(n: u64) -> Vec<u8> {
    if n == 0 {
        return vec![];
    }
    let b = n.to_be_bytes();
    let s = b.iter().position(|x| *x != 0).unwrap_or(7);
    b[s..].to_vec()
}

fn decode_nibble_path(compact: &[u8]) -> Result<(Vec<u8>, bool), String> {
    if compact.is_empty() {
        return Err("empty compact hex".into());
    }
    let flag = compact[0] >> 4;
    let is_leaf = flag == 2 || flag == 3;
    let mut ns = Vec::new();
    if flag & 1 == 1 {
        ns.push(compact[0] & 0x0f);
    }
    for b in &compact[1..] {
        ns.push(b >> 4);
        ns.push(b & 0x0f);
    }
    Ok((ns, is_leaf))
}

fn rlp_split_list(buf: &[u8]) -> Result<Vec<&[u8]>, String> {
    if buf.is_empty() {
        return Err("empty rlp".into());
    }
    let (is_list, payload, _) = rlp_payload(buf)?;
    if !is_list {
        return Err("want rlp list".into());
    }
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < payload.len() {
        let (_, _, total) = rlp_payload(&payload[i..])?;
        out.push(&payload[i..i + total]);
        i += total;
    }
    Ok(out)
}

fn rlp_payload(buf: &[u8]) -> Result<(bool, &[u8], usize), String> {
    if buf.is_empty() {
        return Err("eof rlp".into());
    }
    let b0 = buf[0];
    if b0 < 0x80 {
        return Ok((false, &buf[..1], 1));
    }
    if b0 < 0xb8 {
        let l = (b0 - 0x80) as usize;
        if buf.len() < 1 + l {
            return Err("eof str".into());
        }
        return Ok((false, &buf[1..1 + l], 1 + l));
    }
    if b0 < 0xc0 {
        let n = (b0 - 0xb7) as usize;
        if buf.len() < 1 + n {
            return Err("eof long str".into());
        }
        let mut len = 0usize;
        for x in &buf[1..1 + n] {
            len = (len << 8) + *x as usize;
        }
        if buf.len() < 1 + n + len {
            return Err("eof long str body".into());
        }
        return Ok((false, &buf[1 + n..1 + n + len], 1 + n + len));
    }
    if b0 < 0xf8 {
        let l = (b0 - 0xc0) as usize;
        if buf.len() < 1 + l {
            return Err("eof list".into());
        }
        return Ok((true, &buf[1..1 + l], 1 + l));
    }
    let n = (b0 - 0xf7) as usize;
    if buf.len() < 1 + n {
        return Err("eof long list".into());
    }
    let mut len = 0usize;
    for x in &buf[1..1 + n] {
        len = (len << 8) + *x as usize;
    }
    if buf.len() < 1 + n + len {
        return Err("eof long list body".into());
    }
    Ok((true, &buf[1 + n..1 + n + len], 1 + n + len))
}

fn node_hash(raw: &[u8]) -> [u8; 32] {
    if raw.len() < 32 {
        let mut h = [0u8; 32];
        h[..raw.len()].copy_from_slice(raw);
        h
    } else {
        keccak256(raw)
    }
}

/// Verify a receipt MPT proof. `nodes` are RLP node hex, root is receipts_root.
pub fn verify_receipt_proof(
    receipts_root: &str,
    tx_index: u32,
    nodes: &[String],
    leaf_value: &[u8],
) -> Result<(), String> {
    let want_root = parse32(receipts_root)?;
    if nodes.is_empty() {
        return Err("empty mpt proof".into());
    }
    let key = mpt_key_nibbles(tx_index);
    let mut key_i = 0usize;
    let mut expected = want_root;
    for (nidx, hx) in nodes.iter().enumerate() {
        let raw = hex_to_bytes(hx)?;
        let h = if nidx == 0 {
            keccak256(&raw)
        } else {
            node_hash(&raw)
        };
        if nidx == 0 && h != expected {
            return Err("mpt root mismatch".into());
        }
        if nidx > 0 && h != expected && keccak256(&raw) != expected {
            return Err(format!("mpt node {nidx} hash mismatch"));
        }
        let items = rlp_split_list(&raw)?;
        if items.len() == 17 {
            if key_i >= key.len() {
                return Err("mpt branch overflow".into());
            }
            let nib = key[key_i] as usize;
            key_i += 1;
            let child = rlp_payload(items[nib])?.1;
            if child.len() == 32 {
                expected.copy_from_slice(child);
            } else if child.is_empty() {
                return Err("mpt empty branch".into());
            } else {
                expected = keccak256(child);
            }
        } else if items.len() == 2 {
            let (path, is_leaf) = decode_nibble_path(rlp_payload(items[0])?.1)?;
            if key[key_i..].get(..path.len()) != Some(path.as_slice()) {
                return Err("mpt extension/leaf path".into());
            }
            key_i += path.len();
            if is_leaf {
                let val = rlp_payload(items[1])?.1;
                if val != leaf_value && items[1] != leaf_value {
                    // leaf value may be wrapped
                    if val != leaf_value {
                        return Err("mpt leaf value mismatch".into());
                    }
                }
                if key_i != key.len() {
                    return Err("mpt key leftover".into());
                }
                return Ok(());
            }
            let child = rlp_payload(items[1])?.1;
            if child.len() == 32 {
                expected.copy_from_slice(child);
            } else {
                expected = keccak256(child);
            }
        } else {
            return Err("mpt node shape".into());
        }
    }
    Err("mpt proof exhausted".into())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DepositLog {
    pub dest20: [u8; 20],
    pub token: [u8; 20],
    pub amount: u128,
    pub lock_id: [u8; 32],
}

fn topic0_deposit() -> [u8; 32] {
    keccak256(b"Deposit(bytes32,address,uint256,bytes32)")
}

/// Parse a typed or legacy receipt; pull FalconQc Deposit logs.
pub fn deposit_from_receipt(receipt: &[u8], bridge20: &[u8; 20]) -> Result<Vec<DepositLog>, String> {
    let body = if receipt.first() == Some(&0x01)
        || receipt.first() == Some(&0x02)
        || receipt.first() == Some(&0x03)
        || receipt.first() == Some(&0x04)
    {
        &receipt[1..]
    } else {
        receipt
    };
    let items = rlp_split_list(body)?;
    // status, cumgas, bloom, logs  (post-byzantium)
    if items.len() < 4 {
        return Err("receipt fields".into());
    }
    let logs_raw = rlp_split_list(items[3])?;
    let want_t0 = topic0_deposit();
    let mut out = Vec::new();
    for log in logs_raw {
        let f = rlp_split_list(log)?;
        if f.len() < 3 {
            continue;
        }
        let addr = rlp_payload(f[0])?.1;
        if addr.len() != 20 || addr != bridge20 {
            continue;
        }
        let topics = rlp_split_list(f[1])?;
        if topics.is_empty() {
            continue;
        }
        let t0 = rlp_payload(topics[0])?.1;
        if t0 != want_t0.as_slice() {
            continue;
        }
        if topics.len() < 3 {
            continue;
        }
        let t1 = rlp_payload(topics[1])?.1;
        let t2 = rlp_payload(topics[2])?.1;
        let data = rlp_payload(f[2])?.1;
        if t1.len() != 32 || t2.len() != 32 || data.len() < 64 {
            continue;
        }
        let mut dest20 = [0u8; 20];
        dest20.copy_from_slice(&t1[12..32]);
        let mut token = [0u8; 20];
        token.copy_from_slice(&t2[12..32]);
        let mut amount_b = [0u8; 16];
        amount_b.copy_from_slice(&data[16..32]);
        let amount = u128::from_be_bytes(amount_b);
        let mut lock_id = [0u8; 32];
        lock_id.copy_from_slice(&data[32..64]);
        out.push(DepositLog {
            dest20,
            token,
            amount,
            lock_id,
        });
    }
    Ok(out)
}

pub fn dest20_from_account(account: &str) -> [u8; 20] {
    crate::btc_spv::dest_id20(account)
}

/// One V3 `Deposit` log. `dest20` is the FPL destination (bytes20, left-aligned
/// in its ABI word). `sender` is the refund address (topic2, right-aligned).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V3DepositLog {
    pub deposit_id: [u8; 32],
    pub sender: [u8; 20],
    pub dest20: [u8; 20],
    pub token: [u8; 20],
    pub amount: u64,
    pub timestamp: u64,
}

/// `keccak256(abi.encode(uint256 chainid, address bridge, uint256 nonce))`.
///
/// 96 bytes, not packed: chain id in the low 8 of word 0, bridge right-aligned
/// in word 1, nonce in the low 8 of word 2. Matches
/// `FalconQcBridgeV3.deriveDepositId` (pre-increment nonce, first deposit is 0).
pub fn v3_deposit_id(chainid: u64, bridge20: &[u8; 20], nonce: u64) -> [u8; 32] {
    let mut buf = [0u8; 96];
    buf[24..32].copy_from_slice(&chainid.to_be_bytes());
    buf[44..64].copy_from_slice(bridge20);
    buf[88..96].copy_from_slice(&nonce.to_be_bytes());
    keccak256(&buf)
}

fn abi_u64_word(word: &[u8]) -> Option<u64> {
    if word.len() != 32 || word[..24].iter().any(|b| *b != 0) {
        return None;
    }
    let mut b = [0u8; 8];
    b.copy_from_slice(&word[24..32]);
    Some(u64::from_be_bytes(b))
}

fn abi_right_addr(word: &[u8]) -> Option<[u8; 20]> {
    if word.len() != 32 || word[..12].iter().any(|b| *b != 0) {
        return None;
    }
    let mut a = [0u8; 20];
    a.copy_from_slice(&word[12..32]);
    Some(a)
}

/// bytes20 in `abi.encode` is left-aligned: bytes 0..20, the rest zero.
fn abi_left_bytes20(word: &[u8]) -> Option<[u8; 20]> {
    if word.len() != 32 || word[20..].iter().any(|b| *b != 0) {
        return None;
    }
    let mut a = [0u8; 20];
    a.copy_from_slice(&word[..20]);
    Some(a)
}

/// V3 Deposit logs from `bridge20` in a typed or legacy receipt.
///
/// A log is kept only when address and topic0 match, there are exactly 3
/// topics, and every ABI word has zero padding. Amount must fit in u64.
/// Malformed logs and other events (including `PoolFunded`) are skipped.
/// A receipt that does not parse yields an empty vec.
///
/// Any EIP-2718 type byte (`0x00..=0x7f`) is stripped, not only today's
/// 1..=4, so a receipt of a future tx type still yields its logs. A legacy
/// receipt is an RLP list and starts at `0xc0` or above.
pub fn v3_deposits_from_receipt(receipt: &[u8], bridge20: &[u8; 20]) -> Vec<V3DepositLog> {
    let body = match receipt.first() {
        Some(&t) if t <= 0x7f => &receipt[1..],
        _ => receipt,
    };
    let Ok(items) = rlp_split_list(body) else {
        return Vec::new();
    };
    if items.len() < 4 {
        return Vec::new();
    }
    let Ok(logs_raw) = rlp_split_list(items[3]) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for log in logs_raw {
        let Ok(f) = rlp_split_list(log) else {
            continue;
        };
        if f.len() < 3 {
            continue;
        }
        let Ok((_, addr, _)) = rlp_payload(f[0]) else {
            continue;
        };
        if addr.len() != 20 || addr != bridge20 {
            continue;
        }
        let Ok(topics) = rlp_split_list(f[1]) else {
            continue;
        };
        if topics.len() != 3 {
            continue;
        }
        let Ok((_, t0, _)) = rlp_payload(topics[0]) else {
            continue;
        };
        let Ok((_, t1, _)) = rlp_payload(topics[1]) else {
            continue;
        };
        let Ok((_, t2, _)) = rlp_payload(topics[2]) else {
            continue;
        };
        let Ok((_, data, _)) = rlp_payload(f[2]) else {
            continue;
        };
        if t0 != ETH_V3_DEPOSIT_TOPIC0.as_slice() || t1.len() != 32 || t2.len() != 32 {
            continue;
        }
        let Some(sender) = abi_right_addr(t2) else {
            continue;
        };
        if data.len() != 128 {
            continue;
        }
        let Some(dest20) = abi_left_bytes20(&data[0..32]) else {
            continue;
        };
        let Some(token) = abi_right_addr(&data[32..64]) else {
            continue;
        };
        let Some(amount) = abi_u64_word(&data[64..96]) else {
            continue;
        };
        let Some(timestamp) = abi_u64_word(&data[96..128]) else {
            continue;
        };
        let mut deposit_id = [0u8; 32];
        deposit_id.copy_from_slice(t1);
        out.push(V3DepositLog {
            deposit_id,
            sender,
            dest20,
            token,
            amount,
            timestamp,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deposit_topic0_is_keccak_signature() {
        let t = topic0_deposit();
        assert_eq!(hex::encode(t), hex::encode(keccak256(b"Deposit(bytes32,address,uint256,bytes32)")));
        assert_eq!(hex::encode(t), DEPOSIT_TOPIC0);
    }

    #[test]
    fn rlp_roundtrip_small() {
        let b = rlp_bytes(&[0x01]);
        assert_eq!(b, vec![0x01]);
        let l = rlp_list(&[rlp_bytes(&[1]), rlp_bytes(&[2])]);
        assert_eq!(l[0], 0xc2);
        assert_eq!(rlp_uint(0), vec![0x80]);
        assert_eq!(rlp_uint(1), vec![0x01]);
        assert_eq!(mpt_key_nibbles(0), vec![0x8, 0x0]);
        assert_eq!(mpt_key_nibbles(1), vec![0x0, 0x1]);
    }

    fn hp_leaf(nibbles: &[u8]) -> Vec<u8> {
        if nibbles.len() % 2 == 1 {
            let mut o = vec![0x30 | nibbles[0]];
            for i in (1..nibbles.len()).step_by(2) {
                o.push((nibbles[i] << 4) | nibbles[i + 1]);
            }
            o
        } else {
            let mut o = vec![0x20];
            for i in (0..nibbles.len()).step_by(2) {
                o.push((nibbles[i] << 4) | nibbles[i + 1]);
            }
            o
        }
    }

    fn dummy_header(number: u64, parent: [u8; 32], receipts: [u8; 32]) -> EthExecHeader {
        let items = [
            rlp_bytes(&parent),
            rlp_bytes(&[0u8; 32]),
            rlp_bytes(&[0u8; 20]),
            rlp_bytes(&[0u8; 32]),
            rlp_bytes(&[0u8; 32]),
            rlp_bytes(&receipts),
            rlp_bytes(&[0u8; 256]),
            rlp_uint(0),
            rlp_uint(number),
            rlp_uint(30_000_000),
            rlp_uint(0),
            rlp_uint(1),
            rlp_bytes(&[]),
            rlp_bytes(&[0u8; 32]),
            rlp_bytes(&[0u8; 8]),
            rlp_uint(1),
            rlp_bytes(&[0u8; 32]),
            rlp_uint(0),
            rlp_uint(0),
            rlp_bytes(&[0u8; 32]),
            rlp_bytes(&[0u8; 32]),
        ];
        let rlp = rlp_list(&items);
        let hash = keccak256(&rlp);
        EthExecHeader {
            number,
            hash: hex::encode(hash),
            parent_hash: hex::encode(parent),
            receipts_root: hex::encode(receipts),
            rlp_hex: hex::encode(&rlp),
            timestamp: 0,
        }
    }

    #[test]
    fn header_rlp_binds_parent_receipts_number() {
        let parent = [7u8; 32];
        let receipts = [9u8; 32];
        let h = dummy_header(42, parent, receipts);
        verify_exec_header_rlp(&h).unwrap();
        let mut bad = h.clone();
        bad.number = 43;
        assert!(verify_exec_header_rlp(&bad).unwrap_err().contains("number"));
        bad = h.clone();
        bad.parent_hash = hex::encode([8u8; 32]);
        assert!(verify_exec_header_rlp(&bad).unwrap_err().contains("parent"));
    }

    #[test]
    fn receipt_mpt_single_leaf_index0() {
        let receipt = {
            let bloom = vec![0u8; 256];
            let logs = rlp_list(&[]);
            let body = rlp_list(&[rlp_uint(1), rlp_uint(21_000), rlp_bytes(&bloom), logs]);
            let mut v = vec![0x02];
            v.extend_from_slice(&body);
            v
        };
        let key = mpt_key_nibbles(0);
        let leaf = rlp_list(&[rlp_bytes(&hp_leaf(&key)), rlp_bytes(&receipt)]);
        let root = keccak256(&leaf);
        verify_receipt_proof(&hex::encode(root), 0, &[hex::encode(&leaf)], &receipt).unwrap();
        assert!(verify_receipt_proof(&hex::encode(root), 1, &[hex::encode(&leaf)], &receipt).is_err());
    }
}
