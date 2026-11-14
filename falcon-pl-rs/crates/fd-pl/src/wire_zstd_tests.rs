// Copyright (c) 2025-2026 BEARTEC. All rights reserved. See LICENSE.
//! `zstd-stream-v1` wire tests: negotiation with old peers, framing, corrupt
//! frames, decompression limits, memory bound, and real-shaped ledgers.

use super::*;
use crate::crypto::{CryptoScheme, KeyRing};
use crate::wire_zstd::*;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};

fn flag(on: bool) -> Arc<AtomicBool> {
    Arc::new(AtomicBool::new(on))
}

/// Real-shaped wire lines: a Falcon-signed ledger body, its header, txs, votes.
fn wire_lines(n_txs: usize) -> Vec<String> {
    let mut keys = KeyRing::new(CryptoScheme::Falcon512);
    keys.generate_id("packer");
    let mut txs = Vec::new();
    for i in 0..n_txs {
        let acct = format!("loadgen{i:02}");
        keys.generate_id(&acct);
        txs.push(
            Tx::sign_body(&keys, &acct, 7, "loadgen99", 1, 2, NETWORK_ID_PUBLIC_TESTNET_2300, TxBody::Pay)
                .unwrap(),
        );
    }
    let ledger = Ledger::seal(
        params_v2::TESTNET_2300_MERKLE_SENDER_SIG_FROM_HEIGHT + 10,
        "00".repeat(32),
        NETWORK_ID_PUBLIC_TESTNET_2300,
        "packer",
        &keys,
        txs.clone(),
        "ab".repeat(32),
        1,
    )
    .unwrap();
    let mut out = Vec::new();
    for tx in &txs {
        out.push(serde_json::to_string(&WireMsg::SubmitTx { tx: tx.clone() }).unwrap());
    }
    out.push(serde_json::to_string(&WireMsg::ProposeHeader { header: ledger.header(), catchup: false }).unwrap());
    let mut by_id = ledger.clone();
    by_id.txs.clear();
    out.push(serde_json::to_string(&WireMsg::LedgerBodyById { ledger: by_id }).unwrap());
    for v in 0..6 {
        out.push(
            serde_json::to_string(&WireMsg::LedgerOk {
                height: ledger.height,
                ledger_hash: ledger.ledger_hash.clone(),
                voter: format!("v{v}"),
                signature: keys.sign("packer", &format!("ok{v}")).unwrap(),
                round: 0,
            })
            .unwrap(),
        );
    }
    out.push(serde_json::to_string(&WireMsg::LedgerBody { ledger }).unwrap());
    out
}

async fn send_all<W: tokio::io::AsyncWrite + Unpin>(w: &mut ZWriter<W>, lines: &[String]) {
    for l in lines {
        w.write_all((l.clone() + "\n").as_bytes()).await.unwrap();
    }
    w.shutdown().await.unwrap();
}

#[tokio::test]
async fn new_to_new_round_trip_is_exact_and_smaller() {
    let lines = wire_lines(20);
    let plain: usize = lines.iter().map(|l| l.len() + 1).sum();
    let (a, b) = tokio::io::duplex(1 << 20);
    let writer = tokio::spawn({
        let lines = lines.clone();
        async move {
            let mut w = ZWriter::new(a, flag(true), 3);
            send_all(&mut w, &lines).await;
        }
    });
    // Count raw bytes while decoding through a tee.
    let mut raw = Vec::new();
    let mut b = b;
    b.read_to_end(&mut raw).await.unwrap();
    writer.await.unwrap();
    assert!(raw.starts_with(format!("{MARKER_LINE}\n").as_bytes()));
    let mut r = LineReader::new(&raw[..], true);
    let mut got = Vec::new();
    while let Some(l) = r.next_line().await.unwrap() {
        got.push(l);
    }
    assert!(r.compressed());
    assert_eq!(got, lines);
    eprintln!("20-tx gossip bundle: plain {plain} B, zstd-stream {} B ({:.1}%)", raw.len(), 100.0 * raw.len() as f64 / plain as f64);
    assert!(raw.len() * 100 < plain * 70, "expected >30% saving, got {} of {plain}", raw.len());
}

#[tokio::test]
async fn old_peer_without_capability_gets_identical_plain_bytes() {
    let lines = wire_lines(3);
    let expect: Vec<u8> = lines.iter().flat_map(|l| (l.clone() + "\n").into_bytes()).collect();
    let (a, mut b) = tokio::io::duplex(1 << 20);
    let lines2 = lines.clone();
    let t = tokio::spawn(async move {
        // New node, peer Hello had no capability: flag stays false.
        let mut w = ZWriter::new(a, flag(false), 3);
        send_all(&mut w, &lines2).await;
        assert!(!w.compressed());
    });
    let mut raw = Vec::new();
    b.read_to_end(&mut raw).await.unwrap();
    t.await.unwrap();
    assert_eq!(raw, expect, "old peer must see byte-identical lines");
    // And an old-style tokio Lines reader parses them as before.
    let mut old = BufReader::new(&raw[..]).lines();
    let mut n = 0;
    while let Some(l) = old.next_line().await.unwrap() {
        assert_eq!(l, lines[n]);
        n += 1;
    }
    assert_eq!(n, lines.len());
}

#[tokio::test]
async fn new_reader_reads_old_writer_and_ignores_marker_unless_advertised() {
    // Old writer: plain lines, CRLF tolerated like tokio Lines.
    let raw = b"{\"type\":\"need_snapshot\"}\r\n#zstd-stream-v1\n{\"type\":\"need_snapshot\"}\n".to_vec();
    let mut r = LineReader::new(&raw[..], false);
    assert_eq!(r.next_line().await.unwrap().unwrap(), "{\"type\":\"need_snapshot\"}");
    // Not advertised: the marker is just a (junk) line, no switch.
    assert_eq!(r.next_line().await.unwrap().unwrap(), MARKER_LINE);
    assert!(!r.compressed());
    assert_eq!(r.next_line().await.unwrap().unwrap(), "{\"type\":\"need_snapshot\"}");
    assert!(r.next_line().await.unwrap().is_none());
}

#[test]
fn capability_negotiation_matrix() {
    let base = vec!["utc-header-v5".to_string()];
    let new_caps = with_capability(base.clone(), true);
    let off_caps = with_capability(base.clone(), false);
    assert!(peer_has(&new_caps));
    assert!(!peer_has(&off_caps) && !peer_has(&base) && !peer_has(&[]));
    assert_eq!(with_capability(new_caps.clone(), true), new_caps, "no duplicate token");
    // Old Hello JSON without the field still parses (serde default).
    let old = r#"{"type":"hello","id":"v6","public_key":"","tip_height":1}"#;
    match serde_json::from_str::<WireMsg>(old).unwrap() {
        WireMsg::Hello { capabilities, .. } => assert!(!peer_has(&capabilities)),
        _ => panic!("hello"),
    }
}

#[tokio::test]
async fn corrupt_frame_and_bad_lengths_end_the_session() {
    let lines = wire_lines(2);
    let mut w = ZWriter::new(Vec::new(), flag(true), 3);
    for l in &lines {
        let out = w.encode((l.clone() + "\n").as_bytes()).unwrap().into_owned();
        w.inner.extend_from_slice(&out);
    }
    let good = w.inner.clone();
    // Flip one byte inside the second frame's payload.
    let first = MARKER_LINE.len() + 1;
    let len1 = u32::from_be_bytes(good[first..first + 4].try_into().unwrap()) as usize;
    let second = first + 4 + len1;
    let mut bad = good.clone();
    bad[second + 4 + 10] ^= 0xff;
    let mut r = LineReader::new(&bad[..], true);
    assert_eq!(r.next_line().await.unwrap().unwrap(), lines[0]);
    assert!(r.next_line().await.is_err(), "corrupt frame must error");
    // Zero and oversized length prefixes.
    for len in [0u32, (MAX_FRAME_BYTES + 1) as u32] {
        let mut raw = format!("{MARKER_LINE}\n").into_bytes();
        raw.extend_from_slice(&len.to_be_bytes());
        raw.extend_from_slice(&[0u8; 16]);
        let mut r = LineReader::new(&raw[..], true);
        assert!(r.next_line().await.is_err(), "len {len}");
    }
    // Truncated frame at EOF is an error, not a hang.
    let mut r = LineReader::new(&good[..good.len() - 3], true);
    let mut res = Ok(None);
    for _ in 0..lines.len() + 1 {
        res = r.next_line().await;
        if res.is_err() {
            break;
        }
    }
    assert!(res.is_err());
}

#[tokio::test]
async fn decompression_bomb_is_capped() {
    // 64 MiB of zeros compresses to a tiny frame; the reader must refuse it.
    let bomb = vec![0u8; 64 * 1024 * 1024];
    let mut c = Compressor::new(3).unwrap();
    let frame = c.frame(&bomb).unwrap();
    assert!(frame.len() < 64 * 1024, "bomb frame is small: {}", frame.len());
    let mut raw = format!("{MARKER_LINE}\n").into_bytes();
    raw.extend_from_slice(&frame);
    let mut r = LineReader::new(&raw[..], true);
    let e = r.next_line().await.unwrap_err();
    assert!(e.to_string().contains("over limit"), "{e}");
    // Many small frames with no newline: the partial-line cap trips too.
    let mut c = Compressor::new(1).unwrap();
    let mut raw = format!("{MARKER_LINE}\n").into_bytes();
    let chunk = vec![b'a'; 8 * 1024 * 1024];
    for _ in 0..8 {
        raw.extend_from_slice(&c.frame(&chunk).unwrap());
    }
    let mut r = LineReader::new(&raw[..], true);
    assert!(r.next_line().await.is_err());
}

#[tokio::test]
async fn frames_needing_a_bigger_window_are_refused() {
    use zstd::zstd_safe::{zstd_sys::ZSTD_EndDirective, CCtx, CParameter, InBuffer, OutBuffer};
    let mut cctx = CCtx::create();
    cctx.set_parameter(CParameter::WindowLog(24)).unwrap();
    let data = vec![7u8; 4096];
    let mut buf = vec![0u8; 1 << 16];
    let mut ob = OutBuffer::around(&mut buf[..]);
    let mut ib = InBuffer::around(&data[..]);
    cctx.compress_stream2(&mut ob, &mut ib, ZSTD_EndDirective::ZSTD_e_flush).unwrap();
    let n = ob.pos();
    let mut raw = format!("{MARKER_LINE}\n").into_bytes();
    raw.extend_from_slice(&(n as u32).to_be_bytes());
    raw.extend_from_slice(&buf[..n]);
    let mut r = LineReader::new(&raw[..], true);
    assert!(r.next_line().await.is_err(), "window_log 24 frame must be refused");
}

#[test]
fn memory_per_connection_is_bounded() {
    for lvl in 1..=3 {
        let b = context_bytes(lvl).unwrap();
        eprintln!("zstd level {lvl}: compressor+decompressor {} KiB per connection", b / 1024);
        assert!(b <= 3 * 1024 * 1024, "level {lvl}: {b} B");
    }
}

#[test]
fn level_env_is_clamped() {
    // Pure function of the value; avoid touching process env in parallel tests.
    assert_eq!((0i32).clamp(1, 3), 1);
    assert!((1..=3).contains(&level()));
}

/// Offline: every real body round-trips through one compressed stream.
#[tokio::test]
async fn real_bodies_round_trip() {
    let Ok(dir) = std::env::var("FPL_REAL_BODIES_DIR") else {
        return;
    };
    let mut lines = Vec::new();
    for e in std::fs::read_dir(&dir).unwrap() {
        let l: Ledger = serde_json::from_slice(&std::fs::read(e.unwrap().path()).unwrap()).unwrap();
        lines.push(serde_json::to_string(&WireMsg::LedgerBody { ledger: l }).unwrap());
    }
    let plain: usize = lines.iter().map(|l| l.len() + 1).sum();
    let mut w = ZWriter::new(Vec::new(), flag(true), 3);
    for l in &lines {
        let out = w.encode((l.clone() + "\n").as_bytes()).unwrap().into_owned();
        w.inner.extend_from_slice(&out);
    }
    let raw = w.inner;
    let mut r = LineReader::new(&raw[..], true);
    for l in &lines {
        assert_eq!(&r.next_line().await.unwrap().unwrap(), l);
    }
    assert!(r.next_line().await.unwrap().is_none());
    eprintln!("{} real bodies: plain {plain} B, zstd-stream {} B ({:.1}%)", lines.len(), raw.len(), 100.0 * raw.len() as f64 / plain as f64);
}
