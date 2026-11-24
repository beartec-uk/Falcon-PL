// Copyright (c) 2025-2026 BEARTEC. All rights reserved. See LICENSE.
//! 2.11.13 bridge slim: before/after numbers on real-size bridge state.
//!
//! `cargo run --release --example slim_bench -- <join snapshot.json> [out_dir]`
//!
//! Apart from `slim_convert` / `phases` (stubbed for the pre-slim tree) it uses
//! only APIs present before and after the change. Set `FPL_BRIDGE_SLIM_FROM_HEIGHT=1` (non-2300
//! networks only) to measure the slim side. Read-only on the input file.
//! Prints one `RESULT key=value` line per measurement.
use std::time::Instant;

fn rss() -> (u64, u64) {
    let s = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    let f = |k: &str| {
        s.lines()
            .find(|l| l.starts_with(k))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0)
            / 1024
    };
    (f("VmRSS:"), f("VmHWM:"))
}

fn res(k: &str, v: impl std::fmt::Display) {
    println!("RESULT {k}={v}");
}

fn ms(t: Instant) -> String {
    format!("{:.1}", t.elapsed().as_secs_f64() * 1000.0)
}

fn exec_header(n: u64, compact: bool) -> fd_pl::eth_exec::EthExecHeader {
    // Built from JSON so the same code compiles before and after the slim
    // fields exist. A live header's RLP is ~1.3 KB of hex.
    let mut v = serde_json::json!({
        "number": n,
        "hash": format!("{:064x}", n + 1),
        "parent_hash": format!("{n:064x}"),
        "receipts_root": format!("{:064x}", n * 3),
        "rlp_hex": if compact { String::new() } else { "f9".repeat(660) },
    });
    if compact {
        v["timestamp"] = serde_json::json!(1_790_000_000u64 + n);
    }
    serde_json::from_value(v).unwrap()
}

fn main() {
    let path = std::env::args().nth(1).expect("snapshot path");
    let out = std::path::PathBuf::from(std::env::args().nth(2).unwrap_or_else(|| "/tmp/slim-bench".into()));
    std::fs::create_dir_all(&out).unwrap();
    let slim = std::env::var("FPL_BRIDGE_SLIM_FROM_HEIGHT").is_ok();
    res("mode", if slim { "after" } else { "before" });
    let keys = fd_pl::crypto::KeyRing::new(fd_pl::crypto::CryptoScheme::HmacDev);

    // 1. Real snapshot: load, (after) convert, root, snapshot write.
    let t = Instant::now();
    let mut real = fd_pl::Node::load_snapshot(&path, keys.clone()).expect("load");
    res("real_load_ms", ms(t));
    res("real_tip", real.tip_height);
    let (r, _) = rss();
    res("real_rss_after_load_mb", r);
    let mut conv_ms = String::from("n/a");
    if slim {
        // The per-ledger hook runs this at the activation height.
        let mut b = real.bridge.clone();
        let t = Instant::now();
        conv_ms = slim_convert(&mut b, t);
        real.bridge = b;
    }
    res("real_convert_ms", conv_ms);
    let bridge_json = serde_json::to_vec(&real.bridge).unwrap();
    res("real_bridge_json_bytes", bridge_json.len());
    res("real_bridge_sha256", fd_pl::crypto::sha256_hex(&bridge_json));
    drop(bridge_json);
    let t = Instant::now();
    let fresh = real.commitment_root_fresh();
    res("real_root_fresh_ms", ms(t));
    let t = Instant::now();
    let c1 = real.commitment_root();
    res("real_root_cached_first_ms", ms(t));
    assert_eq!(fresh, c1);
    // Per-block case: a non-map field changes, maps keep their cache.
    real.bridge.eth_exec_prune_floor += 1;
    let t = Instant::now();
    let _ = real.commitment_root();
    res("real_root_after_small_change_ms", ms(t));
    real.bridge.eth_exec_prune_floor -= 1;
    // Draft clone of the bridge (pack/verify/commit each take one).
    let t = Instant::now();
    for _ in 0..10 {
        let b = real.bridge.clone();
        std::hint::black_box(&b);
    }
    res("real_bridge_clone_ms_x10", ms(t));
    // Snapshot capture + write (after: zstd once slim is in the state).
    let t = Instant::now();
    let snap = real.to_snapshot();
    res("real_snapshot_capture_ms", ms(t));
    let f = out.join(if slim { "after.json" } else { "before.json" });
    let t = Instant::now();
    let bytes = fd_pl::Node::write_snapshot_checked(&f, &snap, &|_, _| Ok(())).unwrap();
    res("real_snapshot_write_ms", ms(t));
    res("real_snapshot_file_bytes", bytes);
    if slim {
        std::env::set_var("FPL_SNAPSHOT_ZSTD", "0");
        let f2 = out.join("after-plain.json");
        let t = Instant::now();
        let b2 = fd_pl::Node::write_snapshot_checked(&f2, &snap, &|_, _| Ok(())).unwrap();
        res("real_snapshot_plain_write_ms", ms(t));
        res("real_snapshot_plain_bytes", b2);
        std::env::remove_var("FPL_SNAPSHOT_ZSTD");
        let t = Instant::now();
        let back = fd_pl::Node::load_snapshot(&f, keys.clone()).expect("reload zstd");
        res("real_snapshot_zstd_load_ms", ms(t));
        assert_eq!(
            fd_pl::crypto::sha256_hex(&serde_json::to_vec(&back.bridge).unwrap()),
            fd_pl::crypto::sha256_hex(&serde_json::to_vec(&real.bridge).unwrap())
        );
        let _ = std::fs::remove_file(&f2);
    }
    drop(snap);
    let (r, h) = rss();
    res("real_rss_mb", r);
    res("real_hwm_mb", h);
    let real_bridge = real.bridge.clone();
    drop(real);

    // 2. Pack phases on one seat carrying the real-size bridge.
    let users: Vec<(String, u64)> = (0..64).map(|i| (format!("u{i}"), 1_000_000_000)).collect();
    let cfg = fd_pl::ChainConfig {
        scheme: fd_pl::crypto::CryptoScheme::Falcon512,
        pack_budget_ms: 5_000,
        progress_timeout_ms: 4_000,
        max_txs_per_ledger: 200,
        fee_escalate: false,
        min_fee: 1,
        ..Default::default()
    };
    let mut net = fd_pl::Network::bootstrap(&["v1"], 1000, &users, cfg);
    net.nodes.get_mut("v1").unwrap().bridge = real_bridge;
    let mut next_exec = net.nodes["v1"].bridge.eth_exec_headers.keys().next_back().copied().unwrap_or(1) + 1;
    let mut u = 0usize;
    for (round, ntx) in [(0usize, 28usize), (1, 28), (2, 200), (3, 28), (4, 200), (5, 200), (6, 28), (7, 200)] {
        for _ in 0..ntx {
            let from = format!("u{}", u % 64);
            let to = format!("u{}", (u + 1) % 64);
            u += 1;
            net.payment(&from, &to, 1, 1).unwrap();
        }
        // A live block usually also moves the ETH exec map (new header).
        {
            let n = net.nodes.get_mut("v1").unwrap();
            let compact = n.bridge.eth_exec_headers.values().next_back().map(|h| h.rlp_hex.is_empty()).unwrap_or(false);
            n.bridge.eth_exec_headers.make_mut().insert(next_exec, exec_header(next_exec, compact));
            next_exec += 1;
        }
        net.pong_all();
        let n = net.nodes.get_mut("v1").unwrap();
        let t = Instant::now();
        let mut ledger = n.pack_or_skip("v1").expect("pack").expect("ledger");
        let pack = ms(t);
        let t = Instant::now();
        let keys = n.keys.clone();
        let _ = ledger.attach_merkle_batch_known(&keys, &|id| n.account_public_key(id));
        let merkle = ms(t);
        let t = Instant::now();
        n.accept_ledger(&ledger).expect("accept");
        let accept = ms(t);
        let t = Instant::now();
        let _ = n.vote_ok(&ledger.ledger_hash, "v1");
        let commit = ms(t);
        let (r, h) = rss();
        let tag = format!("pack{round}_txs{}", ledger.txs.len());
        res(&format!("{tag}_pack_ms"), pack);
        res(&format!("{tag}_merkle_ms"), merkle);
        res(&format!("{tag}_accept_ms"), accept);
        res(&format!("{tag}_commit_ms"), commit);
        res(&format!("{tag}_rss_mb"), r);
        res(&format!("{tag}_hwm_mb"), h);
        res(&format!("{tag}_tip"), n.tip_height);
        phases(n, &tag);
    }
    let t = Instant::now();
    let snap = net.nodes["v1"].to_snapshot();
    let capture = ms(t);
    let f = out.join(if slim { "seat-after.json" } else { "seat-before.json" });
    let t = Instant::now();
    let bytes = fd_pl::Node::write_snapshot_checked(&f, &snap, &|_, _| Ok(())).unwrap();
    res("seat_snapshot_capture_ms", capture);
    res("seat_snapshot_write_ms", ms(t));
    res("seat_snapshot_bytes", bytes);
    let (r, h) = rss();
    res("final_rss_mb", r);
    res("final_hwm_mb", h);
    println!("OK");
}

// BEFORE-TREE: the two functions below use 2.11.13 APIs; the pre-slim run
// replaces their bodies with "n/a" / no-op stubs.
fn slim_convert(b: &mut fd_pl::bridge::BridgeState, t: Instant) -> String {
    assert!(b.bridge_slim_convert());
    ms(t)
}
fn phases(n: &fd_pl::Node, tag: &str) {
    let p = n.pack_phases;
    for (k, v) in [("sanitize", p.sanitize_us), ("clone", p.clone_us), ("hook", p.hook_us), ("apply", p.apply_us), ("root", p.root_us), ("stage", p.stage_us), ("stage_root", p.stage_root_us)] {
        res(&format!("{tag}_{k}_ms"), format!("{:.1}", v as f64 / 1000.0));
    }
}
