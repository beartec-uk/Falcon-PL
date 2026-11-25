// Copyright (c) 2025-2026 BEARTEC. All rights reserved. See LICENSE.
//! Network load with real Falcon-512 (or HMAC) against live falcon-pl-node(s).
//!
//! Persistent TCP (no connect+Hello per tx) — required for Falcon multi-host inject rate.
//!
//!   falcon-pl-load-net --keys /path/keys --scheme falcon-512 \
//!     --rpc 127.0.0.1:19101,127.0.0.1:19102 --rate 100 --seconds 60 --wallets 1024 --workers 32

use anyhow::{bail, Context, Result};
use clap::Parser;
use fd_pl::crypto::{CryptoScheme, KeyRing};
use fd_pl::{Tx, WireMsg};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, Semaphore};

#[derive(Parser, Debug)]
struct Args {
    #[arg(long)]
    keys: PathBuf,
    #[arg(long, default_value = "falcon-512")]
    scheme: String,
    #[arg(long, default_value = "127.0.0.1:19101")]
    rpc: String,
    #[arg(long, default_value_t = 16)]
    wallets: u32,
    #[arg(long, default_value_t = 20.0)]
    seconds: f64,
    /// Steady txs/sec (0 = dump as fast as possible).
    #[arg(long, default_value_t = 50.0)]
    rate: f64,
    #[arg(long, default_value_t = 4)]
    workers: usize,
    #[arg(long, default_value_t = 9101)]
    network_id: u32,
    #[arg(long, default_value_t = 1)]
    amount: u64,
    #[arg(long, default_value_t = 1)]
    fee: u64,
    #[arg(long, default_value_t = 45.0)]
    drain_wait: f64,
    /// Persist per-wallet next sequence across process restarts (JSON map).
    /// Always **overridden** by live chain `status` account sequences on start
    /// (file is a warm hint only; chain is source of truth).
    #[arg(long, default_value = "")]
    seq_file: String,
    /// Skip chain status resync (debug only — can re-introduce seq poison).
    #[arg(long, default_value_t = false)]
    no_chain_seq: bool,
    /// Also fan each accepted tx to a second RPC (doubles wire work; off by default).
    #[arg(long, default_value_t = false)]
    fan_peers: bool,
    /// Stop launching after this many txs (0 = run for --seconds).
    /// Use with --wallets equal to this value for one next-sequence tx per wallet.
    #[arg(long, default_value_t = 0)]
    max_submit: u64,
}

/// One long-lived TCP session to a hub (Hello drained once).
struct RpcConn {
    reader: BufReader<OwnedReadHalf>,
    writer: OwnedWriteHalf,
}

impl RpcConn {
    async fn connect(addr: &str) -> Result<Self> {
        let stream = TcpStream::connect(addr)
            .await
            .with_context(|| format!("connect {addr}"))?;
        // Disable Nagle — small submits should flush immediately.
        let _ = stream.set_nodelay(true);
        let (reader, writer) = stream.into_split();
        let mut reader = BufReader::new(reader);
        // Drain initial Hello (may be large) so the first SubmitTx sees Ok/Err.
        let mut line = String::new();
        let n = reader
            .read_line(&mut line)
            .await
            .context("read hello")?;
        if n == 0 {
            bail!("eof before hello from {addr}");
        }
        Ok(Self { reader, writer })
    }

    async fn call(&mut self, msg: &WireMsg) -> Result<WireMsg> {
        let line = serde_json::to_string(msg)? + "\n";
        self.writer.write_all(line.as_bytes()).await?;
        self.writer.flush().await?;
        // Skip any trailing Hellos; take first non-Hello.
        for _ in 0..16 {
            let mut resp = String::new();
            let n = self.reader.read_line(&mut resp).await?;
            if n == 0 {
                bail!("eof from peer");
            }
            let m: WireMsg = serde_json::from_str(&resp)?;
            match m {
                WireMsg::Hello { .. } => continue,
                other => return Ok(other),
            }
        }
        bail!("no useful response")
    }
}

/// Pool of reusable connections per RPC address (one free list per addr).
struct ConnPool {
    free: Mutex<BTreeMap<String, Vec<RpcConn>>>,
}

impl ConnPool {
    fn new() -> Self {
        Self {
            free: Mutex::new(BTreeMap::new()),
        }
    }

    async fn take(&self, addr: &str) -> Result<RpcConn> {
        {
            let mut g = self.free.lock().await;
            if let Some(v) = g.get_mut(addr) {
                if let Some(c) = v.pop() {
                    return Ok(c);
                }
            }
        }
        RpcConn::connect(addr).await
    }

    async fn put(&self, addr: String, conn: RpcConn) {
        let mut g = self.free.lock().await;
        g.entry(addr).or_default().push(conn);
    }

    async fn call(&self, addr: &str, msg: WireMsg) -> Result<WireMsg> {
        // Up to 2 attempts (reconnect on broken pipe).
        let mut last_err = None;
        for _ in 0..2 {
            let mut conn = match self.take(addr).await {
                Ok(c) => c,
                Err(e) => {
                    last_err = Some(e);
                    continue;
                }
            };
            match conn.call(&msg).await {
                Ok(r) => {
                    self.put(addr.to_string(), conn).await;
                    return Ok(r);
                }
                Err(e) => {
                    // drop broken conn
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow::anyhow!("rpc failed")))
    }
}

async fn status(pool: &ConnPool, addr: &str) -> Result<serde_json::Value> {
    // Slim by default (ops metrics). Full accounts only when needed for seq resync.
    status_detail(pool, addr, false).await
}

async fn status_detail(pool: &ConnPool, addr: &str, include_accounts: bool) -> Result<serde_json::Value> {
    match pool
        .call(addr, WireMsg::StatusReq { include_accounts, brief: false })
        .await?
    {
        WireMsg::Status { body } => Ok(body),
        other => Ok(serde_json::to_value(other)?),
    }
}

/// Pull each wallet's next-seq from chain status (`accounts.<id>.sequence` == need).
fn resync_seqs_from_status(
    seq_map: &mut BTreeMap<String, u64>,
    st: &serde_json::Value,
    accounts: &[String],
) -> (usize, Option<u64>) {
    let accts = st.get("accounts").cloned().unwrap_or(serde_json::json!({}));
    let mut corrected = 0usize;
    for a in accounts {
        let chain_need = accts
            .get(a)
            .and_then(|v| v.get("sequence"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let prev = seq_map.get(a).copied().unwrap_or(1);
        if prev != chain_need {
            corrected += 1;
        }
        seq_map.insert(a.clone(), chain_need);
    }
    (corrected, seq_map.get("w00").copied())
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let args = Args::parse();
    let scheme = CryptoScheme::parse(&args.scheme).context("scheme")?;
    let keys = KeyRing::load_dir(&args.keys).context("load keys")?;
    if keys.scheme != scheme {
        eprintln!(
            "warn: keys scheme={:?} flag={}",
            keys.scheme.as_str(),
            scheme.as_str()
        );
    }

    let rpcs: Vec<String> = args
        .rpc
        .split(',')
        .map(|s| s.trim().replace("http://", "").replace("https://", ""))
        .filter(|s| !s.is_empty())
        .collect();
    if rpcs.is_empty() {
        bail!("no rpc endpoints");
    }
    let primary = rpcs[0].clone();

    let accounts: Vec<String> = (0..args.wallets).map(|i| format!("w{i:02}")).collect(); // genesis names: w00..w99, w100..
    for a in &accounts {
        if keys.public_hex(a).is_none() {
            bail!("keys dir missing wallet {a}");
        }
    }

    let pool = Arc::new(ConnPool::new());
    // Warm one connection so first status is not cold-start only.
    // Full accounts once for sequence resync; rest of load uses slim status.
    let st0 = status_detail(&pool, &primary, true).await?;
    let tip0 = st0.get("tip_height").and_then(|v| v.as_u64()).unwrap_or(0);
    println!(
        "=== Falcon load-net ===\nscheme={} wallets={} rate={} workers={} seconds={} rpc={:?} fan_peers={}",
        scheme.as_str(),
        args.wallets,
        if args.rate > 0.0 {
            format!("{:.0} tx/s steady", args.rate)
        } else {
            "DUMP".into()
        },
        args.workers,
        args.seconds,
        rpcs,
        args.fan_peers
    );
    println!(
        "start tip={} mempool={:?} node_scheme={:?} (persistent TCP)",
        tip0,
        st0.get("mempool"),
        st0.get("scheme")
    );

    let mut seq_map: BTreeMap<String, u64> = accounts.iter().map(|a| (a.clone(), 0u64)).collect();
    if !args.seq_file.is_empty() {
        let path = PathBuf::from(&args.seq_file);
        if path.exists() {
            let raw = std::fs::read_to_string(&path).context("read seq-file")?;
            let loaded: BTreeMap<String, u64> =
                serde_json::from_str(&raw).context("parse seq-file")?;
            for (k, v) in loaded {
                if seq_map.contains_key(&k) {
                    seq_map.insert(k, v.max(1));
                }
            }
            eprintln!(
                "seq-file loaded {} accounts from {} (sample w00={:?})",
                seq_map.len(),
                path.display(),
                seq_map.get("w00")
            );
        }
    }
    if !args.no_chain_seq {
        let (corrected, sample) = resync_seqs_from_status(&mut seq_map, &st0, &accounts);
        eprintln!(
            "chain-seq resync: corrected={corrected}/{} sample w00={:?} (chain wins over seq-file)",
            accounts.len(),
            sample
        );
        if corrected > 0 {
            eprintln!(
                "  note: seq-file was stale for {corrected} wallet(s) — would have poisoned mempool"
            );
        }
        if !args.seq_file.is_empty() {
            if let Some(parent) = PathBuf::from(&args.seq_file).parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            if let Ok(raw) = serde_json::to_string_pretty(&seq_map) {
                let _ = std::fs::write(&args.seq_file, raw);
                eprintln!("seq-file synced from chain → {}", args.seq_file);
            }
        }
    } else {
        eprintln!("WARN: --no-chain-seq set; using seq-file/defaults only");
    }

    // Shard sequences per-worker to avoid one global mutex on every tx.
    let n_workers = args.workers.max(1);
    let mut shards: Vec<BTreeMap<String, u64>> = (0..n_workers).map(|_| BTreeMap::new()).collect();
    for (i, (k, v)) in seq_map.into_iter().enumerate() {
        shards[i % n_workers].insert(k, v);
    }
    let shards: Arc<Vec<Mutex<BTreeMap<String, u64>>>> =
        Arc::new(shards.into_iter().map(Mutex::new).collect());

    let ok = Arc::new(AtomicU64::new(0));
    let err = Arc::new(AtomicU64::new(0));
    let keys = Arc::new(keys);
    let accounts = Arc::new(accounts);
    let rpcs = Arc::new(rpcs);
    let pool = pool;

    let stop_at = Instant::now() + Duration::from_secs_f64(args.seconds);
    let sem = Arc::new(Semaphore::new(n_workers));
    let interval = if args.rate > 0.0 {
        Duration::from_secs_f64(1.0 / args.rate)
    } else {
        Duration::from_secs(0)
    };
    let next_slot = Arc::new(Mutex::new(Instant::now()));

    let t0 = Instant::now();
    let mut handles = Vec::new();
    let mut i = 0u64;
    while Instant::now() < stop_at {
        if args.max_submit > 0 && i >= args.max_submit {
            break;
        }
        if !interval.is_zero() {
            let mut slot = next_slot.lock().await;
            let now = Instant::now();
            if now < *slot {
                let w = *slot - now;
                *slot += interval;
                drop(slot);
                tokio::time::sleep(w).await;
            } else {
                *slot = now + interval;
            }
        }
        let permit = sem.clone().acquire_owned().await?;
        let keys = keys.clone();
        let accounts = accounts.clone();
        let shards = shards.clone();
        let rpcs = rpcs.clone();
        let pool = pool.clone();
        let ok = ok.clone();
        let err = err.clone();
        let network_id = args.network_id;
        let amount = args.amount;
        let fee = args.fee;
        let fan_peers = args.fan_peers;
        let idx = i;
        i += 1;
        let worker = (idx as usize) % n_workers;
        handles.push(tokio::spawn(async move {
            let _permit = permit;
            // Pin wallet to worker shard so sequences stay coherent under concurrency.
            let from = accounts[idx as usize % accounts.len()].clone();
            let to = accounts[(idx as usize + 1) % accounts.len()].clone();
            // Prefer shard that owns this wallet if present; else worker shard.
            let shard_i = {
                let mut found = worker;
                for (si, sh) in shards.iter().enumerate() {
                    if sh.lock().await.contains_key(&from) {
                        found = si;
                        break;
                    }
                }
                found
            };
            let seq = {
                let mut s = shards[shard_i].lock().await;
                let e = s.entry(from.clone()).or_insert(1);
                let v = *e;
                *e += 1;
                v
            };
            // Falcon sign is CPU-heavy — don't block the tokio reactor.
            let keys2 = keys.clone();
            let from2 = from.clone();
            let to2 = to.clone();
            let sign_res = tokio::task::spawn_blocking(move || {
                Tx::sign_with(&keys2, &from2, seq, &to2, amount, fee, network_id)
            })
            .await;
            let tx = match sign_res {
                Ok(Ok(t)) => t,
                _ => {
                    let mut s = shards[shard_i].lock().await;
                    if let Some(e) = s.get_mut(&from) {
                        if *e == seq + 1 {
                            *e = seq;
                        }
                    }
                    err.fetch_add(1, Ordering::Relaxed);
                    return;
                }
            };
            let primary = &rpcs[idx as usize % rpcs.len()];
            match pool
                .call(primary, WireMsg::SubmitTx { tx: tx.clone() })
                .await
            {
                Ok(WireMsg::Ok { msg }) if msg == "accepted" => {
                    ok.fetch_add(1, Ordering::Relaxed);
                    if fan_peers && rpcs.len() > 1 {
                        let peer = &rpcs[(idx as usize + 1) % rpcs.len()];
                        let _ = pool.call(peer, WireMsg::SubmitTx { tx }).await;
                    }
                }
                Ok(WireMsg::Ok { msg }) => {
                    let mut s = shards[shard_i].lock().await;
                    if let Some(e) = s.get_mut(&from) {
                        if *e == seq + 1 {
                            *e = seq;
                        }
                    }
                    if msg != "duplicate" {
                        err.fetch_add(1, Ordering::Relaxed);
                    }
                }
                Ok(WireMsg::Err { .. }) | Err(_) => {
                    let mut s = shards[shard_i].lock().await;
                    if let Some(e) = s.get_mut(&from) {
                        if *e == seq + 1 {
                            *e = seq;
                        }
                    }
                    err.fetch_add(1, Ordering::Relaxed);
                }
                _ => {
                    let mut s = shards[shard_i].lock().await;
                    if let Some(e) = s.get_mut(&from) {
                        if *e == seq + 1 {
                            *e = seq;
                        }
                    }
                    err.fetch_add(1, Ordering::Relaxed);
                }
            }
        }));
        if handles.len() > n_workers * 64 {
            let h = handles.remove(0);
            let _ = h.await;
        }
    }
    for h in handles {
        let _ = h.await;
    }

    // Merge shards for seq-file save.
    let mut merged = BTreeMap::new();
    for sh in shards.iter() {
        let g = sh.lock().await;
        for (k, v) in g.iter() {
            merged.insert(k.clone(), *v);
        }
    }
    if !args.seq_file.is_empty() {
        if let Some(parent) = PathBuf::from(&args.seq_file).parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        std::fs::write(
            &args.seq_file,
            serde_json::to_string_pretty(&merged).unwrap_or_else(|_| "{}".into()),
        )
        .context("write seq-file")?;
        eprintln!("seq-file saved → {}", args.seq_file);
    }
    let submit_elapsed = t0.elapsed().as_secs_f64();
    let ok_n = ok.load(Ordering::Relaxed);
    let err_n = err.load(Ordering::Relaxed);
    println!(
        "submit_ok={ok_n} submit_err={err_n} elapsed_s={submit_elapsed:.2} submit_tps={:.1}",
        ok_n as f64 / submit_elapsed.max(0.001)
    );

    println!("waiting for drain / seals…");
    let drain_deadline = Instant::now() + Duration::from_secs_f64(args.drain_wait);
    let mut st1 = status(&pool, &primary).await?;
    while Instant::now() < drain_deadline {
        st1 = status(&pool, &primary).await?;
        let mp = st1.get("mempool").and_then(|v| v.as_u64()).unwrap_or(0);
        let tip = st1.get("tip_height").and_then(|v| v.as_u64()).unwrap_or(0);
        if mp == 0 {
            break;
        }
        println!(
            "  … tip={tip} mempool={mp} soft={:?} hard={:?} votes={:?}",
            st1.get("tip_soft"),
            st1.get("tip_hard"),
            st1.get("tip_ok_votes")
        );
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    st1 = status(&pool, &primary).await?;
    let tip1 = st1.get("tip_height").and_then(|v| v.as_u64()).unwrap_or(0);

    println!("\n=== Falcon load-net result ===");
    println!(
        "tip {tip0} → {tip1} (Δ{}) mempool_now={:?} soft={:?} hard={:?} votes={:?}",
        tip1.saturating_sub(tip0),
        st1.get("mempool"),
        st1.get("tip_soft"),
        st1.get("tip_hard"),
        st1.get("tip_ok_votes")
    );
    println!("rewards={:?}", st1.get("rewards"));
    println!("lottery_next={:?}", st1.get("lottery_winner_next"));
    for addr in rpcs.iter() {
        if let Ok(st) = status(&pool, addr).await {
            let tip = st.get("tip_height").and_then(|v| v.as_u64()).unwrap_or(0);
            let h = st
                .get("tip_hash")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .chars()
                .take(16)
                .collect::<String>();
            println!("  {addr}: tip={tip} hash={h}…");
        }
    }
    Ok(())
}
