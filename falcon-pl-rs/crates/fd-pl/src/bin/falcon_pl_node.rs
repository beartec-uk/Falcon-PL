// Copyright (c) 2025-2026 BEARTEC. All rights reserved. See LICENSE.
//! Multi-process PL node — JSON-TCP with **persistent peer writers**.
//!
//! Shared `--keys-dir` required for multi-process key material.

use anyhow::{bail, Context, Result};
use clap::Parser;
use fd_pl::crypto::{CryptoScheme, KeyRing};
use fd_pl::{
    ChainConfig, HelloGate, HelloSession, Ledger, Node, NodeRole, SnapAssembler, SnapInsert,
    WireMsg, NETWORK_ID_PRIVATE_V22, NETWORK_NAME, PRODUCT_VERSION,
};
use parking_lot::Mutex;
use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::AsRawFd;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream, UnixListener, UnixStream};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// Message slots (back-pressure). Real bound is **bytes** (`WIRE_QUEUE_BYTES`).
const WIRE_QUEUE_CAP: usize = 512;
const TX_QUEUE_CAP: usize = 512;
/// Per-peer consensus outbound cap (v2.8.0). Fat bodies must never sit here.
const WIRE_QUEUE_BYTES: usize = 8 * 1024 * 1024;
const TX_QUEUE_BYTES: usize = 4 * 1024 * 1024;
/// Reserved body lane (v2.9.15). Inventory cannot evict LedgerBody.
const BODY_QUEUE_CAP: usize = 64;
const BODY_QUEUE_BYTES: usize = 4 * 1024 * 1024;
/// Catch-up lane (v2.9.16 / v2.9.20). Sized for two byte-capped batches
/// plus NeedLedgers. A 2 MB cap dropped Falcon-512 LedgersBatch (~1.5 MB)
/// and the joiner stalled while live packed 10 ledgers/s.
const CATCH_QUEUE_CAP: usize = 32;
const CATCH_QUEUE_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Copy, PartialEq, Eq)]
enum ConsClass {
    Vote,
    Header,
    Other,
}

#[derive(Clone)]
struct ByteTx {
    tx: mpsc::Sender<String>,
    used: Arc<std::sync::atomic::AtomicUsize>,
    cap: usize,
}

/// One inbound dial. A second Hello from the same seat closes the older one.
#[derive(Clone)]
struct InboundSink {
    id: String,
    tx: ByteTx,
    close: Arc<std::sync::atomic::AtomicBool>,
    large_out: Arc<LargeGate>,
}

/// v2.10.3: a large send whose completion is never observed (writer
/// skipped it, socket wedged, peer stalled) used to hold the per-peer
/// "large in flight" flag forever, so every later dish logged "one already
/// in flight" (1 Nov 2026, crypto-dashboard). The gate now carries the time it
/// was taken and is treated as stale (and retaken) after LARGE_OUT_STALE.
const LARGE_OUT_STALE: std::time::Duration = std::time::Duration::from_secs(10);

struct LargeGate {
    /// Milliseconds since `base` when taken; 0 = clear.
    since_ms: std::sync::atomic::AtomicU64,
    base: std::time::Instant,
}

impl LargeGate {
    fn new() -> Self {
        Self {
            since_ms: std::sync::atomic::AtomicU64::new(0),
            base: std::time::Instant::now(),
        }
    }

    fn now_ms(&self) -> u64 {
        // +1 so a gate taken at t=0 is never confused with "clear".
        self.base.elapsed().as_millis() as u64 + 1
    }

    /// Take the gate. Returns false while a fresh send is in flight.
    fn try_acquire(&self, id: &str) -> bool {
        self.try_acquire_at(self.now_ms(), id)
    }

    fn try_acquire_at(&self, now: u64, id: &str) -> bool {
        use std::sync::atomic::Ordering::Relaxed;
        let cur = self.since_ms.load(Relaxed);
        if cur != 0 {
            let age = now.saturating_sub(cur);
            if age < LARGE_OUT_STALE.as_millis() as u64 {
                return false;
            }
            if self.since_ms.compare_exchange(cur, now, Relaxed, Relaxed).is_err() {
                return false;
            }
            warn!("large send gate to {id} stale after {age} ms, cleared");
            return true;
        }
        self.since_ms.compare_exchange(0, now, Relaxed, Relaxed).is_ok()
    }

    fn clear(&self) {
        self.since_ms.store(0, std::sync::atomic::Ordering::Relaxed);
    }
}

/// Drop a TCP session whose kernel send or receive queue stays over this.
const PIPE_SHED_BYTES: usize = 1_000_000;
const PIPE_SHED_HOLD: std::time::Duration = std::time::Duration::from_secs(2);
/// Do not start another large body while the kernel still holds this much.
const PIPE_PAUSE_BYTES: usize = 256 * 1024;
/// Transaction relay may queue while a body is in flight. Inventory and
/// ledger bodies stay on the 256 KB pause. 2 MB is about 10 seconds of the
/// 50 tx/s intake, then the send is held and retried.
const TX_RELAY_BUDGET: usize = 2 * 1024 * 1024;
/// Consensus lane must be under this before a large inventory write starts.
const CONS_LOW_WATER: usize = 64 * 1024;
const LARGE_LINE: usize = 64 * 1024;
/// After a shed, refuse that peer so both sides do not redial in the same second.
const BLACKHOLE_SECS: u64 = 8;
/// v2.9.67 join-serve retention (local only, not consensus). Hashed serve
/// files `<stem>.join.serve.<sha>.json` stay fetchable by hash: the newest
/// `JOIN_SERVE_KEEP`, anything younger than `JOIN_SERVE_MIN_AGE_MS`, the
/// current pin, and any sha a joiner fetched in the last `JOIN_SERVE_MIN_AGE_MS`.
const JOIN_SERVE_KEEP: usize = 6;
const JOIN_SERVE_MIN_AGE_MS: u64 = 30 * 60 * 1000;
/// v2.9.67: publish a new join pin at most this often (was every saver tick,
/// ~2 min, 100 MB each). A pin this old is a few hundred blocks behind; the
/// joiner closes that with residual NeedLedgers.
const SNAP_PIN_MIN_ROTATE_MS: u64 = 10 * 60 * 1000;
/// v2.9.68 joiner: a download projected to take longer than this is dropped
/// after `SNAP_SLOW_JUDGE_MS`, and its source is skipped for
/// `SNAP_SLOW_SKIP_MS` so a faster seat's offer wins the next round.
const SNAP_SLOW_JUDGE_MS: u64 = 45_000;
const SNAPSHOT_PUSH_MAX: u32 = 48;
/// v2.9.69 server: one push of a sha per requester per this window; a repeat
/// NeedSnapshot gets the offer only (the joiner pulls by window if it wants it).
const SNAPSHOT_REPUSH_MS: u64 = 120_000;
/// v2.9.69 joiner: a NeedLedgers target that moved our tip nowhere in this long
/// is skipped (same slow-source map as snapshots).
const LEDGER_SLOW_MS: u64 = 10_000;
const LEDGER_SLOW_SKIP_MS: u64 = 60_000;
const SNAP_SLOW_BUDGET_MS: u64 = 8 * 60 * 1000;
const SNAP_SLOW_SKIP_MS: u64 = 10 * 60 * 1000;
/// v2.9.74 joiner: aborted snapshot downloads kept for resume (one per hub pin).
const SNAP_STASH_CAP: usize = 2;

fn tcp_queue(fd: std::os::unix::io::RawFd, cmd: libc::c_ulong) -> Option<usize> {
    let mut n: libc::c_int = 0;
    let rc = unsafe { libc::ioctl(fd, cmd, &mut n) };
    if rc < 0 {
        None
    } else {
        Some(n.max(0) as usize)
    }
}

fn tcp_unsent(fd: std::os::unix::io::RawFd) -> Option<usize> {
    tcp_queue(fd, libc::TIOCOUTQ)
}

fn tcp_unread(fd: std::os::unix::io::RawFd) -> Option<usize> {
    tcp_queue(fd, libc::FIONREAD)
}

/// RST the socket. A normal close leaves the old fd ESTABLISHED while the
/// peer keeps writing into it.
fn hard_reset(fd: std::os::unix::io::RawFd) {
    let linger = libc::linger {
        l_onoff: 1,
        l_linger: 0,
    };
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_LINGER,
            &linger as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::linger>() as libc::socklen_t,
        );
    }
}

enum WriteEnd {
    /// Kernel buffer stayed full. Caller resets the socket.
    Shed { unsent: usize, unread: usize, which: &'static str },
    /// Large body skipped. The vote socket stays up.
    Dropped { unsent: usize },
}

fn is_tx_relay(bytes: &[u8]) -> bool {
    let head = &bytes[..bytes.len().min(80)];
    head.windows(10).any(|w| w == b"submit_tx")
        || head.windows(6).any(|w| w == b"tx_inv")
        || head.windows(16).any(|w| w == b"need_mempool_txs")
}

fn line_must_send(bytes: &[u8]) -> bool {
    let head = &bytes[..bytes.len().min(80)];
    // Transaction batches are inventory. Treating them as must-send let a
    // 1.3 MB dish occupy the socket ahead of the ledger body.
    head.windows(13).any(|w| w == b"ledgers_batch")
        || head.windows(14).any(|w| w == b"snapshot_chunk")
        || head.windows(11).any(|w| w == b"ledger_body")
        || head.windows(15).any(|w| w == b"LedgerBodyById")
        || head.windows(9).any(|w| w == b"TxsByIds")
        || head.windows(8).any(|w| w == b"TxsBatch")
        || head.windows(14).any(|w| w == b"propose_ledger")
        // v2.10.3: a dropped piece breaks the whole run, so pieces never drop.
        || head.starts_with(b"{\"type\":\"piece\"")
}

async fn write_or_shed(
    writer: &mut tokio::net::tcp::OwnedWriteHalf,
    probe: std::os::unix::io::RawFd,
    bytes: &[u8],
) -> Result<(), WriteEnd> {
    let mut unsent = tcp_unsent(probe).unwrap_or(0);
    // Catch-up bodies are the only way an accept-only seat moves its tip.
    // A dish may be skipped. A LedgersBatch may not.
    let head = &bytes[..bytes.len().min(80)];
    let catchup_body = head.windows(13).any(|w| w == b"ledgers_batch")
        || head.windows(14).any(|w| w == b"snapshot_chunk");
    // Dish and ledger body are what seals the next block. Dropping them
    // while the kernel queue is full of transaction fan-out froze 447954:
    // the 1.33 MB body was discarded and the socket stayed open.
    let must_send = line_must_send(bytes);
    if must_send && unsent > PIPE_PAUSE_BYTES {
        // The peer is still reading. Reset only after the queue stops
        // shrinking for PIPE_SHED_HOLD, not because it is large.
        let mut last = unsent;
        let mut still_since = tokio::time::Instant::now();
        loop {
            unsent = tcp_unsent(probe).unwrap_or(0);
            if unsent <= PIPE_PAUSE_BYTES {
                break;
            }
            if unsent < last {
                last = unsent;
                still_since = tokio::time::Instant::now();
            } else if still_since.elapsed() >= PIPE_SHED_HOLD {
                return Err(WriteEnd::Shed {
                    unsent,
                    unread: tcp_unread(probe).unwrap_or(0),
                    which: "body",
                });
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    }
    if bytes.len() > LARGE_LINE && unsent > PIPE_PAUSE_BYTES && !must_send {
        return Err(WriteEnd::Dropped { unsent });
    }
    let mut deadline = tokio::time::Instant::now() + PIPE_SHED_HOLD;
    let mut off = 0usize;
    let mut progressed = 0usize;
    loop {
        if off == bytes.len() {
            return Ok(());
        }
        if off > progressed {
            progressed = off;
            deadline = tokio::time::Instant::now() + PIPE_SHED_HOLD;
        }
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        if left.is_zero() {
            let unsent = tcp_unsent(probe).unwrap_or(0);
            let unread = tcp_unread(probe).unwrap_or(0);
            if unsent > PIPE_SHED_BYTES {
                return Err(WriteEnd::Shed {
                    unsent,
                    unread,
                    which: "send",
                });
            }
            // The kernel took none of this line, so the next pong is still framed.
            // A block body must not be discarded: redial and send it on the new socket.
            if off == 0 && !catchup_body {
                if must_send {
                    return Err(WriteEnd::Shed {
                        unsent,
                        unread,
                        which: "body",
                    });
                }
                return Err(WriteEnd::Dropped { unsent });
            }
            // A partial line cannot stay on the socket. Reset it.
            return Err(WriteEnd::Shed {
                unsent,
                unread,
                which: "torn",
            });
        }
        match tokio::time::timeout(left, writer.write(&bytes[off..])).await {
            Ok(Ok(0)) => {
                return Err(WriteEnd::Shed {
                    unsent: tcp_unsent(probe).unwrap_or(0),
                    unread: tcp_unread(probe).unwrap_or(0),
                    which: "send",
                });
            }
            Ok(Ok(n)) => off += n,
            Ok(Err(_)) => {
                return Err(WriteEnd::Shed {
                    unsent: tcp_unsent(probe).unwrap_or(0),
                    unread: tcp_unread(probe).unwrap_or(0),
                    which: "send",
                });
            }
            Err(_) => {}
        }
    }
}

async fn emit_or_shed(
    writer: &mut tokio::net::tcp::OwnedWriteHalf,
    probe: std::os::unix::io::RawFd,
    bytes: &[u8],
    who: &str,
    dir: &str,
) -> Result<(), PipeShed> {
    match write_or_shed(writer, probe, bytes).await {
        Ok(()) => Ok(()),
        Err(WriteEnd::Dropped { unsent }) => {
            warn!(
                "pause large send {dir} to {who} bytes={} unsent={unsent}",
                bytes.len()
            );
            Ok(())
        }
        Err(WriteEnd::Shed { unsent, unread, which }) => {
            warn!(
                "shed stuck {dir} pipe to {who} reason={which} unsent={unsent} unread={unread}"
            );
            hard_reset(probe);
            Err(PipeShed)
        }
    }
}

/// After the dish line is written, withhold only the id body and the header
/// until the kernel queue drops or this elapses. The writer keeps running.
const DISH_GATE: std::time::Duration = std::time::Duration::from_millis(1500);
/// Inventory allowed through while that dish is still in the kernel buffer.
const DISH_INV_BUDGET: usize = 64 * 1024;

fn is_tx_dish(line: &[u8]) -> bool {
    let head = &line[..line.len().min(80)];
    head.windows(8).any(|w| w == b"TxsBatch")
}

fn is_body_successor(line: &[u8]) -> bool {
    let head = &line[..line.len().min(96)];
    head.windows(15).any(|w| w == b"LedgerBodyById")
        || head.windows(13).any(|w| w == b"ProposeHeader")
}

fn dish_blocking(since: &Option<tokio::time::Instant>, probe: std::os::unix::io::RawFd) -> bool {
    let Some(started) = since else {
        return false;
    };
    if started.elapsed() >= DISH_GATE {
        return false;
    }
    tcp_unsent(probe).unwrap_or(0) > PIPE_PAUSE_BYTES
}

/// Sustained high watermark on send or receive, not one sample.
fn pipe_stuck(
    fd: std::os::unix::io::RawFd,
    high_since: &mut Option<std::time::Instant>,
    last_unsent: &mut usize,
    last_unread: &mut usize,
) -> Option<(&'static str, usize, usize)> {
    let unsent = tcp_unsent(fd).unwrap_or(0);
    let unread = tcp_unread(fd).unwrap_or(0);
    let moving = unsent < *last_unsent || unread < *last_unread;
    *last_unsent = unsent;
    *last_unread = unread;
    let which = if unsent > PIPE_SHED_BYTES {
        Some("send")
    } else if unread > PIPE_SHED_BYTES {
        Some("recv")
    } else {
        None
    };
    // A 1.3 MB body sits above the shed line while the peer reads it.
    // That is progress. Shed only when the queue stays high and stops moving.
    if which.is_none() || moving {
        *high_since = None;
        return None;
    }
    let since = high_since.get_or_insert_with(std::time::Instant::now);
    if since.elapsed() >= PIPE_SHED_HOLD {
        Some((which.unwrap(), unsent, unread))
    } else {
        None
    }
}

impl ByteTx {
    /// v2.10.3: queue all piece lines of one message or none of them.
    fn try_send_all(&self, lines: Vec<String>) -> bool {
        use std::sync::atomic::Ordering::Relaxed;
        let total: usize = lines.iter().map(|l| l.len()).sum();
        if self.used.load(Relaxed) + total > self.cap || self.tx.capacity() < lines.len() {
            return false;
        }
        for l in lines {
            if !self.try_send(l, ConsClass::Other) {
                warn!("piece stream cut short (queue raced full)");
                return false;
            }
        }
        true
    }

    /// Piece a large line when `pieces` is given, else send it as is.
    fn send_maybe_pieced(&self, line: String, pieces: Option<Vec<String>>) -> bool {
        match pieces {
            Some(ps) => self.try_send_all(ps),
            None => self.try_send(line, ConsClass::Other),
        }
    }
    fn try_send(&self, line: String, class: ConsClass) -> bool {
        use std::sync::atomic::Ordering::Relaxed;
        let n = line.len();
        let used = self.used.load(Relaxed);
        // Headers drop first when the pipe is 75% full so votes still form QC.
        if class == ConsClass::Header && used + n > self.cap.saturating_mul(3) / 4 {
            return false;
        }
        if used + n > self.cap {
            return false;
        }
        self.used.fetch_add(n, Relaxed);
        match self.tx.try_send(line) {
            Ok(()) => true,
            Err(_) => {
                self.used.fetch_sub(n, Relaxed);
                false
            }
        }
    }
}

/// Hub disaster-recovery: serve a join snap when the archive seat is down.
///
/// v2.9.53: this used to dump a fresh ~200 MB `/tmp/pl-hub-join-<id>-<tip>.json`
/// on **every** `NeedSnapshot` and never delete it — 173 GB on host2 filled
/// the disk and stalled the chain at 374384 (2026-10-07). Now, in order:
/// 1. reuse the periodic pinned `<snapshot-out>.join.serve.json` if fresh;
/// 2. reuse the current hub dump if fresh (or a joiner is mid-transfer);
/// 3. otherwise overwrite **one** bounded file `<data-dir>/<id>.hub-join.json`
///    (tmp+rename), only if the disk guard allows an optional dump.
/// The dump is deleted after `HUB_DUMP_IDLE_DELETE_MS` without a chunk.
/// v2.9.74: an active (bonded, unjailed) seat at tip serves its join pin like
/// a hub. Before, only v1 (archive) and v3 (hub) served, both behind one home
/// uplink; at ~30-140 KB/s a fresh install could not finish in 900 s while
/// the datacenter seats sat idle. Opt out with `FPL_SEAT_SERVE_SNAP=0`.
fn seat_serves_join_snap(shared: &Shared) -> bool {
    if shared.is_archive || shared.is_hub {
        return false;
    }
    if std::env::var("FPL_SEAT_SERVE_SNAP").is_ok_and(|v| v == "0") {
        return false;
    }
    let n = shared.node.lock();
    n.tip_height > 0
        && n.tip_lag() <= 8
        && n.validators.get(&n.id).is_some_and(|v| !v.jailed)
}

fn prepare_hub_join_snapshot(shared: &Shared, prev_chunk_ms: u64) -> Result<SnapMeta, String> {
    use fd_pl::disk::hub_snap_reusable;
    if !shared.is_hub && !seat_serves_join_snap(shared) {
        return Err("not hub".into());
    }
    let (tip, tip_hash, id) = {
        let n = shared.node.lock();
        if n.tip_height == 0 {
            return Err("no chain".into());
        }
        (n.tip_height, n.tip_hash.clone(), n.id.clone())
    };
    let now = unix_ms();
    // v2.9.70: an owned dump a joiner fetched in the last 60 s stays the
    // offer. Switching to the periodic pin here (step 1) left the old sha with
    // no file behind it: 208 "snap hash changed" per join on v3.
    {
        let busy = shared.hub_snap.lock().as_ref().and_then(|h| {
            let used = shared
                .served_shas
                .lock()
                .get(&h.meta.sha256)
                .is_some_and(|t| now.saturating_sub(*t) < 60_000);
            (h.owned && h.path.exists() && used).then(|| h.meta.clone())
        });
        if let Some(m) = busy {
            return Ok(m);
        }
    }
    // 1. Periodic pinned serve file (written every --snapshot-interval-ms anyway).
    if !shared.snapshot_out.as_os_str().is_empty() {
        let serve = snap_serve_path(&shared.snapshot_out);
        let pinned = shared.snap_meta.lock().clone();
        if let Some(m) = pinned {
            if serve.exists() && hub_snap_reusable(tip, m.tip, prev_chunk_ms, now) {
                // v2.9.67: point at the hashed copy when there is one, so
                // the bytes cannot change under this offer.
                let by_sha = snap_serve_sha_path(&shared.snapshot_out, &m.sha256);
                let serve = if by_sha.exists() { by_sha } else { serve };
                *shared.hub_snap.lock() = Some(HubSnap {
                    path: serve,
                    meta: m.clone(),
                    owned: false,
                });
                return Ok(m);
            }
        }
    }
    // 2. Current hub dump. v2.9.69: never rewrite it while a joiner fetched
    // a chunk of it in the last 60 s (that was "snap hash changed" on v3).
    let in_use = |sha: &str| {
        shared
            .served_shas
            .lock()
            .get(sha)
            .is_some_and(|t| now.saturating_sub(*t) < 60_000)
    };
    if let Some(h) = shared.hub_snap.lock().as_ref() {
        if h.owned
            && h.path.exists()
            && (in_use(&h.meta.sha256) || hub_snap_reusable(tip, h.meta.tip, prev_chunk_ms, now))
        {
            return Ok(h.meta.clone());
        }
    }
    // 3. One bounded dump in the data dir.
    let path = fd_pl::disk::hub_join_path(&shared.data_dir, &id);
    let guard = shared.disk_guard;
    let check = move |st: Option<&fd_pl::disk::DiskStat>, need: u64| match st {
        Some(s) => guard.check_optional(s, need),
        None => Ok(()),
    };
    let written = {
        let n = shared.node.lock();
        n.save_join_snapshot_checked(&path, &check)
    };
    if let Err(e) = written {
        let e = e.to_string();
        shared.note_disk_skip("hub join snapshot", &e);
        return Err(e);
    }
    let bytes = std::fs::read(&path).map_err(|e| e.to_string())?;
    let sha256 = fd_pl::crypto::sha256_hex(&bytes);
    let meta = SnapMeta {
        tip,
        tip_hash,
        sha256: sha256.clone(),
        bytes: bytes.len() as u64,
    };
    *shared.hub_snap.lock() = Some(HubSnap {
        path: path.clone(),
        meta: meta.clone(),
        owned: true,
    });
    info!(
        "snapshot hub serve tip={tip} bytes={} sha={} path={path:?}",
        bytes.len(),
        &sha256[..sha256.len().min(16)]
    );
    Ok(meta)
}

/// Startup disk hygiene (v2.9.53). Only touches files this seat owns.
fn startup_disk_cleanup(
    id: &str,
    data_dir: &std::path::Path,
    snapshot_out: &str,
    guard: &fd_pl::disk::DiskGuard,
) {
    let tmp = std::env::temp_dir();
    let (n, b) = fd_pl::disk::prune_legacy_hub_join(&tmp, id);
    if n > 0 {
        warn!(
            "disk cleanup: removed {n} legacy {tmp:?}/pl-hub-join-{id}-*.json ({} MB)",
            b / (1024 * 1024)
        );
    }
    let (n, b) =
        fd_pl::disk::prune_legacy_snap_pull(&tmp, std::time::Duration::from_secs(600));
    if n > 0 {
        warn!(
            "disk cleanup: removed {n} legacy {tmp:?}/pl-snap-pull-*.json ({} MB)",
            b / (1024 * 1024)
        );
    }
    // Bounded hub dump + leftover partial writes from a crash / ENOSPC.
    let hub = fd_pl::disk::hub_join_path(data_dir, id);
    let mut stale = vec![hub.clone(), hub.with_extension("json.tmp")];
    if !snapshot_out.is_empty() {
        let out = PathBuf::from(snapshot_out);
        stale.push(out.with_extension("json.tmp"));
        stale.push(snap_join_path(&out).with_extension("json.tmp"));
    }
    for p in stale {
        if let Ok(md) = std::fs::metadata(&p) {
            if md.is_file() && std::fs::remove_file(&p).is_ok() {
                info!("disk cleanup: removed stale {p:?} ({} MB)", md.len() / (1024 * 1024));
            }
        }
    }
    if !snapshot_out.is_empty() {
        let keep = std::env::var("FALCON_PL_SNAPSHOT_BAK_KEEP")
            .ok()
            .and_then(|v| v.trim().parse::<usize>().ok())
            .unwrap_or(3);
        for p in fd_pl::disk::prune_snapshot_baks(std::path::Path::new(snapshot_out), keep) {
            info!("disk cleanup: pruned old snapshot backup {p:?} (keep newest {keep})");
        }
    }
    match fd_pl::disk::stat(data_dir) {
        Some(s) => {
            let lvl = guard.level(&s);
            let msg = format!(
                "disk {:?}: {} MB free of {} MB ({:.1}%) level={} (warn<{}% low<{}%/{} MB)",
                s.path,
                s.avail_bytes / (1024 * 1024),
                s.total_bytes / (1024 * 1024),
                s.free_pct(),
                lvl.as_str(),
                guard.warn_pct,
                guard.min_free_pct,
                guard.min_free_bytes / (1024 * 1024)
            );
            match lvl {
                fd_pl::disk::DiskLevel::Ok => info!("{msg}"),
                _ => tracing::error!("{msg} — optional snapshot dumps will be skipped while low"),
            }
        }
        None => warn!("disk {data_dir:?}: statvfs failed (low-disk guard inactive)"),
    }
}

fn snap_serve_path(out: &std::path::Path) -> PathBuf {
    let stem = out.file_stem().unwrap_or_default().to_string_lossy();
    out.with_file_name(format!("{stem}.join.serve.json"))
}

/// Bytes for one offered sha. A newer pin must not replace this file.
fn snap_serve_sha_path(out: &std::path::Path, sha256: &str) -> PathBuf {
    let stem = out.file_stem().unwrap_or_default().to_string_lossy();
    out.with_file_name(format!("{stem}.join.serve.{sha256}.json"))
}

/// Write the hashed serve file (tmp + rename). `false` = not on disk, so
/// the caller must not offer this sha (v2.9.67: an offered sha with no file
/// was the "snap hash changed" loop once the pin rotated).
fn write_stable_serve(out: &std::path::Path, sha256: &str, bytes: &[u8]) -> bool {
    let path = snap_serve_sha_path(out, sha256);
    if std::fs::metadata(&path).map(|m| m.len() == bytes.len() as u64).unwrap_or(false) {
        return true;
    }
    let tmp = path.with_extension("json.tmp");
    let ok = std::fs::write(&tmp, bytes).is_ok() && std::fs::rename(&tmp, &path).is_ok();
    if !ok {
        let _ = std::fs::remove_file(&tmp);
    }
    ok
}

/// v2.9.67: rotate only when the old rule says so **and** the pin is at least
/// `SNAP_PIN_MIN_ROTATE_MS` old (no pin yet = rotate).
fn snap_pin_rotate_ok(shared: &Shared, live_tip: u64, pin_tip: u64, last_chunk_ms: u64, now: u64) -> bool {
    if pin_tip == 0 {
        return true;
    }
    let pinned = shared.snap_pin_ms.load(std::sync::atomic::Ordering::Relaxed);
    if pinned > 0 && now.saturating_sub(pinned) < SNAP_PIN_MIN_ROTATE_MS {
        return false;
    }
    fd_pl::Node::snap_pin_should_rotate(live_tip, pin_tip, last_chunk_ms, now)
}

/// v2.9.67: delete old hashed serve files; keep anything still being fetched.
fn prune_join_serve(shared: &Shared) {
    if shared.snapshot_out.as_os_str().is_empty() {
        return;
    }
    let now = unix_ms();
    let mut protect: Vec<String> = Vec::new();
    if let Some(m) = shared.snap_meta.lock().as_ref() {
        protect.push(m.sha256.clone());
    }
    if let Some(h) = shared.hub_snap.lock().as_ref() {
        protect.push(h.meta.sha256.clone());
    }
    {
        let mut served = shared.served_shas.lock();
        served.retain(|_, t| now.saturating_sub(*t) < JOIN_SERVE_MIN_AGE_MS);
        protect.extend(served.keys().cloned());
    }
    let (gone, bytes) = fd_pl::disk::prune_join_serve(
        &shared.snapshot_out,
        JOIN_SERVE_KEEP,
        std::time::Duration::from_millis(JOIN_SERVE_MIN_AGE_MS),
        &protect,
    );
    if !gone.is_empty() {
        info!(
            "join serve prune: removed {} old hashed serve file(s) ({} MB), keep newest {JOIN_SERVE_KEEP} + <30 min + in use",
            gone.len(),
            bytes / (1024 * 1024)
        );
    }
}

fn snap_join_path(out: &std::path::Path) -> PathBuf {
    let stem = out.file_stem().unwrap_or_default().to_string_lossy();
    out.with_file_name(format!("{stem}.join.json"))
}

fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn peek_snap_header(path: &std::path::Path) -> Option<(u64, String)> {
    use std::io::Read;
    let mut f = std::fs::File::open(path).ok()?;
    let mut buf = vec![0u8; 16_384];
    let n = f.read(&mut buf).ok()?;
    let s = String::from_utf8_lossy(&buf[..n]);
    let tip = s
        .split("\"tip_height\":")
        .nth(1)?
        .split([',', '}'])
        .next()?
        .trim()
        .parse::<u64>()
        .ok()?;
    let hash = s
        .split("\"tip_hash\":\"")
        .nth(1)?
        .split('"')
        .next()?
        .to_string();
    Some((tip, hash))
}

fn recved(used: &std::sync::atomic::AtomicUsize, n: usize) {
    use std::sync::atomic::Ordering::Relaxed;
    let _ = used.fetch_update(Relaxed, Relaxed, |u| Some(u.saturating_sub(n)));
}

/// Sign + locally record this seat's OK for `hash` at `height` (round-aware,
/// lock-checked). Returns the wire message and whether the vote was new.
/// `None` = this seat must not vote that hash now (already voted another hash
/// in this round / height, locked elsewhere, or not the staged body).
fn own_ok_msg(n: &mut Node, height: u64, hash: &str) -> Option<(WireMsg, bool)> {
    let (round, signature) = n.own_ok_vote(height, hash)?;
    let me = n.id.clone();
    let (_soft, _hard, fresh) = n.vote_ok_round_ex(hash, &me, &signature, round);
    Some((
        WireMsg::LedgerOk {
            height,
            ledger_hash: hash.to_string(),
            voter: me,
            signature,
            round,
        },
        fresh,
    ))
}

fn propose_header(led: &Ledger) -> WireMsg {
    WireMsg::ProposeHeader {
        header: led.header(),
        catchup: false,
    }
}

fn cons_class(m: &WireMsg) -> ConsClass {
    match m {
        // Recert assist is help for a cert-less peer, not a live proposal
        // vote. Keep it off ConsClass::Vote so it cannot starve ViewChange
        // on a busy cons pipe (827004 stall: fan of recert LedgerOk filled
        // the vote lane at queued_out > 1e6).
        WireMsg::LedgerOk { round, .. } if *round == Node::RECERT_ROUND => ConsClass::Other,
        WireMsg::LedgerOk { .. }
        | WireMsg::SkipPacker { .. }
        | WireMsg::ViewChange { .. }
        | WireMsg::Pong { .. }
        | WireMsg::OnlineSetVote { .. } => ConsClass::Vote,
        WireMsg::ProposeHeader { .. } => ConsClass::Header,
        _ => ConsClass::Other,
    }
}

/// Seat payout: submit `SetSeatPayout{id, want}` (seat key, `<id>#seat`
/// sender) when the seat is bonded, the rule is active, the node is caught up,
/// the on-chain payout differs and no seat tx of ours is already pending.
fn seat_payout_sync(shared: &Arc<Shared>, id: &str, want: &str) {
    let mut n = shared.node.lock();
    if n.still_lagging() || !n.seat_payout_at(n.tip_height.saturating_add(1)) {
        return;
    }
    let Some(v) = n.validators.get(id) else { return };
    if v.seat_payout.as_deref() == Some(want) {
        return;
    }
    let sender = fd_pl::seat_sender(id);
    if n.mempool.iter_candidates().any(|t| t.account == sender) {
        return;
    }
    let seq = n.state.get(&sender).sequence;
    let fee = n.current_min_fee();
    if v.seat_claimable < fee && n.state.get(&sender).balance < fee {
        warn!("seat payout: SetSeatPayout needs a {fee} FPL fee: seat bucket empty; fund account {sender} or wait for the next epoch settle");
        return;
    }
    let body = fd_pl::TxBody::SetSeatPayout {
        validator: id.to_string(),
        payout_account: Some(want.to_string()),
    };
    let tx = match fd_pl::Tx::sign_seat_body(&n.keys, id, seq, fee, n.cfg.network_id, body) {
        Ok(t) => t,
        Err(e) => {
            warn!("seat payout: cannot sign SetSeatPayout: {e}");
            return;
        }
    };
    let tx_id = tx.tx_id.clone();
    match n.submit_tx(tx) {
        Ok(_) => {
            drop(n);
            shared.remember_tx_relay(&tx_id);
            info!("seat payout: submitted SetSeatPayout {id} -> {want} ({tx_id})");
        }
        Err(e) => warn!("seat payout: SetSeatPayout {id} -> {want} refused: {e}"),
    }
}

#[derive(Parser, Debug)]
#[command(version = fd_pl::PRODUCT_VERSION)]
struct Args {
    #[arg(long)]
    id: String,
    #[arg(long, default_value = "0.0.0.0:19101")]
    listen: String,
    #[arg(long, default_value = "")]
    peers: String,
    #[arg(long, default_value = "hmac")]
    scheme: String,
    #[arg(long, default_value_t = 1000)]
    bond: u64,
    #[arg(long, default_value = "")]
    keys_dir: String,
    /// Optional hard cap (0 = unlimited — pack only limited by --pack-budget-ms).
    #[arg(long, default_value_t = 0)]
    max_txs: usize,
    /// Pack as many as possible within this many ms (the real limit).
    #[arg(long, default_value_t = 1000)]
    pack_budget_ms: u64,
    /// If #1 produces no tip advance within this many ms (mempool non-empty),
    /// skip them and let the next ranked ponger pack. 0 = disable.
    /// Default 2500 ≥ pack_budget + multi-host RTT (GROWTH_AND_MEMPOOL).
    #[arg(long, default_value_t = 2500)]
    progress_timeout_ms: u64,
    /// v2.9.59 packer pacing (local; 0 = off): the round-0 winner waits until
    /// this many ms after the height opened before sealing, unless the mempool
    /// already holds `--pace-mempool-txs` or a full block. Capped at one live
    /// pack window (pack budget + 2.3 s) so peers' round-0 silence timeout
    /// (2 windows) cannot fire because of it.
    #[arg(long, default_value_t = 2500)]
    min_block_interval_ms: u64,
    /// v2.9.59: pacing ends early once the local mempool holds this many txs.
    #[arg(long, default_value_t = 400)]
    pace_mempool_txs: usize,
    /// Max pending txs per node (reject new when full). 0 = unlimited.
    #[arg(long, default_value_t = 50_000)]
    max_mempool_txs: usize,
    #[arg(long, default_value_t = 300)]
    seal_interval_ms: u64,
    #[arg(long, value_delimiter = ',')]
    validators: Vec<String>,
    #[arg(long, default_value_t = false)]
    gen_keys_only: bool,
    #[arg(long, default_value_t = 32)]
    load_wallets: u32,
    /// Load JSON snapshot on start (keys still from --keys-dir).
    #[arg(long, default_value = "")]
    snapshot: String,
    /// Periodically save snapshot to this path (empty = disabled).
    #[arg(long, default_value = "")]
    snapshot_out: String,
    /// Snapshot save interval ms (default 60s).
    #[arg(long, default_value_t = 60_000)]
    snapshot_interval_ms: u64,
    /// Base min fee when mempool idle (escalates by util tier).
    #[arg(long, default_value_t = 1)]
    min_fee: u64,
    /// Enforce util-tier min fee on submit (AMD-20260811-1).
    #[arg(long, default_value_t = true)]
    fee_escalate: bool,
    /// Epoch length ms (default 7d). Private soak: e.g. 1000 or 60000.
    #[arg(long, default_value_t = 0)]
    epoch_ms: u64,
    /// First 1-based epoch that emits. Mainnet 8 (bootstrap 1–7). Testnet 1.
    #[arg(long, default_value_t = 8)]
    first_claim_epoch: u64,
    /// Unbond cooldown ms (0 = default 14d). Private: e.g. 5000 or 86400000.
    #[arg(long, default_value_t = 0)]
    unbond_cooldown_ms: u64,
    /// Network id (default 2200 private expansion).
    #[arg(long, default_value_t = NETWORK_ID_PRIVATE_V22)]
    network_id: u32,
    /// Max ledgers retained in memory. **0 is rejected** (clamped to 20000) — OOM risk.
    #[arg(long, default_value_t = 20_000)]
    max_chain_ledgers: usize,
    /// v2.10.0: first height with round-scoped OK votes (`pl-ok:v2`). 0 = off.
    /// PROTOCOL CHANGE — every committee seat must be upgraded with the same
    /// value before the chain reaches it. Env: FALCON_PL_VOTE_ROUNDS_FROM_HEIGHT.
    #[arg(long, default_value_t = 0)]
    vote_rounds_from_height: u64,
    /// v2.9.48: Phase 2 pause window `FROM..RESUME` (resume exclusive) inside
    /// round-scoped history — heights there use legacy `pl-ok:v1`. `off` = no
    /// window. Empty = env / bridge.json / network constant (2300 →
    /// 371037..375000). Env: FALCON_PL_VOTE_ROUNDS_PAUSE.
    #[arg(long, default_value = "")]
    vote_rounds_pause: String,
    /// Liveness watchdog: log an ERROR alert when txs/pending exist but the
    /// tip has not advanced for this many seconds (idle chain never alerts).
    /// 0 = off. Env: FALCON_PL_LIVENESS_ALERT_SECS.
    #[arg(long, default_value_t = 300)]
    liveness_alert_secs: u64,
    /// Persist every tx body to disk (`<snapshot-dir>/../bodies/<id>/`) so
    /// tip-0 joiners can `NeedLedgers from=1`. RAM still strips after 64.
    /// One archive hub per net is enough.
    #[arg(long, default_value_t = false)]
    archive: bool,
    /// Live join: do not register *this* id at process start with genesis bond.
    /// Self appears in the lottery only after a Bond ledger is applied (catch-up
    /// or live). Other `--validators` are still registered as the genesis set.
    /// See docs/LIVE_BOND_IN.md.
    #[arg(long, default_value_t = false)]
    join: bool,
    /// Mempool hub role: primary SubmitTx intake + serve NeedTxs (GROWTH_AND_MEMPOOL).
    #[arg(long, default_value_t = false)]
    hub: bool,
    /// Seat role: archive | hub | val. Empty = infer from argv0
    /// (`falcon-pl-val` / `falcon-pl-hub` / `falcon-pl-archive`).
    #[arg(long, default_value = "")]
    role: String,
    /// Preferred hub peers for NeedTxs / tx fanout (host:port,...). Empty = all peers.
    #[arg(long, default_value = "")]
    hubs: String,
    /// Heights per certified ONLINE epoch (v2.4.0). Packer seats = soft-QC'd online set.
    /// 0 = disable (legacy all-bonded seats). Default 25.
    #[arg(long, default_value_t = 25)]
    online_epoch_heights: u64,
    /// Unix domain socket for operator admin (Snapshot*, HardReset, Tick, SealNow, rails).
    /// Mode 0600, local only. Empty = disabled.
    #[arg(long, default_value = "")]
    admin_sock: String,
    /// Permit `--scheme hmac` (refused otherwise; checklist A8).
    #[arg(long, default_value_t = false)]
    allow_dev_crypto: bool,
    /// Reject admin WireMsgs on the TCP listen port (checklist A3). Implied by
    /// `--admin-sock` unless `--allow-admin-wire` is also set.
    #[arg(long, default_value_t = false)]
    lock_public_wire: bool,
    /// Keep admin WireMsgs on the TCP listen port (overrides lock / admin-sock).
    #[arg(long, default_value_t = false)]
    allow_admin_wire: bool,
    /// Seat payout: account credited with this seat's validator rewards at
    /// every epoch settle. From the seat-payout height the node submits a
    /// `SetSeatPayout` (signed with the seat key) whenever the on-chain value
    /// differs. Empty = leave on-chain as is. Env: FPL_PAYOUT_ADDRESS.
    #[arg(long, default_value = "")]
    payout_address: String,
}

/// Dual wire queues per peer: consensus vs mempool (M1).
struct PeerOut {
    cons: ByteTx,
    txq: ByteTx,
    /// Designated LedgerBody / NeedLedgerBody lane (v2.9.15).
    bodyq: ByteTx,
    /// NeedLedgers only (v2.9.16). Votes cannot evict a residual pull.
    catchq: ByteTx,
    /// Learned from Hello on this outbound session (empty until first Hello).
    peer_id: Arc<parking_lot::Mutex<String>>,
    /// One large body in flight on this socket.
    large_out: Arc<LargeGate>,
}

#[derive(Clone)]
struct SnapMeta {
    tip: u64,
    tip_hash: String,
    sha256: String,
    bytes: u64,
}

/// What a hub (non-archive) is serving to joiners right now (v2.9.53).
#[derive(Clone)]
struct HubSnap {
    path: PathBuf,
    meta: SnapMeta,
    /// `true` = our bounded `<id>.hub-join.json` dump (deleted when idle);
    /// `false` = the periodic `<snapshot-out>.join.serve.json` (never deleted here).
    owned: bool,
}



struct Shared {
    node: Mutex<Node>,
    /// Write sinks for *inbound* sessions (joiners that dialed us).
    inbound: Mutex<Vec<InboundSink>>,
    /// Indices into fanout that are hub peers (for NeedTxs / preferential tx fan).
    hub_peer_idxs: Vec<usize>,
    is_hub: bool,
    is_archive: bool,
    snapshot_out: PathBuf,
    snap_meta: Mutex<Option<SnapMeta>>,
    /// One publish of the served join file at a time. Two NeedSnapshot
    /// handlers were replacing the file while the other was still pushing it.
    snap_publish: Mutex<()>,
    /// Join snap a hub (not --archive) is serving for disaster recovery.
    hub_snap: Mutex<Option<HubSnap>>,
    /// Node data dir (parent of --snapshot-out): bounded dumps live here, not /tmp.
    data_dir: PathBuf,
    disk_guard: fd_pl::disk::DiskGuard,
    /// Optional dumps refused by the disk guard (status `disk.skipped_dumps`).
    disk_skips: std::sync::atomic::AtomicU64,
    disk_last_skip: Mutex<String>,
    snap_pull: Mutex<Option<SnapAssembler>>,
    /// Joiner (v2.9.74): aborted downloads kept by sha; a repeat offer resumes.
    snap_stash: Mutex<fd_pl::SnapStash>,
    /// Joiner (v2.9.74): each source is dropped as "too slow" at most once per join.
    snap_slow_judge: Mutex<fd_pl::SnapSlowJudge>,
    /// Unix-ms of last SnapshotChunk we served. Do not rotate the pinned
    /// serve file while a joiner is mid-transfer (2.9.22).
    last_snap_chunk_ms: std::sync::atomic::AtomicU64,
    /// Unix-ms the current join pin was published (v2.9.67 rotate cadence).
    snap_pin_ms: std::sync::atomic::AtomicU64,
    /// sha → unix-ms of the last chunk served for it (v2.9.67 retention).
    served_shas: Mutex<std::collections::HashMap<String, u64>>,
    /// Joiner: stalled/slow *archive/hub* sources → unix-ms until skipped (v2.9.68).
    /// Never cleared by the all-slow path (only expiry).
    slow_snap_src: Mutex<std::collections::HashMap<String, u64>>,
    /// Joiner: seats that answered SnapshotNo not-archive/not-hub (separate from stall).
    /// May be cleared when every archive/hub is stalled so other seats can be tried.
    snap_nonserve: Mutex<std::collections::HashMap<String, u64>>,
    /// Server: (requester, sha) → unix-ms of the last push (v2.9.69).
    /// Key uses session Hello id (not shared wire_from).
    snap_pushed: Mutex<std::collections::HashMap<String, u64>>,
    /// Joiner: NeedLedgers target rotation / backoff (v2.9.72).
    ledger_slow: Mutex<fd_pl::catchup_slow::LedgerSlowList>,
    /// `--join` and neither hub nor archive: the only role that marks
    /// NeedLedgers targets slow (seats never change catch-up routing).
    joiner: bool,
    /// Legacy shared last-peer tag (outbound only). Prefer `session_peer` args to
    /// `dispatch_wire` / `process_msg` — inbound must not race this mutex.
    wire_from: Arc<parking_lot::Mutex<String>>,
    /// Peer id or dial address → refuse new sessions until this instant.
    blackhole: Mutex<std::collections::HashMap<String, std::time::Instant>>,
    /// Live TCP sessions keyed by remote host:port.
    live_socks: Mutex<std::collections::HashMap<String, usize>>,
    /// SubmitTx ids whose relay was skipped because a peer queue was over
    /// the pause line. Sent again when the queue has room. Not consensus.
    tx_relay_wait: Mutex<std::collections::VecDeque<String>>,
    /// Ids already announced in a TxInv. Cleared once it grows past 20_000.
    tx_announced: Mutex<std::collections::HashSet<String>>,
    /// Dish seats still missing this height's walk. SubmitTx to them waits.
    dish_guard: Mutex<std::collections::HashSet<String>>,
    /// v2.10.3: peers whose last Hello said release >= 2.10.3 (accept `piece`).
    piece_peers: Mutex<std::collections::HashSet<String>>,
    /// Heights already printed on the round-gap trace.
    gap_hard: Mutex<u64>,
    gap_named: Mutex<u64>,
    gap_dish: Mutex<u64>,
    /// Open height and last hold printed for the walk-ready trace.
    gap_walk: Mutex<(u64, String)>,
}


/// Catch-up *control* (must land): Offer / SnapshotNo. Data may be paced.
fn is_snap_control(m: &WireMsg) -> bool {
    matches!(m, WireMsg::SnapshotOffer { .. } | WireMsg::SnapshotNo { .. })
}

#[allow(dead_code)]
fn is_snap_data(m: &WireMsg) -> bool {
    matches!(m, WireMsg::SnapshotChunk { .. })
}

/// Max wait for lane room for a snapshot control reply (Offer / SnapshotNo).
/// Bounded: the session read loop (votes included) waits behind it, so keep
/// it well under the 6.6 s round-0 silence timeout.
const SNAP_CONTROL_WAIT: std::time::Duration = std::time::Duration::from_secs(1);

/// Offer / SnapshotNo onto a catch-up lane, waiting (async, bounded) for room.
/// Data chunks are deferred under pressure, but a lost Offer leaves the joiner
/// without the sha/size it needs to resume, so control waits up to
/// [`SNAP_CONTROL_WAIT`] while the writer drains. Returns (sent, polls).
async fn reply_send_control_wait(
    tx: &mpsc::Sender<String>,
    line: String,
    pieces: Option<Vec<String>>,
) -> (bool, u32) {
    let start = tokio::time::Instant::now();
    let mut polls = 0u32;
    loop {
        if reply_send_pieced(tx, line.clone(), pieces.clone()) {
            return (true, polls);
        }
        if tx.is_closed() || start.elapsed() >= SNAP_CONTROL_WAIT {
            return (false, polls);
        }
        polls += 1;
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
}

static CATCH_DEFER_LAST_MS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static CATCH_DEFER_SUPPRESSED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static CATCH_DEFER_TOTAL: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// A catch-up data reply (SnapshotChunk / LedgersBatch) did not fit the lane.
/// Kept at WARN (rate-limited, with a running total) so operators still see
/// lane pressure; the joiner re-requests the chunk / range.
fn note_catch_defer(dir: &str, r: &WireMsg, peer: &str) {
    let total = CATCH_DEFER_TOTAL.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
    if let Some(sup) = should_log_reply_dropped(unix_ms(), &CATCH_DEFER_LAST_MS, &CATCH_DEFER_SUPPRESSED) {
        let kind = match r {
            WireMsg::SnapshotChunk { .. } => "SnapshotChunk",
            WireMsg::LedgersBatch { .. } => "LedgersBatch",
            _ => "other",
        };
        warn!("{dir} catch-up reply deferred (catch-up lane full) kind={kind} to={peer} total={total} (+{sup} suppressed)");
    }
}

/// Try-send catch-up control with short busy-wait retries (sync path / tests).
#[allow(dead_code)]
fn reply_send_control(tx: &mpsc::Sender<String>, line: String, pieces: Option<Vec<String>>) -> bool {
    for _ in 0..64 {
        if reply_send_pieced(tx, line.clone(), pieces.clone()) {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    false
}

/// v2.10.3: send pieces (all fit) or the legacy line on a plain reply channel.
fn reply_send_pieced(tx: &mpsc::Sender<String>, line: String, pieces: Option<Vec<String>>) -> bool {
    if let Some(ps) = pieces {
        if tx.capacity() >= ps.len() {
            for l in ps {
                if tx.try_send(l).is_err() {
                    warn!("piece reply stream cut short");
                    return false;
                }
            }
            return true;
        }
        // Not enough room for the whole run: the legacy line is still valid.
    }
    tx.try_send(line).is_ok()
}

static PIECE_PID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

/// Per-connection reassembly of `piece` lines. Returns the line to handle:
/// the original for normal lines, the joined line when a run completes,
/// `None` while a run is open (or broken).
fn unpiece_line(asm: &mut fd_pl::pieces::PieceAssembler, who: &str, line: String) -> Option<String> {
    if !line.starts_with("{\"type\":\"piece\"") {
        return Some(line);
    }
    match serde_json::from_str::<WireMsg>(&line) {
        Ok(WireMsg::Piece { pid, i, n, d }) => match asm.feed(unix_ms(), pid, i, n, &d) {
            Ok(done) => done,
            Err(e) => {
                warn!("{e} from {who} (pid {pid} {i}/{n})");
                None
            }
        },
        _ => None,
    }
}

impl Shared {
    /// v2.10.3: piece lines for `peer` if the line is large and the peer
    /// advertised piece support in its Hello; `None` = send legacy line.
    fn pieces_for(&self, peer: &str, line: &str) -> Option<Vec<String>> {
        if line.len() <= LARGE_LINE || peer.is_empty() || !self.piece_peers.lock().contains(peer) {
            return None;
        }
        let pid = PIECE_PID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        fd_pl::pieces::split_line(line, pid)
    }

    fn disk_stat(&self) -> Option<fd_pl::disk::DiskStat> {
        fd_pl::disk::stat(&self.data_dir)
    }

    /// Optional dump (join / serve copy): refused under the low-water mark.
    fn optional_ok(&self, need: u64) -> Result<(), String> {
        match self.disk_stat() {
            Some(s) => self.disk_guard.check_optional(&s, need),
            None => Ok(()),
        }
    }

    fn note_disk_skip(&self, what: &str, reason: &str) {
        self.disk_skips
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        *self.disk_last_skip.lock() = format!("{what}: {reason} (at_ms={})", unix_ms());
        warn!("DISK: skipped {what}: {reason}");
    }

    fn disk_status_json(&self) -> serde_json::Value {
        let st = self.disk_stat();
        let mut v = self.disk_guard.status_json(st.as_ref());
        if let Some(o) = v.as_object_mut() {
            o.insert(
                "skipped_dumps".into(),
                self.disk_skips
                    .load(std::sync::atomic::Ordering::Relaxed)
                    .into(),
            );
            o.insert("last_skip".into(), self.disk_last_skip.lock().clone().into());
            if let Some(h) = self.hub_snap.lock().as_ref() {
                o.insert(
                    "hub_snap".into(),
                    serde_json::json!({
                        "path": h.path.to_string_lossy(),
                        "tip": h.meta.tip,
                        "bytes": h.meta.bytes,
                        "owned": h.owned,
                    }),
                );
            }
        }
        v
    }

    /// Fan consensus line to all configured peers + inbound joiners.
    fn fan_line(&self, fanout: &Arc<Vec<PeerOut>>, line: String) {
        self.fan_line_class(fanout, line, ConsClass::Other);
    }

    /// Header for seats that did not get it on the body lane after the pre-dish.
    fn fan_line_except(&self, fanout: &Arc<Vec<PeerOut>>, line: String, skip: &[String]) {
        for p in fanout.iter() {
            let id = p.peer_id.lock().clone();
            if skip.iter().any(|s| s == &id) {
                continue;
            }
            let _ = p.cons.try_send(line.clone(), ConsClass::Other);
        }
        self.inbound.lock().retain(|s| {
            if skip.iter().any(|id| id == &s.id) {
                return true;
            }
            if s.close.load(std::sync::atomic::Ordering::Relaxed) {
                return false;
            }
            s.tx.try_send(line.clone(), ConsClass::Other)
        });
    }

    fn fan_line_class(&self, fanout: &Arc<Vec<PeerOut>>, line: String, class: ConsClass) {
        for p in fanout.iter() {
            let _ = p.cons.try_send(line.clone(), class);
        }
        self.inbound.lock().retain(|s| {
            if s.close.load(std::sync::atomic::Ordering::Relaxed) {
                return false;
            }
            if s.tx.try_send(line.clone(), class) {
                return true;
            }
            // A full sink is a wedged dial. Stop writing and let it close.
            if s.tx.used.load(std::sync::atomic::Ordering::Relaxed) > PIPE_SHED_BYTES {
                s.close.store(true, std::sync::atomic::Ordering::Relaxed);
            }
            false
        });
    }

    /// Consensus-pipe unicast to one seat: outbound `peer_id` match, else an
    /// inbound sink with that id. No live socket → skip (never mesh-fan).
    fn send_cons_seat(
        &self,
        fanout: Option<&Arc<Vec<PeerOut>>>,
        seat: &str,
        m: &WireMsg,
        class: ConsClass,
    ) -> bool {
        if seat.is_empty() {
            return false;
        }
        let Ok(s) = serde_json::to_string(m) else {
            return false;
        };
        let line = s + "\n";
        if let Some(fanout) = fanout {
            for p in fanout.iter() {
                let id = p.peer_id.lock().clone();
                if id != seat {
                    continue;
                }
                if p.cons.try_send(line.clone(), class) {
                    return true;
                }
                break;
            }
        }
        let mut hit = false;
        for s in self.inbound.lock().iter() {
            if s.id != seat || s.close.load(std::sync::atomic::Ordering::Relaxed) {
                continue;
            }
            if s.tx.try_send(line.clone(), class) {
                hit = true;
            }
        }
        hit
    }

    fn outbound_has_seat(fanout: &Arc<Vec<PeerOut>>, id: &str) -> bool {
        fanout.iter().any(|p| p.peer_id.lock().as_str() == id)
    }

    fn close_inbound_seat(&self, id: &str) {
        for s in self.inbound.lock().iter() {
            if s.id == id {
                s.close.store(true, std::sync::atomic::Ordering::Relaxed);
            }
        }
    }

    fn blackhole_peer(&self, key: &str) {
        if key.is_empty() {
            return;
        }
        self.blackhole.lock().insert(
            key.to_string(),
            std::time::Instant::now() + std::time::Duration::from_secs(BLACKHOLE_SECS),
        );
    }

    fn peer_blackholed(&self, key: &str) -> bool {
        if key.is_empty() {
            return false;
        }
        let mut map = self.blackhole.lock();
        let now = std::time::Instant::now();
        map.retain(|_, until| *until > now);
        map.get(key).is_some_and(|until| *until > now)
    }

    fn sock_add(&self, key: &str, delta: isize) {
        if key.is_empty() {
            return;
        }
        let mut map = self.live_socks.lock();
        let n = map.entry(key.to_string()).or_insert(0);
        if delta < 0 {
            *n = n.saturating_sub((-delta) as usize);
        } else {
            *n += delta as usize;
        }
        if *n == 0 {
            map.remove(key);
        }
    }

    fn sock_summary(&self) -> String {
        let map = self.live_socks.lock();
        let mut parts: Vec<_> = map.iter().map(|(k, n)| format!("{k}={n}")).collect();
        parts.sort();
        parts.join(",")
    }

    fn fan_msg(&self, fanout: &Arc<Vec<PeerOut>>, m: &WireMsg) {
        // Never mesh-fan full bodies (v2.8.0). Directed reply path only.
        if matches!(
            m,
            WireMsg::ProposeLedger { .. }
                | WireMsg::LedgerBody { .. }
                | WireMsg::LedgerBodyById { .. }
                | WireMsg::TxsByIds { .. }
                | WireMsg::LedgersBatch { .. }
                | WireMsg::SnapshotOffer { .. }
                | WireMsg::SnapshotChunk { .. }
                | WireMsg::SnapshotNo { .. }
        ) {
            return;
        }
        if matches!(
            m,
            WireMsg::NeedLedgers { .. }
                | WireMsg::NeedSnapshot { .. }
                | WireMsg::NeedSnapshotChunk { .. }
        ) {
            self.fan_catchup(fanout, m);
            return;
        }
        if let Ok(s) = serde_json::to_string(m) {
            self.fan_line_class(fanout, s + "\n", cons_class(m));
        }
    }

    /// NeedLedgers / NeedSnapshot on the catch-up lane. One peer at a time
    /// (v2.9.20); hub index rotates after a miss (AMD-20260827-1).
    /// Snapshot pulls prefer an advertised archive seat (v2.9.21).
    fn fan_catchup(&self, fanout: &Arc<Vec<PeerOut>>, m: &WireMsg) {
        let Ok(s) = serde_json::to_string(m) else {
            return;
        };
        let line = s + "\n";
        let snap = matches!(
            m,
            WireMsg::NeedSnapshot { .. } | WireMsg::NeedSnapshotChunk { .. }
        );
        if snap {
            // Never fall through to a non-archive hub. That was
            // `snapshot rejected: not archive` — v1's catchq was busy so
            // the fallback delivered NeedSnapshot to v2.
            let (archives, hubs) = {
                let n = self.node.lock();
                (n.archive_seats(), n.hub_snap_seats())
            };
            let ask_all = matches!(m, WireMsg::NeedSnapshot { .. });
            // v2.9.67: chunks go to the peer that made the offer. Through the
            // public seed every relay port looks untagged, so a chunk request
            // landed on another seat and came back "snap hash changed".
            if let WireMsg::NeedSnapshotChunk { sha256, .. } = m {
                let src = self
                    .snap_pull
                    .lock()
                    .as_ref()
                    .filter(|p| &p.sha256 == sha256)
                    .map(|p| p.source_peer.clone())
                    .unwrap_or_default();
                if !src.is_empty() {
                    // Live inbound session from the offering seat first. An
                    // outbound PeerOut keeps its Hello id after the dial rule
                    // refused / shed that socket, so try_send there could queue
                    // hole-fill requests into a dead session (5–13 s joins in
                    // the loopback rehearsal, nothing reached the archive).
                    for s in self.inbound.lock().iter() {
                        if s.id == src
                            && !s.close.load(std::sync::atomic::Ordering::Relaxed)
                            && s.tx.try_send(line.clone(), ConsClass::Other)
                        {
                            return;
                        }
                    }
                    for p in fanout.iter() {
                        if *p.peer_id.lock() == src && p.catchq.try_send(line.clone(), ConsClass::Other) {
                            return;
                        }
                    }
                }
            }
            // Stalled archives/hubs (slow_snap_src) and non-servers (snap_nonserve)
            // are separate. Computed before any send so the inbound-archive path
            // honours the cooldown too (an offer from a stalled source is
            // discarded by the joiner, so asking it only re-pushed chunks).
            let slow: Vec<String> = {
                let now = unix_ms();
                let mut stalled = self.slow_snap_src.lock();
                let mut nonserve = self.snap_nonserve.lock();
                let skip = fd_pl::snap_skip_ids(&mut stalled, &mut nonserve, now);
                let any_fast = archives
                    .iter()
                    .chain(hubs.iter())
                    .any(|id| !fd_pl::is_snap_skipped(&skip, id));
                if any_fast {
                    skip
                } else {
                    // Archives/hubs all stalled (or skipped). Try other seats;
                    // forget nonserve marks only so non-servers can be re-probed later.
                    let other = fanout.iter().find_map(|p| {
                        let id = p.peer_id.lock().clone();
                        let other = !id.is_empty()
                            && !fd_pl::is_snap_skipped(&skip, &id)
                            && !archives.contains(&id)
                            && !hubs.contains(&id);
                        other.then_some(id)
                    });
                    if other.is_some() && ask_all {
                        let skip2 = fd_pl::all_slow_forget_nonserve_only(&mut stalled, &mut nonserve, now);
                        drop(stalled);
                        drop(nonserve);
                        for p in fanout.iter() {
                            let id = p.peer_id.lock().clone();
                            if id.is_empty()
                                || fd_pl::is_snap_skipped(&skip2, &id)
                                || archives.contains(&id)
                                || hubs.contains(&id)
                            {
                                continue;
                            }
                            if p.catchq.try_send(line.clone(), ConsClass::Other) {
                                info!("NeedSnapshot → seat {id} (archives/hubs stalled; nonserve cleared)");
                                return;
                            }
                        }
                        return;
                    }
                    // No other seat: clear nonserve and cap each stalled mark to
                    // a short backoff. The stashed download resumes from the
                    // stalled source after SNAP_ALL_STALLED_RETRY_MS — not a
                    // 600 s freeze, not the old immediate clear() hot retry.
                    fd_pl::all_slow_cap_stalled(
                        &mut stalled,
                        &mut nonserve,
                        now,
                        fd_pl::SNAP_ALL_STALLED_RETRY_MS,
                    )
                }
            };
            let mut sent = false;
            // Higher-id seats never dial a lower-id archive (dial rule): the archive
            // session is inbound-only. NeedLedgers already prefers inbound archives;
            // NeedSnapshot must too or tip-0 joiners pull forever with no Offer.
            if !archives.is_empty() {
                let sinks: Vec<_> = self.inbound.lock().iter().cloned().collect();
                for s in &sinks {
                    if !archives.iter().any(|a| a == &s.id) || fd_pl::is_snap_skipped(&slow, &s.id) {
                        continue;
                    }
                    if s.close.load(std::sync::atomic::Ordering::Relaxed) {
                        continue;
                    }
                    if s.tx.try_send(line.clone(), ConsClass::Other) {
                        sent = true;
                        info!("NeedSnapshot → inbound archive {}", s.id);
                        if !ask_all {
                            return;
                        }
                    }
                }
            }
            if sent && !ask_all {
                return;
            }
            for p in fanout.iter() {
                let id = p.peer_id.lock().clone();
                if !archives.iter().any(|a| a == &id) || slow.contains(&id) {
                    continue;
                }
                if p.catchq.try_send(line.clone(), ConsClass::Other) {
                    sent = true;
                    if !ask_all {
                        return;
                    }
                }
            }
            if !sent {
                for p in fanout.iter() {
                    let id = p.peer_id.lock().clone();
                    if !hubs.iter().any(|h| h == &id) || slow.contains(&id) {
                        continue;
                    }
                    if p.catchq.try_send(line.clone(), ConsClass::Other) {
                        sent = true;
                        if !ask_all {
                            info!("NeedSnapshot → hub {id} (no archive seat)");
                            return;
                        }
                    }
                }
            }
            if !sent {
                // Lite joiners dial the public relay only. That peer is not
                // tagged archive or hub, so the request used to be dropped
                // and the seat sat on a stale tip. Ask every connected peer.
                for p in fanout.iter() {
                    if slow.contains(&*p.peer_id.lock()) {
                        continue;
                    }
                    if p.catchq.try_send(line.clone(), ConsClass::Other) {
                        sent = true;
                        if !ask_all {
                            info!("NeedSnapshot → seed (no archive or hub tag)");
                            return;
                        }
                    }
                }
                // And inbound sessions (higher-id joiner ↔ lower-id archive).
                let sinks: Vec<_> = self.inbound.lock().iter().cloned().collect();
                for s in &sinks {
                    if slow.contains(&s.id) {
                        continue;
                    }
                    if s.close.load(std::sync::atomic::Ordering::Relaxed) {
                        continue;
                    }
                    if s.tx.try_send(line.clone(), ConsClass::Other) {
                        sent = true;
                        info!("NeedSnapshot → inbound {}", s.id);
                        if !ask_all {
                            return;
                        }
                    }
                }
            }
            if !sent {
                warn!("catch-up NeedSnapshot dropped (no archive or hub catch lane)");
            }
            return;
        }
        // v2.9.49: hubs first, then any healthy non-jailed peer, never self.
        // Only-hubs left a lagging hub (v1: hubs = itself + v3) with a single
        // candidate; when that lane was busy every pull was dropped.
        let peers: Vec<(usize, String)> = fanout
            .iter()
            .enumerate()
            .map(|(i, p)| (i, p.peer_id.lock().clone()))
            .collect();
        let plan = self
            .node
            .lock()
            .catchup_candidates(&peers, &self.hub_peer_idxs);
        // v2.9.72: own slow list (not the snapshot one), per-peer backoff,
        // everyone retried after 30 s stuck. See fd_pl::catchup_slow.
        let (slow, route): (Vec<String>, Vec<usize>) = {
            let now = unix_ms();
            let tip = self.node.lock().tip_height;
            let mut l = self.ledger_slow.lock();
            if self.joiner {
                if let Some((id, skip)) = l.tick(now, tip, LEDGER_SLOW_MS) {
                    info!("catch-up: {id} gave no ledgers in {}s — skip it for {}s", LEDGER_SLOW_MS / 1000, skip / 1000);
                }
            }
            let mut cands: Vec<String> = plan
                .order
                .iter()
                .filter_map(|&i| peers.get(i).map(|(_, id)| fd_pl::catchup_slow::target_key(id, i)))
                .collect();
            // v2.9.75 (joiner): the peer that served the last advancing batch
            // first, repeat-slow peers (v1/v3 on the shared uplink) last.
            let route: Vec<usize> = if self.joiner {
                let n = plan.order.len().min(cands.len());
                let mut r = l.route(&cands[..n], now);
                r.extend(n..plan.order.len());
                r
            } else {
                (0..plan.order.len()).collect()
            };
            cands.extend(self.inbound.lock().iter().map(|s| s.id.clone()));
            (l.skip_set(&cands, now), route)
        };
        let note = |id: &str| {
            let tip = self.node.lock().tip_height;
            self.ledger_slow.lock().note_sent(id, unix_ms(), tip);
        };
        // v11 dials v3 (higher id) and never dials v1, so the archive is
        // inbound only. The outbound hub accepts NeedLedgers and answers
        // empty once the height has left its RAM window. Ask the archive
        // first.
        {
            let archives = self.node.lock().archive_seats();
            if !archives.is_empty() {
                let sinks: Vec<_> = self.inbound.lock().iter().cloned().collect();
                for s in &sinks {
                    if !archives.iter().any(|a| a == &s.id) || slow.contains(&s.id) {
                        continue;
                    }
                    if s.close.load(std::sync::atomic::Ordering::Relaxed) {
                        continue;
                    }
                    if s.tx.try_send(line.clone(), ConsClass::Other) {
                        note(&s.id);
                        info!("NeedLedgers → archive {}", s.id);
                        return;
                    }
                }
            }
        }
        let mut full = 0usize;
        for k in route.iter().copied() {
            let i = plan.order[k];
            let Some(p) = fanout.get(i) else {
                continue;
            };
            // v2.9.73: an untagged lane (seed relay port, no Hello id yet) is
            // keyed lane#<idx> so it can be timed out and skipped too.
            let pid = fd_pl::catchup_slow::target_key(
                peers.get(i).map(|(_, id)| id.as_str()).unwrap_or(""),
                i,
            );
            if slow.contains(&pid) {
                continue;
            }
            if p.catchq.try_send(line.clone(), ConsClass::Other) {
                note(&pid);
                if k >= plan.hub_count {
                    let id = peers.get(i).map(|(_, id)| id.as_str()).unwrap_or("");
                    debug!("NeedLedgers → non-hub peer idx={i} id={id} (hubs full/behind)");
                }
                return;
            }
            full += 1;
        }
        // The seats ahead of us may be lites that dial in and are not in
        // --peers. Asking only the outbound list dropped every pull
        // (candidates=0) while those lites were 4 blocks ahead.
        {
            let ahead: Vec<String> = {
                let n = self.node.lock();
                let tip = n.tip_height;
                n.validators
                    .iter()
                    .filter(|(_, v)| {
                        v.last_advertised_tip.unwrap_or(0) > tip
                            && v.pong_fresh(n.now_ms, n.cfg.pong_window_ms)
                    })
                    .map(|(id, _)| id.clone())
                    .collect()
            };
            if !ahead.is_empty() {
                let (archives, hubs) = {
                    let n = self.node.lock();
                    (n.archive_seats(), n.hub_snap_seats())
                };
                let mut sinks: Vec<_> = self.inbound.lock().iter().cloned().collect();
                sinks.sort_by_key(|s| {
                    if archives.iter().any(|a| a == &s.id) {
                        0
                    } else if hubs.iter().any(|h| h == &s.id) {
                        1
                    } else {
                        2
                    }
                });
                for s in &sinks {
                    if !ahead.iter().any(|id| id == &s.id) {
                        continue;
                    }
                    if s.close.load(std::sync::atomic::Ordering::Relaxed) {
                        continue;
                    }
                    if slow.contains(&s.id) {
                        continue;
                    }
                    if s.tx.try_send(line.clone(), ConsClass::Other) {
                        note(&s.id);
                        info!("NeedLedgers → inbound {}", s.id);
                        return;
                    }
                }
            }
        }
        // Rate-limited: this fired ~1/s per Pong on v1 and buried the journal.
        static LAST_WARN_MS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        static SUPPRESSED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let now = unix_ms();
        let last = LAST_WARN_MS.load(std::sync::atomic::Ordering::Relaxed);
        if now.saturating_sub(last) >= 10_000 {
            LAST_WARN_MS.store(now, std::sync::atomic::Ordering::Relaxed);
            let sup = SUPPRESSED.swap(0, std::sync::atomic::Ordering::Relaxed);
            warn!(
                "catch-up NeedLedgers dropped: candidates={} lanes_full={full} behind={} jailed={} self={} (suppressed {sup} in last 10s)",
                plan.order.len(),
                plan.skipped_behind,
                plan.skipped_jailed,
                plan.skipped_self
            );
        } else {
            SUPPRESSED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }

    /// Fan SubmitTx on the **tx queue only**. Never spill into consensus queues.
    ///
    /// A hub relays a locally accepted tx once so every packer shares the pool.
    /// It does not relay a tx that arrived from a peer, or the mesh echoes it.
    /// The send is skipped when that peer's tx queue is already above the relay
    /// budget, or when the queue refuses the line. A refused line is remembered
    /// and tried again, so a later sequence cannot land while the earlier one
    /// was dropped. Light validators still fan toward hubs.
    fn fan_tx(&self, fanout: &Arc<Vec<PeerOut>>, m: &WireMsg, relay_state: bool) {
        if let WireMsg::SubmitTx { tx } = m {
            if self.earlier_seq_waiting(&tx.account, tx.sequence) {
                self.remember_tx_relay(&tx.tx_id);
                return;
            }
        }
        let held = self.fan_tx_once(fanout, m, relay_state);
        if held {
            if let WireMsg::SubmitTx { tx } = m {
                self.remember_tx_relay(&tx.tx_id);
            }
        }
    }

    /// An earlier sequence for this account is still on the retry list.
    /// Sending this one now is how a later sequence lands and the head does not.
    fn earlier_seq_waiting(&self, account: &str, sequence: u64) -> bool {
        let ids: Vec<String> = self.tx_relay_wait.lock().iter().cloned().collect();
        if ids.is_empty() {
            return false;
        }
        let n = self.node.lock();
        ids.iter().any(|id| {
            n.mempool
                .get(id)
                .is_some_and(|t| t.account == account && t.sequence < sequence)
        })
    }

    /// `true` when at least one peer was skipped. The caller keeps the tx id
    /// and tries again. A full channel slot (512) is a skip even when the
    /// byte counter is still under the 2 MB relay budget. Ignoring that
    /// failure dropped the earlier sequence and let a later one through.
    fn fan_tx_once(&self, fanout: &Arc<Vec<PeerOut>>, m: &WireMsg, relay_state: bool) -> bool {
        let Ok(s) = serde_json::to_string(m) else {
            return false;
        };
        let line = s + "\n";
        let mut held = false;
        let enqueue = |held: &mut bool, q: &ByteTx, line: &str| {
            if q.used.load(std::sync::atomic::Ordering::Relaxed) > TX_RELAY_BUDGET
                || !q.try_send(line.to_string(), ConsClass::Other)
            {
                *held = true;
            }
        };
        if self.is_hub {
            if !relay_state {
                return false;
            }
            let guard = self.dish_guard.lock().clone();
            for p in fanout.iter() {
                let id = p.peer_id.lock().clone();
                if guard.contains(&id) {
                    held = true;
                    continue;
                }
                enqueue(&mut held, &p.txq, &line);
            }
            self.inbound.lock().retain(|sink| {
                if sink.close.load(std::sync::atomic::Ordering::Relaxed) {
                    return false;
                }
                if guard.contains(&sink.id) {
                    held = true;
                    return true;
                }
                enqueue(&mut held, &sink.tx, &line);
                true
            });
            return held;
        }
        if self.hub_peer_idxs.is_empty() {
            for p in fanout.iter() {
                enqueue(&mut held, &p.txq, &line);
            }
        } else {
            for &i in &self.hub_peer_idxs {
                if let Some(p) = fanout.get(i) {
                    enqueue(&mut held, &p.txq, &line);
                }
            }
        }
        held
    }

    /// A line already taken off the send queue was not written. Put the
    /// transaction back on the retry list. The old `continue` dropped it,
    /// so the next sequence could arrive and the earlier one never did.
    fn hold_unsent_tx_line(&self, line: &str) {
        let Ok(msg) = serde_json::from_str::<WireMsg>(line.trim()) else {
            return;
        };
        match msg {
            WireMsg::SubmitTx { tx } => self.remember_tx_relay(&tx.tx_id),
            WireMsg::TxInv { ids } => {
                let mut announced = self.tx_announced.lock();
                for id in ids {
                    announced.remove(&id);
                }
            }
            _ => {}
        }
    }

    fn remember_tx_relay(&self, tx_id: &str) {
        const CAP: usize = 8192;
        let mut q = self.tx_relay_wait.lock();
        if q.iter().any(|id| id == tx_id) {
            return;
        }
        if q.len() >= CAP {
            // Keep the earlier sequences. Dropping the front dropped the head.
            q.pop_back();
        }
        q.push_back(tx_id.to_string());
    }

    /// One layer of every account, then the next layer, up to one block.
    /// A tick of 64 left the winner two or three deep. Fewer than 400
    /// walkable transactions send as they are. A later sequence with a gap
    /// is not part of the walk.
    fn flush_tx_relay(&self, fanout: &Arc<Vec<PeerOut>>) {
        let ids: Vec<String> = self.tx_relay_wait.lock().iter().cloned().collect();
        if ids.is_empty() {
            return;
        }
        let mut send: Vec<String> = Vec::new();
        let mut missing: Vec<String> = Vec::new();
        {
            let n = self.node.lock();
            let mut by: std::collections::HashMap<String, Vec<(u64, String)>> =
                std::collections::HashMap::new();
            for id in &ids {
                let Some(tx) = n.mempool.get(id) else {
                    missing.push(id.clone());
                    continue;
                };
                by.entry(tx.account.clone())
                    .or_default()
                    .push((tx.sequence, id.clone()));
            }
            let mut runs: Vec<Vec<String>> = Vec::new();
            for (account, mut seqs) in by {
                seqs.sort_by_key(|(seq, _)| *seq);
                let mut expect = n.state.get(&account).sequence;
                let mut run = Vec::new();
                for (seq, id) in seqs {
                    if seq < expect {
                        continue;
                    }
                    if seq != expect {
                        break;
                    }
                    run.push(id);
                    expect = expect.saturating_add(1);
                }
                if !run.is_empty() {
                    runs.push(run);
                }
            }
            let mut depth = 0usize;
            while send.len() < 400 {
                let mut progressed = false;
                for run in &runs {
                    if let Some(id) = run.get(depth) {
                        send.push(id.clone());
                        progressed = true;
                        if send.len() == 400 {
                            break;
                        }
                    }
                }
                if !progressed {
                    break;
                }
                depth += 1;
            }
        }
        if !missing.is_empty() {
            let mut q = self.tx_relay_wait.lock();
            q.retain(|id| !missing.iter().any(|m| m == id));
        }
        for id in send {
            let tx = {
                let n = self.node.lock();
                n.mempool.get(&id).cloned()
            };
            let Some(tx) = tx else {
                continue;
            };
            let msg = WireMsg::SubmitTx { tx };
            if self.fan_tx_once(fanout, &msg, true) {
                return;
            }
            let mut q = self.tx_relay_wait.lock();
            q.retain(|queued| queued != &id);
        }
    }

    /// Announce the same walk, up to one block. A peer that is missing one
    /// answers with NeedMempoolTxs on the same connection. The full
    /// transaction is not pushed with the announcement.
    fn announce_tx_inv(&self, fanout: &Arc<Vec<PeerOut>>) {
        let ids = {
            let n = self.node.lock();
            let announced = self.tx_announced.lock();
            let mut by: std::collections::HashMap<String, Vec<(u64, String)>> =
                std::collections::HashMap::new();
            for tx in n.mempool.iter_candidates() {
                by.entry(tx.account.clone())
                    .or_default()
                    .push((tx.sequence, tx.tx_id.clone()));
            }
            let mut runs: Vec<Vec<String>> = Vec::new();
            for (account, mut seqs) in by {
                seqs.sort_by_key(|(seq, _)| *seq);
                let mut expect = n.state.get(&account).sequence;
                let mut run = Vec::new();
                for (seq, id) in seqs {
                    if seq < expect {
                        continue;
                    }
                    if seq != expect {
                        break;
                    }
                    if !announced.contains(&id) {
                        run.push(id);
                    }
                    expect = expect.saturating_add(1);
                }
                if !run.is_empty() {
                    runs.push(run);
                }
            }
            let mut ids = Vec::new();
            let mut depth = 0usize;
            while ids.len() < 400 {
                let mut progressed = false;
                for run in &runs {
                    if let Some(id) = run.get(depth) {
                        ids.push(id.clone());
                        progressed = true;
                        if ids.len() == 400 {
                            break;
                        }
                    }
                }
                if !progressed {
                    break;
                }
                depth += 1;
            }
            ids
        };
        if ids.is_empty() {
            return;
        }
        let msg = WireMsg::TxInv { ids: ids.clone() };
        if self.fan_tx_once(fanout, &msg, true) {
            return;
        }
        let mut announced = self.tx_announced.lock();
        for id in ids {
            announced.insert(id);
        }
        if announced.len() > 20_000 {
            announced.clear();
        }
    }

    /// TxsBatch to every peer on the **tx** plane (packer feed). Not hub-only:
    /// the lottery winner is often a light val. Drops at 75% so LedgerBody
    /// still fits (v2.9.13).
    fn fan_tx_batch(&self, fanout: &Arc<Vec<PeerOut>>, m: &WireMsg) {
        let Ok(s) = serde_json::to_string(m) else {
            return;
        };
        let line = s + "\n";
        for p in fanout.iter() {
            if p.txq.used.load(std::sync::atomic::Ordering::Relaxed) > PIPE_PAUSE_BYTES {
                continue;
            }
            let _ = p.txq.try_send(line.clone(), ConsClass::Header);
        }
    }

    /// Pieces under the 64 KB large-line cap. A 20-transaction body was about
    /// 107 KB, so the second piece always paused as "one already in flight".
    /// Stay near 48 KB so several pieces can be queued in one round.
    fn dish_pieces(batch: &[fd_pl::Tx]) -> Vec<Vec<fd_pl::Tx>> {
        const TARGET: usize = 48 * 1024;
        let mut pieces = Vec::new();
        let mut cur: Vec<fd_pl::Tx> = Vec::new();
        for tx in batch {
            cur.push(tx.clone());
            let msg = WireMsg::TxsBatch { txs: cur.clone() };
            let n = serde_json::to_string(&msg).map(|s| s.len()).unwrap_or(0);
            if n <= TARGET {
                continue;
            }
            if cur.len() == 1 {
                pieces.push(std::mem::take(&mut cur));
                continue;
            }
            let last = cur.pop().unwrap();
            pieces.push(std::mem::take(&mut cur));
            cur.push(last);
        }
        if !cur.is_empty() {
            pieces.push(cur);
        }
        pieces
    }

    /// One seat's missing suffix. Returns the tx ids that were queued.
    /// A refused chunk stops the seat so the rest stays a suffix.
    fn fan_seat_suffix(
        &self,
        fanout: &Arc<Vec<PeerOut>>,
        seat: &str,
        batch: &[fd_pl::Tx],
    ) -> Vec<String> {
        if seat.is_empty() || batch.is_empty() {
            return Vec::new();
        }
        let mut queued = Vec::new();
        for chunk in Self::dish_pieces(batch) {
            let msg = WireMsg::TxsBatch { txs: chunk.clone() };
            let one = [seat.to_string()];
            if !self.fan_tx_dish(fanout, &msg, &one) {
                break;
            }
            queued.extend(chunk.iter().map(|tx| tx.tx_id.clone()));
        }
        queued
    }

    fn note_hard_qc(&self, h: u64) {
        if h == 0 {
            return;
        }
        let mut seen = self.gap_hard.lock();
        if *seen >= h {
            return;
        }
        *seen = h;
        info!("round-gap hard-qc h={h}");
    }

    fn note_walk_ready(&self, h: u64, packable: usize, hold: &str) {
        let mut seen = self.gap_walk.lock();
        if seen.0 == h && seen.1 == hold {
            return;
        }
        *seen = (h, hold.to_string());
        info!("round-gap walk-ready h={h} packable={packable} hold={hold}");
    }

    fn note_packer_known(&self, n: &fd_pl::Node) {
        let h = n.tip_height.saturating_add(1);
        let mut seen = self.gap_named.lock();
        if *seen >= h {
            return;
        }
        *seen = h;
        let winner = n.lottery_packer().unwrap_or_else(|| "-".into());
        info!(
            "round-gap packer-known h={h} winner={winner} parent={}",
            n.tip_height
        );
    }

    fn refresh_dish_guard(&self) {
        let seats = {
            let mut n = self.node.lock();
            n.dish_priority_seats()
        };
        *self.dish_guard.lock() = seats.into_iter().collect();
    }

    /// One-ledger dish to winner + first backup (v2.9.14). Yields at 75% so
    /// it cannot fill the inventory pipe (body lives on its own lane).
    /// One shot at the known winner sockets. No spray onto peers that have
    /// not said Hello yet — that filled every unidentified pipe.
    fn fan_tx_dish(&self, fanout: &Arc<Vec<PeerOut>>, m: &WireMsg, seats: &[String]) -> bool {
        if seats.is_empty() {
            return false;
        }
        let Ok(s) = serde_json::to_string(m) else {
            return false;
        };
        let line = s + "\n";
        let large = line.len() > LARGE_LINE;
        let mut sent = false;
        for seat in seats {
            let mut hit = false;
            for p in fanout.iter() {
                let id = p.peer_id.lock().clone();
                if &id != seat {
                    continue;
                }
                let pieces = self.pieces_for(&id, &line);
                let large = large && pieces.is_none();
                if !self.lane_accepts_large(p, large, &id) {
                    break;
                }
                if p.txq.send_maybe_pieced(line.clone(), pieces) {
                    sent = true;
                    hit = true;
                } else if large {
                    p.large_out.clear();
                    warn!("tx dish dropped for peer {id} bytes={}", line.len());
                }
                break;
            }
            if !hit && self.send_inbound_seats(std::slice::from_ref(seat), &line) {
                sent = true;
            }
        }
        sent
    }

    fn lane_accepts_large(&self, p: &PeerOut, large: bool, id: &str) -> bool {
        if !large {
            return true;
        }
        let cons = p.cons.used.load(std::sync::atomic::Ordering::Relaxed);
        let txu = p.txq.used.load(std::sync::atomic::Ordering::Relaxed);
        if cons > PIPE_PAUSE_BYTES || txu > PIPE_SHED_BYTES {
            warn!("pause large dish to {id} cons={cons} txq={txu}");
            return false;
        }
        if !p.large_out.try_acquire(id)
        {
            warn!("pause large dish to {id}: one already in flight");
            return false;
        }
        true
    }

    fn clear_large_out(fanout: &Arc<Vec<PeerOut>>, id: &str) {
        for p in fanout.iter() {
            if p.peer_id.lock().as_str() == id {
                p.large_out.clear();
            }
        }
    }

    /// A higher seat does not dial us. Its socket is the inbound dial we accepted.
    /// Skip a large line when that socket is already holding bytes.
    fn send_inbound_seats(&self, seats: &[String], line: &str) -> bool {
        if seats.is_empty() {
            return false;
        }
        let large = line.len() > LARGE_LINE;
        let mut hit = 0usize;
        for s in self.inbound.lock().iter() {
            if !seats.iter().any(|id| id == &s.id) {
                continue;
            }
            if s.close.load(std::sync::atomic::Ordering::Relaxed) {
                continue;
            }
            let pieces = self.pieces_for(&s.id, line);
            let large = large && pieces.is_none();
            if large {
                let used = s.tx.used.load(std::sync::atomic::Ordering::Relaxed);
                if used > PIPE_PAUSE_BYTES {
                    warn!("pause large send to inbound {} bytes={}", s.id, line.len());
                    return false;
                }
                if !s.large_out.try_acquire(&s.id)
                {
                    warn!("pause large send to inbound {}: one already in flight", s.id);
                    return false;
                }
            }
            if s.tx.send_maybe_pieced(line.to_string(), pieces) {
                hit += 1;
            } else if large {
                s.large_out.clear();
            }
        }
        hit > 0
    }

    /// NeedLedgerBody on the catch-up lane to an archive seat, then a hub.
    /// The tx lane is the one the flood fills. A small pull there never
    /// arrives in time to stop the view-change.
    fn fan_body_pull(&self, fanout: &Arc<Vec<PeerOut>>, m: &WireMsg) {
        let Ok(s) = serde_json::to_string(m) else {
            return;
        };
        let line = s + "\n";
        let (archives, hubs) = {
            let n = self.node.lock();
            (n.archive_seats(), n.hub_snap_seats())
        };
        for p in fanout.iter() {
            let id = p.peer_id.lock().clone();
            if archives.iter().any(|a| a == &id) && p.catchq.try_send(line.clone(), ConsClass::Other) {
                return;
            }
        }
        for p in fanout.iter() {
            let id = p.peer_id.lock().clone();
            if hubs.iter().any(|h| h == &id) && p.catchq.try_send(line.clone(), ConsClass::Other) {
                return;
            }
        }
        let ask: Vec<String> = if !archives.is_empty() {
            archives
        } else {
            hubs
        };
        let _ = self.send_inbound_seats(&ask, &line);
    }

    /// The exact set, then the id-only body, then the header, on the body lane.
    /// The consensus lane is written first, so a header sent there jumps ahead
    /// of the transactions and the seat misses every id.
    fn fan_pre_dish(
        &self,
        fanout: &Arc<Vec<PeerOut>>,
        seats: &[String],
        txs: &[fd_pl::Tx],
        by_id: &WireMsg,
        header: &WireMsg,
    ) {
        // v2.10.3: split the dish into <=48 KB TxsBatch pieces (a 1.3 MB single
        // line sat in one slow WAN socket and held the large-send gate).
        let mut dish_lines = Vec::new();
        let mut dish_bytes = 0usize;
        for piece in Self::dish_pieces(txs) {
            let Ok(d) = serde_json::to_string(&WireMsg::TxsBatch { txs: piece }) else {
                return;
            };
            dish_bytes += d.len();
            dish_lines.push(d + "\n");
        }
        let Ok(body) = serde_json::to_string(by_id) else {
            return;
        };
        let Ok(head) = serde_json::to_string(header) else {
            return;
        };
        info!(
            "pre-dish bytes={dish_bytes} n={} pieces={}",
            txs.len(),
            dish_lines.len()
        );
        let mut lines = dish_lines;
        lines.push(body + "\n");
        lines.push(head + "\n");
        let mut hit = 0usize;
        for p in fanout.iter() {
            let id = p.peer_id.lock().clone();
            if seats.iter().any(|s| s == &id) {
                for line in &lines {
                    let _ = p.bodyq.try_send(line.clone(), ConsClass::Other);
                }
                hit += 1;
            }
        }
        if hit < seats.len() {
            for line in &lines {
                let _ = self.send_inbound_seats(seats, line);
            }
        }
    }

    /// Id body and header only. The 1.33 MB dish is sent once, at pack time.
    /// Skip a peer whose body queue is already above the pause line.
    fn fan_id_followup(
        &self,
        fanout: &Arc<Vec<PeerOut>>,
        seats: &[String],
        by_id: &WireMsg,
        header: &WireMsg,
    ) {
        let Ok(body) = serde_json::to_string(by_id) else {
            return;
        };
        let Ok(head) = serde_json::to_string(header) else {
            return;
        };
        let lines = [body + "\n", head + "\n"];
        let mut hit = 0usize;
        for p in fanout.iter() {
            let id = p.peer_id.lock().clone();
            if !seats.iter().any(|s| s == &id) {
                continue;
            }
            if p.bodyq.used.load(std::sync::atomic::Ordering::Relaxed) > PIPE_PAUSE_BYTES {
                info!("id-follow skip seat={id} queued high");
                hit += 1;
                continue;
            }
            for line in &lines {
                let _ = p.bodyq.try_send(line.clone(), ConsClass::Other);
            }
            hit += 1;
        }
        if hit < seats.len() {
            for line in &lines {
                let _ = self.send_inbound_seats(seats, line);
            }
        }
    }

    /// LedgerBody to the QC committee on the **body** lane (v2.9.15).
    /// Not full-mesh. Inventory cannot evict these.
    fn fan_ledger_body(&self, fanout: &Arc<Vec<PeerOut>>, m: &WireMsg, seats: &[String]) {
        let Ok(s) = serde_json::to_string(m) else {
            return;
        };
        let line = s + "\n";
        let mut hit = 0usize;
        for p in fanout.iter() {
            let id = p.peer_id.lock().clone();
            if seats.iter().any(|s| s == &id) {
                let _ = p.bodyq.try_send(line.clone(), ConsClass::Other);
                hit += 1;
            }
        }
        if hit < seats.len() {
            let _ = self.send_inbound_seats(seats, &line);
        }
    }

    /// Directed NeedTxs to hub peers (or all if none tagged).
    fn fan_need_txs(&self, fanout: &Arc<Vec<PeerOut>>, m: &WireMsg) {
        let Ok(s) = serde_json::to_string(m) else {
            return;
        };
        let line = s + "\n";
        if self.hub_peer_idxs.is_empty() {
            let hubs: Vec<String> = {
                let n = self.node.lock();
                n.validators
                    .iter()
                    .filter(|(_, v)| v.advertised_hub)
                    .map(|(id, _)| id.clone())
                    .collect()
            };
            if !self.send_inbound_seats(&hubs, &line) {
                for p in fanout.iter() {
                    let _ = p.txq.try_send(line.clone(), ConsClass::Other);
                }
            }
        } else {
            for &i in &self.hub_peer_idxs {
                if let Some(p) = fanout.get(i) {
                    let _ = p.txq.try_send(line.clone(), ConsClass::Other);
                }
            }
        }
    }
}

/// Wallet history: entries returned, archive heights scanned, time budget.
const ACCOUNT_HISTORY_LIMIT: usize = 8;
const ACCOUNT_HISTORY_DISK_HEIGHTS: u64 = 20_000;
const ACCOUNT_HISTORY_DISK_MS: u64 = 300;

#[tokio::main]
async fn main() -> Result<()> {
    {
        // Same fmt output as before, plus WARN/ERROR copied into the health
        // ring (`falcon.health.v1` `warnings`).
        use tracing_subscriber::prelude::*;
        fd_pl::health::mark_start();
        tracing_subscriber::registry()
            .with(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| "info".into()),
            )
            .with(tracing_subscriber::fmt::layer())
            .with(fd_pl::health::WarnCapture)
            .init();
    }

    let mut args = Args::parse();
    let role = NodeRole::parse(&args.role)
        .or_else(|| {
            std::env::args()
                .next()
                .as_deref()
                .and_then(NodeRole::from_exe_name)
        });
    if let Some(r) = role {
        match r {
            NodeRole::Archive => {
                args.archive = true;
                args.hub = true;
            }
            NodeRole::Hub => {
                args.archive = false;
                args.hub = true;
            }
            NodeRole::Val => {
                args.archive = false;
                args.hub = false;
                args.max_chain_ledgers = NodeRole::VAL_MAX_CHAIN;
            }
        }
        info!("seat role={} id={}", r.as_str(), args.id);
    }
    let scheme = CryptoScheme::parse(&args.scheme).context("scheme")?;
    if matches!(scheme, CryptoScheme::HmacDev) && !args.allow_dev_crypto && !args.gen_keys_only {
        bail!("hmac-dev refused without --allow-dev-crypto (checklist A8)");
    }
    let _ = TEST_HOOKS.set(test_hooks_allowed(
        std::env::var("FALCON_PL_TEST_HOOKS").as_deref() == Ok("1"),
        matches!(scheme, CryptoScheme::HmacDev),
        args.network_id,
    ));
    if test_hooks_on() {
        warn!("TEST HOOKS ENABLED (isolated rehearsal only; hmac-dev, network {})", args.network_id);
    }
    let allow_admin = if args.allow_admin_wire {
        true
    } else if args.lock_public_wire || !args.admin_sock.is_empty() {
        false
    } else {
        true
    };

    let mut val_ids = args.validators.clone();
    if val_ids.is_empty() {
        val_ids = vec![args.id.clone()];
    }
    if !val_ids.iter().any(|v| v == &args.id) {
        val_ids.push(args.id.clone());
    }
    val_ids.sort();
    val_ids.dedup();

    let user_ids = fd_pl::genesis_account_ids(args.load_wallets);

    let keys = if args.gen_keys_only {
        if args.keys_dir.is_empty() {
            bail!("--gen-keys-only requires --keys-dir");
        }
        let mut k = KeyRing::new(scheme);
        k.generate_many(val_ids.iter().map(|s| s.as_str()));
        k.generate_many(user_ids.iter().map(|s| s.as_str()));
        k.save_dir(&args.keys_dir)?;
        info!("wrote keys → {}", args.keys_dir);
        return Ok(());
    } else if !args.keys_dir.is_empty()
        && PathBuf::from(&args.keys_dir).join("pl_keys.json").exists()
    {
        // Production: all registry publics, only this node's secret.
        KeyRing::load_dir_slim(&args.keys_dir, &[args.id.as_str()])?
    } else if !args.keys_dir.is_empty() {
        let mut k = KeyRing::new(scheme);
        k.generate_many(val_ids.iter().map(|s| s.as_str()));
        k.generate_many(user_ids.iter().map(|s| s.as_str()));
        k.save_dir(&args.keys_dir)?;
        k
    } else {
        let mut k = KeyRing::new(scheme);
        k.generate_many(val_ids.iter().map(|s| s.as_str()));
        k.generate_many(user_ids.iter().map(|s| s.as_str()));
        k
    };

    if args.max_chain_ledgers == 0 {
        info!(
            "--max-chain-ledgers 0 → archive default {}",
            ChainConfig::DEFAULT_MAX_CHAIN_LEDGERS
        );
    }
    let mut cfg = ChainConfig {
        network_id: args.network_id,
        max_txs_per_ledger: args.max_txs,
        pack_budget_ms: args.pack_budget_ms,
        pong_window_ms: 30_000,
        confirm_depth: 3,
        slash_equivocation: 100,
        scheme,
        soft_ok_votes: 3,
        hard_ok_ratio: 0.6,
        progress_timeout_ms: args.progress_timeout_ms,
        max_mempool_txs: args.max_mempool_txs,
        max_chain_ledgers: ChainConfig::resolve_max_chain_ledgers(args.max_chain_ledgers),
        min_fee: args.min_fee,
        fee_escalate: args.fee_escalate,
        ..Default::default()
    };
    cfg.sanitize(); // v2.3.1 P1: never allow max_chain_ledgers=0
    if args.archive {
        cfg.archive = true;
        // RAM window stays at max_body_ledgers (64). Disk holds the rest.
    }
    if args.epoch_ms > 0 {
        cfg.epoch_ms = args.epoch_ms;
    }
    if args.first_claim_epoch > 0 {
        cfg.first_claim_epoch = args.first_claim_epoch;
    }
    if args.unbond_cooldown_ms > 0 {
        cfg.unbond_cooldown_ms = args.unbond_cooldown_ms;
    }
    cfg.online_epoch_heights = args.online_epoch_heights;
    // A2: Falcon fleets require signed consensus votes. HMAC-dev tests stay unsigned.
    cfg.require_vote_sigs = matches!(scheme, CryptoScheme::Falcon512);
    cfg.allow_admin_wire = allow_admin;
    let genesis_users = fd_pl::genesis_accounts(args.load_wallets);
    // Seed validator ids for hard-resync (never include live joiners only bonded later).
    let seed_val_ids: Vec<String> = val_ids
        .iter()
        .filter(|v| !(args.join && *v == &args.id))
        .cloned()
        .collect();
    let node = if !args.snapshot.is_empty() && PathBuf::from(&args.snapshot).exists() {
        info!("loading snapshot {}", args.snapshot);
        let mut n = Node::load_snapshot(&args.snapshot, keys).context("load snapshot")?;
        n.id = args.id.clone();
        // Restore ring keys this seat held before the restart (local sidecar
        // written next to --snapshot-out; never served, never from a peer).
        let ring_src = if !args.snapshot_out.is_empty() { &args.snapshot_out } else { &args.snapshot };
        let ring_path = Node::ring_sidecar_path(ring_src);
        let restored = n.merge_ring_publics(&ring_path);
        if restored > 0 {
            info!("key ring: restored {restored} public key(s) from {ring_path:?}");
        }
        n.keys_dir = Some(PathBuf::from(&args.keys_dir));
        // Ensure registered validators exist even if snap is sparse.
        // Live join: do not invent a free bond for self — Bond ledger / snap state.
        for v in &val_ids {
            if args.join && v == &args.id {
                continue;
            }
            if !n.validators.contains_key(v) {
                n.register_validator(v, args.bond);
            }
        }
        // Backfill genesis seed set for hard-resync (pre-v2.2.5 snaps omit it).
        n.ensure_genesis_validators(&seed_val_ids, args.bond);
        n.ensure_faucet();
        if args.join {
            info!(
                "join mode (snapshot): id={} tip={} self_bonded={} genesis_vals={}",
                args.id,
                n.tip_height,
                n.validators.contains_key(&args.id),
                n.genesis_validators.len()
            );
        }
        n
    } else {
        let mut n = Node::new(args.id.clone(), cfg, keys, &genesis_users);
        for v in &val_ids {
            // Live join: self is not pre-bonded; Bond tx on chain supplies weight.
            if args.join && v == &args.id {
                continue;
            }
            n.register_validator(v, args.bond);
        }
        n.ensure_genesis_validators(&seed_val_ids, args.bond);
        n.ensure_faucet();
        if args.join {
            info!(
                "join mode: id={} not pre-registered; bond must appear via ledger catch-up/live (prefer --snapshot from a live peer for long chains)",
                args.id
            );
        }
        n
    };
    // Apply hub role after load/new.
    let mut node = node;
    node.keys_dir = Some(PathBuf::from(&args.keys_dir));
    // Snapshot JSON still carries the pack cap from whenever it was first
    // written (2300 snaps say 128 txs / 1000 ms). The process flags are the
    // live knobs; they are not part of the state root.
    node.cfg.max_txs_per_ledger = args.max_txs;
    node.cfg.pack_budget_ms = args.pack_budget_ms;
    node.cfg.progress_timeout_ms = args.progress_timeout_ms;
    node.cfg.max_mempool_txs = args.max_mempool_txs;
    info!(
        "pack knobs: max_txs={} pack_budget_ms={} progress_timeout_ms={} max_mempool={}",
        node.cfg.max_txs_per_ledger,
        node.cfg.pack_budget_ms,
        node.cfg.progress_timeout_ms,
        node.cfg.max_mempool_txs
    );
    // v2.9.59 packer pacing (runtime knob; not in the snapshot or cfg digest).
    node.pace_min_interval_ms = args.min_block_interval_ms;
    node.pace_mempool_txs = args.pace_mempool_txs.max(1);
    info!(
        "packer pacing: min_block_interval_ms={} (effective {}) pace_mempool_txs={}",
        node.pace_min_interval_ms,
        node.pace_effective_ms(),
        node.pace_mempool_txs
    );
    // v2.9.62 A13: deterministic seat-key registry (votes/certs from H_act).
    {
        let genesis: Vec<String> = args.validators.clone();
        node.init_seat_key_registry_from_genesis(&genesis);
        if node.cfg.network_id == fd_pl::NETWORK_ID_PUBLIC_TESTNET_2300
            && node.rewards_v2_from_height != u64::MAX
            && node.seat_key_registry.is_empty()
        {
            anyhow::bail!("2300 armed for rewards v2 but TESTNET_2300_SEAT_KEYS is empty (A13): refusing to start");
        }
        eprintln!(
            "seat_key_registry: {} legacy seat key(s) [{}] (enforced from H_act={})",
            node.seat_key_registry.len(),
            node.seat_key_registry.keys().cloned().collect::<Vec<_>>().join(","),
            node.rewards_v2_from_height
        );
    }
    // v2.10.0 runtime consensus knobs (not taken from the snapshot's cfg).
    {
        let env_u64 = |k: &str| std::env::var(k).ok().and_then(|v| v.trim().parse::<u64>().ok());
        // Phase 2 activation: env > CLI > bridge.json > network constant
        // (2300 → 369998). A value that disagrees with the baked network
        // constant refuses to start unless explicitly overridden — a seat on
        // the wrong activation height mis-verifies round-scoped certs.
        let bridge_vr = crate_lc_vote_rounds(&args.keys_dir);
        let res = fd_pl::resolve_vote_rounds_from_height(
            node.cfg.network_id,
            env_u64("FALCON_PL_VOTE_ROUNDS_FROM_HEIGHT"),
            args.vote_rounds_from_height,
            bridge_vr,
        );
        // Phase 2 pause window (v2.9.48): same precedence and the same
        // refuse-on-mismatch rule as the activation height.
        let env_pause = match std::env::var("FALCON_PL_VOTE_ROUNDS_PAUSE") {
            Ok(v) => Some(
                fd_pl::parse_vote_rounds_pause(&v)
                    .map_err(|e| anyhow::anyhow!("FALCON_PL_VOTE_ROUNDS_PAUSE: {e}"))?,
            ),
            Err(_) => None,
        };
        let cli_pause = if args.vote_rounds_pause.trim().is_empty() {
            None
        } else {
            Some(
                fd_pl::parse_vote_rounds_pause(&args.vote_rounds_pause)
                    .map_err(|e| anyhow::anyhow!("--vote-rounds-pause: {e}"))?,
            )
        };
        let bridge_pause = crate_lc_vote_rounds_pause(&args.keys_dir);
        if let Err(e) = fd_pl::validate_vote_rounds_pause(bridge_pause.0, bridge_pause.1) {
            bail!("keys/lc/bridge.json: {e}");
        }
        let pres = fd_pl::resolve_vote_rounds_pause(
            node.cfg.network_id,
            env_pause,
            cli_pause,
            bridge_pause,
        );
        let allow = std::env::var("FALCON_PL_ALLOW_VOTE_ROUNDS_OVERRIDE")
            .map(|v| v.trim() == "1")
            .unwrap_or(false);
        match fd_pl::check_vote_rounds_startup(node.cfg.network_id, &res, &pres, allow) {
            Ok(warnings) => {
                for w in warnings {
                    warn!("{w}");
                }
            }
            Err(e) => bail!("{e}"),
        }
        let vr = res.height;
        let la = env_u64("FALCON_PL_LIVENESS_ALERT_SECS").unwrap_or(args.liveness_alert_secs);
        node.cfg.vote_rounds_from_height = vr;
        node.cfg.vote_rounds_pause_from = pres.from;
        node.cfg.vote_rounds_resume_at = pres.resume_at;
        if pres.from > 0 && (vr == 0 || pres.resume_at <= vr) {
            // e.g. the legacy-unjam drop-in (vr=999999999): window is inert.
            info!(
                "vote_rounds_pause=[{}, {}) is inert (activation {vr} is not before resume)",
                pres.from, pres.resume_at
            );
        }
        node.cfg.liveness_alert_ms = la.saturating_mul(1000);
        let base = if !args.snapshot_out.is_empty() {
            args.snapshot_out.clone()
        } else {
            args.snapshot.clone()
        };
        if !base.is_empty() {
            node.vote_journal = Some(PathBuf::from(format!("{base}.own-votes.json")));
            let merged = node.load_vote_journal();
            if merged > 0 {
                info!("vote journal: restored {merged} open-height round vote(s)");
            }
        }
        info!(
            "consensus: vote_rounds_from_height={} (source={}, network_default={}) pause=[{}, {}) (source={}) (active_now={}) liveness_alert_secs={}",
            vr,
            res.source,
            res.network_default,
            pres.from,
            pres.resume_at,
            pres.source,
            node.vote_rounds_at(node.tip_height.saturating_add(1)),
            la
        );
    }
    node.apply_qc_bridge_cfg();
    node.btc_exit_mode = fd_pl::bitvm2_exit::BtcExitMode::from_env();
    info!("BTC_EXIT_MODE={}", node.btc_exit_mode.as_str());
    if let Ok(h) = std::env::var("BITVM2_INSTANCE_SPK") {
        if let Ok(spk) = hex::decode(h.trim()) {
            if let Ok(rail) = node.bridge.rail_mut(fd_pl::bridge::RAIL_BTC) {
                rail.bitvm2_instance_spk = Some(spk);
                info!("BITVM2_INSTANCE_SPK overlay set (mint dest; 369k NUMS untouched)");
            }
        }
    }
    if let Ok(v) = std::env::var("FPL_BTC_MIN_CONFIRMATIONS") {
        if let Ok(n) = v.parse::<u64>() {
            if let Ok(rail) = node.bridge.rail_mut(fd_pl::bridge::RAIL_BTC) {
                rail.min_confirmations = n;
                info!("FPL_BTC_MIN_CONFIRMATIONS={n}");
            }
        }
    }
    {
        let n = fd_pl::lc::backfill_chain(
            PathBuf::from(&args.keys_dir).as_path(),
            &node.id,
            &node.chain,
            &node.bridge,
        );
        if n > 0 {
            info!("LC backfill signed {n} headers seat={}", node.id);
        }
    }
    node.is_hub = args.hub;
    // CLI safety flags win over older snapshot cfg.
    node.cfg.require_vote_sigs = matches!(scheme, CryptoScheme::Falcon512);
    node.cfg.allow_admin_wire = allow_admin;
    // Last resume may have persisted a recertify cert with empty/outsider sigs.
    node.drop_invalid_certs();
    if args.epoch_ms > 0 {
        node.cfg.epoch_ms = args.epoch_ms;
    }
    if args.first_claim_epoch > 0 {
        node.cfg.first_claim_epoch = args.first_claim_epoch;
    }
    if args.archive {
        node.cfg.archive = true;
        let body_dir = if !args.snapshot_out.is_empty() {
            PathBuf::from(&args.snapshot_out)
                .parent()
                .map(|p| p.to_path_buf())
                .unwrap_or_else(|| PathBuf::from("."))
                .join("bodies")
                .join(&args.id)
        } else {
            PathBuf::from(&args.keys_dir)
                .join("..")
                .join("bodies")
                .join(&args.id)
        };
        if let Err(e) = node.open_body_store(&body_dir) {
            // Without a store, archive=true disables RAM strip (test helper).
            // A failed open must not leave a joiner holding every body — that
            // made settle disagree with hubs at 20922.
            warn!("archive body store {body_dir:?}: {e} (strip RAM; no disk archive)");
            node.cfg.archive = false;
            node.prune_old_bodies();
        } else {
            info!("archive body store {:?}", body_dir);
            node.prune_old_bodies();
        }
    } else {
        // Snapshots copied from an archive hub persist archive=true. v4/v11
        // loaded v1's snap, never opened a store, and stopped stripping.
        node.cfg.archive = false;
        node.prune_old_bodies();
    }
    // Role wins over snap cfg (light val must not keep a 20k tail).
    // CLI 0 is the archive default (20k), never a 1-ledger tail (2.9.34).
    node.cfg.max_chain_ledgers = if matches!(role, Some(NodeRole::Val)) {
        NodeRole::VAL_MAX_CHAIN
    } else {
        ChainConfig::resolve_max_chain_ledgers(args.max_chain_ledgers)
    };
    node.cfg.sanitize();
    node.prune_chain();
    node.prune_old_bodies();
    // Public vault identity only (no shares). Shares stay in per-seat 600 files.
    {
        let keys = PathBuf::from(&args.keys_dir);
        let frost = keys.join("vault-frost-pub.json");
        let legacy = keys.join("vault-pub.json");
        let loaded = if frost.exists() {
            fd_pl::frost_vault::load_vault_pub(&keys).ok()
        } else if legacy.exists() {
            std::fs::read_to_string(&legacy)
                .ok()
                .and_then(|s| serde_json::from_str::<fd_pl::vault::VaultPub>(&s).ok())
        } else {
            None
        };
        if let Some(p) = loaded {
            if let Ok(r) = node.bridge.rail_mut(fd_pl::bridge::RAIL_BTC) {
                r.local_vault_pub = Some(p.clone());
                info!(
                    "BTC vault pubkey loaded locally epoch={} n={} t={} spk={} consensus={}",
                    p.epoch,
                    p.n,
                    p.t,
                    p.spk_hex,
                    r.vault_pub.is_some()
                );
            }
        }
    }
    if args.hub {
        info!("hub role enabled id={}", args.id);
    }
    if !allow_admin {
        info!("public TCP wire locked (admin-only via --admin-sock)");
    }

    let peers: Vec<String> = args
        .peers
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    let hub_addrs: Vec<String> = args
        .hubs
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    let hub_peer_idxs: Vec<usize> = peers
        .iter()
        .enumerate()
        .filter(|(_, p)| hub_addrs.iter().any(|h| h == *p))
        .map(|(i, _)| i)
        .collect();

    // v2.9.53 disk hygiene: data dir for bounded dumps, startup cleanup of
    // unbounded legacy dumps, .bak retention, thresholds for the low-disk guard.
    let data_dir = {
        let base = if !args.snapshot_out.is_empty() {
            args.snapshot_out.clone()
        } else {
            args.snapshot.clone()
        };
        let from_snap = PathBuf::from(&base)
            .parent()
            .filter(|p| !base.is_empty() && !p.as_os_str().is_empty())
            .map(|p| p.to_path_buf());
        from_snap.unwrap_or_else(|| {
            if !args.keys_dir.is_empty() {
                PathBuf::from(&args.keys_dir).join("..").join("snapshots")
            } else {
                std::env::temp_dir().join(format!("falcon-pl-{}", args.id))
            }
        })
    };
    let disk_guard = fd_pl::disk::DiskGuard::from_env();
    startup_disk_cleanup(&args.id, &data_dir, &args.snapshot_out, &disk_guard);

    let shared = Arc::new(Shared {
        node: Mutex::new(node),
        inbound: Mutex::new(Vec::new()),
        hub_peer_idxs,
        is_hub: args.hub,
        is_archive: args.archive,
        snapshot_out: PathBuf::from(&args.snapshot_out),
        snap_meta: Mutex::new(None),
        snap_publish: Mutex::new(()),
        hub_snap: Mutex::new(None),
        data_dir,
        disk_guard,
        disk_skips: std::sync::atomic::AtomicU64::new(0),
        disk_last_skip: Mutex::new(String::new()),
        snap_pull: Mutex::new(None),
        snap_stash: Mutex::new(fd_pl::SnapStash::new(SNAP_STASH_CAP)),
        snap_slow_judge: Mutex::new(fd_pl::SnapSlowJudge::new()),
        last_snap_chunk_ms: std::sync::atomic::AtomicU64::new(0),
        snap_pin_ms: std::sync::atomic::AtomicU64::new(0),
        served_shas: Mutex::new(std::collections::HashMap::new()),
        slow_snap_src: Mutex::new(std::collections::HashMap::new()),
        snap_nonserve: Mutex::new(std::collections::HashMap::new()),
        snap_pushed: Mutex::new(std::collections::HashMap::new()),
        ledger_slow: Mutex::new(fd_pl::catchup_slow::LedgerSlowList::new()),
        joiner: args.join && !args.hub && !args.archive,
        wire_from: Arc::new(parking_lot::Mutex::new(String::new())),
        blackhole: Mutex::new(std::collections::HashMap::new()),
        live_socks: Mutex::new(std::collections::HashMap::new()),
        tx_relay_wait: Mutex::new(std::collections::VecDeque::new()),
        tx_announced: Mutex::new(std::collections::HashSet::new()),
        dish_guard: Mutex::new(std::collections::HashSet::new()),
        piece_peers: Mutex::new(std::collections::HashSet::new()),
        gap_hard: Mutex::new(0),
        gap_named: Mutex::new(0),
        gap_dish: Mutex::new(0),
        gap_walk: Mutex::new((0, String::new())),
    });

    // Four lanes per peer: cons / catch-up / body / inventory (v2.9.16).
    let mut peer_outs = Vec::new();
    let mut peer_rxs = Vec::new();
    for peer in peers {
        let cons_used = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let tx_used = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let body_used = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let catch_used = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (cons_tx, cons_rx) = mpsc::channel::<String>(WIRE_QUEUE_CAP);
        let (tx_tx, tx_rx) = mpsc::channel::<String>(TX_QUEUE_CAP);
        let (body_tx, body_rx) = mpsc::channel::<String>(BODY_QUEUE_CAP);
        let (catch_tx, catch_rx) = mpsc::channel::<String>(CATCH_QUEUE_CAP);
        peer_outs.push(PeerOut {
            cons: ByteTx {
                tx: cons_tx,
                used: cons_used.clone(),
                cap: WIRE_QUEUE_BYTES,
            },
            txq: ByteTx {
                tx: tx_tx,
                used: tx_used.clone(),
                cap: TX_QUEUE_BYTES,
            },
            bodyq: ByteTx {
                tx: body_tx,
                used: body_used.clone(),
                cap: BODY_QUEUE_BYTES,
            },
            catchq: ByteTx {
                tx: catch_tx,
                used: catch_used.clone(),
                cap: CATCH_QUEUE_BYTES,
            },
            peer_id: Arc::new(parking_lot::Mutex::new(String::new())),
            large_out: Arc::new(LargeGate::new()),
        });
        peer_rxs.push((
            peer, cons_rx, tx_rx, body_rx, catch_rx, cons_used, tx_used, body_used, catch_used,
        ));
    }
    let fanout = Arc::new(peer_outs);
    if args.archive && !args.snapshot_out.is_empty() {
        let p = PathBuf::from(&args.snapshot_out);
        if p.exists() {
            let shared_h = shared.clone();
            tokio::spawn(async move {
                // Never pin the 160 MB full snap. Join file is the product serve.
                let join = snap_join_path(&p);
                let serve = snap_serve_path(&p);
                let src = if join.exists() {
                    join
                } else if serve.exists() {
                    serve.clone()
                } else {
                    return;
                };
                let header = peek_snap_header(&src);
                let read_p = src.clone();
                if let Ok(Ok(bytes)) =
                    tokio::task::spawn_blocking(move || std::fs::read(&read_p)).await
                {
                    let sha256 = fd_pl::crypto::sha256_hex(&bytes);
                    let (tip, tip_hash) = header.unwrap_or((0, String::new()));
                    if src != serve {
                        let _ = std::fs::copy(&src, &serve);
                    }
                    if !write_stable_serve(&p, &sha256, &bytes) {
                        return;
                    }
                    let mut meta = shared_h.snap_meta.lock();
                    if meta.is_none() {
                        *meta = Some(SnapMeta {
                            tip,
                            tip_hash,
                            sha256,
                            bytes: bytes.len() as u64,
                        });
                    }
                }
            });
        }
    }
    for (i, (peer, cons_rx, tx_rx, body_rx, catch_rx, cons_used, tx_used, body_used, catch_used)) in
        peer_rxs.into_iter().enumerate()
    {
        let shared_c = shared.clone();
        let fanout_c = fanout.clone();
        let peer_id = fanout[i].peer_id.clone();
        let my_id = args.id.clone();
        tokio::spawn(async move {
            peer_writer_loop(
                peer, cons_rx, tx_rx, body_rx, catch_rx, cons_used, tx_used, body_used,
                catch_used, shared_c, fanout_c, my_id, peer_id,
            )
            .await;
        });
    }

    // Seat payout: keep the on-chain payout account equal to --payout-address.
    {
        let want = if args.payout_address.trim().is_empty() {
            std::env::var("FPL_PAYOUT_ADDRESS").unwrap_or_default()
        } else {
            args.payout_address.clone()
        };
        let want = want.trim().to_string();
        if !want.is_empty() {
            let shared_c = shared.clone();
            let my_id = args.id.clone();
            info!("seat payout: --payout-address {want} (submitted on chain from the activation height)");
            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                let mut tick = tokio::time::interval(std::time::Duration::from_secs(120));
                loop {
                    tick.tick().await;
                    seat_payout_sync(&shared_c, &my_id, &want);
                }
            });
        }
    }

    // Health: note when the tip advances (wall clock) for blocks/min. One
    // u64 read per second via try_lock, so it never waits on consensus.
    {
        let shared_c = shared.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(1));
            loop {
                tick.tick().await;
                let h = shared_c.node.try_lock().map(|n| n.tip_height);
                if let Some(h) = h {
                    fd_pl::health::observe_tip(unix_ms(), h);
                }
            }
        });
    }

    // Periodic snapshot (private fleet durability / OOM restart recovery).
    if !args.snapshot_out.is_empty() {
        let shared_c = shared.clone();
        let path = args.snapshot_out.clone();
        let interval = args.snapshot_interval_ms.max(5_000);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_millis(interval));
            // v2.9.53: the seat's own snapshot is essential (only refused if it
            // would leave < hard reserve); the join + serve copies are optional
            // dumps (skipped under the low-water mark).
            let guard = shared_c.disk_guard;
            let essential = move |st: Option<&fd_pl::disk::DiskStat>, need: u64| match st {
                Some(s) => guard.check_essential(s, need),
                None => Ok(()),
            };
            let optional = move |st: Option<&fd_pl::disk::DiskStat>, need: u64| match st {
                Some(s) => guard.check_optional(s, need),
                None => Ok(()),
            };
            loop {
                tick.tick().await;
                // v2.9.58: capture under the lock (cheap clones; the exec header
                // map is shared), serialize + write outside it. Before, both
                // ~207 MB files were encoded and written while holding
                // `node.lock` every minute (seconds on a 2-vCPU seat).
                // One capture only; the join copy is trimmed from it after the
                // full file is written (no second deep clone held alongside).
                let (snap, tip, tip_hash, ring, scheme) = {
                    let n = shared_c.node.lock();
                    (
                        n.to_snapshot(),
                        n.tip_height,
                        n.tip_hash.clone(),
                        n.keys.export_publics(),
                        n.keys.scheme,
                    )
                };
                let saved = tokio::task::block_in_place(|| {
                    fd_pl::Node::write_snapshot_checked(&path, &snap, &essential)
                });
                if saved.is_ok() {
                    let ring_path = fd_pl::Node::ring_sidecar_path(&path);
                    if let Err(e) = tokio::task::block_in_place(|| {
                        fd_pl::Node::write_ring_publics(&ring_path, scheme, &ring)
                    }) {
                        warn!("key ring sidecar {ring_path:?}: {e}");
                    }
                }
                drop(ring);
                let join_snap = fd_pl::Node::trim_to_join(snap);
                if let Err(e) = saved {
                    let e = e.to_string();
                    if e.contains("disk full") {
                        tracing::error!("DISK: snapshot save {path} refused: {e}");
                    } else {
                        warn!("snapshot save {path}: {e}");
                    }
                } else {
                    let join = snap_join_path(std::path::Path::new(&path));
                    let join_res = tokio::task::block_in_place(|| {
                        fd_pl::Node::write_snapshot_checked(&join, &join_snap, &optional)
                    });
                    drop(join_snap);
                    let join_ok = match join_res {
                        Ok(_) => true,
                        Err(e) => {
                            let e = e.to_string();
                            if e.contains("low disk") {
                                shared_c.note_disk_skip("join snapshot", &e);
                            } else {
                                warn!("join snapshot {join:?}: {e}");
                            }
                            false
                        }
                    };
                    info!("snapshot saved {path} tip={tip}");
                    if !join_ok {
                        // Do not rotate the pin onto a stale/missing join file.
                        continue;
                    }
                    let _publish = shared_c.snap_publish.lock();
                    let last = shared_c
                        .last_snap_chunk_ms
                        .load(std::sync::atomic::Ordering::Relaxed);
                    let pin_tip = shared_c
                        .snap_meta
                        .lock()
                        .as_ref()
                        .map(|m| m.tip)
                        .unwrap_or(0);
                    if snap_pin_rotate_ok(&shared_c, tip, pin_tip, last, unix_ms()) {
                        let serve = snap_serve_path(std::path::Path::new(&path));
                        let src = if join.exists() {
                            join
                        } else {
                            PathBuf::from(&path)
                        };
                        let need = std::fs::metadata(&src).map(|m| m.len()).unwrap_or(0);
                        if let Err(e) = shared_c.optional_ok(need) {
                            shared_c.note_disk_skip("snapshot serve pin copy", &e);
                            continue;
                        }
                        if let Err(e) = std::fs::copy(&src, &serve) {
                            warn!("snapshot pin {serve:?}: {e}");
                        } else if let Ok(bytes) = std::fs::read(&serve) {
                            let sha256 = fd_pl::crypto::sha256_hex(&bytes);
                            if tip.saturating_sub(pin_tip) >= fd_pl::Node::SNAPSHOT_PULL_LAG
                                && pin_tip > 0
                            {
                                info!(
                                    "snapshot pin rotate live={tip} was={pin_tip} bytes={}",
                                    bytes.len()
                                );
                            }
                            if write_stable_serve(std::path::Path::new(&path), &sha256, &bytes) {
                                *shared_c.snap_meta.lock() = Some(SnapMeta {
                                    tip,
                                    tip_hash,
                                    sha256,
                                    bytes: bytes.len() as u64,
                                });
                                shared_c
                                    .snap_pin_ms
                                    .store(unix_ms(), std::sync::atomic::Ordering::Relaxed);
                            } else {
                                shared_c.note_disk_skip("snapshot serve hashed copy", "write failed");
                            }
                        }
                    }
                    drop(_publish);
                    tokio::task::block_in_place(|| prune_join_serve(&shared_c));
                    continue;
                }
            }
        });
    }

    // Disk watchdog (v2.9.53): loud log when low, delete the idle hub dump.
    {
        let shared_c = shared.clone();
        tokio::spawn(async move {
            use fd_pl::disk::DiskLevel;
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(30));
            let mut last_log_ms = 0u64;
            let mut last_level = DiskLevel::Ok;
            loop {
                tick.tick().await;
                let now = unix_ms();
                if let Some(st) = shared_c.disk_stat() {
                    let lvl = shared_c.disk_guard.level(&st);
                    let every = match lvl {
                        DiskLevel::Low => 60_000,
                        DiskLevel::Warn => 300_000,
                        DiskLevel::Ok => u64::MAX,
                    };
                    let changed = lvl != last_level;
                    if changed || now.saturating_sub(last_log_ms) >= every {
                        let msg = format!(
                            "DISK {} {:?}: {} MB free of {} MB ({:.1}%), warn<{}% low<{}%/{} MB, skipped_dumps={}",
                            lvl.as_str().to_uppercase(),
                            st.path,
                            st.avail_bytes / (1024 * 1024),
                            st.total_bytes / (1024 * 1024),
                            st.free_pct(),
                            shared_c.disk_guard.warn_pct,
                            shared_c.disk_guard.min_free_pct,
                            shared_c.disk_guard.min_free_bytes / (1024 * 1024),
                            shared_c.disk_skips.load(std::sync::atomic::Ordering::Relaxed),
                        );
                        match lvl {
                            DiskLevel::Low => tracing::error!("{msg} — optional snapshot dumps are being skipped; free space now"),
                            DiskLevel::Warn => warn!("{msg}"),
                            DiskLevel::Ok => info!("{msg}"),
                        }
                        last_log_ms = now;
                        last_level = lvl;
                    }
                }
                // Delete our bounded hub dump once no joiner has pulled for a while.
                let last = shared_c
                    .last_snap_chunk_ms
                    .load(std::sync::atomic::Ordering::Relaxed);
                if now.saturating_sub(last) >= fd_pl::disk::HUB_DUMP_IDLE_DELETE_MS {
                    let mut h = shared_c.hub_snap.lock();
                    if let Some(cur) = h.as_ref() {
                        if cur.owned {
                            let _ = std::fs::remove_file(&cur.path);
                            info!(
                                "hub join snapshot idle → removed {:?} (tip={})",
                                cur.path, cur.meta.tip
                            );
                        }
                        *h = None;
                    }
                }
            }
        });
    }

    // Seal / pong / rebroadcast
    {
        let shared_c = shared.clone();
        let fanout = fanout.clone();
        let my_id = args.id.clone();
        let interval = args.seal_interval_ms.max(150);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_millis(interval));
            let mut ntick = 0u64;
            // Test binary only. Hold a partial applicable set until it
            // reaches the pack cap or 8 s. /tmp/fpl-only-pack, when it
            // contains a seat id, is the only seat allowed to seal.

            loop {
                tick.tick().await;
                ntick += 1;
                // Dish the missing suffix before ordinary SubmitTx, and hold
                // those seats until this height's walk is queued.
                if shared_c.is_hub {
                    let rows = {
                        let mut n = shared_c.node.lock();
                        if n.still_lagging() {
                            None
                        } else {
                            n.take_packer_dish()
                        }
                    };
                    if let Some(rows) = rows {
                        let mut any = false;
                        for (seat, batch) in &rows {
                            let queued = shared_c.fan_seat_suffix(&fanout, seat, batch);
                            if queued.is_empty() {
                                continue;
                            }
                            any = true;
                            let (open_h, winner) = {
                                let n = shared_c.node.lock();
                                (
                                    n.tip_height.saturating_add(1),
                                    n.lottery_packer().unwrap_or_default(),
                                )
                            };
                            info!(
                                "dish-suffix seat={seat} n={} h={open_h}",
                                queued.len()
                            );
                            if seat == &winner {
                                let mut seen = shared_c.gap_dish.lock();
                                if *seen < open_h {
                                    *seen = open_h;
                                    info!(
                                        "round-gap dish h={open_h} seat={seat} n={}",
                                        queued.len()
                                    );
                                }
                            }
                            shared_c.node.lock().note_dish_queued(seat, &queued);
                        }
                        let mut n = shared_c.node.lock();
                        if !n.winner_dish_started() {
                            // The winner has nothing queued. Do not sit out
                            // the 5s fail backoff or the 400ms feed gap.
                            n.release_dish_attempt();
                        } else if !any {
                            n.block_dish();
                        }
                    }
                    shared_c.refresh_dish_guard();
                }
                shared_c.flush_tx_relay(&fanout);
                shared_c.announce_tx_inv(&fanout);
                let pong = {
                    let mut n = shared_c.node.lock();
                    n.tick(interval);
                    n.pong(&my_id);
                    WireMsg::Pong {
                        id: my_id.clone(),
                        now_ms: n.now_ms,
                        tip_height: n.tip_height,
                        tip_hash: n.tip_hash.clone(),
                        is_hub: n.is_hub,
                        mempool_len: n.mempool.len() as u64,
                        archive: shared_c.is_archive,
                        snap_height: shared_c
                            .snap_meta
                            .lock()
                            .as_ref()
                            .map(|m| m.tip)
                            .unwrap_or(0),
                    }
                };
                if let Ok(line) = serde_json::to_string(&pong) {
                    shared_c.fan_line(&fanout, line + "\n");
                }

                // v2.4.0: certified ONLINE epoch — vote observed pong-fresh bonded set;
                // soft QC freezes packer seats for this epoch (not local pong alone).
                {
                    let mut n = shared_c.node.lock();
                    if let Some((epoch_id, members)) = n.maybe_online_set_vote() {
                        let qc = n.online_ok.contains_key(&epoch_id);
                        let list: Vec<String> = members.iter().cloned().collect();
                        let hash = fd_pl::Node::online_set_hash(
                            epoch_id,
                            &members.iter().cloned().collect(),
                        );
                        let signature = n.sign_online_vote(epoch_id, &hash);
                        drop(n);
                        if qc {
                            info!(
                                "ONLINE epoch {epoch_id} certified seats={} → {:?}",
                                list.len(),
                                list
                            );
                        }
                        let vote = WireMsg::OnlineSetVote {
                            epoch_id,
                            members: list,
                            voter: my_id.clone(),
                            signature,
                        };
                        if let Ok(line) = serde_json::to_string(&vote) {
                            shared_c.fan_line(&fanout, line + "\n");
                        }
                    }
                }

                // v2.9.15: re-push pending body on the body lane to the committee.
                {
                    let mut n = shared_c.node.lock();
                    let seats = n.body_lane_seats();
                    let push = n.take_pending_body_push();
                    let pull = n.take_body_pull();
                    drop(n);
                    if let Some(led) = push {
                        if !led.batch_sig.is_empty() {
                            // Retry the small Merkle body on the must-send body
                            // lane. Do not pull the original signed body.
                            shared_c.fan_ledger_body(
                                &fanout,
                                &WireMsg::LedgerBody { ledger: led },
                                &seats,
                            );
                        } else {
                            let header = propose_header(&led);
                            let mut by_id = led;
                            by_id.txs.clear();
                            shared_c.fan_id_followup(
                                &fanout,
                                &seats,
                                &WireMsg::LedgerBodyById { ledger: by_id },
                                &header,
                            );
                        }
                    }
                    if let Some(hash) = pull {
                        shared_c.fan_body_pull(
                            &fanout,
                            &WireMsg::NeedLedgerBody { ledger_hash: hash },
                        );
                    }
                }

                // v2.9.10: snap/catch-up tip may lack certs[h]. Re-OK the tip.
                {
                    let mut n = shared_c.node.lock();
                    if let Some((h, hash, signature)) = n.recertify_committed_tip() {
                        let voter = my_id.clone();
                        let round = n.own_ok_round(h);
                        drop(n);
                        if let Ok(line) = serde_json::to_string(&WireMsg::LedgerOk {
                            height: h,
                            ledger_hash: hash,
                            voter,
                            signature,
                            round,
                        }) {
                            shared_c.fan_line(&fanout, line + "\n");
                        }
                    }
                }

                // M2 / P1: lottery winner pre-pack NeedTxs (canonical hub inventory path).
                // Skip while lagging — catch-up owns the wire.
                {
                    let mut n = shared_c.node.lock();
                    let lagging = n.still_lagging();
                    let i_win = n.lottery_packer().as_ref() == Some(&my_id);
                    if !lagging && i_win && (n.should_pre_pack_need_txs() || n.wants_need_txs())
                    {
                        if n.should_pre_pack_need_txs() {
                            n.mark_pre_pack_need_txs();
                        } else {
                            n.note_need_txs_sent();
                        }
                        drop(n);
                        shared_c.fan_need_txs(
                            &fanout,
                            &WireMsg::NeedTxs {
                                max_count: fd_pl::Node::NEED_TXS_BATCH as u64,
                            },
                        );
                    }
                }

                // Far behind: exclusive join-snap. Mixing NeedLedgers into an
                // in-flight pull put LedgersBatch on the same inbound TCP as
                // SnapshotChunk — Falcon verify blocked the read task (2.9.23).
                let (retry_chunks, abort_pull, pulling, pull_sha) = {
                    let local_tip = shared_c.node.lock().tip_height;
                    let mut g = shared_c.snap_pull.lock();
                    if let Some(p) = g.as_mut() {
                        let now = unix_ms();
                        // A pin we already adopted must not sit in the assembler.
                        // That blocked NeedLedgers after the joiner caught the pin
                        // by admin load while the download was still open.
                        if p.tip_height <= local_tip {
                            let sha = p.sha256.clone();
                            (Vec::new(), true, false, sha)
                        } else if now.saturating_sub(p.last_progress_ms)
                            > fd_pl::Node::SNAPSHOT_STALL_ABORT_MS
                        {
                            // v2.9.70: a stalled source is skipped like a slow
                            // one, so NeedSnapshot reaches the hubs next round.
                            if !p.source_peer.is_empty() {
                                info!(
                                    "snapshot source {} stalled — skip it for up to {}s ({}s if it is the only source)",
                                    p.source_peer,
                                    SNAP_SLOW_SKIP_MS / 1000,
                                    fd_pl::SNAP_ALL_STALLED_RETRY_MS / 1000
                                );
                                shared_c
                                    .slow_snap_src
                                    .lock()
                                    .insert(p.source_peer.clone(), now + SNAP_SLOW_SKIP_MS);
                            }
                            let sha = p.sha256.clone();
                            (Vec::new(), true, false, sha)
                        } else if !p.source_peer.is_empty()
                            && !p.keep_slow
                            && p.too_slow(now, SNAP_SLOW_JUDGE_MS, SNAP_SLOW_BUDGET_MS)
                            && !shared_c.snap_slow_judge.lock().should_abort(&p.source_peer)
                        {
                            // v2.9.74: this source was already judged too slow
                            // and so was every other one we were offered; a
                            // slow download that finishes beats a fast one
                            // that never starts. Stall abort still applies.
                            p.keep_slow = true;
                            info!(
                                "snapshot pull slow from {} ({}/{} chunks) but no faster source left — keep downloading",
                                p.source_peer,
                                p.got(),
                                p.total
                            );
                            (Vec::new(), false, true, p.sha256.clone())
                        } else if !p.source_peer.is_empty()
                            && !p.keep_slow
                            && p.too_slow(now, SNAP_SLOW_JUDGE_MS, SNAP_SLOW_BUDGET_MS)
                        {
                            info!(
                                "snapshot pull too slow from {} ({}/{} chunks in {}s) — skip that source for {}s",
                                p.source_peer,
                                p.got(),
                                p.total,
                                now.saturating_sub(p.started_ms) / 1000,
                                SNAP_SLOW_SKIP_MS / 1000
                            );
                            shared_c
                                .slow_snap_src
                                .lock()
                                .insert(p.source_peer.clone(), now + SNAP_SLOW_SKIP_MS);
                            let sha = p.sha256.clone();
                            (Vec::new(), true, false, sha)
                        } else if now.saturating_sub(p.last_req_ms)
                            >= fd_pl::Node::SNAPSHOT_RETRY_MS
                        {
                            p.last_req_ms = now;
                            // v2.9.62: holes below the highest chunk only
                            // (the push is still sending the tail).
                            let idx = p.retry_indices(
                                fd_pl::Node::SNAPSHOT_PIPE_WINDOW,
                                now,
                                fd_pl::Node::SNAPSHOT_TAIL_RETRY_MS,
                            );
                            p.note_requested(&idx);
                            (idx, false, true, p.sha256.clone())
                        } else {
                            (Vec::new(), false, true, p.sha256.clone())
                        }
                    } else {
                        (Vec::new(), false, false, String::new())
                    }
                };
                if abort_pull {
                    // v2.9.74: keep the chunks; a repeat offer of this sha resumes.
                    if let Some(p) = shared_c.snap_pull.lock().take() {
                        let tip = shared_c.node.lock().tip_height;
                        if p.tip_height > tip && p.got() > 0 {
                            info!(
                                "snapshot pull {} kept for resume ({}/{} chunks)",
                                &p.sha256[..p.sha256.len().min(12)],
                                p.got(),
                                p.total
                            );
                            let mut st = shared_c.snap_stash.lock();
                            st.prune_below(tip);
                            st.put(p);
                        }
                    }
                    info!("snapshot pull stalled — retry NeedSnapshot");
                    shared_c.fan_catchup(&fanout, &WireMsg::NeedSnapshot {});
                } else {
                    if !retry_chunks.is_empty() {
                        debug!(
                            "snapshot hole-fill request n={} first={:?}",
                            retry_chunks.len(),
                            retry_chunks.first()
                        );
                    }
                    for index in retry_chunks {
                        shared_c.fan_catchup(
                            &fanout,
                            &WireMsg::NeedSnapshotChunk {
                                sha256: pull_sha.clone(),
                                index,
                            },
                        );
                    }
                    {
                        let mut n = shared_c.node.lock();
                        if !pulling && n.take_snapshot_pull() {
                            let lag = n.tip_lag();
                            let tip = n.tip_height;
                            drop(n);
                            info!("snapshot pull local_tip={tip} lag={lag}");
                            shared_c.fan_catchup(&fanout, &WireMsg::NeedSnapshot {});
                        }
                    }
                    if !pulling {
                        let mut n = shared_c.node.lock();
                        let tip = n.tip_height;
                        let best = n.best_peer_tip;
                        let hard = n.need_hard_resync && n.can_hard_resync();
                        let lagging = n.still_lagging();
                        if let Some(from_height) = n.take_catchup_pull() {
                            let max_count = fd_pl::Node::CATCHUP_BATCH as u64;
                            if lagging {
                                info!(
                                    "catch-up pull from_height={from_height} local_tip={tip} best_peer={best} hard={hard}"
                                );
                            }
                            drop(n);
                            shared_c.fan_catchup(
                                &fanout,
                                &WireMsg::NeedLedgers {
                                    from_height,
                                    max_count,
                                },
                            );
                        }
                    }
                }

                // v2.5.0: proposal-timeout view-change (height-local recovery).
                {
                    let mut n = shared_c.node.lock();
                    if let Some(alert) = n.liveness_tick() {
                        tracing::error!("{alert}");
                    }
                    if let Some((h, tip, round)) = n.maybe_view_change_vote() {
                        let applied = n.height_view_round >= round;
                        let pending_h = n
                            .pending_proposal
                            .as_ref()
                            .map(|p| p.ledger_hash.chars().take(16).collect::<String>());
                        info!(
                            "view-change vote h={h} round={round} applied={applied} pending={pending_h:?} → lottery {:?}",
                            n.lottery_packer()
                        );
                        let signature = n.sign_vc_vote(h, &tip, round);
                        // Round advanced by our own vote: re-vote the target body.
                        let revote = if applied {
                            n.pending_proposal
                                .as_ref()
                                .map(|p| (p.height, p.ledger_hash.clone()))
                                .and_then(|(ph, phash)| own_ok_msg(&mut n, ph, &phash))
                                .map(|(m, _)| m)
                        } else {
                            None
                        };
                        drop(n);
                        let vc = WireMsg::ViewChange {
                            height: h,
                            tip_hash: tip,
                            round,
                            voter: my_id.clone(),
                            signature,
                        };
                        if let Ok(line) = serde_json::to_string(&vc) {
                            shared_c.fan_line(&fanout, line + "\n");
                        }
                        if let Some(m) = revote {
                            if let Ok(line) = serde_json::to_string(&m) {
                                shared_c.fan_line(&fanout, line + "\n");
                            }
                        }
                        continue;
                    }
                }

                // Progress-timeout: cast skip **vote** + gossip so peers accumulate QC
                // (v2.3.0 P0). Lottery only moves after soft QC of skip votes.
                // v2.3.7: uncertified seats re-fan SkipPacker (queue drops under load).
                {
                    let mut n = shared_c.node.lock();
                    if let Some((h, packer, tip)) = n.maybe_progress_timeout_skip() {
                        let applied = n.skip_set_for(h).contains(&packer);
                        let n_votes = n
                            .skip_votes
                            .get(&h)
                            .and_then(|m| m.get(&packer))
                            .map(|s| s.len())
                            .unwrap_or(0);
                        let need = n.soft_votes_needed();
                        if applied || n_votes <= 1 {
                            info!(
                                "progress timeout skip-vote: {packer} at h={h} certified={applied} votes={n_votes}/{need} → lottery {:?}",
                                n.lottery_packer()
                            );
                        } else {
                            debug!(
                                "skip re-fan: {packer} at h={h} votes={n_votes}/{need} → lottery {:?}",
                                n.lottery_packer()
                            );
                        }
                        let signature = n.sign_skip_vote(h, &packer, &tip);
                        drop(n);
                        let skip = WireMsg::SkipPacker {
                            height: h,
                            packer,
                            tip_hash: tip,
                            voter: my_id.clone(),
                            signature,
                        };
                        if let Ok(line) = serde_json::to_string(&skip) {
                            shared_c.fan_line(&fanout, line + "\n");
                        }
                        // Wait a tick for QC + late seals before packing as standby.
                        continue;
                    }
                }

                // Pack at most one proposal per tick; tip advances only after soft QC
                // (no multi-height pipeline without mesh soft — v2.3.0 P0).
                // P1: pre-pack NeedTxs + grace before sealing thin/empty mempool.
                {
                    let mut n = shared_c.node.lock();
                    n.pong(&my_id);
                    n.note_head_progress();
                    if n.lottery_packer().as_deref() == Some(my_id.as_str()) {
                        let open = n.tip_height.saturating_add(1);
                        let (_, _, packable, _, _, ready) = n.walk_report();
                        if ready {
                            let hold = if n.in_skip_grace() {
                                "skip-grace"
                            } else if !n.tip_is_soft() {
                                "tip-not-soft"
                            } else if n.pending_proposal.is_some() {
                                "pending"
                            } else if n.should_pre_pack_need_txs() {
                                "need-txs"
                            } else if n.waiting_need_txs_grace() {
                                "grace"
                            } else if n.pace_wait() {
                                "pace"
                            } else {
                                "none"
                            };
                            shared_c.note_walk_ready(open, packable, hold);
                        }
                    }
                    if n.in_skip_grace() {
                        // wait
                    } else if !n.tip_is_soft() {
                        // wait for soft QC before packing next height
                    } else if n.pending_proposal.is_some() {
                        // Votes for this height are still arriving. Check the
                        // next block's signatures now so the following proposal
                        // can go out when this quorum lands.
                        n.warm_pipeline();
                        // Proposal in flight — wait for soft QC. Do **not** clone
                        // the full Falcon body every 200ms tick (was ~100KB × 5/s).
                        let elapsed = n.now_ms.saturating_sub(n.height_open_ms);
                        let window = n.cfg.progress_timeout_ms.max(1);
                        let should_refan = elapsed >= window && (elapsed % window) <= 250;
                        let me = my_id.clone();
                        let i_am_packer = n
                            .pending_proposal
                            .as_ref()
                            .map(|p| p.packer == me)
                            .unwrap_or(false);
                        let (ph, p_hash) = n
                            .pending_proposal
                            .as_ref()
                            .map(|p| (p.height, p.ledger_hash.clone()))
                            .unwrap();
                        let header_msg = if should_refan && i_am_packer {
                            Some(propose_header(n.pending_proposal.as_ref().unwrap()))
                        } else {
                            None
                        };
                        drop(n);
                        if should_refan {
                            if let Some(h) = header_msg {
                                shared_c.fan_msg(&fanout, &h);
                            }
                            // Lock/round-checked: never re-fan an OK that would
                            // be a second hash in this (height, round).
                            let ok = {
                                let mut n = shared_c.node.lock();
                                own_ok_msg(&mut n, ph, &p_hash).map(|(m, _)| m)
                            };
                            let _ = &me;
                            if let Some(m) = ok {
                                if let Ok(line) = serde_json::to_string(&m) {
                                    shared_c.fan_line(&fanout, line + "\n");
                                }
                            }
                        }
                    } else {
                        let w = n.lottery_packer();
                        let mp_now = n.mempool.len();
                        let i_win = w.as_deref() == Some(my_id.as_str());
                        let only_pack = match std::fs::metadata("/tmp/fpl-only-pack") {
                            Ok(meta) => {
                                let age = meta.modified().ok().and_then(|t| t.elapsed().ok());
                                if age.is_some_and(|d| d.as_secs() >= 20) {
                                    let _ = std::fs::remove_file("/tmp/fpl-only-pack");
                                    String::new()
                                } else {
                                    std::fs::read_to_string("/tmp/fpl-only-pack")
                                        .unwrap_or_default()
                                        .trim()
                                        .to_string()
                                }
                            }
                            Err(_) => String::new(),
                        };
                        let designated = only_pack == my_id;
                        let applicable = if i_win || designated || (ntick % 20 == 0 && mp_now >= 400) {
                            n.applicable_head_count()
                        } else {
                            0
                        };
                        // Test hold only: a designated seat with a full set may
                        // seal even though the lottery cursor is still ahead.
                        let force_full = designated && applicable >= 400;
                        if force_full {
                            let h = n.tip_height.saturating_add(1);
                            let order = n.lottery_order();
                            if let Some(idx) = order.iter().position(|id| id == &my_id) {
                                for id in &order[..idx] {
                                    n.skip_packer(h, id);
                                }
                                // Receivers sign in this slot. The packer's own
                                // OK has to be the same round or the votes never
                                // meet.
                                n.height_view_round = idx as u64;
                            }
                        }
                        if ntick % 20 == 0 && (mp_now >= 400 || i_win) {
                            let why = if !i_win {
                                "not-lottery"
                            } else if n.pending_proposal.is_some() {
                                "pending"
                            } else if n.should_pre_pack_need_txs() {
                                "need-txs"
                            } else if n.waiting_need_txs_grace() {
                                "grace"
                            } else if n.pace_wait() {
                                "pace"
                            } else {
                                "ready"
                            };
                            info!(
                                "silent-pack why={why} winner={} me={my_id} pool={mp_now} applicable={applicable} round={} skips={}",
                                w.as_deref().unwrap_or("-"),
                                n.height_view_round,
                                n.skip_set_for(n.tip_height.saturating_add(1)).len()
                            );
                        }
                        if i_win || force_full {
                            let open_h = n.tip_height.saturating_add(1);
                            n.maybe_switch_target(open_h);
                            if n.pending_proposal.is_some() {
                                // Locked / already-known body. Re-fan it; do not
                                // mint another hash for this height.
                            } else if !n.can_seal_empty()
                                && !(n.mempool.len() > 0 && !n.has_applicable_tx())
                                && n.should_pre_pack_need_txs()
                            {
                                n.mark_pre_pack_need_txs();
                                drop(n);
                                shared_c.fan_need_txs(
                                    &fanout,
                                    &WireMsg::NeedTxs {
                                        max_count: fd_pl::Node::NEED_TXS_BATCH as u64,
                                    },
                                );
                            } else if !n.can_seal_empty()
                                && !(n.mempool.len() > 0 && !n.has_applicable_tx())
                                && n.waiting_need_txs_grace()
                            {
                                // Wait for TxsBatch to land before packing empty.
                            } else if !n.can_seal_empty() && n.pace_wait() {
                                // v2.9.59: pacing — let a few more txs arrive
                                // instead of sealing a tiny block every ~1.4 s.
                            } else if !only_pack.is_empty() && !designated && !force_full {
                                if ntick % 25 == 0 {
                                    info!(
                                        "burst-hold suppressed me={my_id} applicable={}",
                                        n.applicable_head_count()
                                    );
                                }
                            } else {
                            let (pool, applicable, packable, accounts, min_depth, walk_ready) =
                                n.walk_report();
                            let winner = w.clone().unwrap_or_else(|| "-".into());
                            let open_height = n.tip_height.saturating_add(1);
                            info!(
                                "pack-try pool={pool} applicable={applicable} packable={packable} accounts={accounts} min_depth={min_depth} walk_ready={walk_ready}"
                            );
                            info!(
                                "pack-walk h={open_height} winner={winner} pool={pool} applicable={applicable} packable={packable} accounts={accounts} min_depth={min_depth} walk_ready={walk_ready}"
                            );
                            shared_c.note_walk_ready(open_height, packable, "propose-call");
                            if force_full {
                                // Checker rule is sealed <= max(local+5s, parent+1s).
                                // A hot snap clock stamps ~20s ahead and the live
                                // body is rejected. Parent+1s is always accepted.
                                let parent = n.chain.last().map(|l| l.sealed_at_ms).unwrap_or(0);
                                n.now_ms = parent.saturating_add(1_000);
                            }
                            match n.pack_or_skip(&my_id) {
                                Ok(Some(mut ledger)) => {
                                    if let Err(e) = ledger.attach_merkle_batch_known(&n.keys, &|id| {
                                        n.account_public_key(id)
                                    }) {
                                        warn!("merkle batch: {e}");
                                    }
                                    match n.accept_ledger(&ledger) {
                                        Ok(r) => {
                                            let committed = n.tip_height >= r.height
                                                && n.tip_hash == ledger.ledger_hash;
                                            info!(
                                                "proposed h={} txs={} committed={committed} (soft QC required)",
                                                r.height, r.n_txs
                                            );
                                            info!(
                                                "round-gap propose h={} txs={}",
                                                r.height, r.n_txs
                                            );
                                            let hash = ledger.ledger_hash.clone();
                                            let h = ledger.height;
                                            let header = propose_header(&ledger);
                                            let ok = own_ok_msg(&mut n, h, &hash).map(|(m, _)| m);
                                            let seats = n.body_lane_seats();
                                            let wire = ledger;
                                            let bytes = serde_json::to_string(&WireMsg::LedgerBody {
                                                ledger: wire.clone(),
                                            })
                                            .map(|s| s.len())
                                            .unwrap_or(0);
                                            info!(
                                                "batch-body bytes={bytes} txs={} h={}",
                                                wire.txs.len(),
                                                wire.height
                                            );
                                            if wire.txs.len() >= 400 {
                                                let _ = std::fs::remove_file("/tmp/fpl-only-pack");
                                            }
                                            drop(n);
                                            shared_c.fan_ledger_body(
                                                &fanout,
                                                &WireMsg::LedgerBody { ledger: wire },
                                                &seats,
                                            );
                                            // Header still goes to seats that are not on the body lane.
                                            if let Ok(line) = serde_json::to_string(&header) {
                                                shared_c.fan_line_except(&fanout, line + "\n", &seats);
                                            }
                                            if let Some(m) = ok {
                                                if let Ok(line) = serde_json::to_string(&m) {
                                                    shared_c.fan_line(&fanout, line + "\n");
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            warn!("self-accept: {e}");
                                            if let Some(id) = n.evict_self_accept_failure() {
                                                warn!("self-accept: evicted {id} from mempool (fails apply)");
                                            }
                                        }
                                    }
                                }
                                Ok(None) => {
                                    let h = n.tip_height + 1;
                                    let skipped = n.skip_set_for(h).contains(&my_id);
                                    let tip = n.tip_hash.clone();
                                    let mp = n.mempool.len();
                                    let no_app = n.pack_no_applicable;
                                    let applicable = n.has_applicable_tx();
                                    if applicable {
                                        warn!("pack produced no block with an applicable tx h={h} mp={mp}");
                                    }
                                    let skip_sig = n.sign_skip_vote(h, &my_id, &tip);
                                    drop(n);
                                    if skipped {
                                        let skip = WireMsg::SkipPacker {
                                            height: h,
                                            packer: my_id.clone(),
                                            tip_hash: tip,
                                            voter: my_id.clone(),
                                            signature: skip_sig,
                                        };
                                        if let Ok(line) = serde_json::to_string(&skip) {
                                            shared_c.fan_line(&fanout, line + "\n");
                                        }
                                    } else if mp > 0
                                        && !applicable
                                        && no_app > 0
                                        && ntick % 25 == 0
                                    {
                                        debug!(
                                            "pack wait: mp={mp} no_applicable_total={no_app} h={h} (seq gaps)"
                                        );
                                    }
                                }
                                Err(e)
                                    if e.contains("not lottery")
                                        || e.contains("pong stale")
                                        || e.contains("tip lag")
                                        || e.contains("soft")
                                        || e.contains("pending") =>
                                {
                                    let h = n.tip_height.saturating_add(1);
                                    shared_c.note_walk_ready(h, n.packable_tx_count(), &e);
                                }
                                Err(e) => {
                                    let h = n.tip_height.saturating_add(1);
                                    shared_c.note_walk_ready(h, n.packable_tx_count(), &e);
                                    warn!("pack: {e}");
                                }
                            }
                            } // end else pack after NeedTxs grace
                        }
                    }
                }
                // Live tip gossip only (last sealed ledger). Full history is
                // pull-based via NeedLedgers → LedgersBatch (directed). The old
                // 128-ledger mesh rebroadcast caused dual-host catch-up storms.
                if ntick % 4 == 0 {
                    let n = shared_c.node.lock();
                    if let Some(led) = n.chain.last() {
                        let msg = propose_header(led);
                        drop(n);
                        shared_c.fan_msg(&fanout, &msg);
                    }
                }
                if ntick % 150 == 0 {
                    let mut n_out = 0usize;
                    let mut out_bytes = 0usize;
                    for p in fanout.iter() {
                        if !p.peer_id.lock().is_empty() {
                            n_out += 1;
                        }
                        out_bytes += p.cons.used.load(std::sync::atomic::Ordering::Relaxed)
                            + p.txq.used.load(std::sync::atomic::Ordering::Relaxed)
                            + p.bodyq.used.load(std::sync::atomic::Ordering::Relaxed)
                            + p.catchq.used.load(std::sync::atomic::Ordering::Relaxed);
                    }
                    let inbound = shared_c.inbound.lock();
                    let n_in = inbound.len();
                    let in_bytes: usize = inbound
                        .iter()
                        .map(|s| s.tx.used.load(std::sync::atomic::Ordering::Relaxed))
                        .sum();
                    drop(inbound);
                    let socks = shared_c.sock_summary();
                    info!("mesh sockets outbound={n_out} inbound={n_in} queued_out={out_bytes} queued_in={in_bytes} live={socks}");
                }
            }
        });
    }

    if !args.admin_sock.is_empty() {
        let shared_a = shared.clone();
        let fanout_a = fanout.clone();
        let sock = args.admin_sock.clone();
        tokio::spawn(async move {
            admin_sock_loop(sock, shared_a, fanout_a).await;
        });
    }

    let listener = TcpListener::bind(&args.listen).await?;
    info!(
        "{NETWORK_NAME} product={PRODUCT_VERSION} id={} role={} archive={} hub={} chain_cap={} listen={} scheme={} peers={} admin_sock={} allow_admin_wire={}",
        args.id,
        role.map(NodeRole::as_str).unwrap_or("node"),
        args.archive,
        args.hub,
        args.max_chain_ledgers,
        args.listen,
        scheme.as_str(),
        fanout.len(),
        if args.admin_sock.is_empty() {
            "-"
        } else {
            args.admin_sock.as_str()
        },
        allow_admin
    );

    loop {
        let (stream, addr) = listener.accept().await?;
        let shared_c = shared.clone();
        let fanout_c = fanout.clone();
        let my_id = args.id.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_inbound(stream, shared_c, fanout_c, &my_id).await {
                warn!("session {addr}: {e}");
            }
        });
    }
}

/// Keep one TCP connection open; write queued lines; also read inbound on same socket.
async fn peer_writer_loop(
    peer: String,
    mut cons_rx: mpsc::Receiver<String>,
    mut tx_rx: mpsc::Receiver<String>,
    mut body_rx: mpsc::Receiver<String>,
    mut catch_rx: mpsc::Receiver<String>,
    cons_used: Arc<std::sync::atomic::AtomicUsize>,
    tx_used: Arc<std::sync::atomic::AtomicUsize>,
    body_used: Arc<std::sync::atomic::AtomicUsize>,
    catch_used: Arc<std::sync::atomic::AtomicUsize>,
    shared: Arc<Shared>,
    fanout: Arc<Vec<PeerOut>>,
    my_id: String,
    peer_id: Arc<parking_lot::Mutex<String>>,
) {
    loop {
        if shared.peer_blackholed(&peer) {
            tokio::time::sleep(std::time::Duration::from_secs(BLACKHOLE_SECS)).await;
            continue;
        }
        match TcpStream::connect(&peer).await {
            Ok(stream) => {
                info!("persistent peer {peer}");
                shared.sock_add(&peer, 1);
                if let Err(e) = peer_session(
                    stream,
                    &mut cons_rx,
                    &mut tx_rx,
                    &mut body_rx,
                    &mut catch_rx,
                    &cons_used,
                    &tx_used,
                    &body_used,
                    &catch_used,
                    shared.clone(),
                    fanout.clone(),
                    &my_id,
                    peer_id.clone(),
                )
                .await
                {
                    warn!("peer {peer} session: {e}");
                    if e.downcast_ref::<PipeShed>().is_some() {
                        shared.blackhole_peer(&peer);
                        shared.blackhole_peer(&peer_id.lock());
                        while let Ok(line) = tx_rx.try_recv() {
                            recved(&tx_used, line.len());
                        }
                        while let Ok(line) = body_rx.try_recv() {
                            recved(&body_used, line.len());
                        }
                        tokio::time::sleep(std::time::Duration::from_secs(BLACKHOLE_SECS)).await;
                    } else if e.downcast_ref::<YieldDial>().is_some() {
                        shared.blackhole_peer(&peer);
                        info!("yield dial {peer}: lower seat id connects to us");
                        tokio::time::sleep(std::time::Duration::from_secs(YIELD_DIAL_SECS)).await;
                    } else if e.downcast_ref::<HelloRejected>().is_some() {
                        tokio::time::sleep(std::time::Duration::from_secs(
                            HELLO_REJECT_REDIAL_SECS,
                        ))
                        .await;
                    }
                }
                shared.sock_add(&peer, -1);
            }
            Err(e) => {
                warn!("connect {peer}: {e}");
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
}

async fn peer_session(
    stream: TcpStream,
    cons_rx: &mut mpsc::Receiver<String>,
    tx_rx: &mut mpsc::Receiver<String>,
    body_rx: &mut mpsc::Receiver<String>,
    catch_rx: &mut mpsc::Receiver<String>,
    cons_used: &std::sync::atomic::AtomicUsize,
    tx_used: &std::sync::atomic::AtomicUsize,
    body_used: &std::sync::atomic::AtomicUsize,
    catch_used: &std::sync::atomic::AtomicUsize,
    shared: Arc<Shared>,
    fanout: Arc<Vec<PeerOut>>,
    my_id: &str,
    peer_id: Arc<parking_lot::Mutex<String>>,
) -> Result<()> {
    stream.set_nodelay(true)?;
    let probe = unsafe { libc::dup(stream.as_raw_fd()) };
    let (reader, mut writer) = stream.into_split();

    // hello (includes tip so peer can start pull catch-up immediately).
    // **Validators only** in publics — never dump load-wallet keyring (was ~1.9MB
    // Falcon Hello with 1024 wallets; filled TCP and blocked catch-up).
    let hello_line = {
        let n = shared.node.lock();
        let mut validators = BTreeMap::new();
        let mut publics = BTreeMap::new();
        for (id, v) in &n.validators {
            validators.insert(id.clone(), v.bond);
            if let Some(pk) = n.keys.public_hex(id) {
                publics.insert(id.clone(), pk);
            } else if !v.public_key.is_empty() {
                publics.insert(id.clone(), v.public_key.clone());
            }
        }
        // Always include self packer key.
        if let Some(pk) = n.keys.public_hex(my_id) {
            publics.insert(my_id.to_string(), pk);
        }
        let hello = WireMsg::Hello {
            id: my_id.to_string(),
            public_key: n.keys.public_hex(my_id).unwrap_or_default(),
            validators,
            publics,
            tip_height: n.tip_height,
            tip_hash: n.tip_hash.clone(),
            is_hub: n.is_hub,
            mempool_len: n.mempool.len() as u64,
            product_version: fd_pl::HELLO_WIRE_VERSION.to_string(),
            hello_network_id: n.cfg.network_id,
            archive: shared.is_archive,
            snap_height: shared
                .snap_meta
                .lock()
                .as_ref()
                .map(|m| m.tip)
                .unwrap_or(0),
            release_version: PRODUCT_VERSION.to_string(),
            capabilities: fd_pl::utc_header::local_hello_capabilities(),
        };
        serde_json::to_string(&hello)? + "\n"
    };
    writer.write_all(hello_line.as_bytes()).await?;

    let shared_r = shared.clone();
    let fanout_r = fanout.clone();
    // Split directed replies: catch-up (LedgersBatch) must never be starved by
    // TxsBatch / Ok spam under load (v2.6.0 multi-host tip=0 freeze).
    let (catchup_tx, mut catchup_rx) =
        mpsc::channel::<String>(catch_lane_cap("FALCON_PL_TEST_OUTBOUND_CATCH_CAP", 512));
    let catch_drain = catch_drain_delay();
    let (reply_tx, mut reply_rx) = mpsc::channel::<String>(WIRE_QUEUE_CAP.max(TX_QUEUE_CAP / 4));
    // v2.9.60: when the Hello gate refuses the peer the read task stores the
    // reason here and exits; the write loop stops (its reply channels close),
    // sends `Err` and ends the session. A slot, not the task's return value:
    // the biased select can see a closed reply channel before the task.
    let yield_dial = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let yield_dial_r = yield_dial.clone();
    let my_id_r = my_id.to_string();
    let peer_id_w = peer_id.clone();
    let hello_rejected: Arc<parking_lot::Mutex<Option<String>>> =
        Arc::new(parking_lot::Mutex::new(None));
    let hello_rejected_r = hello_rejected.clone();
    let mut read_task = tokio::spawn(async move {
        let mut lines = BufReader::new(reader).lines();
        let mut gate = HelloSession::default();
        let mut asm = fd_pl::pieces::PieceAssembler::default();
        while let Ok(Some(line)) = lines.next_line().await {
            if line.trim().is_empty() {
                continue;
            }
            let who_r = peer_id.lock().clone();
            let Some(line) = unpiece_line(&mut asm, &who_r, line) else {
                continue;
            };
            let Ok(msg) = serde_json::from_str::<WireMsg>(&line) else {
                continue;
            };
            {
                if let WireMsg::Hello { id, .. } = &msg {
                    *peer_id.lock() = id.clone();
                    if !we_dial(&my_id_r, id) {
                        yield_dial_r.store(true, std::sync::atomic::Ordering::Relaxed);
                    }
                }
                if HelloSession::needs_check(&msg) {
                    let verdict = gate.check(&shared_r.node.lock(), &msg);
                    match verdict {
                        HelloGate::Pass => {}
                        HelloGate::Drop => continue,
                        HelloGate::Close(reason) => {
                            warn!("hello gate close outbound {}: {reason}", peer_id.lock());
                            *hello_rejected_r.lock() = Some(reason);
                            return;
                        }
                    }
                }
                let session_peer = peer_id.lock().clone();
                // Keep legacy tag for any residual readers; session_peer is authoritative.
                *shared_r.wire_from.lock() = session_peer.clone();
                let budget = fd_pl::snap_push_budget(catchup_tx.capacity(), snapshot_push_max());
                for reply in dispatch_wire(
                    &shared_r,
                    msg,
                    Some(&fanout_r),
                    false,
                    false,
                    &session_peer,
                    budget,
                ) {
                    if let Ok(s) = serde_json::to_string(&reply) {
                        let out = s + "\n";
                        let is_catchup = matches!(
                            reply,
                            WireMsg::LedgersBatch { .. }
                                | WireMsg::SnapshotOffer { .. }
                                | WireMsg::SnapshotChunk { .. }
                                | WireMsg::SnapshotNo { .. }
                        );
                        let pieces = shared_r.pieces_for(&session_peer, &out);
                        if is_catchup {
                            if is_snap_control(&reply) {
                                let (ok, polls) = reply_send_control_wait(&catchup_tx, out, pieces).await;
                                if !ok {
                                    warn!("snapshot control reply failed after {polls} waits (catchup queue full)");
                                } else if polls > 0 {
                                    info!("snapshot control reply sent after {polls} waits (lane full) to={session_peer}");
                                }
                            } else if !reply_send_pieced(&catchup_tx, out, pieces) {
                                // Data: skip under pressure; joiner hole-fills / retries.
                                note_catch_defer("outbound", &reply, &session_peer);
                            }
                        } else {
                            let _ = reply_send_pieced(&reply_tx, out, pieces);
                        }
                    }
                }
            }
        }
    });

    let mut high_since = None;
    let mut last_unsent = 0usize;
    let mut last_unread = 0usize;
    let mut dish_since: Option<tokio::time::Instant> = None;
    let mut succ_hold: std::collections::VecDeque<String> = std::collections::VecDeque::new();
    let mut inv_left = 0usize;
    loop {
        if yield_dial.load(std::sync::atomic::Ordering::Relaxed) {
            read_task.abort();
            unsafe { libc::close(probe) };
            return Err(YieldDial.into());
        }
        if let Some((which, unsent, unread)) = pipe_stuck(probe, &mut high_since, &mut last_unsent, &mut last_unread) {
            let who = peer_id_w.lock().clone();
            warn!(
                "shed stuck outbound pipe to {who} reason={which} unsent={unsent} unread={unread}"
            );
            hard_reset(probe);
            read_task.abort();
            unsafe { libc::close(probe) };
            return Err(PipeShed.into());
        }
        let who = peer_id_w.lock().clone();
        if dish_since.is_some() && !dish_blocking(&dish_since, probe) {
            let why = if dish_since.unwrap().elapsed() >= DISH_GATE {
                "timeout"
            } else {
                "release"
            };
            if let Some(line) = succ_hold.pop_front() {
                info!(
                    "dish-gate {why} to {who} unsent={}",
                    tcp_unsent(probe).unwrap_or(0)
                );
                if emit_or_shed(&mut writer, probe, line.as_bytes(), &who, "outbound").await.is_err() {
                    read_task.abort();
                    unsafe { libc::close(probe) };
                    return Err(PipeShed.into());
                }
                if succ_hold.is_empty() {
                    dish_since = None;
                    inv_left = 0;
                }
                continue;
            }
            dish_since = None;
            inv_left = 0;
        }
        // Start a dish ahead of votes. Once it is written, votes and a small
        // inventory budget go first and the id body stays held.
        if dish_since.is_none() {
            if let Ok(line) = body_rx.try_recv() {
                recved(body_used, line.len());
                if is_tx_dish(line.as_bytes()) {
                    if emit_or_shed(&mut writer, probe, line.as_bytes(), &who, "outbound").await.is_err() {
                        read_task.abort();
                        unsafe { libc::close(probe) };
                        return Err(PipeShed.into());
                    }
                    dish_since = Some(tokio::time::Instant::now());
                    inv_left = DISH_INV_BUDGET;
                    continue;
                }
                if emit_or_shed(&mut writer, probe, line.as_bytes(), &who, "outbound").await.is_err() {
                    read_task.abort();
                    unsafe { libc::close(probe) };
                    return Err(PipeShed.into());
                }
                continue;
            }
        }
        // Lanes: LedgersBatch reply → other reply → cons → NeedLedgers → body → inventory.
        tokio::select! {
            biased;
            line = catchup_rx.recv() => {
                match line {
                    Some(line) => {
                        if emit_or_shed(&mut writer, probe, line.as_bytes(), &who, "outbound").await.is_err() {
                            read_task.abort();
                            unsafe { libc::close(probe) };
                            return Err(PipeShed.into());
                        }
                        if line.len() > LARGE_LINE {
                            Shared::clear_large_out(&fanout, &who);
                        }
                        if let Some(d) = catch_drain {
                            tokio::time::sleep(d).await;
                        }
                    }
                    None => break,
                }
            }
            line = reply_rx.recv() => {
                match line {
                    Some(line) => {
                        if emit_or_shed(&mut writer, probe, line.as_bytes(), &who, "outbound").await.is_err() {
                            read_task.abort();
                            unsafe { libc::close(probe) };
                            return Err(PipeShed.into());
                        }
                    }
                    None => break,
                }
            }
            line = cons_rx.recv() => {
                match line {
                    Some(line) => {
                        recved(cons_used, line.len());
                        if emit_or_shed(&mut writer, probe, line.as_bytes(), &who, "outbound").await.is_err() {
                            read_task.abort();
                            unsafe { libc::close(probe) };
                            return Err(PipeShed.into());
                        }
                    }
                    None => break,
                }
            }
            line = catch_rx.recv() => {
                match line {
                    Some(line) => {
                        recved(catch_used, line.len());
                        if emit_or_shed(&mut writer, probe, line.as_bytes(), &who, "outbound").await.is_err() {
                            read_task.abort();
                            unsafe { libc::close(probe) };
                            return Err(PipeShed.into());
                        }
                    }
                    None => break,
                }
            }
            line = body_rx.recv() => {
                match line {
                    Some(line) => {
                        recved(body_used, line.len());
                        if is_tx_dish(line.as_bytes()) {
                            succ_hold.clear();
                            if emit_or_shed(&mut writer, probe, line.as_bytes(), &who, "outbound").await.is_err() {
                                read_task.abort();
                                unsafe { libc::close(probe) };
                                return Err(PipeShed.into());
                            }
                            dish_since = Some(tokio::time::Instant::now());
                            inv_left = DISH_INV_BUDGET;
                        } else if is_body_successor(line.as_bytes()) && dish_blocking(&dish_since, probe) {
                            succ_hold.push_back(line);
                        } else if emit_or_shed(&mut writer, probe, line.as_bytes(), &who, "outbound").await.is_err() {
                            read_task.abort();
                            unsafe { libc::close(probe) };
                            return Err(PipeShed.into());
                        }
                    }
                    None => break,
                }
            }
            line = tx_rx.recv() => {
                match line {
                    Some(line) => {
                        recved(tx_used, line.len());
                        // Inventory yields the socket to a ledger body. The
                        // peer refetches a dropped transaction batch.
                        // A dish already in the kernel may still take a short budget.
                        let unsent = tcp_unsent(probe).unwrap_or(0);
                        // Transaction relay has its own budget. A body in the
                        // kernel buffer must not throw the transaction away.
                        if is_tx_relay(line.as_bytes()) {
                            if unsent > TX_RELAY_BUDGET {
                                shared.hold_unsent_tx_line(&line);
                                continue;
                            }
                        } else if unsent > CONS_LOW_WATER && inv_left < line.len() {
                            if line.len() > LARGE_LINE {
                                Shared::clear_large_out(&fanout, &who);
                            }
                            continue;
                        }
                        if unsent > CONS_LOW_WATER {
                            inv_left = inv_left.saturating_sub(line.len());
                        }
                        if emit_or_shed(&mut writer, probe, line.as_bytes(), &who, "outbound").await.is_err() {
                            read_task.abort();
                            unsafe { libc::close(probe) };
                            return Err(PipeShed.into());
                        }
                        if line.len() > LARGE_LINE {
                            Shared::clear_large_out(&fanout, &who);
                        }
                    }
                    None => break,
                }
            }
            _ = &mut read_task => break,
            _ = tokio::time::sleep(std::time::Duration::from_secs(1)) => {}
        }
    }
    read_task.abort();
    unsafe { libc::close(probe) };
    let rejected = hello_rejected.lock().take();
    if let Some(reason) = rejected {
        let who = peer_id_w.lock().clone();
        if let Ok(s) = serde_json::to_string(&WireMsg::Err { msg: reason.clone() }) {
            let _ = writer.write_all((s + "\n").as_bytes()).await;
        }
        let _ = writer.shutdown().await;
        return Err(HelloRejected(format!("{who}: {reason}")).into());
    }
    Ok(())
}

/// Session ended because the peer's Hello (or a later Pong re-check after the
/// Gloas gate) was refused. The dial loop backs off before redialing.
#[derive(Debug)]
struct HelloRejected(String);

impl std::fmt::Display for HelloRejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "hello rejected: {}", self.0)
    }
}

impl std::error::Error for HelloRejected {}

/// Kernel send queue stayed over 1 MB. Redial after dropping the inventory queue.
#[derive(Debug)]
struct PipeShed;

impl std::fmt::Display for PipeShed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "shed stuck pipe")
    }
}

impl std::error::Error for PipeShed {}

/// Redial delay after a refused Hello (a pre-2.9.60 peer after H stays
/// refused until it is upgraded; do not reconnect twice a second).
const HELLO_REJECT_REDIAL_SECS: u64 = 10;
/// Lower seat id dials. After a hello shows we are the higher id, stay
/// quiet this long so both sides do not redial at once.
const YIELD_DIAL_SECS: u64 = 60;

/// The peer's id is lower or equal, so they dial us. Do not redial immediately.
#[derive(Debug)]
struct YieldDial;

impl std::fmt::Display for YieldDial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "peer dials us")
    }
}

impl std::error::Error for YieldDial {}

/// Lower id dials. Equal ids are a self-dial and must stop.
struct SockCount {
    shared: Arc<Shared>,
    key: String,
}

impl Drop for SockCount {
    fn drop(&mut self) {
        self.shared.sock_add(&self.key, -1);
    }
}

/// Inbound-session catch-up reply lane depth (matches the outbound session).
const INBOUND_CATCHUP_REPLY_CAP: usize = 512;

/// Directed catch-up replies that must not share the general reply queue.
fn is_catchup_reply(m: &WireMsg) -> bool {
    matches!(
        m,
        WireMsg::LedgersBatch { .. }
            | WireMsg::SnapshotOffer { .. }
            | WireMsg::SnapshotChunk { .. }
            | WireMsg::SnapshotNo { .. }
    )
}

/// Ok/Err acks a mesh peer never reads (its process_msg returns None for them).
fn is_peer_ack(m: &WireMsg) -> bool {
    matches!(m, WireMsg::Ok { .. } | WireMsg::Err { .. })
}

/// Whether an inbound reply should be suppressed because the session has
/// completed `Hello` as a mesh peer and the reply is an unread `Ok`/`Err` ack.
fn should_drop_inbound_reply(inbound_registered: bool, was_hello: bool, reply: &WireMsg) -> bool {
    inbound_registered && !was_hello && is_peer_ack(reply)
}

/// Minimum interval (10s) between `inbound reply dropped` warnings across seats.
const REPLY_DROP_LOG_INTERVAL_MS: u64 = 10_000;
static REPLY_DROP_LAST_MS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static REPLY_DROP_SUPPRESSED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Rate-limit `inbound reply dropped` warnings to at most once every
/// `REPLY_DROP_LOG_INTERVAL_MS`. Returns `Some(suppressed_count)` when a log
/// line should be emitted and `None` when suppressed.
fn should_log_reply_dropped(
    now_ms: u64,
    last_ms: &std::sync::atomic::AtomicU64,
    suppressed: &std::sync::atomic::AtomicU64,
) -> Option<u64> {
    use std::sync::atomic::Ordering::Relaxed;
    let prev = last_ms.load(Relaxed);
    if prev == 0 || now_ms.saturating_sub(prev) >= REPLY_DROP_LOG_INTERVAL_MS {
        if last_ms
            .compare_exchange(prev, now_ms.max(1), Relaxed, Relaxed)
            .is_ok()
        {
            return Some(suppressed.swap(0, Relaxed));
        }
    }
    suppressed.fetch_add(1, Relaxed);
    None
}

fn we_dial(my_id: &str, peer_id: &str) -> bool {
    my_id < peer_id
}

async fn handle_inbound(
    stream: TcpStream,
    shared: Arc<Shared>,
    fanout: Arc<Vec<PeerOut>>,
    my_id: &str,
) -> Result<()> {
    let _ = stream.set_nodelay(true);
    let remote = stream
        .peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_default();
    shared.sock_add(&remote, 1);
    let _sock = SockCount {
        shared: shared.clone(),
        key: remote.clone(),
    };
    let probe = unsafe { libc::dup(stream.as_raw_fd()) };
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();

    // Register sink so mesh fanout (Pong/ProposeLedger/Skip) reaches joiners
    // that dialed us but are not on our --peers list.
    // Only mesh peers that send Hello get inbound fan. ctl / load-net never
    // Hello — registering them used to dump ProposeLedger/Pong onto the same
    // TCP as Status/SubmitTx (Recv-Q hang past --seconds; ctl tip=-1).
    let inbound_used = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let (inbound_raw, mut inbound_rx) = mpsc::channel::<String>(WIRE_QUEUE_CAP);
    let inbound_tx = ByteTx {
        tx: inbound_raw,
        used: inbound_used.clone(),
        cap: WIRE_QUEUE_BYTES,
    };
    let close_me = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut inbound_registered = false;
    let mut seen_id = String::new();
    let mut gate = HelloSession::default();

    let hello_line = {
        let n = shared.node.lock();
        let mut validators = BTreeMap::new();
        let mut publics = BTreeMap::new();
        for (id, v) in &n.validators {
            validators.insert(id.clone(), v.bond);
            if let Some(pk) = n.keys.public_hex(id) {
                publics.insert(id.clone(), pk);
            } else if !v.public_key.is_empty() {
                publics.insert(id.clone(), v.public_key.clone());
            }
        }
        if let Some(pk) = n.keys.public_hex(my_id) {
            publics.insert(my_id.to_string(), pk);
        }
        let hello = WireMsg::Hello {
            id: my_id.to_string(),
            public_key: n.keys.public_hex(my_id).unwrap_or_default(),
            validators,
            publics,
            tip_height: n.tip_height,
            tip_hash: n.tip_hash.clone(),
            is_hub: n.is_hub,
            mempool_len: n.mempool.len() as u64,
            product_version: fd_pl::HELLO_WIRE_VERSION.to_string(),
            hello_network_id: n.cfg.network_id,
            archive: shared.is_archive,
            snap_height: shared
                .snap_meta
                .lock()
                .as_ref()
                .map(|m| m.tip)
                .unwrap_or(0),
            release_version: PRODUCT_VERSION.to_string(),
            capabilities: fd_pl::utc_header::local_hello_capabilities(),
        };
        serde_json::to_string(&hello)? + "\n"
    };
    writer.write_all(hello_line.as_bytes()).await?;

    // Writer is its own task. The reader must keep pulling bytes while a
    // large send sits in the kernel buffer. One task doing both is why
    // inbound receive queues grew into the megabytes.
    let (reply_tx, mut reply_rx) = mpsc::channel::<String>(64);
    // 2.9.79 upgrade stall: catch-up replies (LedgersBatch / snapshot) get
    // their own lane, as on the outbound session. Sharing the 64-slot reply
    // queue with Ok/Err/tx replies dropped them on a busy hub (v3: ~100
    // "inbound reply dropped"/s), so a restarted seat that dials the hub
    // never got a ledger back and stalled until a second restart.
    let (catch_reply_tx, mut catch_reply_rx) = mpsc::channel::<String>(catch_lane_cap(
        "FALCON_PL_TEST_INBOUND_CATCH_CAP",
        INBOUND_CATCHUP_REPLY_CAP,
    ));
    let catch_drain_w = catch_drain_delay();
    let close_w = close_me.clone();
    let shed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let shed_w = shed.clone();
    let large_out = Arc::new(LargeGate::new());
    let large_w = large_out.clone();
    let remote_w = remote.clone();
    let shared_w = shared.clone();
    let mut writer_task = tokio::spawn(async move {
        let mut high_since = None;
        let mut last_unsent = 0usize;
        let mut last_unread = 0usize;
        let mut dish_since: Option<tokio::time::Instant> = None;
        let mut succ_hold: std::collections::VecDeque<String> = std::collections::VecDeque::new();
        let mut inv_left = 0usize;
        loop {
            if close_w.load(std::sync::atomic::Ordering::Relaxed) {
                break;
            }
            if let Some((which, unsent, unread)) = pipe_stuck(probe, &mut high_since, &mut last_unsent, &mut last_unread) {
                warn!(
                    "shed stuck inbound pipe from {remote_w} reason={which} unsent={unsent} unread={unread}"
                );
                shed_w.store(true, std::sync::atomic::Ordering::Relaxed);
                hard_reset(probe);
                break;
            }
            if dish_since.is_some() && !dish_blocking(&dish_since, probe) {
                if let Some(line) = succ_hold.pop_front() {
                    info!(
                        "dish-gate {} inbound {remote_w} unsent={}",
                        if dish_since.unwrap().elapsed() >= DISH_GATE { "timeout" } else { "release" },
                        tcp_unsent(probe).unwrap_or(0)
                    );
                    if emit_or_shed(&mut writer, probe, line.as_bytes(), &remote_w, "inbound").await.is_err() {
                        shed_w.store(true, std::sync::atomic::Ordering::Relaxed);
                        break;
                    }
                    if succ_hold.is_empty() {
                        dish_since = None;
                        inv_left = 0;
                    }
                    continue;
                }
                dish_since = None;
                inv_left = 0;
            }
            tokio::select! {
                biased;
                line = catch_reply_rx.recv() => {
                    match line {
                        Some(line) => {
                            if emit_or_shed(&mut writer, probe, line.as_bytes(), &remote_w, "inbound").await.is_err() {
                                shed_w.store(true, std::sync::atomic::Ordering::Relaxed);
                                break;
                            }
                            if let Some(d) = catch_drain_w {
                                tokio::time::sleep(d).await;
                            }
                        }
                        None => break,
                    }
                }
                line = reply_rx.recv() => {
                    match line {
                        Some(line) => {
                            if emit_or_shed(&mut writer, probe, line.as_bytes(), &remote_w, "inbound").await.is_err() {
                                shed_w.store(true, std::sync::atomic::Ordering::Relaxed);
                                break;
                            }
                        }
                        None => break,
                    }
                }
                line = inbound_rx.recv() => {
                    match line {
                        Some(line) => {
                            recved(&inbound_used, line.len());
                            let unsent = tcp_unsent(probe).unwrap_or(0);
                            if is_tx_relay(line.as_bytes()) {
                                if unsent > TX_RELAY_BUDGET {
                                    shared_w.hold_unsent_tx_line(&line);
                                    continue;
                                }
                            } else if is_tx_dish(line.as_bytes()) {
                                succ_hold.clear();
                            } else if is_body_successor(line.as_bytes()) && dish_blocking(&dish_since, probe) {
                                succ_hold.push_back(line);
                                continue;
                            } else if !line_must_send(line.as_bytes()) && unsent > CONS_LOW_WATER {
                                if inv_left < line.len() {
                                    if line.len() > LARGE_LINE {
                                        large_w.clear();
                                    }
                                    continue;
                                }
                                inv_left = inv_left.saturating_sub(line.len());
                            }
                            if emit_or_shed(&mut writer, probe, line.as_bytes(), &remote_w, "inbound").await.is_err() {
                                shed_w.store(true, std::sync::atomic::Ordering::Relaxed);
                                break;
                            }
                            if is_tx_dish(line.as_bytes()) {
                                dish_since = Some(tokio::time::Instant::now());
                                inv_left = DISH_INV_BUDGET;
                            }
                            if line.len() > LARGE_LINE {
                                large_w.clear();
                            }
                        }
                        None => break,
                    }
                }
                _ = tokio::time::sleep(std::time::Duration::from_secs(1)) => {}
            }
        }
        unsafe { libc::close(probe) };
    });

    let enqueue = |reply_tx: &mpsc::Sender<String>, line: String| {
        if reply_tx.try_send(line).is_err() {
            if let Some(suppressed) =
                should_log_reply_dropped(unix_ms(), &REPLY_DROP_LAST_MS, &REPLY_DROP_SUPPRESSED)
            {
                if suppressed == 0 {
                    warn!("inbound reply dropped");
                } else {
                    warn!("inbound reply dropped (suppressed={suppressed})");
                }
            }
        }
    };

    let mut asm = fd_pl::pieces::PieceAssembler::default();
    while let Ok(Some(line)) = lines.next_line().await {
        if close_me.load(std::sync::atomic::Ordering::Relaxed) || writer_task.is_finished() {
            break;
        }
        if line.trim().is_empty() {
            continue;
        }
        let Some(line) = unpiece_line(&mut asm, &seen_id, line) else {
            continue;
        };
        let msg: WireMsg = match serde_json::from_str(&line) {
            Ok(m) => m,
            Err(e) => {
                let err = serde_json::to_string(&WireMsg::Err { msg: e.to_string() })? + "\n";
                enqueue(&reply_tx, err);
                continue;
            }
        };
        if HelloSession::needs_check(&msg) {
            let verdict = gate.check(&shared.node.lock(), &msg);
            match verdict {
                HelloGate::Pass => {}
                HelloGate::Drop => continue,
                HelloGate::Close(reason) => {
                    warn!("hello gate close inbound {remote}: {reason}");
                    let err = serde_json::to_string(&WireMsg::Err {
                        msg: reason.clone(),
                    })? + "\n";
                    enqueue(&reply_tx, err);
                    close_me.store(true, std::sync::atomic::Ordering::Relaxed);
                    writer_task.abort();
                    return Err(HelloRejected(reason).into());
                }
            }
        }
        if !inbound_registered {
            if let WireMsg::Hello { id, .. } = &msg {
                if we_dial(my_id, id) {
                    info!("refuse inbound from {id}: we dial them");
                    close_me.store(true, std::sync::atomic::Ordering::Relaxed);
                    break;
                }
                if shared.peer_blackholed(id) {
                    info!("refuse inbound from {id}: blackhole");
                    close_me.store(true, std::sync::atomic::Ordering::Relaxed);
                    break;
                }
                seen_id = id.clone();
                shared.close_inbound_seat(id);
                shared.inbound.lock().push(InboundSink {
                    id: id.clone(),
                    tx: inbound_tx.clone(),
                    close: close_me.clone(),
                    large_out: large_out.clone(),
                });
                inbound_registered = true;
            }
        }
        let was_hello = matches!(msg, WireMsg::Hello { .. });
        // Session peer is Hello-validated `seen_id` only (immutable for this call).
        let session_peer = seen_id.as_str();
        let budget = fd_pl::snap_push_budget(catch_reply_tx.capacity(), snapshot_push_max());
        let replies = dispatch_wire(
            &shared,
            msg,
            Some(&fanout),
            true,
            false,
            session_peer,
            budget,
        );
        for r in replies {
            let out = serde_json::to_string(&r)? + "\n";
            let pieces = shared.pieces_for(session_peer, &out);
            if is_catchup_reply(&r) {
                if is_snap_control(&r) {
                    // Offer / SnapshotNo: retry so resume control is not lost.
                    let (ok, polls) = reply_send_control_wait(&catch_reply_tx, out, pieces).await;
                    if !ok {
                        warn!("inbound snapshot control reply failed after {polls} waits (lane full) to={session_peer}");
                    } else if polls > 0 {
                        info!("inbound snapshot control reply sent after {polls} waits (lane full) to={session_peer}");
                    }
                } else if !reply_send_pieced(&catch_reply_tx, out, pieces) {
                    // SnapshotChunk / LedgersBatch: credit-aware skip under pressure.
                    note_catch_defer("inbound", &r, session_peer);
                }
            } else if should_drop_inbound_reply(inbound_registered, was_hello, &r) {
                // Hello'd mesh peer: it discards Ok/Err (process_msg -> None),
                // so acks to gossip (header-known, voted, buffered/dup, tx
                // duplicate ...) only filled the 64-slot queue (~2.5k
                // "inbound reply dropped"/min on v3) and crowded out data
                // replies (NeedLedgerBody, TxsBatch, NeedMempoolTxs).
                // Clients (no Hello) still get every ack.
                continue;
            } else if pieces.is_some() {
                if !reply_send_pieced(&reply_tx, out, pieces) {
                    warn!("inbound pieced reply dropped");
                }
            } else {
                enqueue(&reply_tx, out);
            }
        }
    }
    close_me.store(true, std::sync::atomic::Ordering::Relaxed);
    drop(reply_tx);
    drop(catch_reply_tx);
    let _ = writer_task.await;
    if shed.load(std::sync::atomic::Ordering::Relaxed) && !seen_id.is_empty() {
        shared.blackhole_peer(&seen_id);
        shared.close_inbound_seat(&seen_id);
        warn!("shed removed inbound {seen_id} remote={remote}");
    }
    Ok(())
}

async fn admin_sock_loop(path: String, shared: Arc<Shared>, fanout: Arc<Vec<PeerOut>>) {
    let p = PathBuf::from(&path);
    if p.exists() {
        let _ = std::fs::remove_file(&p);
    }
    if let Some(parent) = p.parent() {
        if !parent.as_os_str().is_empty() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                warn!("admin sock mkdir {}: {e}", parent.display());
                return;
            }
        }
    }
    let listener = match UnixListener::bind(&p) {
        Ok(l) => l,
        Err(e) => {
            warn!("admin sock bind {path}: {e}");
            return;
        }
    };
    if let Err(e) = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)) {
        warn!("admin sock chmod {path}: {e}");
    }
    info!("admin sock listening {path} mode=0600");
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let shared_c = shared.clone();
                let fanout_c = fanout.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_admin(stream, shared_c, fanout_c).await {
                        warn!("admin session: {e}");
                    }
                });
            }
            Err(e) => {
                warn!("admin accept: {e}");
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            }
        }
    }
}

/// Operator unix session: JSON-line WireMsg, no Hello, no mesh inbound fan.
async fn handle_admin(
    stream: UnixStream,
    shared: Arc<Shared>,
    fanout: Arc<Vec<PeerOut>>,
) -> Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();
    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        let msg: WireMsg = match serde_json::from_str(&line) {
            Ok(m) => m,
            Err(e) => {
                let err = serde_json::to_string(&WireMsg::Err { msg: e.to_string() })? + "\n";
                writer.write_all(err.as_bytes()).await?;
                continue;
            }
        };
        let replies = dispatch_wire(&shared, msg, Some(&fanout), true, true, "admin", SNAPSHOT_PUSH_MAX);
        for r in replies {
            let out = serde_json::to_string(&r)? + "\n";
            writer.write_all(out.as_bytes()).await?;
        }
    }
    Ok(())
}

/// Publish a fresh join snap when live tip moved ahead of the pinned serve file.
fn refresh_archive_serve_snapshot(shared: &Shared) {
    if !shared.is_archive || shared.snapshot_out.as_os_str().is_empty() {
        return;
    }
    let _publish = shared.snap_publish.lock();
    let path = shared.snapshot_out.clone();
    let (live_tip, tip_hash, pin_tip) = {
        let n = shared.node.lock();
        let pin = shared
            .snap_meta
            .lock()
            .as_ref()
            .map(|m| m.tip)
            .unwrap_or(0);
        (n.tip_height, n.tip_hash.clone(), pin)
    };
    if live_tip <= pin_tip {
        return;
    }
    // Same rule as the periodic saver: a joiner mid-download keeps this pin
    // until it is idle or SNAPSHOT_PULL_LAG behind.
    let last = shared
        .last_snap_chunk_ms
        .load(std::sync::atomic::Ordering::Relaxed);
    if pin_tip > 0 && !snap_pin_rotate_ok(shared, live_tip, pin_tip, last, unix_ms()) {
        return;
    }
    // Serve refresh is an optional dump (v2.9.53): skip it under the
    // low-water mark rather than fill the disk; joiners get the older pin.
    let guard = shared.disk_guard;
    let optional = move |st: Option<&fd_pl::disk::DiskStat>, need: u64| match st {
        Some(s) => guard.check_optional(s, need),
        None => Ok(()),
    };
    let n = shared.node.lock();
    if let Err(e) = n.save_snapshot_checked(&path, &optional) {
        drop(n);
        shared.note_disk_skip("archive serve refresh (snapshot)", &e.to_string());
        return;
    }
    let join = snap_join_path(std::path::Path::new(&path));
    let join_bytes = match n.save_join_snapshot_checked(&join, &optional) {
        Ok(b) => b,
        Err(e) => {
            drop(n);
            shared.note_disk_skip("archive serve refresh (join)", &e.to_string());
            return;
        }
    };
    drop(n);
    let serve = snap_serve_path(std::path::Path::new(&path));
    let src = if join.exists() { join } else { path.clone() };
    if let Err(e) = shared.optional_ok(join_bytes) {
        shared.note_disk_skip("archive serve copy", &e);
        return;
    }
    if std::fs::copy(&src, &serve).is_err() {
        return;
    }
    if let Ok(bytes) = std::fs::read(&serve) {
        let sha256 = fd_pl::crypto::sha256_hex(&bytes);
        info!(
            "snapshot serve refresh live={live_tip} was={pin_tip} bytes={}",
            bytes.len()
        );
        if !write_stable_serve(&path, &sha256, &bytes) {
            shared.note_disk_skip("archive serve hashed copy", "write failed");
            return;
        }
        *shared.snap_meta.lock() = Some(SnapMeta {
            tip: live_tip,
            tip_hash,
            sha256,
            bytes: bytes.len() as u64,
        });
        shared
            .snap_pin_ms
            .store(unix_ms(), std::sync::atomic::Ordering::Relaxed);
    }
}

/// Isolated-rehearsal hooks (snapshot transport tests). Enabled only when
/// `FALCON_PL_TEST_HOOKS=1` AND the scheme is hmac-dev (`--allow-dev-crypto`)
/// AND `--network-id` is not 2300. Otherwise every hook below is a no-op and
/// production values apply. Set once in `main`.
static TEST_HOOKS: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

fn test_hooks_on() -> bool {
    *TEST_HOOKS.get().unwrap_or(&false)
}

fn test_hooks_allowed(env_on: bool, hmac_dev: bool, network_id: u32) -> bool {
    env_on && hmac_dev && network_id != 2300
}

fn test_hook_u64(name: &str) -> Option<u64> {
    if !test_hooks_on() {
        return None;
    }
    std::env::var(name).ok()?.parse::<u64>().ok()
}

/// Max chunks bulk-pushed after an Offer. Default [`SNAPSHOT_PUSH_MAX`];
/// test hook `FALCON_PL_SNAPSHOT_PUSH_MAX` clamps to 0..=default.
fn snapshot_push_max() -> u32 {
    test_hook_u64("FALCON_PL_SNAPSHOT_PUSH_MAX")
        .map(|n| (n.min(SNAPSHOT_PUSH_MAX as u64)) as u32)
        .unwrap_or(SNAPSHOT_PUSH_MAX)
}

/// Join-snap chunk size. Default [`fd_pl::Node::SNAPSHOT_CHUNK_BYTES`];
/// test hook `FALCON_PL_SNAPSHOT_CHUNK_BYTES` clamps to 16 KiB..=default.
fn snapshot_chunk_bytes() -> usize {
    const DEFAULT: usize = fd_pl::Node::SNAPSHOT_CHUNK_BYTES;
    test_hook_u64("FALCON_PL_SNAPSHOT_CHUNK_BYTES")
        .map(|n| (n.min(DEFAULT as u64) as usize).max(16 * 1024))
        .unwrap_or(DEFAULT)
}

/// Catch-up reply lane capacity (test hook clamps 16..=default).
fn catch_lane_cap(name: &str, default: usize) -> usize {
    test_hook_u64(name)
        .map(|n| (n.min(default as u64) as usize).max(16))
        .unwrap_or(default)
}

/// Test hook: delay after each catch-lane line written (simulates a slow
/// socket so the lane fills). Off unless set; capped at 1 s.
fn catch_drain_delay() -> Option<std::time::Duration> {
    test_hook_u64("FALCON_PL_TEST_CATCH_DRAIN_MS")
        .filter(|&ms| ms > 0)
        .map(|ms| std::time::Duration::from_millis(ms.min(1_000)))
}

static SNAP_TEST_STALL_START: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Test hook: the archive silently withholds chunks
/// `>= FALCON_PL_TEST_SNAP_STALL_FROM_CHUNK` for `FALCON_PL_TEST_SNAP_STALL_MS`
/// after the first such request, then serves normally (controlled stall →
/// joiner abort/stash → stalled cooldown → resume).
fn snap_test_withhold(index: u32) -> bool {
    let Some(from) = test_hook_u64("FALCON_PL_TEST_SNAP_STALL_FROM_CHUNK") else {
        return false;
    };
    let dur = test_hook_u64("FALCON_PL_TEST_SNAP_STALL_MS").unwrap_or(0);
    if (index as u64) < from || dur == 0 {
        return false;
    }
    let now = unix_ms();
    let start = match SNAP_TEST_STALL_START.compare_exchange(
        0,
        now,
        std::sync::atomic::Ordering::SeqCst,
        std::sync::atomic::Ordering::SeqCst,
    ) {
        Ok(_) => now,
        Err(s) => s,
    };
    now.saturating_sub(start) < dur
}

fn serve_snap_chunk(shared: &Shared, sha256: &str, index: u32) -> Result<WireMsg, String> {
    // v2.9.67: any seat with hashed serve files (archive or hub) serves an
    // offered sha by hash until retention drops it, so a pin rotation no
    // longer breaks a download already in flight.
    let stable = if !shared.snapshot_out.as_os_str().is_empty()
        && sha256.len() == 64
        && sha256.bytes().all(|b| b.is_ascii_hexdigit())
    {
        let p = snap_serve_sha_path(&shared.snapshot_out, sha256);
        if p.exists() {
            Some(p)
        } else {
            None
        }
    } else {
        None
    };
    let path = if let Some(p) = stable.clone() {
        p
    } else if shared.is_archive {
        let out = shared.snapshot_out.clone();
        let serve = snap_serve_path(&out);
        if serve.exists() {
            serve
        } else {
            out
        }
    } else if shared.is_hub || seat_serves_join_snap(shared) {
        // Hub (v2.9.74: or serving seat): serve whatever `prepare_hub_join_snapshot` offered (own meta,
        // so the periodic pin rotating `snap_meta` cannot mismatch the file).
        shared
            .hub_snap
            .lock()
            .as_ref()
            .map(|h| h.path.clone())
            .ok_or_else(|| "no hub snapshot".to_string())?
    } else {
        return Err("not archive".into());
    };
    if path.as_os_str().is_empty() {
        return Err("no snapshot path".into());
    }
    shared
        .last_snap_chunk_ms
        .store(unix_ms(), std::sync::atomic::Ordering::Relaxed);
    shared.served_shas.lock().insert(sha256.to_string(), unix_ms());
    let meta = if shared.is_archive {
        shared.snap_meta.lock().clone()
    } else {
        let h = shared.hub_snap.lock().clone();
        match h {
            // Serving the periodic pin: it may rotate under us — check the
            // live pin meta so a rotated file reports "snap hash changed".
            Some(h) if !h.owned => shared.snap_meta.lock().clone(),
            Some(h) => Some(h.meta),
            None => None,
        }
    };
    let (nbytes, sha_ok) = if stable.is_some() {
        let n = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        (n, true)
    } else if let Some(meta) = meta {
        (meta.bytes, meta.sha256 == sha256)
    } else {
        return Err("no snapshot file yet".into());
    };
    if !sha_ok {
        return Err("snap hash changed".into());
    }
    let chunk_sz = snapshot_chunk_bytes();
    let total = (nbytes as usize).div_ceil(chunk_sz).max(1) as u32;
    let start = index as u64 * chunk_sz as u64;
    if start > nbytes {
        return Err("chunk oob".into());
    }
    let want = (nbytes.saturating_sub(start) as usize).min(chunk_sz);
    let mut buf = vec![0u8; want];
    let read_ok = (|| {
        use std::io::{Read, Seek, SeekFrom};
        let mut f = std::fs::File::open(&path)?;
        f.seek(SeekFrom::Start(start))?;
        f.read_exact(&mut buf)?;
        Ok::<(), std::io::Error>(())
    })();
    if read_ok.is_err() {
        return Err("read chunk failed".into());
    }
    Ok(WireMsg::SnapshotChunk {
        sha256: sha256.to_string(),
        index,
        total,
        data: hex::encode(buf),
    })
}

/// Offer + every join-snap chunk on the same session (v2.9.24).
/// One NeedSnapshot must finish the transfer; stop-and-wait died on WAN.
fn dispatch_wire(
    shared: &Shared,
    msg: WireMsg,
    fanout: Option<&Arc<Vec<PeerOut>>>,
    relay_state: bool,
    from_admin: bool,
    // Validated Hello id for this TCP session (immutable for the call). Empty
    // until Hello; never read from shared `wire_from` for attribution.
    session_peer: &str,
    // Max SnapshotChunk to bulk-push after Offer (0 = Offer only). Caller
    // derives this from catch-up lane free capacity.
    push_budget: u32,
) -> Vec<WireMsg> {
    let push = matches!(msg, WireMsg::NeedSnapshot {});
    let mut out = Vec::new();
    if let Some(r) = process_msg(shared, msg, fanout, relay_state, from_admin, session_peer) {
        let extra = if push {
            if let WireMsg::SnapshotOffer { sha256, chunks, .. } = &r {
                let who = session_peer;
                let now = unix_ms();
                let mut m = shared.snap_pushed.lock();
                m.retain(|_, t| now.saturating_sub(*t) < SNAPSHOT_REPUSH_MS);
                let key = format!("{who}|{sha256}");
                // Unknown session (no Hello yet): Offer only — never key as empty.
                if who.is_empty() {
                    None
                } else if m.contains_key(&key) {
                    // Recent push to this requester+sha: Offer only; joiner hole-fills.
                    None
                } else if push_budget == 0 {
                    // Offer only; do not mark pushed so a later pull can ship chunks.
                    None
                } else {
                    m.insert(key, now);
                    Some((sha256.clone(), *chunks))
                }
            } else {
                None
            }
        } else {
            None
        };
        out.push(r);
        if let Some((sha, n)) = extra {
            // Cap by SNAPSHOT_PUSH_MAX and caller credit (lane free slots).
            let n_push = n.min(snapshot_push_max()).min(push_budget);
            for i in 0..n_push {
                if snap_test_withhold(i) {
                    debug!("snapshot push withheld from chunk {i} (test stall hook)");
                    break;
                }
                match serve_snap_chunk(shared, &sha, i) {
                    Ok(c) => out.push(c),
                    Err(reason) => {
                        warn!("snapshot push chunk {i}/{n}: {reason}");
                        out.push(WireMsg::SnapshotNo { reason });
                        break;
                    }
                }
            }
        }
    }
    out
}

fn process_msg(
    shared: &Shared,
    msg: WireMsg,
    fanout: Option<&Arc<Vec<PeerOut>>>,
    // When true (ctl/origin), fan state-mutating ops once to peers.
    // Peer-received paths pass false to avoid amplify loops (double-bond etc.).
    relay_state: bool,
    // Unix admin socket bypasses the TCP allow_admin_wire gate.
    from_admin: bool,
    session_peer: &str,
) -> Option<WireMsg> {
    let fan = |m: WireMsg| {
        if let Some(f) = fanout {
            shared.fan_msg(f, &m);
        } else {
            // Still reach inbound joiners even without configured fanout.
            if let Ok(s) = serde_json::to_string(&m) {
                shared.inbound.lock().retain(|sink| {
                    if sink.close.load(std::sync::atomic::Ordering::Relaxed) {
                        return false;
                    }
                    sink.tx.try_send(s.clone() + "\n", ConsClass::Other)
                });
            }
        }
    };
    let fan_tx = |m: WireMsg| {
        if let Some(f) = fanout {
            shared.fan_tx(f, &m, relay_state);
        } else {
            fan(m);
        }
    };
    let fan_state = |m: WireMsg| {
        if relay_state {
            fan(m);
        }
    };

    if !from_admin && !shared.node.lock().cfg.allow_admin_wire && msg.is_admin() {
        return Some(WireMsg::Err {
            msg: "admin-only".into(),
        });
    }

    // Directed body pull arrives as LedgerBody; ingest like a live proposal.
    // A by-id body is the same once the seat already has every tx.
    let msg = match msg {
        WireMsg::LedgerBody { ledger } => WireMsg::ProposeLedger {
            ledger,
            catchup: false,
        },
        WireMsg::LedgerBodyById { ledger } => {
            let height = ledger.height;
            let n_ids = ledger.tx_ids.len();
            let mut n = shared.node.lock();
            let me = n.id.clone();
            match n.assemble_body_by_id(ledger) {
                Ok(ledger) => {
                    info!("body-ids seat={me} h={height} n={n_ids} have={n_ids} miss=0");
                    WireMsg::ProposeLedger {
                        ledger,
                        catchup: false,
                    }
                }
                Err((hash, tx_ids)) => {
                    let miss = tx_ids.len();
                    info!(
                        "body-ids seat={me} h={height} n={n_ids} have={} miss={miss} pull",
                        n_ids.saturating_sub(miss)
                    );
                    drop(n);
                    let ask = WireMsg::NeedTxsByIds {
                        ledger_hash: hash,
                        tx_ids,
                    };
                    if let Some(f) = fanout {
                        shared.fan_body_pull(f, &ask);
                    }
                    return Some(ask);
                }
            }
        }
        WireMsg::TxsByIds { ledger_hash, txs } => {
            let mut n = shared.node.lock();
            let me = n.id.clone();
            match n.supply_body_txs(&ledger_hash, txs) {
                Some(ledger) => {
                    info!(
                        "body-ids seat={me} h={} filled-from-pull",
                        ledger.height
                    );
                    WireMsg::ProposeLedger {
                        ledger,
                        catchup: false,
                    }
                }
                None => {
                    info!("body-ids seat={me} hash={ledger_hash} full-body-fallback");
                    drop(n);
                    return Some(WireMsg::NeedLedgerBody { ledger_hash });
                }
            }
        }
        other => other,
    };

    match msg {
        // Reassembled in the read loops; a stray piece here is ignored.
        WireMsg::Piece { .. } => None,
        WireMsg::Hello {
            id,
            public_key,
            validators: _,
            publics,
            tip_height,
            tip_hash,
            is_hub,
            mempool_len,
            product_version,
            hello_network_id,
            archive,
            snap_height,
            release_version,
            capabilities: _, // gated earlier via HelloSession::check
        } => {
            // Live bond-in: Hello only advertises keys (+ tip). Bonded seats come
            // from genesis register or Bond ledger txs — never free-register from wire.
            // Lock order: snap_pull before node (ticker holds them that way).
            let hello_pulling = shared.snap_pull.lock().is_some();
            let mut n = shared.node.lock();
            // A10: refuse a different network_id. Version (`Node::hello_version_ok`):
            // below the Gloas gate H (local tip < H, incl. H == u64::MAX) 2.9.60
            // accepts any 2.9.x peer (legacy empty version still tolerated).
            // This does NOT make the roll order-free: 2.9.59 seats still
            // exact-match Hello and reject 2.9.60 peers, so the documented roll
            // order (v3, v12, v13, v11, v1, v6, v10 last) is still required, and
            // block H forks any older binary. Once local tip >= H the peer must
            // be 2.9.x with x >= 60 (2.9.61 still connects); empty is refused.
            // Mesh sessions run the same check first (`HelloSession`) and close
            // the socket on a refusal; this arm keeps admin/other callers equal.
            if let Some(reason) = n.hello_reject_reason(hello_network_id, &product_version) {
                warn!(
                    "hello reject {id}: {reason} (peer network_id {hello_network_id} version {product_version:?}; local {} {PRODUCT_VERSION})",
                    n.cfg.network_id
                );
                return Some(WireMsg::Err { msg: reason.into() });
            }
            n.note_peer_release(&id, &release_version);
            {
                let mut pp = shared.piece_peers.lock();
                if fd_pl::pieces::peer_release_supports_pieces(&release_version) {
                    pp.insert(id.clone());
                } else {
                    pp.remove(&id);
                }
            }
            if let Some(reason) = n.hello_release_reject(&release_version) {
                warn!("hello reject {id}: {reason} (local {PRODUCT_VERSION})");
                return Some(WireMsg::Err { msg: reason });
            }
            // v2.9.62 A6: a v2 seat's key is bound on chain (BondV2 + PoP);
            // a Hello claiming that id with another key is refused.
            if let Some(v) = n.validators.get(&id) {
                if v.v2_seat && !public_key.is_empty() && !v.public_key.eq_ignore_ascii_case(&public_key) {
                    eprintln!("hello reject {id}: key differs from on-chain BondV2 key");
                    return Some(WireMsg::Err { msg: "hello: key differs from on-chain key".into() });
                }
            }
            // A1: never overwrite registry keys from Hello. Only fill *empty*
            // bonded-validator slots (first-seen from a known seater).
            if n.validators.contains_key(&id) {
                let _ = n.keys.insert_public(&id, &public_key);
            }
            if let Some(v) = n.validators.get_mut(&id) {
                if v.public_key.is_empty() && !public_key.is_empty() {
                    v.public_key = public_key.clone();
                }
            }
            for (pid, pk) in publics {
                if n.validators.contains_key(&pid) {
                    let _ = n.keys.insert_public(&pid, &pk);
                }
                if let Some(v) = n.validators.get_mut(&pid) {
                    if v.public_key.is_empty() && !pk.is_empty() {
                        v.public_key = pk;
                    }
                }
            }
            n.pong_with_role(&id, tip_height, mempool_len, is_hub, archive, snap_height);
            // Joiner path: peer Hello carries tip so we can pull immediately
            // without waiting for Pong fanout (which may never reach inbound dialers).
            // Do not mix NeedLedgers with a snapshot pull (fills the archive catchq).
            // snap_pull is peeked before this arm (lock order: snap_pull → node).
            let need_from = if hello_pulling || n.wants_snapshot() {
                None
            } else if tip_height > 0 {
                n.note_peer_tip(tip_height, &tip_hash)
            } else {
                None
            };
            // Only request from=1 when hard-resync is actually possible.
            let need_from = need_from.and_then(|from| {
                if from == 1 && !n.can_hard_resync() {
                    if n.tip_height < tip_height {
                        Some(n.tip_height.saturating_add(1))
                    } else {
                        None
                    }
                } else {
                    Some(from)
                }
            });
            let hard = n.need_hard_resync && n.can_hard_resync();
            let local_tip = n.tip_height;
            drop(n);
            if let Some(from_height) = need_from {
                debug!(
                    "catch-up (hello) from_height={from_height} hard={hard} local_tip={local_tip} peer={id} peer_tip={tip_height}"
                );
                fan(WireMsg::NeedLedgers {
                    from_height,
                    max_count: fd_pl::Node::CATCHUP_BATCH as u64,
                });
            }
            None
        }
        WireMsg::Pong {
            id,
            tip_height,
            tip_hash,
            is_hub,
            mempool_len,
            archive,
            snap_height,
            ..
        } => {
            let pulling = shared.snap_pull.lock().is_some();
            let mut n = shared.node.lock();
            n.pong_with_role(&id, tip_height, mempool_len, is_hub, archive, snap_height);
            // Pull catch-up: if peer is ahead (or hard-resync), request missing heights.
            // P2: pass tip_hash for best_peer tracking; residual unless operator hard-reset.
            let need_from = if pulling || n.wants_snapshot() {
                None
            } else {
                n.note_peer_tip(tip_height, &tip_hash)
            }
            .and_then(|from| {
                if from == 1 && !n.can_hard_resync() {
                    if n.tip_height < tip_height {
                        Some(n.tip_height.saturating_add(1))
                    } else {
                        None
                    }
                } else {
                    Some(from)
                }
            });
            let hard = n.need_hard_resync && n.can_hard_resync();
            let local_tip = n.tip_height;
            let want_txs = n.wants_need_txs()
                && n.lottery_packer().as_ref() == Some(&n.id);
            if want_txs {
                n.note_need_txs_sent();
            }
            drop(n);
            if let Some(from_height) = need_from {
                debug!(
                    "catch-up request from_height={from_height} hard={hard} local_tip={local_tip} peer={id} peer_tip={tip_height}"
                );
                fan(WireMsg::NeedLedgers {
                    from_height,
                    max_count: fd_pl::Node::CATCHUP_BATCH as u64,
                });
            }
            if want_txs {
                if let Some(f) = fanout {
                    shared.fan_need_txs(
                        f,
                        &WireMsg::NeedTxs {
                            max_count: fd_pl::Node::NEED_TXS_BATCH as u64,
                        },
                    );
                }
            }
            None
        }
        WireMsg::NeedTxs { max_count } => {
            let mut n = shared.node.lock();
            // While lagging, prefer catch-up replies over TxsBatch on the wire.
            if n.still_lagging() {
                return None;
            }
            let batch = n.serve_need_txs(max_count as usize);
            drop(n);
            if batch.is_empty() {
                None
            } else {
                debug!("NeedTxs serve n={}", batch.len());
                Some(WireMsg::TxsBatch { txs: batch })
            }
        }
        WireMsg::TxInv { ids } => {
            let missing: Vec<String> = {
                let n = shared.node.lock();
                ids.into_iter()
                    .filter(|id| !n.mempool.contains(id))
                    .take(32)
                    .collect()
            };
            if missing.is_empty() {
                None
            } else {
                Some(WireMsg::NeedMempoolTxs { ids: missing })
            }
        }
        WireMsg::NeedMempoolTxs { ids } => {
            let n = shared.node.lock();
            let txs: Vec<_> = ids
                .iter()
                .filter_map(|id| n.mempool.get(id).cloned())
                .take(32)
                .collect();
            drop(n);
            if txs.is_empty() {
                None
            } else {
                Some(WireMsg::TxsBatch { txs })
            }
        }
        WireMsg::TxsBatch { txs } => {
            if txs.is_empty() {
                return None;
            }
            let mut n = shared.node.lock();
            n.note_body_fill(txs.iter().cloned());
            let added = n.absorb_txs(&txs);
            if added > 0 {
                debug!("TxsBatch absorbed {added}/{}", txs.len());
            }
            None
        }
        WireMsg::NeedLedgers {
            from_height,
            max_count,
        } => {
            // Directed reply only — never mesh-fan catch-up history.
            let n = shared.node.lock();
            let batch = n.ledgers_from(from_height, max_count as usize);
            let nserve = batch.len();
            drop(n);
            if nserve > 0 {
                let asker = session_peer.to_string();
                let busy = shared.inbound.lock().iter().any(|s| {
                    s.id == asker
                        && s.tx.used.load(std::sync::atomic::Ordering::Relaxed) > PIPE_PAUSE_BYTES
                });
                if busy {
                    warn!("pause LedgersBatch to {asker}: inbound queue high");
                    return None;
                }
                debug!("catch-up serve directed from={from_height} n={nserve}");
                Some(WireMsg::LedgersBatch {
                    from_height,
                    ledgers: batch,
                })
            } else {
                None
            }
        }
        WireMsg::LedgersBatch {
            from_height,
            ledgers,
        } => {
            let n_batch = ledgers.len();
            if n_batch == 0 {
                return None;
            }
            let mut n = shared.node.lock();
            let before = n.tip_height;
            match n.apply_catchup_batch(&ledgers) {
                Ok(tip) => {
                    let lag = n.tip_lag();
                    let hard = n.need_hard_resync && n.can_hard_resync();
                    let advanced = tip > before;
                    n.note_catchup_batch(advanced);
                    if advanced {
                        info!(
                            "catch-up batch from={from_height} n={n_batch} tip {before}→{tip} lag={lag}"
                        );
                    } else {
                        debug!(
                            "catch-up batch from={from_height} n={n_batch} tip={tip} lag={lag} hard={hard} ({})",
                            n.last_catchup_conflict
                        );
                    }
                    // Residual only. from=1 is operator-only (never auto-rewind).
                    // note_catchup_batch already cleared inflight; take_catchup_pull
                    // issues the next NeedLedgers (one hub, not a 3-way fan).
                    if n.still_lagging() && advanced {
                        if let Some(from) = n.take_catchup_pull() {
                            drop(n);
                            fan(WireMsg::NeedLedgers {
                                from_height: from,
                                max_count: fd_pl::Node::CATCHUP_BATCH as u64,
                            });
                        }
                    }
                    Some(WireMsg::Ok {
                        msg: format!("catchup batch tip={tip}"),
                    })
                }
                Err(e) => {
                    warn!("catch-up batch fail from={from_height}: {e}");
                    n.note_catchup_batch(false);
                    let _ = n.arm_lagging_fork_resync(&e);
                    // State-root / fork: the next ledger can never apply.
                    // Drop a stale download and ask for a snapshot now.
                    let heal = e.contains("state root") || e.contains("fork at h=");
                    if heal && n.wants_snapshot() {
                        drop(n);
                        shared.snap_pull.lock().take();
                        info!("catch-up heal → NeedSnapshot after {e}");
                        fan(WireMsg::NeedSnapshot {});
                        return Some(WireMsg::Err { msg: e });
                    }
                    // Residual retry only. Never NeedLedgers from=1 here.
                    if n.still_lagging() && n.hard_resync_operator && n.can_hard_resync() {
                        let interval = fd_pl::Node::HARD_RESYNC_REQ_INTERVAL_MS;
                        if n.now_ms.saturating_sub(n.last_catchup_req_ms) >= interval {
                            n.last_catchup_req_ms = n.now_ms;
                            drop(n);
                            info!("operator hard-resync → NeedLedgers from=1");
                            fan(WireMsg::NeedLedgers {
                                from_height: 1,
                                max_count: fd_pl::Node::CATCHUP_BATCH as u64,
                            });
                        }
                    }
                    Some(WireMsg::Err { msg: e })
                }
            }
        }
        WireMsg::NeedSnapshot {} => {
            let meta = if shared.is_archive {
                // Mark the pin busy before refresh so a second request, and
                // the 60s saver, keep this file for the whole push.
                shared
                    .last_snap_chunk_ms
                    .store(unix_ms(), std::sync::atomic::Ordering::Relaxed);
                refresh_archive_serve_snapshot(shared);
                shared.snap_meta.lock().clone()
            } else if shared.is_hub || seat_serves_join_snap(shared) {
                let prev = shared
                    .last_snap_chunk_ms
                    .swap(unix_ms(), std::sync::atomic::Ordering::Relaxed);
                match prepare_hub_join_snapshot(shared, prev) {
                    Ok(m) => Some(m),
                    Err(reason) => {
                        return Some(WireMsg::SnapshotNo { reason });
                    }
                }
            } else {
                return Some(WireMsg::SnapshotNo {
                    reason: "not archive".into(),
                });
            };
            let Some(meta) = meta else {
                return Some(WireMsg::SnapshotNo {
                    reason: "no snapshot file yet".into(),
                });
            };
            let chunk = snapshot_chunk_bytes() as u32;
            let chunks = meta.bytes.div_ceil(chunk as u64).max(1) as u32;
            info!(
                "snapshot serving tip={} bytes={} chunks={chunks} to={}",
                meta.tip,
                meta.bytes,
                session_peer
            );
            Some(WireMsg::SnapshotOffer {
                tip_height: meta.tip,
                tip_hash: meta.tip_hash,
                sha256: meta.sha256,
                bytes: meta.bytes,
                chunk_size: chunk,
                chunks,
            })
        }
        WireMsg::NeedSnapshotChunk { sha256, index } => {
            if snap_test_withhold(index) {
                debug!("snapshot chunk {index} withheld to={session_peer} (test stall hook)");
                return None;
            }
            match serve_snap_chunk(shared, &sha256, index) {
                Ok(m) => {
                    debug!("snapshot chunk serve idx={index} to={session_peer}");
                    Some(m)
                }
                Err(reason) => Some(WireMsg::SnapshotNo { reason }),
            }
        }
        WireMsg::SnapshotOffer {
            tip_height,
            tip_hash,
            sha256,
            bytes,
            chunk_size,
            chunks,
        } => {
            let mut n = shared.node.lock();
            if tip_height <= n.tip_height {
                // Stale pin: looping NeedSnapshot starves residual NeedLedgers.
                // Back off join-snap for a while so residual pulls run.
                n.note_stale_snapshot_offer();
                return None;
            }
            // A late offer from ask-all must not start another 100 MB pull
            // after adopt. Residual owns every gap under SNAPSHOT_JOIN_LAG.
            let want = n.wants_snapshot();
            drop(n);
            if chunk_size == 0 || chunks == 0 || bytes == 0 {
                return None;
            }
            let hole_fill = {
                let mut pull = shared.snap_pull.lock();
                if let Some(p) = pull.as_ref() {
                    // A newer pin replaces a download that has not received
                    // a chunk yet. Keeping the old one is how a joiner applied
                    // a pin one block behind and then state-root-mismatched.
                    // v2.9.67: a download with chunks keeps its sha (the
                    // serving seat keeps it fetchable by hash); only the
                    // stall abort drops it for a newer pin.
                    if p.sha256 == sha256 || p.got() > 0 {
                        return None;
                    }
                }
                if !want {
                    let lag = shared.node.lock().tip_lag();
                    // A few dozen blocks behind stays on NeedLedgers. A pull
                    // stuck by 256 or more must take the newer pin; ignoring
                    // it is how the public joiners froze under JOIN_LAG.
                    if lag < fd_pl::Node::SNAPSHOT_PULL_LAG {
                        info!("snapshot offer ignored tip={tip_height} (ledger catch-up)");
                        return None;
                    }
                    info!("snapshot offer taken tip={tip_height} lag={lag} (ledger pull stalled)");
                }
                let source_peer = session_peer.to_string();
                {
                    let now = unix_ms();
                    let mut slow = shared.slow_snap_src.lock();
                    slow.retain(|_, until| *until > now);
                    if slow.contains_key(&source_peer) {
                        info!("snapshot offer from {source_peer} skipped (slow source)");
                        return None;
                    }
                }
                info!("snapshot offer tip={tip_height} bytes={bytes} chunks={chunks} from={source_peer}");
                let now = unix_ms();
                // v2.9.74: same sha as an aborted download → resume it.
                let stashed = shared.snap_stash.lock().take(&sha256).filter(|a| {
                    a.total == chunks && a.chunk_size == chunk_size && a.expected_bytes == bytes
                });
                let asm = if let Some(mut a) = stashed {
                    info!("snapshot offer resumes kept download ({}/{} chunks)", a.got(), a.total);
                    a.resume(now, source_peer);
                    a
                } else {
                    let mut a = SnapAssembler::new(
                        sha256.clone(),
                        tip_height,
                        tip_hash,
                        chunks,
                        chunk_size,
                        bytes,
                        now,
                    );
                    a.source_peer = source_peer;
                    a
                };
                let window = asm.request_window(fd_pl::Node::SNAPSHOT_PIPE_WINDOW);
                let mut asm = asm;
                asm.note_requested(&window);
                *pull = Some(asm);
                window
            };
            // Backup if the archive push is dropped. Archive already writes
            // every chunk after the offer (2.9.24); these fill holes only.
            for index in hole_fill {
                fan(WireMsg::NeedSnapshotChunk {
                    sha256: sha256.clone(),
                    index,
                });
            }
            // Test hook: re-ask right behind the hole-fill window so the
            // archive must queue an Offer while that lane is full.
            if test_hook_u64("FALCON_PL_TEST_REASK_AFTER_OFFER") == Some(1) {
                info!("snapshot re-ask after offer (test hook)");
                fan(WireMsg::NeedSnapshot {});
            }
            None
        }
        WireMsg::SnapshotChunk {
            sha256,
            index,
            total: _,
            data,
        } => {
            let raw = match hex::decode(&data) {
                Ok(b) => b,
                Err(_) => {
                    warn!("snapshot chunk {index} bad hex");
                    return None;
                }
            };
            let mut refill: Option<(String, Vec<u32>)> = None;
            let finished = {
                let mut pull = shared.snap_pull.lock();
                let Some(p) = pull.as_mut() else {
                    return None;
                };
                if p.sha256 != sha256 {
                    return None;
                }
                let ins = p.insert(index, raw, unix_ms());
                debug!("snapshot chunk recv idx={index} got={}/{}", p.got(), p.total);
                if matches!(ins, Ok(SnapInsert::Progress)) {
                    let more = p.pipeline_refill(index, fd_pl::Node::SNAPSHOT_PIPE_WINDOW, SNAPSHOT_PUSH_MAX);
                    if !more.is_empty() {
                        refill = Some((p.sha256.clone(), more));
                    }
                }
                match ins {
                    Ok(SnapInsert::Complete) => true,
                    Ok(SnapInsert::Progress) | Ok(SnapInsert::Duplicate) => false,
                    Err(e) => {
                        warn!("snapshot chunk {index}: {e}");
                        false
                    }
                }
            };
            if let Some((sha, idx)) = refill {
                for index in idx {
                    fan(WireMsg::NeedSnapshotChunk {
                        sha256: sha.clone(),
                        index,
                    });
                }
            }
            if !finished {
                return None;
            }
            let Some(p) = shared.snap_pull.lock().take() else {
                return None;
            };
            let Some(buf) = p.assemble() else {
                warn!("snapshot assemble failed after last chunk");
                return None;
            };
            let got = fd_pl::crypto::sha256_hex(&buf);
            if got != p.sha256 {
                warn!("snapshot hash mismatch after {} chunks", p.total);
                return None;
            }
            // One bounded file per seat (v2.9.53; was /tmp/pl-snap-pull-<tip>.json).
            let dest = if shared.snapshot_out.as_os_str().is_empty() {
                shared.data_dir.join(format!("{}.pull.json", shared.node.lock().id))
            } else {
                shared.snapshot_out.with_extension("pull.json")
            };
            if let Some(st) = fd_pl::disk::stat(&dest) {
                if let Err(e) = shared.disk_guard.check_essential(&st, buf.len() as u64) {
                    shared.note_disk_skip("snapshot pull write", &e);
                    return None;
                }
            }
            if let Some(parent) = dest.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            if let Err(e) = std::fs::write(&dest, &buf) {
                let _ = std::fs::remove_file(&dest);
                warn!("snapshot write {dest:?}: {e}");
                return None;
            }
            let mut n = shared.node.lock();
            let keys = n.keys.clone();
            match Node::load_snapshot(&dest, keys) {
                Ok(loaded) => {
                    let old = n.tip_height;
                    n.adopt_peer_snapshot(loaded);
                    shared.ledger_slow.lock().reset(unix_ms(), n.tip_height);
                    shared.snap_stash.lock().clear();
                    shared.snap_slow_judge.lock().reset();
                    if !p.source_peer.is_empty() {
                        n.note_snap_source(&p.source_peer);
                    }
                    info!(
                        "snapshot adopted tip {old}→{} hash={}",
                        n.tip_height,
                        &n.tip_hash[..n.tip_hash.len().min(16)]
                    );
                    if n.still_lagging() {
                        if let Some(from) = n.take_catchup_pull() {
                            drop(n);
                            fan(WireMsg::NeedLedgers {
                                from_height: from,
                                max_count: fd_pl::Node::CATCHUP_BATCH as u64,
                            });
                        }
                    }
                }
                Err(e) => warn!("snapshot load {dest:?}: {e}"),
            }
            None
        }
        WireMsg::SnapshotNo { reason } => {
            warn!("snapshot rejected: {reason}");
            // Non-servers go to snap_nonserve (not stalled-archive cooldown).
            if reason == "not archive" || reason == "not hub" {
                let who = session_peer;
                if !who.is_empty() {
                    shared
                        .snap_nonserve
                        .lock()
                        .insert(who.to_string(), unix_ms() + SNAP_SLOW_SKIP_MS);
                }
            }
            if reason == "no snapshot file yet" {
                // Source has nothing to offer yet: let residual NeedLedgers run.
                shared.node.lock().note_stale_snapshot_offer();
            }
            // Wrong peer / transient: keep the pull so we retry the archive,
            // not wipe and start over. A rotating hub's "snap hash changed"
            // must not throw away a good archive push already in flight.
            if reason != "not archive" && reason != "snap hash changed" {
                shared.snap_pull.lock().take();
            }
            None
        }
        WireMsg::SubmitTx { tx } => {
            let mut n = shared.node.lock();
            // Only defer inject when we know we are **behind** peers. Cold tip=0
            // with best_peer=0 is normal genesis for the whole mesh — must accept.
            if n.still_lagging() {
                // Must be Err, not Ok: clients treated Ok as accepted and
                // waitSeq'd until timeout while live packers starved
                // (AMD-20260827-1).
                return Some(WireMsg::Err {
                    msg: format!(
                        "deferred-until-catchup (local {} < peer {})",
                        n.tip_height, n.best_peer_tip
                    ),
                });
            }
            // A1: do not insert wire public keys before verify. Registry wins.
            match n.submit_tx(tx.clone()) {
                Ok(true) => {
                    drop(n);
                    fan_tx(WireMsg::SubmitTx { tx });
                    Some(WireMsg::Ok {
                        msg: "accepted".into(),
                    })
                }
                Ok(false) => Some(WireMsg::Ok {
                    msg: "duplicate".into(),
                }),
                Err(e) => Some(WireMsg::Err { msg: e }),
            }
        }
        WireMsg::ProposeHeader { header, catchup: _ } => {
            let mut n = shared.node.lock();
            if n.validators.contains_key(&header.packer) {
                let _ = n
                    .keys
                    .insert_public(&header.packer, &header.packer_public_key);
            }
            n.pong(&header.packer);
            if header.height == n.tip_height + 1 {
                n.note_next_height_activity();
            }
            if !n.header_sig_ok(&header) {
                return Some(WireMsg::Err {
                    msg: "bad header sig".into(),
                });
            }
            let already = n
                .pending_proposal
                .as_ref()
                .map(|p| p.ledger_hash == header.ledger_hash)
                .unwrap_or(false)
                || n.chain.iter().any(|l| l.ledger_hash == header.ledger_hash);
            if already {
                // Known header: do **not** re-sign or re-fan LedgerOk.
                // Epidemic header gossip × always-fan OK was the 2.9.0 RSS climb
                // (100+ copies of the same vote per height). Stuck pending is
                // recovered by the seal-loop timeout re-fan, not this path.
                return Some(WireMsg::Ok {
                    msg: "header-known".into(),
                });
            }
            if header.height == n.tip_height + 1 && n.ledger_body(&header.ledger_hash).is_none() {
                n.note_want_body(header.height, &header.ledger_hash);
                n.last_want_body_ms = n.now_ms;
                let hash = header.ledger_hash.clone();
                drop(n);
                // Ask hubs now — the header-forwarder often has no body (v2.9.13).
                if let Some(f) = fanout {
                    shared.fan_body_pull(
                        f,
                        &WireMsg::NeedLedgerBody {
                            ledger_hash: hash.clone(),
                        },
                    );
                }
                return Some(WireMsg::NeedLedgerBody {
                    ledger_hash: hash,
                });
            }
            None
        }
        WireMsg::NeedLedgerBody { ledger_hash } => {
            let n = shared.node.lock();
            match n.ledger_body(&ledger_hash) {
                Some(ledger) => Some(WireMsg::LedgerBody { ledger }),
                None => None,
            }
        }
        WireMsg::NeedTxsByIds { ledger_hash, tx_ids } => {
            let n = shared.node.lock();
            let Some(ledger) = n.ledger_body(&ledger_hash) else {
                return None;
            };
            let want: std::collections::BTreeSet<&str> = tx_ids.iter().map(|s| s.as_str()).collect();
            let txs: Vec<_> = ledger
                .txs
                .into_iter()
                .filter(|t| want.contains(t.tx_id.as_str()))
                .collect();
            if txs.is_empty() {
                None
            } else {
                Some(WireMsg::TxsByIds { ledger_hash, txs })
            }
        }
        WireMsg::LedgerBodyById { .. } | WireMsg::TxsByIds { .. } => None,
        WireMsg::LedgerBody { .. } => None, // rewritten to ProposeLedger above
        WireMsg::ProposeLedger { ledger, catchup } => {
            let mut n = shared.node.lock();
            // A1: do not learn account keys from a gossiped proposal (pre-QC).
            // Packer pk may fill an empty bonded slot only (same as Hello).
            if n.validators.contains_key(&ledger.packer) {
                let _ = n
                    .keys
                    .insert_public(&ledger.packer, &ledger.packer_public_key);
            }
            n.pong(&ledger.packer);
            n.clear_want_body();
            // Activity on the next height → reset progress-timeout clock (winner may)
            // have sealed; do not shared-skip them while their proposal is in flight).
            if ledger.height == n.tip_height + 1 {
                n.note_next_height_activity();
            }
            // v2.9.59: compute the stage-time state root (one ~207 MB SHA-256)
            // with `node.lock` released; the stage below then hits the root
            // memo. Pure cache warm-up — the stage still verifies as before.
            if !catchup {
                match n.prestage_root_input(&ledger) {
                    fd_pl::Prestage::Run(job) => {
                        drop(n);
                        // Sync handler on a multi-thread runtime worker:
                        // hand the worker's other tasks off while we hash.
                        let _ = tokio::task::block_in_place(move || job.run());
                        n = shared.node.lock();
                    }
                    fd_pl::Prestage::Wait(hash) => {
                        if fd_pl::PrestageJob::in_flight(&hash) {
                            drop(n);
                            tokio::task::block_in_place(|| fd_pl::PrestageJob::wait(&hash, 5_000));
                            n = shared.node.lock();
                        }
                    }
                    fd_pl::Prestage::Skip => {}
                }
            }
            // Hard resync after fork: buffer heights; rebuild only when continuous
            // prefix from h=1 is available. Rate-limited re-request (no per-msg storm).
            if catchup && n.need_hard_resync && n.hard_resync_operator {
                n.pending_ledgers
                    .entry(ledger.height)
                    .or_insert_with(|| ledger.clone());
                if n.pending_ledgers.contains_key(&1) {
                    let mut heights: Vec<u64> = n.pending_ledgers.keys().copied().collect();
                    heights.sort_unstable();
                    let mut cont = Vec::new();
                    let mut expect = 1u64;
                    for h in heights {
                        if h == expect {
                            if let Some(led) = n.pending_ledgers.get(&h) {
                                cont.push(led.clone());
                            }
                            expect += 1;
                        } else if h > expect {
                            break;
                        }
                    }
                    if !cont.is_empty() {
                        let n_batch = cont.len();
                        match n.hard_resync_from_ledgers(&cont) {
                            Ok(tip) => {
                                info!("hard-resync tip={tip} n_ledgers={n_batch}");
                                if n.still_lagging() {
                                    n.last_catchup_req_ms = 0;
                                    let from = if n.need_hard_resync {
                                        1
                                    } else {
                                        tip.saturating_add(1).max(1)
                                    };
                                    drop(n);
                                    fan(WireMsg::NeedLedgers {
                                        from_height: from,
                                        max_count: fd_pl::Node::CATCHUP_BATCH as u64,
                                    });
                                }
                                return Some(WireMsg::Ok {
                                    msg: format!("hard-resync tip={tip}"),
                                });
                            }
                            Err(e) => {
                                warn!("hard-resync fail: {e}");
                                return Some(WireMsg::Err { msg: e });
                            }
                        }
                    }
                } else if n
                    .now_ms
                    .saturating_sub(n.last_catchup_req_ms)
                    >= fd_pl::Node::HARD_RESYNC_REQ_INTERVAL_MS
                {
                    n.last_catchup_req_ms = n.now_ms;
                    drop(n);
                    fan(WireMsg::NeedLedgers {
                        from_height: 1,
                        max_count: fd_pl::Node::CATCHUP_BATCH as u64,
                    });
                    return Some(WireMsg::Ok {
                        msg: format!("hard-resync buffering h={}", ledger.height),
                    });
                }
                return Some(WireMsg::Ok {
                    msg: format!("hard-resync buffering h={}", ledger.height),
                });
            }
            // Detect re-delivery of an already-staged proposal **before** ingest
            // so we do not re-fan ProposeLedger (v2.3.2 hotfix — soft-QC fan storm).
            let already_staged = n
                .pending_proposal
                .as_ref()
                .map(|p| p.ledger_hash == ledger.ledger_hash)
                .unwrap_or(false);
            let tip_before = n.tip_height;
            // A7: gossip ProposeLedger is always stage+soft-QC. Immediate catch-up
            // commit only after an operator-armed hard-resync (LedgersBatch is the
            // pull path).
            let ingest = if catchup && n.need_hard_resync {
                n.ingest_ledger_catchup(&ledger)
            } else {
                n.ingest_ledger(&ledger)
            };
            match ingest {
                Ok(Some(r)) => {
                    let committed = n.tip_height > tip_before;
                    if already_staged {
                        debug!(
                            "proposal re-delivery h={} from {} tip={} (vote only, no re-fan)",
                            r.height, r.packer, n.tip_height
                        );
                    } else if committed {
                        info!(
                            "committed h={} from {} catchup={catchup} tip={}",
                            r.height, r.packer, n.tip_height
                        );
                        shared.note_packer_known(&n);
                        shared.note_hard_qc(n.tip_height);
                        if !ledger.batch_sig.is_empty() {
                            info!(
                                "batch-verify ok h={} n={} paths=1 falcon=1 fallback=0",
                                r.height,
                                ledger.txs.len()
                            );
                        }
                    } else {
                        info!(
                            "staged h={} from {} catchup={catchup} tip={} (await soft QC)",
                            r.height, r.packer, n.tip_height
                        );
                    }
                    let h = ledger.height;
                    // A view-change lock from an earlier round must stay the
                    // vote target. Staging the new body and then refusing to
                    // sign it is what left 443449 with no quorum.
                    // Test hold only: a 400-tx body from the named seat is not
                    // the current round proposer, so select_round_target leaves
                    // it cached and own_ok finds nothing staged. Move this
                    // seat's round onto that packer so the body is signed.
                    let only = std::fs::read_to_string("/tmp/fpl-only-pack")
                        .unwrap_or_default();
                    let only = only.trim();
                    if !only.is_empty()
                        && ledger.packer == only
                        && ledger.txs.len() >= 400
                    {
                        let slot = ledger.skipped_predecessors.len() as u64;
                        if n.height_view_round != slot {
                            info!(
                                "burst-hold vote-round h={h} from={} to={slot} packer={}",
                                n.height_view_round, ledger.packer
                            );
                            n.height_view_round = slot;
                        }
                    }
                    n.maybe_switch_target(h);
                    let hash = n
                        .pending_proposal
                        .as_ref()
                        .map(|p| p.ledger_hash.clone())
                        .unwrap_or_else(|| ledger.ledger_hash.clone());
                    let own = own_ok_msg(&mut n, h, &hash);
                    if ledger.txs.len() >= 400 && !only.is_empty() && ledger.packer == only {
                        let _ = std::fs::remove_file("/tmp/fpl-only-pack");
                    }
                    if own.is_none() && !catchup {
                        let round = n.own_ok_round(h);
                        let why = n
                            .may_cast_own_ok(h, round, &hash)
                            .err()
                            .unwrap_or_else(|| "sign empty or not the staged body".into());
                        warn!("no OK for staged h={h} round={round}: {why}");
                    }
                    let fresh = own.as_ref().map(|(_, f)| *f).unwrap_or(false);
                    let soft = n.soft_ok.contains(&hash);
                    let hard = n.hard_ok.contains(&hash);
                    // Live: fan header only on **first** stage. Always fan our OK
                    // on first stage even if accept_ledger already recorded it
                    // (fresh=false) — otherwise tip 0→1 deadlocks: nobody hears
                    // peer OKs and soft QC never forms. Catch-up: never re-fan.
                    if !catchup && !already_staged {
                        fan(propose_header(&ledger));
                    }
                    if !catchup && (!already_staged || fresh) {
                        if let Some((m, _)) = own {
                            fan(m);
                        }
                    }
                    Some(WireMsg::Ok {
                        msg: format!(
                            "{} h={} tip={} soft={soft} hard={hard} catchup={catchup}",
                            if committed {
                                "committed"
                            } else if already_staged {
                                "voted"
                            } else {
                                "staged"
                            },
                            r.height,
                            n.tip_height
                        ),
                    })
                }
                Ok(None) => Some(WireMsg::Ok {
                    msg: format!(
                        "buffered/dup h={} tip={} catchup={catchup}",
                        ledger.height, n.tip_height
                    ),
                }),
                Err(e) => {
                    // v2.3.2 P2: never auto-arm hard-resync on live or catch-up forks.
                    // Operator uses `OperatorHardReset` / re-snap. Keep tip; residual only.
                    let forkish = e.contains("state root")
                        || e.contains("bad parent")
                        || e.contains("equivocation")
                        || e.contains("fork");
                    // v2.9.49: a rival body for an already-committed height
                    // (below our tip, or at a certified tip) is stale gossip.
                    // It must not overwrite the catch-up conflict: that flipped
                    // wants_snapshot() on and suppressed residual pulls.
                    let stale = ledger.height < n.tip_height
                        || (ledger.height == n.tip_height
                            && n.certs.contains_key(&n.tip_height));
                    if forkish && stale {
                        debug!(
                            "ingest stale rival h={} tip={} catchup={catchup}: {e}",
                            ledger.height, n.tip_height
                        );
                    } else if forkish {
                        n.last_catchup_conflict = format!(
                            "ingest h={} catchup={catchup}: {e}",
                            ledger.height
                        );
                        warn!(
                            "ingest reject h={} catchup={catchup}: {e} (no auto hard-resync; operator hard-reset if needed)",
                            ledger.height
                        );
                    } else {
                        warn!(
                            "ingest fail h={} catchup={catchup}: {e}",
                            ledger.height
                        );
                    }
                    Some(WireMsg::Err { msg: e })
                }
            }
        }
        WireMsg::SkipPacker {
            height,
            packer,
            tip_hash,
            voter,
            signature,
        } => {
            let mut n = shared.node.lock();
            let voter = if voter.is_empty() {
                // Legacy unsigned skip: ignore (must not mutate lottery without QC).
                return None;
            } else {
                voter
            };
            let (qc, vote_new) =
                n.vote_skip_ex(height, &packer, &tip_hash, &voter, &signature);
            if qc {
                info!(
                    "skip-QC applied packer={packer} h={height} (voter={voter}) → lottery {:?}",
                    n.lottery_packer()
                );
            }
            // Epidemic re-fan of newly recorded skip votes (multi-host under load).
            if vote_new {
                drop(n);
                fan(WireMsg::SkipPacker {
                    height,
                    packer,
                    tip_hash,
                    voter,
                    signature,
                });
            }
            None
        }
        WireMsg::LedgerOk {
            height,
            ledger_hash,
            voter,
            signature,
            round,
        } => {
            let mut n = shared.node.lock();
            let tip_before = n.tip_height;
            let slashes_before = n.pending_slashes.len();
            // v2.9.58: carry the vote's own height (future OKs are buffered).
            let (soft, hard, fresh) = n.vote_ok_wire(height, &ledger_hash, &voter, &signature, round);
            let new_slash = n.pending_slashes.len() > slashes_before;
            // v2.9.79: an OK for our committed tip while we lack its cert —
            // keep it and try to rebuild the original cert (671185 stall).
            if !new_slash
                && height == n.tip_height
                && n.note_tip_cert_vote(height, &ledger_hash, &voter, &signature, round)
            {
                info!("tip cert rebuilt h={height} from relayed OKs");
            }
            // Log once per new vote, or when this vote moved the tip.
            // Logging every echo after QC (soft=true forever) was ~260 lines/s.
            if fresh || n.tip_height > tip_before {
                info!(
                    "votes on {} soft={soft} hard={hard} fresh={fresh} tip {}→{} (voter={voter})",
                    &ledger_hash[..16.min(ledger_hash.len())],
                    tip_before,
                    n.tip_height
                );
            }
            if n.tip_height > tip_before {
                shared.note_packer_known(&n);
            }
            if hard && n.tip_height > 0 {
                let qc_h = n.tip_height;
                shared.note_hard_qc(qc_h);
            }
            // v2.9.57: a peer re-OKs our certified tip in the recert round →
            // it has no cert. Join its recert round (379780 stall).
            let assist = if new_slash {
                None
            } else {
                n.recert_assist(&ledger_hash, round, &voter)
            };
            if let Some((h, hash, sig)) = assist {
                let me_id = n.id.clone();
                drop(n);
                info!("recert assist h={h} for {voter} (peer lacks tip cert)");
                // Unicast to the asking seat only. A mesh fan of the assist
                // plus every original tip_cert_relay OK filled queued_out
                // and starved ViewChange (h=827004).
                let assist_msg = WireMsg::LedgerOk {
                    height: h,
                    ledger_hash: hash.clone(),
                    voter: me_id,
                    signature: sig,
                    round,
                };
                shared.send_cons_seat(fanout, &voter, &assist_msg, ConsClass::Other);
                // v2.9.79: also relay the original cert's OKs so a cert-less
                // peer can rebuild it even when the recert round (next
                // committee) cannot reach quorum. Other, not Vote: even a
                // handful of unicasted sealing OKs share this peer's cons
                // pipe with ViewChange.
                let relay = shared.node.lock().tip_cert_relay();
                for (v, s, r) in relay {
                    let relay_msg = WireMsg::LedgerOk {
                        height: h,
                        ledger_hash: hash.clone(),
                        voter: v,
                        signature: s,
                        round: r,
                    };
                    shared.send_cons_seat(fanout, &voter, &relay_msg, ConsClass::Other);
                }
                n = shared.node.lock();
            }
            if new_slash {
                // Fan **both** OKs. Peers who only saw hash_b must still learn
                // hash_a or the packer never queues the slash.
                let ev = n.pending_slashes.last().cloned();
                info!(
                    "equivocation queued {} h={} — fanning both OKs",
                    voter, height
                );
                drop(n);
                if let Some(ev) = ev {
                    fan(WireMsg::LedgerOk {
                        height: ev.height,
                        ledger_hash: ev.hash_a,
                        voter: ev.offender.clone(),
                        signature: ev.sig_a,
                        round: ev.round,
                    });
                    fan(WireMsg::LedgerOk {
                        height: ev.height,
                        ledger_hash: ev.hash_b,
                        voter: ev.offender,
                        signature: ev.sig_b,
                        round: ev.round,
                    });
                }
            } else if fresh && !soft {
                // Re-fan **new** OK only until commit QC. After 4-of-6, echoes must die.
                drop(n);
                fan(WireMsg::LedgerOk {
                    height,
                    ledger_hash,
                    voter,
                    signature,
                    round,
                });
            }
            None
        }
        WireMsg::OnlineSetVote {
            epoch_id,
            members,
            voter,
            signature,
        } => {
            let mut n = shared.node.lock();
            let set: std::collections::BTreeSet<String> = members.iter().cloned().collect();
            let (qc, vote_new) = n.vote_online_set_ex(epoch_id, set, &voter, &signature);
            if qc {
                info!(
                    "ONLINE epoch {epoch_id} certified (voter={voter}) seats={:?} hash={}",
                    n.online_members.iter().cloned().collect::<Vec<_>>(),
                    &n.online_hash[..16.min(n.online_hash.len())]
                );
            }
            if vote_new {
                drop(n);
                fan(WireMsg::OnlineSetVote {
                    epoch_id,
                    members,
                    voter,
                    signature,
                });
            }
            None
        }
        WireMsg::ViewChange {
            height,
            tip_hash,
            round,
            voter,
            signature,
        } => {
            let mut n = shared.node.lock();
            let (qc, vote_new) =
                n.vote_view_change_ex(height, &tip_hash, round, &voter, &signature);
            if qc {
                info!(
                    "view-change QC h={height} round={round} (voter={voter}) → lottery {:?}",
                    n.lottery_packer()
                );
                // New round: re-vote the target body (round-scoped, lock-checked).
                let revote = n
                    .pending_proposal
                    .as_ref()
                    .map(|p| (p.height, p.ledger_hash.clone()))
                    .and_then(|(ph, phash)| own_ok_msg(&mut n, ph, &phash))
                    .map(|(m, _)| m);
                if let Some(m) = revote {
                    fan(m);
                }
            }
            if vote_new {
                drop(n);
                fan(WireMsg::ViewChange {
                    height,
                    tip_hash,
                    round,
                    voter,
                    signature,
                });
            }
            None
        }

        WireMsg::StatusReq {
            include_accounts,
            brief,
        } => {
            // v2.9.58: brief takes the lock only for cheap fields (roots come
            // from the commit cache). Full captures the root inputs under the
            // lock and computes the root / claim leaves / attestation reads
            // after dropping it.
            let mut body = if brief && !include_accounts {
                shared.node.lock().status_json_brief_cached()
            } else {
                let (mut body, heavy) = shared.node.lock().status_json_split(include_accounts, false);
                heavy.fill(&mut body);
                body
            };
            if let Some(obj) = body.as_object_mut() {
                // v2.9.53: free disk on the data dir (soak check alerts on it).
                obj.insert("disk".into(), shared.disk_status_json());
            }
            if brief {
                if let Some(obj) = body.as_object_mut() {
                    if let Some(qc) = obj.get_mut("falcon_qc").and_then(|v| v.as_object_mut()) {
                        qc.insert("attestations".into(), serde_json::json!([]));
                        qc.insert("attestations_v2".into(), serde_json::json!([]));
                    }
                    if let Some(lc) = obj.get_mut("lc").and_then(|v| v.as_object_mut()) {
                        lc.insert("claim_leaves".into(), serde_json::json!([]));
                        lc.insert("attestations".into(), serde_json::json!([]));
                    }
                }
            }
            Some(WireMsg::Status { body })
        }
        WireMsg::HealthReq { warnings } => Some(WireMsg::Health {
            body: health_body(shared, fanout, warnings),
        }),
        WireMsg::SealNow => {
            let mut n = shared.node.lock();
            let me = n.id.clone();
            n.pong(&me);
            match n.pack_or_skip(&me) {
                Ok(Some(ledger)) => match n.accept_ledger(&ledger) {
                    Ok(r) => {
                        fan(propose_header(&ledger));
                        let _ = &me;
                        if let Some((m, _)) = own_ok_msg(&mut n, ledger.height, &ledger.ledger_hash) {
                            fan(m);
                        }
                        if let Some(f) = fanout {
                            let seats = n.body_lane_seats();
                            let mut by_id = ledger.clone();
                            by_id.txs.clear();
                            shared.fan_ledger_body(
                                f,
                                &WireMsg::LedgerBodyById { ledger: by_id },
                                &seats,
                            );
                        }
                        Some(WireMsg::Ok {
                            msg: format!("sealed h={} txs={}", r.height, r.n_txs),
                        })
                    }
                    Err(e) => Some(WireMsg::Err { msg: e }),
                },
                Ok(None) => {
                    let h = n.tip_height + 1;
                    let skipped = n.skip_set_for(h).contains(&me);
                    let tip = n.tip_hash.clone();
                    let mp = n.mempool.len();
                    // Only gossip skip for no-applicable; empty mempool is idle wait.
                    if skipped {
                        let signature = n.sign_skip_vote(h, &me, &tip);
                        fan(WireMsg::SkipPacker {
                            height: h,
                            packer: me.clone(),
                            tip_hash: tip,
                            voter: me,
                            signature,
                        });
                        Some(WireMsg::Ok {
                            msg: format!("skipped no-applicable at h={h} mp={mp}"),
                        })
                    } else {
                        Some(WireMsg::Ok {
                            msg: format!("idle empty mempool at h={h}"),
                        })
                    }
                }
                Err(e) => Some(WireMsg::Err { msg: e }),
            }
        }
        WireMsg::SealForce => {
            let mut n = shared.node.lock();
            let me = n.id.clone();
            match n.pack_as_admin_force(&me) {
                Ok(ledger) => match n.accept_ledger_catchup(&ledger) {
                    Ok(r) => Some(WireMsg::Ok {
                        msg: format!("force-sealed h={} txs={}", r.height, r.n_txs),
                    }),
                    Err(e) => Some(WireMsg::Err { msg: e }),
                },
                Err(e) => Some(WireMsg::Err { msg: e }),
            }
        }
        WireMsg::VaultOpen {
            account,
            destination,
        } => {
            let mut n = shared.node.lock();
            match n.open_vault(&account, &destination) {
                Ok(()) => {
                    drop(n);
                    fan_state(WireMsg::VaultOpen {
                        account: account.clone(),
                        destination: destination.clone(),
                    });
                    Some(WireMsg::Ok {
                        msg: format!("vault open {account} → {destination}"),
                    })
                }
                Err(e) => Some(WireMsg::Err { msg: e }),
            }
        }
        WireMsg::VaultLock { account } => {
            let mut n = shared.node.lock();
            match n.vault_lock(&account) {
                Ok(()) => {
                    drop(n);
                    fan_state(WireMsg::VaultLock {
                        account: account.clone(),
                    });
                    Some(WireMsg::Ok {
                        msg: format!("vault locked {account}"),
                    })
                }
                Err(e) => Some(WireMsg::Err { msg: e }),
            }
        }
        WireMsg::ClaimRewards { account } => {
            let mut n = shared.node.lock();
            match n.claim_rewards(&account) {
                Ok(amt) => {
                    drop(n);
                    fan_state(WireMsg::ClaimRewards {
                        account: account.clone(),
                    });
                    Some(WireMsg::Ok {
                        msg: format!("claimed {amt} for {account}"),
                    })
                }
                Err(e) => Some(WireMsg::Err { msg: e }),
            }
        }
        WireMsg::CreatePool {
            pool_id,
            asset_a,
            asset_b,
        } => {
            let mut n = shared.node.lock();
            match n.create_pool(&pool_id, &asset_a, &asset_b) {
                Ok(()) => {
                    drop(n);
                    fan_state(WireMsg::CreatePool {
                        pool_id: pool_id.clone(),
                        asset_a: asset_a.clone(),
                        asset_b: asset_b.clone(),
                    });
                    Some(WireMsg::Ok {
                        msg: format!("pool {pool_id} {asset_a}/{asset_b}"),
                    })
                }
                Err(e) => Some(WireMsg::Err { msg: e }),
            }
        }
        WireMsg::AddLiquidity {
            pool_id,
            provider,
            amt_a,
            amt_b,
        } => {
            let mut n = shared.node.lock();
            match n.add_liquidity(&pool_id, &provider, amt_a, amt_b) {
                Ok(lp) => {
                    drop(n);
                    fan_state(WireMsg::AddLiquidity {
                        pool_id: pool_id.clone(),
                        provider: provider.clone(),
                        amt_a,
                        amt_b,
                    });
                    Some(WireMsg::Ok {
                        msg: format!("add_liq pool={pool_id} lp={lp}"),
                    })
                }
                Err(e) => Some(WireMsg::Err { msg: e }),
            }
        }
        WireMsg::Swap {
            pool_id,
            who,
            token_in,
            amount_in,
            min_out,
        } => {
            let mut n = shared.node.lock();
            match n.swap(&pool_id, &who, &token_in, amount_in, min_out) {
                Ok(out) => {
                    drop(n);
                    fan_state(WireMsg::Swap {
                        pool_id: pool_id.clone(),
                        who: who.clone(),
                        token_in: token_in.clone(),
                        amount_in,
                        min_out,
                    });
                    Some(WireMsg::Ok {
                        msg: format!("swap out={out}"),
                    })
                }
                Err(e) => Some(WireMsg::Err { msg: e }),
            }
        }
        WireMsg::CreateMarket { market_id, asset } => {
            let mut n = shared.node.lock();
            match n.create_market(&market_id, &asset) {
                Ok(()) => {
                    drop(n);
                    fan_state(WireMsg::CreateMarket {
                        market_id: market_id.clone(),
                        asset: asset.clone(),
                    });
                    Some(WireMsg::Ok {
                        msg: format!("market {market_id} asset={asset}"),
                    })
                }
                Err(e) => Some(WireMsg::Err { msg: e }),
            }
        }
        WireMsg::LendSupply {
            market_id,
            who,
            amount,
        } => {
            let mut n = shared.node.lock();
            match n.lend_supply(&market_id, &who, amount) {
                Ok(shares) => {
                    drop(n);
                    fan_state(WireMsg::LendSupply {
                        market_id: market_id.clone(),
                        who: who.clone(),
                        amount,
                    });
                    Some(WireMsg::Ok {
                        msg: format!("lend_supply shares={shares}"),
                    })
                }
                Err(e) => Some(WireMsg::Err { msg: e }),
            }
        }
        WireMsg::WatcherCredit { .. } => {
            return Some(WireMsg::Err {
                msg: "watcher-credit disabled; use WatcherHeartbeat or rail work".into(),
            });
        }
        WireMsg::Bond { id, from, amount } => {
            let mut n = shared.node.lock();
            match n.bond(&id, &from, amount) {
                Ok(total) => {
                    drop(n);
                    fan_state(WireMsg::Bond {
                        id: id.clone(),
                        from: from.clone(),
                        amount,
                    });
                    Some(WireMsg::Ok {
                        msg: format!("bonded {amount} → {id} total={total}"),
                    })
                }
                Err(e) => Some(WireMsg::Err { msg: e }),
            }
        }
        WireMsg::RequestUnbond { id, amount } => {
            let mut n = shared.node.lock();
            match n.request_unbond(&id, amount) {
                Ok(()) => {
                    let ready = n
                        .validators
                        .get(&id)
                        .map(|v| v.unbond_ready_ms)
                        .unwrap_or(0);
                    drop(n);
                    fan_state(WireMsg::RequestUnbond {
                        id: id.clone(),
                        amount,
                    });
                    Some(WireMsg::Ok {
                        msg: format!("unbond requested {amount} from {id} ready_ms={ready}"),
                    })
                }
                Err(e) => Some(WireMsg::Err { msg: e }),
            }
        }
        WireMsg::CompleteUnbond { id } => {
            let mut n = shared.node.lock();
            match n.complete_unbond(&id) {
                Ok(amt) => {
                    drop(n);
                    fan_state(WireMsg::CompleteUnbond { id: id.clone() });
                    Some(WireMsg::Ok {
                        msg: format!("unbond complete {id} returned {amt}"),
                    })
                }
                Err(e) => Some(WireMsg::Err { msg: e }),
            }
        }
        WireMsg::CreditAsset {
            account,
            asset,
            amount,
        } => {
            let mut n = shared.node.lock();
            match n.credit_asset_admin(&account, &asset, amount) {
                Ok(()) => {
                    drop(n);
                    fan_state(WireMsg::CreditAsset {
                        account: account.clone(),
                        asset: asset.clone(),
                        amount,
                    });
                    Some(WireMsg::Ok {
                        msg: format!("credited {amount} {asset} → {account}"),
                    })
                }
                Err(e) => Some(WireMsg::Err { msg: e }),
            }
        }
        WireMsg::Tick { dt_ms } => {
            let mut n = shared.node.lock();
            n.tick(dt_ms);
            let settled = n.maybe_settle_epochs();
            Some(WireMsg::Ok {
                msg: format!(
                    "tick {dt_ms}ms epoch={} settled={settled:?}",
                    n.current_epoch()
                ),
            })
        }
        WireMsg::ForceSettleEpoch => {
            let mut n = shared.node.lock();
            n.force_settle_current_epoch();
            Some(WireMsg::Ok {
                msg: format!(
                    "force settled last_settled={}",
                    n.last_settled_epoch
                ),
            })
        }
        WireMsg::RailHeader {
            asset,
            height,
            hash,
            parent_hash,
            merkle_root,
            watcher,
            raw,
        } => {
            let mut n = shared.node.lock();
            let w = if watcher.is_empty() {
                None
            } else {
                Some(watcher.as_str())
            };
            match n.submit_rail_header(
                &asset,
                fd_pl::bridge::RailHeader {
                    height,
                    hash: hash.clone(),
                    parent_hash,
                    merkle_root,
                    raw,
                },
                w,
            ) {
                Ok(()) => Some(WireMsg::Ok {
                    msg: format!("rail_header {asset} h={height} hash={hash}"),
                }),
                Err(e) => Some(WireMsg::Err { msg: e }),
            }
        }
        WireMsg::RailDeposit {
            asset,
            to,
            amount,
            proof,
            watcher,
        } => {
            let mut n = shared.node.lock();
            let w = if watcher.is_empty() {
                None
            } else {
                Some(watcher.as_str())
            };
            match n.rail_deposit(&asset, &to, amount, proof, w) {
                Ok(()) => Some(WireMsg::Ok {
                    msg: format!("rail_deposit {asset} {amount} → {to}"),
                }),
                Err(e) => Some(WireMsg::Err { msg: e }),
            }
        }
        WireMsg::RailWithdraw {
            asset,
            from,
            amount,
            external_to,
            vault_sig,
            signed_btc_tx,
        } => {
            let mut n = shared.node.lock();
            let sig = if vault_sig.is_empty() {
                None
            } else {
                Some(vault_sig.as_str())
            };
            let signed = if signed_btc_tx.is_empty() {
                None
            } else {
                Some(signed_btc_tx.as_str())
            };
            match n.rail_withdraw_full(&asset, &from, amount, &external_to, sig, signed) {
                Ok(note) => Some(WireMsg::Ok {
                    msg: format!("rail_withdraw note={note}"),
                }),
                Err(e) => Some(WireMsg::Err { msg: e }),
            }
        }
        WireMsg::RailBitvm2Attest {
            note_id,
            operator,
            pegout_txid_hex,
            claim_txid_hex,
            proof_hex,
            public_hex,
            statement_digest_hex,
        } => {
            let prep = {
                let n = shared.node.lock();
                match n.bitvm2_attest_prepare(&note_id) {
                    Ok(p) => p,
                    Err(e) => return Some(WireMsg::Err { msg: e }),
                }
            };
            let pegout = match fd_pl::bitvm2_exit::pegout_txid_bytes(&pegout_txid_hex) {
                Ok(p) => p,
                Err(e) => return Some(WireMsg::Err { msg: e }),
            };
            let header = fd_pl::bitvm2_exit::header_hash_placeholder(
                prep.tip_height,
                &prep.tip_hash,
            );
            let note = prep.note_id.clone();
            let dest_h160 = prep.dest_h160;
            let amount = prep.amount;
            let tip_height = prep.tip_height;
            let leaves = prep.mimc_leaves.clone();
            let proof = proof_hex.clone();
            let pubs = public_hex.clone();
            let digest = statement_digest_hex.clone();
            let verify = std::thread::spawn(move || {
                fd_pl::bitvm2_exit::verify_attest(
                    &note,
                    &dest_h160,
                    amount,
                    tip_height,
                    &header,
                    &pegout,
                    &leaves,
                    &proof,
                    &pubs,
                    &digest,
                )
            });
            match verify.join() {
                Ok(Ok(())) => {
                    let mut n = shared.node.lock();
                    match n.bitvm2_attest_apply(
                        &note_id,
                        &operator,
                        &pegout_txid_hex,
                        &claim_txid_hex,
                        &proof_hex,
                        &public_hex,
                        &statement_digest_hex,
                    ) {
                        Ok(()) => Some(WireMsg::Ok {
                            msg: format!("rail_bitvm2_attest note={note_id}"),
                        }),
                        Err(e) => Some(WireMsg::Err { msg: e }),
                    }
                }
                Ok(Err(e)) => Some(WireMsg::Err { msg: e }),
                Err(_) => Some(WireMsg::Err {
                    msg: "attest verify thread panicked".into(),
                }),
            }
        }
        WireMsg::RailBitvm2Pegout {
            note_id,
            operator,
            pegout_txid_hex,
        } => {
            let mut n = shared.node.lock();
            match n.rail_bitvm2_pegout(&note_id, &pegout_txid_hex, &operator) {
                Ok(()) => Some(WireMsg::Ok {
                    msg: format!("rail_bitvm2_pegout note={note_id} tx={pegout_txid_hex}"),
                }),
                Err(e) => Some(WireMsg::Err { msg: e }),
            }
        }
        WireMsg::OperatorHardReset { reason } => {
            let mut n = shared.node.lock();
            match n.operator_request_hard_resync(&reason) {
                Ok(()) => {
                    info!(
                        "operator hard-reset armed reason={reason:?} → NeedLedgers from=1"
                    );
                    n.last_catchup_req_ms = 0;
                    drop(n);
                    fan(WireMsg::NeedLedgers {
                        from_height: 1,
                        max_count: fd_pl::Node::CATCHUP_BATCH as u64,
                    });
                    Some(WireMsg::Ok {
                        msg: format!("hard-resync armed: {reason}"),
                    })
                }
                Err(e) => Some(WireMsg::Err { msg: e }),
            }
        }
        WireMsg::MempoolDrop { target } => {
            let mut n = shared.node.lock();
            let dropped = n.drop_mempool_target(&target);
            Some(WireMsg::Ok {
                msg: format!(
                    "mempool-drop target={target} evicted={} ids={dropped:?}",
                    dropped.len()
                ),
            })
        }
        WireMsg::SnapshotSave { path } => {
            let n = shared.node.lock();
            match n.save_snapshot(&path) {
                Ok(()) => Some(WireMsg::Ok {
                    msg: format!("snapshot saved {path}"),
                }),
                Err(e) => Some(WireMsg::Err {
                    msg: e.to_string(),
                }),
            }
        }
        WireMsg::SnapshotLoad { path } => {
            let mut n = shared.node.lock();
            let keys = n.keys.clone();
            match Node::load_snapshot(&path, keys) {
                Ok(loaded) => {
                    n.adopt_peer_snapshot(loaded);
                    shared.ledger_slow.lock().reset(unix_ms(), n.tip_height);
                    shared.snap_stash.lock().clear();
                    shared.snap_slow_judge.lock().reset();
                    Some(WireMsg::Ok {
                        msg: format!(
                            "snapshot loaded tip={} treasury={}",
                            n.tip_height, n.treasury
                        ),
                    })
                }
                Err(e) => Some(WireMsg::Err {
                    msg: e.to_string(),
                }),
            }
        }
        WireMsg::AccountQuery { account } => {
            // RAM part under the lock; older history from the archive body store
            // after the lock is released (bounded heights + time budget).
            let (mut body, store, floor) = {
                let n = shared.node.lock();
                (n.account_json(&account), n.body_store.clone(), n.ram_body_floor())
            };
            if let Some(store) = store {
                let mut txs: Vec<serde_json::Value> = body
                    .get("recent_txs")
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();
                if txs.len() < ACCOUNT_HISTORY_LIMIT {
                    fd_pl::account_history_from_store(
                        &store,
                        &account,
                        floor,
                        ACCOUNT_HISTORY_DISK_HEIGHTS,
                        std::time::Duration::from_millis(ACCOUNT_HISTORY_DISK_MS),
                        ACCOUNT_HISTORY_LIMIT,
                        &mut txs,
                    );
                    body["recent_txs"] = serde_json::Value::Array(txs);
                }
            }
            Some(WireMsg::Account { body })
        }
        WireMsg::OrderBookQuery { pair, levels } => {
            let n = shared.node.lock();
            let lv = if levels == 0 { 50 } else { (levels as usize).min(200) };
            Some(WireMsg::OrderBook {
                body: fd_pl::orderbook::depth_json(&n.defi, &pair, lv),
            })
        }
        WireMsg::OpenOrdersQuery { account } => {
            let n = shared.node.lock();
            Some(WireMsg::OrderBook {
                body: fd_pl::orderbook::account_orders_json(&n.defi, &account),
            })
        }
        WireMsg::FillsQuery { pair, account, limit } => {
            let n = shared.node.lock();
            let lim = if limit == 0 { 50 } else { limit as usize };
            Some(WireMsg::OrderBook {
                body: fd_pl::orderbook::fills_json(&n.defi, pair.as_deref(), account.as_deref(), lim),
            })
        }
        WireMsg::RailChallenge {
            asset,
            note_id,
            observed_dest,
            observed_amount,
        } => {
            let mut n = shared.node.lock();
            match n.rail_challenge(&asset, &note_id, &observed_dest, observed_amount, "watcher") {
                Ok(_) => Some(WireMsg::Ok {
                    msg: format!("rail_challenge {asset} {note_id}"),
                }),
                Err(e) => Some(WireMsg::Err { msg: e }),
            }
        }
        WireMsg::Status { .. }
        | WireMsg::Health { .. }
        | WireMsg::Ok { .. }
        | WireMsg::Err { .. }
        | WireMsg::Account { .. }
        | WireMsg::OrderBook { .. } => None,
    }
}

/// `falcon.health.v1` body. Only [`fd_pl::Node::health_core`] runs under
/// `node.lock` (scalars + a bounded chain walk); peers, process, disk and the
/// warning ring are read after it is dropped.
fn health_body(shared: &Shared, fanout: Option<&Arc<Vec<PeerOut>>>, warnings: u32) -> serde_json::Value {
    let mut body = shared.node.lock().health_core();
    let now = unix_ms();
    if let Some(h) = body.pointer("/chain/local_height").and_then(|v| v.as_u64()) {
        fd_pl::health::observe_tip(now, h);
    }
    let (bpm, spark, adv_age) = fd_pl::health::tip_rate(now);
    if let Some(c) = body.get_mut("chain").and_then(|v| v.as_object_mut()) {
        c.insert("blocks_per_min".into(), bpm.into());
        c.insert("blocks_per_min_spark".into(), serde_json::json!(spark));
        c.insert("tip_advanced_age_ms".into(), serde_json::json!(adv_age));
    }
    let outbound: Vec<String> = fanout
        .map(|f| {
            f.iter()
                .map(|p| p.peer_id.lock().clone())
                .filter(|id| !id.is_empty())
                .collect()
        })
        .unwrap_or_default();
    let inbound: Vec<String> = shared
        .inbound
        .lock()
        .iter()
        .filter(|s| !s.close.load(std::sync::atomic::Ordering::Relaxed))
        .map(|s| s.id.clone())
        .collect();
    let mut all: Vec<String> = outbound.iter().chain(inbound.iter()).cloned().collect();
    all.sort();
    all.dedup();
    let disk = shared.disk_stat();
    let n_warn = if warnings == 0 { 20 } else { warnings.min(fd_pl::health::WARN_RING_CAP as u32) } as usize;
    if let Some(o) = body.as_object_mut() {
        o.insert("generated_at_ms".into(), now.into());
        if let Some(p) = o.get_mut("peers").and_then(|v| v.as_object_mut()) {
            p.insert("count".into(), all.len().into());
            p.insert("outbound".into(), outbound.len().into());
            p.insert("inbound".into(), inbound.len().into());
            p.insert("live_sockets".into(), shared.live_socks.lock().len().into());
            p.insert("connected".into(), serde_json::json!(all));
        }
        o.insert(
            "system".into(),
            serde_json::json!({
                "process": fd_pl::health::process_json(now),
                "disk": disk.as_ref().map(|d| serde_json::json!({
                    "path": d.path.to_string_lossy(),
                    "free_bytes": d.avail_bytes,
                    "total_bytes": d.total_bytes,
                    "free_pct": (d.free_pct() * 10.0).round() / 10.0,
                })),
            }),
        );
        o.insert("warnings".into(), fd_pl::health::warnings_json(n_warn));
    }
    body
}

/// Pause window from `<keys_dir>/lc/bridge.json` (`(0, 0)` if absent).
fn crate_lc_vote_rounds_pause(keys_dir: &str) -> (u64, u64) {
    let c = fd_pl::lc::load_bridge_cfg(std::path::Path::new(keys_dir));
    (c.vote_rounds_pause_from, c.vote_rounds_resume_at)
}

/// `vote_rounds_from_height` from `<keys_dir>/lc/bridge.json` (0 if absent).
fn crate_lc_vote_rounds(keys_dir: &str) -> u64 {
    fd_pl::lc::load_bridge_cfg(std::path::Path::new(keys_dir)).vote_rounds_from_height
}

#[cfg(test)]
mod test_hook_gate_tests {
    use super::*;

    #[test]
    fn test_hooks_never_on_mainnet_or_real_crypto() {
        assert!(!test_hooks_allowed(true, true, 2300));
        assert!(!test_hooks_allowed(true, false, 2200));
        assert!(!test_hooks_allowed(false, true, 2200));
        assert!(test_hooks_allowed(true, true, 2200));
        // Gate unset in unit tests → production defaults.
        assert_eq!(snapshot_chunk_bytes(), fd_pl::Node::SNAPSHOT_CHUNK_BYTES);
        assert_eq!(snapshot_push_max(), SNAPSHOT_PUSH_MAX);
        assert_eq!(catch_lane_cap("FALCON_PL_TEST_INBOUND_CATCH_CAP", 512), 512);
        assert!(catch_drain_delay().is_none());
        assert!(!snap_test_withhold(400));
    }
}

#[cfg(test)]
mod large_gate_tests {
    use super::*;

    #[test]
    fn fresh_gate_blocks_second_send() {
        let g = LargeGate::new();
        assert!(g.try_acquire_at(1_000, "p"));
        assert!(!g.try_acquire_at(1_000 + 9_999, "p"));
    }

    #[test]
    fn stale_gate_is_retaken_after_10s() {
        let g = LargeGate::new();
        assert!(g.try_acquire_at(1_000, "p"));
        assert!(g.try_acquire_at(1_000 + LARGE_OUT_STALE.as_millis() as u64, "p"));
        // Retaken at the new time: fresh again.
        assert!(!g.try_acquire_at(11_500, "p"));
    }

    #[test]
    fn clear_releases_gate() {
        let g = LargeGate::new();
        assert!(g.try_acquire("p"));
        assert!(!g.try_acquire("p"));
        g.clear();
        assert!(g.try_acquire("p"));
    }

    fn tx(i: usize, pad: usize) -> fd_pl::Tx {
        fd_pl::Tx {
            account: format!("a{i}"),
            sequence: i as u64,
            destination: "d".into(),
            amount: 1,
            fee: 1,
            network_id: 1,
            public_key: "ab".repeat(pad),
            signature: "cd".repeat(pad),
            tx_id: format!("t{i}"),
            body: Default::default(),
        }
    }

    #[test]
    fn dish_pieces_are_at_most_48kb() {
        // ~5.3 KB per tx, 250 txs ~ 1.3 MB (the pre-dish size in the incident).
        let batch: Vec<_> = (0..250).map(|i| tx(i, 1_300)).collect();
        let pieces = Shared::dish_pieces(&batch);
        assert!(pieces.len() > 20);
        let mut n = 0;
        for p in &pieces {
            let line = serde_json::to_string(&WireMsg::TxsBatch { txs: p.clone() }).unwrap();
            assert!(line.len() <= 48 * 1024, "piece {} bytes", line.len());
            assert!(line.len() + 1 <= LARGE_LINE, "piece must not trip the large gate");
            n += p.len();
        }
        assert_eq!(n, batch.len(), "no tx lost and order kept");
        let flat: Vec<_> = pieces.concat().into_iter().map(|t| t.tx_id).collect();
        let want: Vec<_> = batch.iter().map(|t| t.tx_id.clone()).collect();
        assert_eq!(flat, want);
    }
}

#[cfg(test)]
mod inbound_ack_tests {
    use super::*;
    use std::sync::atomic::AtomicU64;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpListener;

    fn test_shared(id: &str) -> Arc<Shared> {
        let mut cfg = ChainConfig::default();
        cfg.network_id = 1;
        let mut keys = crate::KeyRing::default();
        let _ = keys.generate_id(id);
        let _ = keys.generate_id("v9");
        let mut node = Node::new(id, cfg, keys, &[]);
        node.register_validator("v9", 10_000_000_000);
        if let Some(pk) = node.keys.public_hex("v9") {
            if let Some(v) = node.validators.get_mut("v9") {
                v.public_key = pk;
            }
        }
        Arc::new(Shared {
            node: parking_lot::Mutex::new(node),
            inbound: parking_lot::Mutex::new(Vec::new()),
            hub_peer_idxs: Vec::new(),
            is_hub: true,
            is_archive: false,
            snapshot_out: PathBuf::from("/tmp/falcon-test-snap.bin"),
            snap_meta: parking_lot::Mutex::new(None),
            snap_publish: parking_lot::Mutex::new(()),
            hub_snap: parking_lot::Mutex::new(None),
            data_dir: PathBuf::from("/tmp"),
            disk_guard: fd_pl::disk::DiskGuard::default(),
            disk_skips: std::sync::atomic::AtomicU64::new(0),
            disk_last_skip: parking_lot::Mutex::new(String::new()),
            snap_pull: parking_lot::Mutex::new(None),
            snap_stash: parking_lot::Mutex::new(fd_pl::SnapStash::default()),
            snap_slow_judge: parking_lot::Mutex::new(fd_pl::SnapSlowJudge::default()),
            last_snap_chunk_ms: std::sync::atomic::AtomicU64::new(0),
            snap_pin_ms: std::sync::atomic::AtomicU64::new(0),
            served_shas: parking_lot::Mutex::new(std::collections::HashMap::new()),
            slow_snap_src: parking_lot::Mutex::new(std::collections::HashMap::new()),
            snap_nonserve: parking_lot::Mutex::new(std::collections::HashMap::new()),
            snap_pushed: parking_lot::Mutex::new(std::collections::HashMap::new()),
            ledger_slow: parking_lot::Mutex::new(fd_pl::catchup_slow::LedgerSlowList::default()),
            joiner: false,
            wire_from: Arc::new(parking_lot::Mutex::new(String::new())),
            blackhole: parking_lot::Mutex::new(std::collections::HashMap::new()),
            live_socks: parking_lot::Mutex::new(std::collections::HashMap::new()),
            tx_relay_wait: parking_lot::Mutex::new(std::collections::VecDeque::new()),
            tx_announced: parking_lot::Mutex::new(std::collections::HashSet::new()),
            dish_guard: parking_lot::Mutex::new(std::collections::HashSet::new()),
            piece_peers: parking_lot::Mutex::new(std::collections::HashSet::new()),
            gap_hard: parking_lot::Mutex::new(0),
            gap_named: parking_lot::Mutex::new(0),
            gap_dish: parking_lot::Mutex::new(0),
            gap_walk: parking_lot::Mutex::new((0, String::new())),
        })
    }

    fn big_line() -> String {
        let m = WireMsg::NeedMempoolTxs { ids: (0..12_000).map(|i| format!("tx{i:032}")).collect() };
        serde_json::to_string(&m).unwrap() + "\n"
    }

    fn byte_tx(slots: usize, cap: usize) -> (ByteTx, mpsc::Receiver<String>) {
        let (tx, rx) = mpsc::channel::<String>(slots);
        (ByteTx { tx, used: Arc::new(std::sync::atomic::AtomicUsize::new(0)), cap }, rx)
    }

    #[test]
    fn pieces_only_to_2_10_3_peers() {
        let sh = test_shared("v1");
        let line = big_line();
        assert!(line.len() > 300 * 1024);
        // Unknown / 2.10.2 peer: legacy single line.
        assert!(sh.pieces_for("old", &line).is_none());
        // Small line never pieced.
        sh.piece_peers.lock().insert("new".into());
        assert!(sh.pieces_for("new", "{\"type\":\"ping\"}\n").is_none());
        let ps = sh.pieces_for("new", &line).expect("2.10.3 peer gets pieces");
        assert!(ps.iter().all(|p| p.len() <= fd_pl::pieces::PIECE_MAX_LINE));
        assert!(ps.iter().all(|p| p.len() <= LARGE_LINE && line_must_send(p.as_bytes())));
        // Receiver joins them back to the exact original message.
        let mut asm = fd_pl::pieces::PieceAssembler::default();
        let mut got = None;
        for p in ps {
            if let Some(l) = unpiece_line(&mut asm, "v1", p.trim_end().to_string()) {
                assert!(got.is_none());
                got = Some(l);
            }
        }
        let got = got.unwrap();
        assert_eq!(got + "\n", line);
        // Normal lines pass straight through the reassembler.
        assert_eq!(unpiece_line(&mut asm, "v1", "{\"type\":\"ping\"}".into()).as_deref(), Some("{\"type\":\"ping\"}"));
    }

    #[test]
    fn mixed_version_queueing() {
        let sh = test_shared("v1");
        let line = big_line();
        sh.piece_peers.lock().insert("new".into());
        // Legacy peer: exactly one line, identical to the original.
        let (q, mut rx) = byte_tx(64, 8 << 20);
        assert!(q.send_maybe_pieced(line.clone(), sh.pieces_for("old", &line)));
        assert_eq!(rx.try_recv().unwrap(), line);
        assert!(rx.try_recv().is_err());
        // New peer: several in-order pieces.
        let (q, mut rx) = byte_tx(64, 8 << 20);
        assert!(q.send_maybe_pieced(line.clone(), sh.pieces_for("new", &line)));
        let mut idx = 0u32;
        while let Ok(l) = rx.try_recv() {
            match serde_json::from_str::<WireMsg>(l.trim()).unwrap() {
                WireMsg::Piece { i, .. } => assert_eq!(i, idx),
                _ => panic!(),
            }
            idx += 1;
        }
        assert!(idx > 1);
        // All or nothing: too few slots queues no piece at all.
        let (q, mut rx) = byte_tx(2, 8 << 20);
        assert!(!q.send_maybe_pieced(line.clone(), sh.pieces_for("new", &line)));
        assert!(rx.try_recv().is_err());
        assert_eq!(q.used.load(std::sync::atomic::Ordering::Relaxed), 0);
        // Plain reply channel without room for the run falls back to legacy.
        let (tx, mut rx) = mpsc::channel::<String>(2);
        assert!(reply_send_pieced(&tx, line.clone(), sh.pieces_for("new", &line)));
        assert_eq!(rx.try_recv().unwrap(), line);
    }

    #[test]
    fn peer_ack_suppression_rules() {
        let ok = WireMsg::Ok { msg: "tx duplicate".into() };
        let err = WireMsg::Err { msg: "header-known".into() };
        let need_body = WireMsg::NeedLedgerBody { ledger_hash: "h1".into() };

        // (a) After Hello (`inbound_registered == true, was_hello == false`), Ok/Err acks are suppressed,
        // while data replies still flow.
        assert!(should_drop_inbound_reply(true, false, &ok));
        assert!(should_drop_inbound_reply(true, false, &err));
        assert!(!should_drop_inbound_reply(true, false, &need_body));

        // (b) Without Hello (`inbound_registered == false`, e.g. falcon-pl-ctl RPC), Ok/Err acks still flow.
        assert!(!should_drop_inbound_reply(false, false, &ok));
        assert!(!should_drop_inbound_reply(false, false, &err));

        // (c) On the Hello message itself (`was_hello == true`), a Hello-reject Err is never suppressed.
        assert!(!should_drop_inbound_reply(false, true, &err));
        assert!(!should_drop_inbound_reply(true, true, &err));
    }

    #[test]
    fn reply_dropped_warning_is_rate_limited() {
        let last = AtomicU64::new(0);
        let sup = AtomicU64::new(0);

        // First drop logs immediately with 0 suppressed.
        assert_eq!(should_log_reply_dropped(1_000, &last, &sup), Some(0));
        // Drops within the 10s window are suppressed and counted.
        for t in [1_100, 2_500, 5_000, 10_999] {
            assert_eq!(should_log_reply_dropped(t, &last, &sup), None);
        }
        // Once 10s have elapsed, logs again and reports 4 suppressed warnings.
        assert_eq!(should_log_reply_dropped(11_000, &last, &sup), Some(4));
        assert_eq!(should_log_reply_dropped(11_001, &last, &sup), None);
        assert_eq!(should_log_reply_dropped(21_000, &last, &sup), Some(1));
    }

    #[tokio::test]
    async fn inbound_session_hello_suppresses_acks_while_rpc_and_hello_reject_receive_replies() {
        let shared = test_shared("v99");
        let fanout = Arc::new(Vec::new());

        // Case (a): Session sends valid Hello as mesh peer "v9" (`we_dial("v99", "v9")` is false),
        // followed by a SkipPacker with bad signature (normally returns WireMsg::Err)
        // and then StatusReq (returns WireMsg::Status). The Err ack is suppressed so Status arrives immediately.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let sh1 = shared.clone();
        let f1 = fanout.clone();
        let srv1 = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let _ = handle_inbound(sock, sh1, f1, "v99").await;
        });

        let client = TcpStream::connect(addr).await.unwrap();
        let (cr, mut cw) = client.into_split();
        let mut lines = BufReader::new(cr).lines();
        let srv_hello: WireMsg = serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
        assert!(matches!(srv_hello, WireMsg::Hello { .. }));

        let hello = WireMsg::Hello {
            id: "v9".into(),
            public_key: String::new(),
            validators: BTreeMap::new(),
            publics: BTreeMap::new(),
            tip_height: 0,
            tip_hash: String::new(),
            is_hub: false,
            mempool_len: 0,
            product_version: PRODUCT_VERSION.into(),
            hello_network_id: 1,
            archive: false,
            snap_height: 0,
            release_version: String::new(),
            capabilities: Vec::new(),
        };
        cw.write_all((serde_json::to_string(&hello).unwrap() + "\n").as_bytes()).await.unwrap();

        let bad_skip = WireMsg::SubmitTx {
            tx: fd_pl::Tx {
                tx_id: "tx-invalid-sig".into(),
                account: "alice".into(),
                destination: "bob".into(),
                amount: 100,
                fee: 1000,
                sequence: 0,
                signature: "deadbeef".into(),
                public_key: String::new(),
                body: fd_pl::TxBody::default(),
                network_id: 1,
            },
        };
        cw.write_all((serde_json::to_string(&bad_skip).unwrap() + "\n").as_bytes()).await.unwrap();
        let status_req = WireMsg::StatusReq {
            include_accounts: false,
            brief: true,
        };
        cw.write_all((serde_json::to_string(&status_req).unwrap() + "\n").as_bytes()).await.unwrap();

        let next_reply: WireMsg = serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
        assert!(
            matches!(next_reply, WireMsg::Status { .. }),
            "expected Status right away with SkipPacker's Err ack suppressed, got {next_reply:?}"
        );
        drop(cw);
        let _ = srv1.await;

        // Case (b): Session WITHOUT Hello (like falcon-pl-ctl RPC) sends bad SkipPacker and STILL receives WireMsg::Err
        let listener2 = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr2 = listener2.local_addr().unwrap();
        let sh2 = shared.clone();
        let f2 = fanout.clone();
        let srv2 = tokio::spawn(async move {
            let (sock, _) = listener2.accept().await.unwrap();
            let _ = handle_inbound(sock, sh2, f2, "v99").await;
        });
        let client2 = TcpStream::connect(addr2).await.unwrap();
        let (cr2, mut cw2) = client2.into_split();
        let mut lines2 = BufReader::new(cr2).lines();
        let _ = lines2.next_line().await.unwrap().unwrap();
        cw2.write_all((serde_json::to_string(&bad_skip).unwrap() + "\n").as_bytes()).await.unwrap();
        let rpc_reply: WireMsg = serde_json::from_str(&lines2.next_line().await.unwrap().unwrap()).unwrap();
        assert!(
            matches!(rpc_reply, WireMsg::Err { .. }),
            "expected non-Hello RPC session to receive WireMsg::Err, got {rpc_reply:?}"
        );
        drop(cw2);
        let _ = srv2.await;

        // Case (c): Hello-reject error (wrong network_id) still goes out before session closes
        let bad_hello = WireMsg::Hello {
            id: "v9".into(),
            public_key: String::new(),
            validators: BTreeMap::new(),
            publics: BTreeMap::new(),
            tip_height: 0,
            tip_hash: String::new(),
            is_hub: false,
            mempool_len: 0,
            product_version: PRODUCT_VERSION.into(),
            hello_network_id: 999,
            archive: false,
            snap_height: 0,
            release_version: String::new(),
            capabilities: Vec::new(),
        };
        let mut gate = HelloSession::default();
        let verdict = gate.check(&shared.node.lock(), &bad_hello);
        assert!(
            matches!(verdict, HelloGate::Close(_)),
            "expected HelloGate::Close on wrong network_id"
        );
        let replies = dispatch_wire(&shared, bad_hello, None, true, false, "test-peer", 0);
        assert_eq!(replies.len(), 1);
        assert!(matches!(replies[0], WireMsg::Err { .. }));
        assert!(!should_drop_inbound_reply(false, true, &replies[0]));
    }

    #[test]
    fn session_peer_repush_keys_are_isolated() {
        let shared = test_shared("v1");
        // Without a real pin / archive flag, NeedSnapshot returns SnapshotNo —
        // still exercises session_peer path without touching shared wire_from.
        *shared.wire_from.lock() = "stale-v6".into();
        let a = dispatch_wire(
            &shared,
            WireMsg::NeedSnapshot {},
            None,
            false,
            false,
            "crypto-dashboard",
            0,
        );
        let b = dispatch_wire(
            &shared,
            WireMsg::NeedSnapshot {},
            None,
            false,
            false,
            "other-joiner",
            0,
        );
        assert!(!a.is_empty() && !b.is_empty());
        // wire_from must remain untouched by dispatch (session_peer only).
        assert_eq!(shared.wire_from.lock().as_str(), "stale-v6");
        // Distinct session peers must not collide on empty repush keying.
        assert!(matches!(a[0], WireMsg::SnapshotNo { .. }));
        assert!(matches!(b[0], WireMsg::SnapshotNo { .. }));
    }

    #[test]
    fn snapshot_no_not_archive_marks_nonserve_not_stalled() {
        let shared = test_shared("v1");
        let _ = process_msg(
            &shared,
            WireMsg::SnapshotNo {
                reason: "not archive".into(),
            },
            None,
            false,
            false,
            "v12",
        );
        assert!(shared.slow_snap_src.lock().is_empty());
        assert!(shared.snap_nonserve.lock().contains_key("v12"));
    }

    #[test]
    fn item16_admin_mempool_drop_and_leader_empty_block_fallback() {
        let shared = test_shared("v1");
        let nid = shared.node.lock().cfg.network_id;
        let mut uk = crate::KeyRing::default();
        for acct in ["alice", "bob", "carol", "dave"] {
            let _ = uk.generate_id(acct);
        }

        {
            let mut n = shared.node.lock();
            n.cfg.pack_budget_ms = 0;
            n.cfg.min_fee = 0;
            n.cfg.fee_escalate = false;
            n.bitvm2_m1_from_height = 0;
            n.empty_block_from_height = 0;
            n.register_validator("v1", 10_000_000_000);
            for v in ["v1", "v9"] {
                n.pong(v);
            }
            for acct in ["alice", "bob", "carol", "dave"] {
                let _ = n.keys.insert_public(acct, &uk.public_hex(acct).unwrap());
                let mut a = n.state.get(acct);
                a.balance = 50_000;
                if acct == "bob" {
                    a.meta.public_key = uk.public_hex("bob").unwrap();
                }
                n.state.accounts.insert(acct.into(), a);
            }

            // Insert a valid tx for bob and test admin RPC MempoolDrop
            let tx_bob = fd_pl::Tx::sign_with(&uk, "bob", 1, "alice", 10, 2, nid).unwrap();
            assert!(n.submit_tx(tx_bob.clone()).unwrap());
            drop(n);

            let replies = dispatch_wire(
                &shared,
                WireMsg::MempoolDrop {
                    target: tx_bob.tx_id.clone(),
                },
                None,
                false,
                true,
                "admin",
                0,
            );
            assert_eq!(replies.len(), 1);
            match &replies[0] {
                WireMsg::Ok { msg } => assert!(msg.contains("evicted=1"), "unexpected msg: {msg}"),
                other => panic!("expected WireMsg::Ok, got {other:?}"),
            }

            let mut n = shared.node.lock();
            assert!(n.mempool.is_empty());

            // Now insert all 4 invalid error classes into the leader's mempool and verify leader seals an empty block:
            let op_xonly = "11".repeat(32);
            let dep_txid = "aa".repeat(32);
            let k2_txid = "bb".repeat(32);
            let af_txid = "cc".repeat(32);
            let op_params = n.operator_params();
            n.bridge
                .operators
                .register(&op_params, "alice", &op_xonly, op_params.min_bond, 0)
                .unwrap();
            n.bridge
                .operators
                .bind_graph("alice", &dep_txid, &k2_txid, &af_txid, 0)
                .unwrap();
            n.create_market("m-usdc", "USDC").unwrap();
            n.defi.credit_asset("bob", "USDC", 50_000);
            n.lend_supply("m-usdc", "bob", 10_000).unwrap();
            n.open_vault("dave", "alice").unwrap();

            let tx1 = fd_pl::Tx::sign_body(
                &uk,
                "alice",
                n.state.get("alice").sequence,
                "",
                0,
                2,
                nid,
                fd_pl::TxBody::OperatorGraphBind {
                    deposit_txid: dep_txid,
                    kick_off_2_txid: k2_txid,
                    assert_final_txid: af_txid,
                    depositor_account: String::new(),
                    cosign: false,
                },
            )
            .unwrap();
            let tx2 = fd_pl::Tx::sign_body(
                &uk,
                "bob",
                n.state.get("bob").sequence,
                "",
                0,
                2,
                nid,
                fd_pl::TxBody::LendBorrow {
                    market_id: "m-usdc".into(),
                    amount: 5_000,
                    collateral_fpl: 100,
                },
            )
            .unwrap();
            let tx3 = fd_pl::Tx::sign_body(
                &uk,
                "carol",
                n.state.get("carol").sequence,
                "bob",
                10,
                2,
                nid,
                fd_pl::TxBody::PayToKey {
                    key_hash: "33".repeat(32),
                },
            )
            .unwrap();
            let tx4 = fd_pl::Tx::sign_body(
                &uk,
                "dave",
                n.state.get("dave").sequence,
                "",
                0,
                2,
                nid,
                fd_pl::TxBody::VaultOpen {
                    destination: "alice".into(),
                },
            )
            .unwrap();

            let max_mp = n.cfg.max_mempool_txs;
            for tx in [tx1, tx2, tx3, tx4] {
                assert!(!n.is_tx_applicable(&tx));
                let _ = n.mempool.insert(tx, max_mp);
            }
            assert!(n.mempool.len() > 0 && !n.has_applicable_tx());

            let winner = n.lottery_packer().unwrap();
            let sealed = n
                .pack_or_skip(&winner)
                .expect("pack_or_skip must succeed")
                .expect("leader must seal an empty fallback block after evicting invalid txs");
            assert_eq!(sealed.height, 1);
            assert!(sealed.txs.is_empty());
            assert!(n.mempool.is_empty());
        }
    }
}
