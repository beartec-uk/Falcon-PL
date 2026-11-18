// Copyright (c) 2025-2026 BEARTEC. All rights reserved. See LICENSE.
//! Node health snapshot (`falcon.health.v1`) and the `falcon-node dash` renderer.
//!
//! Read-only. The node answers [`crate::WireMsg::HealthReq`] on its existing
//! local wire address (and the admin unix socket) with
//! [`crate::WireMsg::Health`]. Schema: `docs/ops/NODE_HEALTH_SCHEMA.md`.
//!
//! Cheap by construction (lesson from 2.9.58): [`crate::Node::health_core`]
//! copies scalars and walks at most [`CHAIN_SCAN_CAP`] retained ledgers under
//! `node.lock`; no roots, no accounts, no attestations. Process, disk, peer
//! and log data are gathered by the caller after the lock is dropped.

use parking_lot::Mutex;
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::sync::OnceLock;

pub const HEALTH_SCHEMA: &str = "falcon.health.v1";
/// Most retained ledgers inspected per request (blocks/min, last proposal, epoch proposals).
pub const CHAIN_SCAN_CAP: usize = 4096;
/// Sparkline window: one bucket per minute.
pub const SPARK_MINUTES: usize = 30;
/// Lag (blocks) at or above which the node reports `syncing`.
pub const SYNCING_LAG: u64 = 8;
/// Log warnings/errors kept in memory.
pub const WARN_RING_CAP: usize = 64;

// ---------------------------------------------------------------- start time

static START_MS: OnceLock<u64> = OnceLock::new();

fn wall_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Record process start (idempotent). Called early in node `main`.
pub fn mark_start() -> u64 {
    *START_MS.get_or_init(wall_ms)
}

pub fn uptime_secs(now_ms: u64) -> u64 {
    now_ms.saturating_sub(mark_start()) / 1000
}

// ---------------------------------------------------------------- warn ring

#[derive(Clone, Debug, PartialEq)]
pub struct WarnEntry {
    pub at_ms: u64,
    pub level: &'static str,
    pub target: String,
    pub msg: String,
}

static WARN_RING: Mutex<VecDeque<WarnEntry>> = Mutex::new(VecDeque::new());

/// Max chars kept per message (bounded memory; also keeps the JSON small).
const WARN_MSG_MAX: usize = 240;

pub fn note_warning(level: &'static str, target: &str, msg: &str) {
    let mut m: String = msg.chars().take(WARN_MSG_MAX).collect();
    if msg.chars().count() > WARN_MSG_MAX {
        m.push('…');
    }
    let mut r = WARN_RING.lock();
    if r.len() >= WARN_RING_CAP {
        r.pop_front();
    }
    r.push_back(WarnEntry {
        at_ms: wall_ms(),
        level,
        target: target.to_string(),
        msg: m,
    });
}

/// Newest last, at most `n`.
pub fn recent_warnings(n: usize) -> Vec<WarnEntry> {
    let r = WARN_RING.lock();
    let skip = r.len().saturating_sub(n);
    r.iter().skip(skip).cloned().collect()
}

pub fn warnings_json(n: usize) -> Value {
    Value::Array(
        recent_warnings(n)
            .into_iter()
            .map(|w| json!({"at_ms": w.at_ms, "level": w.level, "target": w.target, "msg": w.msg}))
            .collect(),
    )
}

/// `tracing` layer copying WARN/ERROR events into the ring. Cheap: one
/// short mutex hold per warning; never touches `node.lock`.
pub struct WarnCapture;

struct MsgVisitor(String);

impl tracing::field::Visit for MsgVisitor {
    fn record_str(&mut self, f: &tracing::field::Field, v: &str) {
        if f.name() == "message" {
            self.0 = v.to_string();
        }
    }
    fn record_debug(&mut self, f: &tracing::field::Field, v: &dyn std::fmt::Debug) {
        if f.name() == "message" {
            self.0 = format!("{v:?}");
        }
    }
}

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for WarnCapture {
    fn on_event(&self, ev: &tracing::Event<'_>, _ctx: tracing_subscriber::layer::Context<'_, S>) {
        let lvl = *ev.metadata().level();
        let level = if lvl == tracing::Level::ERROR {
            "ERROR"
        } else if lvl == tracing::Level::WARN {
            "WARN"
        } else {
            return;
        };
        let mut v = MsgVisitor(String::new());
        ev.record(&mut v);
        note_warning(level, ev.metadata().target(), &v.0);
    }
}

// ---------------------------------------------------------------- observed tip rate

/// Ledger `sealed_at_ms` is a chain stamp, not wall time (it can trail the
/// wall clock by minutes), so blocks/min and "last block age" come from when
/// this process *saw* the tip advance. Fed by the node's 1 s observer task
/// and by every health request.
static TIP_SEEN: Mutex<VecDeque<(u64, u64)>> = Mutex::new(VecDeque::new());
const TIP_SEEN_KEEP_MS: u64 = (SPARK_MINUTES as u64 + 1) * 60_000;

pub fn observe_tip(now_ms: u64, height: u64) {
    let mut q = TIP_SEEN.lock();
    match q.back() {
        Some(&(_, h)) if h == height => {}
        _ => q.push_back((now_ms, height)),
    }
    while q.len() > 2 && q.front().map(|f| now_ms.saturating_sub(f.0) > TIP_SEEN_KEEP_MS).unwrap_or(false) {
        q.pop_front();
    }
}

/// (blocks/min over 5 min, 30 per-minute block counts, ms since tip last advanced).
pub fn tip_rate_from(seen: &[(u64, u64)], now_ms: u64) -> (f64, Vec<u64>, Option<u64>) {
    let mut spark = vec![0u64; SPARK_MINUTES];
    let mut in5 = 0u64;
    for w in seen.windows(2) {
        let ((_, h0), (t1, h1)) = (w[0], w[1]);
        let d = h1.saturating_sub(h0);
        let age = now_ms.saturating_sub(t1);
        let m = (age / 60_000) as usize;
        if m < SPARK_MINUTES {
            spark[SPARK_MINUTES - 1 - m] += d;
        }
        if age < 5 * 60_000 {
            in5 += d;
        }
    }
    // Before 5 min of observation, rate over what we have.
    let span = seen.first().map(|f| now_ms.saturating_sub(f.0)).unwrap_or(0).clamp(1, 5 * 60_000);
    let bpm = ((in5 as f64 * 60_000.0 / span as f64) * 10.0).round() / 10.0;
    let last = if seen.len() >= 2 { seen.last().map(|l| now_ms.saturating_sub(l.0)) } else { None };
    (bpm, spark, last)
}

pub fn tip_rate(now_ms: u64) -> (f64, Vec<u64>, Option<u64>) {
    let v: Vec<(u64, u64)> = TIP_SEEN.lock().iter().copied().collect();
    tip_rate_from(&v, now_ms)
}

// ---------------------------------------------------------------- process / disk

#[derive(Clone, Copy)]
struct CpuSample {
    wall_ms: u64,
    ticks: u64,
}
static LAST_CPU: Mutex<Option<CpuSample>> = Mutex::new(None);

fn clk_tck() -> u64 {
    // SAFETY: sysconf is thread-safe and has no preconditions.
    let t = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if t > 0 { t as u64 } else { 100 }
}

fn page_size() -> u64 {
    // SAFETY: as above.
    let p = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if p > 0 { p as u64 } else { 4096 }
}

/// utime+stime ticks from a `/proc/<pid>/stat` line (comm may contain spaces).
pub fn parse_proc_stat_ticks(s: &str) -> Option<u64> {
    let rest = &s[s.rfind(')')? + 1..];
    let f: Vec<&str> = rest.split_whitespace().collect();
    // after ')' field 0 is state (#3); utime=#14, stime=#15 -> idx 11, 12
    Some(f.get(11)?.parse::<u64>().ok()? + f.get(12)?.parse::<u64>().ok()?)
}

/// CPU% since the previous call (first call: since process start) and RSS.
pub fn process_json(now_ms: u64) -> Value {
    let ticks = std::fs::read_to_string("/proc/self/stat")
        .ok()
        .and_then(|s| parse_proc_stat_ticks(&s));
    let rss = std::fs::read_to_string("/proc/self/statm").ok().and_then(|s| {
        s.split_whitespace()
            .nth(1)
            .and_then(|x| x.parse::<u64>().ok())
            .map(|p| p * page_size())
    });
    let mem_total = std::fs::read_to_string("/proc/meminfo").ok().and_then(|s| {
        s.lines()
            .find(|l| l.starts_with("MemTotal:"))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|k| k.parse::<u64>().ok())
            .map(|k| k * 1024)
    });
    let load = std::fs::read_to_string("/proc/loadavg").ok().map(|s| {
        s.split_whitespace()
            .take(3)
            .filter_map(|x| x.parse::<f64>().ok())
            .collect::<Vec<_>>()
    });
    let cpu_pct = ticks.map(|t| {
        let hz = clk_tck() as f64;
        let mut last = LAST_CPU.lock();
        let (w0, t0) = match *last {
            Some(c) => (c.wall_ms, c.ticks),
            None => (mark_start(), 0),
        };
        *last = Some(CpuSample { wall_ms: now_ms, ticks: t });
        let dt_ms = now_ms.saturating_sub(w0).max(1) as f64;
        let used_ms = t.saturating_sub(t0) as f64 * 1000.0 / hz;
        ((used_ms / dt_ms) * 1000.0).round() / 10.0
    });
    json!({
        "pid": std::process::id(),
        "cpu_pct": cpu_pct,
        "rss_bytes": rss,
        "mem_total_bytes": mem_total,
        "cpus": std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1),
        "loadavg": load,
    })
}

// ---------------------------------------------------------------- pure helpers

/// active / jailed / inactive / syncing / observer.
pub fn classify_status(
    seat: Option<(bool /*jailed*/, bool /*inactive*/, u64 /*bond*/)>,
    lag: u64,
    need_hard_resync: bool,
) -> &'static str {
    match seat {
        Some((true, _, _)) => "jailed",
        Some((_, true, _)) | Some((_, _, 0)) => "inactive",
        _ if need_hard_resync || lag >= SYNCING_LAG => "syncing",
        Some(_) => "active",
        None => "observer",
    }
}

/// Per-minute block counts, oldest first, `minutes` buckets ending at `now_ms`.
pub fn minute_buckets(sealed_ms: &[u64], now_ms: u64, minutes: usize) -> Vec<u32> {
    let mut b = vec![0u32; minutes];
    for &t in sealed_ms {
        if t > now_ms {
            continue;
        }
        let age_min = ((now_ms - t) / 60_000) as usize;
        if age_min < minutes {
            b[minutes - 1 - age_min] += 1;
        }
    }
    b
}

/// Blocks/min over the last `window_ms`.
pub fn blocks_per_min(sealed_ms: &[u64], now_ms: u64, window_ms: u64) -> f64 {
    let n = sealed_ms
        .iter()
        .filter(|&&t| t <= now_ms && now_ms - t < window_ms)
        .count() as f64;
    let r = n * 60_000.0 / window_ms.max(1) as f64;
    (r * 10.0).round() / 10.0
}

impl crate::Node {
    /// Seat operator balances for the health snapshot. Integer FPL, read from
    /// ledger state only: liquid balance and pending (claimable) rewards of the
    /// node id, bonded / unbonding amount of its seat, and the liquid balance of
    /// the seat's bond account when it differs. Never touches key material.
    pub fn health_balance(&self, seat: Option<&crate::ValidatorInfo>) -> Value {
        let liquid = |acct: &str| self.state.accounts.get(acct).map(|a| a.balance).unwrap_or(0);
        let bond_account = seat
            .map(|v| v.bond_account.clone())
            .filter(|a| !a.is_empty() && *a != self.id);
        json!({
            "account": self.id,
            "liquid": liquid(&self.id),
            "pending_rewards": self.claimable.get(&self.id).copied().unwrap_or(0),
            "seat_claimable": seat.map(|v| v.seat_claimable).unwrap_or(0),
            "seat_payout": seat.and_then(|v| v.seat_payout.clone()),
            "bonded": seat.map(|v| v.bond).unwrap_or(0),
            "unbonding": seat.map(|v| v.unbonding).unwrap_or(0),
            "unbond_ready_ms": seat.map(|v| v.unbond_ready_ms).unwrap_or(0),
            // Chain time (tip `sealed_at`), the clock CompleteUnbond is checked against.
            "unbond_ready": seat.map(|v| v.unbonding > 0 && self.parent_sealed_at() >= v.unbond_ready_ms).unwrap_or(false),
            "unbond_remaining_ms": seat
                .filter(|v| v.unbonding > 0)
                .map(|v| v.unbond_ready_ms.saturating_sub(self.parent_sealed_at()))
                .unwrap_or(0),
            "bond_account": bond_account,
            "bond_account_liquid": bond_account.as_deref().map(liquid),
        })
    }

    /// Cheap health fields. Safe to call under `node.lock`: scalar copies plus
    /// one reverse walk of at most [`CHAIN_SCAN_CAP`] retained ledgers.
    pub fn health_core(&self) -> Value {
        let now = self.now_ms.max(1);
        let lag = self.tip_lag();
        let seat = self.validators.get(&self.id);
        let epoch = self.current_epoch();
        let epoch_ms = self.cfg.epoch_ms.max(1);
        // epoch_index is 1-based: epoch N spans genesis + (N-1)*epoch_ms ..
        let epoch_start = self
            .genesis_ms
            .saturating_add(epoch.saturating_sub(1).saturating_mul(epoch_ms));
        let spark_from = now.saturating_sub(SPARK_MINUTES as u64 * 60_000);
        let mut sealed = Vec::new();
        let mut last_prop: Option<(u64, u64)> = None;
        let mut epoch_props = 0u64;
        let mut scanned = 0usize;
        let mut last_block: Option<(u64, u64, String, String)> = None;
        for l in self.chain.iter().rev().take(CHAIN_SCAN_CAP) {
            scanned += 1;
            if last_block.is_none() {
                last_block = Some((l.height, l.sealed_at_ms, l.ledger_hash.clone(), l.packer.clone()));
            }
            if l.sealed_at_ms >= spark_from {
                sealed.push(l.sealed_at_ms);
            }
            if l.packer == self.id {
                if last_prop.is_none() {
                    last_prop = Some((l.height, l.sealed_at_ms));
                }
                if l.sealed_at_ms >= epoch_start {
                    epoch_props += 1;
                }
            }
            if l.sealed_at_ms < spark_from && l.sealed_at_ms < epoch_start && last_prop.is_some() {
                break;
            }
        }
        let status = classify_status(
            seat.map(|v| (v.jailed, v.inactive, v.bond)),
            lag,
            self.need_hard_resync,
        );
        let tip = self.best_peer_tip.max(self.tip_height);
        json!({
            "schema": HEALTH_SCHEMA,
            "node": {
                "id": self.id,
                "version": crate::PRODUCT_VERSION,
                "network": crate::NETWORK_NAME,
                "network_id": self.cfg.network_id,
                "role": if self.is_hub { "hub" } else if seat.is_some() { "validator" } else { "observer" },
                "uptime_secs": uptime_secs(wall_ms()),
                "status": status,
            },
            "chain": {
                "local_height": self.tip_height,
                "tip_hash": self.tip_hash,
                "network_tip": tip,
                "best_peer_tip": self.best_peer_tip,
                "lag": lag,
                "blocks_per_min": blocks_per_min(&sealed, now, 5 * 60_000),
                "blocks_per_min_spark": minute_buckets(&sealed, now, SPARK_MINUTES),
                "last_block": last_block.map(|(h, t, hash, p)| json!({
                    "height": h, "sealed_at_ms": t, "age_ms": now.saturating_sub(t), "hash": hash, "packer": p,
                })),
                "need_hard_resync": self.need_hard_resync,
            },
            "consensus": {
                "epoch": epoch,
                "epoch_ms": epoch_ms,
                "epoch_progress_pct": ((now.saturating_sub(epoch_start)) * 100 / epoch_ms).min(100),
                "last_proposal": last_prop.map(|(h, t)| json!({"height": h, "sealed_at_ms": t})),
                "proposals_this_epoch": epoch_props,
                "proposals_scan_capped": scanned >= CHAIN_SCAN_CAP,
                "votes_this_epoch": self.epoch_work.check_votes.get(&self.id).copied().unwrap_or(0),
                "missed_turns": seat.map(|v| v.missed_turns).unwrap_or(0),
                "missed_turns_limit": crate::params_v2::MISSED_TURNS_INACTIVE,
                "bond": seat.map(|v| v.bond).unwrap_or(0),
                "jailed": seat.map(|v| v.jailed).unwrap_or(false),
                "inactive": seat.map(|v| v.inactive).unwrap_or(false),
                "online_member": self.online_members.contains(&self.id),
                "validators": self.validators.len(),
            },
            // 2.9.79: operator balances (read-only; three map lookups, no keys).
            "balance": self.health_balance(seat),
            "mempool": {
                "size": self.mempool.len(),
                "max": self.cfg.max_mempool_txs,
            },
            "peers": {
                "seats": self.validators.values().filter(|v| v.id != self.id).map(|v| json!({
                    "id": v.id,
                    "tip": v.last_advertised_tip,
                    "pong_age_ms": if v.last_pong_ms == 0 { Value::Null } else { now.saturating_sub(v.last_pong_ms).into() },
                    "account": v.bond_account,
                    "release_version": self.peer_release_label(&v.id),
                    "hello_age_ms": self.peer_releases.get(&v.id).map(|(_, t)| now.saturating_sub(*t)),
                })).collect::<Vec<_>>(),
                // v2.10.3: every peer that said Hello (seats and non-seats).
                "releases": self.peer_releases.iter().map(|(id, (r, t))| json!({
                    "id": id,
                    "account": self.validators.get(id).map(|v| v.bond_account.clone()),
                    "release_version": if r.is_empty() { crate::PEER_RELEASE_NONE } else { r.as_str() },
                    "last_seen_ms": t,
                    "hello_age_ms": now.saturating_sub(*t),
                })).collect::<Vec<_>>(),
            },
        })
    }
}

// ---------------------------------------------------------------- dash rendering

pub mod dash {
    use serde_json::Value;

    pub const RESET: &str = "\x1b[0m";
    const CYAN: &str = "\x1b[36;1m";
    const GREEN: &str = "\x1b[32m";
    const YELLOW: &str = "\x1b[33m";
    const RED: &str = "\x1b[31m";
    const DIM: &str = "\x1b[2m";

    pub struct Style {
        pub color: bool,
    }

    impl Style {
        fn c(&self, code: &str, s: &str) -> String {
            if self.color { format!("{code}{s}{RESET}") } else { s.to_string() }
        }
    }

    pub fn sparkline(v: &[u64]) -> String {
        const B: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
        let max = v.iter().copied().max().unwrap_or(0).max(1);
        v.iter().map(|&x| B[((x * 7) / max) as usize]).collect()
    }

    pub fn bar(frac: f64, width: usize) -> String {
        let f = frac.clamp(0.0, 1.0);
        let n = (f * width as f64).round() as usize;
        format!("[{}{}]", "|".repeat(n), " ".repeat(width - n))
    }

    pub fn human_bytes(b: u64) -> String {
        let g = b as f64 / 1_073_741_824.0;
        if g >= 1.0 { format!("{g:.1}G") } else { format!("{:.0}M", b as f64 / 1_048_576.0) }
    }

    pub fn human_dur(secs: u64) -> String {
        let (d, h, m) = (secs / 86_400, (secs / 3600) % 24, (secs / 60) % 60);
        if d > 0 { format!("{d}d {h:02}h {m:02}m") } else { format!("{h:02}h {m:02}m {:02}s", secs % 60) }
    }

    fn u(v: &Value, p: &str) -> Option<u64> {
        v.pointer(p).and_then(|x| x.as_u64())
    }
    fn s<'a>(v: &'a Value, p: &str) -> &'a str {
        v.pointer(p).and_then(|x| x.as_str()).unwrap_or("?")
    }
    fn num(n: Option<u64>) -> String {
        n.map(|x| x.to_string()).unwrap_or_else(|| "?".into())
    }
    fn hhmmss(ms: u64) -> String {
        let t = (ms / 1000) % 86_400;
        format!("{:02}:{:02}:{:02}", t / 3600, (t / 60) % 60, t % 60)
    }

    fn panel(st: &Style, title: &str, lines: Vec<String>) -> Vec<String> {
        let mut out = vec![st.c(CYAN, &format!("┤ {title} ├"))];
        out.extend(lines.into_iter().map(|l| format!("  {l}")));
        out
    }

    /// Full frame for a `falcon.health.v1` body. Plain text lines (ANSI
    /// colour optional) so it works over any SSH terminal.
    pub fn render_health(h: &Value, st: &Style, addr: &str, now_label: &str) -> Vec<String> {
        let mut o = Vec::new();
        let status = s(h, "/node/status");
        let scol = match status {
            "active" => GREEN,
            "syncing" => YELLOW,
            _ => RED,
        };
        o.push(st.c(
            CYAN,
            &format!(
                "falcon-node dash — {} @ {addr} · network {} · epoch {} · {now_label} · q quits",
                s(h, "/node/id"),
                num(u(h, "/node/network_id")),
                num(u(h, "/consensus/epoch")),
            ),
        ));
        o.extend(panel(st, "Node", vec![
            format!("ID        {}", s(h, "/node/id")),
            format!("Version   {}", s(h, "/node/version")),
            format!("Network   {} ({})", num(u(h, "/node/network_id")), s(h, "/node/network")),
            format!("Uptime    {}", u(h, "/node/uptime_secs").map(human_dur).unwrap_or("?".into())),
            format!("Status    {}", st.c(scol, &format!("● {}", status.to_uppercase()))),
            format!("Role      {}", s(h, "/node/role")),
        ]));
        let lag = u(h, "/chain/lag").unwrap_or(0);
        let lcol = if lag < 3 { GREEN } else if lag < super::SYNCING_LAG { YELLOW } else { RED };
        let spark: Vec<u64> = h
            .pointer("/chain/blocks_per_min_spark")
            .and_then(|a| a.as_array())
            .map(|a| a.iter().filter_map(|x| x.as_u64()).collect())
            .unwrap_or_default();
        let bpm = h.pointer("/chain/blocks_per_min").and_then(|x| x.as_f64()).unwrap_or(0.0);
        let mut chain = vec![
            format!("Local height   {}", num(u(h, "/chain/local_height"))),
            format!("Network tip    {}", num(u(h, "/chain/network_tip"))),
            format!("Lag            {}", st.c(lcol, &format!("{lag} blocks"))),
            format!("Blocks/min     {bpm:.1}  (5 min)"),
            format!("Last {}m      {}", spark.len(), sparkline(&spark)),
        ];
        if let Some(lb) = h.pointer("/chain/last_block").filter(|v| !v.is_null()) {
            let hash = s(lb, "/hash");
            let short = if hash.len() > 12 { format!("{}…{}", &hash[..6], &hash[hash.len() - 4..]) } else { hash.into() };
            chain.push(format!(
                "Last block     {}s ago  by {}  {short}",
                u(h, "/chain/tip_advanced_age_ms").or(u(lb, "/age_ms")).unwrap_or(0) / 1000,
                s(lb, "/packer")
            ));
        }
        o.extend(panel(st, "Chain", chain));
        let missed = u(h, "/consensus/missed_turns").unwrap_or(0);
        let limit = u(h, "/consensus/missed_turns_limit").unwrap_or(20).max(1);
        let mcol = if missed == 0 { GREEN } else if missed * 2 < limit { YELLOW } else { RED };
        let lp = h
            .pointer("/consensus/last_proposal")
            .filter(|v| !v.is_null())
            .map(|p| format!("#{} at {}Z", num(u(p, "/height")), hhmmss(u(p, "/sealed_at_ms").unwrap_or(0))))
            .unwrap_or_else(|| "none in retained window".into());
        o.extend(panel(st, "Consensus", vec![
            format!("Epoch          {}  ({}%)", num(u(h, "/consensus/epoch")), num(u(h, "/consensus/epoch_progress_pct"))),
            format!("Proposals      {} this epoch", num(u(h, "/consensus/proposals_this_epoch"))),
            format!("Last proposal  {lp}"),
            format!("Votes          {} this epoch", num(u(h, "/consensus/votes_this_epoch"))),
            format!("Missed turns   {} {}", st.c(mcol, &format!("{missed}/{limit}")), bar(missed as f64 / limit as f64, 20)),
            format!("Bond           {} FPL", num(u(h, "/consensus/bond"))),
            match h.get("balance").filter(|b| b.is_object()) {
                Some(b) => format!("Balance        {}", super::balance::one_line(b)),
                None => "Balance        n/a".to_string(),
            },
            format!("Mempool        {} / {}", num(u(h, "/mempool/size")), num(u(h, "/mempool/max"))),
        ]));
        let local = u(h, "/chain/local_height").unwrap_or(0);
        let mut peers = vec![format!(
            "Connected  {}  (outbound {} · inbound {})",
            num(u(h, "/peers/count")),
            num(u(h, "/peers/outbound")),
            num(u(h, "/peers/inbound"))
        )];
        if let Some(a) = h.pointer("/peers/seats").and_then(|x| x.as_array()) {
            for p in a.iter().take(10) {
                let tip = u(p, "/tip").unwrap_or(0);
                let line = format!(
                    "{:<20} {:>10}  pong {}  rel {}",
                    s(p, "/id"),
                    tip,
                    u(p, "/pong_age_ms").map(|a| format!("{}s", a / 1000)).unwrap_or("-".into()),
                    p.pointer("/release_version").and_then(|x| x.as_str()).unwrap_or("-")
                );
                peers.push(if local.saturating_sub(tip) >= super::SYNCING_LAG { st.c(YELLOW, &line) } else { line });
            }
        }
        o.extend(panel(st, "Peers", peers));
        let mut sys = Vec::new();
        if let Some(c) = h.pointer("/system/process/cpu_pct").and_then(|x| x.as_f64()) {
            sys.push(format!("CPU   {} {c:.1}%", bar(c / 100.0, 20)));
        }
        if let Some(r) = u(h, "/system/process/rss_bytes") {
            let tot = u(h, "/system/process/mem_total_bytes").unwrap_or(0);
            let f = if tot > 0 { r as f64 / tot as f64 } else { 0.0 };
            sys.push(format!("Mem   {} {}/{}", bar(f, 20), human_bytes(r), human_bytes(tot)));
        }
        if let (Some(free), Some(total)) = (u(h, "/system/disk/free_bytes"), u(h, "/system/disk/total_bytes")) {
            let used = total.saturating_sub(free);
            let f = if total > 0 { used as f64 / total as f64 } else { 0.0 };
            let line = format!("Disk  {} {} free of {}", bar(f, 20), human_bytes(free), human_bytes(total));
            sys.push(if f > 0.9 { st.c(RED, &line) } else if f > 0.75 { st.c(YELLOW, &line) } else { line });
        }
        if let Some(l) = h.pointer("/system/process/loadavg").and_then(|x| x.as_array()) {
            let l: Vec<String> = l.iter().filter_map(|x| x.as_f64()).map(|x| format!("{x:.2}")).collect();
            sys.push(format!("Load  {}", l.join(" ")));
        }
        if sys.is_empty() {
            sys.push("n/a".into());
        }
        o.extend(panel(st, "System", sys));
        let mut w = Vec::new();
        if let Some(a) = h.pointer("/warnings").and_then(|x| x.as_array()) {
            for e in a.iter().rev().take(8) {
                let lvl = s(e, "/level");
                let col = if lvl == "ERROR" { RED } else { YELLOW };
                w.push(format!(
                    "{} {} {}",
                    st.c(DIM, &format!("{}Z", hhmmss(u(e, "/at_ms").unwrap_or(0)))),
                    st.c(col, &format!("{lvl:<5}")),
                    s(e, "/msg")
                ));
            }
        }
        if w.is_empty() {
            w.push(st.c(GREEN, "none"));
        }
        o.extend(panel(st, "Recent warnings", w));
        o
    }

    /// Fallback frame from a legacy `Status` body (node without HealthReq).
    pub fn render_status_fallback(b: &Value, st: &Style, addr: &str, now_label: &str, why: &str) -> Vec<String> {
        let tip = u(b, "/tip_height");
        let best = u(b, "/best_peer_tip");
        let id = s(b, "/id");
        let seat = b
            .pointer("/validators")
            .and_then(|x| x.as_array())
            .and_then(|a| a.iter().find(|v| v.get("id").and_then(|x| x.as_str()) == Some(id)));
        let mut o = vec![
            st.c(CYAN, &format!("falcon-node dash — {id} @ {addr} · {now_label} · q quits")),
            st.c(YELLOW, &format!("health endpoint unavailable ({why}); showing legacy status")),
        ];
        o.extend(panel(st, "Node", vec![
            format!("ID        {id}"),
            format!("Version   {}", s(b, "/product_version")),
            format!("Network   {}", num(u(b, "/network_id"))),
        ]));
        o.extend(panel(st, "Chain", vec![
            format!("Local height   {}", num(tip)),
            format!("Best peer tip  {}", num(best)),
            format!("Lag            {}", num(u(b, "/tip_lag"))),
            format!("Mempool        {}", num(u(b, "/mempool"))),
            format!("Epoch          {}", num(u(b, "/epoch"))),
        ]));
        if let Some(v) = seat {
            o.extend(panel(st, "Consensus", vec![
                format!("Bond           {}", num(u(v, "/bond"))),
                format!("Jailed         {}", v.get("jailed").and_then(|x| x.as_bool()).unwrap_or(false)),
                format!("Missed turns   {}/20", num(u(v, "/v2/missed_turns"))),
                format!("Lottery ready  {}", v.get("lottery_ready").and_then(|x| x.as_bool()).unwrap_or(false)),
            ]));
        }
        if let Some(d) = b.get("disk") {
            o.extend(panel(st, "System", vec![format!("Disk  {}", d)]));
        }
        o
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The ring is process-global; serialise the tests that fill it.
    static RING_TEST: Mutex<()> = Mutex::new(());

    #[test]
    fn classify() {
        assert_eq!(classify_status(None, 0, false), "observer");
        assert_eq!(classify_status(None, 50, false), "syncing");
        assert_eq!(classify_status(Some((true, false, 10)), 0, false), "jailed");
        assert_eq!(classify_status(Some((false, true, 10)), 0, false), "inactive");
        assert_eq!(classify_status(Some((false, false, 0)), 0, false), "inactive");
        assert_eq!(classify_status(Some((false, false, 10)), SYNCING_LAG, false), "syncing");
        assert_eq!(classify_status(Some((false, false, 10)), 0, true), "syncing");
        assert_eq!(classify_status(Some((false, false, 10)), 2, false), "active");
    }

    #[test]
    fn buckets_and_rate() {
        let now: u64 = 40 * 60_000;
        let t = [now, now - 1, now - 61_000, now - 29 * 60_000, now - 31 * 60_000, now + 5];
        let b = minute_buckets(&t, now, 30);
        assert_eq!(b.len(), 30);
        assert_eq!(b[29], 2);
        assert_eq!(b[28], 1);
        assert_eq!(b[0], 1);
        assert_eq!(b.iter().sum::<u32>(), 4);
        assert_eq!(blocks_per_min(&[now, now - 1000, now - 120_000], now, 5 * 60_000), 0.6);
    }

    #[test]
    fn observed_rate() {
        let now = 100 * 60_000u64;
        // tip seen at 90, then +1 every 30 s for the last 4 min
        let mut seen = vec![(now - 10 * 60_000, 90)];
        for i in 0..8u64 {
            seen.push((now - 4 * 60_000 + i * 30_000, 91 + i));
        }
        let (bpm, spark, last) = tip_rate_from(&seen, now);
        assert_eq!(spark.iter().sum::<u64>(), 8);
        assert_eq!(spark.len(), SPARK_MINUTES);
        assert_eq!(bpm, 1.6, "8 blocks / 5 min");
        assert_eq!(last, Some(30_000));
        assert_eq!(tip_rate_from(&[(now, 5)], now).2, None, "never advanced");
    }

    #[test]
    fn proc_stat_parse() {
        let s = "1234 (falcon pl) S 1 2 3 4 5 6 7 8 9 10 250 50 0 0 20 0 1";
        assert_eq!(parse_proc_stat_ticks(s), Some(300));
        assert_eq!(parse_proc_stat_ticks("garbage"), None);
    }

    #[test]
    fn warn_ring_bounded() {
        let _g = RING_TEST.lock();
        for i in 0..(WARN_RING_CAP + 10) {
            note_warning("WARN", "t", &format!("w{i} {}", "x".repeat(400)));
        }
        let r = recent_warnings(1000);
        assert_eq!(r.len(), WARN_RING_CAP);
        assert!(r.last().unwrap().msg.starts_with(&format!("w{}", WARN_RING_CAP + 9)));
        assert!(r[0].msg.chars().count() <= WARN_MSG_MAX + 1);
        assert_eq!(recent_warnings(3).len(), 3);
    }

    #[test]
    fn warn_capture_layer() {
        let _g = RING_TEST.lock();
        use tracing_subscriber::prelude::*;
        let sub = tracing_subscriber::registry().with(WarnCapture);
        tracing::subscriber::with_default(sub, || {
            tracing::info!("not captured zz-info");
            tracing::warn!("captured zz-warn {}", 7);
            tracing::error!("captured zz-err");
        });
        let r = recent_warnings(WARN_RING_CAP);
        assert!(r.iter().any(|w| w.msg == "captured zz-warn 7" && w.level == "WARN"));
        assert!(r.iter().any(|w| w.msg == "captured zz-err" && w.level == "ERROR"));
        assert!(!r.iter().any(|w| w.msg.contains("zz-info")));
    }

    #[test]
    fn spark_and_bar() {
        assert_eq!(dash::sparkline(&[0, 7, 14]), "▁▄█");
        assert_eq!(dash::sparkline(&[]), "");
        assert_eq!(dash::bar(0.5, 4), "[||  ]");
        assert_eq!(dash::bar(2.0, 2), "[||]");
        assert_eq!(dash::human_dur(90_061), "1d 01h 01m");
    }
}

// ---------------------------------------------------------------- operator balance

/// Operator balance view shared by `falcon-pl-ctl balance`, `dash` and `web`.
/// Pure JSON shaping over existing read-only replies; never reads key files.
pub mod balance {
    use serde_json::{json, Value};

    fn u(v: &Value, p: &str) -> u64 {
        v.pointer(p).and_then(|x| x.as_u64()).unwrap_or(0)
    }

    /// Build the `balance` block from an `AccountQuery` body for `account` and
    /// a `StatusReq` body (its `validators` list). Used against nodes older than
    /// 2.9.79 whose health snapshot has no `balance` block. The seat is the
    /// validator whose id is `account`, else whose `bond_account` is `account`.
    pub fn from_account_status(account: &str, acct: Option<&Value>, status: Option<&Value>) -> Value {
        let seat = status
            .and_then(|s| s.pointer("/validators"))
            .and_then(|x| x.as_array())
            .and_then(|a| {
                a.iter()
                    .find(|v| v.get("id").and_then(|x| x.as_str()) == Some(account))
                    .or_else(|| a.iter().find(|v| v.get("bond_account").and_then(|x| x.as_str()) == Some(account)))
            });
        let bond_account = seat
            .and_then(|v| v.get("bond_account").and_then(|x| x.as_str()))
            .filter(|a| !a.is_empty() && *a != account)
            .map(str::to_string);
        json!({
            "account": account,
            "liquid": acct.map(|a| u(a, "/balance")).unwrap_or(0),
            "pending_rewards": acct.map(|a| u(a, "/claimable")).unwrap_or(0),
            "seat_claimable": seat.map(|v| u(v, "/seat_claimable")).unwrap_or(0),
            "seat_payout": seat.and_then(|v| v.get("seat_payout")).cloned().unwrap_or(Value::Null),
            "bonded": seat.map(|v| u(v, "/bond")).unwrap_or(0),
            "unbonding": seat.map(|v| u(v, "/unbonding")).unwrap_or(0),
            "unbond_ready_ms": seat.map(|v| u(v, "/unbond_ready_ms")).unwrap_or(0),
            "unbond_ready": seat.and_then(|v| v.get("unbond_ready")).and_then(|x| x.as_bool()).unwrap_or(false),
            "unbond_remaining_ms": seat.map(|v| u(v, "/unbond_remaining_ms")).unwrap_or(0),
            "bond_account": bond_account,
            "bond_account_liquid": Value::Null,
            "seat": seat.and_then(|v| v.get("id")).cloned().unwrap_or(Value::Null),
            "source": "account+status",
        })
    }

    /// Thousands-separated integer FPL.
    pub fn fpl(n: u64) -> String {
        let s = n.to_string();
        let mut o = String::new();
        for (i, c) in s.chars().enumerate() {
            if i > 0 && (s.len() - i) % 3 == 0 {
                o.push(',');
            }
            o.push(c);
        }
        o
    }

    /// One line for `falcon-pl-ctl balance` / `falcon-node balance`.
    pub fn one_line(b: &Value) -> String {
        let mut s = format!(
            "{}: liquid {} FPL · bonded {} FPL · pending rewards {} FPL",
            b.get("account").and_then(|x| x.as_str()).unwrap_or("?"),
            fpl(u(b, "/liquid")),
            fpl(u(b, "/bonded")),
            fpl(u(b, "/pending_rewards")),
        );
        if u(b, "/seat_claimable") > 0 {
            s.push_str(&format!(" · seat rewards {} FPL", fpl(u(b, "/seat_claimable"))));
        }
        if let Some(p) = b.get("seat_payout").and_then(|x| x.as_str()) {
            s.push_str(&format!(" · seat payout -> {p}"));
        }
        if u(b, "/unbonding") > 0 {
            s.push_str(&format!(" · unbonding {} FPL", fpl(u(b, "/unbonding"))));
        }
        if let Some(a) = b.get("bond_account").and_then(|x| x.as_str()) {
            match b.get("bond_account_liquid").and_then(|x| x.as_u64()) {
                Some(n) => s.push_str(&format!(" · bond account {a} {} FPL", fpl(n))),
                None => s.push_str(&format!(" · bond account {a}")),
            }
        }
        s
    }
}
