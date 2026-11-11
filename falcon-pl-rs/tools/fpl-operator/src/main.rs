// Copyright (c) 2025-2026 BEARTEC. All rights reserved. See LICENSE.
//! fpl-operatord: Falcon PL BitVM2 bridge operator node (operator network).
//!
//! Every operator runs the same kit:
//!  * reads BTC withdrawals from the Falcon ledger (falcon-pl-ctl status ->
//!    rails[BTC].bitvm2_claims) and maps each to a presigned deposit graph;
//!  * gossips signed records (WithdrawalSeen, ClaimIntent, PayoutTx, Kickoff,
//!    Heartbeat, Disagreement, Challenge) to registered peers, persisted + replayed;
//!  * PRE-CLAIM CROSS-CHECK: fronts BTC / kicks off only when a quorum of peers
//!    signed the same withdrawal binding; any mismatch halts and alerts;
//!  * fronts the payout from ITS OWN bitcoind wallet and runs the graph steps;
//!  * WATCHES all operators' claims vs the Falcon ledger and challenges bad ones
//!    (disprove via the presigned graph earns the watcher a bounty on-chain);
//!  * serves /health (local) and a public JSON feed /feed for the status page.
//! Keys stay local (0600 file + own bitcoind wallet). Records carry facts, never
//! keys, never votes over funds: BTC moves only through the presigned graph.

mod deposits;
mod ledger;
mod gossip;
mod payout;
mod prover;

use gossip::{CrossCheck, Record, Signer_, Store};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}
fn log(msg: &str) {
    println!("{} fpl-operatord: {}", now(), msg);
}

// ---------------- config ----------------

#[derive(Debug, Clone, Serialize)]
struct Config {
    home: PathBuf,
    network: String,
    mode: String,
    falcon_ctl: String,
    falcon_rpc: String,
    falcon_account: String,
    bitcoin_cli: String,
    bitcoin_args: Vec<String>,
    btc_wallet: String,
    payout_fee_bps: u64,
    max_payout_sats: u64,
    min_wallet_reserve_sats: u64,
    poll_secs: u64,
    health_listen: String,
    p2p_listen: String,
    pregen_target: u64,
    bin_dir: PathBuf,
    esplora: String,
    kickoff_cmd: String,
    challenge_cmd: String,
    alert_cmd: String,
    btc_xonly_hex: String,
    btc_pubkey_hex: String,
    payout_address: String,
    fee_rate: u64,
    /// PEG_OUT fee rate (sat/vB, floor 2): paid ON TOP of the exact withdrawal amount.
    pegout_fee_rate: u64,
    quorum: Option<usize>,
    intent_wait_secs: u64,
    payout_deadline_secs: u64,
    heartbeat_secs: u64,
    name: String,
    max_peer_fee_bps: u64,
    pegout_fee_allow_sats: u64,
    challenge_retry_secs: u64,
    challenge_vk_dir: String,
    /// BRIDGE ledger duties (used only once the node reports bridge_operators.active).
    falcon_keys_dir: String,
    falcon_scheme: String,
    falcon_network_id: String,
    slash_cmd: String,
    reward_spk_hex: String,
    /// M1 attest via the public snarkjs prover (hook default bin/fpl-operator-attest.sh).
    attest_cmd: String,
    attest_zkey: String,
    attest_vk_json: String,
    attest_vk_hex: String,
    /// FPL_OP_ALLOW_UNATTESTED_PEGOUT=1: front peg-outs even with no attest prover
    /// (the ledger then refunds the claim after the window: double payout).
    allow_unattested: bool,
    /// Groth16 proof set (vk.bin/proof.bin/public.bin) passed as FPL_PROOF_DIR.
    proof_dir: String,
    disprove_vk_sha256: String,
    withdraw_vk_sha256: String,
}

fn parse_env_file(p: &Path) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    if let Ok(s) = std::fs::read_to_string(p) {
        for line in s.lines() {
            let l = line.trim();
            if l.is_empty() || l.starts_with('#') {
                continue;
            }
            if let Some((k, v)) = l.split_once('=') {
                m.insert(k.trim().to_string(), v.trim().trim_matches('"').to_string());
            }
        }
    }
    m
}

impl Config {
    fn load(home: &Path) -> Config {
        let f = parse_env_file(&home.join("operator.env"));
        let g = |k: &str, d: &str| std::env::var(k).ok().or_else(|| f.get(k).cloned()).unwrap_or_else(|| d.to_string());
        let n = |k: &str, d: u64| g(k, &d.to_string()).parse().unwrap_or(d);
        Config {
            home: home.to_path_buf(),
            network: g("FPL_OP_NETWORK", "testnet4"),
            mode: g("FPL_OP_MODE", "dry-run"),
            falcon_ctl: g("FPL_OP_FALCON_CTL", "falcon-pl-ctl"),
            falcon_rpc: g("FPL_OP_FALCON_RPC", "127.0.0.1:19401"),
            falcon_account: g("FPL_OP_FALCON_ACCOUNT", ""),
            bitcoin_cli: g("FPL_OP_BITCOIN_CLI", "bitcoin-cli"),
            bitcoin_args: g("FPL_OP_BITCOIN_ARGS", "-testnet4").split_whitespace().map(String::from).collect(),
            btc_wallet: g("FPL_OP_BTC_WALLET", "fpl-operator"),
            payout_fee_bps: n("FPL_OP_PAYOUT_FEE_BPS", 30),
            max_payout_sats: n("FPL_OP_MAX_PAYOUT_SATS", 1_000_000),
            min_wallet_reserve_sats: n("FPL_OP_MIN_RESERVE_SATS", 50_000),
            poll_secs: n("FPL_OP_POLL_SECS", 30),
            health_listen: g("FPL_OP_HEALTH_LISTEN", "127.0.0.1:19480"),
            p2p_listen: g("FPL_OP_P2P_LISTEN", "0.0.0.0:19481"),
            pregen_target: n("FPL_OP_PREGEN_TARGET", 2),
            bin_dir: PathBuf::from(g("FPL_OP_BIN_DIR", &home.join("bin").to_string_lossy())),
            esplora: g("FPL_OP_ESPLORA", "https://mempool.space/testnet4/api"),
            kickoff_cmd: g("FPL_OP_KICKOFF_CMD", ""),
            challenge_cmd: g("FPL_OP_CHALLENGE_CMD", ""),
            alert_cmd: g("FPL_OP_ALERT_CMD", ""),
            btc_xonly_hex: g("FPL_OP_BTC_XONLY", ""),
            btc_pubkey_hex: g("FPL_OP_BTC_PUBKEY", "").to_ascii_lowercase(),
            payout_address: g("FPL_OP_PAYOUT_ADDRESS", ""),
            fee_rate: n("FPL_OP_FEE_RATE", MIN_FEE_RATE).max(MIN_FEE_RATE),
            pegout_fee_rate: n("FPL_OP_PEGOUT_FEE_RATE", MIN_FEE_RATE).max(MIN_FEE_RATE),
            quorum: g("FPL_OP_QUORUM", "").parse().ok(),
            intent_wait_secs: n("FPL_OP_INTENT_WAIT_SECS", 60),
            payout_deadline_secs: n("FPL_OP_PAYOUT_DEADLINE_SECS", 6 * 3600),
            heartbeat_secs: n("FPL_OP_HEARTBEAT_SECS", 600),
            name: g("FPL_OP_NAME", "operator"),
            max_peer_fee_bps: n("FPL_OP_MAX_PEER_FEE_BPS", 100),
            pegout_fee_allow_sats: n("FPL_OP_PEGOUT_FEE_ALLOW_SATS", 1_000),
            challenge_retry_secs: n("FPL_OP_CHALLENGE_RETRY_SECS", 60),
            challenge_vk_dir: g("FPL_OP_CHALLENGE_VK_DIR", ""),
            falcon_keys_dir: g("FPL_OP_FALCON_KEYS_DIR", ""),
            falcon_scheme: g("FPL_OP_FALCON_SCHEME", "falcon"),
            falcon_network_id: g("FPL_OP_FALCON_NETWORK_ID", "2300"),
            slash_cmd: g("FPL_OP_SLASH_CMD", ""),
            reward_spk_hex: g("FPL_OP_REWARD_SPK", ""),
            attest_cmd: g("FPL_OP_ATTEST_CMD", ""),
            attest_zkey: g("FPL_OP_ATTEST_ZKEY", ""),
            attest_vk_json: g("FPL_OP_ATTEST_VK_JSON", ""),
            attest_vk_hex: g("FPL_OP_ATTEST_VK_HEX", ""),
            allow_unattested: g("FPL_OP_ALLOW_UNATTESTED_PEGOUT", "") == "1",
            proof_dir: g("FPL_OP_PROOF_DIR", ""),
            disprove_vk_sha256: g("FPL_OP_DISPROVE_VK_SHA256", ""),
            withdraw_vk_sha256: g("FPL_OP_WITHDRAW_VK_SHA256", ""),
        }
    }
    /// Checked FPL_PROOF_DIR (pinned disprove VK; no mock fallback off regtest).
    fn proof(&self) -> Result<Option<(PathBuf, String)>, String> {
        let pin = prover::expected_disprove_vk(&self.network, &self.disprove_vk_sha256);
        prover::resolve_proof_dir(&self.proof_dir, &self.challenge_vk_dir, &self.network, &pin)
    }
    fn proof_env(&self) -> Vec<(String, String)> {
        match self.proof() {
            Ok(Some((d, _))) => vec![("FPL_PROOF_DIR".into(), d.to_string_lossy().to_string())],
            _ => vec![],
        }
    }
    /// Withdraw (M1 attest) VK must match the pin when set / on testnet4.
    fn check_withdraw_vk(&self) -> Result<String, String> {
        let pin = if !self.withdraw_vk_sha256.is_empty() { self.withdraw_vk_sha256.to_ascii_lowercase() } else if self.network == "regtest" { String::new() } else { prover::TESTNET_WITHDRAW_VK_SHA256.into() };
        let sha = prover::withdraw_vk_sha(&self.attest_vk_hex)?;
        if !pin.is_empty() && sha != pin { return Err(format!("attest VK sha256 {sha} != pinned {pin}")); }
        Ok(sha)
    }
    fn secret_path(&self) -> PathBuf {
        self.home.join("keys").join("operator.secret")
    }
    fn pool(&self) -> PathBuf {
        self.home.join("pregen")
    }
    fn graphs(&self) -> PathBuf {
        self.home.join("graphs")
    }
    /// Can this operator submit the M1 Bitvm2AttestV2 that records a completed
    /// peg-out on the ledger? Without it the claim stays AwaitingPegout and the
    /// ledger refunds the user after `pegout_refund_ledgers` (double payout).
    fn attest_ready(&self) -> Result<(), String> {
        if self.attest_zkey.is_empty() || self.attest_vk_json.is_empty() {
            return Err("FPL_OP_ATTEST_ZKEY / FPL_OP_ATTEST_VK_JSON not set".into());
        }
        for (label, path) in [("FPL_OP_ATTEST_ZKEY", &self.attest_zkey), ("FPL_OP_ATTEST_VK_JSON", &self.attest_vk_json)] {
            let meta = std::fs::metadata(path).map_err(|e| format!("{label} {path}: {e}"))?;
            if !meta.is_file() {
                return Err(format!("{label} {path}: not a regular file"));
            }
        }
        self.check_withdraw_vk().map(|_| ())
    }

    fn live(&self) -> bool {
        self.mode == "live"
    }
    fn hook(&self, v: &str, default: &str) -> String {
        if v.is_empty() { self.bin_dir.join(default).to_string_lossy().to_string() } else { v.to_string() }
    }
}

// ---------------- Falcon ledger reader ----------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct LedgerClaim {
    pub note_id: String,
    pub dest: String,
    pub amount: u64,
    pub open_height: u64,
    pub status: String,
    pub operator: String,
    pub pegout_txid_hex: String,
    pub claim_txid_hex: String,
}

impl LedgerClaim {
    fn binding(&self) -> String {
        gossip::binding(&self.note_id, &self.dest, self.amount, self.open_height)
    }
}

/// Ledger status JSON uses snake_case (`awaiting_pegout`); the kit compares CamelCase.
pub fn camel_status(s: &str) -> String {
    if !s.contains('_') && s.chars().next().map_or(false, |c| c.is_ascii_uppercase()) {
        return s.to_string();
    }
    s.split('_')
        .map(|w| {
            let mut c = w.chars();
            c.next().map(|f| f.to_ascii_uppercase().to_string() + c.as_str()).unwrap_or_default()
        })
        .collect()
}

pub fn parse_ledger(v: &serde_json::Value) -> (u64, Vec<LedgerClaim>) {
    // falcon-pl-ctl status wraps the ledger in {"type":..,"body":{..}}; accept both shapes.
    let v = if v["body"].is_object() { &v["body"] } else { v };
    let h = v["height"].as_u64().or(v["tip_height"].as_u64()).unwrap_or(0);
    let s = |c: &serde_json::Value, k: &str| c[k].as_str().unwrap_or("").to_string();
    let mut out = vec![];
    // BRIDGE: once the testnet4 rail exists, only its claims are served
    // (legacy BTC claims name testnet3 destinations).
    let rails: Vec<&serde_json::Value> = v["rails"].as_array().into_iter().flatten().collect();
    let want = if rails.iter().any(|r| r["asset"].as_str() == Some("BTC4")) { "btc4" } else { "btc" };
    for r in rails {
        if !r["asset"].as_str().unwrap_or("").eq_ignore_ascii_case(want) {
            continue;
        }
        for c in r["bitvm2_claims"].as_array().into_iter().flatten() {
            out.push(LedgerClaim {
                note_id: s(c, "note_id"),
                dest: s(c, "dest"),
                amount: c["amount"].as_u64().unwrap_or(0),
                open_height: c["open_height"].as_u64().unwrap_or(0),
                status: camel_status(&s(c, "status")),
                operator: s(c, "operator"),
                pegout_txid_hex: s(c, "pegout_txid_hex"),
                claim_txid_hex: s(c, "claim_txid_hex"),
            });
        }
    }
    (h, out)
}

// ---------------- external calls ----------------

fn run_cmd(prog: &str, args: &[String], envs: &[(String, String)]) -> Result<String, String> {
    let mut c = Command::new(prog);
    c.args(args).stdin(Stdio::null());
    for (k, v) in envs {
        c.env(k, v);
    }
    let o = c.output().map_err(|e| format!("{prog}: {e}"))?;
    if !o.status.success() {
        return Err(format!("{prog} exit {}: {}", o.status, String::from_utf8_lossy(&o.stderr).trim()));
    }
    Ok(String::from_utf8_lossy(&o.stdout).to_string())
}

fn btc(cfg: &Config, wallet: bool, args: &[&str]) -> Result<String, String> {
    let mut a = cfg.bitcoin_args.clone();
    if wallet {
        a.push(format!("-rpcwallet={}", cfg.btc_wallet));
    }
    a.extend(args.iter().map(|s| s.to_string()));
    run_cmd(&cfg.bitcoin_cli, &a, &[])
}

fn wallet_sats(cfg: &Config) -> Result<u64, String> {
    let v: serde_json::Value = serde_json::from_str(&btc(cfg, true, &["getbalances"])?).map_err(|e| e.to_string())?;
    let t = v["mine"]["trusted"].as_f64().ok_or("no trusted balance")?;
    Ok((t * 1e8).round() as u64)
}

fn falcon_status(cfg: &Config) -> Result<serde_json::Value, String> {
    let out = run_cmd(&cfg.falcon_ctl, &["--addr".into(), cfg.falcon_rpc.clone(), "status".into()], &[])?;
    serde_json::from_str(&out).map_err(|e| format!("status json: {e}"))
}

fn falcon_ledger(cfg: &Config) -> Result<(u64, Vec<LedgerClaim>), String> {
    Ok(parse_ledger(&falcon_status(cfg)?))
}

fn ctl_operator(cfg: &Config, body: &serde_json::Value, amount: u64) -> Result<String, String> {
    let args = ledger::ctl_args(&cfg.falcon_rpc, &cfg.falcon_account, body, amount, &cfg.falcon_scheme, &cfg.falcon_keys_dir, &cfg.falcon_network_id);
    run_cmd(&cfg.falcon_ctl, &args, &[])
}

/// BRIDGE: ledger duties once the node reports the bridge height active.
fn ledger_duties(n: &Node, st: &mut State, status: &serde_json::Value, cap: u64) {
    let cfg = &n.cfg;
    if !ledger::bridge_active(status) || !cfg.live() || cfg.falcon_account.is_empty() {
        return;
    }
    if ledger::our_record(status, &cfg.falcon_account).is_none() {
        st.ledger_last_error = "bridge active but this account is not registered (fpl-operatord register)".into();
        return;
    }
    // liveness slot is hourly on the ledger; send twice per slot
    if now() >= st.last_ledger_heartbeat + 1800 {
        match ctl_operator(cfg, &ledger::heartbeat_body(cap), 0) {
            Ok(_) => st.last_ledger_heartbeat = now(),
            Err(e) => st.ledger_last_error = format!("heartbeat: {e}"),
        }
    }
    for g in deposits::index(&cfg.graphs()) {
        let key = g.dir.to_string_lossy().to_string();
        if st.ledger_bound.contains(&key) {
            continue;
        }
        let Ok(raw) = std::fs::read(g.dir.join("final.json")) else { continue };
        let Ok(v) = serde_json::from_slice::<serde_json::Value>(&raw) else { continue };
        // confirmed only when the ledger status shows the binding; resubmit at most every 10 min
        let depositor = ledger::request_depositor(&g.dir);
        let bodies: Vec<serde_json::Value> = ledger::bind_or_cosign_bodies(&v, &n.signer.xonly)
            .into_iter()
            .map(|mut b| {
                if !depositor.is_empty() {
                    b["depositor_account"] = serde_json::Value::String(depositor.clone());
                }
                b
            })
            .collect();
        let mut all = true;
        for b in &bodies {
            let dep = b["deposit_txid"].as_str().unwrap_or("");
            if ledger::is_bound(status, dep, &n.signer.xonly) {
                continue;
            }
            all = false;
            let tk = format!("bind:{dep}");
            if now() < st.bind_tried.get(&tk).copied().unwrap_or(0) + 600 {
                continue;
            }
            st.bind_tried.insert(tk, now());
            match ctl_operator(cfg, b, 0) {
                Ok(_) => log(&format!("ledger: graph bind submitted for deposit {dep}")),
                Err(e) => st.ledger_last_error = format!("graph bind: {e}"),
            }
        }
        if all {
            st.ledger_bound.insert(key);
        }
    }
    // re-check submitted slashes against the ledger; resubmit if not applied in 30 min
    let sub: Vec<(String, (String, String, u64))> = st.slash_submitted.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    for (txid, (op, dep, at)) in sub {
        if ledger::slash_applied(status, &dep, &op) {
            log(&format!("ledger: slash of {op} for deposit {dep} applied (disprove {txid})"));
            st.slash_submitted.remove(&txid);
            st.slash_done.insert(txid, op);
        } else if now() >= at + 1800 {
            st.ledger_last_error = format!("slash {txid} not applied after 30 min; resubmitting");
            st.slash_submitted.remove(&txid);
            st.slash_pending.insert(txid, (op, dep));
        }
    }
    attest_duties(n, st, status);
    btc4_header_duty(n, st, status);
    btc4_pegin_duty(n, st, status);
    let pending: Vec<(String, (String, String))> = st.slash_pending.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    for (txid, (op, dep)) in pending {
        let hook = cfg.hook(&cfg.slash_cmd, "fpl-operator-slash.sh");
        let mut cli = vec![cfg.bitcoin_cli.clone()];
        cli.extend(cfg.bitcoin_args.iter().cloned());
        let (code, _out, err) = run_cmd_full(&hook, &[
            ("FPL_SLASH_TXID".into(), txid.clone()),
            ("FPL_SLASH_OPERATOR".into(), op.clone()),
            ("FPL_SLASH_DEPOSIT".into(), dep.clone()),
            ("FPL_OP_BITCOIN_CLI".into(), cli.join(" ")),
            ("FPL_OP_FALCON_CTL".into(), cfg.falcon_ctl.clone()),
            ("FPL_OP_FALCON_RPC".into(), cfg.falcon_rpc.clone()),
            ("FPL_OP_FALCON_ACCOUNT".into(), cfg.falcon_account.clone()),
            ("FPL_OP_FALCON_KEYS_DIR".into(), cfg.falcon_keys_dir.clone()),
            ("FPL_OP_FALCON_SCHEME".into(), cfg.falcon_scheme.clone()),
            ("FPL_OP_FALCON_NETWORK_ID".into(), cfg.falcon_network_id.clone()),
            ("FPL_OP_BIN_DIR".into(), cfg.bin_dir.to_string_lossy().to_string()),
        ]);
        if code == 0 {
            log(&format!("ledger: slash evidence for {op} (disprove {txid}) submitted; waiting for the ledger to apply it"));
            st.slash_pending.remove(&txid);
            st.slash_submitted.insert(txid, (op, dep, now()));
        } else {
            // not enough confirmations yet / transient: retry next poll
            st.ledger_last_error = format!("slash {txid}: exit {code}: {}", err.trim().chars().take(200).collect::<String>());
        }
    }
}

/// BRIDGE BTC4: relay testnet4 headers from our node to the ledger rail
/// (permissionless; every operator does it, duplicates are refused).
fn btc4_header_duty(n: &Node, st: &mut State, status: &serde_json::Value) {
    let cfg = &n.cfg;
    let Some((rail_tip, _)) = ledger::btc4_rail(status) else { return };
    let Ok(node_tip) = btc(cfg, false, &["getblockcount"]).map(|s| s.trim().parse::<u64>().unwrap_or(0)) else { return };
    let start = if rail_tip == 0 { ledger::BTC4_CHECKPOINT_HEIGHT } else { rail_tip + 1 };
    if node_tip < start || now() < st.btc4_hdr_tried + 20 {
        return;
    }
    st.btc4_hdr_tried = now();
    let seq0 = ledger::account_sequence(&run_cmd(&cfg.falcon_ctl, &["--addr".into(), cfg.falcon_rpc.clone(), "account".into(), "--account".into(), cfg.falcon_account.clone()], &[]).unwrap_or_default());
    let Some(seq0) = seq0 else { return };
    let end = node_tip.min(start + ledger::BTC4_HEADER_BURST - 1);
    for (i, h) in (start..=end).enumerate() {
        let Ok(hash) = btc(cfg, false, &["getblockhash", &h.to_string()]) else { break };
        let Ok(raw) = btc(cfg, false, &["getblockheader", hash.trim(), "false"]) else { break };
        let mut a = vec!["--addr".to_string(), cfg.falcon_rpc.clone(), "submit-btc-header".into(),
            "--account".into(), cfg.falcon_account.clone(), "--asset".into(), "BTC4".into(),
            "--raw".into(), raw.trim().to_string(), "--height".into(), h.to_string(),
            "--scheme".into(), cfg.falcon_scheme.clone(), "--network-id".into(), cfg.falcon_network_id.clone(),
            "--sequence".into(), (seq0 + i as u64).to_string()];
        if !cfg.falcon_keys_dir.is_empty() {
            a.push("--keys-dir".into());
            a.push(cfg.falcon_keys_dir.clone());
        }
        if let Err(e) = run_cmd(&cfg.falcon_ctl, &a, &[]) {
            st.ledger_last_error = format!("btc4 header {h}: {}", e.chars().take(160).collect::<String>());
            break;
        }
    }
}

/// BRIDGE BTC4: submit the SPV mint for bound peg-ins once confirmed (>= 6).
fn btc4_pegin_duty(n: &Node, st: &mut State, status: &serde_json::Value) {
    let cfg = &n.cfg;
    let Some((_, minted)) = ledger::btc4_rail(status) else { return };
    for g in deposits::index(&cfg.graphs()) {
        let txid = g.confirm_outpoint.split(':').next().unwrap_or("").to_ascii_lowercase();
        if txid.len() != 64 || minted.contains(&txid) || ledger::request_depositor(&g.dir).is_empty() {
            continue;
        }
        let tk = format!("pegin:{txid}");
        if now() < st.bind_tried.get(&tk).copied().unwrap_or(0) + 120 {
            continue;
        }
        st.bind_tried.insert(tk, now());
        let hook = cfg.hook("", "fpl-operator-pegin.sh");
        let mut cli = vec![cfg.bitcoin_cli.clone()];
        cli.extend(cfg.bitcoin_args.iter().cloned());
        let (code, _o, err) = run_cmd_full(&hook, &[
            ("FPL_PEGIN_TXID".into(), txid.clone()),
            ("FPL_OP_BITCOIN_CLI".into(), cli.join(" ")),
            ("FPL_OP_FALCON_CTL".into(), cfg.falcon_ctl.clone()),
            ("FPL_OP_FALCON_RPC".into(), cfg.falcon_rpc.clone()),
            ("FPL_OP_FALCON_ACCOUNT".into(), cfg.falcon_account.clone()),
            ("FPL_OP_FALCON_KEYS_DIR".into(), cfg.falcon_keys_dir.clone()),
            ("FPL_OP_FALCON_SCHEME".into(), cfg.falcon_scheme.clone()),
            ("FPL_OP_FALCON_NETWORK_ID".into(), cfg.falcon_network_id.clone()),
            ("FPL_OP_BIN_DIR".into(), cfg.bin_dir.to_string_lossy().to_string()),
        ]);
        if code == 0 {
            log(&format!("ledger: btc4 peg-in mint submitted for {txid}"));
        } else if code != 3 {
            st.ledger_last_error = format!("pegin {txid}: exit {code}: {}", err.trim().chars().take(160).collect::<String>());
        }
    }
}

/// Refuse to front a peg-out the ledger can never see completed: with no
/// attest prover the claim is refunded after the window and the user is paid twice.
pub(crate) fn front_blocked(attest: Result<(), String>, allow_unattested: bool) -> Option<String> {
    match attest {
        Ok(()) => None,
        Err(_) if allow_unattested => None,
        Err(e) => Some(format!("not fronting: attest prover not ready ({e}); ledger would refund after the window (double payout). Set FPL_OP_ALLOW_UNATTESTED_PEGOUT=1 to override")),
    }
}

/// M1: our claims with a mined PEG_OUT still awaiting attest on the ledger.
pub(crate) fn attest_due(ledger: &[LedgerClaim], claims: &BTreeMap<String, (String, String)>) -> Vec<(String, String, String)> {
    claims
        .iter()
        .filter(|(_, (pegout, _))| pegout.len() == 64)
        .filter_map(|(note, (pegout, k1))| {
            let lc = ledger.iter().find(|l| &l.note_id == note)?;
            matches!(lc.status.as_str(), "AwaitingPegout" | "PegoutPosted").then(|| (note.clone(), pegout.clone(), k1.clone()))
        })
        .collect()
}

/// M1 Bitvm2AttestV2 for our peg-outs through the snarkjs prover hook. The hook exits
/// non-zero until the peg-out has the ledger's confirmations and a final checkpoint exists.
fn attest_duties(n: &Node, st: &mut State, status: &serde_json::Value) {
    let cfg = &n.cfg;
    if let Err(e) = cfg.attest_ready() {
        // Loud, not silent: a mined peg-out we cannot attest will be refunded.
        let (_, ledger) = parse_ledger(status);
        for c in st.claims.iter().filter(|(_, c)| c.peg_out_txid.len() == 64) {
            if let Some(lc) = ledger.iter().find(|l| &l.note_id == c.0 && matches!(l.status.as_str(), "AwaitingPegout" | "PegoutPosted")) {
                let refund_at = ledger::refund_height(status, lc.open_height).unwrap_or(0);
                let msg = format!("attest: cannot record peg-out {} for {} ({e}); ledger refunds it at height {refund_at}", c.1.peg_out_txid, c.0);
                if st.ledger_last_error != msg {
                    log(&msg);
                    st.ledger_last_error = msg;
                }
            }
        }
        return;
    }
    let (_, ledger) = parse_ledger(status);
    let ours: BTreeMap<String, (String, String)> = st
        .claims
        .iter()
        .filter(|(_, c)| matches!(c.phase.as_str(), "kickoff" | "done"))
        .map(|(k, c)| {
            let k1 = std::fs::read_to_string(Path::new(&c.deposit_dir).join("kick_off_1.txid")).unwrap_or_default().trim().to_string();
            (k.clone(), (c.peg_out_txid.clone(), k1))
        })
        .collect();
    for (note, _) in ours.iter() {
        if st.attest_tried.contains_key(note) && ledger.iter().any(|l| &l.note_id == note && !matches!(l.status.as_str(), "AwaitingPegout" | "PegoutPosted")) {
            if st.attest_done.insert(note.clone()) {
                log(&format!("ledger: attest for {note} applied"));
            }
        }
    }
    for (note, pegout, k1) in attest_due(&ledger, &ours) {
        if now() < st.attest_tried.get(&note).copied().unwrap_or(0) + 600 {
            continue;
        }
        st.attest_tried.insert(note.clone(), now());
        let hook = cfg.hook(&cfg.attest_cmd, "fpl-operator-attest.sh");
        let mut cli = vec![cfg.bitcoin_cli.clone()];
        cli.extend(cfg.bitcoin_args.iter().cloned());
        let (code, _out, err) = run_cmd_full(&hook, &[
            ("FPL_ATTEST_NOTE".into(), note.clone()),
            ("FPL_ATTEST_PEGOUT_TXID".into(), pegout.clone()),
            ("FPL_ATTEST_CLAIM_TXID".into(), k1),
            ("FPL_ZKEY".into(), cfg.attest_zkey.clone()),
            ("FPL_VK_JSON".into(), cfg.attest_vk_json.clone()),
            ("FPL_VK_HEX".into(), cfg.attest_vk_hex.clone()),
            ("FPL_OP_BITCOIN_CLI".into(), cli.join(" ")),
            ("FPL_OP_BITCOIN_ARGS".into(), String::new()),
            ("FPL_OP_FALCON_CTL".into(), cfg.falcon_ctl.clone()),
            ("FPL_OP_FALCON_RPC".into(), cfg.falcon_rpc.clone()),
            ("FPL_OP_FALCON_ACCOUNT".into(), cfg.falcon_account.clone()),
            ("FPL_OP_FALCON_KEYS_DIR".into(), cfg.falcon_keys_dir.clone()),
            ("FPL_OP_FALCON_SCHEME".into(), cfg.falcon_scheme.clone()),
            ("FPL_OP_FALCON_NETWORK_ID".into(), cfg.falcon_network_id.clone()),
            ("FPL_OP_BIN_DIR".into(), cfg.bin_dir.to_string_lossy().to_string()),
        ]);
        if code == 0 {
            log(&format!("ledger: M1 attest for {note} (peg-out {pegout}) submitted"));
        } else {
            st.ledger_last_error = format!("attest {note}: exit {code}: {}", err.trim().chars().take(200).collect::<String>());
        }
    }
}

/// Outputs (value, scriptPubKey hex) of a BTC tx (own node, txindex=1) and its confirmations.
fn btc_tx_outputs(cfg: &Config, txid: &str) -> Result<(Vec<(u64, String)>, u64), String> {
    let v: serde_json::Value = serde_json::from_str(&btc(cfg, false, &["getrawtransaction", txid, "true"])?).map_err(|e| e.to_string())?;
    let outs = v["vout"].as_array().into_iter().flatten()
        .map(|o| ((o["value"].as_f64().unwrap_or(0.0) * 1e8).round() as u64, o["scriptPubKey"]["hex"].as_str().unwrap_or("").to_ascii_lowercase()))
        .collect();
    Ok((outs, v["confirmations"].as_u64().unwrap_or(0)))
}

/// Run a hook, returning (exit code, stdout, stderr) without failing on non-zero exit.
fn run_cmd_full(prog: &str, envs: &[(String, String)]) -> (i32, String, String) {
    let mut c = Command::new(prog);
    c.stdin(Stdio::null());
    for (k, v) in envs {
        c.env(k, v);
    }
    match c.output() {
        Ok(o) => (o.status.code().unwrap_or(-1), String::from_utf8_lossy(&o.stdout).to_string(), String::from_utf8_lossy(&o.stderr).to_string()),
        Err(e) => (-1, String::new(), format!("{prog}: {e}")),
    }
}

/// Outcome of looking a txid up on Bitcoin for payout verification.
#[derive(Debug, Clone, PartialEq)]
enum TxLookup {
    /// (outputs as (sats, spk_hex), confirmations)
    Found(Vec<(u64, String)>, u64),
    /// Genuinely absent: bitcoind returned RPC -5 with a synced txindex.
    NotFound,
    /// Could not tell (bitcoind down/erroring, index not synced, esplora unreachable): skip, retry later.
    Unavailable(String),
}

/// True only for bitcoind's RPC -5 "No such mempool or blockchain transaction".
fn is_rpc_tx_not_found(err: &str) -> bool {
    err.contains("No such mempool or blockchain transaction") && (err.contains("code: -5") || err.contains("\"code\":-5"))
}

/// Pure resolution logic (unit-tested): a -5 counts as not-found only with a synced txindex;
/// any other bitcoind error falls back to esplora; if esplora can't confirm presence either, Unavailable.
fn resolve_tx_lookup(
    rpc: Result<(Vec<(u64, String)>, u64), String>,
    txindex_synced: impl FnOnce() -> bool,
    esplora: impl FnOnce() -> Result<(Vec<(u64, String)>, u64), String>,
) -> TxLookup {
    match rpc {
        Ok((o, c)) => TxLookup::Found(o, c),
        Err(e) if is_rpc_tx_not_found(&e) && txindex_synced() => TxLookup::NotFound,
        Err(e) => match esplora() {
            Ok((o, c)) => TxLookup::Found(o, c),
            Err(e2) => TxLookup::Unavailable(format!("bitcoind: {e}; esplora: {e2}")),
        },
    }
}

fn btc_txindex_synced(cfg: &Config) -> bool {
    btc(cfg, false, &["getindexinfo", "txindex"])
        .ok()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
        .and_then(|v| v["txindex"]["synced"].as_bool())
        .unwrap_or(false)
}

/// Parse an esplora `/tx/<txid>` JSON body into (outputs, confirmations-ish: 1 if confirmed else 0).
fn parse_esplora_tx(body: &str) -> Result<(Vec<(u64, String)>, u64), String> {
    let v: serde_json::Value = serde_json::from_str(body).map_err(|e| format!("esplora json: {e}"))?;
    let vout = v["vout"].as_array().ok_or("esplora: no vout")?;
    let outs = vout.iter()
        .map(|o| (o["value"].as_u64().unwrap_or(0), o["scriptpubkey"].as_str().unwrap_or("").to_ascii_lowercase()))
        .collect();
    Ok((outs, if v["status"]["confirmed"].as_bool().unwrap_or(false) { 1 } else { 0 }))
}

fn esplora_tx_outputs(cfg: &Config, txid: &str) -> Result<(Vec<(u64, String)>, u64), String> {
    if cfg.esplora.is_empty() {
        return Err("no esplora configured".into());
    }
    let url = format!("{}/tx/{}", cfg.esplora.trim_end_matches('/'), txid);
    let body = run_cmd("curl", &["-sSf".into(), "--max-time".into(), "20".into(), url], &[])?;
    parse_esplora_tx(&body)
}

fn btc_tx_lookup(cfg: &Config, txid: &str) -> TxLookup {
    resolve_tx_lookup(btc_tx_outputs(cfg, txid), || btc_txindex_synced(cfg), || esplora_tx_outputs(cfg, txid))
}

fn deposit_unspent(cfg: &Config, outpoint: &str) -> bool {
    let (txid, vout) = outpoint.split_once(':').unwrap_or((outpoint, "0"));
    btc(cfg, false, &["gettxout", txid, vout]).map(|s| !s.trim().is_empty()).unwrap_or(false)
}

/// Free fronting capacity: wallet minus amounts committed to in-flight payouts
/// (claims we sent an intent for but have not funded yet; funded payouts have
/// already left the wallet) minus the configured reserve.
fn available_capacity(cfg: &Config, wallet: u64, st: &State) -> u64 {
    let committed: u64 = st.claims.values().filter(|c| c.phase == "intent").map(|c| fronted_amount(cfg, c.amount)).sum();
    wallet.saturating_sub(committed).saturating_sub(cfg.min_wallet_reserve_sats)
}

/// Floor for operator-paid fee rates (sat/vB): 0.125-1 sat/vB payouts sat unconfirmed on testnet4.
pub(crate) const MIN_FEE_RATE: u64 = 2;
/// PEG_OUT vsize estimate (1 P2WSH(P2PK) input, 1 output), as upstream MIN_RELAY_FEE_PEG_OUT.
pub(crate) const PEG_OUT_VSIZE: u64 = 122;

/// Sats the PEG_OUT itself pays in fees at `rate` sat/vB.
pub(crate) fn pegout_fee_sats(rate: u64) -> u64 {
    rate.max(MIN_FEE_RATE) * PEG_OUT_VSIZE
}

/// PEG_OUT input the operator funds: the EXACT withdrawal amount (ledger M1 attest requires an
/// output of exactly the burn amount to the dest) plus the PEG_OUT fee on top.
pub(crate) fn payout_funding_sats(amount: u64, pegout_fee_rate: u64) -> u64 {
    amount + pegout_fee_sats(pegout_fee_rate)
}

fn fronted_amount(cfg: &Config, amount: u64) -> u64 {
    amount - (amount as u128 * cfg.payout_fee_bps as u128 / 10_000) as u64
}

fn pool_ready(cfg: &Config) -> u64 {
    std::fs::read_dir(cfg.pool().join("ready")).map(|d| d.filter_map(|e| e.ok()).count() as u64).unwrap_or(0)
}

fn read_secret(cfg: &Config) -> Result<String, String> {
    let p = cfg.secret_path();
    let s = std::fs::read_to_string(&p).map_err(|_| format!("missing {}", p.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&p).map(|m| m.permissions().mode() & 0o077).unwrap_or(0);
        if mode != 0 {
            return Err(format!("{} must be 0600", p.display()));
        }
    }
    Ok(s.trim().to_string())
}

// ---------------- state ----------------

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct ClaimState {
    note_id: String,
    dest: String,
    amount: u64,
    binding: String,
    deposit_dir: String,
    deposit_outpoint: String,
    fronted_sats: u64,
    payout_txid: String,
    #[serde(default)]
    peg_out_txid: String,
    phase: String, // seen | intent | fronted | kickoff | done | lost | skipped | halted | error
    detail: String,
    updated: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Disagreement {
    note_id: String,
    kind: String,
    detail: String,
    peer: String,
    ts: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct State {
    claims: BTreeMap<String, ClaimState>,
    halted: bool,
    halt_reason: String,
    disagreements: Vec<Disagreement>,
    challenged: BTreeSet<String>,
    last_heartbeat: u64,
    #[serde(default)]
    last_capacity: Option<u64>,
    peer_cursor: BTreeMap<String, u64>,
    /// on-chain challenges detected but not yet broadcast (keyed chain:<operator>:<deposit>)
    #[serde(default)]
    challenge_pending: BTreeMap<String, PendingChallenge>,
    /// chain key -> challenge txid (or "already:<txid>") once on chain: never challenge twice
    #[serde(default)]
    challenge_txids: BTreeMap<String, String>,
    /// BRIDGE ledger duties (inert before activation).
    #[serde(default)]
    last_ledger_heartbeat: u64,
    #[serde(default)]
    ledger_bound: BTreeSet<String>,
    /// mined Disprove txid -> (cheating operator x-only, deposit confirm txid)
    #[serde(default)]
    slash_pending: BTreeMap<String, (String, String)>,
    #[serde(default)]
    slash_done: BTreeMap<String, String>,
    #[serde(default)]
    ledger_last_error: String,
    #[serde(default)]
    bind_tried: BTreeMap<String, u64>,
    /// submitted slash evidence awaiting ledger application: txid -> (operator, deposit, submitted_at)
    #[serde(default)]
    slash_submitted: BTreeMap<String, (String, String, u64)>,
    /// M1 attest: note -> last attempt (retry every 10 min until the ledger leaves AwaitingPegout/PegoutPosted)
    #[serde(default)]
    attest_tried: BTreeMap<String, u64>,
    #[serde(default)]
    attest_done: BTreeSet<String>,
    #[serde(default)]
    btc4_hdr_tried: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct PendingChallenge {
    note_id: String,
    binding: String,
    operator: String,
    deposit: String,
    reason: String,
    attempts: u64,
    last_try: u64,
    last_result: String,
    dry_run_done: bool,
}

impl State {
    fn load(p: &Path) -> State {
        std::fs::read_to_string(p).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
    }
    fn save(&self, p: &Path) {
        let tmp = p.with_extension("tmp");
        if std::fs::write(&tmp, serde_json::to_vec_pretty(self).unwrap()).is_ok() {
            let _ = std::fs::rename(tmp, p);
        }
    }
}

#[derive(Debug, Clone, Default, Serialize)]
struct Health {
    version: String,
    name: String,
    network: String,
    mode: String,
    operator_xonly: String,
    started: u64,
    last_poll: u64,
    last_error: String,
    falcon_ok: bool,
    falcon_height: u64,
    btc_ok: bool,
    btc_wallet_sats: u64,
    /// Free BTC for fronting: wallet - committed (won/intent, not yet funded) - reserve.
    #[serde(default)]
    available_sats: u64,
    pregen_ready: u64,
    pregen_target: u64,
    pregen_running: bool,
    deposits_indexed: u64,
    registered_peers: u64,
    quorum: u64,
    halted: bool,
    halt_reason: String,
    open_claims_seen: u64,
    fronted_total: u64,
    claims: Vec<ClaimState>,
    ledger: Vec<LedgerClaim>,
    disagreements: Vec<Disagreement>,
}

// ---------------- node shared ----------------

struct Node {
    cfg: Config,
    signer: Signer_,
    registry: Vec<gossip::Peer>,
    store: Mutex<Store>,
    health: Mutex<Health>,
}

impl Node {
    fn registry_keys(&self) -> BTreeSet<String> {
        let mut s: BTreeSet<String> = self.registry.iter().map(|p| p.xonly.to_ascii_lowercase()).collect();
        s.insert(self.signer.xonly.clone());
        s
    }
    fn quorum(&self) -> usize {
        self.cfg.quorum.unwrap_or_else(|| gossip::quorum(self.registry_keys().len()))
    }
    /// Sign, store, push to peers.
    fn emit(&self, kind: &str, note: &str, binding: &str, data: &[(&str, String)]) {
        let r = self.signer.sign(Record {
            v: 1,
            kind: kind.into(),
            note_id: note.into(),
            binding: binding.into(),
            data: data.iter().map(|(k, v)| (k.to_string(), v.clone())).collect(),
            signer: String::new(),
            ts: now(),
            sig: String::new(),
        });
        self.store.lock().unwrap().accept(r.clone(), &self.registry_keys(), now());
        let body = serde_json::to_string(&r).unwrap();
        for p in &self.registry {
            if p.url.is_empty() || p.xonly.eq_ignore_ascii_case(&self.signer.xonly) {
                continue;
            }
            if let Err(e) = http("POST", &p.url, "/gossip", Some(&body)) {
                log(&format!("push to {}: {e}", p.name));
            }
        }
    }
    fn pull_peers(&self, st: &mut State) {
        for p in &self.registry {
            if p.url.is_empty() || p.xonly.eq_ignore_ascii_case(&self.signer.xonly) {
                continue;
            }
            let since = st.peer_cursor.get(&p.xonly).copied().unwrap_or(0);
            match http("GET", &p.url, &format!("/gossip?since={since}"), None) {
                Ok(body) => {
                    let recs: Vec<Record> = serde_json::from_str(&body).unwrap_or_default();
                    let keys = self.registry_keys();
                    let mut store = self.store.lock().unwrap();
                    let mut max = since;
                    for r in recs {
                        max = max.max(r.ts);
                        store.accept(r, &keys, now());
                    }
                    st.peer_cursor.insert(p.xonly.clone(), max);
                }
                Err(e) => log(&format!("pull from {}: {e}", p.name)),
            }
        }
    }
}

// minimal HTTP/1.1 client (plain TCP; run peers over WireGuard/TLS proxy)
fn http(method: &str, base: &str, path: &str, body: Option<&str>) -> Result<String, String> {
    let hostport = base.trim_start_matches("http://").trim_end_matches('/');
    let mut s = TcpStream::connect(hostport).map_err(|e| e.to_string())?;
    s.set_read_timeout(Some(Duration::from_secs(10))).ok();
    s.set_write_timeout(Some(Duration::from_secs(10))).ok();
    let b = body.unwrap_or("");
    write!(s, "{method} {path} HTTP/1.1\r\nHost: {hostport}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{b}", b.len()).map_err(|e| e.to_string())?;
    let mut resp = String::new();
    s.read_to_string(&mut resp).map_err(|e| e.to_string())?;
    let (head, body) = resp.split_once("\r\n\r\n").ok_or("bad response")?;
    if !head.starts_with("HTTP/1.1 2") && !head.starts_with("HTTP/1.0 2") {
        return Err(head.lines().next().unwrap_or("").to_string());
    }
    Ok(body.to_string())
}

// ---------------- operator flow ----------------

fn alert(n: &Node, st: &mut State, d: Disagreement) {
    log(&format!("ALERT {} {}: {}", d.kind, d.note_id, d.detail));
    let hook = n.cfg.alert_cmd.clone();
    if !hook.is_empty() {
        let _ = run_cmd(&hook, &[], &[("FPL_ALERT_KIND".into(), d.kind.clone()), ("FPL_ALERT_NOTE".into(), d.note_id.clone()), ("FPL_ALERT_DETAIL".into(), d.detail.clone())]);
    }
    n.emit("Disagreement", &d.note_id, "", &[("kind", d.kind.clone()), ("detail", d.detail.clone()), ("peer", d.peer.clone())]);
    st.disagreements.push(d);
    if st.disagreements.len() > 500 {
        st.disagreements.remove(0);
    }
}

fn pick_deposit(n: &Node, st: &State, deps: &[deposits::DepositGraph], c: &LedgerClaim) -> Option<deposits::DepositGraph> {
    let taken: BTreeSet<String> = st.claims.values().map(|c| c.deposit_outpoint.clone()).collect();
    let store = n.store.lock().unwrap();
    let gossip_taken: BTreeSet<String> = store.records.iter().filter(|r| r.kind == "ClaimIntent" && r.note_id != c.note_id).filter_map(|r| r.data.get("deposit").cloned()).collect();
    deps.iter()
        .filter(|d| d.amount == c.amount)
        .filter(|d| n.cfg.btc_pubkey_hex.is_empty() || d.operator_pubkeys.contains(&n.cfg.btc_pubkey_hex))
        .filter(|d| !taken.contains(&d.confirm_outpoint) && !gossip_taken.contains(&d.confirm_outpoint))
        .find(|d| deposit_unspent(&n.cfg, &d.confirm_outpoint))
        .cloned()
}

fn write_falcon_claims(n: &Node, c: &ClaimState, ledger: &LedgerClaim) -> Result<PathBuf, String> {
    let p = n.cfg.home.join("claims").join(format!("{}.json", c.note_id));
    std::fs::create_dir_all(p.parent().unwrap()).map_err(|e| e.to_string())?;
    let v = serde_json::json!([{
        "note_id": c.note_id, "dest": c.dest, "amount": c.amount, "open_height": ledger.open_height,
        "deposit_confirm_outpoint": c.deposit_outpoint, "operator_pubkey": n.cfg.btc_pubkey_hex,
    }]);
    std::fs::write(&p, serde_json::to_vec_pretty(&v).unwrap()).map_err(|e| e.to_string())?;
    Ok(p)
}

fn front_payout(cfg: &Config, sats: u64) -> Result<String, String> {
    if cfg.network == "mainnet" {
        return Err("mainnet disabled until the bridge activates".into());
    }
    if cfg.payout_address.is_empty() {
        return Err("FPL_OP_PAYOUT_ADDRESS not set".into());
    }
    let btc_amt = format!("{}.{:08}", sats / 100_000_000, sats % 100_000_000);
    let outputs = format!("{{\"{}\":{btc_amt}}}", cfg.payout_address);
    let out = btc(cfg, true, &["-named", "send", &format!("outputs={outputs}"), &format!("fee_rate={}", cfg.fee_rate)])?;
    let v: serde_json::Value = serde_json::from_str(&out).map_err(|e| e.to_string())?;
    let txid = v["txid"].as_str().ok_or_else(|| format!("send: {out}"))?.to_string();
    let t: serde_json::Value = serde_json::from_str(&btc(cfg, true, &["gettransaction", &txid])?).map_err(|e| e.to_string())?;
    let vout = t["details"].as_array().into_iter().flatten()
        .find(|d| d["address"].as_str() == Some(cfg.payout_address.as_str()))
        .and_then(|d| d["vout"].as_u64())
        .ok_or("payout vout not found")?;
    Ok(format!("{txid}:{vout}"))
}

fn run_graph_steps(n: &Node, c: &ClaimState, claims_file: &Path) -> Result<(), String> {
    let cmd = n.cfg.hook(&n.cfg.kickoff_cmd, "fpl-operator-graph.sh");
    let envs = vec![
        ("FPL_OPERATOR_SECRET".to_string(), read_secret(&n.cfg)?),
        ("FPL_CLAIM_NOTE_ID".to_string(), c.note_id.clone()),
        ("FPL_CLAIM_AMOUNT".to_string(), c.amount.to_string()),
        ("FPL_CLAIM_DEST".to_string(), c.dest.clone()),
        ("FPL_PAYOUT_OUTPOINT".to_string(), c.payout_txid.clone()),
        ("FPL_PEG_OUT_FEE_SAT_PER_VB".to_string(), n.cfg.pegout_fee_rate.to_string()),
        ("FPL_DEPOSIT_DIR".to_string(), c.deposit_dir.clone()),
        ("FPL_FALCON_CLAIMS".to_string(), claims_file.to_string_lossy().to_string()),
        ("FPL_NETWORK".to_string(), n.cfg.network.clone()),
        ("FPL_ESPLORA".to_string(), n.cfg.esplora.clone()),
        ("FPL_OP_HOME".to_string(), n.cfg.home.to_string_lossy().to_string()),
    ].into_iter().chain(n.cfg.proof_env()).collect::<Vec<_>>();
    run_cmd(&cmd, &[], &envs).map(|_| ())
}

/// Our own claims: see -> cross-check -> intent -> win -> front -> kickoff.
fn operate(n: &Node, st: &mut State, ledger: &[LedgerClaim], h: &mut Health, status: &serde_json::Value, falcon_height: u64) {
    let bridge = ledger::bridge_active(status);
    // BRIDGE refusal rule: once active, only deposits whose every operator graph is
    // bound on the ledger (and matches final.json) are usable for fronting.
    let deps: Vec<deposits::DepositGraph> = deposits::index(&n.cfg.graphs())
        .into_iter()
        .filter(|d| {
            if !bridge {
                return true;
            }
            let v = std::fs::read(d.dir.join("final.json")).ok().and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok());
            match v.as_ref().map(|v| ledger::check_deposit_graphs(v, status)) {
                Some(Ok(_)) => true,
                Some(Err(e)) => {
                    h.last_error = format!("deposit {} refused: {e}", d.confirm_outpoint);
                    false
                }
                None => false,
            }
        })
        .collect();
    h.deposits_indexed = deps.len() as u64;
    let need = n.quorum();
    for lc in ledger.iter().filter(|c| c.status == "AwaitingPegout") {
        let bind = lc.binding();
        let fresh = !st.claims.contains_key(&lc.note_id);
        if fresh {
            n.emit("WithdrawalSeen", &lc.note_id, &bind, &[("dest", lc.dest.clone()), ("amount", lc.amount.to_string()), ("open_height", lc.open_height.to_string())]);
            st.claims.insert(lc.note_id.clone(), ClaimState { note_id: lc.note_id.clone(), dest: lc.dest.clone(), amount: lc.amount, binding: bind.clone(), phase: "seen".into(), updated: now(), ..Default::default() });
        }
        let phase = st.claims[&lc.note_id].phase.clone();
        if phase != "seen" && phase != "intent" {
            continue;
        }
        // pre-claim cross-check against peers
        let cc = gossip::cross_check(&n.store.lock().unwrap(), &lc.note_id, &bind, &n.signer.xonly, need);
        match cc {
            CrossCheck::Disagree { peer, theirs } => {
                let e = st.claims.get_mut(&lc.note_id).unwrap();
                e.phase = "halted".into();
                e.detail = format!("peer {peer} binding {theirs} != ours {bind}");
                st.halted = true;
                st.halt_reason = format!("binding disagreement on {}", lc.note_id);
                alert(n, st, Disagreement { note_id: lc.note_id.clone(), kind: "binding".into(), detail: format!("ours {bind} theirs {theirs}"), peer, ts: now() });
                continue;
            }
            CrossCheck::Waiting { have, need } => {
                st.claims.get_mut(&lc.note_id).unwrap().detail = format!("cross-check: {have}/{need} peers agree");
                continue;
            }
            CrossCheck::Agreed { .. } => {}
        }
        if st.halted {
            st.claims.get_mut(&lc.note_id).unwrap().detail = format!("node halted: {}", st.halt_reason);
            continue;
        }
        let e = st.claims.get(&lc.note_id).unwrap().clone();
        if lc.amount == 0 || lc.amount > n.cfg.max_payout_sats {
            let e = st.claims.get_mut(&lc.note_id).unwrap();
            e.phase = "skipped".into();
            e.detail = format!("amount outside policy (max {})", n.cfg.max_payout_sats);
            continue;
        }
        // BRIDGE: stop fronting once half the refund window has passed
        if bridge {
            if let Some(cut) = ledger::front_cutoff(status, lc.open_height) {
                if falcon_height >= cut {
                    let e = st.claims.get_mut(&lc.note_id).unwrap();
                    e.phase = "skipped".into();
                    e.detail = format!("past front cutoff (ledger {cut}): claim may refund; not fronting");
                    continue;
                }
            }
        }
        if e.phase == "seen" {
            let fronted = payout_funding_sats(lc.amount, n.cfg.pegout_fee_rate);
            if available_capacity(&n.cfg, h.btc_wallet_sats, st) < fronted {
                st.claims.get_mut(&lc.note_id).unwrap().detail = "insufficient operator BTC; will retry".into();
                continue;
            }
            let Some(d) = pick_deposit(n, st, &deps, lc) else {
                st.claims.get_mut(&lc.note_id).unwrap().detail = "no free deposit graph of this amount with our peg-out graph".into();
                continue;
            };
            n.emit("ClaimIntent", &lc.note_id, &bind, &[("deposit", d.confirm_outpoint.clone())]);
            let e = st.claims.get_mut(&lc.note_id).unwrap();
            e.phase = "intent".into();
            e.deposit_dir = d.dir.to_string_lossy().to_string();
            e.deposit_outpoint = d.confirm_outpoint;
            e.updated = now();
            e.detail = format!("intent sent; waiting {}s for competing intents", n.cfg.intent_wait_secs);
            continue;
        }
        // phase intent: decide winner after the wait
        if now() < e.updated + n.cfg.intent_wait_secs {
            continue;
        }
        // only operators whose advertised capacity covered the amount are eligible
        let winner = gossip::intent_winner_eligible(&n.store.lock().unwrap(), &lc.note_id, fronted_amount(&n.cfg, lc.amount));
        if winner.as_ref().map(|w| w.0.as_str()) != Some(n.signer.xonly.as_str()) {
            let e = st.claims.get_mut(&lc.note_id).unwrap();
            e.phase = "lost".into();
            e.detail = format!("another operator serves it: {:?}", winner.map(|w| w.0));
            e.deposit_outpoint.clear();
            continue;
        }
        let fronted = fronted_amount(&n.cfg, lc.amount);
        if let Some(why) = front_blocked(n.cfg.attest_ready(), n.cfg.allow_unattested) {
            st.claims.get_mut(&lc.note_id).unwrap().detail = why;
            continue;
        }
        if !n.cfg.live() {
            st.claims.get_mut(&lc.note_id).unwrap().detail = format!("dry-run: won; would fund PEG_OUT with {fronted} sats for {} using deposit {}", lc.dest, e.deposit_outpoint);
            continue;
        }
        match front_payout(&n.cfg, payout_funding_sats(lc.amount, n.cfg.pegout_fee_rate)) {
            Ok(op) => {
                log(&format!("claim {}: funded PEG_OUT input {op}", lc.note_id));
                deposits::bind_claim(&n.cfg.graphs(), &lc.note_id, Path::new(&e.deposit_dir));
                n.emit("PayoutTx", &lc.note_id, &bind, &[("funding_outpoint", op.clone()), ("deposit", e.deposit_outpoint.clone()), ("fronted", fronted.to_string())]);
                let e = st.claims.get_mut(&lc.note_id).unwrap();
                e.fronted_sats = fronted;
                e.payout_txid = op;
                e.phase = "fronted".into();
                h.fronted_total += fronted;
            }
            Err(err) => {
                let e = st.claims.get_mut(&lc.note_id).unwrap();
                e.phase = "error".into();
                e.detail = err;
            }
        }
    }
    // PEG_OUT txid written by the coordinator: gossip it so watchers verify the exact payout script
    let kicked: Vec<String> = st.claims.iter().filter(|(_, c)| c.phase == "kickoff" && c.peg_out_txid.is_empty()).map(|(k, _)| k.clone()).collect();
    for id in kicked {
        let c = st.claims[&id].clone();
        let dir = Path::new(&c.deposit_dir);
        let Ok(t) = std::fs::read_to_string(dir.join("peg_out.txid")) else { continue };
        let t = t.trim().to_string();
        if t.len() != 64 {
            continue;
        }
        let k1 = std::fs::read_to_string(dir.join("kick_off_1.txid")).unwrap_or_default().trim().to_string();
        n.emit("PegOut", &id, &c.binding, &[("peg_out_txid", t.clone()), ("deposit", c.deposit_outpoint.clone()), ("kick_off_1", k1)]);
        st.claims.get_mut(&id).unwrap().peg_out_txid = t;
    }
    // graph steps (kickoff -> take)
    let ids: Vec<String> = st.claims.iter().filter(|(_, c)| c.phase == "fronted").map(|(k, _)| k.clone()).collect();
    for id in ids {
        let c = st.claims[&id].clone();
        let Some(lc) = ledger.iter().find(|l| l.note_id == id) else { continue };
        // re-check binding right before kickoff
        if lc.binding() != c.binding {
            st.halted = true;
            st.halt_reason = format!("ledger binding changed for {id}");
            alert(n, st, Disagreement { note_id: id.clone(), kind: "ledger-changed".into(), detail: "binding changed between payout and kickoff".into(), peer: String::new(), ts: now() });
            continue;
        }
        let r = write_falcon_claims(n, &c, lc).and_then(|f| run_graph_steps(n, &c, &f));
        let e = st.claims.get_mut(&id).unwrap();
        match r {
            Ok(()) => {
                e.phase = "kickoff".into();
                e.detail = "graph steps started (PEG_OUT -> kickoff -> take)".into();
                let (b, dep) = (c.binding.clone(), c.deposit_outpoint.clone());
                n.emit("Kickoff", &id, &b, &[("deposit", dep)]);
            }
            Err(err) => e.detail = format!("graph steps: {err}"),
        }
        e.updated = now();
    }
}

/// Watcher over ALL operators. Every Kickoff / PayoutTx / PegOut record must match the Falcon
/// ledger; a kickoff must be followed (by the deadline) by a PEG_OUT that pays the EXACT upstream
/// payout script (dest hash + open height + Falcon note id) at least amount - fee. Bad kickoffs
/// are challenged on Bitcoin with fpl_challenge (funded from our wallet), once per graph.
fn watch(n: &Node, st: &mut State, ledger: &[LedgerClaim]) {
    let by_note: BTreeMap<&str, &LedgerClaim> = ledger.iter().map(|c| (c.note_id.as_str(), c)).collect();
    let recs: Vec<Record> = n.store.lock().unwrap().records.iter().filter(|r| matches!(r.kind.as_str(), "Kickoff" | "PayoutTx" | "PegOut") && r.signer != n.signer.xonly).cloned().collect();
    let mut findings = vec![];
    for r in &recs {
        // one evaluation per distinct record (a graph = deposit; a payout = PEG_OUT txid)
        let d = |k: &str| r.data.get(k).cloned().unwrap_or_default();
        let key = format!("{}:{}:{}:{}:{}", r.kind, r.signer, r.note_id, d("deposit"), d("peg_out_txid"));
        if st.challenged.contains(&key) {
            continue;
        }
        let bad = match by_note.get(r.note_id.as_str()) {
            None => Some("no such withdrawal in the Falcon ledger".to_string()),
            Some(lc) if lc.binding() != r.binding => Some("binding differs from the Falcon ledger".into()),
            Some(lc) => check_payout(n, r, lc, &recs),
        };
        if let Some(why) = bad {
            findings.push((key, r.clone(), why));
        }
    }
    for (key, r, why) in findings {
        st.challenged.insert(key);
        let deposit = r.data.get("deposit").cloned().unwrap_or_else(|| {
            recs.iter().find(|k| k.signer == r.signer && k.note_id == r.note_id && k.data.contains_key("deposit")).and_then(|k| k.data.get("deposit").cloned()).unwrap_or_default()
        });
        let ck = format!("chain:{}:{}", r.signer, if deposit.is_empty() { &r.note_id } else { &deposit });
        n.emit("Challenge", &r.note_id, &r.binding, &[("operator", r.signer.clone()), ("reason", why.clone()), ("deposit", deposit.clone())]);
        alert(n, st, Disagreement { note_id: r.note_id.clone(), kind: "challenge".into(), detail: why.clone(), peer: r.signer.clone(), ts: now() });
        if st.challenge_txids.contains_key(&ck) || st.challenge_pending.contains_key(&ck) {
            continue; // same graph already being / been challenged: never double-challenge
        }
        st.challenge_pending.insert(ck, PendingChallenge { note_id: r.note_id.clone(), binding: r.binding.clone(), operator: r.signer.clone(), deposit, reason: why, ..Default::default() });
    }
    run_challenges(n, st);
}

/// Payout checks for a record whose withdrawal exists in the ledger with the same binding.
fn check_payout(n: &Node, r: &Record, lc: &LedgerClaim, recs: &[Record]) -> Option<String> {
    let past_deadline = |ts: u64| now() > ts + n.cfg.payout_deadline_secs;
    let pegout_txid = |rec: &Record| rec.data.get("peg_out_txid").cloned().unwrap_or_default();
    // Err("tx-not-found: ..") only for a genuine RPC -5 with synced txindex; Err("unavailable: ..")
    // when bitcoind and esplora can't tell (never grounds for a challenge: skip and retry next poll).
    let verify = |txid: &str| -> Result<(), String> {

        let min = payout::min_payout(lc.amount, n.cfg.max_peer_fee_bps, n.cfg.pegout_fee_allow_sats);
        let outs = match btc_tx_lookup(&n.cfg, txid) {
            TxLookup::Found(outs, _) => outs,
            TxLookup::NotFound => return Err(format!("tx-not-found: {txid}")),
            TxLookup::Unavailable(e) => return Err(format!("unavailable: {e}")),
        };
        payout::payout_ok(&outs, &lc.dest, lc.open_height, &lc.note_id, lc.amount, min, &n.cfg.network).map(|_| ())
    };
    match r.kind.as_str() {
        "PegOut" => match verify(&pegout_txid(r)) {
            Ok(()) => None,
            Err(e) if e.starts_with("unavailable") => {
                eprintln!("check_payout: skip PEG_OUT {} this round ({e})", pegout_txid(r));
                None
            }
            Err(e) if e.starts_with("tx-not-found") => past_deadline(r.ts).then(|| format!("PEG_OUT {} not found on Bitcoin by the deadline", pegout_txid(r))),
            Err(e) => Some(e),
        },
        "Kickoff" => {
            let pegouts: Vec<&Record> = recs.iter().filter(|p| p.kind == "PegOut" && p.signer == r.signer && p.note_id == r.note_id && p.data.get("deposit") == r.data.get("deposit")).collect();
            let results: Vec<Result<(), String>> = pegouts.iter().map(|p| verify(&pegout_txid(p))).collect();
            if results.iter().any(|v| v.is_ok()) {
                None
            } else if results.iter().any(|v| matches!(v, Err(e) if e.starts_with("unavailable"))) {
                None // can't verify right now: never challenge on our own outage
            } else if past_deadline(r.ts) {
                Some(if pegouts.is_empty() { "kickoff without a PEG_OUT past the payout deadline".into() } else { "kickoff without a valid PEG_OUT past the payout deadline".into() })
            } else {
                None
            }
        }
        _ => None, // PayoutTx = funding of the PEG_OUT input (operator's own address); checked via PegOut
    }
}

/// Broadcast pending on-chain challenges via the challenge hook (fpl_challenge). Idempotent:
/// a graph with a known challenge txid is never challenged again; dry-run plans only.
fn run_challenges(n: &Node, st: &mut State) {
    let keys: Vec<String> = st.challenge_pending.keys().cloned().collect();
    for ck in keys {
        let p = st.challenge_pending[&ck].clone();
        if p.dry_run_done && !n.cfg.live() {
            continue;
        }
        if p.attempts > 0 && now() < p.last_try + n.cfg.challenge_retry_secs {
            continue;
        }
        let secret = read_secret(&n.cfg).unwrap_or_default();
        let mut cli = vec![n.cfg.bitcoin_cli.clone()];
        cli.extend(n.cfg.bitcoin_args.iter().cloned());
        cli.push(format!("-rpcwallet={}", n.cfg.btc_wallet));
        let hook = n.cfg.hook(&n.cfg.challenge_cmd, "fpl-operator-challenge.sh");
        let (code, out, err) = run_cmd_full(&hook, &[
            ("FPL_CHALLENGE_NOTE".into(), p.note_id.clone()),
            ("FPL_CHALLENGE_OPERATOR".into(), p.operator.clone()),
            ("FPL_CHALLENGE_DEPOSIT".into(), p.deposit.clone()),
            ("FPL_CHALLENGE_REASON".into(), p.reason.clone()),
            ("FPL_OP_HOME".into(), n.cfg.home.to_string_lossy().to_string()),
            ("FPL_NETWORK".into(), n.cfg.network.clone()),
            ("FPL_ESPLORA".into(), n.cfg.esplora.clone()),
            ("FPL_OP_BITCOIN_CLI".into(), cli.join(" ")),
            ("FPL_DRY_RUN".into(), if n.cfg.live() { "0".into() } else { "1".into() }),
            ("FPL_CHALLENGE_VK_DIR".into(), n.cfg.challenge_vk_dir.clone()),
            ("FPL_OPERATOR_SECRET".into(), secret),
        ].into_iter().chain(n.cfg.proof_env()).collect::<Vec<_>>());
        let tag = |t: &str| out.lines().find_map(|l| l.strip_prefix(t).map(|x| x.trim().to_string()));
        if let Some(d) = ledger::disprove_txid_in(&out) {
            let dep = p.deposit.split(':').next().unwrap_or("").to_string();
            st.slash_pending.entry(d).or_insert((p.operator.clone(), dep));
        }
        let e = st.challenge_pending.get_mut(&ck).unwrap();
        e.attempts += 1;
        e.last_try = now();
        let short = |s: &str| s.trim().chars().take(300).collect::<String>();
        if let Some(txid) = tag("CHALLENGE_TXID ") {
            log(&format!("challenge broadcast for {} operator {}: {txid}", p.note_id, p.operator));
            st.challenge_pending.remove(&ck);
            st.challenge_txids.insert(ck, txid.clone());
            n.emit("ChallengeTx", &p.note_id, &p.binding, &[("operator", p.operator.clone()), ("deposit", p.deposit.clone()), ("challenge_txid", txid), ("reason", p.reason.clone())]);
        } else if let Some(txid) = tag("ALREADY_CHALLENGED ") {
            st.challenge_pending.remove(&ck);
            st.challenge_txids.insert(ck, format!("already:{txid}"));
        } else if let Some(plan) = tag("DRY_RUN ") {
            e.dry_run_done = true;
            e.last_result = format!("dry-run: {}", short(&plan));
        } else if code == 0 {
            // hook without fpl_challenge (records + alerts only)
            e.dry_run_done = !n.cfg.live();
            e.last_result = short(&out);
            if out.contains("recorded (no fpl_challenge") {
                e.dry_run_done = true;
            }
        } else if code == 75 {
            e.last_result = format!("not ready: {}", short(&out));
        } else {
            e.last_result = format!("exit {code}: {}", short(&err));
            log(&format!("challenge {} failed: {}", p.note_id, e.last_result));
        }
    }
}

// ---------------- servers ----------------

fn read_request(s: &mut TcpStream) -> Option<(String, String, String)> {
    s.set_read_timeout(Some(Duration::from_secs(5))).ok();
    let mut r = BufReader::new(s.try_clone().ok()?);
    let mut first = String::new();
    r.read_line(&mut first).ok()?;
    let mut parts = first.split_whitespace();
    let (m, p) = (parts.next()?.to_string(), parts.next()?.to_string());
    let mut len = 0usize;
    loop {
        let mut l = String::new();
        if r.read_line(&mut l).ok()? == 0 || l == "\r\n" {
            break;
        }
        if let Some(v) = l.to_ascii_lowercase().strip_prefix("content-length:") {
            len = v.trim().parse().unwrap_or(0);
        }
    }
    let mut body = vec![0u8; len.min(1 << 20)];
    r.read_exact(&mut body).ok()?;
    Some((m, p, String::from_utf8_lossy(&body).to_string()))
}

fn respond(s: &mut TcpStream, code: &str, body: &str) {
    let _ = write!(s, "HTTP/1.1 {code}\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
}

fn feed_json(n: &Node) -> String {
    let h = n.health.lock().unwrap().clone();
    let store = n.store.lock().unwrap();
    let mut ops = vec![];
    for k in n.registry_keys() {
        let mine: Vec<&Record> = store.records.iter().filter(|r| r.signer == k).collect();
        let name = n.registry.iter().find(|p| p.xonly.eq_ignore_ascii_case(&k)).map(|p| p.name.clone()).unwrap_or_else(|| if k == n.signer.xonly { n.cfg.name.clone() } else { String::new() });
        ops.push(serde_json::json!({
            "name": name, "xonly": k,
            "last_seen": mine.iter().map(|r| r.ts).max().unwrap_or(0),
            "heartbeats": mine.iter().filter(|r| r.kind == "Heartbeat").count(),
            "available_sats": gossip::capacity_at(&store, &k, u64::MAX),
            "payouts": mine.iter().filter(|r| r.kind == "PayoutTx").count(),
            "kickoffs": mine.iter().filter(|r| r.kind == "Kickoff").count(),
            "challenges_raised": mine.iter().filter(|r| r.kind == "Challenge").count(),
            "challenged": store.records.iter().filter(|r| r.kind == "Challenge" && r.data.get("operator") == Some(&k)).count(),
        }));
    }
    let claims: Vec<serde_json::Value> = h.ledger.iter().map(|c| {
        let recs: Vec<serde_json::Value> = store.for_note(&c.note_id).map(|r| serde_json::json!({"kind": r.kind, "signer": r.signer, "ts": r.ts, "binding_ok": r.binding.is_empty() || r.binding == c.binding(), "data": r.data})).collect();
        serde_json::json!({"note_id": c.note_id, "amount": c.amount, "dest": c.dest, "status": c.status, "binding": c.binding(), "records": recs})
    }).collect();
    let disagreements: Vec<&Record> = store.records.iter().filter(|r| r.kind == "Disagreement" || r.kind == "Challenge" || r.kind == "ChallengeTx").collect();
    serde_json::to_string_pretty(&serde_json::json!({
        "feed_version": 1, "generated": now(), "reporter": n.signer.xonly, "network": h.network,
        "falcon_height": h.falcon_height, "quorum": h.quorum, "halted": h.halted, "halt_reason": h.halt_reason,
        "operators": ops, "claims": claims, "disagreements": disagreements,
    })).unwrap()
}

/// Public p2p server: POST /gossip, GET /gossip?since=, GET /feed. No secrets here.
fn serve_p2p(n: Arc<Node>) {
    let l = match TcpListener::bind(&n.cfg.p2p_listen) {
        Ok(l) => l,
        Err(e) => return log(&format!("p2p bind {}: {e}", n.cfg.p2p_listen)),
    };
    log(&format!("p2p/feed on http://{}/feed", n.cfg.p2p_listen));
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            let n = n.clone();
            std::thread::spawn(move || {
                let mut s = s;
                let Some((m, p, body)) = read_request(&mut s) else { return };
                match (m.as_str(), p.split('?').next().unwrap_or("")) {
                    ("POST", "/gossip") => {
                        let res = serde_json::from_str::<Record>(&body).map(|r| n.store.lock().unwrap().accept(r, &n.registry_keys(), now()));
                        match res {
                            Ok(gossip::Accept::New) | Ok(gossip::Accept::Duplicate) => respond(&mut s, "200 OK", "{\"ok\":true}"),
                            Ok(a) => respond(&mut s, "403 Forbidden", &format!("{{\"ok\":false,\"reason\":\"{a:?}\"}}")),
                            Err(_) => respond(&mut s, "400 Bad Request", "{}"),
                        }
                    }
                    ("GET", "/gossip") => {
                        let since = p.split("since=").nth(1).and_then(|v| v.parse().ok()).unwrap_or(0);
                        let recs: Vec<Record> = n.store.lock().unwrap().since(since).into_iter().take(5000).cloned().collect();
                        respond(&mut s, "200 OK", &serde_json::to_string(&recs).unwrap());
                    }
                    ("GET", "/feed") | ("GET", "/") => respond(&mut s, "200 OK", &feed_json(&n)),
                    _ => respond(&mut s, "404 Not Found", "{}"),
                }
            });
        }
    });
}

/// Local only: /health, /status (+ POST /resume to clear a halt via `falcon-operator resume`).
fn serve_local(n: Arc<Node>, resume: Arc<Mutex<bool>>) {
    let l = match TcpListener::bind(&n.cfg.health_listen) {
        Ok(l) => l,
        Err(e) => return log(&format!("health bind {}: {e}", n.cfg.health_listen)),
    };
    log(&format!("health on http://{}/health", n.cfg.health_listen));
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            let mut s = s;
            let Some((m, p, _)) = read_request(&mut s) else { continue };
            let hv = n.health.lock().unwrap().clone();
            let healthy = hv.falcon_ok && hv.btc_ok && !hv.halted;
            match (m.as_str(), p.as_str()) {
                (_, "/health") => respond(&mut s, if healthy { "200 OK" } else { "503 Service Unavailable" }, &serde_json::json!({"ok": healthy, "halted": hv.halted, "version": hv.version}).to_string()),
                ("POST", "/resume") => {
                    *resume.lock().unwrap() = true;
                    respond(&mut s, "200 OK", "{\"ok\":true}")
                }
                (_, "/status") | (_, "/") => respond(&mut s, "200 OK", &serde_json::to_string_pretty(&hv).unwrap()),
                _ => respond(&mut s, "404 Not Found", "{}"),
            }
        }
    });
}

// ---------------- pregen ----------------

fn spawn_pregen(cfg: &Config) -> Result<std::process::Child, String> {
    let secret = read_secret(cfg)?;
    let net = if cfg.network == "regtest" { "regtest" } else { "testnet4" };
    let proof = cfg.proof()?;
    let tag = proof.as_ref().map(|p| p.1.clone()).unwrap_or_else(|| "mock-regtest".into());
    let retired = prover::retag_pool(&cfg.pool(), &tag)?;
    if retired > 0 {
        log(&format!("pregen: retired {retired} pool entries built for another VK"));
    }
    let log = std::fs::OpenOptions::new().create(true).append(true).open(cfg.home.join("logs").join("pregen.log")).map_err(|e| e.to_string())?;
    let mut c = Command::new("nice");
    if let Some((d, _)) = &proof {
        c.env("FPL_PROOF_DIR", d);
    }
    c
        .args(["-n", "10"])
        .arg(cfg.bin_dir.join("fpl_pregen"))
        .args(["--network", net, "--pool"])
        .arg(cfg.pool())
        .args(["--count", "1"])
        .env("FPL_OPERATOR_SECRET", secret)
        .stdin(Stdio::null())
        .stdout(log.try_clone().map_err(|e| e.to_string())?)
        .stderr(log)
        .spawn()
        .map_err(|e| format!("spawn fpl_pregen: {e}"))
}

// ---------------- commands ----------------

fn ensure_dirs(home: &Path) {
    for d in ["keys", "logs", "pregen/ready", "pregen/used", "bin", "graphs/by-claim", "claims"] {
        let _ = std::fs::create_dir_all(home.join(d));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(home, std::fs::Permissions::from_mode(0o700));
        let _ = std::fs::set_permissions(home.join("keys"), std::fs::Permissions::from_mode(0o700));
    }
}

const DEFAULT_ENV: &str = r#"# fpl-operatord config. Keys are NOT here: keys/operator.secret (0600) and your bitcoind wallet.
FPL_OP_NAME=operator
FPL_OP_NETWORK=testnet4
# dry-run logs what it would pay; live actually sends from your wallet.
FPL_OP_MODE=dry-run
FPL_OP_FALCON_CTL=falcon-pl-ctl
FPL_OP_FALCON_RPC=127.0.0.1:19401
FPL_OP_FALCON_ACCOUNT=
FPL_OP_BITCOIN_CLI=bitcoin-cli
# your bitcoind needs txindex=1 (watcher verifies other operators' payouts)
FPL_OP_BITCOIN_ARGS=-testnet4
FPL_OP_BTC_WALLET=fpl-operator
FPL_OP_PAYOUT_FEE_BPS=30
FPL_OP_MAX_PAYOUT_SATS=1000000
FPL_OP_MIN_RESERVE_SATS=50000
FPL_OP_POLL_SECS=30
FPL_OP_HEALTH_LISTEN=127.0.0.1:19480
# public: peers gossip here and the status page reads /feed (put behind TLS/WireGuard)
FPL_OP_P2P_LISTEN=0.0.0.0:19481
FPL_OP_PREGEN_TARGET=2
FPL_OP_ESPLORA=https://mempool.space/testnet4/api
# watcher: max fee (bps) + PEG_OUT relay-fee allowance (sats) a peer may deduct from a payout
FPL_OP_MAX_PEER_FEE_BPS=100
FPL_OP_PEGOUT_FEE_ALLOW_SATS=1000
# watcher: vk.bin dir of the bridge circuit -> follow challenged graphs and broadcast Disprove
# (non-standard; miner channels in submit.json, see OPERATOR_GUIDE)
FPL_OP_CHALLENGE_VK_DIR=
# public operator keys (falcon-operator keys)
FPL_OP_BTC_XONLY=
FPL_OP_BTC_PUBKEY=
FPL_OP_PAYOUT_ADDRESS=
FPL_OP_FEE_RATE=2
# PEG_OUT fee (sat/vB, min 2), paid on top of the exact withdrawal amount
FPL_OP_PEGOUT_FEE_RATE=2
# cross-check quorum (default ceil(2/3) of other registered operators)
#FPL_OP_QUORUM=
FPL_OP_INTENT_WAIT_SECS=60
FPL_OP_PAYOUT_DEADLINE_SECS=21600
FPL_OP_HEARTBEAT_SECS=600
# optional hooks
#FPL_OP_ALERT_CMD=/path/to/notify.sh
"#;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(String::as_str).unwrap_or("help");
    let mut home = std::env::var("FPL_OP_HOME").map(PathBuf::from).unwrap_or_else(|_| PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".into())).join(".falcon-operator"));
    let mut i = 2;
    while i < args.len() {
        if args[i] == "--home" && i + 1 < args.len() {
            home = PathBuf::from(&args[i + 1]);
            i += 1;
        }
        i += 1;
    }
    match cmd {
        "payout-spk" => {
            // payout-spk <dest> <open_height> <note_id> [network]: exact PEG_OUT output script
            let a = |k: usize| args.iter().filter(|x| !x.starts_with("--")).nth(k).cloned().unwrap_or_default();
            let net = if a(5).is_empty() { Config::load(&home).network } else { a(5) };
            match payout::expected_payout_spk(&a(2), a(3).parse().unwrap_or(0), &a(4), &net) {
                Ok(s) => println!("{s}"),
                Err(e) => {
                    eprintln!("{e}");
                    std::process::exit(1)
                }
            }
        }
        "check-deposit" => {
            // check-deposit <graph dir | final.json>: depositor/kit refusal rule. Exit 0 = OK to
            // broadcast the peg-in confirm; 2 = REFUSE; 1 = error. Before the bridge height
            // the rule is not enforced (exit 0, says so).
            let a = args.iter().filter(|x| !x.starts_with("--")).nth(2).cloned().unwrap_or_default();
            let p = PathBuf::from(&a);
            let p = if p.is_dir() { p.join("final.json") } else { p };
            let cfg = Config::load(&home);
            let res = std::fs::read(&p)
                .map_err(|e| format!("{}: {e}", p.display()))
                .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).map_err(|e| e.to_string()))
                .and_then(|f| falcon_status(&cfg).map(|st| (f, st)));
            match res {
                Err(e) => {
                    eprintln!("{e}");
                    std::process::exit(1)
                }
                Ok((_, st)) if !ledger::bridge_active(&st) => println!("bridge not active on this node: binding rule not enforced yet"),
                Ok((f, st)) => match ledger::check_deposit_graphs(&f, &st) {
                    Ok(n) => println!("OK: all {n} operator graphs bound on the ledger and matching"),
                    Err(e) => {
                        println!("REFUSE: {e}");
                        std::process::exit(2)
                    }
                },
            }
        }
        "init" => {
            ensure_dirs(&home);
            let p = home.join("operator.env");
            if !p.exists() {
                std::fs::write(&p, DEFAULT_ENV).unwrap();
            }
            if !home.join("peers.json").exists() {
                std::fs::write(home.join("peers.json"), "[]\n").unwrap();
            }
            println!("initialized {}", home.display());
        }
        "pubkey" => {
            let cfg = Config::load(&home);
            match read_secret(&cfg).and_then(|s| Signer_::from_secret_hex(&s)) {
                Ok(s) => println!("{}", s.xonly), // public x-only key only
                Err(e) => {
                    eprintln!("{e}");
                    std::process::exit(1)
                }
            }
        }
        "register" => {
            let cfg = Config::load(&home);
            let xonly = read_secret(&cfg).and_then(|s| Signer_::from_secret_hex(&s)).map(|s| s.xonly).unwrap_or_default();
            if cfg.falcon_account.is_empty() || xonly.is_empty() {
                eprintln!("set FPL_OP_FALCON_ACCOUNT in operator.env and make sure keys/operator.secret exists");
                std::process::exit(2);
            }
            let req = serde_json::json!({
                "type": "OperatorRegister", "account": cfg.falcon_account, "btc_xonly": xonly,
                "gossip_url": format!("http://<your-public-host>:{}", cfg.p2p_listen.rsplit(':').next().unwrap_or("19481")),
                "network": cfg.network, "payout_fee_bps": cfg.payout_fee_bps, "kit_version": VERSION,
                "note": "public data only; sign + submit with falcon-pl-ctl once operator registration is active on-chain (docs/bridge/OPERATOR_REWARDS.md). Until then share it with the other operators for peers.json.",
                "bond_fpl": 5000,
                "ledger_body": ledger::register_body(&xonly, &cfg.reward_spk_hex, &format!("http://<your-public-host>:{}", cfg.p2p_listen.rsplit(':').next().unwrap_or("19481")), 0),
                "submit": format!("{} --addr {} operator --account {} --amount 5000 --scheme {} --network-id {} --keys-dir <falcon keys dir> --body '<ledger_body>'", cfg.falcon_ctl, cfg.falcon_rpc, cfg.falcon_account, cfg.falcon_scheme, cfg.falcon_network_id),
            });
            let p = home.join("registration.json");
            std::fs::write(&p, serde_json::to_vec_pretty(&req).unwrap()).unwrap();
            println!("wrote {}", p.display());
        }
        "check" => {
            let cfg = Config::load(&home);
            let mut ok = true;
            let mut line = |name: &str, r: Result<String, String>| match r {
                Ok(s) => println!("ok    {name}: {s}"),
                Err(e) => {
                    ok = false;
                    println!("FAIL  {name}: {e}")
                }
            };
            line("btc wallet", wallet_sats(&cfg).map(|s| format!("{s} sats in '{}'", cfg.btc_wallet)));
            line("falcon node", falcon_ledger(&cfg).map(|(h, c)| format!("height {h}, {} BTC claims", c.len())));
            line("operator secret", read_secret(&cfg).and_then(|s| Signer_::from_secret_hex(&s)).map(|s| format!("present, 0600; public x-only {}", s.xonly)));
            line("fpl_pregen", if cfg.bin_dir.join("fpl_pregen").exists() { Ok("found".into()) } else { Err("missing".into()) });
            line("proof dir (FPL_PROOF_DIR)", cfg.proof().map(|p| match p { Some((d, s)) => format!("{} vk sha256 {}…{}", d.display(), &s[..8], &s[s.len()-4..]), None => "none (regtest mock VK)".into() }));
            if !cfg.attest_vk_hex.is_empty() { line("withdraw VK", cfg.check_withdraw_vk().map(|s| format!("sha256 {}…{}", &s[..8], &s[s.len()-4..]))); }
            line("pregen pool", Ok(format!("{} ready (target {})", pool_ready(&cfg), cfg.pregen_target)));
            line("deposit graphs", Ok(format!("{} indexed", deposits::index(&cfg.graphs()).len())));
            line("peers", Ok(format!("{} in peers.json", gossip::load_registry(&home.join("peers.json")).len())));
            line("mode", Ok(format!("{} on {}", cfg.mode, cfg.network)));
            std::process::exit(if ok { 0 } else { 1 });
        }
        "status" => {
            let cfg = Config::load(&home);
            let st = State::load(&home.join("state.json"));
            println!("{}", serde_json::to_string_pretty(&serde_json::json!({"network": cfg.network, "mode": cfg.mode, "halted": st.halted, "halt_reason": st.halt_reason, "pregen_ready": pool_ready(&cfg), "claims": st.claims, "disagreements": st.disagreements})).unwrap());
        }
        "sign-record" => {
            // Sign a record (JSON on stdin: kind, note_id, binding, data) with the local key and
            // print it (public, signed). For manual reports / tests; never prints the key.
            let cfg = Config::load(&home);
            let signer = read_secret(&cfg).and_then(|s| Signer_::from_secret_hex(&s)).unwrap_or_else(|e| { eprintln!("{e}"); std::process::exit(1) });
            let mut inp = String::new();
            std::io::stdin().read_to_string(&mut inp).unwrap();
            let mut r: Record = serde_json::from_str(&inp).unwrap_or_else(|e| { eprintln!("record json: {e}"); std::process::exit(1) });
            r.ts = now();
            println!("{}", serde_json::to_string(&signer.sign(r)).unwrap());
        }
        "run" => run(home),
        _ => println!("fpl-operatord {VERSION}\nusage: fpl-operatord <init|pubkey|register|check|status|sign-record|payout-spk|run> [--home DIR]"),
    }
}

fn run(home: PathBuf) {
    ensure_dirs(&home);
    let cfg = Config::load(&home);
    if cfg.network == "mainnet" && cfg.live() {
        eprintln!("mainnet live mode is disabled until the bridge activates");
        std::process::exit(2);
    }
    let signer = match read_secret(&cfg).and_then(|s| Signer_::from_secret_hex(&s)) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("operator key: {e}");
            std::process::exit(2)
        }
    };
    let registry = gossip::load_registry(&home.join("peers.json"));
    let store = Store::open(&home.join("records.jsonl"));
    log(&format!("v{VERSION} {} ({}): network={} mode={} peers={} replayed_records={}", cfg.name, signer.xonly, cfg.network, cfg.mode, registry.len(), store.records.len()));
    let node = Arc::new(Node {
        health: Mutex::new(Health { version: VERSION.into(), name: cfg.name.clone(), network: cfg.network.clone(), mode: cfg.mode.clone(), operator_xonly: signer.xonly.clone(), started: now(), pregen_target: cfg.pregen_target, ..Default::default() }),
        cfg,
        signer,
        registry,
        store: Mutex::new(store),
    });
    let resume = Arc::new(Mutex::new(false));
    serve_local(node.clone(), resume.clone());
    serve_p2p(node.clone());
    let sp = home.join("state.json");
    let mut st = State::load(&sp);
    let mut pregen: Option<std::process::Child> = None;
    // retire pool entries built for another VK at startup too (a full pool never spawns pregen)
    match node.cfg.proof() {
        Ok(p) => {
            let tag = p.map(|p| p.1).unwrap_or_else(|| "mock-regtest".into());
            match prover::retag_pool(&node.cfg.pool(), &tag) {
                Ok(n) if n > 0 => log(&format!("pregen: retired {n} pool entries built for another VK")),
                Ok(_) => {}
                Err(e) => log(&format!("pregen: pool retag failed: {e}")),
            }
        }
        Err(e) => log(&format!("pregen: refusing: {e}")),
    }
    loop {
        let cfg = &node.cfg;
        if std::mem::take(&mut *resume.lock().unwrap()) {
            log("halt cleared by operator");
            st.halted = false;
            st.halt_reason.clear();
            for c in st.claims.values_mut().filter(|c| c.phase == "halted") {
                c.phase = "seen".into();
            }
        }
        if let Some(ch) = pregen.as_mut() {
            if let Ok(Some(s)) = ch.try_wait() {
                log(&format!("pregen finished: {s}"));
                pregen = None;
            }
        }
        if pregen.is_none() && pool_ready(cfg) < cfg.pregen_target && cfg.bin_dir.join("fpl_pregen").exists() {
            if let Ok(c) = spawn_pregen(cfg) {
                pregen = Some(c);
            }
        }
        let mut h = node.health.lock().unwrap().clone();
        h.last_poll = now();
        match wallet_sats(cfg) {
            Ok(s) => {
                h.btc_ok = true;
                h.btc_wallet_sats = s;
            }
            Err(e) => {
                h.btc_ok = false;
                h.last_error = format!("btc: {e}");
            }
        }
        node.pull_peers(&mut st);
        let cap = available_capacity(cfg, h.btc_wallet_sats, &st);
        h.available_sats = cap;
        if now() >= st.last_heartbeat + cfg.heartbeat_secs {
            node.emit("Heartbeat", "", "", &[("pregen_ready", pool_ready(cfg).to_string()), ("version", VERSION.into()), ("available_sats", cap.to_string())]);
            st.last_heartbeat = now();
            st.last_capacity = Some(cap);
        } else if h.btc_ok && st.last_capacity != Some(cap) {
            node.emit("Balance", "", "", &[("available_sats", cap.to_string())]);
            st.last_capacity = Some(cap);
        }
        match falcon_status(cfg).map(|v| { ledger_duties(&node, &mut st, &v, cap); let p = parse_ledger(&v); (p, v) }) {
            Ok(((height, ledger), status)) => {
                h.falcon_ok = true;
                h.falcon_height = height;
                h.open_claims_seen = ledger.iter().filter(|c| c.status == "AwaitingPegout").count() as u64;
                operate(&node, &mut st, &ledger, &mut h, &status, height);
                watch(&node, &mut st, &ledger);
                h.ledger = ledger;
            }
            Err(e) => {
                h.falcon_ok = false;
                h.last_error = format!("falcon: {e}");
            }
        }
        h.pregen_ready = pool_ready(cfg);
        h.pregen_running = pregen.is_some();
        h.registered_peers = node.registry.len() as u64;
        h.quorum = node.quorum() as u64;
        h.halted = st.halted;
        h.halt_reason = st.halt_reason.clone();
        h.claims = st.claims.values().rev().take(50).cloned().collect();
        h.disagreements = st.disagreements.iter().rev().take(50).cloned().collect();
        *node.health.lock().unwrap() = h;
        st.save(&sp);
        std::thread::sleep(Duration::from_secs(cfg.poll_secs.max(5)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_btc_ledger_claims() {
        let v = serde_json::json!({"height": 7, "rails": [
            {"asset": "ETH", "bitvm2_claims": [{"note_id":"e","dest":"x","amount":1,"status":"AwaitingPegout"}]},
            {"asset": "BTC", "bitvm2_claims": [
                {"note_id":"a","dest":"tb1qa","amount":5000,"open_height":3,"status":"AwaitingPegout"},
                {"note_id":"b","dest":"tb1qb","amount":9,"status":"PaidOptimistic","operator":"op"}]}]});
        let (h, c) = parse_ledger(&v);
        assert_eq!(h, 7);
        assert_eq!(c.len(), 2);
        assert_eq!(c[0].open_height, 3);
        assert_eq!(c[1].operator, "op");
    }
    #[test]
    fn attest_due_only_for_mined_pegouts_awaiting_attest() {
        let l = |n: &str, st: &str| LedgerClaim { note_id: n.into(), status: st.into(), ..Default::default() };
        let ledger = vec![l("a", "AwaitingPegout"), l("b", "ClaimPosted"), l("c", "PegoutPosted"), l("d", "AwaitingPegout")];
        let mut ours = BTreeMap::new();
        ours.insert("a".to_string(), ("11".repeat(32), "k1".to_string()));
        ours.insert("b".to_string(), ("22".repeat(32), "k1".to_string()));
        ours.insert("c".to_string(), ("33".repeat(32), "k1".to_string()));
        ours.insert("d".to_string(), (String::new(), "k1".to_string())); // no PEG_OUT yet
        let due: Vec<String> = attest_due(&ledger, &ours).into_iter().map(|x| x.0).collect();
        assert_eq!(due, vec!["a".to_string(), "c".to_string()]);
    }

    #[test]
    fn fee_deduction() {
        let mut cfg = Config::load(Path::new("/nonexistent"));
        cfg.payout_fee_bps = 30;
        assert_eq!(fronted_amount(&cfg, 100_000), 99_700);
        // PEG_OUT fee is paid on top of the exact amount, at >= 2 sat/vB
        assert_eq!(pegout_fee_sats(0), 244);
        assert_eq!(pegout_fee_sats(1), 244);
        assert_eq!(pegout_fee_sats(5), 610);
        assert_eq!(payout_funding_sats(50_000, 2), 50_244);
    }
}

#[cfg(test)]
mod parse_ledger_body_tests {
    #[test]
    fn reads_height_and_claims_inside_body() {
        let v = serde_json::json!({"type":"status","body":{"tip_height":625273,"rails":[{"asset":"BTC","bitvm2_claims":[{"note_id":"n1","amount":5,"status":"AwaitingPegout"}]}]}});
        let (h, c) = super::parse_ledger(&v);
        assert_eq!(h, 625273);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].note_id, "n1");
        let (h2, _) = super::parse_ledger(&serde_json::json!({"height": 7}));
        assert_eq!(h2, 7);
    }

    #[test]
    fn btc4_rail_preferred_and_snake_status_normalized() {
        assert_eq!(crate::camel_status("awaiting_pegout"), "AwaitingPegout");
        assert_eq!(crate::camel_status("PegoutPosted"), "PegoutPosted");
        assert_eq!(crate::camel_status("claim_posted"), "ClaimPosted");
        let v = serde_json::json!({"type":"status","body":{"tip_height":730_100,"rails":[
            {"asset":"BTC","bitvm2_claims":[{"note_id":"legacy","dest":"tb1qa","amount":5,"status":"awaiting_pegout"}]},
            {"asset":"BTC4","tip_height":157_300,"spent_deposits":["AB"],"bitvm2_claims":[{"note_id":"n4","dest":"tb1qb","amount":7,"open_height":730_050,"status":"awaiting_pegout"}]}]}});
        let (h, c) = crate::parse_ledger(&v);
        assert_eq!(h, 730_100);
        assert_eq!(c.len(), 1, "legacy testnet3 claims are not served once BTC4 exists");
        assert_eq!((c[0].note_id.as_str(), c[0].status.as_str()), ("n4", "AwaitingPegout"));
        assert_eq!(crate::ledger::btc4_rail(&v), Some((157_300, vec!["ab".to_string()])));
        assert_eq!(crate::ledger::account_sequence("x {\"type\":\"account\",\"body\":{\"sequence\":42,\"recent_txs\":[{\"sequence\":3}]}}"), Some(42));
    }
}

#[cfg(test)]
mod tx_lookup_tests {
    use super::*;
    const NF: &str = "bitcoin-cli exit exit status: 5: error code: -5\nerror message:\nNo such mempool or blockchain transaction. Use gettransaction for wallet transactions.";
    fn outs() -> (Vec<(u64, String)>, u64) { (vec![(49984, "0020ab".into())], 3) }

    #[test]
    fn rpc_found() {
        assert_eq!(resolve_tx_lookup(Ok(outs()), || panic!("no index check"), || panic!("no esplora")), TxLookup::Found(outs().0, 3));
    }
    #[test]
    fn genuine_minus5_with_synced_index_is_not_found() {
        assert!(is_rpc_tx_not_found(NF));
        assert_eq!(resolve_tx_lookup(Err(NF.into()), || true, || panic!("no esplora")), TxLookup::NotFound);
    }
    #[test]
    fn minus5_with_unsynced_index_falls_back_to_esplora() {
        assert_eq!(resolve_tx_lookup(Err(NF.into()), || false, || Ok(outs())), TxLookup::Found(outs().0, 3));
        assert!(matches!(resolve_tx_lookup(Err(NF.into()), || false, || Err("404".into())), TxLookup::Unavailable(_)));
    }
    #[test]
    fn bitcoind_down_uses_esplora_then_unavailable() {
        // 28 Oct 2026 falcon2 case: bitcoind crash-looping on a corrupt txindex
        let down = "bitcoin-cli exit exit status: 1: error: Could not connect to the server 127.0.0.1:48342";
        assert!(!is_rpc_tx_not_found(down));
        assert_eq!(resolve_tx_lookup(Err(down.into()), || panic!("must not trust index"), || Ok(outs())), TxLookup::Found(outs().0, 3));
        assert!(matches!(resolve_tx_lookup(Err(down.into()), || true, || Err("timeout".into())), TxLookup::Unavailable(_)));
        let warm = "error code: -28\nerror message:\nLoading block index...";
        assert!(matches!(resolve_tx_lookup(Err(warm.into()), || true, || Err("x".into())), TxLookup::Unavailable(_)));
    }
    #[test]
    fn esplora_parse() {
        let b = r#"{"txid":"eb18","vout":[{"value":49984,"scriptpubkey":"00205BB4"}],"status":{"confirmed":true,"block_height":157566}}"#;
        assert_eq!(parse_esplora_tx(b).unwrap(), (vec![(49984, "00205bb4".to_string())], 1));
        assert!(parse_esplora_tx("Transaction not found").is_err());
    }
}

#[cfg(test)]
mod front_guard_tests {
    use super::front_blocked;

    #[test]
    fn blocks_without_attest_unless_overridden() {
        assert!(front_blocked(Ok(()), false).is_none());
        assert!(front_blocked(Err("x".into()), true).is_none());
        let why = front_blocked(Err("no zkey".into()), false).unwrap();
        assert!(why.contains("double payout") && why.contains("no zkey"));
    }
}
