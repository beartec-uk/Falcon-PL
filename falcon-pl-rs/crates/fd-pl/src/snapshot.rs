// Copyright (c) 2025-2026 BEARTEC. All rights reserved. See LICENSE.
//! JSON snapshot persistence for private fleet restarts (v2.2.x).
//!
//! ## Reliability (v2.2.1 / snapshot schema 2)
//!
//! Snapshots store **tip world state** plus the **in-memory chain tail**
//! (already pruned by `max_chain_ledgers`). On load the tail is restored so:
//! - peers can serve residual `NeedLedgers` after a restart
//! - `last_pack_*` / tip continuity stay available without replaying genesis
//! - a fleet that restarts together still has overlapping history to re-sync
//!
//! Pre-v2.2.1 snapshots omit `chain` (serde default empty) and still load tip
//! state; residual catch-up then depends on peers that retained history.

use crate::accounts::AccountMeta;
use crate::names::NameRegistry;
use crate::bridge::BridgeState;
use crate::crypto::{CryptoScheme, KeyRing};
use crate::defi::DefiState;
use crate::economy::{EpochWork, TREASURY_GENESIS};
use crate::economy::{MIN_BOND, UNBOND_COOLDOWN_MS};
use crate::metrics::{NodeMetrics, DEFAULT_MIN_FEE};
use crate::{
    AccountState, ChainConfig, Ledger, LedgerCert, Node, SlashEvidence, ValidatorInfo, WorldState,
};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;

/// Snapshot file schema. Bumped when fields are added that change load semantics.
/// v1 = tip state only (chain wiped on load). v2 = tip state + chain tail.
pub const SNAPSHOT_VERSION: u32 = 2;

#[derive(Debug, Serialize, Deserialize)]
pub struct NodeSnapshot {
    pub version: u32,
    pub id: String,
    pub cfg: ChainConfigSnap,
    pub state: WorldState,
    pub tip_hash: String,
    pub tip_height: u64,
    pub validators: BTreeMap<String, ValidatorInfo>,
    pub rewards: BTreeMap<String, u64>,
    pub now_ms: u64,
    pub genesis_ms: u64,
    pub treasury: u64,
    pub epoch_work: EpochWork,
    pub last_settled_epoch: u64,
    pub claimable: BTreeMap<String, u64>,
    pub defi: DefiState,
    pub bridge: BridgeState,
    #[serde(default)]
    pub metrics: NodeMetrics,
    pub height_open_ms: u64,
    /// scheme string for keyring reload path
    pub scheme: String,
    /// Recent sealed ledgers (tail), continuous up to tip when present.
    /// Empty on pre-v2 snapshots — load still restores tip state only.
    #[serde(default)]
    pub chain: Vec<Ledger>,
    /// True genesis balances (not tip state). Required for hard-resync after fork.
    /// Pre-v2.2.2 snaps omit this; load leaves hard-resync disabled until restart
    /// from true genesis or a new snap that includes it.
    #[serde(default)]
    pub genesis_accounts: Vec<(String, u64)>,
    /// Seed validator bonds at tip=0. Live bond-ins must not be listed here.
    /// Empty on pre-v2.2.5 snaps — process start backfills from CLI `--validators`.
    #[serde(default)]
    pub genesis_validators: BTreeMap<String, u64>,
    /// Certified online epoch (v2.4.0). Empty members = bootstrap all bonded.
    #[serde(default)]
    pub online_epoch_id: u64,
    #[serde(default)]
    pub online_members: Vec<String>,
    #[serde(default)]
    pub online_hash: String,
    /// Tip 4-of-6 certs (v2.9.0). Empty on older snaps — rebuilt from chain parent_cert.
    #[serde(default)]
    pub names: NameRegistry,
    #[serde(default)]
    pub certs: BTreeMap<u64, LedgerCert>,
    /// Queued equivocation evidence for **committed** heights (h ≤ tip).
    /// Uncommitted (h > tip) is dropped on load — the pending body is not restored.
    #[serde(default)]
    pub pending_slashes: Vec<SlashEvidence>,
    /// OK map for committed heights. Open-height (h > tip) votes are attempt-local
    /// and stripped on load (v2.9.7).
    #[serde(default)]
    pub ok_by_height_voter: HashMap<u64, HashMap<String, String>>,
    /// Matching OK signatures (feeds SlashEvidence.sig_a after reload).
    #[serde(default)]
    pub ok_sigs: HashMap<String, HashMap<String, String>>,
    /// v2.10.0 round-scoped votes for the **open** height (h > tip) only:
    /// the restarted seat keeps its own lock and the round's dead-proof, so
    /// it never signs a second hash in one (height, round). Empty on legacy.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub round_votes: BTreeMap<u64, BTreeMap<u64, BTreeMap<String, (String, String)>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainConfigSnap {
    pub network_id: u32,
    pub max_txs_per_ledger: usize,
    pub pack_budget_ms: u64,
    pub pong_window_ms: u64,
    pub confirm_depth: u64,
    pub slash_equivocation: u64,
    pub scheme: String,
    pub soft_ok_votes: usize,
    pub hard_ok_ratio: f64,
    pub progress_timeout_ms: u64,
    pub max_mempool_txs: usize,
    pub max_chain_ledgers: usize,
    pub epoch_ms: u64,
    pub emission_bps: u64,
    pub min_bond: u64,
    #[serde(default = "default_min_fee")]
    pub min_fee: u64,
    #[serde(default = "default_true")]
    pub fee_escalate: bool,
    #[serde(default = "default_unbond_cd")]
    pub unbond_cooldown_ms: u64,
    /// Heights per certified online epoch (v2.4.0). 0 = disabled.
    #[serde(default = "default_online_epoch_heights")]
    pub online_epoch_heights: u64,
    #[serde(default)]
    pub archive: bool,
    /// 0 on old snaps → sanitize to 1; we still default new configs to 8.
    #[serde(default)]
    pub first_claim_epoch: u64,
}

fn default_online_epoch_heights() -> u64 {
    25
}

fn default_min_fee() -> u64 {
    DEFAULT_MIN_FEE
}
fn default_true() -> bool {
    true
}
fn default_unbond_cd() -> u64 {
    UNBOND_COOLDOWN_MS
}

impl From<&ChainConfig> for ChainConfigSnap {
    fn from(c: &ChainConfig) -> Self {
        Self {
            network_id: c.network_id,
            max_txs_per_ledger: c.max_txs_per_ledger,
            pack_budget_ms: c.pack_budget_ms,
            pong_window_ms: c.pong_window_ms,
            confirm_depth: c.confirm_depth,
            slash_equivocation: c.slash_equivocation,
            scheme: c.scheme.as_str().to_string(),
            soft_ok_votes: c.soft_ok_votes,
            hard_ok_ratio: c.hard_ok_ratio,
            progress_timeout_ms: c.progress_timeout_ms,
            max_mempool_txs: c.max_mempool_txs,
            max_chain_ledgers: c.max_chain_ledgers,
            epoch_ms: c.epoch_ms,
            emission_bps: c.emission_bps,
            min_bond: c.min_bond,
            min_fee: c.min_fee,
            fee_escalate: c.fee_escalate,
            unbond_cooldown_ms: c.unbond_cooldown_ms,
            online_epoch_heights: c.online_epoch_heights,
            archive: c.archive,
            first_claim_epoch: c.first_claim_epoch,
        }
    }
}

impl ChainConfigSnap {
    pub fn into_config(self) -> Result<ChainConfig> {
        let scheme = CryptoScheme::parse(&self.scheme)
            .ok_or_else(|| anyhow::anyhow!("unknown scheme {}", self.scheme))?;
        Ok(ChainConfig {
            network_id: self.network_id,
            max_txs_per_ledger: self.max_txs_per_ledger,
            pack_budget_ms: self.pack_budget_ms,
            pong_window_ms: self.pong_window_ms,
            confirm_depth: self.confirm_depth,
            slash_equivocation: self.slash_equivocation,
            scheme,
            soft_ok_votes: self.soft_ok_votes,
            hard_ok_ratio: self.hard_ok_ratio,
            progress_timeout_ms: self.progress_timeout_ms,
            max_mempool_txs: self.max_mempool_txs,
            max_chain_ledgers: self.max_chain_ledgers,
            epoch_ms: self.epoch_ms,
            emission_bps: self.emission_bps,
            min_bond: self.min_bond,
            min_fee: self.min_fee,
            fee_escalate: self.fee_escalate,
            unbond_cooldown_ms: self.unbond_cooldown_ms,
            online_epoch_heights: self.online_epoch_heights,
            archive: self.archive,
            first_claim_epoch: self.first_claim_epoch,
            ..Default::default()
        })
    }
}

/// Keep only a continuous suffix ending at `tip_height` with matching tip hash.
/// Drops corrupt / divergent tails instead of loading a fork into RAM.
fn sanitize_chain_tail(chain: Vec<Ledger>, tip_height: u64, tip_hash: &str) -> Vec<Ledger> {
    if chain.is_empty() {
        return chain;
    }
    // Require last ledger to match snap tip.
    let Some(last) = chain.last() else {
        return Vec::new();
    };
    if last.height != tip_height || last.ledger_hash != tip_hash {
        return Vec::new();
    }
    // Walk backwards for continuous parent links; keep longest valid suffix.
    let mut ok_from = chain.len() - 1;
    for i in (1..chain.len()).rev() {
        let cur = &chain[i];
        let prev = &chain[i - 1];
        if cur.height != prev.height + 1 {
            break;
        }
        if cur.parent_hash != prev.ledger_hash {
            break;
        }
        ok_from = i - 1;
    }
    // Also require the first kept height is not above tip (sanity).
    chain[ok_from..].to_vec()
}

fn rebuild_seen_from_chain(chain: &[Ledger]) -> HashMap<u64, (String, String)> {
    let mut seen = HashMap::with_capacity(chain.len());
    for led in chain {
        seen.insert(led.height, (led.packer.clone(), led.ledger_hash.clone()));
    }
    seen
}

impl Node {
    /// Local key-ring sidecar next to a snapshot: `<stem>.ring.json`.
    ///
    /// The key ring is node-local and was rebuilt only from txs seen since
    /// start, so a restart dropped every public key that was bound before the
    /// key-bind gate (2.9.65) but never recorded on the account
    /// (`meta.public_key`). On 2300 that left `watcher-eth` unable to sign
    /// after the 2.9.74 roll: every packer refused its txs with
    /// `KEY_BIND_REFUSED`, while v1 (key in its keys dir) still admitted them.
    /// The sidecar is written by this seat and read back only by this seat.
    /// It is not part of the snapshot, the join snapshot, or anything served
    /// to peers, and it is not consensus state.
    pub fn ring_sidecar_path(snapshot: impl AsRef<Path>) -> std::path::PathBuf {
        let p = snapshot.as_ref();
        let stem = p.file_stem().unwrap_or_default().to_string_lossy();
        p.with_file_name(format!("{stem}.ring.json"))
    }

    /// Write `publics` (id -> public hex) atomically (tmp + rename).
    pub fn write_ring_publics(
        path: impl AsRef<Path>,
        scheme: CryptoScheme,
        publics: &BTreeMap<String, String>,
    ) -> Result<usize> {
        let path = path.as_ref();
        let body = serde_json::json!({ "scheme": scheme.as_str(), "publics": publics });
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec(&body)?).context("write ring sidecar")?;
        std::fs::rename(&tmp, path).context("rename ring sidecar")?;
        Ok(publics.len())
    }

    pub fn save_ring_publics(&self, path: impl AsRef<Path>) -> Result<usize> {
        Self::write_ring_publics(path, self.keys.scheme, &self.keys.export_publics())
    }

    /// Merge a sidecar back into the ring after a restart. Returns the number
    /// of keys added. Never replaces a key already in the ring, never adds a
    /// key that contradicts the account's on-chain key, and ignores a sidecar
    /// written under another scheme. A missing or unreadable file adds nothing.
    pub fn merge_ring_publics(&mut self, path: impl AsRef<Path>) -> usize {
        let Ok(raw) = std::fs::read(path.as_ref()) else {
            return 0;
        };
        let Ok(v) = serde_json::from_slice::<serde_json::Value>(&raw) else {
            return 0;
        };
        if v.get("scheme").and_then(|s| s.as_str()) != Some(self.keys.scheme.as_str()) {
            return 0;
        }
        let Some(map) = v.get("publics").and_then(|m| m.as_object()) else {
            return 0;
        };
        let mut added = 0;
        for (id, pk) in map {
            let Some(pk) = pk.as_str() else { continue };
            if self.keys.has_public(id) {
                continue;
            }
            if let Some(bound) = self.account_public_key(id) {
                if !crate::crypto::hex_eq(&bound, pk) {
                    continue;
                }
            }
            if self.keys.insert_public(id, pk).is_ok() {
                added += 1;
            }
        }
        added
    }

    pub fn to_snapshot(&self) -> NodeSnapshot {
        // Persist the in-RAM tail (already pruned). Cap again as a hard guard.
        let mut chain = self.chain.clone();
        let max = self.cfg.max_chain_ledgers;
        if max > 0 && chain.len() > max {
            let drop_n = chain.len() - max;
            chain.drain(0..drop_n);
        }
        NodeSnapshot {
            version: SNAPSHOT_VERSION,
            id: self.id.clone(),
            cfg: ChainConfigSnap::from(&self.cfg),
            state: self.state.clone(),
            tip_hash: self.tip_hash.clone(),
            tip_height: self.tip_height,
            validators: self.validators.clone(),
            rewards: self.rewards.clone(),
            now_ms: self.now_ms,
            genesis_ms: self.genesis_ms,
            treasury: self.treasury,
            epoch_work: self.epoch_work.clone(),
            last_settled_epoch: self.last_settled_epoch,
            claimable: self.claimable.clone(),
            defi: self.defi.clone(),
            bridge: self.bridge.clone(),
            metrics: self.metrics.clone(),
            height_open_ms: self.height_open_ms,
            scheme: self.cfg.scheme.as_str().to_string(),
            chain,
            genesis_accounts: self.genesis_accounts.clone(),
            genesis_validators: self.genesis_validators.clone(),
            online_epoch_id: self.online_epoch_id,
            online_members: self.online_members.iter().cloned().collect(),
            online_hash: self.online_hash.clone(),
            names: self.names.clone(),
            certs: self.certs.clone(),
            pending_slashes: self.pending_slashes.clone(),
            ok_by_height_voter: self.ok_by_height_voter.clone(),
            ok_sigs: self.ok_sigs.clone(),
            round_votes: self
                .round_votes
                .iter()
                .filter(|(h, _)| **h > self.tip_height)
                .map(|(h, m)| (*h, m.clone()))
                .collect(),
        }
    }

    pub fn save_snapshot(&self, path: impl AsRef<Path>) -> Result<()> {
        Self::write_snapshot_file(path, &self.to_snapshot(), None).map(|_| ())
    }

    /// Tip state + short chain tail for joiners (v2.9.23).
    /// The 20k RAM tail is a 160 MB JSON (Falcon certs). A joiner does not
    /// need it — they adopt tip state and residual-pull `tip+1`.
    pub const JOIN_CHAIN_LEDGERS: usize = 128;

    pub fn to_join_snapshot(&self) -> NodeSnapshot {
        Self::trim_to_join(self.to_snapshot())
    }

    /// Turn a full [`to_snapshot`](Self::to_snapshot) into the join snapshot
    /// in place (v2.9.58: the periodic saver captures one snapshot under the
    /// lock and derives the join copy after writing it, instead of holding
    /// two deep clones at once).
    pub fn trim_to_join(mut snap: NodeSnapshot) -> NodeSnapshot {
        let keep = Self::JOIN_CHAIN_LEDGERS.max(1);
        if snap.chain.len() > keep {
            let drop_n = snap.chain.len() - keep;
            snap.chain.drain(0..drop_n);
        }
        let min_h = snap.tip_height.saturating_sub(keep as u64);
        snap.certs.retain(|h, _| *h >= min_h);
        snap.ok_by_height_voter.retain(|h, _| *h >= min_h);
        snap.ok_sigs.clear();
        snap
    }

    pub fn save_join_snapshot(&self, path: impl AsRef<Path>) -> Result<()> {
        Self::write_snapshot_file(path, &self.to_join_snapshot(), None).map(|_| ())
    }

    /// [`save_snapshot`](Self::save_snapshot) behind a disk check (v2.9.53).
    /// `check(stat, bytes)` sees the serialized size before anything touches
    /// disk; `Err` refuses the write (nothing is created). Returns bytes written.
    pub fn save_snapshot_checked(
        &self,
        path: impl AsRef<Path>,
        check: &dyn Fn(Option<&crate::disk::DiskStat>, u64) -> std::result::Result<(), String>,
    ) -> Result<u64> {
        Self::write_snapshot_file(path, &self.to_snapshot(), Some(check))
    }

    /// Join-snapshot variant of [`save_snapshot_checked`](Self::save_snapshot_checked).
    pub fn save_join_snapshot_checked(
        &self,
        path: impl AsRef<Path>,
        check: &dyn Fn(Option<&crate::disk::DiskStat>, u64) -> std::result::Result<(), String>,
    ) -> Result<u64> {
        Self::write_snapshot_file(path, &self.to_join_snapshot(), Some(check))
    }

    /// v2.9.58: write a snapshot captured earlier (e.g. under `node.lock`)
    /// without holding the node. Same bytes and checks as
    /// [`save_snapshot_checked`](Self::save_snapshot_checked).
    pub fn write_snapshot_checked(
        path: impl AsRef<Path>,
        snap: &NodeSnapshot,
        check: &dyn Fn(Option<&crate::disk::DiskStat>, u64) -> std::result::Result<(), String>,
    ) -> Result<u64> {
        Self::write_snapshot_file(path, snap, Some(check))
    }

    fn write_snapshot_file(
        path: impl AsRef<Path>,
        snap: &NodeSnapshot,
        check: Option<&dyn Fn(Option<&crate::disk::DiskStat>, u64) -> std::result::Result<(), String>>,
    ) -> Result<u64> {
        // v2.9.58: same bytes as `serde_json::to_vec(snap)`; the ~200 MB exec
        // header map JSON is reused from its per-generation cache.
        let bytes = crate::exec_map::to_vec_split(snap).context("serialize snapshot")?;
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        if let Some(check) = check {
            let st = crate::disk::stat(path);
            if let Err(e) = check(st.as_ref(), bytes.len() as u64) {
                anyhow::bail!("{e}");
            }
        }
        let tmp = path.with_extension("json.tmp");
        if let Err(e) = std::fs::write(&tmp, &bytes) {
            // ENOSPC used to leave a partial (or 0-byte) `.json.tmp` behind
            // on every attempt (host2, 2026-10-07). Never keep it.
            let _ = std::fs::remove_file(&tmp);
            return Err(anyhow::Error::new(e).context("write snapshot tmp"));
        }
        if let Err(e) = std::fs::rename(&tmp, path) {
            let _ = std::fs::remove_file(&tmp);
            return Err(anyhow::Error::new(e).context("rename snapshot into place"));
        }
        Ok(bytes.len() as u64)
    }

    /// Load snapshot over existing keyring (keys stay on disk separately).
    pub fn load_snapshot(path: impl AsRef<Path>, keys: KeyRing) -> Result<Self> {
        let s = std::fs::read_to_string(path.as_ref()).context("read snapshot")?;
        let snap: NodeSnapshot = serde_json::from_str(&s).context("parse snapshot")?;
        let cfg = snap.cfg.into_config()?;
        // CRITICAL: never treat tip-state balances as genesis. Doing so made
        // hard_resync rebuild from wrong balances → perpetual state-root fails
        // → NeedLedgers(from=1) storms (multi-GB logs / 10GB+ RSS in minutes).
        let genesis_accounts = snap.genesis_accounts;
        let chain = sanitize_chain_tail(snap.chain, snap.tip_height, &snap.tip_hash);
        let seen_at_height = rebuild_seen_from_chain(&chain);
        // v2.9.60 / v2.9.61: runtime network constants (not in the snapshot file).
        let eth_lc_gloas_from_height = crate::network_eth_lc_gloas_from_height(cfg.network_id);
        let eth_v3_from_height = crate::network_eth_v3_from_height(cfg.network_id);
        let bitvm2_m1_from_height = crate::params_v2::bitvm2_m1_from_height(cfg.network_id);
        let bitvm2_vk = crate::bitvm2_exit::withdraw_vk_for_network(cfg.network_id);
        let ring_restore_from_height = crate::params_v2::ring_restore_from_height(cfg.network_id);
        let claim_enroll_from_height = crate::params_v2::claim_enroll_from_height(cfg.network_id);
        let seat_payout_from_height = crate::params_v2::seat_payout_from_height(cfg.network_id);
        let external_addrs_from_height = crate::params_v2::external_addrs_from_height(cfg.network_id);
        let empty_block_from_height = crate::params_v2::empty_block_from_height(cfg.network_id);
        let btc4_fork_fix_from_height = crate::params_v2::btc4_fork_fix_from_height(cfg.network_id);
        let btc4_lend_scale_from_height = crate::params_v2::btc4_lend_scale_from_height(cfg.network_id);
        let orderbook_from_height = crate::params_v2::orderbook_from_height(cfg.network_id);
        let hello_min_release_from_height = crate::params_v2::hello_min_release_from_height(cfg.network_id);
        let network_id_for_utc_hello = cfg.network_id;
        let rewards_v2_from_height = crate::params_v2::network_rewards_v2_from_height(cfg.network_id);
        let rewards_v2_epoch = crate::params_v2::network_rewards_v2_epoch(cfg.network_id);
        let presence_from_height = crate::params_v2::network_presence_from_height(cfg.network_id);
        let catchup_miss_from_height =
            crate::params_v2::network_catchup_miss_from_height(cfg.network_id);
        let seat_key_registry = crate::params_v2::network_seat_keys(cfg.network_id);
        // Set-but-malformed env fails the load (and so startup) instead of
        // silently leaving the seat without a V3 address.
        let eth_v3_bridge = crate::evm_spv::sepolia_qc_v3_bridge_addr()
            .map_err(|e| anyhow::anyhow!("refusing to load snapshot: {e} (fix or unset it)"))?;
        let mut n = Node {
            id: snap.id,
            cfg,
            keys,
            state: snap.state,
            mempool: Default::default(),
            body_shells: HashMap::new(),
            body_fill: HashMap::new(),
            chain,
            tip_hash: snap.tip_hash,
            tip_height: snap.tip_height,
            validators: snap.validators,
            rewards: snap.rewards,
            now_ms: snap.now_ms,
            seen_at_height,
            skips: HashMap::new(),
            skip_votes: HashMap::new(),
            ok_votes: HashMap::new(),
            soft_ok: BTreeSet::new(),
            hard_ok: BTreeSet::new(),
            pending_proposal: None,
            sig_warm: std::collections::BTreeSet::new(),
            pipeline_for: String::new(),
            height_open_ms: snap.height_open_ms,
            genesis_ms: snap.genesis_ms,
            treasury: snap.treasury,
            epoch_work: snap.epoch_work,
            last_settled_epoch: snap.last_settled_epoch,
            claimable: snap.claimable,
            names: snap.names,
            defi: snap.defi,
            bridge: {
                let mut b = snap.bridge;
                b.ensure_genesis();
                b
            },
            metrics: snap.metrics,
            pending_ledgers: BTreeMap::new(),
            skip_grace_until_ms: 0,
            // v2.9.56: local sanitize memo is never snapshotted.
            perm_head_memo: BTreeSet::new(),
            perm_head_memo_tip: String::new(),
            perm_head_memo_since_ms: 0,
            perm_head_dry_runs: 0,
            perm_dropped: crate::PermDropSet::default(),
            last_apply_fail_tx: None,
            recert_assist_h: 0,
            recert_assist_ms: 0,
            recert_assist_peers: BTreeSet::new(),
            tip_cert_votes: std::collections::BTreeMap::new(),
            tip_cert_votes_h: 0,
            tip_roots: None,
            future_oks: Vec::new(),
            pace_min_interval_ms: 0,
            pace_mempool_txs: Node::PACE_DEFAULT_MEMPOOL_TXS,
            prestaged_hash: String::new(),
            prestage_count: 0,
            last_catchup_req_ms: 0,
            catchup_inflight: false,
            empty_residual_streak: 0,
            stale_snap_offer_ms: 0,
            bridge_cfg_startup: None,
            catchup_hub_rotate: 0,
            catchup_snap_peer: String::new(),
            last_snap_req_ms: 0,
            started_ms: 0,
            best_peer_tip: 0,
            best_peer_tip_hash: String::new(),
            last_catchup_conflict: String::new(),
            genesis_accounts,
            genesis_bond: MIN_BOND,
            genesis_validators: snap.genesis_validators,
            need_hard_resync: false,
            hard_resync_operator: false,
            hard_resync_fail_streak: 0,
            is_hub: false,
            last_need_txs_ms: 0,
            need_txs_for_height: 0,
            need_txs_open_ms: 0,
            need_txs_pulls_open: 0,
            packer_feed_height: 0,
            packer_feed_ms: 0,
            dish_sent: std::collections::HashMap::new(),
            dish_priority_height: 0,
            dish_priority_since_ms: 0,
            grace_heads_height: 0,
            grace_heads: 0,
            grace_heads_ms: 0,
            dish_blocked_until_ms: 0,
            want_body_hash: String::new(),
            want_body_height: 0,
            last_want_body_ms: 0,
            last_body_push_ms: 0,
            mempool_pulls: 0,
            mempool_served: 0,
            mempool_absorbed: 0,
            pack_no_applicable: 0,
            evicted_since_last_seal: false,
            skip_reopen_cooldown_until_ms: 0,
            online_epoch_id: snap.online_epoch_id,
            online_members: snap.online_members.into_iter().collect(),
            online_hash: snap.online_hash,
            online_votes: HashMap::new(),
            online_ok: HashMap::new(),
            last_online_vote_epoch: 0,
            last_online_vote_hash: String::new(),
            last_online_vote_ms: 0,
            schedule_height: 0,
            schedule_online_members: BTreeSet::new(),
            schedule_online_hash: String::new(),
            schedule_committee: Vec::new(),
            height_view_round: 0,
            view_change_votes: HashMap::new(),
            last_view_change_vote_ms: 0,
            height_sealers: HashMap::new(),
            certs: snap.certs,
            ok_by_height_voter: snap.ok_by_height_voter,
            ok_sigs: snap.ok_sigs,
            pending_slashes: snap.pending_slashes,
            body_store: None,
            keys_dir: None,
            btc_exit_mode: crate::bitvm2_exit::BtcExitMode::from_env(),
            qc_header_version: 3,
            qc_start_height: 0,
            eth_lc_gloas_from_height,
            eth_v3_from_height,
            bitvm2_m1_from_height,
            bitvm2_vk,
            ring_restore_from_height,
            claim_enroll_from_height,
            seat_payout_from_height,
            external_addrs_from_height,
            empty_block_from_height,
            btc4_fork_fix_from_height,
            btc4_lend_scale_from_height,
            orderbook_from_height,
            hello_min_release_from_height,
            utc_hello_enforce_from_height: crate::utc_header::network_utc_hello_enforce_from_height(network_id_for_utc_hello),
            utc_pack_clock: crate::utc_header::UtcPackClock::System,
            peer_releases: BTreeMap::new(),
            rewards_v2_from_height,
            rewards_v2_epoch,
            presence_from_height,
            catchup_miss_from_height,
            seat_key_registry,
            last_settle: None,
            eth_v3_bridge,
            round_votes: snap.round_votes,
            ok_round: HashMap::new(),
            stall: None,
            pending_rounds: 0,
            tip_advanced_ms: 0,
            round_open_ms: 0,
            work_seen_since_ms: 0,
            liveness_alert_last_ms: 0,
            vote_journal: None,
            open_bodies: BTreeMap::new(),
        };
        n.cfg.sanitize();
        n.sync_now_to_chain();
        n.started_ms = n.now_ms;
        n.tip_advanced_ms = n.now_ms;
        n.round_open_ms = n.now_ms;
        // pending_proposal is always None after load. Votes/slashes for h > tip
        // would pin a ghost hash and deadlock the next honest pack (v2.9.7).
        n.drop_uncommitted_attempt_votes();
        // ensure treasury default if old snap
        if n.treasury == 0 {
            n.treasury = TREASURY_GENESIS;
        }
        n.ensure_faucet();
        // Bound chain to cfg in case snap was taken with a higher cap.
        n.prune_chain();
        // Re-seed certified online map so seats survive restart (v2.4.0).
        if !n.online_hash.is_empty() {
            n.online_ok
                .insert(n.online_epoch_id, n.online_hash.clone());
        }
        // v2.5.0: freeze lottery schedule for open height after restore.
        n.freeze_open_height_schedule();
        // Harvest parent_cert from the tail so a pre-2.9.0 snap still yields
        // certs[h-1] after upgrade (tip cert itself must be in snap.certs).
        for l in &n.chain {
            if let Some(c) = &l.parent_cert {
                n.certs.entry(c.height).or_insert_with(|| c.clone());
            }
        }
        n.drop_invalid_certs();
        // Vote maps are not in the snap. Re-seed soft/hard QC marks from the
        // committed chain so packing is not stuck on "tip not soft-QC'd" (v2.3.6).
        for l in &n.chain {
            n.soft_ok.insert(l.ledger_hash.clone());
            n.hard_ok.insert(l.ledger_hash.clone());
        }
        if n.tip_height > 0 && !n.tip_hash.is_empty() {
            n.soft_ok.insert(n.tip_hash.clone());
            n.hard_ok.insert(n.tip_hash.clone());
        }
        let _ = AccountMeta::default(); // silence unused in some builds
        let _ = AccountState::default();
        Ok(n)
    }
}

/// In-flight join-snap assembly (v2.9.24).
///
/// Chunks may arrive out of order (archive push + hole-fill). Complete
/// only when every index is present; the caller hashes the concatenation.
#[derive(Debug)]
pub struct SnapAssembler {
    pub sha256: String,
    pub tip_height: u64,
    pub tip_hash: String,
    pub total: u32,
    pub chunk_size: u32,
    pub expected_bytes: u64,
    parts: BTreeMap<u32, Vec<u8>>,
    pub source_peer: String,
    pub last_progress_ms: u64,
    pub last_req_ms: u64,
    /// v2.9.68: when this download started (slow-source switch).
    pub started_ms: u64,
    /// v2.9.74: chunks already held when this attempt started (resumed from
    /// [`SnapStash`]); `too_slow` judges only the progress since then.
    pub got_at_start: u32,
    /// v2.9.74: every source was already judged too slow once; keep this
    /// download running (only the stall abort can drop it).
    pub keep_slow: bool,
    /// One past the highest index requested or received (pull pipeline).
    pub next_req: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapInsert {
    Duplicate,
    Progress,
    Complete,
}

impl SnapAssembler {
    pub fn new(
        sha256: String,
        tip_height: u64,
        tip_hash: String,
        total: u32,
        chunk_size: u32,
        expected_bytes: u64,
        now_ms: u64,
    ) -> Self {
        Self {
            sha256,
            tip_height,
            tip_hash,
            total: total.max(1),
            chunk_size,
            expected_bytes,
            parts: BTreeMap::new(),
            source_peer: String::new(),
            last_progress_ms: now_ms,
            last_req_ms: now_ms,
            started_ms: now_ms,
            got_at_start: 0,
            keep_slow: false,
            next_req: 0,
        }
    }

    /// v2.9.74: restart the clocks of a stashed download for a new attempt
    /// (same sha, possibly another source). Received chunks are kept.
    pub fn resume(&mut self, now_ms: u64, source_peer: String) {
        self.source_peer = source_peer;
        self.last_progress_ms = now_ms;
        self.last_req_ms = now_ms;
        self.started_ms = now_ms;
        self.got_at_start = self.got();
        self.keep_slow = false;
        self.next_req = 0;
    }

    /// Record indices just requested (offer window / retry tick).
    pub fn note_requested(&mut self, idx: &[u32]) {
        if let Some(&hi) = idx.iter().max() {
            self.next_req = self.next_req.max(hi.saturating_add(1)).min(self.total);
        }
    }

    /// Pull pipeline: after chunk `index` arrives, return the next indices to
    /// request so up to `window` stay outstanding. Without this a pull-only
    /// download (push budget spent / lane full) asked for one window and then
    /// sat until the 1.5 s tail retry: ~16 chunks per ~2 s (163 chunks took
    /// 17.8 s on loopback). Indices below `push_horizon` are left to the
    /// archive push + hole-fill retry so in-flight pushes are not duplicated.
    pub fn pipeline_refill(&mut self, index: u32, window: u32, push_horizon: u32) -> Vec<u32> {
        if index >= self.next_req {
            // The push (or an earlier request) ran ahead of us.
            self.next_req = index.saturating_add(1).min(self.total);
        }
        if self.next_req < push_horizon.min(self.total) {
            return Vec::new();
        }
        let window = window.max(1) as usize;
        let mut outstanding = (0..self.next_req).filter(|i| !self.parts.contains_key(i)).count();
        let mut out = Vec::new();
        while outstanding < window && self.next_req < self.total {
            let i = self.next_req;
            self.next_req += 1;
            if !self.parts.contains_key(&i) {
                out.push(i);
                outstanding += 1;
            }
        }
        out
    }

    /// v2.9.68: a source this slow would take longer than `budget_ms` for the
    /// whole snapshot. Judged only after `min_elapsed_ms`. A trickle never hits
    /// the 15 s stall abort, so a joiner pinned to a congested path
    /// (v1 through the seed relay) could sit there for hours.
    pub fn too_slow(&self, now_ms: u64, min_elapsed_ms: u64, budget_ms: u64) -> bool {
        let el = now_ms.saturating_sub(self.started_ms);
        if el < min_elapsed_ms || self.got() >= self.total {
            return false;
        }
        let new = self.got().saturating_sub(self.got_at_start);
        if new == 0 {
            return true;
        }
        if self.got_at_start == 0 {
            // projected = el * total / got  > budget
            return (el as u128) * (self.total as u128) > (budget_ms as u128) * (new as u128);
        }
        // v2.9.74 resumed: projected time for the chunks still missing.
        let remaining = self.total - self.got();
        (el as u128) * (remaining as u128) > (budget_ms as u128) * (new as u128)
    }

    pub fn got(&self) -> u32 {
        self.parts.len() as u32
    }

    pub fn has(&self, index: u32) -> bool {
        self.parts.contains_key(&index)
    }

    pub fn missing(&self) -> Vec<u32> {
        (0..self.total)
            .filter(|i| !self.parts.contains_key(i))
            .collect()
    }

    /// Next unreceived indices, capped (WAN pipeline window).
    pub fn request_window(&self, max: u32) -> Vec<u32> {
        self.missing().into_iter().take(max.max(1) as usize).collect()
    }

    /// v2.9.62: indices to re-request on a retry tick while the archive is
    /// pushing every chunk (one `NeedSnapshot` = Offer + all chunks).
    ///
    /// Only holes **below the highest received index** (the push already
    /// passed them, so they were dropped). The tail above it is still queued
    /// on the server; asking for it again made a slow WAN joiner receive the
    /// snapshot ~4.7x (installer worker, 9 Oct). Nothing received yet, or no
    /// progress for `tail_after_ms`, falls back to the next window.
    pub fn retry_indices(&self, max: u32, now_ms: u64, tail_after_ms: u64) -> Vec<u32> {
        let cap = max.max(1) as usize;
        let Some((&hi, _)) = self.parts.iter().next_back() else {
            return self.request_window(max);
        };
        let holes: Vec<u32> = (0..hi).filter(|i| !self.parts.contains_key(i)).take(cap).collect();
        if !holes.is_empty() {
            return holes;
        }
        if now_ms.saturating_sub(self.last_progress_ms) >= tail_after_ms {
            return self.request_window(max);
        }
        Vec::new()
    }

    pub fn insert(&mut self, index: u32, data: Vec<u8>, now_ms: u64) -> Result<SnapInsert, String> {
        if index >= self.total {
            return Err("chunk oob".into());
        }
        if self.parts.contains_key(&index) {
            return Ok(SnapInsert::Duplicate);
        }
        self.parts.insert(index, data);
        self.last_progress_ms = now_ms;
        self.last_req_ms = now_ms;
        if self.got() == self.total {
            Ok(SnapInsert::Complete)
        } else {
            Ok(SnapInsert::Progress)
        }
    }

    pub fn assemble(&self) -> Option<Vec<u8>> {
        if self.got() != self.total {
            return None;
        }
        let mut buf = Vec::with_capacity(self.expected_bytes as usize);
        for i in 0..self.total {
            buf.extend_from_slice(self.parts.get(&i)?);
        }
        Some(buf)
    }
}

/// v2.9.74 joiner: aborted downloads kept by sha so a later offer of the same
/// snapshot resumes instead of starting from chunk 0. Before 2.9.74 every
/// "too slow"/stall abort threw the received chunks away; with both hubs on a
/// ~140 KB/s path each 45 s attempt got ~25/410 chunks and a fresh install
/// never finished (first-run livelock, 19 Oct 2026). Bounded to `cap` entries
/// (oldest evicted); cleared when a snapshot is adopted.
#[derive(Debug, Default)]
pub struct SnapStash {
    items: Vec<SnapAssembler>,
    cap: usize,
}

impl SnapStash {
    pub fn new(cap: usize) -> Self {
        Self { items: Vec::new(), cap: cap.max(1) }
    }

    /// Keep `a` if it holds any chunk. Replaces an entry with the same sha
    /// (the one with more chunks wins).
    pub fn put(&mut self, a: SnapAssembler) {
        if a.got() == 0 {
            return;
        }
        if let Some(i) = self.items.iter().position(|x| x.sha256 == a.sha256) {
            if self.items[i].got() >= a.got() {
                return;
            }
            self.items.remove(i);
        }
        self.items.push(a);
        while self.items.len() > self.cap {
            self.items.remove(0);
        }
    }

    pub fn take(&mut self, sha256: &str) -> Option<SnapAssembler> {
        let i = self.items.iter().position(|x| x.sha256 == sha256)?;
        Some(self.items.remove(i))
    }

    /// Drop entries for snapshots at or below `tip` (already passed).
    pub fn prune_below(&mut self, tip: u64) {
        self.items.retain(|x| x.tip_height > tip);
    }

    pub fn clear(&mut self) {
        self.items.clear();
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

/// v2.9.74 joiner: a source may be dropped as "too slow" once per join. When
/// a source already judged slow is downloading again, every faster option was
/// tried, so the slow download is kept (stall abort still applies). Reset on
/// snapshot adopt.
#[derive(Debug, Default)]
pub struct SnapSlowJudge {
    judged: std::collections::HashSet<String>,
}

impl SnapSlowJudge {
    pub fn new() -> Self {
        Self::default()
    }

    /// `true` = abort this too-slow download (first time for `source`);
    /// `false` = no faster source is left, keep it.
    pub fn should_abort(&mut self, source: &str) -> bool {
        self.judged.insert(source.to_string())
    }

    pub fn reset(&mut self) {
        self.judged.clear();
    }
}

#[cfg(test)]
mod snap_pipeline_tests {
    use super::*;

    #[test]
    fn pull_only_keeps_window_full_without_tail_wait() {
        let mut a = SnapAssembler::new("p".into(), 9, "h".into(), 100, 1, 100, 0);
        let w = a.request_window(16);
        a.note_requested(&w);
        assert_eq!(a.next_req, 16);
        // Push horizon 0 (pull-only): each arrival tops the window back up.
        a.insert(0, vec![0], 1).unwrap();
        assert_eq!(a.pipeline_refill(0, 16, 0), vec![16]);
        a.insert(1, vec![1], 2).unwrap();
        assert_eq!(a.pipeline_refill(1, 16, 0), vec![17]);
        // Never more than `window` outstanding.
        let outstanding = (0..a.next_req).filter(|i| !a.has(*i)).count();
        assert_eq!(outstanding, 16);
    }

    #[test]
    fn push_region_not_duplicated() {
        let mut a = SnapAssembler::new("p".into(), 9, "h".into(), 470, 1, 470, 0);
        let w = a.request_window(16);
        a.note_requested(&w);
        // Pushed chunks 0..40 arrive in order: no pipeline requests below horizon 48.
        for i in 0..40u32 {
            a.insert(i, vec![1], 1).unwrap();
            assert!(a.pipeline_refill(i, 16, 48).is_empty(), "dup request at {i}");
        }
        assert_eq!(a.next_req, 40);
        // Retry tick asks 40..56; from then on arrivals pipeline.
        let r: Vec<u32> = (40..56).collect();
        a.note_requested(&r);
        a.insert(40, vec![1], 2).unwrap();
        assert_eq!(a.pipeline_refill(40, 16, 48), vec![56]);
    }

    #[test]
    fn resume_restarts_pipeline_from_holes() {
        let mut a = SnapAssembler::new("p".into(), 9, "h".into(), 50, 1, 50, 0);
        for i in 0..20u32 {
            a.insert(i, vec![1], 1).unwrap();
        }
        a.next_req = 40;
        a.resume(5, "v1".into());
        assert_eq!(a.next_req, 0);
        let w = a.request_window(16);
        assert_eq!(w.first(), Some(&20));
        a.note_requested(&w);
        assert_eq!(a.next_req, 36);
    }
}

#[cfg(test)]
mod snap_resume_tests {
    use super::{SnapAssembler, SnapInsert, SnapSlowJudge, SnapStash};

    fn asm(sha: &str, total: u32, now: u64) -> SnapAssembler {
        SnapAssembler::new(sha.into(), 100, "h".into(), total, 1, u64::from(total), now)
    }

    #[test]
    fn stash_keeps_chunks_by_sha_and_ignores_empty() {
        let mut st = SnapStash::new(2);
        st.put(asm("empty", 10, 0));
        assert!(st.is_empty(), "nothing received, nothing to keep");
        let mut a = asm("a", 10, 0);
        for i in 0..3 {
            a.insert(i, vec![0], 1).unwrap();
        }
        st.put(a);
        let mut b = asm("a", 10, 0);
        b.insert(0, vec![0], 1).unwrap();
        st.put(b); // fewer chunks for the same sha: keep the richer one
        let mut r = st.take("a").unwrap();
        assert_eq!(r.got(), 3);
        assert!(st.take("a").is_none());
        r.resume(5_000, "v3".into());
        assert_eq!((r.got_at_start, r.started_ms, r.source_peer.as_str()), (3, 5_000, "v3"));
        assert_eq!(r.request_window(2), vec![3, 4]);
    }

    #[test]
    fn stash_is_bounded_and_prunes_passed_tips() {
        let mut st = SnapStash::new(2);
        for (k, sha) in ["x", "y", "z"].iter().enumerate() {
            let mut a = SnapAssembler::new((*sha).into(), 100 + k as u64, "h".into(), 4, 1, 4, 0);
            a.insert(0, vec![0], 1).unwrap();
            st.put(a);
        }
        assert_eq!(st.len(), 2);
        assert!(st.take("x").is_none(), "oldest evicted");
        st.prune_below(101);
        assert_eq!(st.len(), 1);
        assert!(st.take("z").is_some());
    }

    #[test]
    fn resumed_too_slow_judges_new_progress_on_remaining() {
        let mut a = asm("s", 100, 0);
        for i in 0..90 {
            a.insert(i, vec![0], 1).unwrap();
        }
        a.resume(100_000, "v1".into());
        // 0 new chunks after 50 s: slow.
        assert!(a.too_slow(150_000, 45_000, 480_000));
        for i in 90..92 {
            a.insert(i, vec![0], 120_000).unwrap();
        }
        // 2 new in 50 s, 8 remaining -> 200 s projected < 480 s: keep.
        assert!(!a.too_slow(150_000, 45_000, 480_000));
    }

    #[test]
    fn judge_aborts_each_source_once_then_keeps() {
        let mut j = SnapSlowJudge::new();
        assert!(j.should_abort("v1"));
        assert!(j.should_abort("v3"));
        assert!(!j.should_abort("v1"), "every source already slow: keep downloading");
        assert!(!j.should_abort("v3"));
        j.reset();
        assert!(j.should_abort("v1"));
    }

    /// 19 Oct 2026 first-run livelock, simulated with the node's loop: two
    /// hubs alternate offers (own sha each), each delivers 25 chunks per
    /// 45 s attempt, 412 chunks, judged at 45 s with an 8 min budget.
    /// Pre-2.9.74 (no stash, no judge) never completes; 2.9.74 completes.
    fn simulate(fixed: bool) -> Option<u64> {
        const TOTAL: u32 = 412;
        const RATE_PER_45S: u32 = 25;
        let mut stash = SnapStash::new(2);
        let mut judge = SnapSlowJudge::new();
        let mut now = 0u64;
        let srcs = [("v1", "sha1"), ("v3", "sha3")];
        let mut turn = 0usize;
        for _attempt in 0..200 {
            let (src, sha) = srcs[turn % 2];
            turn += 1;
            let mut a = match fixed.then(|| stash.take(sha)).flatten() {
                Some(mut a) => {
                    a.resume(now, src.into());
                    a
                }
                None => {
                    let mut a = asm(sha, TOTAL, now);
                    a.source_peer = src.into();
                    a
                }
            };
            loop {
                // one 45 s slice of download
                let mut n = 0;
                while n < RATE_PER_45S {
                    let Some(&i) = a.missing().first() else { break };
                    if a.insert(i, vec![0], now).unwrap() == SnapInsert::Complete {
                        return Some(now);
                    }
                    n += 1;
                }
                now += 45_000;
                // Same order as the node tick: keep_slow skips the judgement.
                if !a.keep_slow && a.too_slow(now, 45_000, 480_000) {
                    if !fixed || judge.should_abort(src) {
                        break; // abort this attempt
                    }
                    a.keep_slow = true;
                }
            }
            if fixed {
                stash.put(a);
            }
        }
        None
    }

    #[test]
    fn slow_hubs_first_run_livelock_is_fixed() {
        assert_eq!(simulate(false), None, "pre-2.9.74 behaviour: never completes");
        let t = simulate(true).expect("2.9.74 completes");
        // 412 chunks at 25/45 s = ~742 s of transfer; well under the 900 s installer wait.
        assert!(t <= 800_000, "completed after {t} ms");
    }
}

#[cfg(test)]
mod snap_assembler_tests {
    use super::{SnapAssembler, SnapInsert, SnapStash};
    use crate::crypto::sha256_hex;

    /// Regression (WAN observer, 9 Oct 2026): a slow in-order push must not
    /// trigger re-requests of the in-flight tail; dropped holes still are.
    #[test]
    fn retry_only_holes_below_highest_received() {
        let mut a = SnapAssembler::new("s".into(), 1, "h".into(), 380, 10, 3800, 0);
        // Nothing yet: ask for the first window (push may have been dropped).
        assert_eq!(a.retry_indices(4, 1_000, 3_000), vec![0, 1, 2, 3]);
        // In-order push, 1.2 s gaps (slow link): no retries at all.
        let mut sent = 0usize;
        for i in 0..50u32 {
            a.insert(i, vec![0; 10], 1_200 * u64::from(i)).unwrap();
            sent += a.retry_indices(4, 1_200 * u64::from(i) + 1_100, 3_000).len();
        }
        assert_eq!(sent, 0, "no duplicate requests while the push is progressing");
        // Two chunks dropped inside the push: only those are re-requested.
        a.insert(52, vec![0; 10], 61_000).unwrap();
        a.insert(55, vec![0; 10], 61_500).unwrap();
        assert_eq!(a.retry_indices(4, 62_600, 3_000), vec![50, 51, 53, 54]);
        // Tail stalled (no holes below max) for 3 s: next window as a fallback.
        let mut b = SnapAssembler::new("s".into(), 1, "h".into(), 10, 10, 100, 0);
        b.insert(0, vec![0; 10], 0).unwrap();
        assert!(b.retry_indices(4, 2_000, 3_000).is_empty());
        assert_eq!(b.retry_indices(4, 3_000, 3_000), vec![1, 2, 3, 4]);
    }

    #[test]
    fn assembles_out_of_order_and_hashes() {
        let file = b"abcdefghijklmnopqrstuvwxyz0123456789".to_vec();
        let sha = sha256_hex(&file);
        let chunk = 10usize;
        let total = file.len().div_ceil(chunk) as u32;
        let mut a = SnapAssembler::new(
            sha.clone(),
            42,
            "tip".into(),
            total,
            chunk as u32,
            file.len() as u64,
            1,
        );
        // Reverse order — WAN hole-fill + archive push.
        for i in (0..total).rev() {
            let s = (i as usize) * chunk;
            let e = (s + chunk).min(file.len());
            let r = a.insert(i, file[s..e].to_vec(), 10 + i as u64).unwrap();
            if i == 0 {
                assert_eq!(r, SnapInsert::Complete);
            } else {
                assert_eq!(r, SnapInsert::Progress);
            }
        }
        let got = a.assemble().expect("complete");
        assert_eq!(got, file);
        assert_eq!(sha256_hex(&got), sha);
        assert!(a.request_window(4).is_empty());
    }

    #[test]
    fn window_skips_received_and_rejects_oob() {
        let mut a = SnapAssembler::new("x".into(), 1, "h".into(), 5, 8, 40, 0);
        assert_eq!(a.request_window(3), vec![0, 1, 2]);
        assert_eq!(a.insert(1, vec![1; 8], 1).unwrap(), SnapInsert::Progress);
        assert_eq!(a.request_window(3), vec![0, 2, 3]);
        assert!(a.insert(9, vec![0], 2).is_err());
        assert_eq!(a.insert(1, vec![2; 8], 3).unwrap(), SnapInsert::Duplicate);
        assert_eq!(a.got(), 1);
    }

    #[test]
    fn snap_assembler_too_slow_projects_total_time() {
        let mut a = SnapAssembler::new("s".into(), 1, "h".into(), 100, 1, 100, 0);
        assert!(!a.too_slow(10_000, 45_000, 480_000), "too early to judge");
        assert!(a.too_slow(50_000, 45_000, 480_000), "nothing after 50 s");
        for i in 0..5 {
            a.insert(i, vec![0], 1).unwrap();
        }
        // 5/100 in 60 s -> 1200 s projected > 480 s
        assert!(a.too_slow(60_000, 45_000, 480_000));
        for i in 5..50 {
            a.insert(i, vec![0], 1).unwrap();
        }
        // 50/100 in 60 s -> 120 s projected
        assert!(!a.too_slow(60_000, 45_000, 480_000));
    }

    #[test]
    fn resume_108_of_470_requests_tail_after_quiet() {
        let mut a = SnapAssembler::new("pin".into(), 100, "h".into(), 470, 256 * 1024, 470 * 256 * 1024, 0);
        for i in 0..108u32 {
            // Same progress stamp so tail_after is measured from last insert.
            assert_eq!(a.insert(i, vec![0u8; 8], 1_000).unwrap(), SnapInsert::Progress);
        }
        assert_eq!(a.got(), 108);
        // Contiguous: no holes below hi → empty until tail_after.
        assert!(a.retry_indices(16, 1_000 + 1_499, 1_500).is_empty());
        let tail = a.retry_indices(16, 1_000 + 1_500, 1_500);
        assert_eq!(tail, (108..124).collect::<Vec<_>>());
        a.resume(10_000, "v1".into());
        assert_eq!(a.got_at_start, 108);
        assert_eq!(a.source_peer, "v1");
        assert_eq!(a.got(), 108);
    }

    #[test]
    fn resume_208_of_470_keeps_chunks_across_sources() {
        let mut a = SnapAssembler::new("pin2".into(), 200, "h".into(), 470, 256 * 1024, 470 * 256 * 1024, 0);
        for i in 0..208u32 {
            a.insert(i, vec![1u8; 4], 1).unwrap();
        }
        let mut stash = SnapStash::new(2);
        stash.put(a);
        let mut b = stash.take("pin2").expect("stashed");
        b.resume(50_000, "v3".into());
        assert_eq!(b.got(), 208);
        assert_eq!(b.source_peer, "v3");
        let tail = b.retry_indices(16, 50_000 + 2_000, 1_500);
        assert_eq!(tail.first().copied(), Some(208));
    }

    #[test]
    fn resume_with_holes_prefers_hole_fill_not_tail() {
        let mut a = SnapAssembler::new("pin3".into(), 1, "h".into(), 470, 8, 470 * 8, 0);
        for i in 0..108u32 {
            if i == 50 {
                continue; // hole
            }
            a.insert(i, vec![0u8; 8], 1).unwrap();
        }
        let holes = a.retry_indices(16, 10, 1_500);
        assert_eq!(holes, vec![50]);
    }
}
