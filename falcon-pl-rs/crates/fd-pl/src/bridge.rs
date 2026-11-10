// Copyright (c) 2025-2026 BEARTEC. All rights reserved. See LICENSE.
//! Hardcoded SPV rails for Falcon PL — custodialess mint/burn substrate.
//!
//! Relayers submit headers + merkle proofs. No federated mint authority.
//! BTC uses real Bitcoin headers (80-byte, PoW, hash256 merkle) and a raw tx
//! extract against the protocol watch script. ETH/BNB keep protocol merkle.

use crate::bitvm::{self, BitvmClaim, ClaimStatus};
use crate::btc_spv;
use crate::crypto::sha256_hex;
use crate::vault::{self, VaultPub, VaultUtxo};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const RAIL_BTC: &str = "BTC";
pub const RAIL_ETH: &str = "ETH";
pub const RAIL_BNB: &str = "BNB";
pub const RAIL_USDC: &str = "USDC";
/// BRIDGE: Bitcoin testnet4 rail for the BitVM2 operator bridge. Created at
/// `TESTNET_2300_BRIDGE_FROM_HEIGHT` (not a genesis rail, so snapshots/roots
/// before the bridge height are unchanged). The legacy `BTC` rail follows
/// testnet3 and has a frozen checkpoint, so testnet4 needs its own rail.
pub const RAIL_BTC4: &str = "BTC4";
/// Testnet4 retarget block 155,232 (2016 * 77): real difficulty, so
/// `last_real_bits` is defined from the first header.
pub const BTC4_CHECKPOINT_HEIGHT: u64 = 155_232;
pub const BTC4_CHECKPOINT_HASH: &str =
    "0000000000000002314dc5b90175408b22d2c80dfe99979629b40e572d40345b";
pub const GENESIS_RAILS: &[&str] = &[RAIL_BTC, RAIL_ETH, RAIL_BNB, RAIL_USDC];

pub const DEFAULT_MIN_CONFIRMATIONS: u64 = 6;
/// Always keep at least this many headers, even if they are older than the
/// time window (testnet timestamps can jump).
pub const HEADER_HISTORY: usize = 16_384;
/// A forgotten claim or a return a few days later must still find its block.
/// Testnet can mint a block every few seconds, so a short count is not enough.
pub const HEADER_RETAIN_SECS: u64 = 14 * 24 * 60 * 60;
/// Safety cap if a difficulty-1 sprint runs the whole retention window.
/// 500k headers is about six days at one block per second.
pub const HEADER_HARD_CAP: usize = 500_000;

/// Rolling window of ETH execution headers kept behind the light-client head
/// (~7 days at a 12s slot). Headers with `number < eth_exec_prune_floor` are dropped.
/// The floor is `execution_number.saturating_sub(ETH_EXEC_HEADER_WINDOW)` and
/// only moves when that head number moves.
pub const ETH_EXEC_HEADER_WINDOW: u64 = 50_400;

/// V3 peg-in expiry (E), measured in LC-head execution time. Shorter than
/// [`ETH_EXEC_HEADER_WINDOW`] (~7 days) so a deposit still inside the header
/// window can be refunded after it expires. 3 days.
pub const ETH_V3_DEPOSIT_EXPIRY_SECS: u64 = 3 * 86_400;

/// Sepolia beacon genesis, 2022-06-20 14:00:00 UTC. Fallback LC-head time when
/// the stored execution header has no parseable timestamp at RLP field 11:
/// `genesis + 12 * finalized_slot`.
pub const SEPOLIA_BEACON_GENESIS_UNIX: u64 = 1_655_733_600;

/// `mint_evm_lc` rejects a deposit below [`ETH_EXEC_HEADER_WINDOW`]. Permanent:
/// the header will not come back, so the tx must leave the mempool.
pub const DEPOSIT_OLDER_THAN_HEADER_WINDOW: &str = "deposit older than header window";
/// v2.9.60: every header in an `EthExecHeaders` batch is below the monotonic
/// prune floor. The floor never goes down, so the batch can never apply;
/// permanent so a stale relayer head is dropped instead of stalling its account.
pub const EXEC_HEADERS_BELOW_PRUNE_FLOOR: &str = "execution headers below prune floor";

pub const V3_DEPOSIT_ALREADY_RESOLVED: &str = "V3 deposit already resolved";
pub const V1_DEPOSIT_AFTER_V3_ACTIVATION: &str = "V1 deposit after V3 activation";
pub const V3_DEPOSIT_NOT_IN_RECEIPT: &str = "receipt has no matching V3 Deposit";
/// Permanent: the log's token is fixed on chain, so the tx can never apply.
pub const V3_DEPOSIT_BAD_TOKEN: &str = "V3 deposit token is not ETH or USDC";
/// Permanent: the tx names the wrong asset for an immutable log.
pub const V3_DEPOSIT_ASSET_MISMATCH: &str = "V3 deposit asset mismatch";
/// Not permanent: a wrong or missing preimage must not freeze the deposit into
/// a refund while it is still inside the expiry window.
pub const V3_DEPOSIT_DEST_UNRESOLVED: &str =
    "V3 deposit dest unresolved: supply credit_to before expiry";
pub const V3_DEPOSITS_NOT_ACTIVE: &str = "V3 deposits not active";
/// Permanent: `deposit_id` is not 32-byte hex, so the tx can never apply.
pub const V3_DEPOSIT_ID_MALFORMED: &str = "V3 deposit_id must be 32-byte hex";
pub const V3_BRIDGE_NOT_CONFIGURED: &str = "V3 bridge address not configured";

/// `sha256("refund|" || depositId)`. 7 ASCII bytes then the 32-byte id.
/// Solidity: `sha256(abi.encodePacked("refund|", depositId))`.
pub fn v3_refund_note_id(deposit_id: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 39];
    buf[..7].copy_from_slice(b"refund|");
    buf[7..].copy_from_slice(deposit_id);
    crate::crypto::sha256_raw(&buf)
}

/// `sha256("mint|" || depositId)`. Tests and docs only.
///
/// FPL must never put a leaf under this id into `claim_leaves`. V3 registers
/// the mint note on the contract at deposit time; a claim-root leaf would pay
/// it out as a withdrawal and block the refund.
pub fn v3_mint_note_id(deposit_id: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 37];
    buf[..5].copy_from_slice(b"mint|");
    buf[5..].copy_from_slice(deposit_id);
    crate::crypto::sha256_raw(&buf)
}

/// Ledger state a V3 mint needs to decide whether it can credit at all.
/// Consensus passes views of `WorldState` / `DefiState`; nothing else.
pub struct V3CreditView<'a> {
    /// Current non-native balance of `(account, asset)`.
    pub balance_of: &'a dyn Fn(&str, &str) -> u64,
}

/// Reserved ids a V3 mint may credit: the genesis accounts
/// ([`crate::genesis_accounts`]: `alice`, `bob`, `carol`, `dave`, `faucet`)
/// plus `treasury` and `watcher-browser`, the reserved names auto-mint already
/// resolves for V1. A fixed list, not "has a ledger entry": any `Pay` creates
/// its destination's entry, so that test would let anyone make `admin` or
/// `bridge` creditable.
pub const V3_CREDITABLE_RESERVED: &[&str] = &[
    "alice",
    "bob",
    "carol",
    "dave",
    "faucet",
    "treasury",
    "watcher-browser",
];

/// Creditable FPL recipient for a V3 mint.
///
/// `validate_name` rejects reserved ids so they cannot be re-registered. A
/// reserved id is creditable only if it is in [`V3_CREDITABLE_RESERVED`].
/// Other reserved ids (`admin`, `pool`, `bridge`, `operator`, `v3`, …) are not
/// user accounts, even after something paid them, and neither is anything else
/// that fails `validate_name`: an invalid dest (refund inside the expiry
/// window).
pub fn v3_creditable_account(credit_to: &str) -> Option<String> {
    if let Ok(n) = crate::names::NameRegistry::validate_name(credit_to) {
        return Some(n);
    }
    let s = credit_to.trim().to_ascii_lowercase();
    if crate::names::is_reserved_name(&s) && V3_CREDITABLE_RESERVED.contains(&s.as_str()) {
        Some(s)
    } else {
        None
    }
}

fn parse_v3_deposit_id(s: &str) -> Result<[u8; 32], String> {
    let h = s
        .trim()
        .trim_start_matches("0x")
        .trim_start_matches("0X");
    // One stable, permanent error for any malformed id: the tx can never apply.
    let b = hex::decode(h).map_err(|_| V3_DEPOSIT_ID_MALFORMED.to_string())?;
    if b.len() != 32 {
        return Err(V3_DEPOSIT_ID_MALFORMED.into());
    }
    let mut a = [0u8; 32];
    a.copy_from_slice(&b);
    Ok(a)
}

pub fn v3_deposit_id_hex(deposit_id: &[u8; 32]) -> String {
    hex::encode(deposit_id)
}

fn u32_is_zero(v: &u32) -> bool {
    *v == 0
}

fn is_zero(v: &u64) -> bool {
    *v == 0
}

pub fn bridge_account(rail: &str) -> String {
    format!("bridge:{rail}")
}

pub fn genesis_lock_id(rail: &str) -> String {
    sha256_hex(format!("fpl-spv-lock-v1:{rail}").as_bytes())
}

/// BTC dest-lock note id — dest, not FPL height, so Kickoff can be pre-signed.
pub fn btc_withdraw_note_id(from: &str, amount: u64, external_to: &str) -> String {
    sha256_hex(format!("wd:BTC:{from}:{amount}:{external_to}").as_bytes())
}

/// Proof payload attached to deposit / header submit.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct BridgeProof {
    #[serde(default)]
    pub external_txid: String,
    #[serde(default)]
    pub block_hash: String,
    #[serde(default)]
    pub height: u64,
    #[serde(default)]
    pub merkle_path: Vec<String>,
    #[serde(default)]
    pub merkle_index: u32,
    #[serde(default)]
    pub lock_id: String,
    #[serde(default)]
    pub parent_hash: String,
    #[serde(default)]
    pub merkle_root: String,
    #[serde(default)]
    pub external_to: String,
    /// Raw Bitcoin transaction hex. Required for BTC mint.
    /// ETH LC: receipt RLP hex.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub raw_tx: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RailHeader {
    pub height: u64,
    pub hash: String,
    pub parent_hash: String,
    pub merkle_root: String,
    /// 80-byte Bitcoin header hex. Required on the BTC rail.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub raw: String,
}

impl RailHeader {
    pub fn fixture(height: u64, hash: impl Into<String>, parent: impl Into<String>, merkle: impl Into<String>) -> Self {
        Self {
            height,
            hash: hash.into(),
            parent_hash: parent.into(),
            merkle_root: merkle.into(),
            raw: String::new(),
        }
    }
}

/// Protocol-generic merkle pairing: sha256("{left}|{right}").
pub fn merkle_root_protocol(leaf: &str, path: &[String], index: u32) -> String {
    let mut hash = leaf.to_string();
    let mut idx = index;
    for sib in path {
        if idx % 2 == 0 {
            hash = sha256_hex(format!("{hash}|{sib}").as_bytes());
        } else {
            hash = sha256_hex(format!("{sib}|{hash}").as_bytes());
        }
        idx /= 2;
    }
    hash
}

/// Max headers held on a pending competing BTC branch (v2 strict mode).
pub const BTC_FORK_MAX: usize = 144;
/// v2.10.1: a pending fork this many headers behind a heavier main tip is dropped.
pub const BTC_FORK_STALE_N: u64 = 6;

fn header_work(h: &RailHeader) -> u128 {
    btc_spv::parse_header_hex(&h.raw)
        .map(|p| btc_spv::header_work_bits(p.bits))
        .unwrap_or(0)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RailState {
    pub asset: String,
    pub min_confirmations: u64,
    pub lock_id: String,
    pub tip_height: u64,
    pub tip_hash: String,
    pub tip_merkle_root: String,
    pub total_minted: u64,
    pub total_burned: u64,
    /// height -> header
    pub headers: BTreeMap<u64, RailHeader>,
    /// spent external txids (deposits)
    pub spent_deposits: BTreeSet<String>,
    /// open withdraw notes: note_id -> (amount, external_to, from)
    pub withdrawals: BTreeMap<String, (u64, String, String)>,
    /// Confirmed BTC vault UTXOs (fungible pool).
    #[serde(default)]
    pub vault_utxos: Vec<VaultUtxo>,
    /// Public vault identity (pubkey/spk only — never shares).
    /// Consensus: only what was packed / snapshotted. Do **not** fill this
    /// from a local `vault-pub.json` — that desyncs the state root (v1 99622).
    #[serde(default)]
    pub vault_pub: Option<VaultPub>,
    /// Operator overlay from `keys/vault-pub.json`. Not snapshotted, not in
    /// the commitment root. Used to verify/sign when the chain field is unset.
    #[serde(skip)]
    pub local_vault_pub: Option<VaultPub>,
    /// First accepted Bitcoin header (height, hash). After this, no reanchor.
    #[serde(default)]
    pub btc_checkpoint: Option<(u64, String)>,
    /// Last non-min-diff nBits. Survives a window of only POW_LIMIT headers.
    /// Omit when 0 so old snaps / packers hash the same (commitment includes RailState).
    #[serde(default, skip_serializing_if = "u32_is_zero")]
    pub last_real_bits: u32,
    /// note_id → signed Bitcoin tx hex (broadcastable). Never contains shares.
    #[serde(default)]
    pub signed_vault_txs: BTreeMap<String, String>,
    /// BitVM-class dest-locked claims (abort hash only; preimages are local 600 files).
    #[serde(default)]
    pub bitvm_claims: BTreeMap<String, BitvmClaim>,
    /// Local-only abort preimages (never snapshot / status). Key = note_id.
    #[serde(skip)]
    pub abort_secrets: BTreeMap<String, [u8; 32]>,
    /// BitVM Kickoff merkle leaves (hex). Root is public; no founder key.
    #[serde(default)]
    pub claim_leaves: Vec<String>,
    #[serde(default)]
    pub claim_root: String,
    /// BitVM2 MiMC claim tree (Groth16 path).
    /// Omit when empty so pre-bitvm2 packers/snaps hash the same RailState
    /// (commitment root includes the whole bridge).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub bitvm2_claims: BTreeMap<String, crate::bitvm2_exit::Bitvm2Claim>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bitvm2_claim_leaves: Vec<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub bitvm2_claim_root: String,
    /// M1: FPL ledger height → ledger hash, recorded every
    /// `BITVM2_CHECKPOINT_INTERVAL` ledgers from the M1 activation height.
    /// `Bitvm2AttestV2` proofs bind to one of these (circuit `header_hash`).
    /// Empty-omitted, so the commitment root is unchanged before activation.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fpl_checkpoints: BTreeMap<u64, String>,
    /// User-vault 1:1 metadata (txid → owner/h160/nonce). Empty-omitted for old snaps.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub user_vaults: BTreeMap<String, UserVaultMeta>,
    /// note_id → take preimage hex (public after burn).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub published_takes: BTreeMap<String, String>,
    /// Take-preimage seed (abort-seed). Never snapshotted.
    #[serde(skip)]
    pub take_seed: Option<[u8; 32]>,
    /// BitVM2 instance scriptPubKey (overlay). Extra mint dest; not the 369k NUMS vault.
    #[serde(skip)]
    pub bitvm2_instance_spk: Option<Vec<u8>>,
    /// v2.9.62 (rewards v2, `H_act`): pending competing BTC branch. It replaces
    /// the main suffix only once it carries strictly more cumulative work.
    /// Empty (and not serialized) before activation, so the commitment is unchanged.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub btc_fork: Vec<RailHeader>,
    /// v2.10.1 (`btc4_fork_fix_from_height`): a second competing BTC branch
    /// that accumulates from its common ancestor while a pending fork exists.
    /// It replaces `btc_fork` once its cumulative work is strictly greater.
    /// Always empty (and not serialized) before activation, so the commitment
    /// is byte-identical to 2.10.0 until then.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub btc_fork_alt: Vec<RailHeader>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserVaultMeta {
    pub owner: String,
    pub user_h160_hex: String,
    pub nonce_hex: String,
    pub sats: u64,
    #[serde(default)]
    pub vout: u32,
}

/// M1 attestation body (see [`RailState::attest_bitvm2_claim_v2`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Bitvm2AttestV2 {
    pub note_id: String,
    pub claim_txid_hex: String,
    /// FPL checkpoint height in `fpl_checkpoints` the proof is bound to.
    pub checkpoint_height: u64,
    /// Bitcoin block height of the peg-out on the BTC rail.
    pub btc_height: u64,
    /// Full peg-out tx (txid is computed from it).
    pub pegout_raw_tx_hex: String,
    /// Bitcoin merkle siblings (display hex, bottom-up) and tx index.
    pub merkle_path: Vec<String>,
    pub merkle_index: u32,
    /// Optional dest-lock abort commit when the payout is a dest-lock P2WSH.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub dest_lock_abort_commit_hex: String,
    pub proof_hex: String,
    pub public_hex: Vec<String>,
    pub statement_digest_hex: String,
}

impl RailState {
    pub fn new(asset: &str) -> Self {
        Self {
            asset: asset.to_string(),
            min_confirmations: DEFAULT_MIN_CONFIRMATIONS,
            lock_id: genesis_lock_id(asset),
            tip_height: 0,
            tip_hash: String::new(),
            tip_merkle_root: String::new(),
            total_minted: 0,
            total_burned: 0,
            headers: BTreeMap::new(),
            spent_deposits: BTreeSet::new(),
            withdrawals: BTreeMap::new(),
            vault_utxos: Vec::new(),
            vault_pub: None,
            local_vault_pub: None,
            btc_checkpoint: None,
            last_real_bits: 0,
            signed_vault_txs: BTreeMap::new(),
            bitvm_claims: BTreeMap::new(),
            abort_secrets: BTreeMap::new(),
            claim_leaves: Vec::new(),
            claim_root: String::new(),
            bitvm2_claims: BTreeMap::new(),
            bitvm2_claim_leaves: Vec::new(),
            bitvm2_claim_root: String::new(),
            fpl_checkpoints: BTreeMap::new(),
            user_vaults: BTreeMap::new(),
            published_takes: BTreeMap::new(),
            take_seed: None,
            bitvm2_instance_spk: None,
            btc_fork: Vec::new(),
            btc_fork_alt: Vec::new(),
        }
    }

    /// Packed/snapshot `vault_pub`, else the local operator overlay.
    /// Packed P2TR wins (NUMS after pool-move, else FROST). Local P2TR only
    /// covers a packed Shamir P2WPKH leftover.
    pub fn effective_vault_pub(&self) -> Option<&crate::vault::VaultPub> {
        if let Some(packed) = self.vault_pub.as_ref() {
            if let Ok(spk) = hex::decode(packed.spk_hex.trim()) {
                if crate::btc_tx::is_p2tr(&spk) {
                    return Some(packed);
                }
            }
        }
        if let Some(local) = self.local_vault_pub.as_ref() {
            if let Ok(spk) = hex::decode(local.spk_hex.trim()) {
                if crate::btc_tx::is_p2tr(&spk) {
                    return Some(local);
                }
            }
        }
        self.vault_pub.as_ref().or(self.local_vault_pub.as_ref())
    }

    /// BTC-family rail (testnet3 `BTC` or testnet4 `BTC4`): Bitcoin header rules + SPV.
    pub fn is_btc(&self) -> bool {
        self.asset == RAIL_BTC || self.asset == RAIL_BTC4
    }

    /// Fresh testnet4 rail anchored at the hard-coded checkpoint.
    pub fn new_btc4() -> Self {
        let mut r = RailState::new(RAIL_BTC4);
        r.btc_checkpoint = Some((BTC4_CHECKPOINT_HEIGHT, BTC4_CHECKPOINT_HASH.to_string()));
        r
    }

    pub fn is_bitcoin_tip(&self) -> bool {
        self.is_btc()
            && self
                .headers
                .get(&self.tip_height)
                .map(|h| !h.raw.is_empty())
                .unwrap_or(false)
    }

    pub fn submit_header(&mut self, h: RailHeader) -> Result<(), String> {
        if self.is_btc() {
            return self.submit_btc_header(h);
        }
        self.commit_header(h, false)
    }

    /// v2.9.62: `strict` (rewards v2 at `H_act`) rejects identical re-submits
    /// and only lets a competing BTC branch replace the main suffix when it has
    /// strictly more cumulative work. Returns `Ok(true)` when the rail tip
    /// advanced or a winning reorg landed (watcher work is credited), and
    /// `Ok(false)` when a header was only queued on a pending fork (no credit).
    pub fn submit_header_ex(&mut self, h: RailHeader, strict: bool) -> Result<bool, String> {
        self.submit_header_ex2(h, strict, false)
    }

    /// v2.10.1: as [`Self::submit_header_ex`]; `fork_fix` (BTC4 rail at or after
    /// `btc4_fork_fix_from_height`) lets a competing branch accumulate next to
    /// a pending fork and replace it once heavier, and drops a pending fork
    /// left more than [`BTC_FORK_STALE_N`] headers behind a heavier main chain.
    /// `fork_fix == false` is exactly the 2.10.0 behaviour.
    pub fn submit_header_ex2(&mut self, h: RailHeader, strict: bool, fork_fix: bool) -> Result<bool, String> {
        self.submit_header_ex3(h, strict, fork_fix, false)
    }

    /// Later-height alt-slot replacement on top of [`Self::submit_header_ex2`].
    /// `slot_fix` (BTC4 rail at or after `btc4_fork_slot_from_height`) lets a
    /// new main-ancestral fork that starts *above* the current alt tip replace
    /// `btc_fork_alt` even when its 1-header work is not strictly greater —
    /// the leftover alt cannot be extended through that later height, so it
    /// would otherwise permanently occupy the only competing slot.
    /// `slot_fix == false` is exactly the 2.10.1 behaviour.
    pub fn submit_header_ex3(
        &mut self,
        h: RailHeader,
        strict: bool,
        fork_fix: bool,
        slot_fix: bool,
    ) -> Result<bool, String> {
        if !strict || !self.is_btc() {
            return self.submit_header(h).map(|_| true);
        }
        let fork_fix = fork_fix && self.asset == RAIL_BTC4;
        let slot_fix = slot_fix && fork_fix;
        self.submit_btc_header_strict(h, fork_fix, slot_fix)
    }

    fn submit_btc_header_strict(&mut self, mut h: RailHeader, fork_fix: bool, slot_fix: bool) -> Result<bool, String> {
        if h.raw.is_empty() {
            return Err("BTC rail requires 80-byte Bitcoin header".into());
        }
        let parsed = btc_spv::parse_header_hex(&h.raw)?;
        if !btc_spv::hash_meets_target(&parsed.hash_internal, parsed.bits) {
            return Err("BTC header does not meet target".into());
        }
        h.hash = parsed.hash_display.clone();
        h.parent_hash = parsed.prev_display.clone();
        h.merkle_root = parsed.merkle_display.clone();
        h.raw = parsed.raw_hex.clone();

        let tip_is_fixture = self.tip_height > 0
            && self
                .headers
                .get(&self.tip_height)
                .map(|t| t.raw.is_empty())
                .unwrap_or(true);
        if self.tip_height == 0 || tip_is_fixture {
            // Anchoring rules are unchanged.
            return self.submit_btc_header(h).map(|_| true);
        }
        // Identical to what we already store (main chain or pending fork).
        if let Some(stored) = self.headers.get(&h.height) {
            if btc_spv::hex_eq(&stored.hash, &h.hash) {
                return Err(format!("BTC duplicate header at {}", h.height));
            }
        }
        if self
            .btc_fork
            .iter()
            .any(|f| f.height == h.height && btc_spv::hex_eq(&f.hash, &h.hash))
        {
            return Err(format!("BTC duplicate header at {} (pending fork)", h.height));
        }
        if fork_fix
            && self
                .btc_fork_alt
                .iter()
                .any(|f| f.height == h.height && btc_spv::hex_eq(&f.hash, &h.hash))
        {
            return Err(format!("BTC duplicate header at {} (competing branch)", h.height));
        }
        // Plain extension of the main tip.
        if h.height == self.tip_height + 1 && btc_spv::hex_eq(&h.parent_hash, &self.tip_hash) {
            self.submit_btc_header(h)?;
            if fork_fix {
                self.btc_drop_stale_fork();
            }
            return Ok(true);
        }
        // v2.10.1: extension of the competing branch.
        if fork_fix {
            if let Some(last) = self.btc_fork_alt.last().cloned() {
                if h.height == last.height + 1 && btc_spv::hex_eq(&h.parent_hash, &last.hash) {
                    if self.btc_fork_alt.len() >= BTC_FORK_MAX {
                        return Err("BTC fork too long".into());
                    }
                    let last_p = btc_spv::parse_header_hex(&last.raw)?;
                    let lrb = Self::last_real_bits_in(&self.btc_fork_alt)
                        .unwrap_or_else(|| self.btc_fork_last_real_bits_for(&self.btc_fork_alt));
                    if !btc_spv::bits_ok_testnet(&last_p, &parsed, lrb, h.height) {
                        return Err("BTC bits do not follow parent / testnet min-diff".into());
                    }
                    self.btc_fork_alt.push(h);
                    return self.btc_try_promote_alt();
                }
            }
        }
        // Extension of the pending fork.
        if let Some(last) = self.btc_fork.last().cloned() {
            if h.height == last.height + 1 && btc_spv::hex_eq(&h.parent_hash, &last.hash) {
                if self.btc_fork.len() >= BTC_FORK_MAX {
                    return Err("BTC fork too long".into());
                }
                let last_p = btc_spv::parse_header_hex(&last.raw)?;
                let lrb = self.btc_fork_last_real_bits();
                if !btc_spv::bits_ok_testnet(&last_p, &parsed, lrb, h.height) {
                    return Err("BTC bits do not follow parent / testnet min-diff".into());
                }
                self.btc_fork.push(h);
                return self.btc_try_switch_fork();
            }
        }
        // New competing branch forking off the stored main chain at H-1.
        if h.height > 0 && h.height <= self.tip_height {
            let ancestor = self.headers.get(&(h.height - 1)).cloned().ok_or_else(|| {
                format!("BTC header parent mismatch: no stored header at {}", h.height - 1)
            })?;
            if !btc_spv::hex_eq(&h.parent_hash, &ancestor.hash) {
                return Err(format!(
                    "BTC header parent mismatch: height {} parent {} != stored {} at {}",
                    h.height, h.parent_hash, ancestor.hash, ancestor.height
                ));
            }
            let ancestor_p = btc_spv::parse_header_hex(&ancestor.raw)?;
            let lrb = self.btc_last_real_bits(h.height - 1, ancestor_p.bits);
            if !btc_spv::bits_ok_testnet(&ancestor_p, &parsed, lrb, h.height) {
                return Err("BTC bits do not follow parent / testnet min-diff".into());
            }
            // Don't let a cheap 1-header branch evict a heavier pending fork.
            if !self.btc_fork.is_empty() {
                let cur: u128 = self.btc_fork.iter().map(header_work).fold(0, u128::saturating_add);
                if btc_spv::header_work_bits(parsed.bits) <= cur {
                    if !fork_fix {
                        return Err("BTC fork has less work than the pending fork".into());
                    }
                    // v2.10.1: start (or restart) the competing branch here; it
                    // accumulates and replaces the pending fork once heavier.
                    if !self.btc_fork_alt.is_empty() {
                        let alt: u128 = self.btc_fork_alt.iter().map(header_work).fold(0, u128::saturating_add);
                        if btc_spv::header_work_bits(parsed.bits) <= alt {
                            // Leftover earlier-height alt cannot be extended
                            // to include this later fork (it would have to
                            // pass through heights already on a different
                            // parent). Replace the slot so the submitter can
                            // accumulate the later branch.
                            if slot_fix {
                                if let Some(alt_tip) = self.btc_fork_alt.last() {
                                    if h.height > alt_tip.height {
                                        self.btc_fork_alt = vec![h];
                                        return Ok(false);
                                    }
                                }
                            }
                            return Err("BTC fork has less work than the competing branch".into());
                        }
                    }
                    self.btc_fork_alt = vec![h];
                    return Ok(false);
                }
            }
            self.btc_fork = vec![h];
            return self.btc_try_switch_fork();
        }
        if !btc_spv::hex_eq(&h.parent_hash, &self.tip_hash) {
            return Err("BTC header parent mismatch".into());
        }
        Err(format!("header height want {} got {}", self.tip_height + 1, h.height))
    }

    fn last_real_bits_in(v: &[RailHeader]) -> Option<u32> {
        v.iter().rev().find_map(|f| {
            btc_spv::parse_header_hex(&f.raw)
                .ok()
                .map(|p| p.bits)
                .filter(|b| *b != btc_spv::POW_LIMIT_BITS)
        })
    }

    fn btc_fork_last_real_bits_for(&self, v: &[RailHeader]) -> u32 {
        let start = v.first().map(|f| f.height).unwrap_or(1);
        let fallback = self
            .headers
            .get(&start.saturating_sub(1))
            .and_then(|a| btc_spv::parse_header_hex(&a.raw).ok())
            .map(|p| p.bits)
            .unwrap_or(btc_spv::POW_LIMIT_BITS);
        self.btc_last_real_bits(start.saturating_sub(1), fallback)
    }

    /// v2.10.1: the competing branch replaces the pending fork once its
    /// cumulative work is strictly greater; then the usual main-chain switch
    /// rule (strictly more work than the replaced main suffix) applies.
    fn btc_try_promote_alt(&mut self) -> Result<bool, String> {
        let alt_work: u128 = self.btc_fork_alt.iter().map(header_work).fold(0, u128::saturating_add);
        let fork_work: u128 = self.btc_fork.iter().map(header_work).fold(0, u128::saturating_add);
        if alt_work <= fork_work {
            return Ok(false);
        }
        self.btc_fork = std::mem::take(&mut self.btc_fork_alt);
        self.btc_try_switch_fork()
    }

    /// v2.10.1: drop a pending fork (and competing branch) that has not been
    /// extended while the main chain moved more than `BTC_FORK_STALE_N` headers
    /// past its tip with strictly more work over the same range.
    fn btc_drop_stale_fork(&mut self) {
        for alt in [false, true] {
            let v = if alt { &self.btc_fork_alt } else { &self.btc_fork };
            let (Some(first), Some(last)) = (v.first(), v.last()) else { continue };
            if self.tip_height <= last.height.saturating_add(BTC_FORK_STALE_N) {
                continue;
            }
            let w: u128 = v.iter().map(header_work).fold(0, u128::saturating_add);
            if self.btc_main_work_from(first.height) > w {
                if alt {
                    self.btc_fork_alt.clear();
                } else {
                    self.btc_fork.clear();
                }
            }
        }
    }

    /// Status only (non-consensus): summary of a pending branch.
    pub fn btc_branch_summary(v: &[RailHeader]) -> Option<serde_json::Value> {
        let (first, last) = (v.first()?, v.last()?);
        let w: u128 = v.iter().map(header_work).fold(0, u128::saturating_add);
        Some(serde_json::json!({
            "len": v.len(),
            "start_height": first.height,
            "tip_height": last.height,
            "tip_hash": last.hash,
            "work": w.to_string(),
        }))
    }

    fn btc_fork_last_real_bits(&self) -> u32 {
        for f in self.btc_fork.iter().rev() {
            if let Ok(p) = btc_spv::parse_header_hex(&f.raw) {
                if p.bits != btc_spv::POW_LIMIT_BITS {
                    return p.bits;
                }
            }
        }
        let start = self.btc_fork.first().map(|f| f.height).unwrap_or(1);
        let fallback = self
            .headers
            .get(&start.saturating_sub(1))
            .and_then(|a| btc_spv::parse_header_hex(&a.raw).ok())
            .map(|p| p.bits)
            .unwrap_or(btc_spv::POW_LIMIT_BITS);
        self.btc_last_real_bits(start.saturating_sub(1), fallback)
    }

    /// Cumulative work of the main chain over `from..=tip`.
    pub fn btc_main_work_from(&self, from: u64) -> u128 {
        self.headers
            .range(from..=self.tip_height)
            .map(|(_, h)| header_work(h))
            .fold(0, u128::saturating_add)
    }

    /// Switch to the pending fork iff it has strictly more work than the main
    /// suffix it would replace. Returns whether the tip moved.
    fn btc_try_switch_fork(&mut self) -> Result<bool, String> {
        let Some(first) = self.btc_fork.first() else {
            return Ok(false);
        };
        let start = first.height;
        let fork_work: u128 = self.btc_fork.iter().map(header_work).fold(0, u128::saturating_add);
        if fork_work <= self.btc_main_work_from(start) {
            return Ok(false);
        }
        let fork = std::mem::take(&mut self.btc_fork);
        let ancestor = self
            .headers
            .get(&(start - 1))
            .cloned()
            .ok_or("BTC fork ancestor missing")?;
        let saved_headers = self.headers.clone();
        let saved = (
            self.tip_height,
            self.tip_hash.clone(),
            self.tip_merkle_root.clone(),
            self.last_real_bits,
        );
        self.headers.retain(|k, _| *k < start);
        self.tip_height = ancestor.height;
        self.tip_hash = ancestor.hash.clone();
        self.tip_merkle_root = ancestor.merkle_root.clone();
        for f in fork {
            if let Err(e) = self.submit_btc_header(f) {
                self.headers = saved_headers;
                self.tip_height = saved.0;
                self.tip_hash = saved.1;
                self.tip_merkle_root = saved.2;
                self.last_real_bits = saved.3;
                return Err(format!("BTC fork switch failed: {e}"));
            }
        }
        self.btc_fork_alt.clear();
        Ok(true)
    }

    fn submit_btc_header(&mut self, mut h: RailHeader) -> Result<(), String> {
        if h.raw.is_empty() {
            return Err("BTC rail requires 80-byte Bitcoin header".into());
        }
        let parsed = btc_spv::parse_header_hex(&h.raw)?;
        if !btc_spv::hash_meets_target(&parsed.hash_internal, parsed.bits) {
            return Err("BTC header does not meet target".into());
        }
        h.hash = parsed.hash_display.clone();
        h.parent_hash = parsed.prev_display.clone();
        h.merkle_root = parsed.merkle_display.clone();
        h.raw = parsed.raw_hex.clone();

        let tip_is_fixture = self.tip_height > 0
            && self
                .headers
                .get(&self.tip_height)
                .map(|t| t.raw.is_empty())
                .unwrap_or(true);
        // BTC4 anchors its first header at the hard-coded checkpoint (below);
        // legacy BTC keeps "no reanchor once a checkpoint is set".
        let first_btc4 = self.asset == RAIL_BTC4 && self.tip_height == 0;
        if !first_btc4 && self.btc_checkpoint.is_some() && (self.tip_height == 0 || tip_is_fixture) {
            return Err("BTC checkpoint set — reanchor forbidden".into());
        }
        if self.tip_height == 0 || tip_is_fixture {
            // First real Bitcoin header (or upgrade off the fixture chain).
            if let Some((ch, cref)) = &self.btc_checkpoint {
                if h.height != *ch || !btc_spv::hex_eq(&h.hash, cref) {
                    return Err("BTC header does not match frozen checkpoint".into());
                }
            }
            self.headers.clear();
            return self.commit_header(h, true);
        }

        // Bitcoin reorg: a header at height H ≤ tip whose parent is our stored
        // H-1 replaces the fork from H onward. Deep testnet reorgs must be
        // submitted at the fork height (common ancestor + 1), not the stale tip.
        if h.height > 0 && h.height <= self.tip_height {
            let ancestor = self
                .headers
                .get(&(h.height - 1))
                .cloned()
                .ok_or_else(|| {
                    format!(
                        "BTC header parent mismatch: no stored header at {}",
                        h.height - 1
                    )
                })?;
            if !btc_spv::hex_eq(&h.parent_hash, &ancestor.hash) {
                return Err(format!(
                    "BTC header parent mismatch: height {} parent {} != stored {} at {}",
                    h.height, h.parent_hash, ancestor.hash, ancestor.height
                ));
            }
            let ancestor_p = btc_spv::parse_header_hex(&ancestor.raw)?;
            let last_real_bits = self.btc_last_real_bits(h.height - 1, ancestor_p.bits);
            if !btc_spv::bits_ok_testnet(&ancestor_p, &parsed, last_real_bits, h.height) {
                return Err("BTC bits do not follow parent / testnet min-diff".into());
            }
            let cut = h.height;
            self.headers.retain(|k, _| *k < cut);
            self.tip_height = ancestor.height;
            self.tip_hash = ancestor.hash;
            self.tip_merkle_root = ancestor.merkle_root;
            if parsed.bits != btc_spv::POW_LIMIT_BITS {
                self.last_real_bits = parsed.bits;
            } else if self.last_real_bits == 0 {
                self.last_real_bits = last_real_bits;
            }
            return self.commit_header(h, false);
        }

        let parent = self
            .headers
            .get(&self.tip_height)
            .ok_or_else(|| "BTC tip header missing".to_string())?;
        let parent_p = btc_spv::parse_header_hex(&parent.raw)?;
        if !btc_spv::hex_eq(&h.parent_hash, &self.tip_hash) {
            return Err("BTC header parent mismatch".into());
        }
        let last_real_bits = {
            let mut bits = if self.last_real_bits != 0 {
                self.last_real_bits
            } else {
                parent_p.bits
            };
            for hgt in (1..=self.tip_height).rev() {
                let Some(prev) = self.headers.get(&hgt) else {
                    continue;
                };
                if prev.raw.is_empty() {
                    continue;
                }
                if let Ok(p) = btc_spv::parse_header_hex(&prev.raw) {
                    if p.bits != btc_spv::POW_LIMIT_BITS {
                        bits = p.bits;
                        break;
                    }
                }
            }
            bits
        };
        if !btc_spv::bits_ok_testnet(&parent_p, &parsed, last_real_bits, h.height) {
            return Err("BTC bits do not follow parent / testnet min-diff".into());
        }
        if parsed.bits != btc_spv::POW_LIMIT_BITS {
            self.last_real_bits = parsed.bits;
        } else if self.last_real_bits == 0 {
            self.last_real_bits = last_real_bits;
        }
        self.commit_header(h, false)
    }

    fn btc_last_real_bits(&self, through_height: u64, fallback: u32) -> u32 {
        let mut bits = if self.last_real_bits != 0 {
            self.last_real_bits
        } else {
            fallback
        };
        for hgt in (1..=through_height).rev() {
            let Some(prev) = self.headers.get(&hgt) else {
                continue;
            };
            if prev.raw.is_empty() {
                continue;
            }
            if let Ok(p) = btc_spv::parse_header_hex(&prev.raw) {
                if p.bits != btc_spv::POW_LIMIT_BITS {
                    bits = p.bits;
                    break;
                }
            }
        }
        bits
    }

    fn commit_header(&mut self, h: RailHeader, reanchor: bool) -> Result<(), String> {
        if h.height == 0 {
            return Err("header height 0".into());
        }
        if !reanchor && self.tip_height != 0 {
            if h.height != self.tip_height + 1 {
                return Err(format!(
                    "header height want {} got {}",
                    self.tip_height + 1,
                    h.height
                ));
            }
            if !self.is_btc() && h.parent_hash != self.tip_hash {
                return Err("header parent mismatch".into());
            }
        }
        if self.headers.contains_key(&h.height) {
            return Err("header already known".into());
        }
        self.tip_height = h.height;
        self.tip_hash = h.hash.clone();
        self.tip_merkle_root = h.merkle_root.clone();
        self.headers.insert(h.height, h);
        self.prune_btc_headers();
        Ok(())
    }

    /// Lowest height still connected, without a gap, up to the rail tip.
    pub fn btc_header_floor(&self) -> u64 {
        let mut floor = self.tip_height;
        while floor > 1 && self.headers.contains_key(&(floor - 1)) {
            floor -= 1;
        }
        floor
    }

    fn header_unix(h: &RailHeader) -> u64 {
        let Ok(raw) = crate::btc_spv::hex_decode(h.raw.trim()) else {
            return 0;
        };
        if raw.len() < 72 {
            return 0;
        }
        u32::from_le_bytes(raw[68..72].try_into().unwrap()) as u64
    }

    fn prune_btc_headers(&mut self) {
        let keep = vault::vault_header_heights(&self.vault_utxos);
        let tip_ts = self
            .headers
            .get(&self.tip_height)
            .map(Self::header_unix)
            .unwrap_or(0);
        let cutoff = tip_ts.saturating_sub(HEADER_RETAIN_SECS);
        // Sprint cap first: drop the oldest non-vault header.
        while self.headers.len() > HEADER_HARD_CAP {
            let Some(k) = self.headers.keys().copied().find(|hgt| !keep.contains(hgt)) else {
                break;
            };
            self.headers.remove(&k);
        }
        // Then drop only headers older than the claim window, and never below
        // HEADER_HISTORY. A deposit from a few days ago stays claimable.
        while self.headers.len() > HEADER_HISTORY {
            let Some(k) = self.headers.keys().copied().find(|hgt| {
                if keep.contains(hgt) {
                    return false;
                }
                let ts = self.headers.get(hgt).map(Self::header_unix).unwrap_or(0);
                ts == 0 || ts < cutoff
            }) else {
                break;
            };
            self.headers.remove(&k);
        }
    }

    /// Insert Bitcoin headers *below* the contiguous tip window.
    ///
    /// The batch must be consecutive, end at `floor - 1`, and the last
    /// header's hash must be the parent of the stored floor header.
    /// Used when Claim FBTC targets a height that prune already dropped.
    pub fn backfill_btc_headers(&mut self, raw_headers: &[RailHeader]) -> Result<(), String> {
        if !self.is_btc() {
            return Err("backfill is BTC only".into());
        }
        if raw_headers.is_empty() {
            return Err("empty btc header backfill".into());
        }
        if self.tip_height == 0 || !self.headers.contains_key(&self.tip_height) {
            return Err("btc tip header missing".into());
        }
        let anchor = self.btc_header_floor();
        let anchor_hdr = self
            .headers
            .get(&anchor)
            .cloned()
            .ok_or("no btc anchor header")?;
        let mut parsed: Vec<(u64, crate::btc_spv::ParsedHeader)> = Vec::with_capacity(raw_headers.len());
        for h in raw_headers {
            if h.raw.is_empty() {
                return Err(format!("backfill height {} missing raw header", h.height));
            }
            let p = crate::btc_spv::parse_header_hex(&h.raw)?;
            if !crate::btc_spv::hash_meets_target(&p.hash_internal, p.bits) {
                return Err(format!("backfill height {} does not meet target", h.height));
            }
            if h.height == 0 {
                return Err("backfill height 0".into());
            }
            parsed.push((h.height, p));
        }
        parsed.sort_by_key(|(ht, _)| *ht);
        let first_h = parsed[0].0;
        let last_h = parsed.last().unwrap().0;
        if last_h + 1 != anchor {
            return Err(format!(
                "backfill must end at {} (anchor {anchor}), got end {last_h}",
                anchor.saturating_sub(1)
            ));
        }
        if first_h + parsed.len() as u64 - 1 != last_h {
            return Err("backfill heights not consecutive".into());
        }
        for w in parsed.windows(2) {
            let (h0, p0) = &w[0];
            let (h1, p1) = &w[1];
            if *h1 != *h0 + 1 {
                return Err(format!("backfill gap at {h1}"));
            }
            if !crate::btc_spv::hex_eq(&p1.prev_display, &p0.hash_display) {
                return Err(format!("backfill parent mismatch at {h1}"));
            }
        }
        let last = parsed.last().unwrap();
        if !crate::btc_spv::hex_eq(&last.1.hash_display, &anchor_hdr.parent_hash) {
            return Err(format!(
                "backfill does not connect to anchor {anchor} parent {} got {}",
                anchor_hdr.parent_hash, last.1.hash_display
            ));
        }
        for (ht, p) in &parsed {
            if self.headers.contains_key(ht) {
                return Err(format!("backfill height {ht} already stored"));
            }
            self.headers.insert(
                *ht,
                RailHeader {
                    height: *ht,
                    hash: p.hash_display.clone(),
                    parent_hash: p.prev_display.clone(),
                    merkle_root: p.merkle_display.clone(),
                    raw: p.raw_hex.clone(),
                },
            );
        }
        Ok(())
    }

    pub fn record_vault_deposit(&mut self, txid: &str, vout: u32, sats: u64, height: u64) {
        self.vault_utxos.push(VaultUtxo {
            txid: txid.to_string(),
            vout,
            sats,
            height,
        });
    }

    /// Coin-select + verify a secp signature from t-of-n shares (caller combined).
    /// Does not mutate until `commit_vault_withdraw`.
    pub fn plan_vault_withdraw(
        &self,
        amount: u64,
        dest: &str,
        fee: u64,
        sig_hex: &str,
    ) -> Result<vault::WithdrawPlan, String> {
        let vp = self
            .effective_vault_pub()
            .ok_or("BTC vault pubkey not genesis-set")?;
        let plan = vault::coin_select(&self.vault_utxos, amount, dest, fee)?;
        let pk = hex::decode(&vp.pubkey_hex).map_err(|e| e.to_string())?;
        vault::verify_plan_sig(&pk, &plan, sig_hex)?;
        Ok(plan)
    }

    pub fn commit_vault_withdraw(&mut self, plan: &vault::WithdrawPlan, change_txid: &str, height: u64) {
        vault::apply_plan(&mut self.vault_utxos, plan, change_txid, height);
    }

    /// Spend vault inputs + credit change-to-pool from a dest-lock Kickoff.
    /// `require_spend`: new withdraws must hit a tracked UTXO; reconcile is idempotent.
    pub fn apply_kickoff_utxos(
        &mut self,
        parsed: &crate::btc_spv::ParsedTx,
        vault_spk: &[u8],
        height: u64,
        require_spend: bool,
    ) -> Result<(), String> {
        let mut spent = 0usize;
        for (txid, vout) in &parsed.inputs {
            let n0 = self.vault_utxos.len();
            self.vault_utxos
                .retain(|u| !(u.txid.eq_ignore_ascii_case(txid) && u.vout == *vout));
            if self.vault_utxos.len() != n0 {
                spent += 1;
            }
        }
        if spent == 0 {
            if require_spend {
                return Err("Kickoff does not spend a tracked vault UTXO".into());
            }
            return Ok(());
        }
        for (i, (sats, spk)) in parsed.outputs.iter().enumerate() {
            if i == 0 {
                continue;
            }
            if spk.as_slice() == vault_spk && *sats >= vault::DUST_SATS {
                self.vault_utxos.push(vault::VaultUtxo {
                    txid: parsed.txid_display.clone(),
                    vout: i as u32,
                    sats: *sats,
                    height,
                });
            }
        }
        Ok(())
    }

    /// Full-pool move (FROST → NUMS). Credits every output that pays `pool_spk`,
    /// including vout0 (unlike Kickoff, where vout0 is dest-lock).
    pub fn apply_pool_move_utxos(
        &mut self,
        parsed: &crate::btc_spv::ParsedTx,
        pool_spk: &[u8],
        height: u64,
        require_spend: bool,
    ) -> Result<(), String> {
        let mut spent = 0usize;
        for (txid, vout) in &parsed.inputs {
            let n0 = self.vault_utxos.len();
            self.vault_utxos
                .retain(|u| !(u.txid.eq_ignore_ascii_case(txid) && u.vout == *vout));
            if self.vault_utxos.len() != n0 {
                spent += 1;
            }
        }
        if spent == 0 {
            if require_spend {
                return Err("pool move does not spend a tracked vault UTXO".into());
            }
            return Ok(());
        }
        for (i, (sats, spk)) in parsed.outputs.iter().enumerate() {
            if spk.as_slice() == pool_spk && *sats >= vault::DUST_SATS {
                self.vault_utxos.push(vault::VaultUtxo {
                    txid: parsed.txid_display.clone(),
                    vout: i as u32,
                    sats: *sats,
                    height,
                });
            }
        }
        Ok(())
    }

    pub fn reconcile_kickoffs(&mut self) {
        let Some(vp) = self.effective_vault_pub().cloned() else {
            return;
        };
        let Ok(spk) = hex::decode(vp.spk_hex.trim()) else {
            return;
        };
        let txs: Vec<String> = self.signed_vault_txs.values().cloned().collect();
        for raw in txs {
            let Ok(bytes) = crate::btc_spv::hex_decode(&raw) else {
                continue;
            };
            let Ok(parsed) = crate::btc_spv::parse_tx(&bytes) else {
                continue;
            };
            let _ = self.apply_kickoff_utxos(&parsed, &spk, 0, false);
        }
    }

    /// Verify deposit proof against a known header; mark spent.
    pub fn verify_and_mint(
        &mut self,
        amount: u64,
        proof: &BridgeProof,
        confirm_tip: u64,
        credit_to: Option<&str>,
    ) -> Result<(), String> {
        if amount == 0 {
            return Err("deposit amount 0".into());
        }
        if proof.external_txid.is_empty() {
            return Err("missing external_txid".into());
        }
        if self.spent_deposits.contains(&proof.external_txid) {
            return Err("deposit already spent".into());
        }
        if !proof.lock_id.is_empty() && proof.lock_id != self.lock_id {
            return Err("lock_id mismatch".into());
        }
        let hdr = self
            .headers
            .get(&proof.height)
            .cloned()
            .ok_or_else(|| format!("no header at height {}", proof.height))?;
        if !proof.block_hash.is_empty() && !btc_spv::hex_eq(&proof.block_hash, &hdr.hash) {
            return Err("block_hash mismatch".into());
        }
        let confs = confirm_tip.saturating_sub(proof.height).saturating_add(1);
        let min_conf = std::env::var("FPL_BTC_MIN_CONFIRMATIONS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(self.min_confirmations);
        if confs < min_conf {
            return Err(format!(
                "need {} confs have {confs}",
                min_conf
            ));
        }
        if self.is_btc() {
            self.verify_btc_proof(amount, proof, &hdr, credit_to)?;
        } else if crate::evm_spv::is_evm_rail(&self.asset) {
            return Err("ETH/USDC mint is ETH LC only (use BridgeState::mint_evm_lc)".into());
        } else {
            let leaf = sha256_hex(
                format!("{}|{}|{}", proof.external_txid, amount, self.lock_id).as_bytes(),
            );
            let root = merkle_root_protocol(&leaf, &proof.merkle_path, proof.merkle_index);
            let expected = if !proof.merkle_root.is_empty() {
                proof.merkle_root.clone()
            } else {
                hdr.merkle_root.clone()
            };
            if root != expected && root != hdr.merkle_root {
                return Err("merkle root mismatch".into());
            }
        }
        self.spent_deposits.insert(proof.external_txid.clone());
        self.total_minted = self.total_minted.saturating_add(amount);
        Ok(())
    }

    fn verify_evm_proof(
        &self,
        amount: u64,
        proof: &BridgeProof,
        hdr: &RailHeader,
        credit_to: Option<&str>,
    ) -> Result<(), String> {
        let dest = credit_to.unwrap_or("").trim();
        if dest.is_empty() {
            return Err("EVM deposit needs dest account".into());
        }
        let token = if proof.external_to.is_empty() {
            crate::evm_spv::default_token(&self.asset).to_string()
        } else {
            proof.external_to.clone()
        };
        if self.asset == RAIL_USDC {
            let want = crate::evm_spv::default_token(RAIL_USDC);
            let got = token.trim().trim_start_matches("0x").trim_start_matches("0X");
            if !got.eq_ignore_ascii_case(want) {
                return Err("USDC token address mismatch".into());
            }
        }
        let leaf = crate::evm_spv::deposit_leaf_hex(
            &proof.external_txid,
            proof.merkle_index,
            &token,
            dest,
            amount,
            &self.lock_id,
        );
        let root = crate::evm_spv::merkle_root_binary(&leaf, &proof.merkle_path, proof.merkle_index)?;
        let expected = if !proof.merkle_root.is_empty() {
            proof.merkle_root.clone()
        } else {
            hdr.merkle_root.clone()
        };
        if !root.eq_ignore_ascii_case(&expected) && !root.eq_ignore_ascii_case(&hdr.merkle_root) {
            return Err("EVM merkle root mismatch".into());
        }
        Ok(())
    }

    fn verify_btc_proof(
        &self,
        amount: u64,
        proof: &BridgeProof,
        hdr: &RailHeader,
        credit_to: Option<&str>,
    ) -> Result<(), String> {
        if hdr.raw.is_empty() {
            return Err("BTC deposit needs a Bitcoin header at that height".into());
        }
        if proof.raw_tx.is_empty() {
            return Err("BTC deposit needs raw Bitcoin tx".into());
        }
        let raw = btc_spv::hex_decode(&proof.raw_tx)?;
        let tx = btc_spv::parse_tx(&raw)?;
        if !btc_spv::hex_eq(&tx.txid_display, &proof.external_txid) {
            return Err("raw txid mismatch".into());
        }
        let siblings = btc_spv::siblings_from_path(&proof.merkle_path)?;
        btc_spv::verify_merkle(
            &tx.txid_display,
            &siblings,
            proof.merkle_index,
            &hdr.merkle_root,
        )?;
        if let Some(seed) = &self.take_seed {
            if let Ok(uv) = crate::user_vault::extract_deposit(&tx, seed, crate::user_vault::USER_VAULT_CSV)
            {
                if uv.value_sats != amount {
                    return Err(format!("BTC amount want {} got {}", amount, uv.value_sats));
                }
                if let Some(to) = credit_to {
                    if uv.fpl_dest20 != btc_spv::dest_id20(to) {
                        return Err("FALC dest does not match claim account".into());
                    }
                }
                return Ok(());
            }
        }
        let mut dest_spks: Vec<Vec<u8>> = Vec::new();
        if let Some(spk) = self.bitvm2_instance_spk.as_ref() {
            dest_spks.push(spk.clone());
        }
        // Network 2300 BitVM2 instance (tb1p2xuek…). Overlay env is optional;
        // without this, packers treat instance peg-ins as "no output to watch"
        // and the wallet times out on Claim FBTC.
        const NETWORK_2300_BITVM2_INSTANCE_SPK: &str =
            "512051b99b1a94717ff365ea891fe7fd3155acf11fd19b341865fd723d4fffdf2c5f";
        if let Ok(spk) = btc_spv::hex_decode(NETWORK_2300_BITVM2_INSTANCE_SPK) {
            if !dest_spks.iter().any(|s| s == &spk) {
                dest_spks.push(spk);
            }
        }
        if let Some(vp) = self.effective_vault_pub() {
            if !vp.spk_hex.is_empty() {
                dest_spks.push(btc_spv::hex_decode(&vp.spk_hex)?);
            }
        }
        if dest_spks.is_empty() {
            return Err("BTC vault identity not set — refuse mint (no tb1q7dnl fallback)".into());
        }
        let mut extracted = None;
        let mut last_err = String::new();
        for spk in &dest_spks {
            match btc_spv::extract_deposit(&tx, spk) {
                Ok(e) => {
                    extracted = Some(e);
                    break;
                }
                Err(e) => last_err = e,
            }
        }
        let extracted = extracted.ok_or(last_err)?;
        if extracted.value_sats != amount {
            return Err(format!(
                "BTC amount want {} got {}",
                extracted.value_sats, amount
            ));
        }
        if let Some(to) = credit_to {
            if extracted.dest_id20 != btc_spv::dest_id20(to) {
                return Err("FALC dest does not match claim account".into());
            }
        }
        Ok(())
    }

    pub fn last_deposit_vout(proof: &BridgeProof) -> u32 {
        // vout 0 unless the raw tx says otherwise; rail_deposit re-extracts.
        let _ = proof;
        0
    }

    pub fn withdraw(
        &mut self,
        from: &str,
        amount: u64,
        external_to: &str,
        falcon_height: u64,
    ) -> Result<String, String> {
        if amount == 0 || external_to.is_empty() {
            return Err("withdraw bad args".into());
        }
        let note_id = if self.is_btc() {
            btc_withdraw_note_id(from, amount, external_to)
        } else {
            sha256_hex(
                format!("wd:{}:{}:{}:{}", self.asset, from, amount, falcon_height).as_bytes(),
            )
        };
        if self.withdrawals.contains_key(&note_id) {
            return Err("duplicate withdraw note".into());
        }
        self.total_burned = self.total_burned.saturating_add(amount);
        self.withdrawals.insert(
            note_id.clone(),
            (amount, external_to.to_string(), from.to_string()),
        );
        Ok(note_id)
    }

    /// Open a dest-locked BitVM claim. `abort_preimage` stays local; only the commit is public.
    pub fn open_bitvm_claim(
        &mut self,
        note_id: &str,
        from: &str,
        dest: &str,
        amount: u64,
        abort_preimage: [u8; 32],
        height: u64,
        csv: u32,
    ) -> Result<BitvmClaim, String> {
        if self.bitvm_claims.contains_key(note_id) {
            return Err("bitvm claim exists".into());
        }
        let dest_h160 = bitvm::dest_h160_from_address(dest)?;
        let commit = bitvm::abort_commit(&abort_preimage);
        let ws = bitvm::claim_witness_script(&commit, &dest_h160, csv)?;
        let claim = BitvmClaim {
            note_id: note_id.to_string(),
            from: from.to_string(),
            dest: dest.to_string(),
            dest_h160: hex::encode(dest_h160),
            amount,
            abort_commit: hex::encode(commit),
            csv_blocks: csv,
            open_height: height,
            status: ClaimStatus::Pending,
            challenge_by: None,
            published_abort: String::new(),
            claim_spk_hex: bitvm::p2wsh_spk_hex(&ws),
        };
        self.abort_secrets.insert(note_id.to_string(), abort_preimage);
        self.bitvm_claims.insert(note_id.to_string(), claim.clone());
        let leaf = bitvm::withdraw_leaf(note_id, &dest_h160, amount);
        self.claim_leaves.push(hex::encode(leaf));
        let leaves: Vec<[u8; 32]> = self
            .claim_leaves
            .iter()
            .filter_map(|h| {
                let b = hex::decode(h).ok()?;
                if b.len() != 32 {
                    return None;
                }
                let mut a = [0u8; 32];
                a.copy_from_slice(&b);
                Some(a)
            })
            .collect();
        if !leaves.is_empty() {
            let idx = leaves.len() - 1;
            if let Ok((root, _)) = crate::evm_spv::build_tree(&leaves, idx) {
                self.claim_root = root;
            }
        }
        Ok(claim)
    }

    /// Open a BitVM2 withdraw (no Kickoff). Operator fronts BTC + posts Claim.
    pub fn open_bitvm2_withdraw(
        &mut self,
        note_id: &str,
        from: &str,
        dest: &str,
        amount: u64,
        height: u64,
    ) -> Result<crate::bitvm2_exit::Bitvm2Claim, String> {
        if self.bitvm2_claims.contains_key(note_id) {
            return Err("bitvm2 claim exists".into());
        }
        let dest_h160 = bitvm::dest_h160_from_address(dest)?;
        crate::bitvm2_exit::append_mimc_leaf(
            &mut self.bitvm2_claim_leaves,
            note_id,
            &dest_h160,
            amount,
        );
        self.bitvm2_claim_root = crate::bitvm2_exit::mimc_root_from_leaves(&self.bitvm2_claim_leaves)?;
        let leaf_hex = crate::bitvm2_exit::mimc_leaf_hex(note_id, &dest_h160, amount);
        let claim = crate::bitvm2_exit::Bitvm2Claim {
            note_id: note_id.to_string(),
            from: from.to_string(),
            dest: dest.to_string(),
            amount,
            open_height: height,
            status: crate::bitvm2_exit::Bitvm2Status::AwaitingPegout,
            mimc_leaf_hex: leaf_hex,
            pegout_txid_hex: String::new(),
            claim_txid_hex: String::new(),
            claim_id: String::new(),
            statement_digest_hex: String::new(),
            proof_hex: String::new(),
            public_hex: Vec::new(),
            operator: String::new(),
            checkpoint_height: 0,
            pegout_btc_height: 0,
            attest_height: 0,
        };
        self.bitvm2_claims
            .insert(note_id.to_string(), claim.clone());
        Ok(claim)
    }

    /// Operator recorded a Bitcoin peg-out tx (Phase D production).
    pub fn record_bitvm2_pegout(
        &mut self,
        note_id: &str,
        operator: &str,
        pegout_txid_hex: &str,
    ) -> Result<(), String> {
        let c = self
            .bitvm2_claims
            .get_mut(note_id)
            .ok_or_else(|| "no bitvm2 claim".to_string())?;
        if c.status != crate::bitvm2_exit::Bitvm2Status::AwaitingPegout {
            return Err("bitvm2 claim not awaiting pegout".into());
        }
        let _ = crate::bitvm2_exit::pegout_txid_bytes(pegout_txid_hex)?;
        c.status = crate::bitvm2_exit::Bitvm2Status::PegoutPosted;
        c.pegout_txid_hex = pegout_txid_hex.trim().to_ascii_lowercase();
        if !operator.is_empty() {
            c.operator = operator.to_string();
        }
        Ok(())
    }

    pub fn attest_bitvm2_claim(
        &mut self,
        note_id: &str,
        operator: &str,
        pegout_txid_hex: &str,
        claim_txid_hex: &str,
        proof_hex: &str,
        public_hex: &[String],
        statement_digest_hex: &str,
        tip_height: u64,
        tip_hash: &str,
    ) -> Result<(), String> {
        let c = self
            .bitvm2_claims
            .get(note_id)
            .ok_or_else(|| "no bitvm2 claim".to_string())?
            .clone();
        if c.status != crate::bitvm2_exit::Bitvm2Status::AwaitingPegout
            && c.status != crate::bitvm2_exit::Bitvm2Status::PegoutPosted
        {
            return Err("bitvm2 claim not awaiting attest".into());
        }
        let dest_h160 = bitvm::dest_h160_from_address(&c.dest)?;
        let pegout = crate::bitvm2_exit::pegout_txid_bytes(pegout_txid_hex)?;
        let header = crate::bitvm2_exit::header_hash_placeholder(tip_height, tip_hash);
        crate::bitvm2_exit::verify_attest(
            note_id,
            &dest_h160,
            c.amount,
            tip_height,
            &header,
            &pegout,
            &self.bitvm2_claim_leaves,
            proof_hex,
            public_hex,
            statement_digest_hex,
        )?;
        self.apply_bitvm2_attest(
            note_id,
            operator,
            pegout_txid_hex,
            claim_txid_hex,
            proof_hex,
            public_hex,
            statement_digest_hex,
        )
    }

    /// M1: record the parent ledger as a checkpoint when the ledger at
    /// `height` is applied (pack, verify and commit all call this on the draft
    /// bridge with the current tip hash). Deterministic: every seat applies the
    /// same (height, parent hash).
    pub fn record_fpl_checkpoint(&mut self, height: u64, parent_hash: &str) {
        let iv = crate::bitvm2_exit::BITVM2_CHECKPOINT_INTERVAL;
        if height == 0 || height % iv != 0 || parent_hash.is_empty() {
            return;
        }
        self.fpl_checkpoints
            .insert(height - 1, parent_hash.to_ascii_lowercase());
        while self.fpl_checkpoints.len() > crate::bitvm2_exit::BITVM2_CHECKPOINT_KEEP {
            let first = *self.fpl_checkpoints.keys().next().expect("non-empty");
            self.fpl_checkpoints.remove(&first);
        }
    }

    /// M1 attestation: the Groth16 proof is bound to a consensus FPL
    /// checkpoint (not the verifier's tip), verified with the fixed ceremony
    /// VK, and the Bitcoin peg-out must be included in a block on this rail
    /// with `BITVM2_PEGOUT_MIN_CONFS` and pay the burn amount to the claim's
    /// dest (or its dest-lock). A peg-out txid backs at most one claim.
    pub fn attest_bitvm2_claim_v2(
        &mut self,
        a: &Bitvm2AttestV2,
        operator: &str,
        vk_bytes: &[u8],
        applying_height: u64,
    ) -> Result<(), String> {
        if vk_bytes.is_empty() {
            return Err("bitvm2 v2: no ceremony verifying key in this release".into());
        }
        let c = self
            .bitvm2_claims
            .get(&a.note_id)
            .ok_or_else(|| "no bitvm2 claim".to_string())?
            .clone();
        if c.status != crate::bitvm2_exit::Bitvm2Status::AwaitingPegout
            && c.status != crate::bitvm2_exit::Bitvm2Status::PegoutPosted
        {
            return Err("bitvm2 claim not awaiting attest".into());
        }
        // FPL checkpoint: recorded in consensus state, after the burn, final.
        let ckpt_hash = self
            .fpl_checkpoints
            .get(&a.checkpoint_height)
            .cloned()
            .ok_or_else(|| format!("no FPL checkpoint at {}", a.checkpoint_height))?;
        if a.checkpoint_height < c.open_height {
            return Err("checkpoint is before the burn".into());
        }
        if a.checkpoint_height.saturating_add(crate::bitvm2_exit::BITVM2_CHECKPOINT_FINALITY)
            > applying_height
        {
            return Err("checkpoint not final".into());
        }
        // Bitcoin inclusion against the rail's header chain.
        let hdr = self
            .headers
            .get(&a.btc_height)
            .cloned()
            .ok_or_else(|| format!("no BTC header at {}", a.btc_height))?;
        if hdr.raw.is_empty() {
            return Err("BTC header at that height has no raw header".into());
        }
        let confs = self.tip_height.saturating_sub(a.btc_height).saturating_add(1);
        if self.tip_height < a.btc_height || confs < crate::bitvm2_exit::BITVM2_PEGOUT_MIN_CONFS {
            return Err(format!(
                "peg-out needs {} confs, has {}",
                crate::bitvm2_exit::BITVM2_PEGOUT_MIN_CONFS,
                if self.tip_height < a.btc_height { 0 } else { confs }
            ));
        }
        let raw = btc_spv::hex_decode(&a.pegout_raw_tx_hex)?;
        let tx = btc_spv::parse_tx(&raw)?;
        let pegout_display = tx.txid_display.to_ascii_lowercase();
        let siblings = btc_spv::siblings_from_path(&a.merkle_path)?;
        btc_spv::verify_merkle(&tx.txid_display, &siblings, a.merkle_index, &hdr.merkle_root)?;
        // One peg-out backs one claim.
        if self.bitvm2_claims.values().any(|o| {
            o.note_id != a.note_id && o.pegout_txid_hex.eq_ignore_ascii_case(&pegout_display)
        }) {
            return Err("peg-out already backs another claim".into());
        }
        // The peg-out pays exactly the burn amount to the dest (or its dest-lock).
        let dest_h160 = bitvm::dest_h160_from_address(&c.dest)?;
        let mut want: Vec<Vec<u8>> = Vec::new();
        if let Ok((_k, spk)) = crate::btc_tx::decode_address(&c.dest) {
            want.push(spk);
        }
        if !a.dest_lock_abort_commit_hex.is_empty() {
            let raw_c = btc_spv::hex_decode(&a.dest_lock_abort_commit_hex)?;
            if raw_c.len() != 32 {
                return Err("abort commit must be 32 bytes".into());
            }
            let mut commit = [0u8; 32];
            commit.copy_from_slice(&raw_c);
            let (_ws, lock) = crate::bitvm2_instance::dest_lock_spk(
                &commit,
                &dest_h160,
                bitvm::CLAIM_CSV_BLOCKS,
            )?;
            want.push(lock);
        }
        if !tx
            .outputs
            .iter()
            .any(|(sats, spk)| *sats == c.amount && want.iter().any(|w| w == spk))
        {
            return Err("peg-out does not pay the burn amount to the claim dest".into());
        }
        let pegout = crate::bitvm2_exit::pegout_txid_bytes(&pegout_display)?;
        let header = crate::bitvm2_exit::checkpoint_header_hash(a.checkpoint_height, &ckpt_hash);
        crate::bitvm2_exit::verify_withdraw_attest_vk_bytes(
            vk_bytes,
            &a.note_id,
            &dest_h160,
            c.amount,
            a.checkpoint_height,
            &header,
            &pegout,
            &self.bitvm2_claim_leaves,
            &a.proof_hex,
            &a.public_hex,
            &a.statement_digest_hex,
        )?;
        self.apply_bitvm2_attest(
            &a.note_id,
            operator,
            &pegout_display,
            &a.claim_txid_hex,
            &a.proof_hex,
            &a.public_hex,
            &a.statement_digest_hex,
        )?;
        if let Some(cl) = self.bitvm2_claims.get_mut(&a.note_id) {
            cl.checkpoint_height = a.checkpoint_height;
            cl.pegout_btc_height = a.btc_height;
            cl.attest_height = applying_height;
        }
        Ok(())
    }

    /// M1 Disprove: re-verify the **stored** attestation (fixed VK, stored
    /// checkpoint). Disproved only if the stored proof fails. Submitted proof
    /// bytes are ignored, so a garbage submission can no longer disprove an
    /// honest claim.
    pub fn disprove_bitvm2_v2(&mut self, note_id: &str, vk_bytes: &[u8]) -> Result<bool, String> {
        if vk_bytes.is_empty() {
            return Err("bitvm2 v2: no ceremony verifying key in this release".into());
        }
        let c = self
            .bitvm2_claims
            .get(note_id)
            .ok_or_else(|| "no bitvm2 claim".to_string())?
            .clone();
        if c.status != crate::bitvm2_exit::Bitvm2Status::Challenged
            && c.status != crate::bitvm2_exit::Bitvm2Status::ClaimPosted
        {
            return Err("bitvm2 claim not in assert/challenge".into());
        }
        if c.checkpoint_height == 0 {
            return Err("claim has no M1 attestation".into());
        }
        let ckpt_hash = self
            .fpl_checkpoints
            .get(&c.checkpoint_height)
            .cloned()
            .ok_or_else(|| "attested checkpoint no longer in state".to_string())?;
        let dest_h160 = bitvm::dest_h160_from_address(&c.dest)?;
        let pegout = crate::bitvm2_exit::pegout_txid_bytes(&c.pegout_txid_hex)?;
        let header = crate::bitvm2_exit::checkpoint_header_hash(c.checkpoint_height, &ckpt_hash);
        match crate::bitvm2_exit::verify_withdraw_attest_vk_bytes(
            vk_bytes,
            note_id,
            &dest_h160,
            c.amount,
            c.checkpoint_height,
            &header,
            &pegout,
            &self.bitvm2_claim_leaves,
            &c.proof_hex,
            &c.public_hex,
            &c.statement_digest_hex,
        ) {
            Ok(()) => Ok(false),
            Err(_) => {
                if let Some(cl) = self.bitvm2_claims.get_mut(note_id) {
                    cl.status = crate::bitvm2_exit::Bitvm2Status::Disproved;
                }
                Ok(true)
            }
        }
    }

    /// Apply attestation after off-thread verify.
    pub fn apply_bitvm2_attest(
        &mut self,
        note_id: &str,
        operator: &str,
        pegout_txid_hex: &str,
        claim_txid_hex: &str,
        proof_hex: &str,
        public_hex: &[String],
        statement_digest_hex: &str,
    ) -> Result<(), String> {
        let c = self
            .bitvm2_claims
            .get(note_id)
            .ok_or_else(|| "no bitvm2 claim".to_string())?
            .clone();
        if c.status != crate::bitvm2_exit::Bitvm2Status::AwaitingPegout
            && c.status != crate::bitvm2_exit::Bitvm2Status::PegoutPosted
        {
            return Err("bitvm2 claim not awaiting attest".into());
        }
        let pegout_display = pegout_txid_hex.trim().to_ascii_lowercase();
        let cid = crate::bitvm2_exit::bitvm2_claim_id(operator, note_id, &pegout_display);
        let updated = crate::bitvm2_exit::Bitvm2Claim {
            status: crate::bitvm2_exit::Bitvm2Status::ClaimPosted,
            pegout_txid_hex: pegout_display,
            claim_txid_hex: claim_txid_hex.trim().to_ascii_lowercase(),
            claim_id: cid,
            statement_digest_hex: statement_digest_hex.trim().to_ascii_lowercase(),
            proof_hex: proof_hex.trim().to_string(),
            public_hex: public_hex.to_vec(),
            operator: operator.to_string(),
            ..c
        };
        self.bitvm2_claims
            .insert(note_id.to_string(), updated);
        Ok(())
    }

    pub fn kickoff_ok(&self, note_id: &str, vout0_spk_hex: &str) -> Result<(), String> {
        let c = self
            .bitvm_claims
            .get(note_id)
            .ok_or_else(|| "no bitvm claim".to_string())?;
        let dest = bitvm::dest_h160_from_address(&c.dest)?;
        let mut commit = [0u8; 32];
        commit.copy_from_slice(&hex::decode(&c.abort_commit).map_err(|e| e.to_string())?);
        let mut root = [0u8; 32];
        if self.claim_root.len() != 64 {
            return Err("empty claim_root".into());
        }
        root.copy_from_slice(&hex::decode(&self.claim_root).map_err(|e| e.to_string())?);
        let leaves: Vec<[u8; 32]> = self
            .claim_leaves
            .iter()
            .filter_map(|h| {
                let b = hex::decode(h).ok()?;
                let mut a = [0u8; 32];
                a.copy_from_slice(&b);
                Some(a)
            })
            .collect();
        let idx = leaves
            .iter()
            .position(|l| hex::encode(l) == hex::encode(bitvm::withdraw_leaf(note_id, &dest, c.amount)))
            .ok_or("leaf missing")?;
        let (_r, path) = crate::evm_spv::build_tree(&leaves, idx)?;
        let spk = hex::decode(vout0_spk_hex).map_err(|e| e.to_string())?;
        bitvm::kickoff_valid(
            note_id,
            &dest,
            c.amount,
            &root,
            &path,
            idx as u32,
            &spk,
            &commit,
            c.csv_blocks,
        )
    }

    /// Permissionless challenge: observed Bitcoin dest/amount must differ from the claim.
    pub fn challenge_claim(
        &mut self,
        note_id: &str,
        observed_dest: &str,
        observed_amount: u64,
        by: &str,
        now_height: u64,
        abort_keys_dir: Option<&std::path::Path>,
    ) -> Result<[u8; 32], String> {
        if self.bitvm2_claims.contains_key(note_id) {
            return self.challenge_bitvm2(note_id, observed_dest, observed_amount, by);
        }
        let claim = self
            .bitvm_claims
            .get(note_id)
            .ok_or_else(|| "no bitvm claim".to_string())?
            .clone();
        if claim.status != ClaimStatus::Pending {
            return Err("claim not pending".into());
        }
        let dest_match = observed_dest.trim().eq_ignore_ascii_case(claim.dest.trim());
        let amt_match = observed_amount == claim.amount;
        if dest_match && amt_match {
            return Err("honest claim — grief challenge rejected".into());
        }
        if let Some(dir) = abort_keys_dir {
            if let Ok(s) = bitvm::read_abort_secret(dir, note_id) {
                self.abort_secrets.insert(note_id.to_string(), s);
            }
        }
        let secret = self
            .abort_secrets
            .get(note_id)
            .copied()
            .ok_or_else(|| "abort preimage missing on this node".to_string())?;
        let c = self.bitvm_claims.get_mut(note_id).unwrap();
        c.status = ClaimStatus::Challenged;
        c.challenge_by = Some(by.to_string());
        c.published_abort = hex::encode(secret);
        let _ = now_height;
        Ok(secret)
    }

    /// Visible fraud on a BitVM2 Kickoff (wrong dest/amount). No abort preimage.
    pub fn challenge_bitvm2(
        &mut self,
        note_id: &str,
        observed_dest: &str,
        observed_amount: u64,
        by: &str,
    ) -> Result<[u8; 32], String> {
        let c = self
            .bitvm2_claims
            .get_mut(note_id)
            .ok_or_else(|| "no bitvm2 claim".to_string())?;
        if c.status != crate::bitvm2_exit::Bitvm2Status::AwaitingPegout
            && c.status != crate::bitvm2_exit::Bitvm2Status::PegoutPosted
            && c.status != crate::bitvm2_exit::Bitvm2Status::ClaimPosted
        {
            return Err("bitvm2 claim not challengeable".into());
        }
        let dest_match = observed_dest.trim().eq_ignore_ascii_case(c.dest.trim());
        let amt_match = observed_amount == c.amount;
        if dest_match && amt_match {
            return Err("honest bitvm2 claim — grief challenge rejected".into());
        }
        c.status = crate::bitvm2_exit::Bitvm2Status::Challenged;
        c.operator = by.to_string();
        Ok([0u8; 32])
    }

    /// Groth16 Disprove: invalid attest → Disproved. Valid proof is not disproved.
    pub fn disprove_bitvm2(
        &mut self,
        note_id: &str,
        proof_hex: &str,
        public_hex: &[String],
        statement_digest_hex: &str,
        tip_height: u64,
        tip_hash: &str,
    ) -> Result<bool, String> {
        let c = self
            .bitvm2_claims
            .get(note_id)
            .ok_or_else(|| "no bitvm2 claim".to_string())?
            .clone();
        if c.status != crate::bitvm2_exit::Bitvm2Status::Challenged
            && c.status != crate::bitvm2_exit::Bitvm2Status::ClaimPosted
        {
            return Err("bitvm2 claim not in assert/challenge".into());
        }
        let dest_h160 = bitvm::dest_h160_from_address(&c.dest)?;
        let pegout = crate::bitvm2_exit::pegout_txid_bytes(&c.pegout_txid_hex)
            .unwrap_or([0u8; 32]);
        let header = crate::bitvm2_exit::header_hash_placeholder(tip_height, tip_hash);
        match crate::bitvm2_exit::verify_attest(
            note_id,
            &dest_h160,
            c.amount,
            tip_height,
            &header,
            &pegout,
            &self.bitvm2_claim_leaves,
            proof_hex,
            public_hex,
            statement_digest_hex,
        ) {
            Ok(()) => Ok(false),
            Err(_) => {
                if let Some(c) = self.bitvm2_claims.get_mut(note_id) {
                    c.status = crate::bitvm2_exit::Bitvm2Status::Disproved;
                }
                Ok(true)
            }
        }
    }

    /// ETH/USDC: append a withdraw leaf (Solidity-compatible) to claim_root.
    pub fn record_evm_withdraw(
        &mut self,
        note_id: &str,
        dest_eth: &str,
        amount: u64,
        usdc: bool,
    ) -> Result<[u8; 32], String> {
        let dest20 = crate::evm_spv::parse_eth_addr(dest_eth)?;
        let mut note = [0u8; 32];
        let nb = hex::decode(note_id.trim()).map_err(|e| e.to_string())?;
        if nb.len() != 32 {
            return Err("note_id must be 32-byte hex".into());
        }
        note.copy_from_slice(&nb);
        let leaf = crate::evm_spv::withdraw_leaf(&note, &dest20, amount, usdc);
        self.claim_leaves.push(hex::encode(leaf));
        let leaves: Vec<[u8; 32]> = self
            .claim_leaves
            .iter()
            .filter_map(|h| {
                let b = hex::decode(h).ok()?;
                let mut a = [0u8; 32];
                a.copy_from_slice(&b);
                Some(a)
            })
            .collect();
        if !leaves.is_empty() {
            let idx = leaves.len() - 1;
            if let Ok((root, _)) = crate::evm_spv::build_tree(&leaves, idx) {
                self.claim_root = root;
            }
        }
        Ok(leaf)
    }

    pub fn finalize_claims(&mut self, tip: u64, window: u64) {
        for c in self.bitvm_claims.values_mut() {
            if c.status == ClaimStatus::Pending && tip.saturating_sub(c.open_height) >= window {
                c.status = ClaimStatus::Final;
            }
        }
    }

    pub fn refund_challenged(&self, note_id: &str) -> Option<(String, u64)> {
        if let Some(c) = self.bitvm_claims.get(note_id) {
            if c.status == ClaimStatus::Challenged {
                return Some((c.from.clone(), c.amount));
            }
        }
        if let Some(c) = self.bitvm2_claims.get(note_id) {
            if c.status == crate::bitvm2_exit::Bitvm2Status::Challenged
                || c.status == crate::bitvm2_exit::Bitvm2Status::Disproved
            {
                return Some((c.from.clone(), c.amount));
            }
        }
        None
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BridgeState {
    pub rails: BTreeMap<String, RailState>,
    /// Sepolia sync-committee LC. Shared by ETH and USDC.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub eth_lc: Option<crate::eth_lc::EthLcState>,
    /// Execution headers linking deposit blocks to the LC head.
    ///
    /// v2.9.56: shared copy-on-write (`Arc`). Until v2.9.60 the map was never
    /// pruned (~126k headers / ~200 MB JSON on testnet 2300 by 2026-10-08) and
    /// the whole `BridgeState` is cloned for every pack / verify / commit
    /// draft and for every mempool head dry-run. With `Arc` a clone is a
    /// refcount bump; [`Self::eth_add_exec_headers`] copies via `Arc::make_mut`,
    /// and [`Self::prune_eth_exec_headers`] replaces the map only when a
    /// header is removed.
    /// Serde serializes the map exactly as a `BTreeMap`, so snapshots, wire
    /// bodies and the commitment root stay byte-identical when the contents
    /// do not change.
    ///
    /// v2.9.58: [`crate::exec_map::ExecHeaderMap`] (same `Arc`, plus a content
    /// generation and a cached canonical JSON encoding used by the commitment
    /// root and snapshot writer). Serialization of the map is unchanged.
    #[serde(default, skip_serializing_if = "exec_headers_empty")]
    pub eth_exec_headers: crate::exec_map::ExecHeaderMap,
    /// Lowest execution number still eligible to mint. `0` means the window
    /// has not armed (pre-activation, or a hash-only Gloas head that has not
    /// resolved). Omitted from serde while zero so pre-activation snapshots
    /// and the commitment root stay byte-identical to 2.9.59. Once non-zero
    /// it is part of the state root. Monotonic: it never decreases.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub eth_exec_prune_floor: u64,
    /// Execution-block number at which V1/V2/DestLock deposits close.
    /// `0` until the first V3-active ledger whose LC head number is resolved
    /// (`execution_number != 0`). Set once, never lowered. Omitted while zero
    /// so pre-H2 snapshots and the commitment root stay byte-identical to
    /// 2.9.60. A V1 mint with `proof.height > cutoff` is rejected; heights at
    /// or below the cutoff still mint while the header is inside the window.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub eth_v1_deposit_cutoff: u64,
    /// depositId (lowercase hex, no `0x`) → the one mint or refund.
    /// Omitted while empty so pre-H2 bytes match 2.9.60. Part of the state
    /// root once a deposit has resolved. Snapshot adopt loads it with the
    /// rest of `BridgeState` (same path as [`Self::eth_exec_prune_floor`]).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub eth_v3_deposits: BTreeMap<String, V3Resolution>,
    /// BRIDGE: BitVM2 operator registry (bonds, liveness, capacity adverts,
    /// graph bindings, slashes). Omitted while empty, so the commitment root and
    /// snapshots are byte-identical until the first `OperatorRegister` (which is
    /// refused before the bridge height). Part of the state root once used.
    #[serde(default, skip_serializing_if = "crate::operator_registry::OperatorRegistry::is_empty")]
    pub operators: crate::operator_registry::OperatorRegistry,
}

/// One resolved V3 deposit. Mint credits an FPL account and writes no claim
/// leaf. Refund appends an `evm-wd-v1` leaf to `sender` and does not credit.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum V3Resolution {
    Mint {
        asset: String,
        amount: u64,
        credit_to: String,
        eth_block: u64,
    },
    Refund {
        asset: String,
        amount: u64,
        /// Sender address, lowercase hex, no `0x`.
        refund_to: String,
        /// Hex of [`v3_refund_note_id`], no `0x`.
        note_id: String,
        eth_block: u64,
    },
}

/// What [`BridgeState::resolve_evm_v3_deposit`] did. The node credits a
/// balance only for [`V3Outcome::Mint`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum V3Outcome {
    Mint {
        asset: String,
        amount: u64,
        credit_to: String,
    },
    Refund {
        asset: String,
        amount: u64,
        refund_to: String,
        note_id: [u8; 32],
    },
}

fn exec_headers_empty(m: &crate::exec_map::ExecHeaderMap) -> bool {
    m.is_empty()
}

impl BridgeState {
    pub fn with_genesis_rails() -> Self {
        let mut s = Self::default();
        s.ensure_genesis();
        s
    }

    /// Insert any missing genesis rails (snapshot upgrade: USDC).
    pub fn ensure_genesis(&mut self) {
        for r in GENESIS_RAILS {
            self.rails
                .entry((*r).to_string())
                .or_insert_with(|| RailState::new(r));
        }
    }

    /// Idempotent: apply packed Kickoff spends that never updated `vault_utxos`.
    pub fn reconcile_btc_kickoff_utxos(&mut self) {
        if let Ok(r) = self.rail_mut(RAIL_BTC) {
            r.reconcile_kickoffs();
        }
    }

    pub fn eth_lc_bootstrap(&mut self, json: &str) -> Result<(), String> {
        if self.eth_lc.is_some() {
            return Err("ETH LC already bootstrapped".into());
        }
        let st = crate::eth_lc::apply_bootstrap(json)?;
        if st.genesis_validators_root
            != crate::eth_lc::SEPOLIA_GENESIS_VALIDATORS_ROOT
        {
            return Err("not Sepolia genesis validators root".into());
        }
        self.eth_lc = Some(st);
        Ok(())
    }

    pub fn eth_lc_update(&mut self, json: &str) -> Result<(), String> {
        let cur = self.eth_lc.as_ref().ok_or("ETH LC not bootstrapped")?;
        let st = crate::eth_lc::apply_update(cur, json)?;
        self.eth_lc = Some(st);
        Ok(())
    }

    /// Height-gated bootstrap (v2.9.60). `gloas = false` is [`Self::eth_lc_bootstrap`].
    pub fn eth_lc_bootstrap_ex(&mut self, json: &str, gloas: bool) -> Result<(), String> {
        if !gloas {
            return self.eth_lc_bootstrap(json);
        }
        if self.eth_lc.is_some() {
            return Err("ETH LC already bootstrapped".into());
        }
        let st = crate::eth_lc::apply_bootstrap_ex(json, true)?;
        if st.genesis_validators_root != crate::eth_lc::SEPOLIA_GENESIS_VALIDATORS_ROOT {
            return Err("not Sepolia genesis validators root".into());
        }
        self.eth_lc = Some(st);
        self.eth_lc_resolve_exec_head();
        self.prune_eth_exec_headers(true);
        Ok(())
    }

    /// Height-gated update (v2.9.60). `gloas = false` is [`Self::eth_lc_update`].
    pub fn eth_lc_update_ex(&mut self, json: &str, gloas: bool) -> Result<(), String> {
        if !gloas {
            return self.eth_lc_update(json);
        }
        let cur = self.eth_lc.as_ref().ok_or("ETH LC not bootstrapped")?;
        let st = crate::eth_lc::apply_update_ex(cur, json, true)?;
        self.eth_lc = Some(st);
        self.eth_lc_resolve_exec_head();
        self.prune_eth_exec_headers(true);
        Ok(())
    }

    /// Gloas LC headers prove only the execution block hash. Once the
    /// RLP-verified execution header with that hash is stored, copy its
    /// number and receipts root into the LC state so the mint ancestry walk
    /// (`n > execution_number` bound) and relayers see the real head.
    /// No-op unless `execution_number == 0` with a non-empty hash, which only
    /// a Gloas-rules update/bootstrap produces.
    pub fn eth_lc_resolve_exec_head(&mut self) {
        let Some(lc) = self.eth_lc.as_mut() else {
            return;
        };
        if lc.execution_number != 0 || lc.execution_block_hash.is_empty() {
            return;
        }
        let want = lc.execution_block_hash.trim_start_matches("0x");
        if let Some(h) = self
            .eth_exec_headers
            .values()
            .rev()
            .find(|h| h.hash.trim_start_matches("0x").eq_ignore_ascii_case(want))
        {
            lc.execution_number = h.number;
            lc.receipts_root = h
                .receipts_root
                .trim_start_matches("0x")
                .to_ascii_lowercase();
        }
    }

    /// Height-gated exec headers (v2.9.60): same checks as
    /// [`Self::eth_add_exec_headers`], then resolve a hash-only LC head.
    pub fn eth_add_exec_headers_ex(
        &mut self,
        headers: Vec<crate::eth_exec::EthExecHeader>,
        gloas: bool,
    ) -> Result<(), String> {
        self.eth_add_exec_headers(headers)?;
        if gloas {
            self.eth_lc_resolve_exec_head();
            self.prune_eth_exec_headers(true);
        }
        Ok(())
    }

    /// Drop execution headers below the rolling window measured from the LC
    /// head. `active` is false below the Gloas activation height: the method
    /// returns without touching state, so pre-activation bytes stay 2.9.59.
    ///
    /// The floor is only computed when `execution_number != 0`. A hash-only
    /// Gloas head (number not resolved yet) does not prune and does not move
    /// a floor that was already set. The new floor is
    /// `max(old, execution_number.saturating_sub(WINDOW))`, so it never
    /// decreases and a static LC head never deletes another header.
    ///
    /// An unchanged map keeps its generation and cached JSON. A removal
    /// replaces the map via [`crate::exec_map::ExecHeaderMap::pruned_below`]
    /// (headers with `number >= floor`). A repeated prune of the same source
    /// generation and floor reuses that map; contents stay the retain result.
    pub fn prune_eth_exec_headers(&mut self, active: bool) {
        if !active {
            return;
        }
        let Some(exec_n) = self.eth_lc.as_ref().map(|lc| lc.execution_number) else {
            return;
        };
        if exec_n == 0 {
            return;
        }
        let next = exec_n.saturating_sub(ETH_EXEC_HEADER_WINDOW);
        let floor = self.eth_exec_prune_floor.max(next);
        if floor != self.eth_exec_prune_floor {
            self.eth_exec_prune_floor = floor;
        }
        if floor == 0 {
            return;
        }
        if let Some(pruned) = self.eth_exec_headers.pruned_below(floor) {
            self.eth_exec_headers = pruned;
        }
    }

    /// One-off V1 close. `active` is `Node::eth_v3_at(height)`.
    ///
    /// Called from the same per-ledger hook as [`Self::prune_eth_exec_headers`]
    /// so pack, verify and commit hash the same cutoff. Does nothing until
    /// the LC head number is resolved, then sets `eth_v1_deposit_cutoff` to
    /// that number exactly once.
    pub fn arm_eth_v1_deposit_cutoff(&mut self, active: bool) {
        if !active || self.eth_v1_deposit_cutoff != 0 {
            return;
        }
        let Some(n) = self.eth_lc.as_ref().map(|lc| lc.execution_number) else {
            return;
        };
        if n == 0 {
            return;
        }
        self.eth_v1_deposit_cutoff = n;
    }

    /// LC-head unix time. Prefer the timestamp (RLP field 11) of the stored
    /// execution header whose hash is `lc.execution_block_hash`. If that
    /// header cannot be parsed, use Sepolia beacon genesis + 12s slots.
    pub fn eth_lc_head_unix_time(lc: &crate::eth_lc::EthLcState, head_rlp_hex: &str) -> u64 {
        let raw = head_rlp_hex
            .trim()
            .trim_start_matches("0x")
            .trim_start_matches("0X");
        if let Ok(rlp) = hex::decode(raw) {
            if let Ok(ts) = crate::eth_exec::exec_header_timestamp(&rlp) {
                return ts;
            }
        }
        SEPOLIA_BEACON_GENESIS_UNIX.saturating_add(12u64.saturating_mul(lc.finalized_slot))
    }

    /// Mint / refund counts. Walks the whole map, so it is for tests and
    /// offline tools, not for status (which reports the O(1) total).
    pub fn eth_v3_resolved_counts(&self) -> (u64, u64) {
        let mut mint = 0u64;
        let mut refund = 0u64;
        for r in self.eth_v3_deposits.values() {
            match r {
                V3Resolution::Mint { .. } => mint += 1,
                V3Resolution::Refund { .. } => refund += 1,
            }
        }
        (mint, refund)
    }

    /// One deposit's resolution, or `None` if `deposit_id` is unknown or not
    /// 32-byte hex. `deposit_id` may be `0x`-prefixed; the map key is lowercase
    /// hex without the prefix.
    pub fn eth_v3_resolution(&self, deposit_id: &str) -> Option<&V3Resolution> {
        let id = parse_v3_deposit_id(deposit_id).ok()?;
        self.eth_v3_deposits.get(&v3_deposit_id_hex(&id))
    }

    /// Status/read-only view of every V3 resolution, in map (depositId) order.
    /// Each entry is the serialized [`V3Resolution`] plus `deposit_id`. Not consensus:
    /// nothing here is hashed or snapshotted beyond `eth_v3_deposits` itself.
    pub fn eth_v3_resolutions_json(&self) -> Vec<serde_json::Value> {
        self.eth_v3_deposits
            .iter()
            .map(|(id, r)| {
                let mut v = serde_json::to_value(r).unwrap_or(serde_json::Value::Null);
                if let Some(obj) = v.as_object_mut() {
                    obj.insert("deposit_id".into(), serde_json::Value::String(id.clone()));
                }
                v
            })
            .collect()
    }

    /// V3 refund notes on `asset`'s rail as status `withdrawals` rows (same keys as a
    /// `RailWithdraw` row, plus `kind: "v3_refund"`, `deposit_id` and `eth_block`).
    /// A refund appends an `evm-wd-v1` claim leaf but no `RailState::withdrawals`
    /// entry, so without these rows the claim-proof tool cannot find the note.
    /// Status only: `RailState::withdrawals` and the state root are unchanged.
    pub fn eth_v3_refund_withdrawals_json(&self, asset: &str) -> Vec<serde_json::Value> {
        self.eth_v3_deposits
            .iter()
            .filter_map(|(id, r)| match r {
                V3Resolution::Refund {
                    asset: a,
                    amount,
                    refund_to,
                    note_id,
                    eth_block,
                } if a == asset => Some(serde_json::json!({
                    "note_id": note_id,
                    "amount": amount,
                    "external_to": format!("0x{refund_to}"),
                    "from": "",
                    "signed_btc_tx": "",
                    "kind": "v3_refund",
                    "deposit_id": id,
                    "eth_block": eth_block,
                })),
                _ => None,
            })
            .collect()
    }

    /// Lowest and highest execution block still connected, with no gap, up to the high tip.
    pub fn eth_exec_bounds(&self) -> (u64, u64) {
        // v2.9.58: cached per map generation (same result).
        self.eth_exec_headers.cached_bounds(|m| {
            let Some((&tip, _)) = m.iter().next_back() else {
                return (0, 0);
            };
            let mut floor = tip;
            while floor > 0 && m.contains_key(&(floor - 1)) {
                floor -= 1;
            }
            (floor, tip)
        })
    }

    pub fn eth_add_exec_headers(
        &mut self,
        mut headers: Vec<crate::eth_exec::EthExecHeader>,
    ) -> Result<(), String> {
        let lc_hash = self
            .eth_lc
            .as_ref()
            .ok_or("ETH LC not bootstrapped")?
            .execution_block_hash
            .clone();
        if headers.is_empty() {
            return Err("no headers".into());
        }
        for h in &headers {
            crate::eth_exec::verify_exec_header_rlp(h)?;
        }
        for i in 1..headers.len() {
            if crate::eth_ssz::parse32(&headers[i].parent_hash)?
                != crate::eth_ssz::parse32(&headers[i - 1].hash)?
            {
                return Err(format!("execution parent mismatch at {}", headers[i].number));
            }
            if headers[i].number != headers[i - 1].number + 1 {
                return Err("execution numbers not consecutive".into());
            }
        }
        // v2.9.60: once the window floor is set, do not re-insert headers
        // below it. A prefix under the floor is dropped; the kept suffix is
        // still checked against the LC head / stored chain. `connects_down`
        // at exactly `floor` is false — parent `floor - 1` was pruned — so a
        // batch whose first kept header is `floor` has to end at the LC hash
        // or connect upward. An entirely-below-floor batch is
        // `EXEC_HEADERS_BELOW_PRUNE_FLOOR` (permanent: the floor is monotonic)
        // and does not touch the map.
        if self.eth_exec_prune_floor > 0 {
            let floor = self.eth_exec_prune_floor;
            headers.retain(|h| h.number >= floor);
            if headers.is_empty() {
                return Err(EXEC_HEADERS_BELOW_PRUNE_FLOOR.into());
            }
        }
        let last = headers.last().unwrap();
        let first = &headers[0];
        let ends_at_lc =
            crate::eth_ssz::parse32(&last.hash)? == crate::eth_ssz::parse32(&lc_hash)?;
        let connects_up = self
            .eth_exec_headers
            .get(&(last.number + 1))
            .map(|h| {
                crate::eth_ssz::parse32(&h.parent_hash).ok()
                    == crate::eth_ssz::parse32(&last.hash).ok()
            })
            .unwrap_or(false);
        let connects_down = first.number > 0
            && self
                .eth_exec_headers
                .get(&(first.number - 1))
                .map(|h| {
                    crate::eth_ssz::parse32(&h.hash).ok()
                        == crate::eth_ssz::parse32(&first.parent_hash).ok()
                })
                .unwrap_or(false);
        if !ends_at_lc && !connects_up && !connects_down {
            return Err("headers neither reach LC head nor connect to stored chain".into());
        }
        let map = self.eth_exec_headers.make_mut();
        for h in headers {
            map.insert(h.number, h);
        }
        Ok(())
    }

    /// Shared LC receipt proof for V1 mint and V3 resolve.
    ///
    /// Returns `(receipt, deposit_block, lc_head_unix_time)`. Error strings for
    /// a missing LC, the header-window floor, the stored-header walk, ancestry,
    /// `block_hash`, and the receipt MPT match `mint_evm_lc` before the V3 split.
    /// `v3_addr` is not read here — callers pass the bridge address themselves.
    fn prove_evm_lc_receipt(&self, proof: &BridgeProof) -> Result<(Vec<u8>, u64, u64), String> {
        let lc = self
            .eth_lc
            .as_ref()
            .ok_or("ETH light client not bootstrapped")?;
        let dep_n = proof.height;
        // Before the stored-header walk. A pruned deposit must report this
        // string, not "no execution header" / "missing execution header".
        // The string is permanent (`Node::is_permanent_tx_failure`) so the
        // mint is not retried for the life of the mempool.
        if self.eth_exec_prune_floor > 0 && dep_n < self.eth_exec_prune_floor {
            return Err(DEPOSIT_OLDER_THAN_HEADER_WINDOW.into());
        }
        let mut chain: Vec<crate::eth_exec::EthExecHeader> = Vec::new();
        if self.eth_exec_headers.contains_key(&dep_n) {
            // Build a path from deposit number up to LC head using stored headers.
            let mut n = dep_n;
            loop {
                let h = self
                    .eth_exec_headers
                    .get(&n)
                    .ok_or_else(|| format!("missing execution header {n}"))?;
                chain.push(h.clone());
                if crate::eth_ssz::parse32(&h.hash)?
                    == crate::eth_ssz::parse32(&lc.execution_block_hash)?
                {
                    break;
                }
                n += 1;
                if n > lc.execution_number {
                    return Err("execution headers do not reach LC head".into());
                }
            }
        } else {
            return Err(format!(
                "no execution header at {dep_n} — submit EthExecHeaders first"
            ));
        }
        let dep_hdr = crate::eth_exec::verify_ancestry(&chain, &lc.execution_block_hash, dep_n)?;
        if !proof.block_hash.is_empty() && !crate::btc_spv::hex_eq(&proof.block_hash, &dep_hdr.hash)
        {
            return Err("block_hash mismatch".into());
        }
        let receipt = crate::btc_spv::hex_decode(&proof.raw_tx)?;
        let receipts_root = dep_hdr.receipts_root.clone();
        let dep_number = dep_hdr.number;
        crate::eth_exec::verify_receipt_proof(
            &receipts_root,
            proof.merkle_index,
            &proof.merkle_path,
            &receipt,
        )?;
        let head_rlp = chain
            .last()
            .map(|h| h.rlp_hex.as_str())
            .unwrap_or("");
        let lc_head_time = Self::eth_lc_head_unix_time(lc, head_rlp);
        Ok((receipt, dep_number, lc_head_time))
    }

    /// Mint ETH/USDC from a receipt in an LC-finalized execution ancestry.
    ///
    /// V1/V2/DestLock path. After [`Self::eth_v1_deposit_cutoff`] is set, a
    /// deposit block above that number is rejected. Pre-cutoff (the field is
    /// zero) this is the 2.9.60 check order and the same error strings.
    pub fn mint_evm_lc(
        &mut self,
        asset: &str,
        amount: u64,
        proof: &BridgeProof,
        credit_to: &str,
    ) -> Result<(), String> {
        if !crate::evm_spv::is_evm_rail(asset) {
            return Err("not an EVM rail".into());
        }
        if self.eth_lc.is_none() {
            return Err("ETH light client not bootstrapped".into());
        }
        if proof.external_txid.is_empty() {
            return Err("missing external_txid".into());
        }
        let rail = self.rail(asset)?;
        if rail.spent_deposits.contains(&proof.external_txid) {
            return Err("deposit already spent".into());
        }
        if !proof.lock_id.is_empty() && proof.lock_id != rail.lock_id {
            return Err("lock_id mismatch".into());
        }
        if amount == 0 {
            return Err("deposit amount 0".into());
        }
        if self.eth_v1_deposit_cutoff > 0 && proof.height > self.eth_v1_deposit_cutoff {
            return Err(V1_DEPOSIT_AFTER_V3_ACTIVATION.into());
        }
        let (receipt, _, _) = self.prove_evm_lc_receipt(proof)?;
        let dest20 = crate::eth_exec::dest20_from_account(credit_to);
        let want_token = crate::evm_spv::default_token(asset);
        let want_token_b = crate::evm_spv::parse_eth_addr(&format!("0x{want_token}"))?;
        let mut lock = [0u8; 32];
        let lb = crate::btc_spv::hex_decode(&rail.lock_id)?;
        if lb.len() != 32 {
            return Err("lock_id 32".into());
        }
        lock.copy_from_slice(&lb);
        let mut logs = Vec::new();
        for bridge20 in crate::evm_spv::sepolia_mint_bridge_addrs() {
            if let Ok(mut batch) = crate::eth_exec::deposit_from_receipt(&receipt, &bridge20) {
                logs.append(&mut batch);
            }
        }
        let found = logs.iter().any(|l| {
            l.dest20 == dest20
                && l.token == want_token_b
                && l.amount == amount as u128
                && l.lock_id == lock
        });
        if !found {
            return Err("receipt has no matching dest-lock/QC Deposit".into());
        }
        let rail = self.rail_mut(asset)?;
        rail.spent_deposits.insert(proof.external_txid.clone());
        rail.total_minted = rail.total_minted.saturating_add(amount);
        Ok(())
    }

    /// Resolve one V3 deposit to a mint or a refund. `v3_addr` is the V3 bridge
    /// (tests pass it; consensus does not read the environment).
    ///
    /// Does not credit an FPL balance — the caller does that for
    /// [`V3Outcome::Mint`], the same way `rail_deposit` credits after
    /// `mint_evm_lc`. A refund writes an `evm-wd-v1` leaf and does not change
    /// `total_minted` or any balance. Never writes a `mint|` leaf.
    ///
    /// Inside the expiry window, an empty `credit_to` or a preimage that does
    /// not hash to `dest20` returns [`V3_DEPOSIT_DEST_UNRESOLVED`] and does not
    /// record the deposit. A preimage that hashes but is not a creditable FPL
    /// name refunds ("invalid dest"); so does a creditable name whose current
    /// `view.balance_of(name, asset)` cannot take `amount` without overflowing
    /// u64.
    /// After expiry, and still at or above the header floor, the deposit
    /// refunds to `sender` regardless of `credit_to`.
    pub fn resolve_evm_v3_deposit(
        &mut self,
        asset: &str,
        deposit_id: &str,
        credit_to: &str,
        proof: &BridgeProof,
        v3_addr: &[u8; 20],
        view: &V3CreditView<'_>,
    ) -> Result<V3Outcome, String> {
        let id = parse_v3_deposit_id(deposit_id)?;
        let id_hex = v3_deposit_id_hex(&id);
        // Cheap map lookup before the receipt proof: a public, permissionless
        // replay of a resolved id must not make the packer walk the header
        // ancestry and the receipt MPT first. Both errors are permanent.
        if self.eth_v3_deposits.contains_key(&id_hex) {
            return Err(V3_DEPOSIT_ALREADY_RESOLVED.into());
        }
        let (receipt, dep_number, lc_head_time) = self.prove_evm_lc_receipt(proof)?;
        let logs = crate::eth_exec::v3_deposits_from_receipt(&receipt, v3_addr);
        let log = logs
            .iter()
            .find(|l| l.deposit_id == id)
            .ok_or(V3_DEPOSIT_NOT_IN_RECEIPT)?;
        let usdc_token = crate::evm_spv::parse_eth_addr(&format!(
            "0x{}",
            crate::evm_spv::default_token(crate::evm_spv::RAIL_USDC)
        ))?;
        let rail = if log.token == [0u8; 20] {
            RAIL_ETH
        } else if log.token == usdc_token {
            RAIL_USDC
        } else {
            return Err(V3_DEPOSIT_BAD_TOKEN.into());
        };
        if asset != rail {
            return Err(format!("{V3_DEPOSIT_ASSET_MISMATCH}: log is {rail}"));
        }
        if log.amount == 0 {
            return Err("deposit amount 0".into());
        }
        let expired = lc_head_time > log.timestamp.saturating_add(ETH_V3_DEPOSIT_EXPIRY_SECS);
        let sender = log.sender;
        let amount = log.amount;
        let dest20 = log.dest20;
        let credit_trim = credit_to.trim();
        let minted_to = if !expired {
            if credit_trim.is_empty() || crate::btc_spv::dest_id20(credit_trim) != dest20 {
                return Err(V3_DEPOSIT_DEST_UNRESOLVED.into());
            }
            // A recipient whose rail balance cannot take `amount` without
            // passing u64::MAX is not creditable either: refund, never wrap.
            v3_creditable_account(credit_trim)
                .filter(|name| (view.balance_of)(name, rail).checked_add(amount).is_some())
        } else {
            None
        };
        if let Some(name) = minted_to {
            {
                let rail_st = self.rail_mut(rail)?;
                rail_st.total_minted = rail_st.total_minted.saturating_add(amount);
            }
            self.eth_v3_deposits.insert(
                id_hex,
                V3Resolution::Mint {
                    asset: rail.to_string(),
                    amount,
                    credit_to: name.clone(),
                    eth_block: dep_number,
                },
            );
            return Ok(V3Outcome::Mint {
                asset: rail.to_string(),
                amount,
                credit_to: name,
            });
        }
        let note = v3_refund_note_id(&id);
        let sender_hex = hex::encode(sender);
        let usdc = rail == RAIL_USDC;
        {
            let rail_st = self.rail_mut(rail)?;
            rail_st.record_evm_withdraw(&hex::encode(note), &sender_hex, amount, usdc)?;
        }
        self.eth_v3_deposits.insert(
            id_hex,
            V3Resolution::Refund {
                asset: rail.to_string(),
                amount,
                refund_to: sender_hex.clone(),
                note_id: hex::encode(note),
                eth_block: dep_number,
            },
        );
        Ok(V3Outcome::Refund {
            asset: rail.to_string(),
            amount,
            refund_to: sender_hex,
            note_id: note,
        })
    }

    pub fn rail_mut(&mut self, asset: &str) -> Result<&mut RailState, String> {
        self.rails
            .get_mut(asset)
            .ok_or_else(|| format!("unknown rail {asset} (hardcoded only)"))
    }

    pub fn rail(&self, asset: &str) -> Result<&RailState, String> {
        self.rails
            .get(asset)
            .ok_or_else(|| format!("unknown rail {asset}"))
    }
}

/// Build a valid single-leaf merkle proof for tests / private fleet fixtures.
pub fn test_deposit_proof(txid: &str, amount: u64, lock_id: &str, height: u64, block_hash: &str) -> BridgeProof {
    let leaf = sha256_hex(format!("{txid}|{amount}|{lock_id}").as_bytes());
    BridgeProof {
        external_txid: txid.into(),
        block_hash: block_hash.into(),
        height,
        merkle_path: vec![],
        merkle_index: 0,
        lock_id: lock_id.into(),
        parent_hash: String::new(),
        merkle_root: leaf, // single leaf = root
        external_to: String::new(),
        raw_tx: String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_vault_pub_is_not_in_snapshot_or_commitment() {
        let mut a = BridgeState::with_genesis_rails();
        let mut b = BridgeState::with_genesis_rails();
        let vp = crate::vault::vault_pub_from_secret(&[7u8; 32], 0, 5, 3).unwrap();
        b.rail_mut(RAIL_BTC).unwrap().local_vault_pub = Some(vp.clone());
        assert_eq!(
            serde_json::to_vec(&a).unwrap(),
            serde_json::to_vec(&b).unwrap(),
            "local vault pub must not serialize"
        );
        b.rail_mut(RAIL_BTC).unwrap().vault_pub = Some(vp);
        assert_ne!(
            serde_json::to_vec(&a).unwrap(),
            serde_json::to_vec(&b).unwrap(),
            "consensus vault_pub does serialize"
        );
    }

    #[test]
    fn empty_bitvm2_fields_do_not_change_rail_commitment_json() {
        let fresh = RailState::new(RAIL_BTC);
        let v = serde_json::to_value(&fresh).unwrap();
        let obj = v.as_object().unwrap();
        assert!(
            !obj.contains_key("bitvm2_claims")
                && !obj.contains_key("bitvm2_claim_leaves")
                && !obj.contains_key("bitvm2_claim_root"),
            "empty bitvm2 fields must be omitted (pre-bitvm2 packer hash)"
        );
        let mut with_empty = v.clone();
        with_empty.as_object_mut().unwrap().insert(
            "bitvm2_claims".into(),
            serde_json::json!({}),
        );
        with_empty.as_object_mut().unwrap().insert(
            "bitvm2_claim_leaves".into(),
            serde_json::json!([]),
        );
        with_empty.as_object_mut().unwrap().insert(
            "bitvm2_claim_root".into(),
            serde_json::json!(""),
        );
        let loaded: RailState = serde_json::from_value(with_empty).unwrap();
        assert_eq!(
            serde_json::to_vec(&fresh).unwrap(),
            serde_json::to_vec(&loaded).unwrap(),
            "loading a new-binary snap with empty bitvm2 must hash like an old snap"
        );
    }

    #[test]
    fn eth_fixture_header_chain_and_mint() {
        let mut r = RailState::new(RAIL_ETH);
        r.min_confirmations = 1;
        let leaf = crate::evm_spv::deposit_leaf_hex(
            "tx1",
            0,
            crate::evm_spv::ETH_NATIVE_TOKEN,
            "bob",
            100,
            &r.lock_id,
        );
        r.submit_header(RailHeader::fixture(1, "h1", "", leaf.clone()))
            .unwrap();
        let proof = BridgeProof {
            external_txid: "tx1".into(),
            block_hash: "h1".into(),
            height: 1,
            merkle_path: vec![],
            merkle_index: 0,
            lock_id: r.lock_id.clone(),
            parent_hash: String::new(),
            merkle_root: leaf,
            external_to: crate::evm_spv::ETH_NATIVE_TOKEN.into(),
            raw_tx: String::new(),
        };
        let err = r.verify_and_mint(100, &proof, 1, Some("bob")).unwrap_err();
        assert!(err.contains("ETH LC only"), "{err}");
    }

    #[test]
    fn usdc_mint_binds_token_and_dest() {
        let mut r = RailState::new(RAIL_USDC);
        r.min_confirmations = 1;
        let leaf = crate::evm_spv::deposit_leaf_hex(
            "usdc-tx",
            0,
            crate::evm_spv::SEPOLIA_USDC,
            "sally",
            50,
            &r.lock_id,
        );
        r.submit_header(RailHeader::fixture(1, "h1", "", leaf.clone()))
            .unwrap();
        let mut proof = BridgeProof {
            external_txid: "usdc-tx".into(),
            block_hash: "h1".into(),
            height: 1,
            merkle_path: vec![],
            merkle_index: 0,
            lock_id: r.lock_id.clone(),
            parent_hash: String::new(),
            merkle_root: leaf,
            external_to: crate::evm_spv::SEPOLIA_USDC.into(),
            raw_tx: String::new(),
        };
        let err = r.verify_and_mint(50, &proof, 1, Some("sally")).unwrap_err();
        assert!(err.contains("ETH LC only"), "{err}");
        let _ = proof;
    }

    fn hp_leaf(nibbles: &[u8]) -> Vec<u8> {
        let mut o = vec![0x20];
        for i in (0..nibbles.len()).step_by(2) {
            o.push((nibbles[i] << 4) | nibbles[i + 1]);
        }
        o
    }

    fn dummy_exec_header(
        number: u64,
        parent: [u8; 32],
        receipts: [u8; 32],
    ) -> crate::eth_exec::EthExecHeader {
        use crate::eth_exec::{keccak256, rlp_bytes, rlp_list, rlp_uint};
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
        crate::eth_exec::EthExecHeader {
            number,
            hash: hex::encode(hash),
            parent_hash: hex::encode(parent),
            receipts_root: hex::encode(receipts),
            rlp_hex: hex::encode(&rlp),
        }
    }

    #[test]
    fn mint_evm_lc_receipt_mpt() {
        use crate::eth_exec::{keccak256, rlp_bytes, rlp_list, rlp_uint};
        let mut st = BridgeState::with_genesis_rails();
        let lock_hex = st.rail(RAIL_ETH).unwrap().lock_id.clone();
        let lock = hex::decode(&lock_hex).unwrap();
        let dest = crate::eth_exec::dest20_from_account("bob");
        let token = [0u8; 20];
        let amount: u64 = 1_000;
        let t0 = crate::eth_exec::keccak256(b"Deposit(bytes32,address,uint256,bytes32)").to_vec();
        let mut t1 = [0u8; 32];
        t1[12..].copy_from_slice(&dest);
        let mut t2 = [0u8; 32];
        t2[12..].copy_from_slice(&token);
        let mut data = [0u8; 64];
        data[24..32].copy_from_slice(&amount.to_be_bytes());
        data[32..64].copy_from_slice(&lock);
        let topics = rlp_list(&[rlp_bytes(&t0), rlp_bytes(&t1), rlp_bytes(&t2)]);
        let addr = crate::evm_spv::sepolia_qc_bridge_addr().unwrap();
        let log = rlp_list(&[rlp_bytes(&addr), topics, rlp_bytes(&data)]);
        let logs = rlp_list(&[log]);
        let bloom = vec![0u8; 256];
        let body = rlp_list(&[rlp_uint(1), rlp_uint(21_000), rlp_bytes(&bloom), logs]);
        let mut receipt = vec![0x02];
        receipt.extend_from_slice(&body);
        let key_nibs = {
            let k = rlp_uint(0);
            let mut ns = Vec::new();
            for b in k {
                ns.push(b >> 4);
                ns.push(b & 0x0f);
            }
            ns
        };
        let leaf = rlp_list(&[rlp_bytes(&hp_leaf(&key_nibs)), rlp_bytes(&receipt)]);
        let receipts_root = keccak256(&leaf);
        let hdr = dummy_exec_header(7, [3u8; 32], receipts_root);
        st.eth_lc = Some(crate::eth_lc::EthLcState {
            genesis_validators_root: crate::eth_lc::SEPOLIA_GENESIS_VALIDATORS_ROOT.into(),
            finalized_slot: 1,
            finalized_beacon_root: "00".repeat(32),
            execution_block_hash: hdr.hash.clone(),
            execution_number: 7,
            receipts_root: hdr.receipts_root.clone(),
            period: 0,
            current_agg_pk: String::new(),
            current_pks: vec![],
            next_agg_pk: String::new(),
            next_pks: vec![],
        });
        st.eth_add_exec_headers(vec![hdr.clone()]).unwrap();
        let proof = BridgeProof {
            external_txid: "aa".repeat(32),
            block_hash: hdr.hash.clone(),
            height: 7,
            merkle_path: vec![hex::encode(&leaf)],
            merkle_index: 0,
            lock_id: String::new(),
            parent_hash: String::new(),
            merkle_root: String::new(),
            external_to: String::new(),
            raw_tx: hex::encode(&receipt),
        };
        st.mint_evm_lc(RAIL_ETH, amount, &proof, "bob").unwrap();
        assert_eq!(st.rail(RAIL_ETH).unwrap().total_minted, amount);
        assert!(st.mint_evm_lc(RAIL_ETH, amount, &proof, "bob").is_err());
    }

    #[test]
    fn btc_checkpoint_forbids_reanchor() {
        let mut r = RailState::new(RAIL_BTC);
        r.btc_checkpoint = Some((10, "aa".repeat(32)));
        let watch = btc_spv::hex_decode(btc_spv::TESTNET_WATCH_SPK).unwrap();
        let (_, tx) = btc_spv::test_deposit_tx(&watch, "bob", 50_000);
        let hdr = btc_spv::mine_header(&"00".repeat(32), &tx.txid_display, 0x207fffff, 1_700_000_000)
            .unwrap();
        assert!(r
            .submit_header(RailHeader {
                height: 99,
                hash: String::new(),
                parent_hash: String::new(),
                merkle_root: String::new(),
                raw: hdr.raw_hex,
            })
            .unwrap_err()
            .contains("checkpoint"));
    }

    #[test]
    fn header_prune_keeps_vault_heights() {
        let mut r = RailState::new(RAIL_BTC);
        r.min_confirmations = 1;
        r.vault_utxos.push(crate::vault::VaultUtxo {
            txid: "old".into(),
            vout: 0,
            sats: 50_000,
            height: 1,
        });
        // commit many headers; height 1 must remain because of the UTXO
        for i in 1..300u64 {
            r.headers.insert(
                i,
                RailHeader {
                    height: i,
                    hash: format!("h{i}"),
                    parent_hash: format!("p{i}"),
                    merkle_root: "m".into(),
                    raw: "00".into(),
                },
            );
        }
        r.tip_height = 299;
        // trigger prune via commit of a dummy extra height through the helper
        let _ = r.commit_header(
            RailHeader {
                height: 300,
                hash: "h300".into(),
                parent_hash: "p300".into(),
                merkle_root: "m".into(),
                raw: "00".into(),
            },
            true,
        );
        assert!(r.headers.contains_key(&1), "vault height must not prune");
        assert!(r.headers.len() <= HEADER_HISTORY + 8);
    }

    #[test]
    fn btc_rejects_fixture_header() {
        let mut r = RailState::new(RAIL_BTC);
        assert!(r
            .submit_header(RailHeader::fixture(1, "h1", "", "mr"))
            .is_err());
    }

    #[test]
    fn btc_real_header_and_mint() {
        let mut r = RailState::new(RAIL_BTC);
        r.min_confirmations = 1;
        r.vault_pub = Some(crate::vault::VaultPub {
            epoch: 0,
            n: 3,
            t: 2,
            pubkey_hex: "00".into(),
            spk_hex: btc_spv::TESTNET_WATCH_SPK.to_string(),
        });
        let watch = btc_spv::hex_decode(btc_spv::TESTNET_WATCH_SPK).unwrap();
        let (raw_tx, tx) = btc_spv::test_deposit_tx(&watch, "bob", 50_000);
        let hdr = btc_spv::mine_header(&"00".repeat(32), &tx.txid_display, 0x207fffff, 1_700_000_000)
            .unwrap();
        r.submit_header(RailHeader {
            height: 100,
            hash: String::new(),
            parent_hash: String::new(),
            merkle_root: String::new(),
            raw: hdr.raw_hex.clone(),
        })
        .unwrap();
        assert!(r.is_bitcoin_tip());
        assert_eq!(r.tip_hash, hdr.hash_display);
        let proof = BridgeProof {
            external_txid: tx.txid_display.clone(),
            block_hash: hdr.hash_display.clone(),
            height: 100,
            merkle_path: vec![],
            merkle_index: 0,
            lock_id: r.lock_id.clone(),
            parent_hash: String::new(),
            merkle_root: hdr.merkle_display.clone(),
            external_to: String::new(),
            raw_tx: btc_spv::hex_encode(&raw_tx),
        };
        assert!(r
            .verify_and_mint(50_000, &proof, 100, Some("alice"))
            .unwrap_err()
            .contains("dest"));
        r.verify_and_mint(50_000, &proof, 100, Some("bob")).unwrap();
        assert_eq!(r.total_minted, 50_000);
        assert!(r.verify_and_mint(50_000, &proof, 100, Some("bob")).is_err());
    }

    #[test]
    fn reconcile_kickoff_replaces_spent_vault_utxo() {
        // Packed 2026-08-21 dest-lock Kickoff: spends dave deposit 193_000 and
        // returns 142_000 change to the FROST P2TR vault.
        const KICKOFF: &str = "020000000001011ad1e38650c5e9a5acf1240892f7e46fac4343b4409a9e01fa0eeff994181ec30000000000feffffff0250c3000000000000220020af44e1270e2dfe14452fbdbadd210adcb617a17b59238684973ad5524c905e29b02a020000000000225120915ba6eb3de91de4faf88ec6afee26bf218e5d6ed583200a9263389aeeeafb78014068b58bcb7985c89adadadf779fdddaa3028be4118e2c94a0bcf946c0c3129bf0562a824aaf8ca31009f8b294fbc3b792aaef9c01f7ed71129953d6ce45da237000000000";
        let mut r = RailState::new(RAIL_BTC);
        r.vault_pub = Some(crate::vault::VaultPub {
            epoch: 0,
            n: 6,
            t: 4,
            pubkey_hex: "915ba6eb3de91de4faf88ec6afee26bf218e5d6ed583200a9263389aeeeafb78"
                .into(),
            spk_hex: "5120915ba6eb3de91de4faf88ec6afee26bf218e5d6ed583200a9263389aeeeafb78"
                .into(),
        });
        r.vault_utxos.push(crate::vault::VaultUtxo {
            txid: "c31e1894f9ef0efa019e9a40b44343ac6fe4f7920824f1aca5e9c55086e3d11a".into(),
            vout: 0,
            sats: 193_000,
            height: 5_126_131,
        });
        r.signed_vault_txs
            .insert("bac114a2e2edc9419c6d8718608025347f76bb8460d17f64f362a58b8e995390".into(), KICKOFF.into());
        r.reconcile_kickoffs();
        assert_eq!(r.vault_utxos.len(), 1);
        assert_eq!(r.vault_utxos[0].sats, 142_000);
        assert!(r.vault_utxos[0]
            .txid
            .eq_ignore_ascii_case("f2af90cc4cb03c5f776be6a7eb2fe2020ea283db28dd7513a8274f7485a32b14"));
        r.reconcile_kickoffs();
        assert_eq!(r.vault_utxos.len(), 1, "reconcile is idempotent");
    }

    fn rh(height: u64, p: &btc_spv::ParsedHeader) -> RailHeader {
        RailHeader {
            height,
            hash: String::new(),
            parent_hash: String::new(),
            merkle_root: String::new(),
            raw: p.raw_hex.clone(),
        }
    }

    /// main chain a: heights base..base+n (bits 0x207fffff).
    fn strict_chain(base: u64, n: usize) -> (RailState, Vec<btc_spv::ParsedHeader>) {
        let mut r = RailState::new(RAIL_BTC);
        let mut prev = "00".repeat(32);
        let mut out = vec![];
        for i in 0..n {
            let h = btc_spv::mine_header(&prev, &format!("{:02x}", 0x10 + i).repeat(32), 0x207fffff, 1_700_000_000 + i as u32).unwrap();
            assert!(r.submit_header_ex(rh(base + i as u64, &h), true).unwrap());
            prev = h.hash_display.clone();
            out.push(h);
        }
        (r, out)
    }

    #[test]
    fn v2_strict_duplicate_rejected_and_no_rewind() {
        let (mut r, a) = strict_chain(100, 5);
        assert_eq!(r.tip_height, 104);
        let e = r.submit_header_ex(rh(104, &a[4]), true).unwrap_err();
        assert!(e.contains("BTC duplicate header"), "{e}");
        let e = r.submit_header_ex(rh(102, &a[2]), true).unwrap_err();
        assert!(e.contains("BTC duplicate header"), "{e}");
        assert_eq!(r.tip_height, 104, "old header must not rewind the rail");
        assert_eq!(r.tip_hash, a[4].hash_display);
        assert_eq!(r.headers.len(), 5);
        // v1 (unarmed) behaviour is unchanged: the same re-submit rewinds.
        let (mut r1, a1) = strict_chain(100, 5);
        r1.submit_header(rh(102, &a1[2])).unwrap();
        assert_eq!(r1.tip_height, 102);
    }

    #[test]
    fn v2_strict_equal_work_fork_waits_until_more_work() {
        let (mut r, a) = strict_chain(100, 5); // 100..104
        let bits = 0x207fffff;
        let t = 1_700_000_100u32;
        let b3 = btc_spv::mine_header(&a[1].hash_display, &"b3".repeat(32), bits, t).unwrap();
        let b4 = btc_spv::mine_header(&b3.hash_display, &"b4".repeat(32), bits, t + 1).unwrap();
        let b5 = btc_spv::mine_header(&b4.hash_display, &"b5".repeat(32), bits, t + 2).unwrap();
        let b6 = btc_spv::mine_header(&b5.hash_display, &"b6".repeat(32), bits, t + 3).unwrap();
        assert!(!r.submit_header_ex(rh(102, &b3), true).unwrap());
        assert!(!r.submit_header_ex(rh(103, &b4), true).unwrap());
        assert!(!r.submit_header_ex(rh(104, &b5), true).unwrap(), "equal work: stay on first seen");
        assert_eq!(r.tip_hash, a[4].hash_display);
        let e = r.submit_header_ex(rh(104, &b5), true).unwrap_err();
        assert!(e.contains("pending fork"), "{e}");
        assert!(r.submit_header_ex(rh(105, &b6), true).unwrap(), "more work: switch");
        assert_eq!(r.tip_height, 105);
        assert_eq!(r.tip_hash, b6.hash_display);
        assert_eq!(r.headers[&102].hash, b3.hash_display);
        assert!(r.btc_fork.is_empty());
    }

    #[test]
    fn v2_strict_heavier_single_header_wins_less_work_loses() {
        // Retarget height (2016) allows any bits.
        let (mut r, a) = strict_chain(2014, 4); // 2014..2017
        let heavy = btc_spv::mine_header(&a[1].hash_display, &"cc".repeat(32), 0x2000ffff, 1_700_000_200).unwrap();
        let light = btc_spv::mine_header(&a[1].hash_display, &"dd".repeat(32), 0x207fffff, 1_700_000_201).unwrap();
        assert!(btc_spv::header_work_bits(0x2000ffff) > 2 * btc_spv::header_work_bits(0x207fffff));
        assert!(!r.submit_header_ex(rh(2016, &light), true).unwrap(), "less work: pending only");
        assert_eq!(r.tip_height, 2017);
        assert!(r.submit_header_ex(rh(2016, &heavy), true).unwrap());
        assert_eq!(r.tip_height, 2016);
        assert_eq!(r.tip_hash, heavy.hash_display);
    }

    #[test]
    fn v2_strict_cheap_branch_cannot_evict_heavier_pending_fork() {
        let (mut r, a) = strict_chain(100, 5);
        let bits = 0x207fffff;
        let b3 = btc_spv::mine_header(&a[1].hash_display, &"e3".repeat(32), bits, 1_700_000_300).unwrap();
        let b4 = btc_spv::mine_header(&b3.hash_display, &"e4".repeat(32), bits, 1_700_000_301).unwrap();
        assert!(!r.submit_header_ex(rh(102, &b3), true).unwrap());
        assert!(!r.submit_header_ex(rh(103, &b4), true).unwrap());
        let x = btc_spv::mine_header(&a[2].hash_display, &"f4".repeat(32), bits, 1_700_000_302).unwrap();
        let e = r.submit_header_ex(rh(103, &x), true).unwrap_err();
        assert!(e.contains("less work than the pending fork"), "{e}");
        assert_eq!(r.btc_fork.len(), 2);
    }

    #[test]
    fn v2_strict_empty_fork_not_serialized() {
        let (r, _) = strict_chain(100, 2);
        let j = serde_json::to_string(&r).unwrap();
        assert!(!j.contains("btc_fork"));
    }

    #[test]
    fn btc_tip_reorg_replaces_stale_header() {
        let mut r = RailState::new(RAIL_BTC);
        let bits = 0x207fffff;
        let t0 = 1_700_000_000u32;
        let h1 = btc_spv::mine_header(&"00".repeat(32), &"11".repeat(32), bits, t0).unwrap();
        let h2 = btc_spv::mine_header(&h1.hash_display, &"22".repeat(32), bits, t0 + 1).unwrap();
        let h3a = btc_spv::mine_header(&h2.hash_display, &"33".repeat(32), bits, t0 + 2).unwrap();
        let h3b = btc_spv::mine_header(&h2.hash_display, &"44".repeat(32), bits, t0 + 3).unwrap();
        for (height, hdr) in [(100u64, &h1), (101, &h2), (102, &h3a)] {
            r.submit_header(RailHeader {
                height,
                hash: String::new(),
                parent_hash: String::new(),
                merkle_root: String::new(),
                raw: hdr.raw_hex.clone(),
            })
            .unwrap();
        }
        assert_eq!(r.tip_height, 102);
        assert_eq!(r.tip_hash, h3a.hash_display);
        r.submit_header(RailHeader {
            height: 102,
            hash: String::new(),
            parent_hash: String::new(),
            merkle_root: String::new(),
            raw: h3b.raw_hex.clone(),
        })
        .unwrap();
        assert_eq!(r.tip_height, 102);
        assert_eq!(r.tip_hash, h3b.hash_display);
        assert_ne!(r.tip_hash, h3a.hash_display);
    }

    #[test]
    fn btc_deep_reorg_must_submit_fork_height_not_stale_tip() {
        let mut r = RailState::new(RAIL_BTC);
        let bits = 0x207fffff;
        let t0 = 1_700_000_000u32;
        let h1 = btc_spv::mine_header(&"00".repeat(32), &"11".repeat(32), bits, t0).unwrap();
        let h2 = btc_spv::mine_header(&h1.hash_display, &"22".repeat(32), bits, t0 + 1).unwrap();
        let h3a = btc_spv::mine_header(&h2.hash_display, &"aa".repeat(32), bits, t0 + 2).unwrap();
        let h4a = btc_spv::mine_header(&h3a.hash_display, &"ab".repeat(32), bits, t0 + 3).unwrap();
        let h5a = btc_spv::mine_header(&h4a.hash_display, &"ac".repeat(32), bits, t0 + 4).unwrap();
        let h3b = btc_spv::mine_header(&h2.hash_display, &"bb".repeat(32), bits, t0 + 5).unwrap();
        let h4b = btc_spv::mine_header(&h3b.hash_display, &"bc".repeat(32), bits, t0 + 6).unwrap();
        let h5b = btc_spv::mine_header(&h4b.hash_display, &"bd".repeat(32), bits, t0 + 7).unwrap();
        for (height, hdr) in [
            (100u64, &h1),
            (101, &h2),
            (102, &h3a),
            (103, &h4a),
            (104, &h5a),
        ] {
            r.submit_header(RailHeader {
                height,
                hash: String::new(),
                parent_hash: String::new(),
                merkle_root: String::new(),
                raw: hdr.raw_hex.clone(),
            })
            .unwrap();
        }
        assert_eq!(r.tip_hash, h5a.hash_display);
        let err = r
            .submit_header(RailHeader {
                height: 104,
                hash: String::new(),
                parent_hash: String::new(),
                merkle_root: String::new(),
                raw: h5b.raw_hex.clone(),
            })
            .unwrap_err();
        assert!(
            err.contains("BTC header parent mismatch"),
            "stale-tip replace must fail on a deep fork: {err}"
        );
        r.submit_header(RailHeader {
            height: 102,
            hash: String::new(),
            parent_hash: String::new(),
            merkle_root: String::new(),
            raw: h3b.raw_hex.clone(),
        })
        .unwrap();
        assert_eq!(r.tip_height, 102);
        assert_eq!(r.tip_hash, h3b.hash_display);
        assert!(!r.headers.contains_key(&103));
        assert!(!r.headers.contains_key(&104));
        r.submit_header(RailHeader {
            height: 103,
            hash: String::new(),
            parent_hash: String::new(),
            merkle_root: String::new(),
            raw: h4b.raw_hex.clone(),
        })
        .unwrap();
        r.submit_header(RailHeader {
            height: 104,
            hash: String::new(),
            parent_hash: String::new(),
            merkle_root: String::new(),
            raw: h5b.raw_hex.clone(),
        })
        .unwrap();
        assert_eq!(r.tip_height, 104);
        assert_eq!(r.tip_hash, h5b.hash_display);
    }

    // ── M1: real header binding for BitVM2 attestations ──────────────────

    fn m1_keys() -> (ark_groth16::ProvingKey<ark_bn254::Bn254>, ark_groth16::VerifyingKey<ark_bn254::Bn254>, Vec<u8>) {
        let (pk, vk) = fd_pl_bitvm2::groth16::setup_from_seed([7u8; 32]).unwrap();
        let vkb = fd_pl_bitvm2::groth16::vk_to_bytes(&vk).unwrap();
        (pk, vk, vkb)
    }

    struct M1Fixture {
        rail: RailState,
        note: String,
        dest: String,
        amount: u64,
        attest: Bitvm2AttestV2,
    }

    /// Burn at FPL height 100, checkpoint at 127, peg-out in BTC block 200
    /// (2-tx block, index 0) with tip 205 (6 confs).
    fn m1_fixture(pk: &ark_groth16::ProvingKey<ark_bn254::Bn254>, vk: &ark_groth16::VerifyingKey<ark_bn254::Bn254>) -> M1Fixture {
        let mut rail = RailState::new(RAIL_BTC);
        let pk_user = crate::btc_tx::compressed_pubkey_from_secret(&[3u8; 32]).unwrap();
        let dest = crate::vault::p2wpkh_testnet_address(&pk_user).unwrap();
        let amount = 20_000u64;
        let note = "m1note".repeat(4);
        rail.open_bitvm2_withdraw(&note, "alice", &dest, amount, 100).unwrap();
        rail.record_fpl_checkpoint(128, &"ab".repeat(32));
        let (_k, dest_spk) = crate::btc_tx::decode_address(&dest).unwrap();
        let (raw_a, tx_a) = btc_spv::test_deposit_tx(&dest_spk, "x", amount);
        let (_raw_b, tx_b) = btc_spv::test_deposit_tx(&dest_spk, "y", 1);
        let a_int = btc_spv::display_to_internal(&tx_a.txid_display).unwrap();
        let b_int = btc_spv::display_to_internal(&tx_b.txid_display).unwrap();
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(&a_int);
        buf[32..].copy_from_slice(&b_int);
        let root_display = btc_spv::display_hex(&btc_spv::hash256(&buf));
        for h in 200..=205u64 {
            let mut hdr = RailHeader::fixture(h, format!("{h:064x}"), format!("{:064x}", h - 1), if h == 200 { root_display.clone() } else { "00".repeat(32) });
            hdr.raw = "00".repeat(80);
            rail.headers.insert(h, hdr);
        }
        rail.tip_height = 205;
        let ckpt_h = 127u64;
        let header = crate::bitvm2_exit::checkpoint_header_hash(ckpt_h, &"ab".repeat(32));
        let pegout = crate::bitvm2_exit::pegout_txid_bytes(&tx_a.txid_display).unwrap();
        let dest_h160 = bitvm::dest_h160_from_address(&dest).unwrap();
        let (proof_hex, public_hex, digest, _cid) = crate::bitvm2_exit::prove_withdraw_attest_with_keys(
            pk, vk, &note, &dest_h160, amount, ckpt_h, &header, &pegout, &rail.bitvm2_claim_leaves, "op",
        )
        .unwrap();
        let attest = Bitvm2AttestV2 {
            note_id: note.clone(),
            claim_txid_hex: "cc".repeat(32),
            checkpoint_height: ckpt_h,
            btc_height: 200,
            pegout_raw_tx_hex: hex::encode(raw_a),
            merkle_path: vec![hex::encode(b_int)],
            merkle_index: 0,
            dest_lock_abort_commit_hex: String::new(),
            proof_hex,
            public_hex,
            statement_digest_hex: digest,
        };
        M1Fixture { rail, note, dest, amount, attest }
    }

    #[test]
    fn m1_empty_checkpoints_do_not_change_rail_commitment_json() {
        let fresh = RailState::new(RAIL_BTC);
        let v = serde_json::to_value(&fresh).unwrap();
        assert!(!v.as_object().unwrap().contains_key("fpl_checkpoints"));
        let mut c = fd_pl_bitvm2_claim_sample();
        c.checkpoint_height = 0;
        c.pegout_btc_height = 0;
        let cv = serde_json::to_value(&c).unwrap();
        assert!(!cv.as_object().unwrap().contains_key("checkpoint_height"));
        assert!(!cv.as_object().unwrap().contains_key("pegout_btc_height"));
    }

    fn fd_pl_bitvm2_claim_sample() -> crate::bitvm2_exit::Bitvm2Claim {
        let mut r = RailState::new(RAIL_BTC);
        let pk = crate::btc_tx::compressed_pubkey_from_secret(&[9u8; 32]).unwrap();
        let dest = crate::vault::p2wpkh_testnet_address(&pk).unwrap();
        r.open_bitvm2_withdraw("n", "a", &dest, 1_000, 1).unwrap()
    }

    #[test]
    fn m1_checkpoints_every_interval_and_bounded() {
        let mut r = RailState::new(RAIL_BTC);
        let iv = crate::bitvm2_exit::BITVM2_CHECKPOINT_INTERVAL;
        r.record_fpl_checkpoint(iv - 1, "aa");
        assert!(r.fpl_checkpoints.is_empty());
        r.record_fpl_checkpoint(iv, "AB");
        assert_eq!(r.fpl_checkpoints.get(&(iv - 1)).map(String::as_str), Some("ab"));
        let keep = crate::bitvm2_exit::BITVM2_CHECKPOINT_KEEP as u64;
        for k in 1..=(keep + 5) {
            r.record_fpl_checkpoint(k * iv, "cd");
        }
        assert_eq!(r.fpl_checkpoints.len() as u64, keep);
        assert!(!r.fpl_checkpoints.contains_key(&(iv - 1)));
    }

    #[test]
    fn m1_attest_v2_honest_passes_and_disprove_holds() {
        let (pk, vk, vkb) = m1_keys();
        let mut f = m1_fixture(&pk, &vk);
        f.rail.attest_bitvm2_claim_v2(&f.attest, "op", &vkb, 200).unwrap();
        let c = f.rail.bitvm2_claims.get(&f.note).unwrap();
        assert_eq!(c.status, crate::bitvm2_exit::Bitvm2Status::ClaimPosted);
        assert_eq!(c.checkpoint_height, 127);
        assert_eq!(c.pegout_btc_height, 200);
        // Honest stored proof is not disprovable (garbage submissions ignored).
        assert!(!f.rail.disprove_bitvm2_v2(&f.note, &vkb).unwrap());
        // A tampered stored proof is disproved.
        f.rail.bitvm2_claims.get_mut(&f.note).unwrap().statement_digest_hex = "00".repeat(32);
        assert!(f.rail.disprove_bitvm2_v2(&f.note, &vkb).unwrap());
        assert_eq!(
            f.rail.bitvm2_claims.get(&f.note).unwrap().status,
            crate::bitvm2_exit::Bitvm2Status::Disproved
        );
    }

    #[test]
    fn m1_attest_v2_rejects_bad_inputs() {
        let (pk, vk, vkb) = m1_keys();
        let base = m1_fixture(&pk, &vk);
        let run = |mutate: &dyn Fn(&mut M1Fixture), vk: &[u8], h: u64| -> Result<(), String> {
            let mut f = M1Fixture { rail: base.rail.clone(), note: base.note.clone(), dest: base.dest.clone(), amount: base.amount, attest: base.attest.clone() };
            mutate(&mut f);
            let a = f.attest.clone();
            f.rail.attest_bitvm2_claim_v2(&a, "op", vk, h)
        };
        // No ceremony VK.
        assert!(run(&|_| {}, &[], 200).unwrap_err().contains("verifying key"));
        // A different VK (e.g. a fresh random setup) fails.
        let (_pk2, vk2) = fd_pl_bitvm2::groth16::setup_from_seed([8u8; 32]).unwrap();
        let vk2b = fd_pl_bitvm2::groth16::vk_to_bytes(&vk2).unwrap();
        assert!(run(&|_| {}, &vk2b, 200).is_err());
        // Unknown checkpoint.
        assert!(run(&|f| f.attest.checkpoint_height = 126, &vkb, 200).unwrap_err().contains("checkpoint"));
        // Checkpoint before the burn.
        assert!(run(&|f| { f.rail.record_fpl_checkpoint(64, "ee"); f.attest.checkpoint_height = 63; }, &vkb, 200).unwrap_err().contains("before the burn"));
        // Not final yet.
        assert!(run(&|_| {}, &vkb, 128).unwrap_err().contains("not final"));
        // Too few confirmations.
        assert!(run(&|f| f.rail.tip_height = 203, &vkb, 200).unwrap_err().contains("confs"));
        // Missing header.
        assert!(run(&|f| f.attest.btc_height = 190, &vkb, 200).unwrap_err().contains("no BTC header"));
        // Merkle path does not reach the header root.
        assert!(run(&|f| f.attest.merkle_path = vec!["11".repeat(32)], &vkb, 200).unwrap_err().contains("merkle"));
        // Wrong index flips the hash order.
        assert!(run(&|f| f.attest.merkle_index = 1, &vkb, 200).is_err());
        // Peg-out pays a different amount: claim amount changed.
        assert!(run(&|f| f.rail.bitvm2_claims.get_mut(&f.note).unwrap().amount = 19_999, &vkb, 200).unwrap_err().contains("burn amount"));
        // Peg-out already backs another claim.
        assert!(run(&|f| {
            let txid = btc_spv::parse_tx(&hex::decode(&f.attest.pegout_raw_tx_hex).unwrap()).unwrap().txid_display;
            let mut other = f.rail.bitvm2_claims.get(&f.note).unwrap().clone();
            other.note_id = "other".into();
            other.pegout_txid_hex = txid.to_ascii_lowercase();
            f.rail.bitvm2_claims.insert("other".into(), other);
        }, &vkb, 200).unwrap_err().contains("another claim"));
        // A proof made against the pre-M1 placeholder header does not verify.
        assert!(run(&|f| {
            let header = crate::bitvm2_exit::header_hash_placeholder(127, &"ab".repeat(32));
            let dest_h160 = bitvm::dest_h160_from_address(&f.dest).unwrap();
            let txid = btc_spv::parse_tx(&hex::decode(&f.attest.pegout_raw_tx_hex).unwrap()).unwrap().txid_display;
            let pegout = crate::bitvm2_exit::pegout_txid_bytes(&txid).unwrap();
            let (p, pubs, d, _) = crate::bitvm2_exit::prove_withdraw_attest_with_keys(
                &pk, &vk, &f.note, &dest_h160, f.amount, 127, &header, &pegout, &f.rail.bitvm2_claim_leaves, "op").unwrap();
            f.attest.proof_hex = p; f.attest.public_hex = pubs; f.attest.statement_digest_hex = d;
        }, &vkb, 200).is_err());
        // Claim not awaiting attest.
        assert!(run(&|f| f.rail.bitvm2_claims.get_mut(&f.note).unwrap().status = crate::bitvm2_exit::Bitvm2Status::Disproved, &vkb, 200).is_err());
    }
}
