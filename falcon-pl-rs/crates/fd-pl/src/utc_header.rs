// Copyright (c) 2025-2026 BEARTEC. All rights reserved. See LICENSE.
//! Protocol UTC header primitive (v5) — **unarmed by default**.
//!
//! Design freeze candidate for the living upgrade Page. This module defines:
//! - `header_msg_v5`: v4 preimage + `|utc:{sealed_utc_ms}`
//! - activation height gate (`u64::MAX` = disabled / never activate)
//! - split validation: **historical / deterministic** vs **live admission**
//!
//! `sealed_at_ms` (chain physics / reward clock) is intentionally untouched.
//! Live skew numbers: **5_000 ms ahead / 60_000 ms behind**, signed off
//! 2026-11-07. They do nothing on a network until `H_utc` is armed.
//! Child≥parent monotonicity is still proposed. Arming `H_utc` still
//! requires a separate preactivation commit.
//!
//! QC coverage: once v5 is armed, OK votes / QCs sign `ledger_hash`, which is
//! derived from the v5 preimage ⇒ they attest to `sealed_utc_ms`. Mutating the
//! UTC field invalidates the packer signature and every existing OK/QC. No
//! UTC-specific slash rule exists; conflicting UTC at one height is ordinary
//! conflicting-hash evidence.
//!
//! See `docs/ops/UTC_HEADER.md` for remaining gates (bake 2300 H_utc and
//! Hello-enforce heights in a separate arming commit) and downstream work.

use crate::NETWORK_ID_PUBLIC_TESTNET_2300;

/// Unarmed on every network until a separate arming commit sets a real height.
/// `u64::MAX` means UTC header rules never apply (field stays 0; v4 msgs only).
pub const UTC_FROM_HEIGHT_DISABLED: u64 = u64::MAX;

/// Baked 2300 activation — **must stay disabled** until seat readiness + soak.
pub const TESTNET_2300_UTC_FROM_HEIGHT: u64 = UTC_FROM_HEIGHT_DISABLED;

/// Signed off 2026-11-07: max `sealed_utc_ms` ahead of checker wall clock (5 seconds).
/// Unused until `H_utc` is armed. Devnet may still override via `FPL_UTC_MAX_AHEAD_MS` (ignored on 2300).
pub const PROPOSED_UTC_MAX_AHEAD_MS: u64 = 5_000;

/// Signed off 2026-11-07: max `sealed_utc_ms` behind checker wall clock on live admit (60 seconds).
/// Unused until `H_utc` is armed. Devnet may still override via `FPL_UTC_MAX_BEHIND_MS` (ignored on 2300).
pub const PROPOSED_UTC_MAX_BEHIND_MS: u64 = 60_000;

/// PROPOSED: child `sealed_utc_ms` must be >= parent when parent carries UTC (>0).
pub const PROPOSED_UTC_REQUIRE_MONOTONIC: bool = true;

/// Env override for non-2300 / local rehearsal. Ignored on public testnet 2300
/// so a mis-set shell cannot arm live consensus. Even `0` is honoured when set
/// (0 means "active from genesis" on that network — still not for 2300).
pub const ENV_UTC_FROM_HEIGHT: &str = "FPL_UTC_FROM_HEIGHT";

/// Devnet-only skew overrides (ignored on 2300).
pub const ENV_UTC_MAX_AHEAD_MS: &str = "FPL_UTC_MAX_AHEAD_MS";
pub const ENV_UTC_MAX_BEHIND_MS: &str = "FPL_UTC_MAX_BEHIND_MS";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UtcSkewBounds {
    pub max_ahead_ms: u64,
    pub max_behind_ms: u64,
    pub require_monotonic: bool,
}

impl Default for UtcSkewBounds {
    fn default() -> Self {
        Self {
            max_ahead_ms: PROPOSED_UTC_MAX_AHEAD_MS,
            max_behind_ms: PROPOSED_UTC_MAX_BEHIND_MS,
            require_monotonic: PROPOSED_UTC_REQUIRE_MONOTONIC,
        }
    }
}

impl UtcSkewBounds {
    /// Resolve bounds: on 2300 always the signed 5s/60s constants (still inactive until H armed).
    /// Elsewhere env may override for tests.
    pub fn resolve(network_id: u32) -> Self {
        let mut b = Self::default();
        if network_id == NETWORK_ID_PUBLIC_TESTNET_2300 {
            return b;
        }
        if let Some(v) = env_u64(ENV_UTC_MAX_AHEAD_MS) {
            b.max_ahead_ms = v;
        }
        if let Some(v) = env_u64(ENV_UTC_MAX_BEHIND_MS) {
            b.max_behind_ms = v;
        }
        b
    }
}

fn env_u64(name: &str) -> Option<u64> {
    std::env::var(name).ok()?.trim().parse().ok()
}

/// Activation height for `network_id`. 2300 uses the baked (disabled) constant;
/// other networks honour `FPL_UTC_FROM_HEIGHT` or stay disabled.
pub fn network_utc_from_height(network_id: u32) -> u64 {
    if let Some((nid, h)) = FROM_HEIGHT_OVERRIDE.with(|c| c.get()) {
        if nid == network_id {
            return h;
        }
    }
    if network_id == NETWORK_ID_PUBLIC_TESTNET_2300 {
        return TESTNET_2300_UTC_FROM_HEIGHT;
    }
    env_u64(ENV_UTC_FROM_HEIGHT).unwrap_or(UTC_FROM_HEIGHT_DISABLED)
}

/// True iff UTC header rules apply at `height` for the given activation.
/// `from_height == u64::MAX` ⇒ never.
pub fn utc_active(height: u64, from_height: u64) -> bool {
    from_height != UTC_FROM_HEIGHT_DISABLED && height >= from_height
}

pub fn utc_active_on(network_id: u32, height: u64) -> bool {
    utc_active(height, network_utc_from_height(network_id))
}

/// v5 header preimage: identical to v4 plus `|utc:{sealed_utc_ms}`.
/// Callers must only use this when `utc_active`; otherwise stick to v4.
pub fn header_msg_v5(
    height: u64,
    parent_hash: &str,
    network_id: u32,
    packer: &str,
    tx_root: &str,
    state_root_after: &str,
    skipped_predecessors: &[String],
    parent_cert_hash: &str,
    claim_root_hex: &str,
    current_committee_root_hex: &str,
    sealed_utc_ms: u64,
) -> String {
    let skips = skipped_predecessors.join(",");
    format!(
        "pl-ledger:v5|{height}|{parent_hash}|{network_id}|{packer}|{tx_root}|{state_root_after}|skips:{skips}|cert:{parent_cert_hash}|claim:{claim_root_hex}|cur6:{current_committee_root_hex}|utc:{sealed_utc_ms}"
    )
}

/// Build v5 from an already-formatted v4 message (must start with `pl-ledger:v4|`).
pub fn header_msg_v5_from_v4(msg_v4: &str, sealed_utc_ms: u64) -> Result<String, String> {
    let rest = msg_v4
        .strip_prefix("pl-ledger:v4|")
        .ok_or_else(|| "header_msg_v5_from_v4: not a v4 msg".to_string())?;
    Ok(format!("pl-ledger:v5|{rest}|utc:{sealed_utc_ms}"))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UtcCheckError {
    /// Height is below activation / activation disabled — field must stay 0.
    UnexpectedUtc { height: u64, sealed_utc_ms: u64 },
    /// Activation requires a positive Unix-ms stamp.
    MissingUtc { height: u64 },
    /// Child UTC < parent UTC when parent had UTC.
    NotMonotonic {
        height: u64,
        parent_utc: u64,
        sealed_utc_ms: u64,
    },
    /// Live-only: stamp too far ahead of local wall clock.
    AheadOfWall {
        sealed_utc_ms: u64,
        local_now_ms: u64,
        max_ahead_ms: u64,
    },
    /// Live-only: stamp too far behind local wall clock.
    BehindWall {
        sealed_utc_ms: u64,
        local_now_ms: u64,
        max_behind_ms: u64,
    },
}

impl std::fmt::Display for UtcCheckError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnexpectedUtc {
                height,
                sealed_utc_ms,
            } => write!(
                f,
                "sealed_utc_ms={sealed_utc_ms} at h={height} but UTC header inactive"
            ),
            Self::MissingUtc { height } => {
                write!(f, "sealed_utc_ms required at h={height} (UTC active)")
            }
            Self::NotMonotonic {
                height,
                parent_utc,
                sealed_utc_ms,
            } => write!(
                f,
                "sealed_utc_ms={sealed_utc_ms} < parent_utc={parent_utc} at h={height}"
            ),
            Self::AheadOfWall {
                sealed_utc_ms,
                local_now_ms,
                max_ahead_ms,
            } => write!(
                f,
                "sealed_utc_ms={sealed_utc_ms} ahead of wall {local_now_ms} by >{max_ahead_ms}ms"
            ),
            Self::BehindWall {
                sealed_utc_ms,
                local_now_ms,
                max_behind_ms,
            } => write!(
                f,
                "sealed_utc_ms={sealed_utc_ms} behind wall {local_now_ms} by >{max_behind_ms}ms"
            ),
        }
    }
}

/// Deterministic checks safe for historical replay / catch-up / archive restore.
/// Does **not** consult wall clock — replay must not reject old tips for skew.
///
/// `parent_utc_ms`: parent's `sealed_utc_ms` (0 if parent pre-activation or genesis).
pub fn check_utc_historical(
    height: u64,
    from_height: u64,
    sealed_utc_ms: u64,
    parent_utc_ms: u64,
    bounds: &UtcSkewBounds,
) -> Result<(), UtcCheckError> {
    if !utc_active(height, from_height) {
        if sealed_utc_ms != 0 {
            return Err(UtcCheckError::UnexpectedUtc {
                height,
                sealed_utc_ms,
            });
        }
        return Ok(());
    }
    if sealed_utc_ms == 0 {
        return Err(UtcCheckError::MissingUtc { height });
    }
    // Bootstrap: first active height may have parent_utc=0 — skip monotonic.
    if bounds.require_monotonic && parent_utc_ms > 0 && sealed_utc_ms < parent_utc_ms {
        return Err(UtcCheckError::NotMonotonic {
            height,
            parent_utc: parent_utc_ms,
            sealed_utc_ms,
        });
    }
    Ok(())
}

/// Live admission: historical rules **plus** skew vs the checker's local wall clock.
/// Call only on the live tip path — never on pure historical apply of stored bytes.
pub fn check_utc_live_admission(
    height: u64,
    from_height: u64,
    sealed_utc_ms: u64,
    parent_utc_ms: u64,
    local_now_ms: u64,
    bounds: &UtcSkewBounds,
) -> Result<(), UtcCheckError> {
    check_utc_historical(height, from_height, sealed_utc_ms, parent_utc_ms, bounds)?;
    if !utc_active(height, from_height) {
        return Ok(());
    }
    if sealed_utc_ms > local_now_ms.saturating_add(bounds.max_ahead_ms) {
        return Err(UtcCheckError::AheadOfWall {
            sealed_utc_ms,
            local_now_ms,
            max_ahead_ms: bounds.max_ahead_ms,
        });
    }
    if local_now_ms > sealed_utc_ms.saturating_add(bounds.max_behind_ms) {
        return Err(UtcCheckError::BehindWall {
            sealed_utc_ms,
            local_now_ms,
            max_behind_ms: bounds.max_behind_ms,
        });
    }
    Ok(())
}

/// Which header domain a packer/verifier must use at this height.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderDomain {
    /// Pre-UTC: existing v4 (or older) paths unchanged.
    LegacyV4,
    /// UTC-active: v5 preimage including sealed_utc_ms.
    V5,
}

pub fn header_domain(height: u64, from_height: u64) -> HeaderDomain {
    if utc_active(height, from_height) {
        HeaderDomain::V5
    } else {
        HeaderDomain::LegacyV4
    }
}

/// Select the message string for packer sig / inner hash given domain.
pub fn packer_msg_for_domain(
    domain: HeaderDomain,
    height: u64,
    parent_hash: &str,
    network_id: u32,
    packer: &str,
    tx_root: &str,
    state_root_after: &str,
    skipped_predecessors: &[String],
    parent_cert_hash: &str,
    claim_root_hex: &str,
    current_committee_root_hex: &str,
    sealed_utc_ms: u64,
) -> String {
    match domain {
        HeaderDomain::LegacyV4 => crate::qc_header::header_msg_v4(
            height,
            parent_hash,
            network_id,
            packer,
            tx_root,
            state_root_after,
            skipped_predecessors,
            parent_cert_hash,
            claim_root_hex,
            current_committee_root_hex,
        ),
        HeaderDomain::V5 => header_msg_v5(
            height,
            parent_hash,
            network_id,
            packer,
            tx_root,
            state_root_after,
            skipped_predecessors,
            parent_cert_hash,
            claim_root_hex,
            current_committee_root_hex,
            sealed_utc_ms,
        ),
    }
}

/// Hello capability token advertised by binaries that understand header v5.
/// Older peers omit the field (empty vec). Not a consensus rule by itself.
pub const CAP_UTC_HEADER_V5: &str = "utc-header-v5";

/// Capabilities this binary advertises on Hello (additive; empty on ancient peers).
/// 2.11.18: this seat rebuilds compact (`LedgerBodyById`) Merkle-batch bodies
/// byte-identically and may be sent them instead of full bodies.
pub const CAP_COMPACT_BODY_V1: &str = "compact-body-v1";

pub fn peer_has_compact_body(capabilities: &[String]) -> bool {
    capabilities.iter().any(|c| c == CAP_COMPACT_BODY_V1)
}

pub fn local_hello_capabilities() -> Vec<String> {
    let mut caps = vec![CAP_UTC_HEADER_V5.to_string()];
    caps.push(CAP_COMPACT_BODY_V1.to_string());
    // Negotiated lean tx gossip (off with FPL_LEAN_TX_GOSSIP=0).
    if crate::crypto::lean_tx_gossip_enabled() {
        caps.push(crate::crypto::CAP_LEAN_TX_GOSSIP_V1.to_string());
    }
    caps
}

pub fn peer_has_utc_header_v5(capabilities: &[String]) -> bool {
    capabilities.iter().any(|c| c == CAP_UTC_HEADER_V5)
}

/// Soft compatibility: when local tip is at/after H_utc, a peer without the
/// capability cannot safely pack/OK v5 tips. Returns a human reason or None.
/// Does **not** close sessions by itself — see `utc_hello_enforce`.
pub fn utc_peer_capability_gap(
    local_tip_height: u64,
    utc_from_height: u64,
    peer_capabilities: &[String],
) -> Option<String> {
    if !utc_active(local_tip_height, utc_from_height) {
        return None;
    }
    if peer_has_utc_header_v5(peer_capabilities) {
        return None;
    }
    Some(format!(
        "peer lacks Hello capability {CAP_UTC_HEADER_V5} while local tip {local_tip_height} >= H_utc {utc_from_height}"
    ))
}

/// Hard Hello enforcement height. `u64::MAX` = never (default on every network,
/// including 2300). Arming this is a **separate** preactivation decision — never
/// implied by shipping the capability advertisement.
pub const UTC_HELLO_ENFORCE_FROM_HEIGHT_DISABLED: u64 = u64::MAX;

/// Baked 2300 Hello-enforce — **must stay disabled** until the arming commit.
/// Signed-off rule: set this to `H_utc - UTC hello lead` (1_000 blocks) once
/// every seat advertises `utc-header-v5`. Until then it stays `u64::MAX`.
pub const TESTNET_2300_UTC_HELLO_ENFORCE_FROM_HEIGHT: u64 =
    UTC_HELLO_ENFORCE_FROM_HEIGHT_DISABLED;

/// Env for non-2300 rehearsal only. Ignored on public testnet 2300 (always the baked constant).
pub const ENV_UTC_HELLO_ENFORCE_FROM_HEIGHT: &str = "FPL_UTC_HELLO_ENFORCE_FROM_HEIGHT";

/// Hard Hello capability enforce height. **2300 uses the baked constant**
/// (disabled until the arming commit). Other nets may set
/// `FPL_UTC_HELLO_ENFORCE_FROM_HEIGHT` for isolated rehearsal.
pub fn network_utc_hello_enforce_from_height(network_id: u32) -> u64 {
    if network_id == NETWORK_ID_PUBLIC_TESTNET_2300 {
        return TESTNET_2300_UTC_HELLO_ENFORCE_FROM_HEIGHT;
    }
    env_u64(ENV_UTC_HELLO_ENFORCE_FROM_HEIGHT).unwrap_or(UTC_HELLO_ENFORCE_FROM_HEIGHT_DISABLED)
}


thread_local! {
    /// Test / rehearsal only: override OS wall for deterministic pack + live skew.
    static WALL_OVERRIDE_MS: std::cell::Cell<Option<u64>> = std::cell::Cell::new(None);
    /// Test / rehearsal only: override `network_utc_from_height` for a network_id.
    static FROM_HEIGHT_OVERRIDE: std::cell::Cell<Option<(u32, u64)>> =
        std::cell::Cell::new(None);
}

/// Install a wall-clock override for the current thread (`None` clears).
pub fn set_wall_unix_ms_override(ms: Option<u64>) {
    WALL_OVERRIDE_MS.with(|c| c.set(ms));
}

/// Install a per-network activation override for the current thread (`None` clears).
/// Ignored for production reasoning on 2300 unless tests explicitly set it — the
/// baked constant remains `u64::MAX`; this override exists so rehearsal does not
/// mutate process-global env (parallel-test safe per thread).
pub fn set_utc_from_height_override(network_id: u32, from_height: Option<u64>) {
    FROM_HEIGHT_OVERRIDE.with(|c| {
        c.set(from_height.map(|h| (network_id, h)));
    });
}

/// Injectable pack / live-admission wall clock carried on `Node`.
///
/// `System` reads [`wall_unix_ms`] (OS wall, or the legacy thread-local test
/// override). `Frozen` / `Offset` let tests and isolated rehearsals pack under
/// V5 deterministically per Node, without any process-global state. Production
/// constructors always use `System`. Never used for `sealed_at_ms` physics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UtcPackClock {
    #[default]
    System,
    /// Always return this Unix-ms value.
    Frozen(u64),
    /// System wall shifted by this many ms (negative = behind). Saturates at 0.
    Offset(i64),
}

impl UtcPackClock {
    pub fn now_unix_ms(&self) -> u64 {
        match *self {
            UtcPackClock::System => wall_unix_ms(),
            UtcPackClock::Frozen(ms) => ms,
            UtcPackClock::Offset(d) => {
                let w = wall_unix_ms();
                if d >= 0 {
                    w.saturating_add(d as u64)
                } else {
                    w.saturating_sub(d.unsigned_abs())
                }
            }
        }
    }
}

/// Signed off 2026-11-07: Hello min-release safety window (1_000 blocks).
/// When Hello enforce is armed, peers lacking `utc-header-v5` are hard-closed
/// from `H_utc - lead` (so they cannot deliver Pack/OK across the activation)
/// or from the explicit enforce height, whichever is earlier. Inert while
/// enforce is `u64::MAX` (default everywhere, and on 2300 until the arming commit).
pub const PROPOSED_UTC_HELLO_LEAD_BLOCKS: u64 = 1_000;

/// Effective hard-close height for peers missing `utc-header-v5`.
/// - enforce disabled ⇒ disabled (never), regardless of H_utc.
/// - H_utc disabled ⇒ the explicit enforce height.
/// - otherwise `min(enforce_from, H_utc - lead)`.
pub fn utc_hello_hard_close_from(enforce_from: u64, utc_from: u64, lead: u64) -> u64 {
    if enforce_from == UTC_HELLO_ENFORCE_FROM_HEIGHT_DISABLED {
        return UTC_HELLO_ENFORCE_FROM_HEIGHT_DISABLED;
    }
    if utc_from == UTC_FROM_HEIGHT_DISABLED {
        return enforce_from;
    }
    enforce_from.min(utc_from.saturating_sub(lead))
}

/// OS wall-clock Unix milliseconds, or the thread override when set.
/// Used only when UTC activation is armed on the pack / live-admission path.
/// Not used for `sealed_at_ms` physics.
pub fn wall_unix_ms() -> u64 {
    if let Some(ms) = WALL_OVERRIDE_MS.with(|c| c.get()) {
        return ms;
    }
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{sha256_hex, CryptoScheme, KeyRing};
    use crate::qc_header::{header_msg_v4, inner_hash_hex};

    fn sample_v4() -> String {
        let claim = "ab".repeat(32);
        let cur = "cd".repeat(32);
        header_msg_v4(
            100,
            "parent",
            2200,
            "v1",
            "txroot",
            "stateroot",
            &["a".into()],
            "cert",
            &claim,
            &cur,
        )
    }

    #[test]
    fn disabled_by_default_on_2300() {
        assert_eq!(TESTNET_2300_UTC_FROM_HEIGHT, UTC_FROM_HEIGHT_DISABLED);
        assert_eq!(
            TESTNET_2300_UTC_HELLO_ENFORCE_FROM_HEIGHT,
            UTC_HELLO_ENFORCE_FROM_HEIGHT_DISABLED
        );
        assert_eq!(
            network_utc_hello_enforce_from_height(NETWORK_ID_PUBLIC_TESTNET_2300),
            UTC_HELLO_ENFORCE_FROM_HEIGHT_DISABLED
        );
        assert!(!utc_active(0, UTC_FROM_HEIGHT_DISABLED));
        assert!(!utc_active(u64::MAX - 1, UTC_FROM_HEIGHT_DISABLED));
        assert!(!utc_active_on(NETWORK_ID_PUBLIC_TESTNET_2300, 1_000_000));
        assert_eq!(
            header_domain(500, UTC_FROM_HEIGHT_DISABLED),
            HeaderDomain::LegacyV4
        );
    }

    #[test]
    fn activation_boundary() {
        let h = 1_000u64;
        assert!(!utc_active(h - 1, h));
        assert!(utc_active(h, h));
        assert!(utc_active(h + 1, h));
        assert_eq!(header_domain(h - 1, h), HeaderDomain::LegacyV4);
        assert_eq!(header_domain(h, h), HeaderDomain::V5);
    }

    #[test]
    fn v5_extends_v4_with_utc_field() {
        let v4 = sample_v4();
        let utc = 1_700_000_000_000u64;
        let v5 = header_msg_v5_from_v4(&v4, utc).unwrap();
        assert!(v5.starts_with("pl-ledger:v5|"));
        assert!(v5.ends_with(&format!("|utc:{utc}")));
        assert!(!v5.contains("pl-ledger:v4|"));
        // Direct builder matches from_v4
        let claim = "ab".repeat(32);
        let cur = "cd".repeat(32);
        let direct = header_msg_v5(
            100,
            "parent",
            2200,
            "v1",
            "txroot",
            "stateroot",
            &["a".into()],
            "cert",
            &claim,
            &cur,
            utc,
        );
        assert_eq!(v5, direct);
    }

    #[test]
    fn mutated_utc_changes_commitment() {
        let v4 = sample_v4();
        let a = header_msg_v5_from_v4(&v4, 1_700_000_000_000).unwrap();
        let b = header_msg_v5_from_v4(&v4, 1_700_000_000_001).unwrap();
        assert_ne!(a, b);
        assert_ne!(sha256_hex(a.as_bytes()), sha256_hex(b.as_bytes()));
        let sig = "deadbeef";
        assert_ne!(inner_hash_hex(&a, sig), inner_hash_hex(&b, sig));
    }

    #[test]
    fn historical_inactive_rejects_nonzero_utc() {
        let b = UtcSkewBounds::default();
        assert!(check_utc_historical(10, 100, 0, 0, &b).is_ok());
        assert!(matches!(
            check_utc_historical(10, 100, 99, 0, &b),
            Err(UtcCheckError::UnexpectedUtc { .. })
        ));
    }

    #[test]
    fn historical_active_requires_utc_and_monotonic() {
        let b = UtcSkewBounds::default();
        let h = 100u64;
        assert!(matches!(
            check_utc_historical(h, h, 0, 0, &b),
            Err(UtcCheckError::MissingUtc { .. })
        ));
        // First UTC block: parent_utc=0 bootstrap OK
        assert!(check_utc_historical(h, h, 1_700_000_000_000, 0, &b).is_ok());
        // Later: monotonic
        assert!(check_utc_historical(h + 1, h, 1_700_000_000_100, 1_700_000_000_000, &b).is_ok());
        assert!(matches!(
            check_utc_historical(h + 1, h, 1_699_999_999_999, 1_700_000_000_000, &b),
            Err(UtcCheckError::NotMonotonic { .. })
        ));
    }

    #[test]
    fn live_skew_boundaries_not_applied_on_historical() {
        let b = UtcSkewBounds {
            max_ahead_ms: 5_000,
            max_behind_ms: 60_000,
            require_monotonic: true,
        };
        let h = 50u64;
        let old = 1_600_000_000_000u64; // far in the past vs any "now"
        // Historical: accept ancient stamp
        assert!(check_utc_historical(h, h, old, 0, &b).is_ok());
        // Live with now far ahead: reject behind
        let now = old + 120_000;
        assert!(matches!(
            check_utc_live_admission(h, h, old, 0, now, &b),
            Err(UtcCheckError::BehindWall { .. })
        ));
        // Live within behind window
        assert!(check_utc_live_admission(h, h, old, 0, old + 30_000, &b).is_ok());
        // Live ahead too far
        assert!(matches!(
            check_utc_live_admission(h, h, now + 10_000, 0, now, &b),
            Err(UtcCheckError::AheadOfWall { .. })
        ));
        // Live ahead within bound
        assert!(check_utc_live_admission(h, h, now + 4_000, 0, now, &b).is_ok());
    }

    #[test]
    fn historical_replay_without_wall_rejection() {
        // Simulates archive restore: stamps from weeks ago must verify offline.
        let b = UtcSkewBounds::default();
        let h_act = 10u64;
        let mut parent = 0u64;
        for i in 0..5u64 {
            let height = h_act + i;
            let utc = 1_700_000_000_000 + i * 1_000;
            check_utc_historical(height, h_act, utc, parent, &b).unwrap();
            parent = utc;
        }
        // Same bytes would fail live if wall moved far — that is intentional split.
        let now = parent + PROPOSED_UTC_MAX_BEHIND_MS + 1;
        assert!(check_utc_live_admission(h_act + 4, h_act, parent, parent - 1_000, now, &b).is_err());
    }

    #[test]
    fn packer_msg_domain_switches_cleanly() {
        let skips: Vec<String> = vec![];
        let claim = "aa".repeat(32);
        let cur = "bb".repeat(32);
        let legacy = packer_msg_for_domain(
            HeaderDomain::LegacyV4,
            9,
            "p",
            2200,
            "v1",
            "t",
            "s",
            &skips,
            "c",
            &claim,
            &cur,
            0,
        );
        assert!(legacy.starts_with("pl-ledger:v4|"));
        let v5 = packer_msg_for_domain(
            HeaderDomain::V5,
            10,
            "p",
            2200,
            "v1",
            "t",
            "s",
            &skips,
            "c",
            &claim,
            &cur,
            42,
        );
        assert!(v5.starts_with("pl-ledger:v5|"));
        assert!(v5.ends_with("|utc:42"));
    }

    #[test]
    fn hmac_sig_covers_utc_field() {
        let mut keys = KeyRing::new(CryptoScheme::HmacDev);
        keys.generate_id("v1");
        let skips: Vec<String> = vec![];
        let claim = "cc".repeat(32);
        let cur = "dd".repeat(32);
        let msg_a = header_msg_v5(10, "p", 2200, "v1", "t", "s", &skips, "c", &claim, &cur, 100);
        let msg_b = header_msg_v5(10, "p", 2200, "v1", "t", "s", &skips, "c", &claim, &cur, 101);
        let sig = keys.sign("v1", &msg_a).unwrap();
        assert!(keys
            .verify_message(keys.scheme, "v1", &keys.public_hex("v1").unwrap(), &msg_a, &sig)
            .is_ok());
        assert!(keys
            .verify_message(keys.scheme, "v1", &keys.public_hex("v1").unwrap(), &msg_b, &sig)
            .is_err());
    }

    #[test]
    fn old_new_decoding_compat_inactive_zero() {
        // Serde-side: zero field omitted / default — exercised at Ledger layer;
        // here we only assert inactive path demands zero.
        let b = UtcSkewBounds::default();
        assert!(check_utc_historical(1, UTC_FROM_HEIGHT_DISABLED, 0, 0, &b).is_ok());
    }

    #[test]
    fn stalled_chain_recovery_is_operational_not_auto_widen() {
        // Documented behaviour: after a long stall, live admission fails BehindWall;
        // recovery is widen bounds via coordinated env on *devnet* or wait for
        // preactivation signoff — this PR does not auto-widen on 2300.
        let b = UtcSkewBounds::default();
        let stamp = 1_700_000_000_000u64;
        let wall_after_stall = stamp + b.max_behind_ms + 5_000;
        let err = check_utc_live_admission(100, 100, stamp, 0, wall_after_stall, &b).unwrap_err();
        assert!(matches!(err, UtcCheckError::BehindWall { .. }));
        // Same stamp still historically fine (replay / restore).
        assert!(check_utc_historical(100, 100, stamp, 0, &b).is_ok());
    }

    #[test]
    fn unarmed_seal_v4_forces_zero_utc_and_v4_msg() {
        use crate::crypto::{CryptoScheme, KeyRing};
        use crate::Ledger;
        let mut keys = KeyRing::new(CryptoScheme::HmacDev);
        keys.generate_id("v1");
        let claim = "aa".repeat(32);
        let cur = "bb".repeat(32);
        let next = "cc".repeat(32);
        // Pass a nonzero utc arg while activation disabled — must store 0 and verify.
        let led = Ledger::seal_v4(
            10,
            "parent".into(),
            2200,
            "v1",
            &keys,
            vec![],
            "state".into(),
            1_000,
            9_999_999_999, // ignored while unarmed
            vec![],
            None,
            claim.clone(),
            vec!["v1".into()],
            vec!["v1".into()],
            cur.clone(),
            next.clone(),
        )
        .unwrap();
        assert_eq!(led.sealed_utc_ms, 0);
        assert!(led.is_v4());
        assert!(led.verify_packer(&keys));
        // Mutating utc after seal must fail verify (inactive rejects nonzero).
        let mut bad = led.clone();
        bad.sealed_utc_ms = 1;
        assert!(!bad.verify_packer(&keys));
    }

    #[test]
    fn v5_domain_msg_signature_roundtrip() {
        use crate::crypto::{CryptoScheme, KeyRing};
        let mut keys = KeyRing::new(CryptoScheme::HmacDev);
        keys.generate_id("v1");
        let skips: Vec<String> = vec![];
        let claim = "ee".repeat(32);
        let cur = "ff".repeat(32);
        let utc = 1_700_000_000_042u64;
        let msg = packer_msg_for_domain(
            HeaderDomain::V5,
            10,
            "p",
            2200,
            "v1",
            "t",
            "s",
            &skips,
            "c",
            &claim,
            &cur,
            utc,
        );
        let sig = keys.sign("v1", &msg).unwrap();
        let pk = keys.public_hex("v1").unwrap();
        assert!(keys.verify_message(keys.scheme, "v1", &pk, &msg, &sig).is_ok());
        let msg_bad = packer_msg_for_domain(
            HeaderDomain::V5,
            10,
            "p",
            2200,
            "v1",
            "t",
            "s",
            &skips,
            "c",
            &claim,
            &cur,
            utc + 1,
        );
        assert!(keys.verify_message(keys.scheme, "v1", &pk, &msg_bad, &sig).is_err());
        let legacy = packer_msg_for_domain(
            HeaderDomain::LegacyV4,
            9,
            "p",
            2200,
            "v1",
            "t",
            "s",
            &skips,
            "c",
            &claim,
            &cur,
            utc,
        );
        assert!(legacy.starts_with("pl-ledger:v4|"));
        assert!(!legacy.contains("utc:"));
    }
}
