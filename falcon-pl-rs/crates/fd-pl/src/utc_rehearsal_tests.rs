// Copyright (c) 2025-2026 BEARTEC. All rights reserved. See LICENSE.
//! **In-process simulation harness** for UTC header activation — not a multi-node
//! soak, not production contact.
//!
//! Covers (unit/integration on a private network_id with thread-local overrides):
//! - pre / post activation domain selection + seal/verify
//! - old peer (no capability) vs new peer Hello soft-gap / hard-enforce
//! - mutated / forged sealed_utc_ms invalidates commitment
//! - serde restart/replay round-trip (historical path accepts; live skew rejects stale)
//! - clock skew, backwards step, stalled recovery (operational, no auto-widen)
//! - version gate default-off on 2300 / unarmed enforce height
//!
//! Isolation: no live keys, peers, ports, data dirs, or Tailscale. Controllable
//! `set_utc_from_height_override` + `set_wall_unix_ms_override` only.

use super::*;
use crate::crypto::{sha256_hex, CryptoScheme, KeyRing};
use crate::utc_header::{
    self, check_utc_historical, check_utc_live_admission, header_domain, local_hello_capabilities,
    peer_has_utc_header_v5, set_utc_from_height_override, set_wall_unix_ms_override,
    utc_peer_capability_gap, HeaderDomain, UtcSkewBounds, CAP_UTC_HEADER_V5,
    UTC_FROM_HEIGHT_DISABLED, UTC_HELLO_ENFORCE_FROM_HEIGHT_DISABLED,
};

const NET: u32 = 2200;
const H_UTC: u64 = 100;

fn users() -> Vec<(String, u64)> {
    vec![("alice".into(), 1_000_000), ("bob".into(), 1_000_000)]
}

/// Serializes the tests that set or read `FPL_UTC_HELLO_ENFORCE_FROM_HEIGHT`
/// (process-wide env; the test harness runs tests in parallel threads). The
/// guard also clears the var on drop, so a failing test cannot leak it.
static UTC_ENFORCE_ENV: std::sync::Mutex<()> = std::sync::Mutex::new(());
struct EnforceEnvGuard(#[allow(dead_code)] std::sync::MutexGuard<'static, ()>);
impl Drop for EnforceEnvGuard {
    fn drop(&mut self) {
        std::env::remove_var(utc_header::ENV_UTC_HELLO_ENFORCE_FROM_HEIGHT);
    }
}
fn enforce_env_lock() -> EnforceEnvGuard {
    let g = UTC_ENFORCE_ENV.lock().unwrap_or_else(|e| e.into_inner());
    std::env::remove_var(utc_header::ENV_UTC_HELLO_ENFORCE_FROM_HEIGHT);
    EnforceEnvGuard(g)
}

struct UtcOverrides;
impl Drop for UtcOverrides {
    fn drop(&mut self) {
        set_utc_from_height_override(NET, None);
        set_wall_unix_ms_override(None);
    }
}

fn arm_rehearsal() -> UtcOverrides {
    set_utc_from_height_override(NET, Some(H_UTC));
    set_wall_unix_ms_override(Some(1_700_000_000_000));
    UtcOverrides
}

fn keys() -> KeyRing {
    let mut k = KeyRing::new(CryptoScheme::HmacDev);
    k.generate_id("v1");
    k
}

fn seal_at(height: u64, utc: u64, keys: &KeyRing) -> Ledger {
    let claim = "aa".repeat(32);
    let cur = "bb".repeat(32);
    let next = "cc".repeat(32);
    Ledger::seal_v4(
        height,
        "parent".into(),
        NET,
        "v1",
        keys,
        vec![],
        "state".into(),
        1_000 + height,
        utc,
        vec![],
        None,
        claim,
        vec!["v1".into()],
        vec!["v1".into()],
        cur,
        next,
    )
    .expect("seal")
}

fn hello_with_caps(caps: Vec<String>) -> WireMsg {
    WireMsg::Hello {
        id: "peer".into(),
        public_key: String::new(),
        validators: BTreeMap::new(),
        publics: BTreeMap::new(),
        tip_height: 0,
        tip_hash: String::new(),
        is_hub: false,
        mempool_len: 0,
        product_version: HELLO_WIRE_VERSION.into(),
        hello_network_id: 0,
        archive: false,
        snap_height: 0,
        release_version: PRODUCT_VERSION.into(),
        capabilities: caps,
    }
}

fn bare_node() -> Node {
    let cfg = ChainConfig {
        network_id: NET,
        ..Default::default()
    };
    let mut net = Network::bootstrap(&["v1", "v2", "v3", "v4"], 1000, &[], cfg);
    net.nodes.remove("v1").unwrap()
}

#[test]
fn rehearsal_pre_activation_stays_v4_and_zero_utc() {
    let _g = arm_rehearsal();
    let keys = keys();
    assert_eq!(header_domain(H_UTC - 1, H_UTC), HeaderDomain::LegacyV4);
    let led = seal_at(H_UTC - 1, 9_999, &keys);
    assert_eq!(led.sealed_utc_ms, 0, "pre-H forces zero regardless of arg");
    assert!(led.verify_packer(&keys));
}

#[test]
fn rehearsal_post_activation_binds_utc_in_hash() {
    let _g = arm_rehearsal();
    let keys = keys();
    let utc = 1_700_000_000_000;
    let led = seal_at(H_UTC, utc, &keys);
    assert_eq!(led.sealed_utc_ms, utc);
    assert!(led.verify_packer(&keys));
    let mut forged = led.clone();
    forged.sealed_utc_ms = utc + 1;
    assert!(!forged.verify_packer(&keys), "mutated utc must fail verify");
}

#[test]
fn rehearsal_first_anchor_bootstrap_and_monotonic() {
    let _g = arm_rehearsal();
    let b = UtcSkewBounds::default();
    // First active: parent_utc=0 OK
    check_utc_historical(H_UTC, H_UTC, 1_700_000_000_000, 0, &b).unwrap();
    // Later: monotonic required
    assert!(check_utc_historical(H_UTC + 1, H_UTC, 1_700_000_000_100, 1_700_000_000_000, &b).is_ok());
    assert!(check_utc_historical(H_UTC + 1, H_UTC, 1_699_999_999_999, 1_700_000_000_000, &b).is_err());
}

#[test]
fn rehearsal_live_skew_vs_historical_replay() {
    let _g = arm_rehearsal();
    let b = UtcSkewBounds {
        max_ahead_ms: 5_000,
        max_behind_ms: 60_000,
        require_monotonic: true,
    };
    let stamp = 1_700_000_000_000u64;
    set_wall_unix_ms_override(Some(stamp));
    check_utc_live_admission(H_UTC, H_UTC, stamp, 0, utc_header::wall_unix_ms(), &b).unwrap();
    // Stalled: wall far ahead → live fails; historical still OK (restart/replay)
    set_wall_unix_ms_override(Some(stamp + b.max_behind_ms + 1));
    assert!(check_utc_live_admission(H_UTC, H_UTC, stamp, 0, utc_header::wall_unix_ms(), &b).is_err());
    assert!(check_utc_historical(H_UTC, H_UTC, stamp, 0, &b).is_ok());
    // Backwards step on live
    set_wall_unix_ms_override(Some(stamp));
    assert!(check_utc_live_admission(H_UTC + 1, H_UTC, stamp - 1, stamp, utc_header::wall_unix_ms(), &b).is_err());
}

#[test]
fn rehearsal_serde_restart_roundtrip_preserves_utc_commitment() {
    let _g = arm_rehearsal();
    let keys = keys();
    let led = seal_at(H_UTC, 1_700_000_000_000, &keys);
    let bytes = serde_json::to_vec(&led).unwrap();
    let restored: Ledger = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(restored.sealed_utc_ms, led.sealed_utc_ms);
    assert_eq!(restored.ledger_hash, led.ledger_hash);
    assert!(restored.verify_packer(&keys));
    // Header gossip path
    let hdr = restored.header();
    assert_eq!(hdr.sealed_utc_ms, restored.sealed_utc_ms);
    assert!(hdr.verify_packer(&keys));
}

#[test]
fn rehearsal_old_peer_capability_soft_gap_vs_hard_enforce() {
    let _env = enforce_env_lock();
    let _g = arm_rehearsal();
    // Soft gap when tip past H_utc and peer has no cap
    let gap = utc_peer_capability_gap(H_UTC, H_UTC, &[]);
    assert!(gap.unwrap().contains(CAP_UTC_HEADER_V5));
    assert!(utc_peer_capability_gap(H_UTC, H_UTC, &local_hello_capabilities()).is_none());
    assert!(utc_peer_capability_gap(H_UTC - 1, H_UTC, &[]).is_none(), "pre-H: no soft gap");

    let mut n = bare_node();
    n.tip_height = H_UTC;
    // Default: hard enforce never — old peer Hello still Pass
    assert_eq!(n.utc_hello_enforce_from_height, UTC_HELLO_ENFORCE_FROM_HEIGHT_DISABLED);
    let mut s = HelloSession::default();
    assert_eq!(s.check(&n, &hello_with_caps(vec![])), HelloGate::Pass);

    // Armed enforce (devnet rehearsal only): old peer closed; new peer Pass
    n.utc_hello_enforce_from_height = H_UTC;
    let mut s = HelloSession::default();
    match s.check(&n, &hello_with_caps(vec![])) {
        HelloGate::Close(r) => assert!(r.contains(HELLO_ERR_UTC_CAPABILITY), "{r}"),
        g => panic!("expected close, got {g:?}"),
    }
    let mut s = HelloSession::default();
    assert_eq!(
        s.check(&n, &hello_with_caps(local_hello_capabilities())),
        HelloGate::Pass
    );
}

#[test]
fn rehearsal_production_defaults_stay_unarmed() {
    let _env = enforce_env_lock();
    // Clear any leftover override for 2300
    set_utc_from_height_override(NETWORK_ID_PUBLIC_TESTNET_2300, None);
    assert_eq!(
        utc_header::network_utc_from_height(NETWORK_ID_PUBLIC_TESTNET_2300),
        UTC_FROM_HEIGHT_DISABLED
    );
    assert_eq!(
        UTC_HELLO_ENFORCE_FROM_HEIGHT_DISABLED,
        u64::MAX
    );
    assert!(peer_has_utc_header_v5(&local_hello_capabilities()));
}

#[test]
fn rehearsal_seed_v2_changes_when_utc_mutated_post_activation() {
    let _g = arm_rehearsal();
    let keys = keys();
    let a = seal_at(H_UTC, 1_700_000_000_000, &keys);
    let b = seal_at(H_UTC, 1_700_000_000_001, &keys);
    assert_ne!(a.seed_v2(), b.seed_v2(), "seed_v2 must bind utc when V5");
    assert_ne!(a.ledger_hash, b.ledger_hash);
}

/// In-process **multi-node** Network (6 seats): arm UTC + v4, seal past H_utc,
/// assert every seat agrees on tip hash and committed sealed_utc_ms.
/// This is still one process — see docs/ops/tools/utc_multinode_rehearsal.sh
/// for OS multi-process loopback rehearsal.
#[test]
fn rehearsal_multinode_network_utc_qc_agreement() {
    let _g = arm_rehearsal();
    set_wall_unix_ms_override(Some(1_700_000_000_000));
    let cfg = ChainConfig {
        network_id: NET,
        pack_budget_ms: 0,
        max_txs_per_ledger: 8,
        soft_ok_votes: 3,
        ..Default::default()
    };
    let mut net = Network::bootstrap(
        &["v1", "v2", "v3", "v4", "v5", "v6"],
        1000,
        &users(),
        cfg,
    );
    for n in net.nodes.values_mut() {
        n.qc_header_version = 4;
        n.qc_start_height = 1;
    }
    net.pong_all();
    // Pre-activation heights: sealed_utc_ms must stay 0
    for h in 1..H_UTC {
        for _ in 0..2 {
            net.payment("alice", "bob", 1, 1).unwrap();
        }
        net.seal_next_height().unwrap();
        assert_eq!(net.tip_height(), h);
        for n in net.nodes.values() {
            let tip = n.chain.last().unwrap();
            assert!(tip.is_v4(), "h={h} expected v4");
            assert_eq!(tip.sealed_utc_ms, 0, "pre-H utc must be 0 at h={h}");
            assert!(tip.verify_packer(&n.keys), "pre-H verify h={h}");
        }
    }
    // Cross activation: wall fixed so all packers stamp same UTC
    let wall = 1_700_000_100_000u64;
    set_wall_unix_ms_override(Some(wall));
    for _ in 0..2 {
        net.payment("alice", "bob", 1, 1).unwrap();
    }
    net.seal_next_height().unwrap();
    assert_eq!(net.tip_height(), H_UTC);
    let mut hashes = std::collections::BTreeSet::new();
    let mut utcs = std::collections::BTreeSet::new();
    for n in net.nodes.values() {
        let tip = n.chain.last().unwrap();
        assert!(tip.is_v4());
        assert_eq!(tip.sealed_utc_ms, wall, "post-H utc must equal wall override");
        assert!(tip.verify_packer(&n.keys));
        hashes.insert(tip.ledger_hash.clone());
        utcs.insert(tip.sealed_utc_ms);
        assert!(n.certs.contains_key(&H_UTC), "QC cert present at H_utc");
    }
    assert_eq!(hashes.len(), 1, "all seats must agree tip hash: {hashes:?}");
    assert_eq!(utcs.len(), 1);

    // Mutated utc fails verify on every seat's keyring
    let mut forged = net.nodes["v1"].chain.last().unwrap().clone();
    forged.sealed_utc_ms = wall + 1;
    for n in net.nodes.values() {
        assert!(!forged.verify_packer(&n.keys));
    }

    // Serde restart/replay of tip ledger
    let tip = net.nodes["v1"].chain.last().unwrap().clone();
    let bytes = serde_json::to_vec(&tip).unwrap();
    let restored: Ledger = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(restored.sealed_utc_ms, wall);
    assert!(restored.verify_packer(&net.nodes["v1"].keys));
    // Historical path accepts; live skew with wall jumped rejects
    let b = UtcSkewBounds::default();
    check_utc_historical(H_UTC, H_UTC, wall, 0, &b).unwrap();
    set_wall_unix_ms_override(Some(wall + b.max_behind_ms + 1));
    assert!(check_utc_live_admission(
        H_UTC,
        H_UTC,
        wall,
        0,
        utc_header::wall_unix_ms(),
        &b
    )
    .is_err());
}

#[test]
fn rehearsal_multinode_unarmed_stays_zero_utc_across_seats() {
    // No arm_rehearsal — production-like disabled from_height
    set_utc_from_height_override(NET, None);
    set_wall_unix_ms_override(None);
    let cfg = ChainConfig {
        network_id: NET,
        pack_budget_ms: 0,
        max_txs_per_ledger: 8,
        ..Default::default()
    };
    let mut net = Network::bootstrap(&["v1", "v2", "v3", "v4", "v5", "v6"], 1000, &users(), cfg);
    for n in net.nodes.values_mut() {
        n.qc_header_version = 4;
        n.qc_start_height = 1;
    }
    net.pong_all();
    for _ in 0..2 {
        net.payment("alice", "bob", 1, 1).unwrap();
    }
    net.seal_next_height().unwrap();
    for n in net.nodes.values() {
        let tip = n.chain.last().unwrap();
        assert_eq!(tip.sealed_utc_ms, 0);
        assert!(tip.verify_packer(&n.keys));
    }
}

#[test]
fn rehearsal_hello_enforce_env_ignored_on_2300() {
    let _env = enforce_env_lock();
    // Safety: even if env is set, 2300 stays disabled.
    std::env::set_var(utc_header::ENV_UTC_HELLO_ENFORCE_FROM_HEIGHT, "1");
    assert_eq!(
        utc_header::network_utc_hello_enforce_from_height(NETWORK_ID_PUBLIC_TESTNET_2300),
        UTC_HELLO_ENFORCE_FROM_HEIGHT_DISABLED
    );
    std::env::remove_var(utc_header::ENV_UTC_HELLO_ENFORCE_FROM_HEIGHT);
    // Non-2300 honours env when set
    std::env::set_var(utc_header::ENV_UTC_HELLO_ENFORCE_FROM_HEIGHT, "42");
    assert_eq!(utc_header::network_utc_hello_enforce_from_height(NET), 42);
    std::env::remove_var(utc_header::ENV_UTC_HELLO_ENFORCE_FROM_HEIGHT);
    assert_eq!(
        utc_header::network_utc_hello_enforce_from_height(NET),
        UTC_HELLO_ENFORCE_FROM_HEIGHT_DISABLED
    );
}



#[test]
fn rehearsal_malformed_and_skew_admission_matrix() {
    let _g = arm_rehearsal();
    let b = UtcSkewBounds {
        max_ahead_ms: 5_000,
        max_behind_ms: 60_000,
        require_monotonic: true,
    };
    let now = 1_700_000_050_000u64;
    // Malformed: nonzero UTC before activation
    assert!(check_utc_historical(H_UTC - 1, H_UTC, 1, 0, &b).is_err());
    // Malformed: missing UTC after activation
    assert!(check_utc_historical(H_UTC, H_UTC, 0, 0, &b).is_err());
    // Backward vs parent (historical + live)
    assert!(check_utc_historical(H_UTC + 1, H_UTC, now - 1, now, &b).is_err());
    assert!(check_utc_live_admission(H_UTC + 1, H_UTC, now - 1, now, now, &b).is_err());
    // Future: too far ahead of wall (live only)
    assert!(check_utc_live_admission(H_UTC, H_UTC, now + 10_000, 0, now, &b).is_err());
    assert!(check_utc_live_admission(H_UTC, H_UTC, now + 4_000, 0, now, &b).is_ok());
    // Historical accepts stamp that would fail live skew (outside behind window)
    let old = now - b.max_behind_ms - 1;
    assert!(check_utc_historical(H_UTC, H_UTC, old, 0, &b).is_ok());
    assert!(check_utc_live_admission(H_UTC, H_UTC, old, 0, now, &b).is_err());
}


// Snapshot save/load UTC tip preservation is covered by process-level
// utc_restart_compat_rehearsal.sh (kill/wipe/restart catch-up) plus
// rehearsal_serde_restart_roundtrip_preserves_utc_commitment. A full
// Network::seal loop here races v4 next-committee freeze under --test-threads>1.

/// Tip-0 joiner catch-up via `ledgers_from` + `apply_catchup_batch` while peers
/// still hold full bodies in the RAM window (no archive body store).
/// Process-level NeedLedgers wire routing is covered separately; this asserts
/// the body-availability precondition for that path and UTC stamp retention.
#[test]
fn rehearsal_tip0_catchup_ledgers_from_ram_window_preserves_utc() {
    // Private-net H_utc=2 so a short tip stays inside max_body_ledgers.
    set_utc_from_height_override(NET, Some(2));
    set_wall_unix_ms_override(Some(1_700_000_000_000));
    let _clear = UtcOverrides;
    let cfg = ChainConfig {
        network_id: NET,
        pack_budget_ms: 0,
        max_txs_per_ledger: 8,
        ..Default::default()
    };
    let mut net = Network::bootstrap(&["v1", "v2", "v3", "v4", "v5", "v6"], 1000, &users(), cfg);
    for n in net.nodes.values_mut() {
        n.qc_header_version = 4;
        n.qc_start_height = 1;
    }
    net.pong_all();
    for _ in 0..4 {
        let _ = net.payment("alice", "bob", 1, 1);
        net.seal_next_height().unwrap();
    }
    let tip = net.tip_height();
    assert!(tip >= 2);
    let donor = net.nodes.get("v1").unwrap();
    assert!(
        donor.chain.iter().all(|l| l.has_body()),
        "RAM window must retain bodies for NeedLedgers tip0 path"
    );
    let batch = donor.ledgers_from(1, 64);
    assert!(!batch.is_empty(), "ledgers_from(1) must serve contiguous bodies");
    assert_eq!(batch[0].height, 1);
    assert_eq!(batch.last().unwrap().height, tip);
    assert!(batch.last().unwrap().sealed_utc_ms > 0);
    let tip_hash = donor.tip_hash.clone();
    let tip_utc = donor.chain.last().unwrap().sealed_utc_ms;

    // Reset v3 to tip-0 (fresh joiner) and apply the batch.
    {
        let n = net.nodes.get_mut("v3").unwrap();
        n.tip_height = 0;
        n.tip_hash = sha256_hex(b"pl-genesis-v1");
        n.chain.clear();
        n.seen_at_height.clear();
        n.state = WorldState::genesis(&users());
        n.best_peer_tip = tip;
        let new_tip = n.apply_catchup_batch(&batch).expect("tip0 catch-up");
        assert_eq!(new_tip, tip);
        assert_eq!(n.tip_hash, tip_hash);
        assert_eq!(n.chain.last().unwrap().sealed_utc_ms, tip_utc);
    }
}

// ---------------------------------------------------------------------------
// Gate 1: injectable pack clock on the real Node seal path.
// ---------------------------------------------------------------------------

fn clock_net(h_utc: u64, clock: utc_header::UtcPackClock) -> Network {
    let cfg = ChainConfig {
        network_id: NET,
        pack_budget_ms: 0,
        max_txs_per_ledger: 8,
        soft_ok_votes: 3,
        ..Default::default()
    };
    set_utc_from_height_override(NET, Some(h_utc));
    // Prove the Node clock, not the legacy thread-local wall, drives packing.
    set_wall_unix_ms_override(None);
    let mut net = Network::bootstrap(&["v1", "v2", "v3", "v4", "v5", "v6"], 1000, &users(), cfg);
    for n in net.nodes.values_mut() {
        n.qc_header_version = 4;
        n.qc_start_height = 1;
        n.utc_pack_clock = clock;
    }
    net.pong_all();
    net
}

fn seal_to(net: &mut Network, h: u64) {
    while net.tip_height() < h {
        net.payment("alice", "bob", 1, 1).unwrap();
        net.seal_next_height().unwrap();
    }
}

#[test]
fn rehearsal_node_pack_clock_frozen_drives_sealed_utc_and_commitment() {
    let _g = UtcOverrides;
    const H: u64 = 3;
    const T: u64 = 1_650_000_000_000; // far from real wall: proves injection
    let mut a = clock_net(H, utc_header::UtcPackClock::Frozen(T));
    seal_to(&mut a, H);
    let mut b = clock_net(H, utc_header::UtcPackClock::Frozen(T + 1));
    seal_to(&mut b, H);
    for h in 1..H {
        let la = a.nodes["v1"].chain.iter().find(|l| l.height == h).unwrap();
        let lb = b.nodes["v1"].chain.iter().find(|l| l.height == h).unwrap();
        assert_eq!(la.sealed_utc_ms, 0, "pre-H utc 0 at {h}");
        assert_eq!(la.ledger_hash, lb.ledger_hash, "pre-H hash independent of clock at {h}");
    }
    let mut hashes = std::collections::BTreeSet::new();
    for n in a.nodes.values() {
        let tip = n.chain.last().unwrap();
        assert_eq!(tip.height, H);
        assert_eq!(tip.sealed_utc_ms, T, "sealed_utc_ms follows injected Node clock");
        assert!(tip.verify_packer(&n.keys));
        assert!(n.certs.contains_key(&H), "QC formed over V5 tip");
        hashes.insert(tip.ledger_hash.clone());
    }
    assert_eq!(hashes.len(), 1);
    let tb = b.nodes["v1"].chain.last().unwrap();
    assert_eq!(tb.sealed_utc_ms, T + 1);
    assert_ne!(
        a.nodes["v1"].chain.last().unwrap().ledger_hash,
        tb.ledger_hash,
        "v5 commitment must change when the injected clock changes"
    );
}

#[test]
fn rehearsal_pack_clock_offset_and_frozen_unit() {
    let _g = UtcOverrides;
    set_wall_unix_ms_override(Some(1_000_000));
    assert_eq!(utc_header::UtcPackClock::System.now_unix_ms(), 1_000_000);
    assert_eq!(utc_header::UtcPackClock::Frozen(7).now_unix_ms(), 7);
    assert_eq!(utc_header::UtcPackClock::Offset(500).now_unix_ms(), 1_000_500);
    assert_eq!(utc_header::UtcPackClock::Offset(-500).now_unix_ms(), 999_500);
    assert_eq!(utc_header::UtcPackClock::Offset(-2_000_000).now_unix_ms(), 0);
    assert_eq!(utc_header::UtcPackClock::default(), utc_header::UtcPackClock::System);
    assert_eq!(bare_node().utc_pack_clock, utc_header::UtcPackClock::System, "prod default");
}

#[test]
fn rehearsal_node_pack_clock_skewed_peer_rejected_by_live_admission() {
    // Packer clock far ahead of verifiers ⇒ live admission refuses (no QC).
    let _g = UtcOverrides;
    const H: u64 = 3;
    const T: u64 = 1_650_000_000_000;
    let mut net = clock_net(H, utc_header::UtcPackClock::Frozen(T));
    seal_to(&mut net, H - 1);
    let b = UtcSkewBounds::resolve(NET);
    let mut n = net.nodes.remove("v1").unwrap();
    let mut probe = n.chain.last().unwrap().clone();
    probe.height = H;
    probe.sealed_utc_ms = T + b.max_ahead_ms + 1;
    n.utc_pack_clock = utc_header::UtcPackClock::Frozen(T);
    assert!(n.check_sealed_utc_live(&probe).is_err(), "ahead beyond bound refused");
    probe.sealed_utc_ms = T;
    assert!(n.check_sealed_utc_live(&probe).is_ok());
}

// ---------------------------------------------------------------------------
// Gate 2: Hello min-release safety window (PROPOSED lead).
// ---------------------------------------------------------------------------

#[test]
fn rehearsal_hello_lead_window_matrix() {
    let _env = enforce_env_lock();
    let _g = UtcOverrides;
    use utc_header::{utc_hello_hard_close_from as f, PROPOSED_UTC_HELLO_LEAD_BLOCKS as LEAD};
    const H: u64 = 5_000;
    // pure function
    assert_eq!(f(u64::MAX, H, LEAD), u64::MAX, "enforce off ⇒ never");
    assert_eq!(f(10_000, u64::MAX, LEAD), 10_000, "H_utc off ⇒ explicit enforce");
    assert_eq!(f(10_000, H, LEAD), H - LEAD);
    assert_eq!(f(100, H, LEAD), 100, "earlier explicit enforce wins");
    assert_eq!(f(10_000, 10, LEAD), 0, "saturates");

    set_utc_from_height_override(NET, Some(H));
    let mut n = bare_node();
    let old = hello_with_caps(vec![]);
    let new = hello_with_caps(local_hello_capabilities());

    // Enforce unarmed (default): advertise/soft only even deep into window/post-H.
    for tip in [H - LEAD - 1, H - LEAD, H, H + 10] {
        n.tip_height = tip;
        assert_eq!(HelloSession::default().check(&n, &old), HelloGate::Pass, "tip {tip}");
        assert!(!n.utc_refuse_peer_pack_ok(&[]));
    }
    n.tip_height = H;
    assert!(n.utc_peer_capability_gap(&[]).is_some(), "soft gap reported post-H");

    // Armed (non-2300): before window = Pass; inside window = hard close.
    n.utc_hello_enforce_from_height = 10_000;
    assert_eq!(n.utc_hello_hard_close_from(), H - LEAD);
    n.tip_height = H - LEAD - 1;
    assert_eq!(HelloSession::default().check(&n, &old), HelloGate::Pass);
    assert!(!n.utc_refuse_peer_pack_ok(&[]));
    for tip in [H - LEAD, H - 1, H, H + 10] {
        n.tip_height = tip;
        match HelloSession::default().check(&n, &old) {
            HelloGate::Close(r) => assert!(r.contains(HELLO_ERR_UTC_CAPABILITY), "{r}"),
            g => panic!("tip {tip}: expected close, got {g:?}"),
        }
        assert!(n.utc_refuse_peer_pack_ok(&[]));
        assert_eq!(HelloSession::default().check(&n, &new), HelloGate::Pass);
        assert!(!n.utc_refuse_peer_pack_ok(&local_hello_capabilities()));
    }
}

#[test]
fn rehearsal_hello_lead_window_inert_on_2300_defaults() {
    let _env = enforce_env_lock();
    let _g = UtcOverrides;
    struct Clear2300;
    impl Drop for Clear2300 {
        fn drop(&mut self) {
            set_utc_from_height_override(NETWORK_ID_PUBLIC_TESTNET_2300, None);
        }
    }
    let _c = Clear2300;
    // Even env set must be ignored on 2300.
    std::env::set_var(utc_header::ENV_UTC_HELLO_ENFORCE_FROM_HEIGHT, "1");
    let cfg = ChainConfig {
        network_id: NETWORK_ID_PUBLIC_TESTNET_2300,
        ..Default::default()
    };
    let mut net = Network::bootstrap(&["v1", "v2", "v3", "v4"], 1000, &[], cfg);
    std::env::remove_var(utc_header::ENV_UTC_HELLO_ENFORCE_FROM_HEIGHT);
    let mut n = net.nodes.remove("v1").unwrap();
    assert_eq!(n.utc_hello_enforce_from_height, UTC_HELLO_ENFORCE_FROM_HEIGHT_DISABLED);
    assert_eq!(utc_header::TESTNET_2300_UTC_FROM_HEIGHT, UTC_FROM_HEIGHT_DISABLED);
    assert_eq!(n.utc_hello_hard_close_from(), u64::MAX);
    // Even a hypothetical test-only H override on 2300 cannot hard-close: enforce is MAX.
    set_utc_from_height_override(NETWORK_ID_PUBLIC_TESTNET_2300, Some(5_000));
    for tip in [0, 4_000, 5_000, 1_000_000] {
        n.tip_height = tip;
        assert_eq!(n.utc_hello_hard_close_from(), u64::MAX);
        assert!(n.hello_utc_capability_reject(&[]).is_none(), "2300 tip {tip}");
        assert!(!n.utc_refuse_peer_pack_ok(&[]));
    }
}
