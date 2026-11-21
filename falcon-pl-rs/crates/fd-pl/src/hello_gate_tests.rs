// Copyright (c) 2025-2026 BEARTEC. All rights reserved. See LICENSE.
//! v2.9.60 Hello version gate: any 2.9.x before the Gloas gate H, 2.9.x with
//! x >= 60 once the local tip reaches H, and a refused peer's session closes
//! without the peer ever being marked live.

use super::*;

const H: u64 = 10;

fn node(gloas_from: u64, tip: u64) -> Node {
    let cfg = ChainConfig::default();
    let mut net = Network::bootstrap(&["v1", "v2", "v3"], 1000, &[], cfg);
    let mut n = net.nodes.remove("v1").unwrap();
    n.eth_lc_gloas_from_height = gloas_from;
    n.tip_height = tip;
    n.now_ms = 5_000;
    n
}

fn hello(version: &str, network_id: u32) -> WireMsg {
    WireMsg::Hello {
        id: "v2".into(),
        public_key: String::new(),
        validators: BTreeMap::new(),
        publics: BTreeMap::new(),
        tip_height: 0,
        tip_hash: String::new(),
        is_hub: false,
        mempool_len: 0,
        product_version: version.into(),
        hello_network_id: network_id,
        archive: false,
        snap_height: 0,
        release_version: String::new(),
        capabilities: Vec::new(),
    }
}

fn pong() -> WireMsg {
    WireMsg::Pong {
        id: "v2".into(),
        now_ms: 1,
        tip_height: 0,
        tip_hash: String::new(),
        is_hub: false,
        mempool_len: 0,
        archive: false,
        snap_height: 0,
    }
}

/// Model of one mesh session (`peer_session` / `handle_inbound` in the node
/// binary): gate every Hello/Pong first; `Drop` skips the message, `Close`
/// ends the session (no later message is read); only a `Pass` Hello/Pong
/// reaches the handler that calls `pong_with_role`.
fn run_session(n: &mut Node, msgs: &[WireMsg]) -> (Vec<HelloGate>, bool) {
    let mut gate = HelloSession::default();
    let mut verdicts = Vec::new();
    for m in msgs {
        let v = if HelloSession::needs_check(m) {
            gate.check(n, m)
        } else {
            HelloGate::Pass
        };
        verdicts.push(v.clone());
        match v {
            HelloGate::Close(_) => return (verdicts, true),
            HelloGate::Drop => continue,
            HelloGate::Pass => {
                if let WireMsg::Hello { id, .. } | WireMsg::Pong { id, .. } = m {
                    n.pong_with_role(id, 0, 0, false, false, 0);
                }
            }
        }
    }
    (verdicts, false)
}

fn live(n: &Node, id: &str) -> bool {
    n.validators[id].pong_fresh(n.now_ms, n.cfg.pong_window_ms)
}

#[test]
fn predicate_before_gloas_accepts_any_2_9_x() {
    // 2.11.0 still accepts the whole legacy 2.9.x line plus its own 2.11.x.
    for v in ["", "2.9.0", "2.9.59", "2.9.60", "2.9.61", "2.11.0", "2.11.7", "2.11.8", "2.11.9", "2.11.10"] {
        assert!(hello_version_compatible_at(v, false), "{v:?} pre-H");
    }
    for v in ["3.0.0", "2.8.99", "2.8.0", "2.10.0", "2.12.0", "2.90.1", "2.9", "2.10", "2.10.07", "2.9.060", "junk"] {
        assert!(!hello_version_compatible_at(v, false), "{v:?} pre-H");
    }
}

#[test]
fn predicate_after_gloas_requires_2_9_60_or_newer() {
    for v in ["2.9.60", "2.9.61", "2.9.100", "2.11.0", "2.11.60"] {
        assert!(hello_version_compatible_at(v, true), "{v:?} post-H");
    }
    for v in [
        "", "2.9.59", "2.9.0", "2.9.060", "3.0.0", "3.9.60", "2.8.99", "2.10.60", "2.12.60", "2.9", "junk",
    ] {
        assert!(!hello_version_compatible_at(v, true), "{v:?} post-H");
    }
    assert_eq!(HELLO_MIN_PATCH_AFTER_GLOAS, 60);
}

#[test]
fn node_gate_boundary_is_local_tip_at_h() {
    // H - 1: still the roll rule.
    let n = node(H, H - 1);
    for v in ["", "2.9.0", "2.9.59", "2.9.60", "2.9.61"] {
        assert!(n.hello_version_ok(v), "{v:?} at tip H-1");
    }
    assert!(!n.hello_version_ok("2.9.060"), "leading-zero patch at tip H-1");
    // H and later: 2.9.60+ only.
    for tip in [H, H + 1] {
        let n = node(H, tip);
        assert!(!n.hello_version_ok("2.9.59"), "2.9.59 at tip {tip}");
        assert!(!n.hello_version_ok(""), "empty at tip {tip}");
        assert!(n.hello_version_ok("2.9.60"), "2.9.60 at tip {tip}");
        assert!(n.hello_version_ok("2.9.61"), "2.9.61 at tip {tip}");
        assert!(!n.hello_version_ok("2.9.060"), "leading-zero patch at tip {tip}");
    }
    // Placeholder gate (u64::MAX) never activates at a real tip.
    let n = node(u64::MAX, 1_000_000);
    assert!(n.hello_version_ok("2.9.59"));
    assert!(n.hello_version_ok(""));
}

#[test]
fn hello_reject_reason_network_then_version() {
    let n = node(H, H);
    let net_id = n.cfg.network_id;
    assert_eq!(n.hello_reject_reason(net_id, "2.9.60"), None);
    assert_eq!(n.hello_reject_reason(0, "2.9.61"), None);
    assert_eq!(
        n.hello_reject_reason(net_id.wrapping_add(1), "2.9.60"),
        Some(HELLO_ERR_NETWORK_ID)
    );
    assert_eq!(
        n.hello_reject_reason(net_id, "2.9.59"),
        Some(HELLO_ERR_PRODUCT_VERSION)
    );
    assert_eq!(
        n.hello_reject_reason(net_id, ""),
        Some(HELLO_ERR_PRODUCT_VERSION)
    );
}

#[test]
fn post_h_old_hello_closes_session_and_never_marks_live() {
    for v in ["2.9.59", ""] {
        let mut n = node(H, H);
        let id = n.cfg.network_id;
        let (verdicts, closed) = run_session(&mut n, &[hello(v, id), pong(), pong()]);
        assert!(closed, "{v:?}: session must end");
        assert_eq!(
            verdicts,
            vec![HelloGate::Close(HELLO_ERR_PRODUCT_VERSION.into())],
            "{v:?}: nothing after the refused Hello is read"
        );
        assert!(
            !live(&n, "v2"),
            "{v:?}: refused peer must not be marked live"
        );
        assert_eq!(n.validators["v2"].last_pong_ms, 0);
    }
}

#[test]
fn pong_without_accepted_hello_is_dropped() {
    let mut n = node(H, H);
    let (verdicts, closed) = run_session(&mut n, &[pong(), pong()]);
    assert!(!closed);
    assert_eq!(verdicts, vec![HelloGate::Drop, HelloGate::Drop]);
    assert!(!live(&n, "v2"));
    // Non-Hello/Pong traffic (ctl: Status, SubmitTx, ...) is not gated.
    let mut gate = HelloSession::default();
    let other = WireMsg::NeedTxs { max_count: 1 };
    assert!(!HelloSession::needs_check(&other));
    assert_eq!(gate.check(&n, &other), HelloGate::Pass);
}

#[test]
fn network_id_mismatch_closes_session() {
    let mut n = node(u64::MAX, 5);
    let bad = n.cfg.network_id.wrapping_add(1);
    let (verdicts, closed) = run_session(&mut n, &[hello("2.9.60", bad), pong()]);
    assert!(closed);
    assert_eq!(
        verdicts,
        vec![HelloGate::Close(HELLO_ERR_NETWORK_ID.into())]
    );
    assert!(!live(&n, "v2"));
}

#[test]
fn post_h_current_and_next_versions_connect() {
    for v in ["2.9.60", "2.9.61"] {
        let mut n = node(H, H + 3);
        let id = n.cfg.network_id;
        let (verdicts, closed) = run_session(&mut n, &[hello(v, id), pong()]);
        assert!(!closed, "{v:?}");
        assert_eq!(verdicts, vec![HelloGate::Pass, HelloGate::Pass]);
        assert!(live(&n, "v2"), "{v:?}");
    }
}

#[test]
fn pre_h_session_with_2_9_59_closes_once_tip_reaches_h() {
    let mut n = node(H, H - 1);
    let id = n.cfg.network_id;
    let mut gate = HelloSession::default();
    assert_eq!(gate.check(&n, &hello("2.9.59", id)), HelloGate::Pass);
    assert_eq!(gate.accepted_version(), Some("2.9.59"));
    assert_eq!(
        gate.check(&n, &pong()),
        HelloGate::Pass,
        "roll still works below H"
    );
    n.tip_height = H;
    assert_eq!(
        gate.check(&n, &pong()),
        HelloGate::Close(HELLO_ERR_PRODUCT_VERSION.into()),
        "first Pong at tip H ends a pre-2.9.60 session"
    );
    // Legacy empty version opened before H closes too.
    let mut n = node(H, H - 1);
    let mut gate = HelloSession::default();
    assert_eq!(gate.check(&n, &hello("", 0)), HelloGate::Pass);
    n.tip_height = H;
    assert_eq!(
        gate.check(&n, &pong()),
        HelloGate::Close(HELLO_ERR_PRODUCT_VERSION.into())
    );
    // A 2.9.60 session opened before H survives the gate.
    let mut n = node(H, H - 1);
    let mut gate = HelloSession::default();
    assert_eq!(gate.check(&n, &hello("2.9.60", id)), HelloGate::Pass);
    n.tip_height = H;
    assert_eq!(gate.check(&n, &pong()), HelloGate::Pass);
}

/// 2.9.64 roll: a 2.9.64 seat must accept 2.9.63 peers (and vice versa via the
/// same rule) both before and after the Gloas gate, so a mixed fleet keeps
/// catch-up candidates during a seat-by-seat roll.
#[test]
fn rolling_2964_accepts_2963_peers() {
    for v in ["2.9.63", "2.9.64"] {
        assert!(crate::hello_version_compatible_at(v, false), "{v} pre-H");
        assert!(crate::hello_version_compatible_at(v, true), "{v} post-H");
    }
}

/// v2.9.65 rolls onto a 2.9.64 mesh: both directions stay compatible.
#[test]
fn rolling_2965_accepts_2964_peers() {
    for v in ["2.9.60", "2.9.63", "2.9.64", "2.9.65", "2.9.66"] {
        assert!(crate::hello_version_compatible_at(v, false), "{v} pre-H");
        assert!(crate::hello_version_compatible_at(v, true), "{v} post-H");
    }
}

/// v2.9.66 rolls onto a 2.9.65 mesh.
#[test]
fn rolling_2966_accepts_2965_peers() {
    for v in ["2.9.65", "2.9.66"] {
        assert!(crate::hello_version_compatible_at(v, false), "{v} pre-H");
        assert!(crate::hello_version_compatible_at(v, true), "{v} post-H");
    }
}

/// v2.9.67 (join-serve fix, node only) rolls onto a 2.9.66 mesh. A four-part
/// `2.9.66.1` would be refused by every peer, so the patch is 2.9.67.
#[test]
fn rolling_2967_accepts_2966_peers() {
    for v in ["2.9.66", "2.9.67"] {
        assert!(crate::hello_version_compatible_at(v, false), "{v} pre-H");
        assert!(crate::hello_version_compatible_at(v, true), "{v} post-H");
    }
    assert!(!crate::hello_version_compatible("2.9.66.1"));
}

/// v2.9.68 (joiner slow-source switch) rolls onto a 2.9.66/2.9.67 mesh.
#[test]
fn rolling_2968_accepts_2966_2967_peers() {
    for v in ["2.9.66", "2.9.67", "2.9.68"] {
        assert!(crate::hello_version_compatible_at(v, false), "{v} pre-H");
        assert!(crate::hello_version_compatible_at(v, true), "{v} post-H");
    }
}

/// v2.9.69 (catch-up slow-skip, push dedupe) rolls onto a 2.9.66-2.9.68 mesh.
#[test]
fn rolling_2969_accepts_2966_to_2968_peers() {
    for v in ["2.9.66", "2.9.67", "2.9.68", "2.9.69"] {
        assert!(crate::hello_version_compatible_at(v, false), "{v} pre-H");
        assert!(crate::hello_version_compatible_at(v, true), "{v} post-H");
    }
}

/// v2.9.70 rolls onto a 2.9.66-2.9.69 mesh.
#[test]
fn rolling_2970_accepts_2966_to_2969_peers() {
    for v in ["2.9.66", "2.9.67", "2.9.68", "2.9.69", "2.9.70"] {
        assert!(crate::hello_version_compatible_at(v, false), "{v} pre-H");
        assert!(crate::hello_version_compatible_at(v, true), "{v} post-H");
    }
}

/// v2.9.71 rolls onto a 2.9.66-2.9.70 mesh.
#[test]
fn rolling_2971_accepts_2966_to_2970_peers() {
    for v in ["2.9.66", "2.9.67", "2.9.68", "2.9.69", "2.9.70", "2.9.71"] {
        assert!(crate::hello_version_compatible_at(v, false), "{v} pre-H");
        assert!(crate::hello_version_compatible_at(v, true), "{v} post-H");
    }
}

/// v2.9.72 rolls onto a 2.9.66-2.9.71 mesh.
#[test]
fn rolling_2972_accepts_2966_to_2971_peers() {
    for v in ["2.9.66", "2.9.67", "2.9.68", "2.9.69", "2.9.70", "2.9.71", "2.9.72"] {
        assert!(crate::hello_version_compatible_at(v, false), "{v} pre-H");
        assert!(crate::hello_version_compatible_at(v, true), "{v} post-H");
    }
}

/// v2.9.73 rolls onto a 2.9.72 mesh (and older 2.9.66+ outside nodes).
#[test]
fn rolling_2973_accepts_2966_to_2973_peers() {
    for v in ["2.9.66", "2.9.70", "2.9.71", "2.9.72", "2.9.73"] {
        assert!(crate::hello_version_compatible_at(v, false), "{v} pre-H");
        assert!(crate::hello_version_compatible_at(v, true), "{v} post-H");
    }
}

/// v2.9.74 (node-local snapshot resume) rolls onto a 2.9.73 mesh.
#[test]
fn rolling_2974_accepts_2966_to_2974_peers() {
    for v in ["2.9.66", "2.9.72", "2.9.73", "2.9.74"] {
        assert!(crate::hello_version_compatible_at(v, false), "{v} pre-H");
        assert!(crate::hello_version_compatible_at(v, true), "{v} post-H");
    }
}

/// v2.9.75 (main reconciled with the 2.9.74 seats) rolls onto a 2.9.74 mesh.
#[test]
fn rolling_2975_accepts_2966_to_2975_peers() {
    for v in ["2.9.66", "2.9.72", "2.9.73", "2.9.74", "2.9.75", "2.9.76", "2.9.77", "2.9.78", "2.9.79", "2.9.80", "2.9.81"] {
        assert!(crate::hello_version_compatible_at(v, false), "{v} pre-H");
        assert!(crate::hello_version_compatible_at(v, true), "{v} post-H");
    }
}

/// v2.10.0 rolls onto a 2.9.81 mesh. A 2.9.x binary accepts a Hello only if it
/// is `2.9.<digits>` (and, after Gloas, patch >= 60), so a 2.10.0 node must put
/// a legacy-line string in its Hello or every 2.9.81 seat closes its session.
#[test]
fn v2_10_0_hello_wire_version_is_accepted_by_2_9_81_and_by_itself() {
    // The rule a 2.9.81 seat applies (same major.minor 2.9, plain integer
    // patch, no leading zero, patch >= 60 once Gloas is active).
    fn legacy_2_9_81_accepts(peer: &str) -> bool {
        let p: Vec<&str> = peer.split('.').collect();
        p.len() == 3
            && p[0] == "2"
            && p[1] == "9"
            && !p[2].is_empty()
            && p[2].bytes().all(|b| b.is_ascii_digit())
            && (p[2].len() == 1 || !p[2].starts_with('0'))
            && p[2].parse::<u64>().is_ok_and(|x| x >= 60)
    }
    assert!(legacy_2_9_81_accepts(crate::HELLO_WIRE_VERSION), "2.9.81 seat must accept our Hello");
    assert!(
        !legacy_2_9_81_accepts(crate::PRODUCT_VERSION),
        "the real 2.10.0 string is what a 2.9.81 seat refuses (why the wire string differs)"
    );
    for gloas in [false, true] {
        assert!(hello_version_compatible_at(crate::HELLO_WIRE_VERSION, gloas));
        assert!(hello_version_compatible_at(crate::PRODUCT_VERSION, gloas));
    }
    for v in ["2.9.60", "2.9.80", "2.9.81"] {
        assert!(hello_version_compatible_at(v, true), "{v} legacy peer post-H");
    }
}
