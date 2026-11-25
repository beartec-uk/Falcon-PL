// Copyright (c) 2025-2026 BEARTEC. All rights reserved. See LICENSE.
//! `falcon.health.v1` body from a live sim node + dash rendering / fallback.

use super::*;
use crate::health::dash::{render_health, render_status_fallback, Style};

fn net() -> Network {
    let users = vec![("alice".to_string(), 1_000_000u64), ("bob".to_string(), 0)];
    Network::bootstrap(&["v1", "v2", "v3"], 1000, &users, ChainConfig::default())
}

fn sealed(n: usize) -> Network {
    let mut net = net();
    for _ in 0..n {
        net.payment("alice", "bob", 5, 2).unwrap();
        net.seal_next_height().unwrap();
    }
    net
}

#[test]
fn health_core_fields() {
    let net = sealed(4);
    let n = net.nodes.get("v1").unwrap();
    let h = n.health_core();
    assert_eq!(h["schema"], "falcon.health.v1");
    assert_eq!(h["node"]["id"], "v1");
    assert_eq!(h["node"]["version"], PRODUCT_VERSION);
    assert_eq!(h["node"]["network_id"], n.cfg.network_id);
    assert_eq!(h["node"]["role"], "validator");
    assert_eq!(h["node"]["status"], "active");
    assert_eq!(h["chain"]["local_height"], n.tip_height);
    assert_eq!(h["chain"]["tip_hash"], n.tip_hash.as_str());
    assert_eq!(h["chain"]["lag"], 0);
    assert_eq!(h["chain"]["last_block"]["height"], n.tip_height);
    assert_eq!(h["chain"]["blocks_per_min_spark"].as_array().unwrap().len(), health::SPARK_MINUTES);
    assert_eq!(h["consensus"]["missed_turns_limit"], 20);
    assert_eq!(h["consensus"]["bond"], 1000);
    assert_eq!(h["consensus"]["validators"], 3);
    assert_eq!(h["mempool"]["size"], n.mempool.len());
    let seats = h["peers"]["seats"].as_array().unwrap();
    assert_eq!(seats.len(), 2, "self excluded");
    // Proposals by v1 in the retained chain match a direct count.
    let mine = n.chain.iter().filter(|l| l.packer == "v1").count() as u64;
    let props = h["consensus"]["proposals_this_epoch"].as_u64().unwrap();
    assert!(props <= mine);
    if mine > 0 {
        assert!(h["consensus"]["last_proposal"]["height"].as_u64().is_some());
    } else {
        assert!(h["consensus"]["last_proposal"].is_null());
    }
}

#[test]
fn health_core_status_transitions() {
    let mut net = sealed(1);
    let n = net.nodes.get_mut("v1").unwrap();
    n.best_peer_tip = n.tip_height + health::SYNCING_LAG;
    assert_eq!(n.health_core()["node"]["status"], "syncing");
    assert_eq!(n.health_core()["chain"]["lag"], health::SYNCING_LAG);
    n.best_peer_tip = n.tip_height;
    n.validators.get_mut("v1").unwrap().missed_turns = 3;
    assert_eq!(n.health_core()["consensus"]["missed_turns"], 3);
    n.validators.get_mut("v1").unwrap().inactive = true;
    assert_eq!(n.health_core()["node"]["status"], "inactive");
    n.validators.get_mut("v1").unwrap().jailed = true;
    assert_eq!(n.health_core()["node"]["status"], "jailed");
    n.validators.remove("v1");
    assert_eq!(n.health_core()["node"]["status"], "observer");
    assert_eq!(n.health_core()["node"]["role"], "observer");
}

#[test]
fn health_wire_roundtrip_and_not_admin() {
    // Wire form other clients (browser / network list) send verbatim.
    let m: WireMsg = serde_json::from_str(r#"{"type":"health_req"}"#).unwrap();
    assert!(matches!(m, WireMsg::HealthReq { warnings: 0 }));
    let req = WireMsg::HealthReq { warnings: 5 };
    assert!(!req.is_admin());
    let back: WireMsg = serde_json::from_str(&serde_json::to_string(&req).unwrap()).unwrap();
    assert!(matches!(back, WireMsg::HealthReq { warnings: 5 }));
    let rep = WireMsg::Health { body: serde_json::json!({"schema": "falcon.health.v1"}) };
    let back: WireMsg = serde_json::from_str(&serde_json::to_string(&rep).unwrap()).unwrap();
    assert!(matches!(back, WireMsg::Health { body } if body["schema"] == "falcon.health.v1"));
}

fn full_body() -> serde_json::Value {
    let net = sealed(2);
    let mut h = net.nodes.get("v1").unwrap().health_core();
    h["peers"]["count"] = 3.into();
    h["peers"]["outbound"] = 2.into();
    h["peers"]["inbound"] = 1.into();
    h["system"] = serde_json::json!({
        "process": {"cpu_pct": 31.0, "rss_bytes": 6_000_000_000u64, "mem_total_bytes": 16_000_000_000u64, "loadavg": [0.84, 0.91, 0.88]},
        "disk": {"free_bytes": 100_000_000_000u64, "total_bytes": 600_000_000_000u64},
    });
    h["warnings"] = serde_json::json!([
        {"at_ms": 1_000, "level": "WARN", "target": "x", "msg": "peer v3 lag 42"},
        {"at_ms": 2_000, "level": "ERROR", "target": "x", "msg": "rpc timeout"},
    ]);
    h
}

#[test]
fn dash_renders_all_panels() {
    let h = full_body();
    let out = render_health(&h, &Style { color: false }, "127.0.0.1:19101", "now").join("\n");
    for p in ["┤ Node ├", "┤ Chain ├", "┤ Consensus ├", "┤ Peers ├", "┤ System ├", "┤ Recent warnings ├"] {
        assert!(out.contains(p), "missing {p}\n{out}");
    }
    assert!(out.contains("ID        v1"));
    assert!(out.contains("● ACTIVE"));
    assert!(out.contains("Missed turns   0/20"));
    assert!(out.contains("Connected  3  (outbound 2 · inbound 1)"));
    assert!(out.contains("CPU   [||||||              ] 31.0%"), "{out}");
    assert!(out.contains("rpc timeout"));
    assert!(out.contains("q quits"));
    assert!(!out.contains('\x1b'), "no ANSI when colour off");
    // newest warning first
    assert!(out.find("rpc timeout").unwrap() < out.find("peer v3 lag").unwrap());
    let coloured = render_health(&h, &Style { color: true }, "a", "now").join("\n");
    assert!(coloured.contains("\x1b["));
}

#[test]
fn dash_tolerates_sparse_body() {
    // Future/partial bodies must never panic the renderer.
    let out = render_health(&serde_json::json!({}), &Style { color: false }, "a", "now").join("\n");
    assert!(out.contains("┤ Node ├") && out.contains("ID        ?"));
    assert!(out.contains("none"));
}

#[test]
fn dash_fallback_from_legacy_status() {
    let net = sealed(1);
    let n = net.nodes.get("v1").unwrap();
    let (body, _) = n.status_json_split(false, true);
    let out = render_status_fallback(&body, &Style { color: false }, "a", "now", "unknown variant").join("\n");
    assert!(out.contains("health endpoint unavailable (unknown variant)"));
    assert!(out.contains("ID        v1"));
    assert!(out.contains(&format!("Local height   {}", body["tip_height"])));
    assert!(out.contains("┤ Consensus ├"));
}

#[test]
fn health_core_balance_block() {
    let mut net = sealed(1);
    let n = net.nodes.get_mut("v1").unwrap();
    n.claimable.insert("v1".into(), 77);
    {
        let v = n.validators.get_mut("v1").unwrap();
        v.unbonding = 500;
        v.unbond_ready_ms = 123;
        v.bond_account = "v1-bond".into();
    }
    n.state.accounts.entry("v1-bond".into()).or_default().balance = 9_000;
    let liquid = n.state.get("v1").balance;
    let b = &n.health_core()["balance"];
    assert_eq!(b["account"], "v1");
    assert_eq!(b["liquid"], liquid);
    assert_eq!(b["pending_rewards"], 77);
    assert_eq!(b["bonded"], 1000);
    assert_eq!(b["unbonding"], 500);
    assert_eq!(b["unbond_ready_ms"], 123);
    assert_eq!(b["bond_account"], "v1-bond");
    assert_eq!(b["bond_account_liquid"], 9_000);
    // Only public ledger numbers: no key material in the block.
    let txt = b.to_string();
    for k in ["secret", "private", "public_key", "seed"] {
        assert!(!txt.contains(k), "{k} in {txt}");
    }
    // Observer (no seat): zeros, no bond account.
    n.validators.remove("v1");
    let b = &n.health_core()["balance"];
    assert_eq!(b["bonded"], 0);
    assert!(b["bond_account"].is_null());
}

#[test]
fn balance_from_account_status_and_one_line() {
    use crate::health::balance::{from_account_status, one_line};
    let acct = serde_json::json!({"balance": 1234567, "claimable": 89});
    let st = serde_json::json!({"id": "x", "validators": [
        {"id": "other", "bond": 1, "bond_account": "other"},
        {"id": "seat9", "bond": 250000, "unbonding": 1000, "unbond_ready_ms": 5, "bond_account": "seat9-bond"}]});
    let b = from_account_status("seat9", Some(&acct), Some(&st));
    assert_eq!(b["liquid"], 1234567);
    assert_eq!(b["pending_rewards"], 89);
    assert_eq!(b["bonded"], 250000);
    assert_eq!(b["unbonding"], 1000);
    assert_eq!(b["bond_account"], "seat9-bond");
    let l = one_line(&b);
    assert_eq!(l, "seat9: liquid 1,234,567 FPL · bonded 250,000 FPL · pending rewards 89 FPL · unbonding 1,000 FPL · bond account seat9-bond");
    // Querying the bond account finds the seat via bond_account.
    let b = from_account_status("seat9-bond", Some(&acct), Some(&st));
    assert_eq!(b["seat"], "seat9");
    assert_eq!(b["bonded"], 250000);
    // No seat at all.
    let b = from_account_status("nobody", None, Some(&st));
    assert_eq!(one_line(&b), "nobody: liquid 0 FPL · bonded 0 FPL · pending rewards 0 FPL");
}

#[test]
fn health_peer_release_versions() {
    let mut net = sealed(1);
    let n = net.nodes.get_mut("v1").unwrap();
    n.now_ms = 10_000;
    n.note_peer_release("v2", "2.10.3");
    n.note_peer_release("v3", ""); // 2.10.2 Hello: field absent
    n.note_peer_release("", "2.10.3"); // ignored
    n.now_ms = 12_500;
    let h = n.health_core();
    let seats = h["peers"]["seats"].as_array().unwrap();
    let by = |id: &str| seats.iter().find(|p| p["id"] == id).unwrap().clone();
    assert_eq!(by("v2")["release_version"], "2.10.3");
    assert_eq!(by("v3")["release_version"], PEER_RELEASE_NONE);
    assert_eq!(by("v2")["hello_age_ms"], 2_500);
    let rel = h["peers"]["releases"].as_array().unwrap();
    assert_eq!(rel.len(), 2);
    assert_eq!(rel[0]["last_seen_ms"], 10_000);
    // Unseen peer -> null, not "none".
    let n2 = net.nodes.get("v2").unwrap();
    let h2 = n2.health_core();
    let s2 = h2["peers"]["seats"].as_array().unwrap();
    assert!(s2.iter().all(|p| p["release_version"].is_null()));
    // Dash renders the release column.
    let out = render_health(&h, &Style { color: false }, "a", "now").join("\n");
    assert!(out.contains("rel 2.10.3"), "{out}");
}

#[test]
fn peer_release_is_observability_only() {
    let mut net = sealed(2);
    let n = net.nodes.get_mut("v1").unwrap();
    let before = (n.tip_hash.clone(), n.commitment_root());
    n.note_peer_release("v2", "9.9.9");
    assert_eq!(before, (n.tip_hash.clone(), n.commitment_root()));
    assert!(n.hello_release_reject("").is_none());
}

/// crypto-dashboard, 18 Nov 2026: status said `unbond_ready: true` while chain
/// time (tip `sealed_at`, the clock CompleteUnbond is checked against) was still
/// ~13 chain days short. The node's local `now_ms` ran ~17.7 days ahead of chain
/// time. Ready must follow chain time.
#[test]
fn unbond_ready_follows_chain_time_not_local_clock() {
    let mut net = sealed(1);
    let n = net.nodes.get_mut("v1").unwrap();
    let chain = n.parent_sealed_at();
    {
        let v = n.validators.get_mut("v1").unwrap();
        v.unbonding = 500;
        v.unbond_ready_ms = chain + 10_000;
    }
    n.now_ms = chain + 1_000_000_000; // local clock far ahead of chain time
    let b = &n.health_core()["balance"];
    assert_eq!(b["unbond_ready"], false);
    assert_eq!(b["unbond_remaining_ms"], 10_000);
    let st = n.status_json();
    let v1 = st["validators"].as_array().unwrap().iter().find(|v| v["id"] == "v1").unwrap();
    assert_eq!(v1["unbond_ready"], false);
    assert_eq!(v1["unbond_remaining_ms"], 10_000);
    // Once chain time passes the ready stamp it flips, whatever the local clock says.
    n.validators.get_mut("v1").unwrap().unbond_ready_ms = chain;
    n.now_ms = 0;
    assert_eq!(n.health_core()["balance"]["unbond_ready"], true);
    let st = n.status_json();
    let v1 = st["validators"].as_array().unwrap().iter().find(|v| v["id"] == "v1").unwrap();
    assert_eq!(v1["unbond_ready"], true);
    assert_eq!(v1["unbond_remaining_ms"], 0);
}
