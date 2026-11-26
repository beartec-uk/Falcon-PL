use fpl_gateway::allowlist::{self, build_wire, BuildErr, FORBIDDEN_WIRE_TYPES, METHODS};
use fpl_gateway::auth::{self, hash_key, KeyStore};
use fpl_gateway::billing::{verify_signature, SigErr};
use fpl_gateway::config::{Config, Tier};
use fpl_gateway::limits::{month_of, Bucket, Deny, Limiter};
use serde_json::json;
use std::collections::HashMap;
use std::time::{Duration, Instant};

// ---------- auth ----------
#[test]
fn auth_accepts_valid_rejects_unknown_disabled_malformed() {
    let (k1, r1) = auth::generate("k_a", Tier::Builder, "a");
    let (k2, mut r2) = auth::generate("k_b", Tier::Free, "b");
    r2.disabled = true;
    let ks = KeyStore::from_records(vec![r1, r2]).unwrap();
    assert_eq!(ks.authenticate(&k1).unwrap().tier, Tier::Builder);
    assert!(ks.authenticate(&k2).is_none(), "disabled");
    assert!(ks.authenticate("fplk_00").is_none(), "unknown");
    assert!(ks.authenticate(&k1[5..]).is_none(), "no prefix");
    assert!(ks.authenticate(&format!("{k1}x")).is_none());
}

#[test]
fn keys_are_stored_hashed_only() {
    let (k, r) = auth::generate("k_a", Tier::Free, "");
    assert_eq!(r.sha256, hash_key(&k));
    let s = serde_json::to_string(&r).unwrap();
    assert!(!s.contains(&k[5..]), "plaintext must not be serialised");
    assert!(k.starts_with("fplk_") && k.len() == 5 + 64);
}

#[test]
fn keystore_rejects_bad_hash_and_duplicates() {
    let (_, r) = auth::generate("k_a", Tier::Free, "");
    let mut bad = r.clone();
    bad.sha256 = "zz".into();
    assert!(KeyStore::from_records(vec![bad]).is_err());
    assert!(KeyStore::from_records(vec![r.clone(), r]).is_err());
}

#[test]
fn key_extraction_bearer_and_header() {
    let mut h = axum::http::HeaderMap::new();
    h.insert("authorization", "Bearer fplk_abc".parse().unwrap());
    assert_eq!(auth::extract(&h).as_deref(), Some("fplk_abc"));
    let mut h = axum::http::HeaderMap::new();
    h.insert("x-api-key", "fplk_def".parse().unwrap());
    assert_eq!(auth::extract(&h).as_deref(), Some("fplk_def"));
    assert!(auth::extract(&axum::http::HeaderMap::new()).is_none());
}

// ---------- allowlist ----------
#[test]
fn allowlist_never_maps_to_admin_or_mesh() {
    for m in METHODS {
        assert!(!FORBIDDEN_WIRE_TYPES.contains(&m.wire_type), "{} -> {}", m.name, m.wire_type);
    }
    for bad in ["seal_now", "mempool_drop", "snapshot_save", "operator_hard_reset", "rail_deposit", "swap", "admin_shutdown", "status_req", ""] {
        assert!(allowlist::lookup(bad).is_none(), "{bad} must not be callable");
    }
}

#[test]
fn params_cannot_override_type() {
    let m = allowlist::lookup("fpl_getAccount").unwrap();
    let w = build_wire(m, Some(&json!({"account":"alice","type":"seal_force"}))).unwrap();
    assert_eq!(w["type"], "account_query");
    assert_eq!(w.as_object().unwrap().len(), 2);
}

#[test]
fn status_is_forced_brief() {
    let m = allowlist::lookup("fpl_status").unwrap();
    let w = build_wire(m, Some(&json!({"include_accounts":true,"brief":false}))).unwrap();
    assert_eq!(w, json!({"type":"status_req","include_accounts":false,"brief":true}));
}

#[test]
fn param_validation_and_clamps() {
    let ob = allowlist::lookup("fpl_orderBook").unwrap();
    assert_eq!(build_wire(ob, Some(&json!({"pair":"BTC4-FPL","levels":10_000}))).unwrap()["levels"], 200);
    assert_eq!(build_wire(ob, None), Err(BuildErr::BadParams("pair")));
    let tx = allowlist::lookup("fpl_submitTx").unwrap();
    assert!(tx.is_tx_submit);
    assert_eq!(build_wire(tx, Some(&json!({"tx":"x"}))), Err(BuildErr::BadParams("tx")));
    assert_eq!(build_wire(tx, Some(&json!([1]))), Err(BuildErr::BadParams("params must be an object")));
    let h = allowlist::lookup("fpl_health").unwrap();
    assert_eq!(build_wire(h, Some(&json!({"warnings":999}))).unwrap()["warnings"], 64);
}

// ---------- limits ----------
#[test]
fn bucket_refills() {
    let t0 = Instant::now();
    let mut b = Bucket::new(2.0, 2.0, t0);
    assert!(b.take(t0).is_ok());
    assert!(b.take(t0).is_ok());
    assert_eq!(b.take(t0), Err(1));
    assert!(b.take(t0 + Duration::from_millis(600)).is_ok());
}

#[test]
fn rate_limit_per_tier_burst() {
    let cfg = Config::proposed_default();
    let lim = Limiter::new(HashMap::new());
    let t0 = Instant::now();
    let unix = 1_800_000_000;
    let burst = cfg.limits(Tier::Free).burst;
    for _ in 0..burst {
        lim.admit(&cfg, "k", Tier::Free, 1, false, t0, unix).unwrap();
    }
    assert!(matches!(lim.admit(&cfg, "k", Tier::Free, 1, false, t0, unix), Err(Deny::RateLimited { .. })));
    // other keys are independent; Scale has a bigger burst
    for _ in 0..cfg.limits(Tier::Scale).burst {
        lim.admit(&cfg, "s", Tier::Scale, 1, false, t0, unix).unwrap();
    }
    // refill after 1s gives `rps` more
    let t1 = t0 + Duration::from_secs(1);
    for _ in 0..cfg.limits(Tier::Free).rps as u32 {
        lim.admit(&cfg, "k", Tier::Free, 1, false, t1, unix).unwrap();
    }
    let u = lim.usage("k").unwrap();
    assert_eq!(u.requests as u32, burst + 5);
    assert_eq!(u.rejected, 1);
}

#[test]
fn tx_submit_bucket_is_separate() {
    let cfg = Config::proposed_default();
    let lim = Limiter::new(HashMap::new());
    let t0 = Instant::now();
    // free: 10/min => bucket cap max(10/6,1)=1.67 => 1 immediate submit
    lim.admit(&cfg, "k", Tier::Free, 5, true, t0, 0).unwrap();
    assert!(matches!(lim.admit(&cfg, "k", Tier::Free, 5, true, t0, 0), Err(Deny::TxRateLimited { .. })));
    assert!(lim.admit(&cfg, "k", Tier::Free, 1, false, t0, 0).is_ok(), "reads still fine");
}

#[test]
fn monthly_quota_enforced_and_resets() {
    let mut cfg = Config::proposed_default();
    cfg.tiers.get_mut(&Tier::Free).unwrap().monthly_quota = 3;
    cfg.tiers.get_mut(&Tier::Free).unwrap().burst = 100;
    let lim = Limiter::new(HashMap::new());
    let t0 = Instant::now();
    let oct = 1_793_000_000; // 2026-10
    let nov = 1_793_600_000; // 2026-11
    assert_eq!(month_of(oct), "2026-10");
    assert_eq!(month_of(nov), "2026-11");
    for _ in 0..3 {
        lim.admit(&cfg, "k", Tier::Free, 1, false, t0, oct).unwrap();
    }
    assert_eq!(lim.admit(&cfg, "k", Tier::Free, 1, false, t0, oct), Err(Deny::QuotaExhausted { quota: 3 }));
    lim.admit(&cfg, "k", Tier::Free, 1, false, t0, nov).unwrap();
    assert_eq!(lim.usage("k").unwrap().units, 1);
}

#[test]
fn month_boundaries() {
    assert_eq!(month_of(0), "1970-01");
    assert_eq!(month_of(951_782_400), "2000-02"); // 2000-02-29
    assert_eq!(month_of(951_868_800), "2000-03");
    assert_eq!(month_of(1_798_761_599), "2026-12");
    assert_eq!(month_of(1_798_761_600), "2027-01");
}

#[test]
fn usage_persists_roundtrip() {
    let cfg = Config::proposed_default();
    let lim = Limiter::new(HashMap::new());
    lim.admit(&cfg, "k", Tier::Builder, 1, false, Instant::now(), 0).unwrap();
    let p = std::env::temp_dir().join(format!("fplgw-usage-{}.json", std::process::id()));
    lim.flush(&p).unwrap();
    let back = Limiter::load_usage(&p);
    assert_eq!(back["k"].requests, 1);
    let _ = std::fs::remove_file(p);
}

#[test]
fn proposed_config_roundtrips_toml() {
    let c = Config::proposed_default();
    let s = toml::to_string_pretty(&c).unwrap();
    let back: Config = toml::from_str(&s).unwrap();
    back.validate().unwrap();
    assert_eq!(back.limits(Tier::Builder).price_gbp_pence, 2900);
    assert_eq!(back.limits(Tier::Scale).price_gbp_pence, 19900);
    assert!(!back.billing.enabled);
}

#[test]
fn cors_default_is_not_wildcard_and_old_configs_still_load() {
    let c = Config::proposed_default();
    assert!(!c.cors_origins.iter().any(|o| o == "*"));
    assert_eq!(c.cors_origins, vec!["https://falcon-fpl.com".to_string(), "https://www.beartec.uk".to_string()]);
    // A gateway.toml written before this change (no cors_origins, no [abuse]) parses with safe defaults.
    let mut v: toml::Value = toml::from_str(&toml::to_string(&c).unwrap()).unwrap();
    let t = v.as_table_mut().unwrap();
    t.remove("cors_origins");
    t.remove("abuse");
    let back: Config = toml::from_str(&toml::to_string(&v).unwrap()).unwrap();
    back.validate().unwrap();
    assert_eq!(back.cors_origins, c.cors_origins);
    assert_eq!(back.abuse, fpl_gateway::config::AbuseLimits::default());
}

#[test]
fn deployed_example_config_parses() {
    let c: Config = toml::from_str(include_str!("../deploy/gateway.example.toml")).unwrap();
    c.validate().unwrap();
    assert!(!c.cors_origins.iter().any(|o| o == "*"));
}

#[test]
fn client_buckets_are_per_client_and_bounded() {
    use fpl_gateway::limits::ClientBuckets;
    let now = std::time::Instant::now();
    let b = ClientBuckets::new(0.001, 1, 2);
    assert!(b.take("a", now).is_ok());
    assert!(b.take("a", now).is_err());
    assert!(b.take("b", now).is_ok());
    assert!(b.take("c", now).is_ok(), "map cleared at cap");
    assert!(b.len() <= 2);
}

#[test]
fn every_method_declares_reply_types() {
    for m in fpl_gateway::allowlist::METHODS {
        if m.market {
            assert!(m.reply_types.contains(&"market"), "{}", m.name);
            continue;
        }
        assert!(!m.reply_types.is_empty(), "{}", m.name);
        for t in m.reply_types {
            assert!(fpl_gateway::upstream::REPLY_TYPES.contains(t), "{} reply {t} not terminal", m.name);
        }
    }
    let oo = fpl_gateway::allowlist::lookup("fpl_openOrders").unwrap();
    assert!(oo.reply_types.contains(&"order_book"));
    let f = fpl_gateway::allowlist::lookup("fpl_fills").unwrap();
    assert!(f.reply_types.contains(&"order_book"));
}

// ---------- billing stub ----------
#[test]
fn stripe_signature() {
    use hmac::{Hmac, Mac};
    let body = br#"{"type":"customer.subscription.updated"}"#;
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(b"whsec_test").unwrap();
    mac.update(b"1000.");
    mac.update(body);
    let sig = hex::encode(mac.finalize().into_bytes());
    let hdr = format!("t=1000,v1={sig}");
    assert_eq!(verify_signature(&hdr, body, "whsec_test", 1100, 300), Ok(()));
    assert_eq!(verify_signature(&hdr, body, "whsec_other", 1100, 300), Err(SigErr::Mismatch));
    assert_eq!(verify_signature(&hdr, body, "whsec_test", 2000, 300), Err(SigErr::Stale));
    assert_eq!(verify_signature("t=1000", body, "whsec_test", 1000, 300), Err(SigErr::Missing));
}
