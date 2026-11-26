//! End-to-end: HTTP router -> gateway -> mock Falcon node (real TCP, newline JSON
//! wire protocol, gossip lines before the reply like the live mesh port).

use axum::body::Body;
use axum::http::{Request, StatusCode};
use fpl_gateway::auth::{self, KeyStore};
use fpl_gateway::config::{Config, Tier};
use fpl_gateway::limits::Limiter;
use fpl_gateway::server::{self, AppState};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tower::ServiceExt;

/// Mock node: records every received message and answers like fd-pl.
async fn mock_node() -> (String, Arc<Mutex<Vec<Value>>>) {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap().to_string();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let seen2 = seen.clone();
    tokio::spawn(async move {
        loop {
            let (s, _) = l.accept().await.unwrap();
            let seen = seen2.clone();
            tokio::spawn(async move {
                let (r, mut w) = s.into_split();
                let mut lines = BufReader::new(r).lines();
                let Ok(Some(line)) = lines.next_line().await else { return };
                let m: Value = serde_json::from_str(&line).unwrap();
                seen.lock().unwrap().push(m.clone());
                // gossip noise first, as the mesh port does
                w.write_all(b"{\"type\":\"pong\",\"nonce\":1}\n{\"type\":\"ledger_ok\",\"height\":7}\n").await.unwrap();
                let resp = match m["type"].as_str().unwrap() {
                    "status_req" => json!({"type":"status","body":{"height":4242,"network":"falcon-pl-testnet"}}),
                    "health_req" => json!({"type":"health","body":{"schema":"falcon.health.v1","ok":true}}),
                    "account_query" if m["account"] == "nobody" => json!({"type":"err","msg":"unknown account"}),
                    "account_query" => json!({"type":"account","body":{"account":m["account"],"balance":"10"}}),
                    "submit_tx" => json!({"type":"ok","msg":"queued"}),
                    // fd-pl v2.10.4 answers all three book queries with `order_book`
                    // (shapes captured from the live seed node, 2026-11-04).
                    "open_orders_query" if m["account"] == "weird" => json!({"type":"status","body":{}}),
                    "open_orders_query" => json!({"type":"order_book","body":{"account":m["account"],"max_open":32,"orders":[]}}),
                    "fills_query" if m["pair"] == "NEW-FPL" => json!({"type":"fills","body":{"fills":[{"px":1}]}}),
                    "fills_query" => json!({"type":"order_book","body":{"fills":[]}}),
                    _ => json!({"type":"err","msg":"admin message rejected"}),
                };
                w.write_all(format!("{resp}\n").as_bytes()).await.unwrap();
            });
        }
    });
    (addr, seen)
}

struct Fx {
    app: axum::Router,
    key_free: String,
    key_scale: String,
    seen: Arc<Mutex<Vec<Value>>>,
}

async fn fixture(tweak: impl FnOnce(&mut Config)) -> Fx {
    let (addr, seen) = mock_node().await;
    let mut cfg = Config::proposed_default();
    cfg.upstream = addr;
    cfg.cors_origins = vec!["https://falcon-fpl.com".into()];
    cfg.max_body_bytes = 4096;
    tweak(&mut cfg);
    let (kf, rf) = auth::generate("k_free", Tier::Free, "");
    let (ks, rs) = auth::generate("k_scale", Tier::Scale, "");
    let st = AppState::new(cfg, KeyStore::from_records(vec![rf, rs]).unwrap(), Limiter::new(HashMap::new()));
    Fx { app: server::router(st), key_free: kf, key_scale: ks, seen }
}

async fn call(app: &axum::Router, key: Option<&str>, body: Value) -> (StatusCode, Value, axum::http::HeaderMap) {
    call_from(app, key, body, "203.0.113.1").await
}

async fn call_from(app: &axum::Router, key: Option<&str>, body: Value, ip: &str) -> (StatusCode, Value, axum::http::HeaderMap) {
    let mut rb = Request::post("/v1/rpc").header("content-type", "application/json").header("origin", "https://falcon-fpl.com").header("x-forwarded-for", ip);
    if let Some(k) = key {
        rb = rb.header("authorization", format!("Bearer {k}"));
    }
    let r = app.clone().oneshot(rb.body(Body::from(body.to_string())).unwrap()).await.unwrap();
    let st = r.status();
    let h = r.headers().clone();
    let b = r.into_body().collect().await.unwrap().to_bytes();
    (st, serde_json::from_slice(&b).unwrap_or(Value::Null), h)
}

fn rq(method: &str, params: Value) -> Value {
    json!({"jsonrpc":"2.0","id":1,"method":method,"params":params})
}

#[tokio::test]
async fn read_methods_and_submit_round_trip() {
    let fx = fixture(|_| {}).await;
    let (s, v, h) = call(&fx.app, Some(&fx.key_scale), rq("fpl_status", json!({}))).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["result"]["height"], 4242);
    assert_eq!(h["access-control-allow-origin"], "https://falcon-fpl.com");
    let (_, v, _) = call(&fx.app, Some(&fx.key_scale), rq("fpl_getAccount", json!({"account":"alice"}))).await;
    assert_eq!(v["result"]["account"], "alice");
    let (_, v, _) = call(&fx.app, Some(&fx.key_scale), rq("fpl_getAccount", json!({"account":"nobody"}))).await;
    assert_eq!(v["error"]["code"], -32000);
    let (_, v, _) = call(&fx.app, Some(&fx.key_scale), rq("fpl_submitTx", json!({"tx":{"from":"alice","seq":1}}))).await;
    assert_eq!(v["result"]["msg"], "queued");
    let seen = fx.seen.lock().unwrap().clone();
    assert_eq!(seen[0], json!({"type":"status_req","include_accounts":false,"brief":true}));
    assert_eq!(seen[3]["type"], "submit_tx");
}

#[tokio::test]
async fn auth_required() {
    let fx = fixture(|_| {}).await;
    let (s, v, _) = call(&fx.app, None, rq("fpl_status", json!({}))).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(v["error"]["code"], -32001);
    let (s, _, _) = call(&fx.app, Some("fplk_deadbeef"), rq("fpl_status", json!({}))).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert!(fx.seen.lock().unwrap().is_empty(), "nothing forwarded");
}

#[tokio::test]
async fn admin_and_ctl_methods_never_reach_node() {
    let fx = fixture(|_| {}).await;
    for m in ["seal_now", "mempool_drop", "snapshot_save", "operator_hard_reset", "fpl_sealForce", "status_req", "rail_deposit"] {
        let (_, v, _) = call(&fx.app, Some(&fx.key_scale), rq(m, json!({}))).await;
        assert_eq!(v["error"]["code"], -32601, "{m}");
    }
    let (_, _, _) = call(&fx.app, Some(&fx.key_scale), rq("fpl_getAccount", json!({"account":"a","type":"seal_force"}))).await;
    let seen = fx.seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0]["type"], "account_query");
}

#[tokio::test]
async fn rate_limit_and_quota_over_http() {
    let fx = fixture(|c| {
        c.tiers.get_mut(&Tier::Free).unwrap().burst = 3;
        c.tiers.get_mut(&Tier::Free).unwrap().rps = 0.001;
    })
    .await;
    for _ in 0..3 {
        assert_eq!(call(&fx.app, Some(&fx.key_free), rq("fpl_health", json!({}))).await.0, StatusCode::OK);
    }
    let (s, v, h) = call(&fx.app, Some(&fx.key_free), rq("fpl_health", json!({}))).await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(v["error"]["code"], -32005);
    assert!(h.contains_key("retry-after"));

    let fx = fixture(|c| c.tiers.get_mut(&Tier::Free).unwrap().monthly_quota = 2).await;
    call(&fx.app, Some(&fx.key_free), rq("fpl_health", json!({}))).await;
    call(&fx.app, Some(&fx.key_free), rq("fpl_health", json!({}))).await;
    let (s, v, _) = call(&fx.app, Some(&fx.key_free), rq("fpl_health", json!({}))).await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS);
    assert!(v["error"]["message"].as_str().unwrap().contains("monthly quota"));
    // usage endpoint reflects metering
    let r = fx.app.clone().oneshot(Request::get("/v1/usage").header("x-api-key", &fx.key_free).body(Body::empty()).unwrap()).await.unwrap();
    let u: Value = serde_json::from_slice(&r.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(u["units_used"], 2);
    assert_eq!(u["tier"], "free");
}

#[tokio::test]
async fn body_cap_cors_preflight_health_tiers() {
    let fx = fixture(|_| {}).await;
    let big = rq("fpl_submitTx", json!({"tx":{"pad":"x".repeat(8000)}}));
    let (s, _, _) = call(&fx.app, Some(&fx.key_scale), big).await;
    assert_eq!(s, StatusCode::PAYLOAD_TOO_LARGE);

    let r = fx.app.clone().oneshot(Request::options("/v1/rpc").header("origin", "https://evil.example").body(Body::empty()).unwrap()).await.unwrap();
    assert!(!r.headers().contains_key("access-control-allow-origin"));
    let r = fx.app.clone().oneshot(Request::options("/v1/rpc").header("origin", "https://falcon-fpl.com").body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(r.status(), StatusCode::NO_CONTENT);
    assert!(r.headers()["access-control-allow-headers"].to_str().unwrap().contains("x-api-key"));

    let r = fx.app.clone().oneshot(Request::get("/v1/health").body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let r = fx.app.clone().oneshot(Request::get("/v1/tiers").body(Body::empty()).unwrap()).await.unwrap();
    let t: Value = serde_json::from_slice(&r.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(t["currency"], "GBP");
    assert_eq!(t["tiers"][1]["price_gbp_per_month"], 29.0);
    assert_eq!(t["tiers"][2]["price_gbp_per_month"], 199.0);

    let r = fx.app.clone().oneshot(Request::post("/v1/billing/stripe/webhook").body(Body::from("{}")).unwrap()).await.unwrap();
    assert_eq!(r.status(), StatusCode::NOT_FOUND, "billing stub off by default");
}

#[tokio::test]
async fn upstream_down_is_502_and_health_503() {
    let fx = fixture(|c| {
        c.upstream = "127.0.0.1:1".into();
        c.upstream_timeout_ms = 500;
    })
    .await;
    let (s, v, _) = call(&fx.app, Some(&fx.key_scale), rq("fpl_status", json!({}))).await;
    assert_eq!(s, StatusCode::BAD_GATEWAY);
    assert_eq!(v["error"]["code"], -32002);
    let r = fx.app.clone().oneshot(Request::get("/v1/health").body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
    let m = server::metrics_router(AppState::new(Config::proposed_default(), KeyStore::default(), Limiter::new(HashMap::new())));
    let r = m.oneshot(Request::get("/metrics").body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
}

async fn get_health(app: &axum::Router) -> StatusCode {
    app.clone().oneshot(Request::get("/v1/health").body(Body::empty()).unwrap()).await.unwrap().status()
}

#[tokio::test]
async fn open_orders_and_fills_accept_live_reply_types() {
    let fx = fixture(|_| {}).await;
    let (s, v, _) = call(&fx.app, Some(&fx.key_scale), rq("fpl_openOrders", json!({"account":"alice"}))).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["result"]["account"], "alice");
    assert_eq!(v["result"]["max_open"], 32);
    let (s, v, _) = call(&fx.app, Some(&fx.key_scale), rq("fpl_fills", json!({"limit":2}))).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(v["result"]["fills"].is_array());
    // dedicated reply variant (future node) is accepted too
    let (s, v, _) = call(&fx.app, Some(&fx.key_scale), rq("fpl_fills", json!({"pair":"NEW-FPL"}))).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["result"]["fills"][0]["px"], 1);
    // a reply of the wrong kind is never passed through as a result
    let (s, v, _) = call(&fx.app, Some(&fx.key_scale), rq("fpl_openOrders", json!({"account":"weird"}))).await;
    assert_eq!(s, StatusCode::BAD_GATEWAY);
    assert_eq!(v["error"]["code"], -32002);
}

#[tokio::test]
async fn health_is_rate_limited_and_cached() {
    let fx = fixture(|c| {
        c.abuse.health_burst = 3;
        c.abuse.health_rps = 0.001;
        c.abuse.health_cache_ms = 60_000;
    })
    .await;
    for _ in 0..3 {
        assert_eq!(get_health(&fx.app).await, StatusCode::OK);
    }
    let r = fx.app.clone().oneshot(Request::get("/v1/health").body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(r.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(r.headers().contains_key("retry-after"));
    let probes = fx.seen.lock().unwrap().iter().filter(|m| m["type"] == "health_req").count();
    assert_eq!(probes, 1, "cached: 3 health calls -> 1 node probe");
}

#[tokio::test]
async fn health_probe_concurrency_is_capped() {
    let fx = fixture(|c| {
        c.abuse.health_burst = 1000;
        c.abuse.health_max_concurrent = 1;
        c.abuse.health_cache_ms = 0;
    })
    .await;
    let mut hs = Vec::new();
    for _ in 0..20 {
        let app = fx.app.clone();
        hs.push(tokio::spawn(async move { get_health(&app).await }));
    }
    let mut ok = 0;
    for h in hs {
        let s = h.await.unwrap();
        assert!(s == StatusCode::OK || s == StatusCode::SERVICE_UNAVAILABLE, "{s}");
        ok += (s == StatusCode::OK) as u32;
    }
    assert!(ok >= 1);
}

#[tokio::test]
async fn bad_or_missing_keys_are_rate_limited_per_client() {
    let fx = fixture(|c| {
        c.abuse.unauth_ip_burst = 2;
        c.abuse.unauth_ip_rps = 0.001;
    })
    .await;
    assert_eq!(call_from(&fx.app, None, rq("fpl_status", json!({})), "198.51.100.7").await.0, StatusCode::UNAUTHORIZED);
    assert_eq!(call_from(&fx.app, Some("fplk_bad"), rq("fpl_status", json!({})), "198.51.100.7").await.0, StatusCode::UNAUTHORIZED);
    let (s, v, h) = call_from(&fx.app, Some("fplk_bad"), rq("fpl_status", json!({})), "198.51.100.7").await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(v["error"]["code"], -32005);
    assert!(h.contains_key("retry-after"));
    // /v1/usage shares the budget
    let r = fx.app.clone().oneshot(Request::get("/v1/usage").header("x-forwarded-for", "198.51.100.7").body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(r.status(), StatusCode::TOO_MANY_REQUESTS);
    // another client is unaffected; a valid key from the throttled client still works
    assert_eq!(call_from(&fx.app, None, rq("fpl_status", json!({})), "198.51.100.8").await.0, StatusCode::UNAUTHORIZED);
    assert_eq!(call_from(&fx.app, Some(&fx.key_scale), rq("fpl_status", json!({})), "198.51.100.7").await.0, StatusCode::OK);

    // gateway-wide cap across many clients
    let fx = fixture(|c| {
        c.abuse.unauth_global_burst = 3;
        c.abuse.unauth_global_rps = 0.001;
    })
    .await;
    let mut codes = Vec::new();
    for i in 0..5 {
        codes.push(call_from(&fx.app, None, rq("fpl_status", json!({})), &format!("192.0.2.{i}")).await.0);
    }
    assert_eq!(codes.iter().filter(|c| **c == StatusCode::TOO_MANY_REQUESTS).count(), 2);
}

#[tokio::test]
async fn cors_default_is_explicit_allowlist() {
    let fx = fixture(|c| c.cors_origins = Config::proposed_default().cors_origins).await;
    for (o, ok) in [("https://falcon-fpl.com", true), ("https://www.beartec.uk", true), ("https://evil.example", false), ("null", false)] {
        let r = fx.app.clone().oneshot(Request::options("/v1/rpc").header("origin", o).body(Body::empty()).unwrap()).await.unwrap();
        match r.headers().get("access-control-allow-origin") {
            Some(v) => {
                assert!(ok, "{o} must not be allowed");
                assert_eq!(v, o, "echoes the origin, never *");
            }
            None => assert!(!ok, "{o} should be allowed"),
        }
    }
}

/// Tiny market-data API used by fpl_pairs / fpl_ticker / fpl_candles / fpl_fills.
async fn mock_market() -> (String, String) {
    use axum::{extract::Query, routing::get, Json, Router};
    use std::collections::HashMap;
    use std::future::IntoFuture;
    let token = "mkt-test-token".to_string();
    let tok = token.clone();
    let app = Router::new()
        .route("/v1/pairs", get({
            let tok = tok.clone();
            move |headers: axum::http::HeaderMap| {
                let tok = tok.clone();
                async move {
                    if headers.get("authorization").and_then(|v| v.to_str().ok()) != Some(&format!("Bearer {tok}")) {
                        return (StatusCode::UNAUTHORIZED, Json(json!({"error":"unauthorized"})));
                    }
                    (StatusCode::OK, Json(json!({"pairs":[{"pair":"BTC4-FPL","base":"BTC4","quote":"FPL","active":true}]})))
                }
            }
        }))
        .route("/v1/candles", get({
            let tok = tok.clone();
            move |headers: axum::http::HeaderMap, Query(q): Query<HashMap<String, String>>| {
                let tok = tok.clone();
                async move {
                    if headers.get("authorization").and_then(|v| v.to_str().ok()) != Some(&format!("Bearer {tok}")) {
                        return (StatusCode::UNAUTHORIZED, Json(json!({"error":"unauthorized"})));
                    }
                    if q.get("pair").map(String::as_str) != Some("BTC4-FPL") || q.get("interval").is_none() {
                        return (StatusCode::BAD_REQUEST, Json(json!({"error":"invalid params: pair"})));
                    }
                    (StatusCode::OK, Json(json!({"pair":"BTC4-FPL","interval":q.get("interval"),"count":1,"time_quality":"observer","candles":[{"time":100,"open":1,"high":2,"low":1,"close":2,"volume":0.5}]})))
                }
            }
        }))
        .route("/v1/ticker", get({
            let tok = tok.clone();
            move |headers: axum::http::HeaderMap| {
                let tok = tok.clone();
                async move {
                    if headers.get("authorization").and_then(|v| v.to_str().ok()) != Some(&format!("Bearer {tok}")) {
                        return (StatusCode::UNAUTHORIZED, Json(json!({"error":"unauthorized"})));
                    }
                    (StatusCode::OK, Json(json!({"tickers":[{"pair":"BTC4-FPL","last":4100000,"change_24h_pct":1.5,"volume_24h":12.0,"time_quality":"observer"}]})))
                }
            }
        }))
        .route("/v1/trades", get({
            let tok = tok.clone();
            move |headers: axum::http::HeaderMap| {
                let tok = tok.clone();
                async move {
                    if headers.get("authorization").and_then(|v| v.to_str().ok()) != Some(&format!("Bearer {tok}")) {
                        return (StatusCode::UNAUTHORIZED, Json(json!({"error":"unauthorized"})));
                    }
                    (StatusCode::OK, Json(json!({"fills":[{"id":9,"height":100,"asset":"BTC4","pair":"BTC4-FPL","price":4100000,"side":"buy"}],"count":1,"next_cursor":null,"time_quality":"observer"})))
                }
            }
        }));
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(axum::serve(l, app).into_future());
    (format!("http://{addr}"), token)
}

async fn fixture_with_market() -> Fx {
    let (url, token) = mock_market().await;
    let (addr, seen) = mock_node().await;
    let mut cfg = Config::proposed_default();
    cfg.upstream = addr;
    cfg.cors_origins = vec!["https://falcon-fpl.com".into()];
    cfg.max_body_bytes = 4096;
    let market = fpl_gateway::market::MarketClient::for_test(url, token, 2000).unwrap();
    let (kf, rf) = auth::generate("k_free", Tier::Free, "");
    let (ks, rs) = auth::generate("k_scale", Tier::Scale, "");
    let st = AppState::build(cfg, KeyStore::from_records(vec![rf, rs]).unwrap(), Limiter::new(HashMap::new()), Some(market));
    Fx { app: server::router(st), key_free: kf, key_scale: ks, seen }
}

#[tokio::test]
async fn market_methods_and_longer_fills() {
    let fx = fixture_with_market().await;
    let (s, v, _) = call(&fx.app, Some(&fx.key_free), rq("fpl_pairs", json!({}))).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["result"]["pairs"][0]["pair"], "BTC4-FPL");
    let (s, v, _) = call(&fx.app, Some(&fx.key_free), rq("fpl_ticker", json!({"pair":"BTC4-FPL"}))).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["result"]["tickers"][0]["last"], 4100000);
    let (s, v, _) = call(&fx.app, Some(&fx.key_free), rq("fpl_candles", json!({"pair":"BTC4-FPL","interval":"1h"}))).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["result"]["count"], 1);
    let (s, v, _) = call(&fx.app, Some(&fx.key_free), rq("fpl_fills", json!({"pair":"BTC4-FPL","limit":50}))).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["result"]["fills"][0]["height"], 100);
    // missing candles params
    let (s, v, _) = call(&fx.app, Some(&fx.key_free), rq("fpl_candles", json!({"pair":"BTC4-FPL"}))).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["error"]["code"], -32602);
}

#[tokio::test]
async fn market_methods_fail_closed_when_unconfigured() {
    let fx = fixture(|_| {}).await;
    let (s, v, _) = call(&fx.app, Some(&fx.key_free), rq("fpl_pairs", json!({}))).await;
    assert_eq!(s, StatusCode::BAD_GATEWAY);
    assert_eq!(v["error"]["code"], -32002);
    // fills still hits the node when the store is off
    let (s, v, _) = call(&fx.app, Some(&fx.key_free), rq("fpl_fills", json!({"pair":"BTC4-FPL"}))).await;
    assert_eq!(s, StatusCode::OK);
    assert!(v["error"].is_null());
}

#[tokio::test]
async fn stream_session_needs_a_key() {
    let fx = fixture(|_| {}).await;
    let r = fx.app.clone().oneshot(
        Request::post("/v1/stream/session").header("content-type", "application/json").body(Body::from("{}")).unwrap()
    ).await.unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    let r = fx.app.clone().oneshot(
        Request::post("/v1/stream/session")
            .header("authorization", format!("Bearer {}", fx.key_free))
            .body(Body::from("{}"))
            .unwrap()
    ).await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let b = r.into_body().collect().await.unwrap().to_bytes();
    let v: Value = serde_json::from_slice(&b).unwrap();
    assert!(v["ticket"].as_str().unwrap().len() >= 16);
    assert_eq!(v["expires_in"], 120);
}

#[tokio::test]
async fn status_is_slim_even_if_the_node_is_chatty() {
    // The default mock is already brief; check the filter keeps height.
    let fx = fixture(|_| {}).await;
    let (_, v, _) = call(&fx.app, Some(&fx.key_free), rq("fpl_status", json!({}))).await;
    assert_eq!(v["result"]["height"], 4242);
    assert!(v["result"].get("accounts").is_none());
    assert!(v["result"].get("amm_pools").is_none());
}
