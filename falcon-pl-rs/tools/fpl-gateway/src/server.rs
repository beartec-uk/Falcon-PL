//! HTTP surface.
//!
//! Public listener:
//!   POST /v1/rpc                       JSON-RPC 2.0 (single request), API key required
//!   GET  /v1/usage                     caller's own month-to-date usage
//!   GET  /v1/health                    gateway + upstream liveness (no key)
//!   GET  /v1/tiers                     published tier table (no key)
//!   POST /v1/billing/stripe/webhook    stub, 404 unless [billing].enabled
//!   POST /v1/stream/session            short-lived SSE ticket (API key required)
//!   GET  /v1/stream                    SSE book/trades/ticker (API key or ticket)
//! Metrics listener (loopback): GET /metrics

use crate::allowlist::{self, BuildErr};
use crate::auth::{self, KeyStore};
use crate::billing;
use crate::brief;
use crate::config::{Config, Tier};
use crate::limits::{now_unix, ClientBuckets, Deny, Limiter, SharedBucket};
use crate::market::{self, MarketClient, MarketErr};
use crate::metrics::Metrics;
use crate::stream::{self, StreamGuards, StreamTickets};
use crate::upstream;
use axum::body::{Body, Bytes};
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use parking_lot::RwLock;
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;

pub struct AppState {
    pub cfg: Config,
    pub keys: RwLock<KeyStore>,
    pub limiter: Limiter,
    pub metrics: Metrics,
    pub upstream_slots: Semaphore,
    /// /v1/health: gateway-wide bucket, probe concurrency cap, short result cache.
    pub health_bucket: SharedBucket,
    pub health_slots: Semaphore,
    pub health_cache: parking_lot::Mutex<Option<(Instant, bool)>>,
    /// Missing/invalid API key: per-client and gateway-wide buckets.
    pub unauth_ip: ClientBuckets,
    pub unauth_global: SharedBucket,
    pub market: Option<MarketClient>,
    pub tickets: StreamTickets,
    pub streams: StreamGuards,
}

impl AppState {
    pub fn new(cfg: Config, keys: KeyStore, limiter: Limiter) -> Arc<Self> {
        let market = match MarketClient::from_config(&cfg.market_data) {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!("market data client not started: {e}");
                None
            }
        };
        Self::build(cfg, keys, limiter, market)
    }

    pub fn build(cfg: Config, keys: KeyStore, limiter: Limiter, market: Option<MarketClient>) -> Arc<Self> {
        let slots = cfg.max_upstream_concurrency;
        let a = cfg.abuse.clone();
        let now = Instant::now();
        Arc::new(Self {
            cfg,
            keys: RwLock::new(keys),
            limiter,
            metrics: Metrics::default(),
            upstream_slots: Semaphore::new(slots),
            health_bucket: SharedBucket::new(a.health_rps, a.health_burst, now),
            health_slots: Semaphore::new(a.health_max_concurrent),
            health_cache: parking_lot::Mutex::new(None),
            unauth_ip: ClientBuckets::new(a.unauth_ip_rps, a.unauth_ip_burst, a.max_tracked_ips),
            unauth_global: SharedBucket::new(a.unauth_global_rps, a.unauth_global_burst, now),
            market,
            tickets: StreamTickets::default(),
            streams: StreamGuards::default(),
        })
    }
}

type S = State<Arc<AppState>>;

pub fn router(st: Arc<AppState>) -> Router {
    let cap = st.cfg.max_body_bytes;
    Router::new()
        .route("/v1/rpc", post(rpc).options(preflight))
        .route("/v1/usage", get(usage).options(preflight))
        .route("/v1/health", get(health))
        .route("/v1/tiers", get(tiers))
        .route("/v1/billing/stripe/webhook", post(stripe_webhook))
        .route("/v1/stream/session", post(stream::session).options(preflight))
        .route("/v1/stream", get(stream::sse).options(preflight))
        .layer(DefaultBodyLimit::max(cap))
        .layer(axum::middleware::from_fn_with_state(st.clone(), cors))
        .with_state(st)
}

pub fn metrics_router(st: Arc<AppState>) -> Router {
    Router::new().route("/metrics", get(metrics)).with_state(st)
}

fn rpc_err(id: &Value, code: i64, msg: &str) -> Value {
    json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":msg}})
}

fn reply(status: StatusCode, v: Value) -> Response {
    (status, axum::Json(v)).into_response()
}

async fn cors(State(st): S, req: axum::extract::Request, next: axum::middleware::Next) -> Response {
    let origin = req.headers().get(header::ORIGIN).cloned();
    let mut resp = next.run(req).await;
    if let Some(o) = origin {
        let allowed = st.cfg.cors_origins.iter().any(|a| a == "*" || o.to_str().map(|s| s == a).unwrap_or(false));
        if allowed {
            let h = resp.headers_mut();
            let v = if st.cfg.cors_origins.iter().any(|a| a == "*") { HeaderValue::from_static("*") } else { o };
            h.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, v);
            h.insert(header::ACCESS_CONTROL_ALLOW_METHODS, HeaderValue::from_static("GET, POST, OPTIONS"));
            h.insert(header::ACCESS_CONTROL_ALLOW_HEADERS, HeaderValue::from_static("authorization, content-type, x-api-key"));
            h.insert(header::ACCESS_CONTROL_MAX_AGE, HeaderValue::from_static("600"));
            h.insert(header::VARY, HeaderValue::from_static("Origin"));
        }
    }
    resp
}

/// Client identity for abuse limits. Caddy (the only public path) overwrites
/// X-Forwarded-For with the real peer, so its last entry is the client.
pub fn client_ip(headers: &HeaderMap) -> String {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.rsplit(',').next())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty() && s.len() <= 64)
        .unwrap_or("-")
        .to_string()
}

/// Charge an auth failure. `Some(retry_after)` once the client (or the gateway
/// as a whole) is over the bad-key budget: answer 429 instead of 401.
fn unauth_throttle(st: &AppState, headers: &HeaderMap) -> Option<u64> {
    let now = Instant::now();
    let ip = st.unauth_ip.take(&client_ip(headers), now).err();
    let global = st.unauth_global.take(now).err();
    ip.max(global)
}

pub(crate) fn unauthorized(st: &AppState, headers: &HeaderMap, id: &Value, msg: &str) -> Response {
    if let Some(retry) = unauth_throttle(st, headers) {
        st.metrics.req("-", "-", "unauth_rate_limited");
        let mut r = reply(StatusCode::TOO_MANY_REQUESTS, rpc_err(id, -32005, "too many requests with a missing or invalid API key"));
        r.headers_mut().insert(header::RETRY_AFTER, HeaderValue::from(retry));
        return r;
    }
    st.metrics.req("-", "-", "unauthorized");
    reply(StatusCode::UNAUTHORIZED, rpc_err(id, -32001, msg))
}

async fn preflight() -> StatusCode {
    StatusCode::NO_CONTENT
}

async fn rpc(State(st): S, headers: HeaderMap, body: Bytes) -> Response {
    let null = Value::Null;
    let Ok(req) = serde_json::from_slice::<Value>(&body) else {
        st.metrics.req("-", "-", "parse_error");
        return reply(StatusCode::BAD_REQUEST, rpc_err(&null, -32700, "parse error"));
    };
    if req.is_array() {
        return reply(StatusCode::BAD_REQUEST, rpc_err(&null, -32600, "batch requests are not supported"));
    }
    let id = req.get("id").cloned().unwrap_or(Value::Null);
    let method_name = req.get("method").and_then(Value::as_str).unwrap_or("");

    // 1. auth
    let Some(presented) = auth::extract(&headers) else {
        return unauthorized(&st, &headers, &id, "missing API key");
    };
    let found = st.keys.read().authenticate(&presented).map(|r| (r.id.clone(), r.tier));
    let Some((key_id, tier)) = found else {
        return unauthorized(&st, &headers, &id, "invalid API key");
    };
    let t = tier.as_str();

    // 2. allowlist
    let Some(m) = allowlist::lookup(method_name) else {
        st.metrics.req(t, "-", "method_not_allowed");
        return reply(StatusCode::OK, rpc_err(&id, -32601, "method not allowed"));
    };
    let wire = match allowlist::build_wire(m, req.get("params")) {
        Ok(w) => w,
        Err(BuildErr::BadParams(p)) => {
            st.metrics.req(t, m.name, "bad_params");
            return reply(StatusCode::OK, rpc_err(&id, -32602, &format!("invalid params: {p}")));
        }
        Err(BuildErr::UnknownMethod) => return reply(StatusCode::OK, rpc_err(&id, -32601, "method not allowed")),
    };

    // 3. rate + quota (metered on admit)
    if let Err(d) = st.limiter.admit(&st.cfg, &key_id, tier, m.cost, m.is_tx_submit, Instant::now(), now_unix()) {
        let (outcome, msg, retry) = match d {
            Deny::RateLimited { retry_after } => ("rate_limited", "rate limit exceeded".to_string(), Some(retry_after)),
            Deny::TxRateLimited { retry_after } => ("tx_rate_limited", "tx submit rate exceeded".to_string(), Some(retry_after)),
            Deny::QuotaExhausted { quota } => ("quota_exhausted", format!("monthly quota of {quota} units used; resets 1st of the month 00:00 UTC"), None),
        };
        st.metrics.req(t, m.name, outcome);
        let mut r = reply(StatusCode::TOO_MANY_REQUESTS, rpc_err(&id, -32005, &msg));
        if let Some(s) = retry {
            r.headers_mut().insert(header::RETRY_AFTER, HeaderValue::from(s));
        }
        return r;
    }

    // 4. market-data methods (and fpl_fills when the store is configured)
    let use_market = m.market || (m.name == "fpl_fills" && st.market.is_some());
    if use_market {
        return market_rpc(&st, t, m.name, &id, req.get("params").cloned().unwrap_or(Value::Null)).await;
    }

    // 5. forward to the node
    let Ok(_slot) = st.upstream_slots.try_acquire() else {
        st.metrics.req(t, m.name, "busy");
        return reply(StatusCode::SERVICE_UNAVAILABLE, rpc_err(&id, -32003, "gateway busy"));
    };
    let started = Instant::now();
    let res = upstream::call(&st.cfg.upstream, &wire, Duration::from_millis(st.cfg.upstream_timeout_ms), st.cfg.upstream_max_reply_bytes).await;
    st.metrics.latency(m.name, started.elapsed().as_millis() as u64);
    match res {
        Ok(v) => {
            let rt = v.get("type").and_then(Value::as_str).unwrap_or("");
            if rt != "err" && !m.reply_types.contains(&rt) {
                st.metrics.upstream_err("unexpected_reply");
                st.metrics.req(t, m.name, "upstream_error");
                tracing::warn!(method = m.name, reply = rt, "unexpected node reply type");
                return reply(StatusCode::BAD_GATEWAY, rpc_err(&id, -32002, "unexpected node reply"));
            }
            if rt == "err" {
                st.metrics.req(t, m.name, "node_err");
                let msg = v.get("msg").and_then(Value::as_str).unwrap_or("node error");
                return reply(StatusCode::OK, rpc_err(&id, -32000, msg));
            }
            st.metrics.req(t, m.name, "ok");
            let mut result = v.get("body").cloned().or_else(|| v.get("msg").map(|m| json!({"msg": m}))).unwrap_or(v);
            if m.name == "fpl_status" {
                result = brief::slim_status(result);
            }
            reply(StatusCode::OK, json!({"jsonrpc":"2.0","id":id,"result":result}))
        }
        Err(e) => {
            st.metrics.upstream_err(match e {
                upstream::UpstreamErr::Connect(_) => "connect",
                upstream::UpstreamErr::Timeout => "timeout",
                upstream::UpstreamErr::TooLarge => "too_large",
                upstream::UpstreamErr::Protocol(_) => "protocol",
            });
            st.metrics.req(t, m.name, "upstream_error");
            tracing::warn!(method = m.name, "{e}");
            reply(StatusCode::BAD_GATEWAY, rpc_err(&id, -32002, "node unavailable"))
        }
    }
}

async fn usage(State(st): S, headers: HeaderMap) -> Response {
    let found = auth::extract(&headers).and_then(|k| st.keys.read().authenticate(&k).map(|r| (r.id.clone(), r.tier)));
    let Some((id, tier)) = found else {
        return unauthorized(&st, &headers, &Value::Null, "missing or invalid API key");
    };
    let l = st.cfg.limits(tier);
    let u = st.limiter.usage(&id).unwrap_or_default();
    let cur = crate::limits::month_of(now_unix());
    let used = if u.month == cur { u.units } else { 0 };
    reply(StatusCode::OK, json!({"key_id": id, "tier": tier.as_str(), "month": cur, "units_used": used, "monthly_quota": l.monthly_quota, "rps": l.rps, "burst": l.burst, "tx_submit_per_min": l.tx_submit_per_min}))
}

fn health_reply(up: bool) -> Response {
    let code = if up { StatusCode::OK } else { StatusCode::SERVICE_UNAVAILABLE };
    reply(code, json!({"service":"fpl-gateway","version":env!("CARGO_PKG_VERSION"),"network":"testnet","gateway":"ok","upstream": if up {"ok"} else {"down"}}))
}

/// Unauthenticated, so: gateway-wide rate limit, results cached for
/// `health_cache_ms`, and at most `health_max_concurrent` probes in flight
/// (callers beyond that get the last cached answer, or 503 if none).
async fn health(State(st): S) -> Response {
    let now = Instant::now();
    if let Err(retry) = st.health_bucket.take(now) {
        st.metrics.req("-", "health", "rate_limited");
        let mut r = (StatusCode::TOO_MANY_REQUESTS, axum::Json(json!({"error":"rate limit exceeded"}))).into_response();
        r.headers_mut().insert(header::RETRY_AFTER, HeaderValue::from(retry));
        return r;
    }
    let ttl = Duration::from_millis(st.cfg.abuse.health_cache_ms);
    let cached = *st.health_cache.lock();
    if let Some((at, up)) = cached {
        if now.saturating_duration_since(at) < ttl {
            return health_reply(up);
        }
    }
    let Ok(_slot) = st.health_slots.try_acquire() else {
        st.metrics.req("-", "health", "busy");
        return match cached {
            Some((_, up)) => health_reply(up),
            None => (StatusCode::SERVICE_UNAVAILABLE, axum::Json(json!({"error":"busy"}))).into_response(),
        };
    };
    let probe = json!({"type":"health_req","warnings":0});
    let r = upstream::call(&st.cfg.upstream, &probe, Duration::from_millis(st.cfg.upstream_timeout_ms.min(3000)), st.cfg.upstream_max_reply_bytes).await;
    let up = matches!(&r, Ok(v) if v.get("type").and_then(Value::as_str) == Some("health"));
    *st.health_cache.lock() = Some((Instant::now(), up));
    health_reply(up)
}

async fn tiers(State(st): S) -> Response {
    let rows: Vec<Value> = [Tier::Free, Tier::Builder, Tier::Scale]
        .iter()
        .map(|t| {
            let l = st.cfg.limits(*t);
            json!({"tier": t.as_str(), "price_gbp_per_month": l.price_gbp_pence as f64 / 100.0, "rps": l.rps, "burst": l.burst, "monthly_quota": l.monthly_quota, "tx_submit_per_min": l.tx_submit_per_min})
        })
        .collect();
    reply(StatusCode::OK, json!({"currency":"GBP","network":"testnet","note":"Falcon PL testnet RPC access. FPL testnet tokens have no monetary value.","tiers":rows}))
}

async fn stripe_webhook(State(st): S, headers: HeaderMap, body: Bytes) -> Response {
    let b = &st.cfg.billing;
    if !b.enabled {
        return StatusCode::NOT_FOUND.into_response();
    }
    let Ok(secret) = std::env::var(&b.webhook_secret_env) else {
        tracing::error!("billing enabled but {} is unset", b.webhook_secret_env);
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let sig = headers.get("stripe-signature").and_then(|v| v.to_str().ok()).unwrap_or("");
    if let Err(e) = billing::verify_signature(sig, &body, &secret, now_unix(), b.tolerance_secs) {
        tracing::warn!("stripe webhook rejected: {e:?}");
        return StatusCode::BAD_REQUEST.into_response();
    }
    let Ok(ev) = serde_json::from_slice::<Value>(&body) else { return StatusCode::BAD_REQUEST.into_response() };
    let typ = ev.get("type").and_then(Value::as_str).unwrap_or("");
    if billing::HANDLED_EVENTS.contains(&typ) {
        let price = ev.pointer("/data/object/items/data/0/price/id").and_then(Value::as_str);
        let rec = json!({
            "received": now_unix(),
            "event_id": ev.get("id"),
            "type": typ,
            "customer": ev.pointer("/data/object/customer"),
            "price": price,
            "mapped_tier": price.and_then(|p| b.price_tiers.get(p)).map(|t| t.as_str()),
            "applied": false
        });
        use std::io::Write;
        let res = std::fs::OpenOptions::new().create(true).append(true).open(&b.events_path).and_then(|mut f| writeln!(f, "{rec}"));
        if res.is_err() {
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    }
    StatusCode::OK.into_response()
}

async fn metrics(State(st): S) -> Response {
    let n = st.keys.read().len();
    Response::builder()
        .header(header::CONTENT_TYPE, "text/plain; version=0.0.4")
        .body(Body::from(st.metrics.render(n)))
        .unwrap()
}


async fn market_rpc(st: &AppState, tier: &str, method: &str, id: &Value, params: Value) -> Response {
    let Some(mkt) = st.market.as_ref() else {
        st.metrics.req(tier, method, "upstream_error");
        return reply(StatusCode::BAD_GATEWAY, rpc_err(id, -32002, "market data unavailable"));
    };
    let q = match market::query_for(method, &params) {
        Ok(q) => q,
        Err(MarketErr::BadParams(p)) => {
            st.metrics.req(tier, method, "bad_params");
            return reply(StatusCode::OK, rpc_err(id, -32602, &format!("invalid params: {p}")));
        }
        Err(_) => {
            st.metrics.req(tier, method, "bad_params");
            return reply(StatusCode::OK, rpc_err(id, -32602, "invalid params"));
        }
    };
    let qref: Vec<(&str, String)> = q.iter().map(|(k, v)| (k.as_str(), v.clone())).collect();
    let started = Instant::now();
    let res = mkt.get(market::path_for(method), &qref).await;
    st.metrics.latency(method, started.elapsed().as_millis() as u64);
    match res {
        Ok(result) => {
            st.metrics.req(tier, method, "ok");
            reply(StatusCode::OK, json!({"jsonrpc":"2.0","id":id,"result":result}))
        }
        Err(MarketErr::BadParams(p)) => {
            st.metrics.req(tier, method, "bad_params");
            reply(StatusCode::OK, rpc_err(id, -32602, &format!("invalid params: {p}")))
        }
        Err(_) => {
            st.metrics.req(tier, method, "upstream_error");
            reply(StatusCode::BAD_GATEWAY, rpc_err(id, -32002, "market data unavailable"))
        }
    }
}
