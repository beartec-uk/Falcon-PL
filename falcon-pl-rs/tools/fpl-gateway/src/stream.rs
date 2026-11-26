//! SSE market stream: book, trades and ticker snapshots.
//!
//! Browser EventSource cannot set Authorization headers, so clients can mint a
//! short-lived ticket (`POST /v1/stream/session` with their API key) and pass
//! `?ticket=` instead of the key. Tickets are not API keys and expire quickly.

use crate::allowlist;
use crate::auth;
use crate::config::Tier;
use crate::limits::{now_unix, Deny};
use crate::market;
use crate::server::{unauthorized, AppState};
use crate::upstream;
use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tokio_stream::wrappers::ReceiverStream;

const TICKET_TTL: Duration = Duration::from_secs(120);
const POLL: Duration = Duration::from_secs(1);
const ALLOWED_PAIRS: &[&str] = &["BTC4-FPL", "USDC-FPL", "ETH-FPL"];

#[derive(Clone)]
struct Ticket {
    key_id: String,
    tier: Tier,
    expires: Instant,
}

#[derive(Default)]
pub struct StreamTickets {
    inner: Mutex<HashMap<String, Ticket>>,
}

impl StreamTickets {
    pub async fn issue(&self, key_id: String, tier: Tier) -> String {
        let mut b = [0u8; 16];
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(&mut b);
        let id = hex::encode(b);
        let mut g = self.inner.lock().await;
        g.retain(|_, t| t.expires > Instant::now());
        g.insert(id.clone(), Ticket { key_id, tier, expires: Instant::now() + TICKET_TTL });
        id
    }

    pub async fn take(&self, id: &str) -> Option<(String, Tier)> {
        let mut g = self.inner.lock().await;
        g.retain(|_, t| t.expires > Instant::now());
        g.get(id).cloned().map(|t| (t.key_id, t.tier))
    }
}

#[derive(Default)]
pub struct StreamGuards {
    open: Mutex<HashMap<String, u32>>,
}

impl StreamGuards {
    fn cap(tier: Tier) -> u32 {
        match tier {
            Tier::Free => 2,
            Tier::Builder => 4,
            Tier::Scale => 8,
        }
    }

    pub async fn try_open(&self, key_id: &str, tier: Tier) -> bool {
        let mut g = self.open.lock().await;
        let n = g.entry(key_id.to_string()).or_insert(0);
        if *n >= Self::cap(tier) {
            return false;
        }
        *n += 1;
        true
    }

    pub async fn close(&self, key_id: &str) {
        let mut g = self.open.lock().await;
        if let Some(n) = g.get_mut(key_id) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                g.remove(key_id);
            }
        }
    }
}

pub async fn session(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let Some(presented) = auth::extract(&headers) else {
        return unauthorized(&st, &headers, &Value::Null, "missing API key");
    };
    let found = st.keys.read().authenticate(&presented).map(|r| (r.id.clone(), r.tier));
    let Some((key_id, tier)) = found else {
        return unauthorized(&st, &headers, &Value::Null, "invalid API key");
    };
    let ticket = st.tickets.issue(key_id, tier).await;
    let body = json!({
        "ticket": ticket,
        "expires_in": TICKET_TTL.as_secs(),
        "channels": "book:BTC4-FPL,trades:BTC4-FPL,ticker:BTC4-FPL"
    });
    (StatusCode::OK, axum::Json(body)).into_response()
}

#[derive(Debug, serde::Deserialize, Default)]
pub struct StreamQuery {
    pub channels: Option<String>,
    pub ticket: Option<String>,
}

#[derive(Clone)]
struct Chan {
    kind: &'static str,
    pair: String,
}

fn parse_channels(s: &str) -> Result<Vec<Chan>, &'static str> {
    let mut out = Vec::new();
    for part in s.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (kind, pair) = part.split_once(':').or_else(|| part.split_once('.')).ok_or("channels")?;
        let kind = match kind {
            "book" => "book",
            "trades" => "trades",
            "ticker" => "ticker",
            _ => return Err("channels"),
        };
        let pair = pair.to_uppercase();
        if !ALLOWED_PAIRS.contains(&pair.as_str()) {
            return Err("pair");
        }
        out.push(Chan { kind, pair });
    }
    if out.is_empty() || out.len() > 8 {
        return Err("channels");
    }
    Ok(out)
}

pub async fn sse(State(st): State<Arc<AppState>>, headers: HeaderMap, Query(q): Query<StreamQuery>) -> Response {
    let authed = if let Some(t) = q.ticket.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        st.tickets.take(t).await
    } else {
        auth::extract(&headers).and_then(|k| st.keys.read().authenticate(&k).map(|r| (r.id.clone(), r.tier)))
    };
    let Some((key_id, tier)) = authed else {
        return unauthorized(&st, &headers, &Value::Null, "missing or invalid API key");
    };
    let channels = match parse_channels(q.channels.as_deref().unwrap_or("book:BTC4-FPL,trades:BTC4-FPL,ticker:BTC4-FPL")) {
        Ok(c) => c,
        Err(p) => {
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(json!({"error":{"code":-32602,"message":format!("invalid params: {p}")},"id":null,"jsonrpc":"2.0"})),
            )
                .into_response();
        }
    };

    if let Err(d) = st.limiter.admit(&st.cfg, &key_id, tier, 1, false, Instant::now(), now_unix()) {
        let (msg, retry) = match d {
            Deny::RateLimited { retry_after } => ("rate limit exceeded".to_string(), Some(retry_after)),
            Deny::TxRateLimited { retry_after } => ("tx submit rate exceeded".to_string(), Some(retry_after)),
            Deny::QuotaExhausted { quota } => (format!("monthly quota of {quota} units used; resets 1st of the month 00:00 UTC"), None),
        };
        let mut r = (
            StatusCode::TOO_MANY_REQUESTS,
            axum::Json(json!({"error":{"code":-32005,"message":msg},"id":null,"jsonrpc":"2.0"})),
        )
            .into_response();
        if let Some(s) = retry {
            r.headers_mut().insert(header::RETRY_AFTER, axum::http::HeaderValue::from(s));
        }
        return r;
    }
    if !st.streams.try_open(&key_id, tier).await {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            axum::Json(json!({"error":{"code":-32005,"message":"too many open streams for this key"},"id":null,"jsonrpc":"2.0"})),
        )
            .into_response();
    }

    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Event, Infallible>>(16);
    let st2 = st.clone();
    let key2 = key_id.clone();
    tokio::spawn(async move {
        let _guard = StreamGuard { st: st2.clone(), key: key2.clone() };
        let mut last: HashMap<(String, String), String> = HashMap::new();
        let mut tick: u64 = 0;
        loop {
            for ch in &channels {
                let payload = snapshot(&st2, ch).await;
                let serial = payload.to_string();
                let k = (ch.kind.to_string(), ch.pair.clone());
                if last.get(&k).map(|s| s == &serial).unwrap_or(false) && tick != 0 {
                    continue;
                }
                last.insert(k, serial);
                let ev = Event::default().event(ch.kind).data(payload.to_string());
                if tx.send(Ok(ev)).await.is_err() {
                    return;
                }
            }
            tick = tick.saturating_add(1);
            if tick % 60 == 0 {
                if st2.limiter.admit(&st2.cfg, &key2, tier, 1, false, Instant::now(), now_unix()).is_err() {
                    return;
                }
            }
            tokio::time::sleep(POLL).await;
        }
    });

    let stream = ReceiverStream::new(rx);
    Sse::new(stream)
        .keep_alive(KeepAlive::new().interval(Duration::from_secs(15)).text("ping"))
        .into_response()
}

struct StreamGuard {
    st: Arc<AppState>,
    key: String,
}

impl Drop for StreamGuard {
    fn drop(&mut self) {
        let st = self.st.clone();
        let key = self.key.clone();
        tokio::spawn(async move { st.streams.close(&key).await });
    }
}

async fn snapshot(st: &AppState, ch: &Chan) -> Value {
    match ch.kind {
        "book" => match node_book(st, &ch.pair).await {
            Ok(v) => json!({"channel":"book","pair":ch.pair,"data":v}),
            Err(msg) => json!({"channel":"book","pair":ch.pair,"error":msg}),
        },
        "trades" => match market_get(st, "fpl_fills", json!({"pair": ch.pair, "limit": 20})).await {
            Ok(v) => json!({"channel":"trades","pair":ch.pair,"data":v}),
            Err(msg) => json!({"channel":"trades","pair":ch.pair,"error":msg}),
        },
        "ticker" => {
            let stats = market_get(st, "fpl_ticker", json!({"pair": ch.pair})).await;
            let mut data = match stats {
                Ok(Value::Object(mut o)) => {
                    if let Some(arr) = o.remove("tickers").and_then(|t| t.as_array().cloned()) {
                        arr.into_iter().next().unwrap_or(Value::Object(o))
                    } else {
                        Value::Object(o)
                    }
                }
                Ok(v) => v,
                Err(_) => json!({}),
            };
            if let Ok(book) = node_book(st, &ch.pair).await {
                if let Some(obj) = data.as_object_mut() {
                    if let Some(bid) = book.get("bids").and_then(|b| b.as_array()).and_then(|a| a.first()) {
                        obj.insert("bid".into(), bid.get("price").cloned().unwrap_or(bid.clone()));
                    }
                    if let Some(ask) = book.get("asks").and_then(|b| b.as_array()).and_then(|a| a.first()) {
                        obj.insert("ask".into(), ask.get("price").cloned().unwrap_or(ask.clone()));
                    }
                }
            }
            json!({"channel":"ticker","pair":ch.pair,"data":data})
        }
        _ => json!({"error":"unknown channel"}),
    }
}

async fn node_book(st: &AppState, pair: &str) -> Result<Value, String> {
    let m = allowlist::lookup("fpl_orderBook").ok_or("unavailable")?;
    let wire = allowlist::build_wire(m, Some(&json!({"pair": pair, "levels": 20}))).map_err(|_| "invalid params".to_string())?;
    let v = upstream::call(
        &st.cfg.upstream,
        &wire,
        Duration::from_millis(st.cfg.upstream_timeout_ms),
        st.cfg.upstream_max_reply_bytes,
    )
    .await
    .map_err(|_| "node unavailable".to_string())?;
    let rt = v.get("type").and_then(Value::as_str).unwrap_or("");
    if rt == "err" {
        return Err(v.get("msg").and_then(Value::as_str).unwrap_or("node error").to_string());
    }
    Ok(v.get("body").cloned().unwrap_or(v))
}

async fn market_get(st: &AppState, method: &str, params: Value) -> Result<Value, String> {
    let Some(mkt) = st.market.as_ref() else {
        return Err("market data unavailable".into());
    };
    let q = market::query_for(method, &params).map_err(|e| e.to_string())?;
    let qref: Vec<(&str, String)> = q.iter().map(|(k, v)| (k.as_str(), v.clone())).collect();
    mkt.get(market::path_for(method), &qref).await.map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::parse_channels;

    #[test]
    fn parses_channel_list() {
        let c = parse_channels("book:BTC4-FPL,ticker:USDC-FPL").unwrap();
        assert_eq!(c.len(), 2);
        assert_eq!(c[0].kind, "book");
        assert_eq!(c[0].pair, "BTC4-FPL");
        assert!(parse_channels("book:DOGE-FPL").is_err());
        assert!(parse_channels("").is_err());
    }
}
