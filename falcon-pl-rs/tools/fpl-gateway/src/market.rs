//! HTTP client for the Falcon fills-store market API (Tailscale, token auth).

use crate::config::MarketConfig;
use serde_json::Value;
use std::time::Duration;

#[derive(Debug)]
pub enum MarketErr {
    Unavailable,
    BadParams(&'static str),
    BadReply,
}

impl std::fmt::Display for MarketErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MarketErr::Unavailable => write!(f, "market data unavailable"),
            MarketErr::BadParams(p) => write!(f, "invalid params: {p}"),
            MarketErr::BadReply => write!(f, "market data unavailable"),
        }
    }
}

#[derive(Clone)]
pub struct MarketClient {
    base: String,
    token: String,
    client: reqwest::Client,
}

impl MarketClient {
    pub fn from_config(cfg: &MarketConfig) -> anyhow::Result<Option<Self>> {
        if !cfg.enabled {
            return Ok(None);
        }
        let token = std::env::var(&cfg.token_env)
            .map_err(|_| anyhow::anyhow!("market_data.enabled but env {} is unset", cfg.token_env))?;
        anyhow::ensure!(!token.is_empty(), "market_data token env is empty");
        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(cfg.timeout_ms.max(100)))
            .build()?;
        Ok(Some(Self { base: cfg.url.trim_end_matches('/').to_string(), token, client }))
    }

    /// Test helper: no real env.
    pub fn for_test(base: String, token: String, timeout_ms: u64) -> anyhow::Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(timeout_ms.max(100)))
            .build()?;
        Ok(Self { base: base.trim_end_matches('/').to_string(), token, client })
    }

    pub async fn get(&self, path: &str, query: &[(&str, String)]) -> Result<Value, MarketErr> {
        let mut url = format!("{}{path}", self.base);
        if !query.is_empty() {
            let qs: Vec<String> = query
                .iter()
                .map(|(k, v)| format!("{}={}", k, urlencoding_lite(v)))
                .collect();
            url.push('?');
            url.push_str(&qs.join("&"));
        }
        let r = self
            .client
            .get(&url)
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|_| MarketErr::Unavailable)?;
        let status = r.status();
        let body = r.json::<Value>().await.map_err(|_| MarketErr::BadReply)?;
        if status.as_u16() == 400 {
            return Err(MarketErr::BadParams("pair or interval"));
        }
        if !status.is_success() {
            return Err(MarketErr::Unavailable);
        }
        Ok(body)
    }
}

fn urlencoding_lite(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Build query string pairs from a JSON-RPC params object for a market method.
pub fn query_for(method: &str, params: &Value) -> Result<Vec<(String, String)>, MarketErr> {
    let obj = match params {
        Value::Null => None,
        Value::Object(o) => Some(o),
        _ => return Err(MarketErr::BadParams("params must be an object")),
    };
    let get = |k: &str| obj.and_then(|o| o.get(k)).and_then(|v| if v.is_null() { None } else { Some(v) });
    let mut q = Vec::new();
    let push = |q: &mut Vec<(String, String)>, k: &str, v: &Value| {
        match v {
            Value::String(s) => q.push((k.to_string(), s.clone())),
            Value::Number(n) => q.push((k.to_string(), n.to_string())),
            Value::Bool(b) => q.push((k.to_string(), b.to_string())),
            _ => {}
        }
    };
    match method {
        "fpl_pairs" => {}
        "fpl_ticker" => {
            if let Some(v) = get("pair") {
                push(&mut q, "pair", v);
            }
        }
        "fpl_candles" => {
            let pair = get("pair").ok_or(MarketErr::BadParams("pair"))?;
            let interval = get("interval").or_else(|| get("timeframe")).ok_or(MarketErr::BadParams("interval"))?;
            push(&mut q, "pair", pair);
            push(&mut q, "interval", interval);
            for k in ["from", "to", "limit"] {
                if let Some(v) = get(k) {
                    push(&mut q, k, v);
                }
            }
        }
        "fpl_fills" => {
            for k in ["pair", "account", "from", "to", "cursor", "limit"] {
                if let Some(v) = get(k) {
                    push(&mut q, k, v);
                }
            }
        }
        _ => return Err(MarketErr::BadParams("method")),
    }
    Ok(q)
}

pub fn path_for(method: &str) -> &'static str {
    match method {
        "fpl_pairs" => "/v1/pairs",
        "fpl_ticker" => "/v1/ticker",
        "fpl_candles" => "/v1/candles",
        "fpl_fills" => "/v1/trades",
        _ => "/v1/pairs",
    }
}
