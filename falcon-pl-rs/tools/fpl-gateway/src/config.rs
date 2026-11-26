//! Gateway configuration (`/etc/fpl-gateway/gateway.toml`).
//!
//! Every numeric limit here is a PROPOSAL pending sign-off by Scott (BEARTEC);
//! see README.md "Tiers". Nothing in this file is a secret: API keys live in
//! `keys.json` as SHA-256 hashes, and the Stripe webhook secret is read from an
//! environment variable whose *name* is configured here.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Tier {
    Free,
    Builder,
    Scale,
}

impl Tier {
    pub fn as_str(&self) -> &'static str {
        match self {
            Tier::Free => "free",
            Tier::Builder => "builder",
            Tier::Scale => "scale",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TierLimits {
    /// Display price in GBP pence per month (0 = free). Billing is GBP only.
    pub price_gbp_pence: u32,
    /// Sustained requests per second (token-bucket refill rate).
    pub rps: f64,
    /// Bucket size (short bursts above `rps`).
    pub burst: u32,
    /// Requests per calendar month (UTC). Reset on the 1st, 00:00 UTC.
    pub monthly_quota: u64,
    /// `submit_tx` calls per minute (separate bucket; tx submit is costlier).
    pub tx_submit_per_min: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BillingConfig {
    /// Master switch. false => webhook route answers 404 and nothing is metered to Stripe.
    #[serde(default)]
    pub enabled: bool,
    /// Name of the env var holding the Stripe webhook signing secret (never the secret itself).
    #[serde(default = "default_secret_env")]
    pub webhook_secret_env: String,
    /// Stripe price id -> tier. Placeholders until Scott creates the GBP prices.
    #[serde(default)]
    pub price_tiers: BTreeMap<String, Tier>,
    /// Max age of a signed webhook (replay window).
    #[serde(default = "default_tolerance")]
    pub tolerance_secs: u64,
    /// Where accepted webhook events are queued for the operator (stub: no tier change is applied automatically).
    #[serde(default = "default_events_path")]
    pub events_path: PathBuf,
}

fn default_secret_env() -> String {
    "FPL_GATEWAY_STRIPE_WEBHOOK_SECRET".into()
}
fn default_tolerance() -> u64 {
    300
}
fn default_events_path() -> PathBuf {
    "/var/lib/fpl-gateway/billing-events.jsonl".into()
}

impl Default for BillingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            webhook_secret_env: default_secret_env(),
            price_tiers: BTreeMap::new(),
            tolerance_secs: default_tolerance(),
            events_path: default_events_path(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Public HTTP listener (put Caddy/nginx TLS in front).
    pub listen: String,
    /// Metrics listener; keep on loopback / tailnet.
    pub metrics_listen: String,
    /// Upstream node wire RPC (newline-delimited JSON `WireMsg`).
    pub upstream: String,
    pub upstream_timeout_ms: u64,
    /// Max upstream reply line (status dumps can be large).
    pub upstream_max_reply_bytes: usize,
    /// HTTP request body cap.
    pub max_body_bytes: usize,
    /// Max concurrent upstream connections.
    pub max_upstream_concurrency: usize,
    /// CORS allowed origins (exact match). Defaults to the BEARTEC sites; `"*"`
    /// still allows any origin but must now be set explicitly.
    #[serde(default = "default_cors_origins")]
    pub cors_origins: Vec<String>,
    pub keys_path: PathBuf,
    pub usage_path: PathBuf,
    pub usage_flush_secs: u64,
    pub tiers: BTreeMap<Tier, TierLimits>,
    #[serde(default)]
    pub billing: BillingConfig,
    /// Optional pull of self-serve keys from the Falcon Cloud portal (off by default).
    #[serde(default)]
    pub portal: PortalConfig,
    /// Abuse limits for unauthenticated surfaces (health probe, bad/missing keys).
    #[serde(default)]
    pub abuse: AbuseLimits,
    /// Optional fills-store market data API (candles, history, ticker, pairs).
    #[serde(default)]
    pub market_data: MarketConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct PortalConfig {
    /// Master switch. false => only keys.json is used.
    pub enabled: bool,
    /// Portal export endpoint, e.g. https://falcon-fpl.com/api/falcon-cloud/internal/keys
    pub url: String,
    /// Name of the env var holding the shared bearer token (never the token itself).
    pub token_env: String,
    /// Poll interval.
    pub interval_secs: u64,
    pub timeout_ms: u64,
}

impl Default for PortalConfig {
    fn default() -> Self {
        Self { enabled: false, url: String::new(), token_env: "FPL_GATEWAY_PORTAL_TOKEN".into(), interval_secs: 60, timeout_ms: 5_000 }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct MarketConfig {
    pub enabled: bool,
    /// Base URL of the fills-store market API, e.g. http://100.96.215.37:8787
    pub url: String,
    /// Name of the env var holding the shared bearer token (never the token itself).
    pub token_env: String,
    pub timeout_ms: u64,
}

impl Default for MarketConfig {
    fn default() -> Self {
        Self { enabled: false, url: String::new(), token_env: "FPL_GATEWAY_MARKET_TOKEN".into(), timeout_ms: 5_000 }
    }
}

/// Explicit default CORS allowlist (matches the deployed gateway.toml).
pub fn default_cors_origins() -> Vec<String> {
    vec!["https://falcon-fpl.com".into(), "https://www.beartec.uk".into()]
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct AbuseLimits {
    /// `GET /v1/health`: gateway-wide token bucket (requests/sec, burst).
    pub health_rps: f64,
    pub health_burst: u32,
    /// Max concurrent upstream health probes; extra callers get the cached result.
    pub health_max_concurrent: usize,
    /// Health result cache (ms); probes within the window never touch the node.
    pub health_cache_ms: u64,
    /// Requests with a missing/invalid API key, per client IP (X-Forwarded-For from Caddy).
    pub unauth_ip_rps: f64,
    pub unauth_ip_burst: u32,
    /// Requests with a missing/invalid API key, gateway-wide.
    pub unauth_global_rps: f64,
    pub unauth_global_burst: u32,
    /// Cap on tracked client IPs (map is cleared when exceeded).
    pub max_tracked_ips: usize,
}

impl Default for AbuseLimits {
    fn default() -> Self {
        Self {
            health_rps: 5.0,
            health_burst: 20,
            health_max_concurrent: 2,
            health_cache_ms: 1_000,
            unauth_ip_rps: 1.0,
            unauth_ip_burst: 10,
            unauth_global_rps: 20.0,
            unauth_global_burst: 50,
            max_tracked_ips: 10_000,
        }
    }
}

impl Config {
    pub fn load(path: &std::path::Path) -> anyhow::Result<Self> {
        let s = std::fs::read_to_string(path)?;
        let c: Config = toml::from_str(&s)?;
        c.validate()?;
        Ok(c)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        for t in [Tier::Free, Tier::Builder, Tier::Scale] {
            let l = self.tiers.get(&t).ok_or_else(|| anyhow::anyhow!("missing tier {}", t.as_str()))?;
            anyhow::ensure!(l.rps > 0.0 && l.burst > 0, "tier {} needs rps>0 and burst>0", t.as_str());
        }
        anyhow::ensure!(self.max_body_bytes > 0 && self.max_body_bytes <= 1 << 20, "max_body_bytes must be 1..=1MiB");
        let a = &self.abuse;
        anyhow::ensure!(a.health_rps > 0.0 && a.health_burst > 0 && a.health_max_concurrent > 0, "abuse.health_* must be > 0");
        anyhow::ensure!(a.unauth_ip_rps > 0.0 && a.unauth_ip_burst > 0 && a.unauth_global_rps > 0.0 && a.unauth_global_burst > 0, "abuse.unauth_* must be > 0");
        anyhow::ensure!(a.max_tracked_ips > 0, "abuse.max_tracked_ips must be > 0");
        if self.portal.enabled {
            anyhow::ensure!(self.portal.url.starts_with("https://") || self.portal.url.starts_with("http://127.0.0.1") || self.portal.url.starts_with("http://localhost"), "portal.url must be https (or loopback http)");
            anyhow::ensure!(self.portal.interval_secs >= 10, "portal.interval_secs must be >= 10");
        }
        if self.market_data.enabled {
            let u = &self.market_data.url;
            let ok = u.starts_with("https://")
                || u.starts_with("http://127.0.0.1")
                || u.starts_with("http://localhost")
                || u.starts_with("http://100."); // Tailscale CGNAT
            anyhow::ensure!(ok, "market_data.url must be https, loopback http, or a Tailscale http://100. address");
            anyhow::ensure!(self.market_data.timeout_ms >= 100, "market_data.timeout_ms must be >= 100");
        }
        if self.cors_origins.iter().any(|o| o == "*") {
            tracing::warn!("cors_origins contains \"*\": any website can call this gateway from a browser");
        }
        Ok(())
    }

    pub fn limits(&self, t: Tier) -> &TierLimits {
        &self.tiers[&t]
    }

    /// Proposed defaults (for tests and `example-config`).
    pub fn proposed_default() -> Self {
        let mut tiers = BTreeMap::new();
        tiers.insert(Tier::Free, TierLimits { price_gbp_pence: 0, rps: 5.0, burst: 10, monthly_quota: 300_000, tx_submit_per_min: 10 });
        tiers.insert(Tier::Builder, TierLimits { price_gbp_pence: 2_900, rps: 25.0, burst: 50, monthly_quota: 5_000_000, tx_submit_per_min: 120 });
        tiers.insert(Tier::Scale, TierLimits { price_gbp_pence: 19_900, rps: 100.0, burst: 200, monthly_quota: 50_000_000, tx_submit_per_min: 600 });
        Config {
            listen: "127.0.0.1:8545".into(),
            metrics_listen: "127.0.0.1:9187".into(),
            upstream: "127.0.0.1:19312".into(),
            upstream_timeout_ms: 5_000,
            upstream_max_reply_bytes: 8 << 20,
            max_body_bytes: 64 * 1024,
            max_upstream_concurrency: 64,
            cors_origins: default_cors_origins(),
            keys_path: "/etc/fpl-gateway/keys.json".into(),
            usage_path: "/var/lib/fpl-gateway/usage.json".into(),
            usage_flush_secs: 30,
            tiers,
            billing: BillingConfig::default(),
            portal: PortalConfig::default(),
            abuse: AbuseLimits::default(),
            market_data: MarketConfig::default(),
        }
    }
}
