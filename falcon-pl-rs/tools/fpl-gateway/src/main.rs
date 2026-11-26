//! fpl-gatewayd
//!   fpl-gatewayd serve --config /etc/fpl-gateway/gateway.toml
//!   fpl-gatewayd new-key --id k_acme --tier builder [--label "Acme"]   (prints the key ONCE to stdout, JSON record to stderr)
//!   fpl-gatewayd example-config
//!   fpl-gatewayd check-config --config PATH
//! SIGHUP reloads keys.json.

use fpl_gateway::{auth, portal, config::{Config, Tier}, limits::Limiter, server};
use std::path::PathBuf;
use std::time::Duration;

fn arg(args: &[String], k: &str) -> Option<String> {
    args.iter().position(|a| a == k).and_then(|i| args.get(i + 1)).cloned()
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into())).init();
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("example-config") => {
            print!("{}", toml::to_string_pretty(&Config::proposed_default())?);
            Ok(())
        }
        Some("check-config") => {
            let c = Config::load(&PathBuf::from(arg(&args, "--config").unwrap_or("/etc/fpl-gateway/gateway.toml".into())))?;
            let k = auth::KeyStore::load(&c.keys_path)?;
            println!("config ok; {} keys; upstream {}", k.len(), c.upstream);
            Ok(())
        }
        Some("new-key") => {
            let id = arg(&args, "--id").ok_or_else(|| anyhow::anyhow!("--id required"))?;
            let tier: Tier = serde_json::from_value(serde_json::Value::String(arg(&args, "--tier").unwrap_or("free".into())))?;
            let (key, rec) = auth::generate(&id, tier, &arg(&args, "--label").unwrap_or_default());
            eprintln!("{}", serde_json::to_string(&rec)?);
            eprintln!("# append the record above to keys.json; the key below is shown once and is not stored");
            println!("{key}");
            Ok(())
        }
        Some("serve") => serve(PathBuf::from(arg(&args, "--config").unwrap_or("/etc/fpl-gateway/gateway.toml".into()))).await,
        _ => {
            eprintln!("usage: fpl-gatewayd serve|new-key|example-config|check-config [--config PATH]");
            std::process::exit(2)
        }
    }
}

async fn serve(path: PathBuf) -> anyhow::Result<()> {
    let cfg = Config::load(&path)?;
    let sources = std::sync::Arc::new(portal::Sources::new(cfg.keys_path.clone()));
    let keys = sources.build()?;
    let limiter = Limiter::new(Limiter::load_usage(&cfg.usage_path));
    tracing::info!(keys = keys.len(), upstream = %cfg.upstream, "fpl-gateway starting (testnet)");
    let st = server::AppState::new(cfg.clone(), keys, limiter);
    if cfg.market_data.enabled && st.market.is_none() {
        anyhow::bail!("market_data.enabled but the client did not start (check env {})", cfg.market_data.token_env);
    }

    let pub_l = tokio::net::TcpListener::bind(&cfg.listen).await?;
    let met_l = tokio::net::TcpListener::bind(&cfg.metrics_listen).await?;
    tokio::spawn(axum::serve(met_l, server::metrics_router(st.clone())).into_future());

    // periodic usage flush
    let st2 = st.clone();
    tokio::spawn(async move {
        let mut iv = tokio::time::interval(Duration::from_secs(st2.cfg.usage_flush_secs.max(5)));
        loop {
            iv.tick().await;
            if let Err(e) = st2.limiter.flush(&st2.cfg.usage_path) {
                tracing::warn!("usage flush: {e}");
            }
        }
    });

    // SIGHUP: reload keys
    let st3 = st.clone();
    let src3 = sources.clone();
    tokio::spawn(async move {
        let Ok(mut hup) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()) else { return };
        while hup.recv().await.is_some() {
            match src3.build() {
                Ok(k) => {
                    tracing::info!(keys = k.len(), "keys reloaded");
                    *st3.keys.write() = k;
                }
                Err(e) => tracing::error!("keys reload failed, keeping old set: {e}"),
            }
        }
    });

    // Portal key pull (off unless [portal] enabled = true).
    if cfg.portal.enabled {
        let token = std::env::var(&cfg.portal.token_env).map_err(|_| anyhow::anyhow!("portal.enabled but env {} is unset", cfg.portal.token_env))?;
        let client = reqwest::Client::builder().timeout(Duration::from_millis(cfg.portal.timeout_ms)).build()?;
        let (st5, src5) = (st.clone(), sources.clone());
        tokio::spawn(async move {
            let mut iv = tokio::time::interval(Duration::from_secs(st5.cfg.portal.interval_secs));
            loop {
                iv.tick().await;
                match portal::fetch(&client, &st5.cfg.portal, &token).await.and_then(|r| src5.set_portal(r)) {
                    Ok(k) => {
                        tracing::debug!(keys = k.len(), portal = src5.portal_len(), "portal keys synced");
                        *st5.keys.write() = k;
                    }
                    Err(e) => tracing::warn!("portal key sync failed, keeping last good set: {e}"),
                }
            }
        });
    }

    let st4 = st.clone();
    axum::serve(pub_l, server::router(st.clone()))
        .with_graceful_shutdown(async {
            let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).expect("sigterm");
            tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = term.recv() => {} }
        })
        .await?;
    st4.limiter.flush(&st4.cfg.usage_path)?;
    Ok(())
}

use std::future::IntoFuture;
