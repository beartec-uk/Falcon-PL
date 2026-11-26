//! Method allowlist. Public JSON-RPC method -> node `WireMsg` type.
//!
//! Only read queries and `submit_tx` are reachable. Every operator/admin
//! message (`WireMsg::is_admin` in fd-pl/src/lib.rs), every mesh/consensus
//! message (proposals, votes, snapshots, catch-up) and every ctl-only message
//! is unreachable because nothing maps to it. Params may not override `type`.

use serde_json::{Map, Value};

pub struct Method {
    pub name: &'static str,
    pub wire_type: &'static str,
    /// Cost against the monthly quota.
    pub cost: u64,
    pub is_tx_submit: bool,
    /// Served from the fills-store market API rather than the node.
    pub market: bool,
    /// Node reply `type`s that answer this method (besides `err`). fd-pl
    /// v2.10.4 answers all three order-book queries with `order_book`
    /// (verified live 2026-11-04); `open_orders` / `fills` are accepted too in
    /// case the node gains dedicated reply variants.
    pub reply_types: &'static [&'static str],
}

pub const METHODS: &[Method] = &[
    Method { name: "fpl_status", wire_type: "status_req", cost: 1, is_tx_submit: false, market: false, reply_types: &["status"] },
    Method { name: "fpl_health", wire_type: "health_req", cost: 1, is_tx_submit: false, market: false, reply_types: &["health"] },
    Method { name: "fpl_getAccount", wire_type: "account_query", cost: 1, is_tx_submit: false, market: false, reply_types: &["account"] },
    Method { name: "fpl_orderBook", wire_type: "order_book_query", cost: 1, is_tx_submit: false, market: false, reply_types: &["order_book"] },
    Method { name: "fpl_openOrders", wire_type: "open_orders_query", cost: 1, is_tx_submit: false, market: false, reply_types: &["order_book", "open_orders"] },
    Method { name: "fpl_fills", wire_type: "fills_query", cost: 1, is_tx_submit: false, market: false, reply_types: &["order_book", "fills"] },
    Method { name: "fpl_submitTx", wire_type: "submit_tx", cost: 5, is_tx_submit: true, market: false, reply_types: &["ok"] },
    Method { name: "fpl_pairs", wire_type: "pairs_query", cost: 1, is_tx_submit: false, market: true, reply_types: &["market"] },
    Method { name: "fpl_ticker", wire_type: "ticker_query", cost: 1, is_tx_submit: false, market: true, reply_types: &["market"] },
    Method { name: "fpl_candles", wire_type: "candles_query", cost: 1, is_tx_submit: false, market: true, reply_types: &["market"] },
];

/// Wire types the gateway must never send (mirrors `WireMsg::is_admin` plus
/// mesh/consensus/snapshot traffic). Used by tests as a regression guard.
pub const FORBIDDEN_WIRE_TYPES: &[&str] = &[
    "seal_now", "seal_force", "vault_open", "vault_lock", "claim_rewards", "create_pool",
    "add_liquidity", "swap", "create_market", "lend_supply", "watcher_credit", "bond",
    "request_unbond", "complete_unbond", "credit_asset", "tick", "force_settle_epoch",
    "rail_header", "rail_deposit", "rail_withdraw", "rail_bitvm2_attest", "rail_bitvm2_pegout",
    "rail_challenge", "snapshot_save", "snapshot_load", "operator_hard_reset", "mempool_drop",
    "hello", "piece", "propose_ledger", "propose_header", "ledger_ok", "online_set_vote",
    "view_change", "skip_packer", "need_snapshot", "need_snapshot_chunk", "need_ledgers",
    "need_txs", "need_mempool_txs", "tx_inv", "need_ledger_body", "need_txs_by_ids",
];

pub fn lookup(name: &str) -> Option<&'static Method> {
    METHODS.iter().find(|m| m.name == name)
}

#[derive(Debug, PartialEq)]
pub enum BuildErr {
    UnknownMethod,
    BadParams(&'static str),
}

/// Build the upstream wire message for an allowlisted method.
pub fn build_wire(m: &Method, params: Option<&Value>) -> Result<Value, BuildErr> {
    let mut obj = match params {
        None | Some(Value::Null) => Map::new(),
        Some(Value::Object(o)) => o.clone(),
        Some(_) => return Err(BuildErr::BadParams("params must be an object")),
    };
    obj.remove("type");
    let s = |o: &Map<String, Value>, k: &'static str| -> Result<(), BuildErr> {
        match o.get(k) {
            Some(Value::String(v)) if !v.is_empty() && v.len() <= 256 => Ok(()),
            _ => Err(BuildErr::BadParams(k)),
        }
    };
    let mut out = Map::new();
    match m.wire_type {
        // Always brief, never the account dump: the full status is ~2MB.
        "status_req" => {
            out.insert("include_accounts".into(), Value::Bool(false));
            out.insert("brief".into(), Value::Bool(true));
        }
        "health_req" => {
            let w = obj.get("warnings").and_then(Value::as_u64).unwrap_or(0).min(64);
            out.insert("warnings".into(), w.into());
        }
        "account_query" | "open_orders_query" => {
            s(&obj, "account")?;
            out.insert("account".into(), obj["account"].clone());
        }
        "order_book_query" => {
            s(&obj, "pair")?;
            out.insert("pair".into(), obj["pair"].clone());
            let l = obj.get("levels").and_then(Value::as_u64).unwrap_or(50).min(200);
            out.insert("levels".into(), l.into());
        }
        "fills_query" => {
            for k in ["pair", "account"] {
                if let Some(v) = obj.get(k) {
                    if !v.is_null() {
                        s(&obj, k)?;
                        out.insert(k.into(), v.clone());
                    }
                }
            }
            let max = if m.market { 500 } else { 200 };
            let l = obj.get("limit").and_then(Value::as_u64).unwrap_or(50).min(max);
            out.insert("limit".into(), l.into());
            for k in ["from", "to", "cursor"] {
                if let Some(v) = obj.get(k) {
                    if !v.is_null() { out.insert(k.into(), v.clone()); }
                }
            }
        }
        "pairs_query" => {}
        "ticker_query" => {
            if let Some(v) = obj.get("pair") {
                if !v.is_null() {
                    s(&obj, "pair")?;
                    out.insert("pair".into(), v.clone());
                }
            }
        }
        "candles_query" => {
            s(&obj, "pair")?;
            s(&obj, "interval")?;
            out.insert("pair".into(), obj["pair"].clone());
            out.insert("interval".into(), obj["interval"].clone());
            for k in ["from", "to", "limit"] {
                if let Some(v) = obj.get(k) {
                    if !v.is_null() { out.insert(k.into(), v.clone()); }
                }
            }
            if let Some(l) = obj.get("limit").and_then(Value::as_u64) {
                out.insert("limit".into(), l.min(500).into());
            }
        }
        "submit_tx" => match obj.get("tx") {
            Some(Value::Object(_)) => {
                out.insert("tx".into(), obj["tx"].clone());
            }
            _ => return Err(BuildErr::BadParams("tx")),
        },
        _ => return Err(BuildErr::UnknownMethod),
    }
    out.insert("type".into(), Value::String(m.wire_type.into()));
    Ok(Value::Object(out))
}
