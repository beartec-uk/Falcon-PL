//! Slim the node status dump for Cloud users. The node honours
//! `brief=true` / `include_accounts=false`, but the remaining object is still
//! hundreds of kilobytes. This keeps the fields the docs promise.

use serde_json::{json, Map, Value};

const KEEP: &[&str] = &[
    "product",
    "product_version",
    "network",
    "network_id",
    "testnet",
    "height",
    "tip_height",
    "tip_hash",
    "tip_lag",
    "committee_size",
];

const RAIL_KEEP: &[&str] = &["asset", "total_minted", "total_burned", "open_withdrawals", "tip_height", "spv"];

/// Return a short status object. Unknown shapes are passed through only if they
/// are already small objects; otherwise we keep an empty object rather than a
/// dump.
pub fn slim_status(v: Value) -> Value {
    let Value::Object(m) = v else {
        return json!({});
    };
    let mut out = Map::new();
    for k in KEEP {
        if let Some(val) = m.get(*k) {
            out.insert((*k).to_string(), val.clone());
        }
    }
    if let Some(rails) = m.get("rails") {
        out.insert("rails".into(), slim_rails(rails));
    }
    Value::Object(out)
}

fn slim_rails(v: &Value) -> Value {
    let Some(arr) = v.as_array() else {
        return json!([]);
    };
    Value::Array(
        arr.iter()
            .map(|r| {
                let Some(obj) = r.as_object() else {
                    return json!({});
                };
                let mut o = Map::new();
                for k in RAIL_KEEP {
                    if let Some(val) = obj.get(*k) {
                        if val.is_object() || val.is_array() {
                            continue;
                        }
                        o.insert((*k).to_string(), val.clone());
                    }
                }
                Value::Object(o)
            })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drops_accounts_amm_and_claim_lists() {
        let fat = json!({
            "product": "Falcon PL",
            "product_version": "2.11.20",
            "network": "falcon-pl-private-v22",
            "network_id": 2300,
            "tip_height": 1000,
            "tip_hash": "ab",
            "tip_lag": 0,
            "committee_size": 7,
            "accounts": {"alice": 1},
            "accounts_count": 1498,
            "amm_lp_weights": {"alice": 1},
            "amm_pools": {"x": {}},
            "disk": {"used": 1},
            "rails": [{
                "asset": "BTC4",
                "total_minted": 10,
                "total_burned": 1,
                "open_withdrawals": 0,
                "spv": "protocol",
                "bitvm2_claims": [{"from":"dave"}],
                "user_vaults": {"x": 1},
                "withdrawals": [1,2,3]
            }]
        });
        let slim = slim_status(fat);
        let s = slim.to_string();
        assert!(s.len() < 600, "still too large: {s}");
        assert_eq!(slim["product"], "Falcon PL");
        assert_eq!(slim["tip_height"], 1000);
        assert_eq!(slim["rails"][0]["asset"], "BTC4");
        assert_eq!(slim["rails"][0]["total_minted"], 10);
        assert!(slim.get("accounts").is_none());
        assert!(slim.get("amm_lp_weights").is_none());
        assert!(slim["rails"][0].get("bitvm2_claims").is_none());
        assert!(slim["rails"][0].get("user_vaults").is_none());
    }

    #[test]
    fn keeps_height_alias_used_in_tests() {
        let slim = slim_status(json!({"height":4242,"network":"falcon-pl-testnet"}));
        assert_eq!(slim["height"], 4242);
        assert_eq!(slim["network"], "falcon-pl-testnet");
    }
}
