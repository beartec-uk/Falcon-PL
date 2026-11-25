//! Loopback rehearsal fixture for the legacy BTC rail (private test nets
//! only). Uses the same fixed test vault secret as the unit tests; never use
//! it on a real network.
//!
//!   rehearse_btc vault <out.json>                  write vault-pub.json
//!   rehearse_btc deposit <dest> <sats> <prev_hash|0> <unix_time>
//!   rehearse_btc withdraw <snapshot> <from> <sats> <btc_dest>
use fd_pl::{btc_spv, vault};

fn secret() -> [u8; 32] {
    let d = fd_pl::crypto::sha256_hex(b"test-vault-sk");
    let mut s = [0u8; 32];
    s.copy_from_slice(&hex::decode(&d).unwrap());
    s[0] &= 0x3f;
    s
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let sk = secret();
    let vp = vault::vault_pub_from_secret(&sk, 0, 5, 3).unwrap();
    match a.get(1).map(|s| s.as_str()) {
        Some("vault") => {
            std::fs::write(&a[2], serde_json::to_vec_pretty(&vp).unwrap()).unwrap();
            println!("{}", vp.spk_hex);
        }
        Some("deposit") => {
            let dest = &a[2];
            let sats: u64 = a[3].parse().unwrap();
            let prev = if a[4] == "0" { "00".repeat(32) } else { a[4].clone() };
            let time: u32 = a[5].parse().unwrap();
            let watch = hex::decode(&vp.spk_hex).unwrap();
            let (raw, tx) = btc_spv::test_deposit_tx(&watch, dest, sats);
            let h = btc_spv::mine_header(&prev, &tx.txid_display, 0x207fffff, time).unwrap();
            println!(
                "{}",
                serde_json::json!({
                    "header_raw": h.raw_hex, "hash": h.hash_display, "merkle": h.merkle_display,
                    "txid": tx.txid_display, "raw_tx": btc_spv::hex_encode(&raw),
                })
            );
        }
        Some("withdraw") => {
            let snap = fd_pl::snapshot::parse_snapshot_bytes(&std::fs::read(&a[2]).unwrap()).unwrap();
            let from = &a[3];
            let sats: u64 = a[4].parse().unwrap();
            let dest = &a[5];
            let utxos = snap.bridge.rail(fd_pl::bridge::RAIL_BTC).unwrap().vault_utxos.clone();
            let shares = vault::split_secret(&sk, 5, 3, 0, b"tv").unwrap();
            let plan = vault::coin_select(&utxos, sats, dest, vault::DEFAULT_FEE_SATS).unwrap();
            let vsig = vault::sign_plan(&shares[0..3], &plan).unwrap();
            let note_id = fd_pl::crypto::sha256_hex(format!("wd:BTC:{from}:{sats}:{dest}").as_bytes());
            let kick = vault::signed_dest_lock_kickoff(
                &shares[0..3], &utxos, dest, sats, vault::DEFAULT_FEE_SATS, &vp.spk_hex, &note_id,
            )
            .unwrap();
            println!(
                "{}",
                serde_json::json!({"vault_sig": vsig, "signed_btc_tx": kick, "utxos": utxos.len(), "snap_tip": snap.tip_height})
            );
        }
        _ => eprintln!("usage: see source"),
    }
}
