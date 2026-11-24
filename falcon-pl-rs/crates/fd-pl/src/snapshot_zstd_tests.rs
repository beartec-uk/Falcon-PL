//! 2.11.13: zstd snapshot files. Written compressed only once the bridge-slim
//! activation is in the snapshot state; plain JSON files keep loading; the
//! JSON inside (and the state root) is unchanged.

use super::*;

fn users() -> Vec<(String, u64)> {
    vec![("alice".into(), 1_000_000), ("bob".into(), 1_000_000)]
}

#[test]
fn zstd_only_after_slim_and_both_forms_load_to_the_same_state() {
    let mut net = Network::bootstrap(&["v1", "v2", "v3"], 1000, &users(), ChainConfig::default());
    net.payment("alice", "bob", 5, 1).unwrap();
    net.seal_next_height().unwrap();
    let dir = std::env::temp_dir().join(format!("fpl-zstd-snap-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let n = net.nodes.get_mut("v1").unwrap();
    let keys = n.keys.clone();

    // Pre-activation: plain JSON, byte-identical to serde_json.
    let plain = dir.join("plain.json");
    let snap = n.to_snapshot();
    let json = serde_json::to_vec(&snap).unwrap();
    let wrote = Node::write_snapshot_checked(&plain, &snap, &|_, _| Ok(())).unwrap();
    let raw = std::fs::read(&plain).unwrap();
    assert_eq!(raw, json);
    assert_eq!(wrote, raw.len() as u64);
    assert!(!crate::snapshot::is_zstd_snapshot(&raw));

    // Post-activation: zstd frame whose content is the exact same JSON shape.
    n.bridge.bridge_slim_convert();
    let z = dir.join("z.json");
    let snap = n.to_snapshot();
    let json = serde_json::to_vec(&snap).unwrap();
    let seen = std::cell::Cell::new(0u64);
    let wrote = Node::write_snapshot_checked(&z, &snap, &|_, need| {
        seen.set(need);
        Ok(())
    })
    .unwrap();
    let raw = std::fs::read(&z).unwrap();
    assert!(crate::snapshot::is_zstd_snapshot(&raw));
    assert_eq!(wrote, raw.len() as u64);
    assert_eq!(seen.get(), raw.len() as u64, "disk check sees the compressed size");
    assert!(raw.len() < json.len());
    assert_eq!(&crate::snapshot::snapshot_json_bytes(&raw).unwrap()[..], &json[..]);

    let a = Node::load_snapshot(&z, keys.clone()).unwrap();
    // Bridge state round-trips exactly (load itself adds the faucet account
    // and takes runtime gates from network constants, zstd or not).
    assert_eq!(serde_json::to_vec(&a.bridge).unwrap(), serde_json::to_vec(&n.bridge).unwrap());
    assert_eq!(a.tip_hash, n.tip_hash);
    assert!(a.bridge.bridge_slim);
    let b = Node::load_snapshot(&plain, keys).unwrap();
    assert_eq!(b.tip_hash, n.tip_hash);
    assert!(!b.bridge.bridge_slim);

    // A truncated zstd file is an error, never a silent partial state.
    std::fs::write(dir.join("bad.json"), &raw[..raw.len() / 2]).unwrap();
    assert!(Node::load_snapshot(dir.join("bad.json"), a.keys.clone()).is_err());
    let _ = std::fs::remove_dir_all(&dir);
}
