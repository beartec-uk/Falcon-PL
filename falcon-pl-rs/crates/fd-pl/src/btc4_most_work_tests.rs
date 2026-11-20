// Copyright (c) 2025-2026 BEARTEC. All rights reserved. See LICENSE.
//! BTC4 most-work rail + testnet4 header checks (`btc4_most_work_from_height`).
//!
//! The regression test replays the 2026-11-17 stall with the **real**
//! testnet4 headers (Bitcoin Core on falcon1, `testdata/btc4_tn4_161830_161880.json`):
//!
//! * main: 161857 `4ff223` → 161858 `4dea5` → 161859 `6c7ed7` (branch A)
//! * pending fork: 161857 `013101c1` → 161858 `3fcb0e7f` → 161859 `1e9f85ba`
//!   (branch B, equal work: all min-difficulty)
//! * canonical: 161859 `d7e70d00` (parent `3fcb0e7f`, *inside* the pending
//!   fork) → 161860 (real difficulty) → …
//!
//! Under 2.11.4 rules `d7e70d00` hits "BTC header parent mismatch … != stored
//! 4dea5 at 161858" (the live journal line) and the rail never moves again.
//! Under the most-work rail it is stored as a side header and 161860 reorgs
//! the rail onto the canonical chain.
use crate::bridge::{BtcHeaderRules, MostWork, RailHeader, RailState, BTC_SIDE_DEPTH, RAIL_BTC4};
use crate::btc_spv;
use std::collections::BTreeMap;

const TN4: BtcHeaderRules = BtcHeaderRules::TESTNET4;

struct Fx {
    by_prefix: BTreeMap<String, (u64, String)>,
    canonical: BTreeMap<u64, String>,
}

fn fx() -> Fx {
    let v: serde_json::Value =
        serde_json::from_str(include_str!("../testdata/btc4_tn4_161830_161880.json")).unwrap();
    let mut by_prefix = BTreeMap::new();
    let mut canonical = BTreeMap::new();
    for h in v["headers"].as_array().unwrap() {
        let height = h["height"].as_u64().unwrap();
        let hash = h["hash"].as_str().unwrap().to_string();
        let raw = h["raw"].as_str().unwrap().to_string();
        let p = btc_spv::parse_header_hex(&raw).unwrap();
        assert_eq!(p.hash_display, hash, "fixture hash");
        by_prefix.insert(hash[..16].to_string(), (height, raw.clone()));
        if h["canonical"].as_bool().unwrap() {
            canonical.insert(height, raw);
        }
    }
    Fx { by_prefix, canonical }
}

impl Fx {
    fn get(&self, prefix: &str) -> RailHeader {
        let (height, raw) = self.by_prefix.get(prefix).unwrap_or_else(|| panic!("{prefix}"));
        RailHeader { height: *height, hash: String::new(), parent_hash: String::new(), merkle_root: String::new(), raw: raw.clone() }
    }
    fn canon(&self, height: u64) -> RailHeader {
        RailHeader { height, hash: String::new(), parent_hash: String::new(), merkle_root: String::new(), raw: self.canonical[&height].clone() }
    }
}

/// UTC well after the fixture (no future-limit interference).
const NOW: u64 = 1_794_930_000;

fn legacy(r: &mut RailState, h: RailHeader) -> Result<bool, String> {
    r.submit_header_ex3(h, true, true, true)
}

fn mw(r: &mut RailState, h: RailHeader) -> Result<bool, String> {
    r.submit_header_ex4(h, true, true, true, Some(MostWork { utc_now_secs: Some(NOW) }))
}

/// Rail anchored at 161831, canonical to 161856, then the live stall state.
fn stalled(f: &Fx) -> RailState {
    let mut r = RailState::new(RAIL_BTC4);
    for h in 161_831..=161_856 {
        assert!(legacy(&mut r, f.canon(h)).unwrap(), "{h}");
    }
    for p in ["00000000004ff223", "000000000004dea5", "00000000006c7ed7"] {
        assert!(legacy(&mut r, f.get(p)).unwrap(), "{p}");
    }
    for p in ["00000000013101c1", "000000003fcb0e7f", "000000001e9f85ba"] {
        assert!(!legacy(&mut r, f.get(p)).unwrap(), "{p}: equal work, pending only");
    }
    assert_eq!(r.tip_height, 161_859);
    assert!(r.tip_hash.starts_with("00000000006c7ed7"));
    assert_eq!(r.btc_fork.len(), 3);
    r
}

#[test]
fn stall_161859_reproduces_under_2_11_4_rules() {
    let f = fx();
    let mut r = stalled(&f);
    let e = legacy(&mut r, f.get("00000000d7e70d00")).unwrap_err();
    assert!(e.contains("BTC header parent mismatch: height 161859 parent 000000003fcb0e7f"), "{e}");
    assert!(e.contains("!= stored 000000000004dea5"), "{e}");
    for h in 161_860..=161_880 {
        assert!(legacy(&mut r, f.canon(h)).is_err(), "{h}");
    }
    assert_eq!(r.tip_height, 161_859);
    // `most_work = None` is the 2.11.4 path, byte for byte.
    let mut a = stalled(&f);
    let mut b = stalled(&f);
    for h in [f.get("00000000d7e70d00"), f.canon(161_860)] {
        assert_eq!(legacy(&mut a, h.clone()), b.submit_header_ex4(h, true, true, true, None));
    }
    assert_eq!(serde_json::to_string(&a).unwrap(), serde_json::to_string(&b).unwrap());
    assert!(!serde_json::to_string(&a).unwrap().contains("btc_side"));
}

#[test]
fn stall_161859_clears_under_most_work_rail() {
    let f = fx();
    let mut r = stalled(&f);
    // Canonical 161859: parent is inside the old pending fork. Stored as a
    // side header; equal work, so first-seen keeps branch A on main.
    assert!(!mw(&mut r, f.get("00000000d7e70d00")).unwrap());
    assert!(r.btc_fork.is_empty() && r.btc_fork_alt.is_empty(), "slots migrated");
    assert_eq!(r.btc_side.len(), 4);
    assert!(r.tip_hash.starts_with("00000000006c7ed7"));
    let e = mw(&mut r, f.get("00000000d7e70d00")).unwrap_err();
    assert!(e.contains("BTC duplicate header at 161859 (side branch)"), "{e}");
    // 161860 (real difficulty) makes branch B+d7e70d00 heaviest: reorg.
    assert!(mw(&mut r, f.canon(161_860)).unwrap());
    assert_eq!(r.tip_height, 161_860);
    for h in 161_857..=161_860 {
        assert_eq!(r.headers[&h].raw, f.canonical[&h], "{h} canonical");
    }
    // Old main A is kept as a side branch.
    assert!(r.btc_side.keys().any(|k| k.starts_with("00000000006c7ed7")));
    for h in 161_861..=161_880 {
        assert!(mw(&mut r, f.canon(h)).unwrap(), "{h}");
    }
    assert_eq!(r.tip_height, 161_880);
    for h in 161_831..=161_880 {
        assert_eq!(r.headers[&h].raw, f.canonical[&h], "{h}");
    }
    let s = r.btc_side_summary().unwrap();
    assert!(s["len"].as_u64().unwrap() > 0);
}

/// Every header Core holds for 161857..=161880, in several orders: the rail
/// always lands on the canonical chain through 161879 (161880 itself has an
/// equal-work stale sibling, so first-seen decides it), and the same order
/// gives byte-identical state on every seat.
#[test]
fn all_branches_any_order_converge_on_canonical() {
    let f = fx();
    let mut side: Vec<RailHeader> = vec![];
    let v: serde_json::Value =
        serde_json::from_str(include_str!("../testdata/btc4_tn4_161830_161880.json")).unwrap();
    for h in v["headers"].as_array().unwrap() {
        let height = h["height"].as_u64().unwrap();
        if height >= 161_857 {
            side.push(RailHeader { height, hash: String::new(), parent_hash: String::new(), merkle_root: String::new(), raw: h["raw"].as_str().unwrap().into() });
        }
    }
    side.sort_by_key(|h| h.height);
    let orders: Vec<Vec<RailHeader>> = vec![
        side.clone(),
        { let mut x = side.clone(); x.sort_by(|a, b| a.height.cmp(&b.height).then(b.raw.cmp(&a.raw))); x },
        { let mut x = side.clone(); x.reverse(); x },
    ];
    let run = |order: &Vec<RailHeader>| {
        let mut r = RailState::new(RAIL_BTC4);
        mw(&mut r, f.canon(161_831)).unwrap();
        for h in 161_832..=161_856 {
            assert!(mw(&mut r, f.canon(h)).unwrap());
        }
        // Repeat passes: a header whose parent arrives later lands next pass.
        for _ in 0..30 {
            for h in order {
                let _ = mw(&mut r, h.clone());
            }
        }
        r
    };
    for order in &orders {
        let r = run(order);
        assert_eq!(r.tip_height, 161_880);
        for h in 161_857..=161_879 {
            assert_eq!(r.headers[&h].raw, f.canonical[&h], "{h}");
        }
        assert_eq!(serde_json::to_string(&r).unwrap(), serde_json::to_string(&run(order)).unwrap());
    }
}

#[test]
fn equal_work_tie_break_is_first_seen() {
    let f = fx();
    // Two orders of the same two equal-work siblings at 161857.
    for (first, second) in [("00000000004ff223", "00000000013101c1"), ("00000000013101c1", "00000000004ff223")] {
        let mut r = RailState::new(RAIL_BTC4);
        mw(&mut r, f.canon(161_831)).unwrap();
        for h in 161_832..=161_856 {
            mw(&mut r, f.canon(h)).unwrap();
        }
        assert!(mw(&mut r, f.get(first)).unwrap());
        assert!(!mw(&mut r, f.get(second)).unwrap(), "equal work: stay on first seen");
        assert!(r.tip_hash.starts_with(first));
    }
}

#[test]
fn real_headers_pass_testnet4_context_checks() {
    // 161853 is real-difficulty with a timestamp 3809 s *before* its parent:
    // valid (after median-time-past), and its nBits come from the walk-back.
    let f = fx();
    let p = btc_spv::parse_header_hex(&f.canonical[&161_853]).unwrap();
    let q = btc_spv::parse_header_hex(&f.canonical[&161_852]).unwrap();
    assert!(p.timestamp < q.timestamp && p.bits == 0x1902a986);
    let mut r = RailState::new(RAIL_BTC4);
    mw(&mut r, f.canon(161_831)).unwrap();
    for h in 161_832..=161_880 {
        assert!(mw(&mut r, f.canon(h)).unwrap(), "{h}");
    }
}

// ---- fake / cheap headers -------------------------------------------------

/// Regtest-style pow limit so test headers mine instantly; the rules are the
/// same code path with a different limit.
const EASY: u32 = 0x207fffff;
const RT: BtcHeaderRules = BtcHeaderRules { pow_limit_bits: EASY };
/// "Real" difficulty below the easy limit (still mines in a few ms).
const REAL: u32 = 0x1f7fffff;

fn mine(prev: &str, tag: u32, bits: u32, t: u32) -> btc_spv::ParsedHeader {
    mine_v(prev, tag, bits, t, 0x2000_0000)
}

fn mine_v(prev: &str, tag: u32, bits: u32, t: u32, version: u32) -> btc_spv::ParsedHeader {
    let merkle = format!("{tag:08x}").repeat(8);
    let prev_i = btc_spv::display_to_internal(prev).unwrap_or([0u8; 32]);
    let merkle_i = btc_spv::display_to_internal(&merkle).unwrap();
    let mut raw = [0u8; 80];
    raw[0..4].copy_from_slice(&version.to_le_bytes());
    raw[4..36].copy_from_slice(&prev_i);
    raw[36..68].copy_from_slice(&merkle_i);
    raw[68..72].copy_from_slice(&t.to_le_bytes());
    raw[72..76].copy_from_slice(&bits.to_le_bytes());
    for nonce in 0u32.. {
        raw[76..80].copy_from_slice(&nonce.to_le_bytes());
        if btc_spv::hash_meets_target(&btc_spv::hash256(&raw), bits) {
            return btc_spv::parse_header(&raw).unwrap();
        }
    }
    unreachable!()
}

fn rh(height: u64, p: &btc_spv::ParsedHeader) -> RailHeader {
    RailHeader { height, hash: String::new(), parent_hash: String::new(), merkle_root: String::new(), raw: p.raw_hex.clone() }
}

const T0: u32 = 1_800_000_000;

/// Rail of `n` real-difficulty headers 10 minutes apart from height 1000.
fn chain(n: u32) -> (RailState, Vec<btc_spv::ParsedHeader>) {
    let mut r = RailState::new(RAIL_BTC4);
    let mut prev = "00".repeat(32);
    let mut v = vec![];
    for i in 0..n {
        let p = mine(&prev, i, REAL, T0 + i * 600);
        assert!(r.submit_btc_header_most_work(rh(1000 + i as u64, &p), Some((T0 + i * 600) as u64), RT).unwrap(), "{i}");
        prev = p.hash_display.clone();
        v.push(p);
    }
    (r, v)
}

fn tip_time(v: &[btc_spv::ParsedHeader]) -> u32 {
    v.last().unwrap().timestamp
}

#[test]
fn rejects_time_too_new() {
    let (mut r, v) = chain(12);
    let now = tip_time(&v) as u64;
    let tip = v.last().unwrap();
    let fake = mine(&tip.hash_display, 0xf00d, EASY, (now + 7200 + 1) as u32);
    let e = r.submit_btc_header_most_work(rh(1012, &fake), Some(now), RT).unwrap_err();
    assert!(e.contains("time-too-new"), "{e}");
    let ok = mine(&tip.hash_display, 0xf00e, EASY, (now + 7200) as u32);
    assert!(r.submit_btc_header_most_work(rh(1012, &ok), Some(now), RT).unwrap());
}

#[test]
fn rejects_time_not_after_median_time_past() {
    let (mut r, v) = chain(12);
    let tip = v.last().unwrap();
    // Median of the last 11 (1001..=1011) is 1006's time.
    let mtp = v[6].timestamp;
    let e = r
        .submit_btc_header_most_work(rh(1012, &mine(&tip.hash_display, 1, REAL, mtp)), Some(tip.timestamp as u64), RT)
        .unwrap_err();
    assert!(e.contains("time-too-old"), "{e}");
    assert!(r.submit_btc_header_most_work(rh(1012, &mine(&tip.hash_display, 2, REAL, mtp + 1)), Some(tip.timestamp as u64), RT).unwrap());
}

#[test]
fn rejects_wrong_difficulty() {
    let (mut r, v) = chain(12);
    let tip = v.last().unwrap();
    let now = tip.timestamp as u64 + 3600;
    // Min-difficulty without the 20-minute gap (exactly 1200 s is not enough).
    let e = r.submit_btc_header_most_work(rh(1012, &mine(&tip.hash_display, 1, EASY, tip.timestamp + 1200)), Some(now), RT).unwrap_err();
    assert!(e.contains("bad-diffbits"), "{e}");
    // After > 20 minutes Core *requires* min-difficulty bits.
    let e = r.submit_btc_header_most_work(rh(1012, &mine(&tip.hash_display, 2, REAL, tip.timestamp + 1201)), Some(now), RT).unwrap_err();
    assert!(e.contains("bad-diffbits"), "{e}");
    // Easier-than-real bits that are not the min-difficulty value.
    let e = r.submit_btc_header_most_work(rh(1012, &mine(&tip.hash_display, 3, 0x203fffff, tip.timestamp + 60)), Some(now), RT).unwrap_err();
    assert!(e.contains("bad-diffbits"), "{e}");
    assert!(r.submit_btc_header_most_work(rh(1012, &mine(&tip.hash_display, 4, EASY, tip.timestamp + 1201)), Some(now), RT).unwrap());
}

#[test]
fn rejects_bits_above_pow_limit_and_old_version() {
    let (mut r, v) = chain(12);
    let tip = v.last().unwrap();
    let now = tip.timestamp as u64 + 3600;
    // Testnet4 limit: a regtest-easy header is refused outright.
    let mut t4 = r.clone();
    let e = t4.submit_btc_header_most_work(rh(1012, &mine(&tip.hash_display, 1, EASY, tip.timestamp + 1201)), Some(now), TN4).unwrap_err();
    assert!(e.contains("outside the pow limit"), "{e}");
    let e = r.submit_btc_header_most_work(rh(1012, &mine_v(&tip.hash_display, 2, REAL, tip.timestamp + 60, 3)), Some(now), RT).unwrap_err();
    assert!(e.contains("bad-version"), "{e}");
}

/// Legacy rule hole: at a retarget height any nBits passed. Now the BIP94
/// value is required and the timewarp bound applies.
#[test]
fn retarget_requires_bip94_bits_and_timewarp_bound() {
    // Build heights 2016*k - 2016 ..= 2016*k - 1 so the next is a retarget.
    let base: u64 = 2016 * 50;
    let mut r = RailState::new(RAIL_BTC4);
    let mut prev = "00".repeat(32);
    let mut v = vec![];
    for i in 0..2016u32 {
        let p = mine(&prev, i, REAL, T0 + i * 300);
        assert!(r.submit_btc_header_most_work(rh(base + i as u64, &p), Some((T0 + i * 300) as u64), RT).unwrap(), "{i}");
        prev = p.hash_display.clone();
        v.push(p);
    }
    let last = v.last().unwrap().clone();
    let first = v[0].clone();
    let now = last.timestamp as u64 + 3600;
    let want = btc_spv::retarget_bip94(first.bits, first.timestamp, last.timestamp, EASY).unwrap();
    assert_ne!(want, REAL, "blocks were 2x fast: difficulty must rise");
    let h = base + 2016;
    // Legacy: any bits at a retarget (here: the easiest possible) pass.
    let cheap = mine(&last.hash_display, 1, EASY, last.timestamp + 60);
    let mut legacy = r.clone();
    assert!(legacy.submit_header_ex3(rh(h, &cheap), true, true, true).is_ok(), "legacy hole");
    let e = r.clone().submit_btc_header_most_work(rh(h, &cheap), Some(now), RT).unwrap_err();
    assert!(e.contains("bad-diffbits"), "{e}");
    // Timewarp: more than 600 s before the parent.
    let warp = mine(&last.hash_display, 2, want, last.timestamp - 601);
    let e = r.clone().submit_btc_header_most_work(rh(h, &warp), Some(now), RT).unwrap_err();
    assert!(e.contains("timewarp"), "{e}");
    let edge = mine(&last.hash_display, 3, want, last.timestamp - 600);
    assert!(r.submit_btc_header_most_work(rh(h, &edge), Some(now), RT).unwrap());
}

/// A funded account mines cheap min-difficulty headers with a fake merkle
/// root on top of the tip. Legacy rules take an unbounded chain of them (each
/// timestamp +1201 s, no future limit), enough to give a fake deposit 6
/// confirmations. With the 2-hour limit at most 5 fit, so a fake deposit
/// header can never reach 6.
#[test]
fn cheap_fake_chain_cannot_reach_six_confirmations() {
    let (r0, v) = chain(12);
    let tip = v.last().unwrap().clone();
    let now = tip.timestamp as u64; // rail is caught up
    let mut legacy = r0.clone();
    let mut fresh = r0.clone();
    let mut prev = tip.clone();
    let mut accepted_new = 0;
    let mut lprev = tip.clone();
    for i in 0..10u32 {
        let h = 1012 + i as u64;
        // Legacy: no future limit at all, so the attacker's chain can run
        // arbitrarily far ahead of real time.
        let lfake = mine(&lprev.hash_display, 0xdead_0000 + i, REAL, lprev.timestamp + 1201);
        assert!(legacy.submit_header_ex3(rh(h, &lfake), true, true, true).unwrap(), "legacy takes {i}");
        lprev = lfake;
        // Most-work: the cheapest legal fake is min-difficulty, +1201 s.
        let fake = mine(&prev.hash_display, 0xdead_1000 + i, EASY, prev.timestamp + 1201);
        if fresh.submit_btc_header_most_work(rh(h, &fake), Some(now), RT).is_ok() {
            accepted_new += 1;
            prev = fake;
        }
    }
    assert_eq!(legacy.tip_height, 1021, "legacy: 10 fake headers deep");
    assert_eq!(accepted_new, 5, "most-work: only 5 fit in the 2h window");
    assert!(accepted_new < r0.min_confirmations as usize);
}

/// A cheap side branch never displaces a heavier main chain.
#[test]
fn low_work_branch_never_wins() {
    let (mut r, v) = chain(12);
    let tip_hash = r.tip_hash.clone();
    let now = tip_time(&v) as u64 + 7200;
    // Fork at 1006 with min-difficulty headers (+1201 s each).
    let mut prev = v[6].clone();
    for i in 0..5u32 {
        let p = mine(&prev.hash_display, 0xbeef_0000 + i, EASY, prev.timestamp + 1201);
        let res = r.submit_btc_header_most_work(rh(1007 + i as u64, &p), Some(now), RT);
        assert_eq!(res, Ok(false), "{i}");
        prev = p;
    }
    assert_eq!(r.tip_hash, tip_hash);
}

#[test]
fn side_store_is_bounded_and_pruned_by_depth() {
    let (mut r, v) = chain(12);
    let now = tip_time(&v) as u64 + 7200;
    // Sibling of 1011 (side), then advance the main tip past BTC_SIDE_DEPTH.
    let sib = mine(&v[10].hash_display, 0x5151, REAL, v[11].timestamp + 1);
    assert_eq!(r.submit_btc_header_most_work(rh(1011, &sib), Some(now), RT), Ok(false));
    assert_eq!(r.btc_side.len(), 1);
    let mut prev = v[11].clone();
    for i in 0..BTC_SIDE_DEPTH as u32 {
        let t = prev.timestamp + 600;
        let p = mine(&prev.hash_display, 0x7000_0000 + i, REAL, t);
        assert!(r.submit_btc_header_most_work(rh(1012 + i as u64, &p), Some(t as u64), RT).unwrap());
        prev = p;
    }
    assert!(r.btc_side.is_empty(), "side header pruned below depth");
    // And a new side header that deep is refused.
    let e = r.submit_btc_header_most_work(rh(1011, &mine(&v[10].hash_display, 0x5252, REAL, v[11].timestamp + 2)), Some(now + 1_000_000), RT).unwrap_err();
    assert!(e.contains("below tip") || e.contains("parent mismatch"), "{e}");
}

#[test]
fn activation_height_is_930000_on_2300() {
    assert_eq!(crate::params_v2::TESTNET_2300_BTC4_MOST_WORK_HEIGHT, 930_000);
    assert_eq!(crate::params_v2::btc4_most_work_from_height(crate::NETWORK_ID_PUBLIC_TESTNET_2300), 930_000);
    // Armed after every height already on the live chain (tip 913,917 on 19 Nov 2026).
    assert!(crate::params_v2::TESTNET_2300_BTC4_MOST_WORK_HEIGHT > 913_917);
}

/// Before the UTC header is armed there is no consensus UTC, so block apply
/// skips the future limit (FPL `sealed_at` counts from genesis, not UTC);
/// mempool admission still applies it against the seat's wall clock.
#[test]
fn future_limit_needs_a_utc_clock() {
    let (r0, v) = chain(12);
    let tip = v.last().unwrap();
    let far = mine(&tip.hash_display, 0xfa7, EASY, tip.timestamp + 100_000);
    let mut apply = r0.clone();
    assert!(apply.submit_btc_header_most_work(rh(1012, &far), None, RT).unwrap());
    let mut admit = r0.clone();
    let e = admit.submit_btc_header_most_work(rh(1012, &far), Some(tip.timestamp as u64), RT).unwrap_err();
    assert!(e.contains("time-too-new"), "{e}");
}

fn ledger_node() -> crate::Node {
    let mut k = crate::KeyRing::new(crate::CryptoScheme::HmacDev);
    k.generate_many(["v1", "w"]);
    let mut n = crate::Node::new("v1", crate::ChainConfig::default(), k, &[("w".into(), 1_000_000)]);
    n.rewards_v2_from_height = 0; // strict rail rules (live since 2.9.62)
    n.btc4_fork_fix_from_height = 0;
    n.btc4_fork_slot_from_height = 0;
    n.bridge.rails.insert(RAIL_BTC4.into(), RailState::new(RAIL_BTC4));
    n
}

/// Ledger wiring: closed gate = 2.11.4 path; apply uses parent `sealed_utc_ms`
/// (0 while unarmed → no consensus future check); admission uses wall clock.
#[test]
fn ledger_gate_and_clocks() {
    let mut n = ledger_node();
    assert_eq!(crate::params_v2::btc4_most_work_from_height(n.cfg.network_id), u64::MAX);
    n.btc4_most_work_from_height = u64::MAX;
    assert!(n.btc4_most_work_apply().is_none() && n.btc4_most_work_admit().is_none());
    n.btc4_most_work_from_height = 0;
    assert_eq!(n.btc4_most_work_apply(), Some(MostWork { utc_now_secs: None }));
    let admit = n.btc4_most_work_admit().unwrap().utc_now_secs.unwrap();
    assert!(admit > 1_700_000_000, "wall clock seconds: {admit}");
}

/// End to end through `Node::submit_rail_header`: the stall builds with the
/// gate closed, and opening the gate clears it with the next two headers.
#[test]
fn ledger_stall_161859_clears_when_gate_opens() {
    let f = fx();
    let mut n = ledger_node();
    n.btc4_most_work_from_height = u64::MAX;
    for h in 161_831..=161_856 {
        n.submit_rail_header(RAIL_BTC4, f.canon(h), Some("w")).unwrap();
    }
    for p in ["00000000004ff223", "000000000004dea5", "00000000006c7ed7", "00000000013101c1", "000000003fcb0e7f", "000000001e9f85ba"] {
        n.submit_rail_header(RAIL_BTC4, f.get(p), Some("w")).unwrap();
    }
    let e = n.submit_rail_header(RAIL_BTC4, f.get("00000000d7e70d00"), Some("w")).unwrap_err();
    assert!(e.contains("parent mismatch"), "{e}");
    n.btc4_most_work_from_height = 0;
    n.submit_rail_header(RAIL_BTC4, f.get("00000000d7e70d00"), Some("w")).unwrap();
    n.submit_rail_header(RAIL_BTC4, f.canon(161_860), Some("w")).unwrap();
    let r = n.bridge.rail(RAIL_BTC4).unwrap();
    assert_eq!(r.tip_height, 161_860);
    assert_eq!(r.headers[&161_859].raw, f.canonical[&161_859]);
}
