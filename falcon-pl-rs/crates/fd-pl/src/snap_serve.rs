// Copyright (c) 2025-2026 BEARTEC. All rights reserved. See LICENSE.
//! Snapshot serve helpers: push budget under catch-up backpressure, and
//! separate stalled-source vs non-server skip lists (no shared wire_from).

use std::collections::HashMap;

/// Leave headroom on large catch-up reply lanes for Offer / SnapshotNo / hole-fill.
pub const SNAP_PUSH_RESERVE_SLOTS: usize = 32;
/// Conservative: 256 KiB chunk → ~512 KiB hex JSON, PIECE_THRESHOLD 64 KiB → ≥8 pieces; pad to 12.
pub const SNAP_EST_PIECES_PER_CHUNK: usize = 12;

/// How many SnapshotChunk messages to bulk-push after Offer given free lane slots.
///
/// Outbound catch lanes are only [`CATCH_QUEUE_CAP`]=32. A flat reserve of 32
/// made `usable==0` on every fresh session, so NeedSnapshot sent Offer with
/// zero chunks and joiners stalled. Reserve shrinks on small lanes so at least
/// one chunk can ship when the lane can hold its pieces.
pub fn snap_push_budget(free_slots: usize, max_push: u32) -> u32 {
    if max_push == 0 || free_slots == 0 {
        return 0;
    }
    let reserve = SNAP_PUSH_RESERVE_SLOTS.min(free_slots.saturating_sub(SNAP_EST_PIECES_PER_CHUNK));
    let usable = free_slots.saturating_sub(reserve);
    if usable < SNAP_EST_PIECES_PER_CHUNK {
        return u32::from(free_slots >= SNAP_EST_PIECES_PER_CHUNK);
    }
    let by_cap = usable / SNAP_EST_PIECES_PER_CHUNK;
    (by_cap as u32).min(max_push)
}

/// Expire both maps; return the union of ids still skipped.
pub fn snap_skip_ids(
    stalled: &mut HashMap<String, u64>,
    nonserve: &mut HashMap<String, u64>,
    now_ms: u64,
) -> Vec<String> {
    stalled.retain(|_, until| *until > now_ms);
    nonserve.retain(|_, until| *until > now_ms);
    let mut out: Vec<String> = stalled.keys().cloned().collect();
    for id in nonserve.keys() {
        if !out.iter().any(|x| x == id) {
            out.push(id.clone());
        }
    }
    out
}

/// All archives/hubs are slow: clear **only** non-server marks so rotation can
/// try other seats; **retain** stalled archive/hub cooldown (do not `clear()` stalled).
pub fn all_slow_forget_nonserve_only(
    stalled: &mut HashMap<String, u64>,
    nonserve: &mut HashMap<String, u64>,
    now_ms: u64,
) -> Vec<String> {
    stalled.retain(|_, until| *until > now_ms);
    nonserve.clear();
    stalled.keys().cloned().collect()
}

/// Backoff before a stalled source is asked again when it is the only one left.
pub const SNAP_ALL_STALLED_RETRY_MS: u64 = 30_000;

/// Every archive/hub is stalled or skipped and no other seat exists: clear
/// non-server marks and cap each stalled cooldown to `retry_ms` from now, so
/// a stashed download resumes from the stalled source after a bounded backoff
/// (instead of a 600 s freeze or an immediate hot retry).
pub fn all_slow_cap_stalled(
    stalled: &mut HashMap<String, u64>,
    nonserve: &mut HashMap<String, u64>,
    now_ms: u64,
    retry_ms: u64,
) -> Vec<String> {
    stalled.retain(|_, until| *until > now_ms);
    nonserve.clear();
    let cap = now_ms.saturating_add(retry_ms);
    for until in stalled.values_mut() {
        if *until > cap {
            *until = cap;
        }
    }
    stalled.keys().cloned().collect()
}

/// True if `id` is in the skip set.
pub fn is_snap_skipped(skip: &[String], id: &str) -> bool {
    !id.is_empty() && skip.iter().any(|s| s == id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_budget_small_outbound_lane_allows_one_chunk() {
        // CATCH_QUEUE_CAP=32: must not reserve the entire lane.
        assert_eq!(snap_push_budget(10, 48), 0); // cannot fit one chunk's pieces
        assert_eq!(snap_push_budget(12, 48), 1);
        assert_eq!(snap_push_budget(32, 48), 1);
        assert_eq!(snap_push_budget(44, 48), 1); // reserve shrinks; usable=12
        assert_eq!(snap_push_budget(32 + 12 * 48, 48), 48);
        assert_eq!(snap_push_budget(10_000, 48), 48);
    }

    #[test]
    fn all_slow_keeps_stalled_clears_nonserve() {
        let mut stalled = HashMap::new();
        stalled.insert("v1".into(), 9_999_999);
        let mut nonserve = HashMap::new();
        nonserve.insert("v6".into(), 9_999_999);
        nonserve.insert("v10".into(), 9_999_999);
        let skip = all_slow_forget_nonserve_only(&mut stalled, &mut nonserve, 1_000);
        assert!(nonserve.is_empty());
        assert_eq!(stalled.get("v1"), Some(&9_999_999));
        assert_eq!(skip, vec!["v1".to_string()]);
    }

    #[test]
    fn all_stalled_caps_cooldown_not_clear() {
        let mut stalled = HashMap::new();
        stalled.insert("v1".into(), 1_000 + 600_000);
        stalled.insert("v3".into(), 1_000 + 5_000);
        let mut nonserve = HashMap::new();
        nonserve.insert("v6".into(), 9_999_999);
        let mut skip = all_slow_cap_stalled(&mut stalled, &mut nonserve, 1_000, 30_000);
        skip.sort();
        assert_eq!(skip, vec!["v1".to_string(), "v3".to_string()]);
        assert!(nonserve.is_empty());
        assert_eq!(stalled["v1"], 31_000); // capped, still skipped now
        assert_eq!(stalled["v3"], 6_000); // shorter mark untouched
        // Repeated calls never extend; after the cap the source is eligible.
        let _ = all_slow_cap_stalled(&mut stalled, &mut nonserve, 20_000, 30_000);
        assert_eq!(stalled["v1"], 31_000);
        let skip = snap_skip_ids(&mut stalled, &mut nonserve, 31_001);
        assert!(!is_snap_skipped(&skip, "v1"));
    }

    #[test]
    fn snap_skip_union_expires() {
        let mut stalled = HashMap::new();
        stalled.insert("v1".into(), 50);
        let mut nonserve = HashMap::new();
        nonserve.insert("v6".into(), 200);
        let skip = snap_skip_ids(&mut stalled, &mut nonserve, 100);
        assert!(!is_snap_skipped(&skip, "v1")); // expired
        assert!(is_snap_skipped(&skip, "v6"));
    }
}
