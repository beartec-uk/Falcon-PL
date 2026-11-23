# Falcon PL 2.11.13: next-block pre-pack, timing defaults, lock and timer fixes, gated committee redraw (testnet 2300)

**Rolling-upgrade compatible with 2.11.12 while the redraw is off.** The PR
ships the redraw activation as a placeholder (`u64::MAX` = never). The release
build must set it (see "Release-build step" below). From that height it is a
**consensus change**: every seat must run 2.11.13 with the same constant
before it, or the network forks at that height.

Nothing else changes consensus, the block format, signatures, the 4-of-6
commit QC or the round-0 lottery.

## What changed

### Pre-pack of N+1 during N's vote window (local)
While height N waits for votes, every seat walks the full N+1 candidate set.
The walk continues each account from N's last sequence through consecutive
pool sequences, up to the pack cap. The seat checks those signatures in
parallel, off `node.lock`, and tags each result with the on-chain key it was
checked against. The pack reuses a check only while that key is unchanged.
It still applies every tx against the real post-commit state, so a different
N, a rival block or a rotated key just falls back to a fresh check. With no
block pending, the same walk runs for the open height, so a builder that is
holding, pacing or waiting out `min_block_interval` has its signatures
checked before it packs. The seal loop also wakes on tip advance instead of
waiting up to one seal tick.
Status fields: `prepack_txs`, `prepack_runs`, `prepack_warm_used`.

### (a) Thin-walk hold cap (local)
`thin_walk_hold_ms` is now at most half of the round-0 silence timeout that
peers apply to a live builder (`2 x (pack budget + 2.3 s)`). Pre-pack
NeedTxs pulls, the NeedTxs grace and pacing all stop once that much time has
passed since the height or round opened. Hold + pack budget + slack therefore
always fit inside round 0. Before, hold was `progress - 2000` (7 s at 9000),
which could overrun.

### (b) Seat timing defaults = the live values (config)
| flag | 2.11.12 default | 2.11.13 default |
|---|---|---|
| `--pack-budget-ms` | 1000 | **5000** |
| `--progress-timeout-ms` | 2500 | **4000** |
| `--max-txs` | 0 (no cap) | **200** |

`scripts/network-2300.env` (reinstalled by `falcon-node upgrade` on
installer seats) carries the same values: `PACK_BUDGET_MS=5000`,
`PROGRESS_TIMEOUT_MS=4000`, `MAX_TXS=200`. Adopted seats with explicit
`node.args` flags keep their own flags; drop them after the upgrade if they
equal these defaults.

Why max-txs 200: the pack holds `node.lock` for the whole pack. Measured live
on 23 Nov: 11-16 s for 250-336 txs on 2 vCPU, 8.4 s for 307 on v1, about 5 s
for 300-400 on v13. Round 0 times out at 14.6 s. Raise the cap only once
2-vCPU builders seal 200+ txs well under that.

### (c) Tokio worker floor of 4 (local)
The runtime gets `max(cpus, 4)` workers. `TOKIO_WORKER_THREADS` still wins
when it is a valid positive number. A 2-vCPU seat used to get 2 workers, so
one long lock holder could freeze it.

### (d) Snapshot timer skips missed runs (local)
`MissedTickBehavior::Skip`: after a stall the snapshot loop runs once instead
of once per missed tick.

### (e) Snapshot capture without one long lock hold (local)
The saver takes the snapshot head (state, tip, keys) under the lock. It then
copies the chain tail in 256-ledger chunks under short locks. The tail must
be contiguous, hash-linked and end at the head's tip hash. If not, the saver
falls back to the old one-lock capture. The snapshot format is unchanged.

### (f) Committee redraw after a full failed rotation (CONSENSUS, gated)
This only applies from `TESTNET_2300_REDRAW_FROM_HEIGHT`
(`params_v2.rs`). Devnets use `FPL_REDRAW_FROM_HEIGHT`; tests set
`Node::redraw_from_height`.

1. A height whose base committee produced nothing for 6 proposal timeouts
   (6 x 16 s = 96 s at progress 4000) lets any bonded seat that has **not**
   signed an OK at that height vote ViewChange to round 6.
2. Entering round 6 needs a bonded-set quorum: 2/3 + 1 of bonded seats
   (7 of 10), not 4 of the stalled committee.
3. From round 6 the committee is redrawn deterministically from the tip.
   Seats outside the base committee come first, each ordered by
   `sha256(seed|id)`. It is reseeded every `committee_size` rounds.
4. Commit still needs 4 of that committee's signatures. Catch-up accepts a
   redraw committee from a bounded round search (`REDRAW_SEARCH_ROUNDS` = 48).

**Limits and risks (read before arming):**
* Safety relies on honest seats. A seat that OK'd at the height never votes
  the redraw, so 7 + 4 > 10 rules out a base-round commit and a redraw entry
  at the same height. A Byzantine double-voter breaks this.
* The cert does not carry the redraw-entry QC, so a node that catches up
  cannot prove the redraw was entered. It only sees 4 valid signatures from
  a valid redraw committee. Carrying the entry QC in the cert is a format
  change and is not done here.
* A redraw block's `current_committee` differs from the parent's
  `next_committee`. Bridge QC attestations and light clients that assume
  `current == parent.next` must accept redraw blocks first.
* Liveness: if fewer than 7 bonded seats are alive (for example 4 frozen),
  the redraw cannot be entered. If live base seats already OK'd a proposal,
  they cannot vote it, and the redraw can also fall short of 7.

## Release-build step (required): set the redraw height
`falcon-pl-rs/crates/fd-pl/src/params_v2.rs`:

```rust
pub const TESTNET_2300_REDRAW_FROM_HEIGHT: u64 = u64::MAX; // placeholder
```

At release-build time:
1. Read the 2300 tip: `falcon-pl-ctl --addr <seat> status` -> `tip_height`.
2. Set the constant to **tip + 400** (about 1 h at 9-10 s blocks), so every
   seat has upgraded before it activates.
3. Rebuild and run `cargo test -p fd-pl --lib redraw_`. The
   `placeholder_keeps_redraw_off_on_2300` test asserts `u64::MAX`. Update it
   to the chosen value in the same commit.
4. Roll every seat before the height. Before each restart, check
   `tip < height`. If the roll cannot finish in time, rebuild with a later
   height. **Never** let some seats pass the height on an older value.

**Conflict to decide:** the earlier rule was to recheck before release that
the activation is at least 24 h ahead of the tip. "tip + 400" is about 1 h,
which fails that recheck. Pick one before the build: keep ~1 h and accept
the tight roll window, or use about tip + 9000 (24 h). Leaving it at
`u64::MAX` ships 2.11.13 with the redraw off.

## Runbook (rollout)
1. Build with the redraw height set (above) and record it in the release
   notes and the release commit.
2. Roll one host at a time as usual (`falcon-node upgrade`). Installer
   seats get the new `network-2300.env`. On adopted seats, remove the
   now-default `--pack-budget-ms 5000 --progress-timeout-ms 4000 --max-txs 200`
   flags from `node.args` in the same restart, or leave them; they are
   equal to the defaults.
3. Confirm every seat reports `product_version` 2.11.13 well before the
   redraw height.
4. Watch `prepack_warm_used` and the walk/hold logs. Expect a block span
   of about one pack budget plus vote time.

## Tests
* Pre-pack: `prepack_walk_continues_past_pending_block_and_next_pack_reuses_it`,
  `prepack_warm_entry_needs_the_same_key`, `prepack_refreshes_only_when_pool_grows`,
  `prepack_off_lock_result_is_dropped_when_the_pending_block_changes`,
  `prepack_plan_verify_apply_matches_the_locked_pass`, `off_lock_key_ring_carries_no_secrets`
* (a) `hold_cap_tests::*`
* (b) `timing_default_tests::*` (CLI defaults, network-2300.env, round-0 fit)
* (c) `tokio_worker_tests::*`
* (d) `snapshot_timer_tests::missed_snapshot_ticks_are_skipped_not_burst`
* (e) `snapshot_chunk_tests::*`
* (f) `redraw_tests::*`: placeholder off, deterministic redraw, dead
  committee recovers and catch-up verifies, OK'd seats excluded, 4 dead
  cannot reach quorum, no base-round OK after the redraw vote
