# Falcon PL 2.11.13: next-block pre-pack, timing defaults, lock and timer fixes, bridge-state slimming, gated committee redraw (testnet 2300)

> **Release build: activation height 945474 on testnet 2300** (redraw and bridge slim together; set at tip 944994 + 480). Every seat must run 2.11.13 before block 945474.

**Rolling-upgrade compatible with 2.11.12 while the activation is off.** The
PR ships one activation height as a placeholder (`u64::MAX` = never) for two
consensus changes: the committee redraw (f) and the bridge-state slim (D+E,
`TESTNET_2300_BRIDGE_SLIM_FROM_HEIGHT = TESTNET_2300_REDRAW_FROM_HEIGHT`).
The release build must set it (see "Release-build step" below). From that
height it is a **consensus change**: every seat must run 2.11.13 with the same
constant before it, or the network forks at that height.

Nothing else changes consensus, the block format, signatures, the 4-of-6
commit QC or the round-0 lottery. Before activation the state bytes, state
root and snapshot files are byte-identical to 2.11.12.

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

### Bridge-state slimming

**A. Copy-on-write rail header maps (local).** `RailState.headers` is a
`CachedMap` (Arc + generation counter + cached JSON), like the ETH exec map.
Cloning the bridge (every pack draft, every mempool-head dry run in
`sanitize_mempool`, every status call) is now a refcount bump instead of a
deep copy of ~120 MB of JSON-shaped data. Serialized bytes are unchanged.

**B. Cached map encodings in the state root (local).** The split root hasher
splices every embedded `CachedMap`'s cached JSON (rail maps and the exec map)
and memoizes the result by (segment hash, generations). The root bytes and
value are unchanged; only unchanged maps are no longer re-encoded.

**C. Visibility and snapshot interval (local/config).**
* Per-phase pack timers: status `pack_phases` {height, txs, sanitize_us,
  clone_us, hook_us, apply_us, root_us, accept_height, stage_us,
  stage_root_us} and `root_stats` {full_hashes, memo_hits}.
* An info log per sealed block: `pack-phases h= txs= pack_ms= sanitize_ms=
  clone_ms= hook_ms= apply_ms= root_ms= merkle_ms= accept_ms= stage_ms=
  stage_root_ms= root_full= root_hits=`.
* `--snapshot-interval-ms` default 300000 (5 min), and
  `SNAPSHOT_INTERVAL_MS=300000` in `scripts/network-2300.env`.

**D. Prune the frozen legacy BTC rail (CONSENSUS, gated).** At activation the
legacy `btc` rail keeps its newest 4,032 headers (~4 weeks) plus every
pinned height (vault UTXO heights, checkpoint, tip). All BTC rails then get a
hard header cap of 32,768 (`header_cap`, serialized only when set), on top of
the existing time-based prune. Audit of the live v13 snapshot: no open claim,
withdrawal or vault item references a header height below the kept window
(see "Open bridge items" below).

**E. Compact ETH exec headers (CONSENSUS, gated).** At activation every
stored exec header drops its RLP and keeps hash, parent hash, number,
receipts root and the timestamp decoded from the RLP. After activation new
headers are fully RLP-verified on insert, then compacted. Ancestry for
receipt proofs uses the stored links on compact headers (they were verified
on insert); the head timestamp comes from the stored field. The conversion is
one deterministic pass, run once (`bridge_slim` flag) in the ledger hook at
the activation height. A submitted `timestamp` field is zeroed, not
rejected, so old and new parsers agree before activation.

**zstd snapshot files (local, follows activation).** After activation the
snapshot file and the `join.serve` copy are written zstd level 3 (magic
`28 b5 2f fd`). The loader and the join header peek accept both plain and
zstd, so old plain snapshots still load. `FPL_SNAPSHOT_ZSTD=0|1` overrides.
The state hash is computed over the same JSON bytes as before; compression
only wraps the file. Old binaries cannot read a zstd file, and scripts that
`jq` the snapshot need `zstd -dc` first.

**Bounded memory (growth simulation, `slim_tests`).**
| map | steady state | JSON |
|---|---|---|
| ETH exec, compact, 7-day window | 50,401 headers | 14.7 MB |
| BTC4 at sprint rate, capped | 32,768 headers | 14.1 MB |
| BTC4 at 10-min blocks (14-day retention) | 16,384 headers | 7.0 MB |
| legacy BTC after activation | 4,032 + pins, frozen | ~1.7 MB (est.) |

Before slim the BTC hard cap was 500,000 headers and ETH headers carried
their RLP (the live bridge was 120.8 MB JSON; after conversion 20.3 MB).

### Fixes found while verifying 2.11.13 (local)
* **Restart catch-up stall.** A seat restarted from its snapshot could sit
  on its old tip forever while the network moved on (also on 2.11.12).
  Cause: lower seat ids dial higher ones, so a seat yields its own dial to
  every lower-id peer and talks to them over their inbound sessions. The
  catch-up router still picked the outbound lane for those peers; that lane
  is parked for `YIELD_DIAL_SECS` (60 s) and never drained, so every
  `NeedLedgers` went into a dead queue. A top-id seat (every peer dials it)
  never got a single ledger. Fix: when a peer has a live inbound session,
  the pull goes on that session (`NeedLedgers → inbound <id> (our dial
  yielded)` in the log). Test: `catchup_pull_goes_to_live_inbound_when_our_dial_yielded`.
* **Debug-build v4-freeze check.** `load_snapshot` freezes the open height
  before the node applies `keys/lc/bridge.json`, so the check compared a v7
  draw with the sealed v8 next-6 and panicked (debug builds only) on any
  snapshot with more than 6 bonded seats, such as the live v13 one. Release
  always used the sealed set (verified on accept), so consensus was never
  affected. The check now runs only once the node draws in v8 mode. Test:
  `redraw_tests::ten_seat_v4_snapshot_loads_with_sealed_next_committee`.
* **Flaky UTC test.** `utc_rehearsal_tests` set
  `FPL_UTC_HELLO_ENFORCE_FROM_HEIGHT` process-wide while a sibling test read
  it. The tests that set or read it now share a lock that also clears it.

* **Silent pack deferral.** A tx that failed with a non-permanent error stayed
  in the mempool and was skipped at every pack with nothing in the log. The
  pack now logs `falcon-pl pack defer <tx> seq <n> <account>: <reason>` once
  per tx. This is how the rehearsal peg-out stall below was found.

### Found, not fixed
* **Joiner whose id sorts above every seat.** If no seat lists it in
  `--peers`, every seat refuses its inbound ("we dial them") while it yields
  its own dials, so it never connects. This comes from the two-sided dial
  rule (`lower id dials`), and changing it needs its own review. The live
  joiners (nodesafe, scottspersonalnode) sort below `v*`, so they are not
  affected.
* **BTC peg-outs need `keys/bitvm-abort-seed` on every seat.** This is by
  design (`falcon-pl-ctl bitvm-abort-seed`, same seed on every seat). Without
  it the withdraw stays in the mempool, and is now logged as a pack defer.

### Activation rehearsal (6 seats, loopback, slim at h60, 30 tx/s, BTC fixture)
* All 6 seats converted at h63: `bridge_slim:true`, same tip and root, 0
  mismatches. Blocks continued.
* Mints worked before and after activation (200,000 sats, 2 UTXOs). A
  double mint was refused ("deposit already spent").
* After activation, a peg-out of 50,000 was packed: burned 50,000,
  withdrawals 1, faucet 150,000.
* v6 was killed, restarted 30 s later from its zstd snapshot, and caught up
  in under 30 s via `NeedLedgers → inbound v1 (our dial yielded)`.
* A fresh joiner adopted a zstd snapshot from v1 (tip 139, 5.2 MB, 20
  chunks, 0.25 s). It then had the same tip and root as v1 and v6.
* pack-phases (loopback): 98 txs, pack_ms 10, sanitize 2, apply 1, accept
  12.

## Release-build step (required): set the redraw height
`falcon-pl-rs/crates/fd-pl/src/params_v2.rs`:

```rust
pub const TESTNET_2300_REDRAW_FROM_HEIGHT: u64 = u64::MAX; // placeholder
```

At release-build time:
1. Read the 2300 tip: `falcon-pl-ctl --addr <seat> status` -> `tip_height`.
2. Set the constant to **tip + 400** (about 1 h at 9-10 s blocks), so every
   seat has upgraded before it activates.
   The bridge slim follows automatically
   (`TESTNET_2300_BRIDGE_SLIM_FROM_HEIGHT = TESTNET_2300_REDRAW_FROM_HEIGHT`).
   To ship the redraw without the slim (or the reverse), give the slim
   constant its own value; it is independent in code.
3. Rebuild and run `cargo test -p fd-pl --lib redraw_ slim`. The
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
5. Watch the `pack-phases` log lines and status `pack_phases` / `root_stats`.
   Snapshots are now written every 5 min (`SNAPSHOT_INTERVAL_MS=300000`).
6. At the activation height every seat's status shows `bridge_slim: true`
   with the same `state_root`. The one-off conversion costs ~0.3 s on brain
   (estimated 0.6-1.5 s on v10). The next snapshot is a zstd file.
7. Any script that reads snapshot files must handle zstd (`zstd -dc`).
   Do not roll back to 2.11.12 after activation: it cannot read the files
   or follow the chain.

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
* Bridge slim: `exec_map::tests::*` (generic CachedMap, two embedded maps
  splice), `bridge::slim_tests::*` (pre-activation bytes unchanged, legacy
  keeps newest 4032 + vault pins, BTC4 sprint capped at 32,768, ETH compact
  window bounded), `eth_v3_deposit_tests::slim_conversion_is_deterministic_idempotent_and_keeps_links`,
  `v3_mint_and_refund_verify_the_same_after_conversion`,
  `inserts_after_conversion_are_verified_then_compacted`,
  `replay_across_slim_activation_agrees` (byte-identical before, same root
  after, mint after, a node restored from a pre-activation snapshot replays
  to the same root), `bridge_slim_tests::legacy_btc_pegout_and_double_mint_guard_after_slim`,
  `bridge_slim_tests::real_snapshot_converts_deterministically` (ignored;
  `FPL_SLIM_SNAPSHOT=<file>`; run on the live v13 snapshot: 120,811,585 ->
  20,317,472 B, legacy BTC 79,327 -> 4,035 headers, sha c802eafa4e1bdde2...,
  same in every run)
* zstd: `snapshot_zstd_tests::zstd_only_after_slim_and_both_forms_load_to_the_same_state`
* C: `timing_default_tests` asserts the snapshot interval CLI default equals
  the profile.
* Bench: `cargo run --release --example slim_bench -- <snapshot>`.

## Measured on beartec-brain under v10 limits (2 CPU, 3.8 GB, swap)
Real v13 state. "before" = 2.11.13 without the slim, "after" = activated.
| | before | after |
|---|---|---|
| bridge JSON | 120.8 MB | 20.3 MB |
| state root, fresh / after small change | 130-140 / 95-105 ms | 27-33 / 12 ms |
| bridge clone x10 | 305-323 ms | 3-4 ms |
| pack 28 txs | 1.02-1.10 s | 36-39 ms |
| pack 200 txs | 2.13-2.30 s | 50-55 ms |
| accept | 185-208 ms | 5-23 ms |
| process peak RSS | 513-526 MB | 323-331 MB |
| snapshot file (seat) | 123 MB, write 101 ms | 7.3 MB zstd, write 70 ms |
| snapshot file (full v13) | 139.8 MB, write 120 ms | 17.4 MB zstd, write 139 ms |

Brain cores are about 2-5x faster than v10's; v10 figures scale by that
(estimate, not measured on v10).

## Open bridge items (live v13 snapshot, read-only)
* Legacy withdrawals: 06420da2e61ceb95 (10,000, refunded), 8016366c35285587
  (5,000, refunded), bac114a2e2edc941 (50,000, BitVM claim final, CSV 6,
  open height 132148, has a signed vault tx).
* 3 vault UTXOs pinned at BTC heights 5127316 / 5127613 / 5127675
  (100,000 / 180,385 / 88,985 sats), kept by the prune.
* 1 claim leaf, 10 spent deposits; minted 1,088,370, burned 50,000.
* None references a header below the kept window. A deposit to the legacy
  vault in a pruned block that was never minted would need
  `backfill_btc_headers` before it can be proven.
