# Falcon PL 2.11.18

Bandwidth and liveness release. No consensus rule, quorum, lottery, ledger hash, snapshot or activation-height change. Includes the 2.11.17 lagging-leader fast view-change (never released on its own).

## 1. Lagging-leader fast view-change (from 2.11.17)
`--lagging-leader-vc-ms` (default 400; `0` = pre-2.11.17 timing).

A committee seat votes the existing signed ViewChange for the open round early when the round proposer is another live (pong-fresh) seat whose latest tip ad, received after the round opened, is >= 2 behind our tip and the knob has elapsed (1 behind: ad arrived at least the knob into the round and 3x the knob elapsed). Not when this seat is lagging itself, already has the body, or is the leader. Same ViewChange payload, signature and QC threshold, so missed-turn accounting is unchanged; un-upgraded seats keep the old timing. Logs `view-change vote ... fast=true|false`; startup `lagging-leader view-change: N ms`.

## 2. Compact block relay
`--compact-body-relay` (default **off**).

When on, the leader sends an eligible sealed lean body (non-empty, lean batch form) to the body lane as `LedgerBodyById` (header + tx ids) instead of the full `LedgerBody`. Receivers rebuild the body byte-identically from their mempool (lean signature form, public key elided when it matches the account key), pull any missing ids with `NeedTxsByIds`, and fall back to the full-body pull (`NeedLedgerBody`, ~800 ms) if the ids cannot be filled. A 400-tx lean block shrinks from ~470 KB to ~32 KB (14.8x).

Per-peer negotiation: every 2.11.18 node advertises Hello capability `compact-body-v1` (receive support is always on). The leader sends the compact shell only to seats whose latest Hello advertised it; every other seat gets the full body, so mixed fleets are safe even with the flag on.

Counters (log line `compact-relay on= peers= stats={...}` every few seconds, and `compact_relay` in `falcon.health.v1`):
- `sent_compact` / `sent_full`: per-seat body sends as compact shell / full body while the flag is on;
- `rebuilt`: compact bodies rebuilt locally (direct or after id pull);
- `pulled`: compact bodies that needed an id pull;
- `fallback`: id pulls that could not complete the body (full-body pull follows).

Rollback: restart without `--compact-body-relay` (or `--lagging-leader-vc-ms 0`), or reinstall 2.11.16.

## Tests
`lagging_leader_vc_tests.rs` (8 + ignored bench), `compact_relay_tests.rs` (byte-identical rebuild pre-lean and lean, eligibility, id-pull fill, fallback, capability advertised/detected). Design: `docs/COMPACT_RELAY_DESIGN.md`.
