# Falcon PL 2.11.4 — stall prevention (12 Nov 2026, h=869559)

No consensus-rule, wire, state-root or activation change. Seats on 2.11.3 and
2.11.4 interoperate; this is a node + installer fix release.

## Incident (15:13–15:36 GMT, ~22 min at h=869559)

1. Dual proposal at 869557 (scottspersonalnode `b4b6554a…`, canonical; v10
   `9b1d9b69…` after a round-1 view change). v13 entered a `DualProposal`
   stall and stayed at 869556 (same canonical tip, not a fork).
2. Catch-up trap: v13 was 3 behind, so it did not vote view-change. After 3
   empty residuals the small-hole rule (`residual_hole_needs_snapshot`, lag <
   `SNAPSHOT_SERVE_STALE_LAG`) set `wants_snapshot()`, `take_catchup_pull`
   returned `None`, and only NeedSnapshot was sent; every one was dropped
   (`no archive or hub catch lane`). A clean restart of v13 pulled the 3
   ledgers from archive v1 in seconds.
3. 869560 never reached a soft QC without v13. `falcon-node autoupgrade`
   (hourly timer) found no new release, waited 120 s for the tip to move,
   saw it flat, "rolled back" to the same 2.11.3 and restarted v3 and v12.
   Restarted seats came back on `height_view_round = 0` and voted round 1;
   the seats that had applied the round-1 QC voted round 2. 3 + 2 < 4.

## Fixes

| | Where | Change |
|---|---|---|
| A | `scripts/install-falcon-node.sh` `cmd_autoupgrade run`, `autoupgrade_health_check`, new `autoupgrade_bins_changed`, `autoupgrade_recover`, `autoupgrade_stall_probe` | A run that replaced no binary never waits on the tip, never rolls back and never restarts a running node. Health check returns 2 for "service active + RPC answering + tip flat" (chain stall): keep the binary, no rollback, no restart. Rollback only when a binary was actually replaced **and** the service is down or the RPC never answers. A failed download/upgrade step with unchanged binaries only (re)starts a node that is actually down. Before an upgrade restarts anything, a 90 s probe (`FALCON_AUTOUPGRADE_STALL_PROBE_SECS`, 0 = off) defers the run when both our tip and the best peer tip are flat (network stall); a seat that is merely lagging still upgrades. |
| B | `lib.rs` `small_lag_residual_allowed`, `snapshot_blocks_residual`, `take_catchup_pull`; `falcon_pl_node.rs` Hello/Pong pull gates | At 0 < lag < `SNAPSHOT_SERVE_STALE_LAG` (32), on a non-fork-poisoned chain with tip > 0 and no operator hard-resync, NeedLedgers keeps running even when the small-hole rule wants a snapshot (the rate-limited NeedSnapshot still goes out as the hole fallback). `SNAPSHOT_PULL_LAG`, `SNAPSHOT_JOIN_LAG`, the no-archive hub fallback, fork poison and the in-progress snapshot pull keep the exclusive snapshot lane. |
| D (part 1) | `consensus_rounds.rs` `restore_open_round_from_own_votes`; called once at start-up after the own-vote journal merge | A same-height restart re-enters the highest round in which **this seat's own** signed OK at the open height is on disk (snapshot `round_votes` or `<snapshot>.own-votes.json`). A seat signs its own OK only in `own_ok_round = height_view_round`, so that vote proves the seat had entered the round via a ViewChange QC; re-entering it is the pre-restart state, not a jump. Peers' votes are never trusted for this; recert slot, legacy heights, other heights and backwards moves are ignored. Uses the existing `apply_round_advance` transition. |

C (DualProposal follow-through) is covered by B in the incident shape: the
stalled seat's certified canonical body arrives by residual catch-up and
commits (`dual_proposal_stalled_seat_commits_canonical_via_catchup`). No
live-path change was made.

## Not in this release (recommended design)

**D part 2 — adopt an already-applied round QC.** A seat that never applied
the round-r QC (falcon-node in the incident) still votes round r while the
rest vote r+1. `apply_round_advance` drops the VC votes for rounds ≤ r, so no
seat can re-gossip the QC. Design: keep the 4 signed VC votes that formed the
applied QC for the open height (`applied_round_qc: (height, round, voters →
sig)`), re-fan them with the seat's own VC vote, and let `vote_round_change`
accept a full signed QC for round r' > cur as a jump (signatures checked with
`accept_vote_sig`, committee frozen for the height). This only moves a seat
to a round 4-of-6 already entered, so it is the same rule as today's "jump on
QC" with the evidence made durable. Needs a wire field (backward-compatible
`#[serde(default)]`) and a multi-seat test; not shipped in a hotfix.

## Operator upgrade (external seats: nodesafe, crypto-dashboard, scottspersonalnode)

* Seats with autoupgrade on pick up the signed `v2.11.4` release on their next
  hourly timer run after it is published. That run still uses the installed
  2.11.3 `falcon-node`, whose health check expects the tip to move within
  120 s of the restart; on a moving chain that passes. Do not publish during
  a stall.
* Manual: `falcon-node upgrade` or `curl -fsSL https://falcon-fpl.com/install.sh | bash -s -- upgrade`
  (add `--home DIR` if not `/var/lib/falcon-pl-2300`). Check with
  `falcon-node status` (version 2.11.4) and `falcon-node autoupgrade status`.
* Upgrade one seat at a time with the chain moving; never restart several
  committee seats at once.
