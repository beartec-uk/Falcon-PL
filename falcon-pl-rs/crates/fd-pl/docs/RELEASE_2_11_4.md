# Falcon PL 2.11.4: stall prevention + BTC4 claim-tree capacity + round-split recovery

Combined release (PR #39 + PR #46, 15 Nov 2026; round-split recovery added
16 Nov 2026 after the h=891419 stall).

* **Stall prevention (PR #39, 12 Nov 2026, h=869559):** no consensus-rule,
  wire, state-root or activation change.
* **BTC4 claim tree full (PR #46, 14 Nov 2026):** Fix A (refuse a burn into a
  full tree, before debit and at submit) is not a consensus change. Fix B
  (prune settled leaves; Disprove against the attest-time root) is a
  consensus change **gated by `TESTNET_2300_BITVM2_LEAF_PRUNE_FROM_HEIGHT`**,
  which ships as `u64::MAX` (never) until Scott picks a height. Until then
  state is byte-identical to 2.11.3, so 2.11.3 and 2.11.4 seats interoperate.
  Setting the height later needs every seat on a release that has it.
* **Round-split recovery (16 Nov 2026, h=891419):** node-local liveness
  only. No payload, cert, wire, state-root or activation change.

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
| A | `scripts/install-falcon-node.sh` `cmd_autoupgrade run`, `autoupgrade_health_check`, new `autoupgrade_bins_changed`, `autoupgrade_recover`, `autoupgrade_stall_probe` | A run that replaced no binary never waits on the tip, never rolls back and never restarts a running node. Health check returns 2 for "service active + RPC answering + tip flat" (chain stall): keep the binary, no rollback, no restart. Rollback only when a binary was actually replaced **and** the service is down or the RPC never answers. A failed download/upgrade step with unchanged binaries only (re)starts a node that is actually down. Before an upgrade restarts anything, a 90 s probe (`FALCON_AUTOUPGRADE_STALL_PROBE_SECS`, 0 = off) defers the run when both our tip and the best peer tip are flat **and** the node reports pending work (`liveness.has_work=true`; an idle load-driven chain is flat too and is never deferred); a seat that is merely lagging still upgrades. The stall verdict (rc 2) holds if the RPC answered at least once in the window. |
| B | `lib.rs` `small_lag_residual_allowed`, `snapshot_blocks_residual`, `peer_snapshot_adoptable`, `take_catchup_pull`; `falcon_pl_node.rs` Hello/Pong pull gates, LedgersBatch continuation, snapshot adopt | At 0 < lag < `SNAPSHOT_SERVE_STALE_LAG` (32), on a non-fork-poisoned chain with tip > 0 and no operator hard-resync, NeedLedgers keeps running even when the small-hole rule wants a snapshot (the rate-limited NeedSnapshot still goes out as the hole fallback). `SNAPSHOT_PULL_LAG`, `SNAPSHOT_JOIN_LAG`, the no-archive hub fallback, fork poison and the in-progress snapshot pull keep the exclusive snapshot lane (the LedgersBatch continuation no longer chains NeedLedgers onto an active snapshot download). A downloaded snapshot that residual catch-up overtook is discarded instead of adopted (no rewind); fork heal / operator hard-resync still adopt. |
| D (part 1) | `consensus_rounds.rs` `restore_open_round_from_own_votes`; called once at start-up after the own-vote journal merge | A same-height restart re-enters the highest round in which **this seat's own** signed OK at the open height is on disk (snapshot `round_votes` or `<snapshot>.own-votes.json`). A seat signs its own OK only in `own_ok_round = height_view_round`, so that vote proves the seat had entered the round via a ViewChange QC; re-entering it is the pre-restart state, not a jump. Peers' votes are never trusted for this; recert slot, legacy heights, other heights and backwards moves are ignored. Uses the existing `apply_round_advance` transition. |

C (DualProposal follow-through) is covered by B in the incident shape: the
stalled seat's certified canonical body arrives by residual catch-up and
commits (`dual_proposal_stalled_seat_commits_canonical_via_catchup`). No
live-path change was made.

## BTC4 BitVM2 claim tree capacity (PR #46)

The BTC4 claim tree is fixed at 16 leaves (MERKLE_DEPTH=4). When it filled
(14 Nov 2026, 13:56 GMT, h 886583), later burns were "accepted" but never
packed. Details, tests and the snapshot replay are in PR #46.

| | Where | Change |
|---|---|---|
| A | `bridge.rs` `bitvm2_claim_tree_check`, `bridge_operators.rs` `btc4_withdraw`, `lib.rs` submit | A burn into a full tree fails with `bitvm2 claim tree full (n/16) on BTC4`, before any debit and at submit. Tree-full is a permanent packer failure only while no prune height is scheduled; once it is scheduled, queued burns wait for a free leaf. |
| B | `bridge.rs` `prune_settled_bitvm2_leaves`, `disprove_bitvm2_v2_ex`; `bridge_operators.rs` `bridge_finalize_rail`; `fd-pl-bitvm2` `verify_stored_withdraw_attest_vk_bytes` | From the prune height (also needs M1): settled claims' leaves (PaidOptimistic/Refunded/Disproved) are pruned every ledger; in-window claims keep their leaf until the 21,600-ledger window closes. Disprove checks the stored proof against its attest-time root, so honest claims stay valid after appends/prunes. |

Activation: `TESTNET_2300_BITVM2_LEAF_PRUNE_FROM_HEIGHT = u64::MAX`
(placeholder). It must be ≥ the M1 height (692,000) and far enough out for all
seats to upgrade first.

## Round-split recovery (stall at h=891419, 15 Nov 07:07 GMT → 16 Nov 02:41 GMT)

Committee for 891420: v10, v12, crypto-dashboard, v6, v1, scottspersonalnode
(4 of 6). v10 was lagging; its catch-up requests were dropped
(`NeedSnapshot dropped`, `catch-up lane full`). v12, crypto-dashboard, v6 and
v1 applied the round-1 ViewChange QC at 07:07:56; v10 and scottspersonalnode
never received those votes and stayed on round 0. v12 proposed `a4c12304…`
in round 1. v1 counted the round-1 OKs of v6, v12 and crypto-dashboard
(`soft=false` on each); its own OK was never counted anywhere, and its pipes
were being shed (`shed stuck inbound/outbound pipe`). From then on:

* v10 and scottspersonalnode voted round 1 every ~10 s (`view-change vote
  h=891420 round=1 applied=false`), 2 votes;
* the round-1 seats voted round 2 (`round=2 applied=false`), never 4
  delivered votes;
* 2 + 3 < 4, for 19.5 hours, until v1 was restarted.

Root cause in code (2.11.4 before this change):

1. `consensus_rounds.rs` `apply_round_advance`: `view_change_votes` for
   rounds ≤ r are deleted the moment the round-r QC is applied, and
   `view_change_votes` (`lib.rs`) holds voter ids only, no signatures. The
   evidence for round r is gone on every seat that has it.
2. `falcon_pl_node.rs` `WireMsg::ViewChange`: a vote is re-fanned only when
   it is new to the receiver (`vote_new`). `maybe_round_timeout_vote` then
   votes r+1 only. Nobody ever sends a round-r vote again, so a seat that
   missed them can only reach round r with the other laggards (2 of 6).
3. `vote_round_change` already lets a seat jump to any higher round
   (≤ +64) at a verified 4-of-6, so the round-0 seats *would* have adopted
   round 1, or round 2, if 4 signed votes for either had reached them.
4. `falcon_pl_node.rs` `WireMsg::LedgerOk`: an OK is re-fanned once, when
   new and not yet soft, and never re-sent. Soft needs 4 OKs in **one**
   round (`retally_round`). An OK lost on a shed pipe, or a seat's own OK
   not cast in the round it later sits in, is never re-tallied anywhere.

Fix (E):

| | Where | Change |
|---|---|---|
| E | `lib.rs` `vc_vote_sigs`, `applied_round_qc`, `last_round_regossip_ms`, `vote_view_change_ex`; `consensus_rounds.rs` `note_vc_vote_sig`, `capture_applied_round_qc`, `apply_round_advance`, `stalled_round_regossip`, `round_regossip_interval_ms`; `falcon_pl_node.rs` tick loop | Keep the verified signature of each round-scoped VC vote at the open height. When a round QC is applied, keep its 4-of-6 signed votes (`applied_round_qc`; only a full quorum, never a partial set). While the open height is stalled with work (round open ≥ one proposal timeout, 36 s on 2300; at most once per interval; never while lagging), re-send those VC votes as ordinary `ViewChange` messages, plus every committee `LedgerOk` this seat holds for its current round (the voters' original signatures), plus its own OK for the staged body if it has not cast one in this round (normal `own_ok_vote` lock rules). |

Safety: a seat still moves rounds only through `vote_view_change_ex` →
`vote_round_change`: committee voter, signature checked with
`accept_vote_sig`, same tip and height, 4-of-6 for that exact round. A
re-sent vote is byte-identical to the original. OKs are counted by the
unchanged `record_round_ok` (one vote per voter per round, equivocation
evidence unchanged) and soft still needs 4 in one round with the lock rule.
The only new signature is a seat's own OK under the same lock rules it would
have signed at staging. So it adds no new way to form a cert and no fork
risk.

Activation: **none needed.** Nothing that is signed, stored in state, carried
in a ledger or cert, or validated by other seats changes; old and new seats
treat the re-sent messages as ordinary (duplicate or late) votes. It takes
effect on each seat as soon as that seat runs 2.11.4; even one upgraded seat
holding the QC can unstick the laggards. Load: ≤ 12 small vote messages per
seat per 36 s, and only while stalled.

Tests (`round_split_tests.rs`, signed votes through an in-process mesh that
mirrors the wire handlers): the exact split (6 members, 4 needed, order[0]
and order[5] stuck on round 0, round-1 OKs landing 2 s and 3 s apart, the
4th round-1 seat cut off) stays stuck for 30 simulated minutes without
re-gossip (exactly 3 round-2 VC votes at the round-0 seats) and commits the
round-1 body with a round-1 cert with it; 3 votes, foreign or garbage
signatures, a wrong tip/height or a non-committee voter never move a seat;
re-gossip waits for a stall, is rate-limited, silent while lagging or idle;
a missing own OK is signed once and sent.

## Not in this release

D part 2 as designed earlier (a new wire field carrying a full QC) is not
needed: E re-sends the original VC votes as ordinary messages instead.
`applied_round_qc` is not persisted, so a restarted seat cannot re-send the
QC itself (it re-enters its round from its own vote, D part 1); any seat that
did not restart can.

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
