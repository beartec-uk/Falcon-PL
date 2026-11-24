# Falcon PL 2.11.17 (draft, not released)

Liveness timing only. No consensus, quorum, lottery, wire-format or snapshot change. No activation height.

## Lagging-leader fast view-change
`--lagging-leader-vc-ms` (default 400; `0` = pre-2.11.17 timing).

A committee seat votes the existing signed ViewChange for the open round early when all hold:
- the height is round-scoped, this seat is not behind any peer (`!still_lagging()`);
- no body is staged or cached for the height;
- the round proposer is another seat, pong-fresh, and its latest tip ad (Pong every seal tick) arrived after this round opened;
- that ad is >= 2 behind our tip and the knob has elapsed since the round opened, or it is 1 behind, arrived at least the knob into the round, and 3x the knob has elapsed.

A newer ad at our tip clears it. The vote is the same `ViewChange` (same payload, signature, target round, re-vote interval), so the 4-of-6 QC, the lottery and missed-turn accounting are unchanged. An offline proposer (stale pong) keeps the existing unavailable timeout; a live proposer at the tip keeps the silence timeout. Mixed fleets are safe: un-upgraded seats keep the old timing, so the QC forms once 4 committee seats agree.

Logs: `view-change vote ... fast=true|false`; startup `lagging-leader view-change: N ms`. Counter `Node::fast_vc_votes`.

## Tests
`lagging_leader_vc_tests.rs`: fires at the grace for a 2-behind leader and not before; no double vote; knob 0 = legacy timing; a healthy leader never triggers it over a full silence window; lag-1 needs a late ad and 3x grace; ads from before the round are ignored; no fast vote when self-lagging, with a body in hand, or as the leader; the QC needs the same number of votes as the legacy path and advances exactly one round; forged-voter and repeat votes rejected. Ignored `lagging_leader_bench` (simulated clock, deployed timings).
