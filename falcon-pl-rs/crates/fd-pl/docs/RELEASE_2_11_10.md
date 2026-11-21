# Falcon PL 2.11.10: upload budgets for non-seat peers, votes first (testnet 2300)

**No activation height. No consensus change. Wire format unchanged.** The bytes
on the wire are the same as 2.11.6–2.11.9, so 2.11.10 runs in any mix with
those releases. Only local send scheduling changes (PR #60).

## Why
On 21 Nov falcon1 (v1) uploaded about 3.9 MB/s over home Wi-Fi. Roughly 40% of
that (1,319 kB/s) went through the public seed relay on v12's host, and one
relayed outside session pulled 21.8 MB of `piece` lines in 20 s. Non-seat
sessions had no upload budget. With zstd on v1, its seat links shed 66 times in
28 min and blocks averaged 48.9 s.

## What changed
* **Upload budgets for non-seat sessions.** An inbound session counts as a
  non-seat until its Hello names a bonded validator. Validators are never paced.
  `FPL_OBSERVER_SESSION_KBPS` caps each non-seat session (default 256) and
  `FPL_OBSERVER_UPLOAD_KBPS` caps all of them together (default 768).
  0 = unlimited (2.11.9 behaviour).
* **Drop before encode.** NeedLedgers / NeedSnapshot / NeedSnapshotChunk from a
  non-seat is ignored while the shared budget is more than 1 s in debt. The
  joiner asks again on its own timers.
* **Votes first** on outbound sessions: cons → catch-up reply → reply →
  NeedLedgers → body → tx.
* **`pipe_stuck` waits 8 s** (`PIPE_STUCK_HOLD`) instead of 2 s, the same
  grace write_or_shed has had since 2.11.9.
* The `mesh sockets` log line gains `observer_bytes`, `observer_paced_ms` and
  `observer_refused`.

## Measured (model soak, `uplink_fanout_soak`, 3,900 kB/s shared uplink, 120 s)
| Case | 2.11.9 vote p50 / delivered | 2.11.10 vote p50 / delivered |
|---|---|---|
| 6 seats + 3 outside | 18 ms / 100% | 1 ms / 100% |
| 4 s uplink stall / 20 s | 527 ms / 98.7%, 3 sheds | 13 ms / 99.3%, 0 sheds |
| 12 seats + 6 outside | 755 ms / 99.6% | 1 ms / 100% |
| 30 seats + 15 outside | 22 s / 67.8% | 3.2 s / 97.7% |

The soak models the writer loop (the same `write_or_shed`, `ZWire` and
`pipe_stuck_for` code), not the whole node.

## Trade-off
A joining node that is not yet bonded syncs at no more than 256 kB/s per
session. A 100 MB snapshot takes about 6.5 min. Raise the env values on
archive nodes if needed.

Design and next phases (node roles: validator / full / archive):
`docs/SEND_PATH_DESIGN.md`.
