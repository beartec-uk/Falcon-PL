# Falcon PL 2.11.11: loopback RPC is never paced as a non-seat (testnet 2300)

**No activation height. No consensus change. Wire format unchanged.** 2.11.11
sends the same bytes as 2.11.6–2.11.10 and runs in any mix with them. It fixes
one 2.11.10 regression (PR #61).

## Why
2.11.10 (#60) treated every inbound session as a non-seat until its Hello named
a bonded validator. `falcon-pl-ctl` never sends a Hello, so a local `ctl status`
(about 2 MB) was paced at 256 kB/s and queued behind the shared 768 kB/s
observer debt. On spn the installer's autoupgrade health check
(`timeout 30 ctl status`, retried for 120 s) got no answer, and the upgrade
rolled back to 2.11.9 (21 Nov).

## What changed
* A loopback client (127/8, ::1, v4-mapped) is the node's own operator and is
  never an observer. Seed relays reach seats over the tailnet, not loopback,
  so relayed outside peers stay paced.
* On a real non-seat session, `status` / `health` / `ok` / `err` replies are
  paced by that session's own budget only, not the shared bulk budget. Bulk
  serving (catch-up, snapshots, bodies, pieces) and the NeedLedgers /
  NeedSnapshot refusal are unchanged.

## Tests
* `loopback_status_is_not_held_by_observer_debt`: shared budget 4 s in debt, a
  loopback StatusReq must answer within 1.5 s. Fails on 2.11.10 (4.01 s),
  passes here.
* `loopback_remotes_are_local_clients`,
  `observer_query_reply_skips_the_shared_debt_bulk_does_not`.
* Box repro of the installer's health-check loop with 16 local status loops
  holding the shared budget in debt: 2.11.10 answered 0 of 4 calls (all timed
  out at 30 s); this fix answered 33 of 33, p50 1.6 s, max 3.8 s.
