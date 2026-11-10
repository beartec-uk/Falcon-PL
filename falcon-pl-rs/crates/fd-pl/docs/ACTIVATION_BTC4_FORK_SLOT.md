# BTC4 later-height fork-slot replacement (activation block 860,000)

Ships as product and installer version **2.11.3**.

Gate: `params_v2::TESTNET_2300_BTC4_FORK_SLOT_HEIGHT = 860_000` (2300); other
networks `FPL_BTC4_FORK_SLOT_FROM_HEIGHT` (default never). Active when
`tip + 1 >= 860,000`.

Before the height, seats apply BTC4 `RailHeader` txs exactly like 2.10.1 / 2.11.2
(`submit_header_ex3(.., slot_fix=false)` == `submit_header_ex2`). After the
height (BTC4 rail only, strict/rv2 path):

- If both `btc_fork` and `btc_fork_alt` are occupied, and a new main-ancestral
  fork starts at a **later height** than the current alt tip, and its 1-header
  work is not strictly greater than the leftover alt, the new header **replaces**
  `btc_fork_alt` instead of being rejected with
  `"BTC fork has less work than the competing branch"`.
- Same- or earlier-height weaker forks are still rejected (2.10.1 behaviour).
- Promotion and main-chain switch rules are unchanged (strictly more work).

## Why

On 10 Nov 2026 the BTC4 SPV rail wedged at 160187. Leftover 1-header pending and
alt forks at 160182 (each work = 4295032833, difficulty-1) occupied both slots.
The submitter correctly found the common ancestor 160185 (rail = Testnet4) and
submitted canonical 160186. That header is a new 1-header fork at 160186 with
equal work, so 2.11.2 rejects it. Stale GC (`BTC_FORK_STALE_N = 6`) does not
drop the 160182 leftovers while tip is 160187 (`160187 <= 160182 + 6`), and GC
only runs on a main-tip extension, which cannot happen because canonical 160188
parents onto mempool 160187, not the stale rail 160187.

Restarting the header submitter cannot unstick this: the leftover slots are
replicated rail state on every seat.

## Deploy runbook (seat binary)

This is a consensus change. A 2.11.2 seat rejects the header a new seat accepts,
so a mixed fleet diverges if that header is packed after H.

1. Merge is **not** required to deploy: build this branch on beartec-brain
   (nice/ionice, scratch dir) and record the exact commit SHA.
2. Confirm Falcon tip is still well below 860,000. If the tip has raced close,
   **stop** and cut a higher H in a new commit before any seat is flipped
   (do not ship two different consensus rules).
3. Copy the current seat binary aside on each host (`*.bak-YYYYMMDD-HHMMSS`).
4. Roll **one seat at a time**, v1 last. After each seat:
   - process is up and serving RPC;
   - `status` tip hash matches the rest of the fleet (no fork);
   - Falcon tip continues to advance.
5. If any seat fails to start or its tip/hash diverges: restore that seat's
   backup binary, restart it, confirm it re-joins the previous hash, and **stop**.
6. After every seat is on the new SHA and H has passed, the falcon1 header
   submitter (unchanged) should admit canonical 160186 as the new alt, walk
   160187/160188, switch onto the heavier Testnet4 branch, and catch up to
   the Testnet4 tip.
7. Rollback (before H, or before any competing-branch header is packed): restore
   each seat's backup binary in reverse order, verifying tip hash after each.

No GitHub Actions. No force-push. No merge unless Scott says "Merge".
