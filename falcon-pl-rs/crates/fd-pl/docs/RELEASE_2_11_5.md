# Falcon PL 2.11.5: BTC4 most-work header rail + testnet4 header checks

Consensus change **gated by `TESTNET_2300_BTC4_MOST_WORK_HEIGHT` = 930,000**
(testnet 2300). Below 930,000 state is byte-identical to 2.11.4, so 2.11.4
and 2.11.5 seats interoperate until then. **Every seat must run 2.11.5 before
930,000**; a 2.11.4 seat diverges at the first BTC4 header the new rules
handle differently. Roll one seat at a time, v1 last.

## Why

* 17 Nov 2026, testnet4 161859: three equal-work min-difficulty branches. The
  canonical 161859 had its parent inside the pending fork, so neither of the
  two fork slots (2.10.1 `btc_fork` / `btc_fork_alt`) could hold it and the
  rail stopped. 19 Nov 2026: the same shape jammed the rail at 162111 (53
  behind); cleared operationally by extending the waiting fork with real
  testnet4 headers until it had more work, then re-feeding the canonical chain.
* The rail accepted any header that met its own nBits target, with no
  timestamp or exact-difficulty context, so a funded account could append
  cheap min-difficulty headers.

## Changes (PR #49)

| | Change |
|---|---|
| Rail | Side-header store `btc_side` (depth 144, cap 1,024; lowest-work leaf evicted first). A header may attach to any stored header; the rail reorgs only on **strictly more cumulative work**. Equal work keeps the current main chain (**first-seen**, as Bitcoin Core). Legacy slots migrate into `btc_side` on first use. Status shows `btc_side` tips. |
| Checks | version ≥ 4; nBits ≤ pow limit; time > median of the previous 11; exact required nBits (20-minute min-difficulty rule; BIP94 retarget from the period's first header); BIP94 timewarp (≥ parent − 600 s at a retarget); time ≤ UTC + 2 h (parent `sealed_utc_ms` once `H_utc` is armed; mempool admission uses the seat's wall clock). |

FPL chain time (`sealed_at_ms`) counts from genesis and is not UTC, so it is
never used for the 2-hour limit. Until `H_utc` is armed the consensus path has
no future limit (admission still applies it).

## Activation height

Tip 913,917 at 06:19 GMT on 19 Nov 2026. Measured average 13.3 s/block
(908,046 → 913,905 over ~77,760 s); recent short sample 10.1 s/block.
930,000 is 16,083 blocks ahead: ≈ 59 h at 13.3 s, ≈ 45 h at 10.1 s.

## Tests

`btc4_most_work_tests` (real testnet4 headers 161830–161880: the 161859 stall
reproduces under 2.11.4 rules and clears under 2.11.5; fake/cheap headers
rejected; tie-break first-seen; activation pinned at 930,000) and
`btc_spv::testnet4_rules_tests`.

Also in tree since 2.11.4 (tooling, not in the node): intake keeps minted
requests' kickoff reserved (#52); intake alerts / seat_sync (#48); bridge
loadgen (#40).

Version 2.11.4 → 2.11.5 (crate, lock, PRODUCT_VERSION, installer).
