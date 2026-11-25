# Falcon PL 2.11.16

Pack and tx-plane only. No consensus, wire-format or snapshot change. No activation height.

## Changes
- **Configurable pack body budget.** New `--pack-body-budget-bytes` (default `0` = auto).
  Auto = `max(1,000,000, max_txs x 2,300 x 1.1)`, capped at 3,500,000 bytes, so raising `--max-txs`
  raises the body budget with it. Before, the budget was fixed at 1 MB, which stops a bound-wallet
  block at ~434 txs. Local only: receivers never re-derive the selection.
  The startup `pack knobs:` line now prints `body_budget=`.
- **NeedTxs / dish batch follows the pack cap.** Requests and the hub export were fixed at 400 txs.
  They now use `clamp(max_txs, 400, 800)` (`Node::NEED_TXS_BATCH_MAX = 800`), so a seat at
  `--max-txs 800` no longer pulls or dishes half a block. Serving clamps to 800.
- Version 2.11.16.

## Measured (bound wallets, 2 cores, release build)
| cap | txs | budget | wire est | sanitize ms | pack ms | peer accept ms |
|---|---|---|---|---|---|---|
| 500 | 500 | 1,265,000 | 760,196 | 13.1 | 6.6 | 25.4 |
| 600 | 600 | 1,518,000 | 911,738 | 16.3 | 8.2 | 30.7 |
| 700 | 700 | 1,771,000 | 1,062,890 | 18.3 | 9.0 | 36.2 |
| 800 | 800 | 2,024,000 | 1,214,480 | 20.4 | 10.1 | 41.6 |

All under the 4 MB body lane and the 8 MB frame. Catch-up batches (1.5 MB) always carry at least one ledger.

## Tests
`pack_body_budget_scales_with_max_txs`, `need_txs_batch_follows_cap`, ignored `body_caps_500_to_800_fit`.
Full `fd-pl` lib + bins suites pass.

## Defaults
Default `--max-txs` stays 400, so default budgets are unchanged (1,012,000 at 400).
