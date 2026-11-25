# Falcon PL 2.11.20

Status display fix plus repo tooling. No consensus rule, quorum, lottery, ledger hash, snapshot or activation-height change. Mixed 2.11.19 / 2.11.20 seats are fine.

## Changes
- **`unbond_ready` follows chain time (#50).** Status and the health page decide `unbond_ready` from the chain's block time, not the node's local clock, and the health page shows the unbond days left in chain time. Display only.
- **Operator graph script refuses written-off graphs (#54).** `tools/fpl-operator/scripts/fpl-operator-graph.sh` (shipped by `build-release.sh`) now carries the live `--resume` and exits 4 for a deposit dir marked `WRITTEN_OFF_TEST` or an intake record with `repayment=written_off_test`. Same bytes as the falcon1 copy patched on 19 Nov.
- **BTC4 header submitter in the repo (#51).** `scripts/pl-btc4-header-submitter.py` (waiting-branch aware, stuck warning, accepted-but-not-included counts as progress) and its unit, plus the intake rail-lag Discord alert. Not installed by the node installer.

## Tests
`cargo test -p fd-pl` (incl. `health_tests::unbond_ready_follows_chain_time_not_local_clock`); `test_pl_btc4_header_submitter.py` (8) and `test_rail_lag.py` (9).
