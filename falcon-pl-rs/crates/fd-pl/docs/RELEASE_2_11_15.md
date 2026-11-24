# Falcon PL 2.11.15: 400-tx blocks and a fast mempool head check (testnet 2300)

**No activation height. No consensus change. Rolling-upgrade compatible with 2.11.14.**
Local pack / mempool policy and the seat default for `--max-txs` only. The block
format, signatures, 4-of-6 commit QC, state root and the round-0 lottery are
unchanged. Receivers never re-derive the pack selection, and there is no
accept-side tx-count cap, so 2.11.14 seats accept 400-tx blocks.

## Why
The 24 Nov dual-sender ramp on 2.11.13/14 sustained about 126 tx/s (peak about
134) and every full block hit the 200-tx cap. On v1 the pack median was 567 ms,
and `sanitize` (the mempool head dry-run before the pack) was 531 ms of it.

That dry-run cloned the six state slices (accounts, defi, bridge, validators,
claimable, epoch work) **for every head** and ran a single-threaded Falcon
signature check inside each apply. With 240 sending wallets that is 240 full
clones and 240 serial Falcon verifies per pack.

## What changed (local)
1. **Head dry-run on one shared draft** (`drop_permanent_applicable_heads`).
   One draft is cloned per call. Each head is applied to it with its signature
   already checked; a failing head is rolled back with the pack's `PackUndo`.
   A head is only **dropped** after the pre-2.11.15 check (fresh clone of
   committed state, signature checked again) also calls it a permanent failure,
   and a bad or unverifiable signature always takes that exact path. So the
   drop set can only shrink, never grow.
2. **Signatures checked once, in parallel, and shared with the pack.** Heads not
   already pre-checked (`sig_warm`, 2.11.13 pre-pack) are verified across the
   seat's cores (`preverify_pack_sigs`, max 16 threads) with the pack's own
   check. Good results are cached by tx id and key in `sig_warm`, so the pack
   that follows does not verify them again.
3. **`--max-txs` default 400** (was 200), in the node default and in
   `network-2300.env` (`MAX_TXS=400`), which `falcon-node upgrade` reinstalls on
   every seat. Limits checked: the pack's 1 MB body budget (400 known-key txs
   ~0.92 MB; first-key txs are counted at 5 KB so a block of new keys stops
   near 200), the 1.5 MB catch-up batch, the 8 MB wire frame, and the
   14.6 s round-0 limit (400-tx pack + sanitize ~31 ms on 2 cores in the bench).
4. Operator fallback: `FPL_SANITIZE_LEGACY=1` restores the pre-2.11.15 dry-run.
5. Node counters `sanitize_sig_checks` and `sanitize_confirm_runs` (diagnostics and tests).

## Bench (beartec-brain, release build; `sanitize_bench_200_400`)
One head per account, bound keys, 6 seats, filler accounts to size the state.
`sanitize` then `pack_as` on the lottery packer; ms.

| heads | filler accts | cores | sanitize before -> after | pack before -> after | total before -> after |
|---|---|---|---|---|---|
| 200 | 5,000 | 32 | 71.4 -> 3.8 | 8.2 -> 5.5 | 79.6 -> 9.3 |
| 400 | 5,000 | 32 | 154.8 -> 6.3 | 11.0 -> 8.3 | 165.8 -> 14.6 |
| 200 | 5,000 | 2 | 71.7 -> 5.9 | 9.0 -> 5.0 | 80.7 -> 10.9 |
| 400 | 5,000 | 2 | 155.5 -> 11.5 | 15.8 -> 7.4 | 171.3 -> 18.9 |
| 200 | 20,000 | 32 | 242.8 -> 6.1 | 17.9 -> 14.2 | 260.6 -> 20.3 |
| 400 | 20,000 | 32 | 511.5 -> 9.8 | 22.1 -> 16.4 | 533.7 -> 26.2 |
| 200 | 20,000 | 2 | 243.9 -> 8.2 | 17.4 -> 13.9 | 261.3 -> 22.1 |
| 400 | 20,000 | 2 | 541.6 -> 13.9 | 25.7 -> 17.2 | 567.3 -> 31.1 |

The "before" cost grows with state size times head count; "after" grows with
head count only (one clone).

## Tests
* `sanitize_fast_tests::shared_draft_drops_exactly_what_the_full_clone_path_drops`
* `sanitize_fast_tests::fast_path_shares_verified_signatures_with_the_pack`
* `sanitize_fast_tests::fast_path_never_trusts_a_bad_signature`
* `sanitize_fast_tests::fast_path_drop_set_is_a_subset_of_the_full_clone_path`
* `sanitize_fast_tests::pack_after_fast_sanitize_matches_pack_after_legacy_sanitize`
* `sanitize_fast_tests::sanitize_bench_200_400` (ignored; bench)
* Existing sanitize memo / poison tests unchanged and passing.
