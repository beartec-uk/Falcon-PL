# Falcon PL 2.11.19

Compact block relay fixes. No consensus rule, quorum, lottery, ledger hash, snapshot or activation-height change. `--compact-body-relay` stays **off by default**.

Live 2.11.18 compact relay rebuilt many bodies only via the slow full-body path: id pulls went to the archive first (often a lagging hub that does not hold the body yet and so never answered), and a second reply for an already finished body was counted as a fallback and triggered a needless full-body pull.

## Changes
- **Leader carries fresh txs.** `--compact-carry-ms` (default 500): body txs that reached the leader's pool less than 500 ms before the seal travel in full inside the compact shell (peers probably lack them). Receivers rebuild byte-identically as before; 2.11.18 receivers ignore the carried txs. `0` = 2.11.18 shell.
- **Short adaptive wait.** `--compact-wait-ms` (default 150): a receiver missing only a few txs (<= max(4, 2%)) parks the shell for a moment so the tx plane can fill it, then pulls. Waits switch themselves off while they stop paying off (after 8 tries, at least half must finish without a pull).
- **Any-peer id pulls.** `NeedTxsByIds` goes to the sender, the packer and one more body-lane seat (not archive-first); any peer answers from the sealed body or its mempool / fill cache. Partial answers merge.
- **No spurious full-body pulls.** A reply for a finished body is ignored (`late`); a partial one waits for the rest (`partial`). The full-body pull runs only from the ~800 ms timer while the shell is still open, and `fallback` counts each such shell once.
- Counters added: `carried`, `waited`, `wait_hit`, `partial`, `late`.
- `falcon-pl-load-net`: wallet names match genesis (`w00..`).

## Local soak (4 seats, falcon-512, lean bodies, one seat behind a 150 ms RTT proxy)
| scenario | 2.11.18 fallback | 2.11.19 fallback |
|---|---|---|
| load to all seats | 4/176 shells (2.3%) | 1/186 (0.5%) |
| delayed seat is the archive, load to 2 seats | 17/180 (9.4%; delayed seat 18%) | 0/188 (0%) |

Carrying fresh txs made shells ~22% of the full body bytes (2.11.18: ~9%), still ~4.5x smaller.

## Tests
`compact_relay_tests.rs`: carried-shell rebuild byte-identical (bound and unbound keys), carry selection by arrival time, wait finishes from the mempool without a pull, wait expiry -> pull naming the packer, adaptive switch-off, any-peer answer from the mempool, partial + late replies.
