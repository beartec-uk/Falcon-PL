# Testnet 2300 throughput: today vs lean encoding vs zstd stream (estimate model)

Labels: **[M]** measured, **[E]** estimated (derived from measurements), **[A]** assumed.
Model script: `throughput_model.py` (same folder). Nothing here was load-tested; brain and the live testnet were not touched.

## 1. The run we are comparing against (correction)
The "98" figure is **98.1 tx/s, not 98 tx/block** [M]. Source: `docs/ops/THROUGHPUT-2300-IMPLEMENTATION.md` (13 Oct 2026, binary `7bdfabc9`, heights 501209–501232, a 120-wallet offer at 200 tx/s into v1 only).

| Measure | Value |
|---|---|
| Blocks, transactions, time | 24 blocks, 8634 tx in 88.0 s [M] |
| Throughput | 98.1 tx/s [M] |
| Block size | average 360 tx/block; 13 of 24 blocks at the 400 cap; 23 of 24 at 300 or more [M] |
| Round time | median 3.53 s, p90 5.79 s; long tail 6.3 s (scottspersonalnode, 2 cores) and 7.3 s (v13) [M] |
| Phases | pack 0.13 s (v1) / 0.56 s (v3); propose to hard QC 0.47–0.89 s; parent-quorum bounce under 1 s; depth dish sent 400 ms after the heads [M] |
| Full 400-tx block | about 892 KB [M] |

What saturated, according to that report:
- The 400 cap was binding on half the blocks.
- The round time was set by getting the walk (the transactions) from hub v1 to a *remote* winner over one socket: 48 KB pieces, a 256 KB pause, 382 large-send pauses. The remote winner then verifies and packs.
- The report says: "Two-core seats do seal 400 when the walk is present. They are not the floor of the 90 tx/s rate."
- So it was **not** v10 CPU on signature verification [M, per the report]. Slow remote winners (2-core and 4-core seats) do stretch the tail.
- Memory was a separate earlier issue on the hubs (fixed). v10's RSS was about 0.9–1.1 GB of 3.8 GB at 20 tx/s [M, 2.9.59 notes].
- The exact split between bandwidth and fixed protocol delay was never measured, so the model below carries it as a range.

Other measured inputs:

| Input | Value |
|---|---|
| Falcon-512 verify on the box | 0.05–0.065 ms/tx on one core [M]; 0.08–0.16 ms on v10's Skylake [A: 1.5–2.5× slower]. So 400 tx is about 30–65 ms: small. |
| v10 fixed per-block cost on 2.9.59 | about 1.4 core-s per block (44% CPU at 18 blocks/min, flat from 5 to 20 tx/s), from the 207 MB state root on a core without SHA-NI [M] |
| Bytes per tx on the critical link (live bundle fit at about 60 tx/block) | today 2.31 KB; PR #44 1.88 KB (Merkle paths gone; tx gossip stays hex); PR #44 + zstd stream 0.83 KB; binary + stream 0.74 KB [M/E] |
| zstd stream memory (wlog 17) | 1.9–2.0 MiB per connection [M] |
| zstd stream CPU | about 0.03 ms/tx per link, compress plus decompress, on a contended half core [E from the bench] |
| Body bytes per tx (for the 1 MB pack estimate) | hex 2.09–2.23 KB [M]; lean 1.22 KB [M]; binary about 0.8 KB [E] |

## 2. Model
Median round:

`T(N) = T0 + N × (k_net × bytes_ratio + k_cpu)`

- **Calibration:** today `T(360) = 3.53 s` [M].
  - `T0` (fixed protocol time) is 1.0–2.0 s [E from the phase traces].
  - `k_cpu` is 0.4–1.4 ms/tx (verify plus apply on the remote winner) [E].
  - `k_net` is the rest, 3–6 ms/tx today [E].
- **Limits:**
  - Median round ≤ 4.57 s, so the p90 (×1.64 [M]) stays 20% under the 9 s progress timeout [A policy].
  - 2.5 s minimum block interval.
  - 1,000,000 B pack estimate.
  - 4 s pack budget (never binding here; pack at 600 tx is about 0.9 s [E]).
- **Tail correction:** the median model gives 107 tx/s at today's 400 cap against 98.1 measured, so a ×0.92 tail factor is applied [E].
- **Biggest uncertainty:** how much of `k_net` really scales with bytes. Some of it is time-based pacing: the 400 ms depth tick and request/reply pulls. Both are shown: 100% byte-scaled (optimistic) and 50% (pessimistic).

## 3. Results [E unless marked]

| Step | ms/tx (opt / pess) | N limit, time | N limit, 1 MB budget* | tx/block at limit | **tx/s** (opt … pess, tail-corrected) | Limiting factor |
|---|---|---|---|---|---|---|
| Today, cap 400 | 5.6 | 545 | 443 | 400 | **98 [M]** | cap 400, then round time (moving the walk to a remote winner) |
| Today, cap lifted | 5.6 | 545 | 443 | about 440 | 100–105 | the 1 MB estimate (2,300 B/tx constant) |
| PR #44 (lean body) | 4.8 / 5.2 | 590–730 | 809 | about 590–650 | 120–145 | round time (dish bytes still hex) |
| PR #44 + zstd stream | 2.6 / 4.1 | 740–1,400 | 809 | about 740–810 | 150–205 (up to about 230 if T0 is short) | the 1 MB budget (opt) or round time (pess) |
| PR #44 + zstd + 2.6× verify | about 2.25–2.8 | similar | 809 | similar | +1–3% over the row above | verify is only 0.1 ms/tx, so this is minor |
| Binary + zstd stream (est) | 2.4 / 4.05 | 760–1,560 | 1,235 | about 760–1,200 | 150–250 | round time, then the 1 MB budget |

\* Only if the per-tx estimate constants follow the encoding. `KNOWN_KEY_TX_EST_BYTES` (2,300) caps every step at 434 until it's changed: about 1,300 B for lean (1,223 measured plus margin), and about 3,100 B for a new-key tx.

**Headline [E]:** today's 98 tx/s is cap-plus-round bound. Lifting the cap alone gives almost nothing (about 100–105 tx/s), because the 1 MB estimate binds at about 440. PR #44 plus the zstd stream, with the per-tx estimate updated and a cap near 600–700, should give **about 150–205 tx/s, roughly 1.5–2× today**. Full binary could reach about 250. Error bars are wide (±25–30%) until a post-activation load test measures the new `k_net`.

## 4. Suggested cap per step (with headroom) [E/A]
About 75–85% of the pessimistic limit, to stay inside both time and bytes:

| Step | Cap | Pack estimate constant |
|---|---|---|
| Today | keep 400 (only about 10% under the 1 MB limit) | 2,300 |
| PR #44 | 500 | 1,300 B/tx |
| PR #44 + zstd stream | 600; then try 700 if the load test p90 stays ≤ 6 s | 1,300 B/tx |
| Binary + zstd stream | 600–800, depending on the measured `k_net` | – |

Also scale together with the cap:
- The 75% "walk seals" threshold (today 300).
- `PACE_DEFAULT_MEMPOOL_TXS` (400).
- The load generator: 120 wallets × window 64 needs more wallets or depth to fill 600+ per block in a 3.5–4.5 s round.

Catch-up: a lean 800-tx block is about 1.0 MB and still fits one 1.5 MB `LedgersBatch`.

## 5. Error bars and what would tighten them
- The remote-winner dish time was never split into bytes against pacing. That's the main ±30%. The post-activation test should log dish bytes, dish duration and propose time per height.
- v10's per-block fixed cost (state root) is from 2.9.59 notes; later binaries may differ. Bigger blocks amortise it, which favours a higher cap.
- Skylake verify speed is assumed. Even at 3× slower it is under 0.2 ms/tx, so it doesn't change the picture.
