# falcon-agg-proto — Falcon-512 aggregation experiments (PROTOTYPE)

**Research prototype. Not used by `falcon-pl-node`, not audited, not a
consensus change.** Own Cargo workspace so it never touches the node build.
Started 14 Nov 2026 after DreggNet's "qsag" post, to check what signature
aggregation could do for Falcon PL with numbers we measured ourselves.

## What is here

| Path | What |
| --- | --- |
| `verify/` | `falcon512-verify`: pure-Rust, `no_std`, no-alloc Falcon-512 verifier for the PQClean round-3 format FPL signs with (`pqcrypto-falcon 0.3`, original `r‖m` framing). Cross-checked against pqcrypto-falcon in tests (valid, wrong message, tampered sig). |
| `bench/` | Native verify cost: raw pqcrypto, the node's current path (hex pk decode + parse + hex sig decode + verify), the pure-Rust verifier, and 2-thread split. |
| `zk/` | RISC Zero 3.x guest that verifies N Falcon-512 sigs and commits `(N, sha256 over pk/msg digests)`; host measures cycles, prove time, receipt size, verify time. Can feed it **real FPL packer `batch_sig`s** from archived bodies. |
| `scripts/block_sig_share.py` | Signature share of real block bodies. |
| `scripts/block_byte_variants.py` | Bytes saved by cheap encoding changes on real bodies. |
| `scripts/run_aerie_bench.sh` | Runs a16z's Aerie (lattice SNARK Falcon aggregation, pinned rev) at FPL batch sizes. |

## Results (14 Nov 2026)

Labels: **measured** = run by us; **published** = from the cited source.
"box" = 8 vCPU Xeon (AVX-512), 15 GB, idle. "brain" = beartec-brain, 2 pinned
cores at nice 19 while the machine was at load ~16, so slower than idle.

### a) Signature share of real blocks — measured (300 testnet bodies, h 887,811–888,110)

| Item | Value |
| --- | --- |
| Mean body size (JSON, as stored/served) | 48,029 B |
| Mean txs per block (min / median / max) | 18.2 (1 / 14 / 99) |
| Tx Falcon-512 sig, binary (min / mean / max) | 647 / 655.0 / 664 B (hex on wire: 2x) |
| Commit cert sigs per block | 4 (298 blocks), 5 (2 blocks); ~2,625 B binary |
| All signature chars (tx + packer + batch + cert) | **65.9 %** of body bytes |
| Tx pubkeys on the wire | 0 (already stripped by the Merkle batch for known accounts) |
| `batch_paths` (Merkle paths) | 12.1 % of body bytes |
| `packer_public_key` | 3.7 % of body bytes |

### b) Verify cost — measured (n = 1000 sigs, 64 keys)

| Path | box µs/sig | brain µs/sig |
| --- | ---: | ---: |
| pqcrypto-falcon verify (pre-parsed) | 37–39 | 71–75 |
| Node path today (hex pk + parse + hex sig + verify) | 50–55 | 100–105 |
| Pure-Rust verifier, pk cached | 19–21 | 40–43 |
| pqcrypto, 2 threads (wall, per sig) | 19.6–20.6 | 35.6 |

Falcon has no algebraic batch verify in our library; "batching" = threads,
which scale ~1.9x on 2 cores (the node already does this in
`preverify_pack_sigs`). At 18 tx/block this is ~1 ms of verify per block.

### c) Cheap byte wins, no new crypto — measured on the same 300 bodies

| Variant (cumulative) | Mean bytes/block | vs today |
| --- | ---: | ---: |
| Today (JSON, hex) | 48,029 | 100 % |
| Drop `batch_paths` (receiver rebuilds the root from the txs it already has) | 41,908 | 87.3 % |
| + drop `packer_public_key` (key is in the on-chain registry) | 40,091 | 83.5 % |
| + signatures base64 instead of hex (still JSON) | 29,572 | 61.6 % |
| + signatures raw binary (estimate from exact char counts) | 24,265 | 50.5 % |
| Archive only: prune tx sigs after finality, keep `sig_root` | 16,036 | 33.4 % |
| Today, just zlib-6 the JSON | 23,816 | 49.6 % |

### d) Proof-based aggregation

| N sigs | Raw Falcon-512 sigs | RISC Zero 3.x succinct STARK (hash-based) | Aerie lattice SNARK (per-record salts) | Aerie common salt |
| ---: | ---: | --- | --- | --- |
| 6 (commit cert) | 3,935 B | **measured box:** 223,490 B, prove 1,241 s CPU, verify 13.7 ms, 4.38 M cycles | **measured box (padded to 8):** 60,548 B, prove 118 ms (8 thr) / 179 ms (2 thr), verify 8–21 ms | 60,285 B |
| 100 (→128 for Aerie) | 65,542 B (85,248 B padded x128) | ~223 KB (size constant); 64.2 M cycles **measured**; prove **estimated** ~5 h on box CPU | **measured:** 66,239 B, prove 154 ms (8 thr) / 243 ms (2 thr), verify 11–37 ms | 61,160 B |
| 1000 (→1024) | 655,131 B (681,984 B x1024) | ~223 KB; 515 M cycles **measured**; prove **estimated** ~40 h on box CPU | **measured:** 104,253 B, prove 282 ms (8 thr) / 555 ms (2 thr), verify 31–119 ms | 63,334 B |

Published, for context: RISC Zero proving one FN-DSA Falcon-512 verify on an
RTX 4090: 1.91 s ± 0.05 s (GhostProver / Kaspa Kii bench, Jul 2026). Aerie
on Apple M4 Max: 32,768 sigs in 645 ms, 1,346 KiB (66 KiB common salt)
(a16z, Oct 2026). LaBRADOR (PSE): 10,000 sigs → 74 KB, 5.96 s prove, 2.65 s verify.

**Format catch:** Aerie only accepts FN-DSA (fn-dsa 0.3.0) key-prefixed
framing (`salt ‖ SHAKE256(pk) ‖ 0 ‖ 0 ‖ msg`, padded 666 B). FPL signs with
original Falcon `r ‖ m` framing, so the Aerie rows use fn-dsa-signed
signatures of the same parameter set, not FPL's on-chain ones.

**Real FPL signatures, proved — measured (box):** the RISC Zero guest proved 6
real packer `batch_sig`s from testnet blocks 887,811+ (5 distinct seat keys,
3,932 B of raw sigs): 4.26 M cycles, prove 1,118 s on CPU, succinct receipt
223,490 B, verify 12.9 ms. Works, but ~57x bigger than the raw sigs.

## Reading the numbers

* For a 6-seat committee, every aggregation route is larger than the raw
  sigs (Aerie ~15x, STARK ~57x). Not worth it for commit certs.
* Aerie crosses below raw at ~100–128 sigs and is ~6.5x smaller at 1024.
  That suits batches of hundreds+: busy blocks, or a light-client/bridge
  "epoch certificate" covering many blocks' commit sigs (256 blocks x 4 =
  1,024 sigs: 104 KB vs ~670 KB raw).
* Generic zkVM STARK proving of Falcon is far too slow on CPU for consensus.
* Biggest near-term win is plain encoding: ~50 % of body bytes, no new crypto.

## Run

```sh
cd falcon-pl-rs/tools/falcon-agg-proto
cargo test --release -p falcon512-verify
cargo run --release -p falcon-agg-bench -- 1000 2
python3 scripts/block_sig_share.py <bodies_dir>
python3 scripts/block_byte_variants.py <bodies_dir>
# zkVM (needs rzup / RISC Zero 3.x, r0vm on PATH):
cd zk && cargo build --release
./target/release/falcon-agg-zk synth 6 6 succinct
./target/release/falcon-agg-zk chain <bodies_dir> 6 execute
```

Credits: Falcon (Fouque et al.), PQClean / pqcrypto, a16z Aerie, RISC Zero,
PSE LaBRADOR work. ZKNox, OpenZeppelin and rukafe0x as in the main NOTICE.
