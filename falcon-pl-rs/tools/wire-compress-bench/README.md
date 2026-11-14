# Wire compression bench (testing only, not wired into the node)

What it does:
- Runs encodings × codecs over real testnet-2300 block bodies, plus the per-block gossip messages built from them.
- Message shapes come from `WireMsg` in `fd-pl/src/lib.rs`.
- The flow comes from `falcon_pl_node.rs`:
  - The packer fans out `ProposeHeader`, then `LedgerBodyById` with **`txs` cleared**, then its `LedgerOk`.
  - Each seat votes `LedgerOk`.
  - Transactions reach peers earlier through mempool gossip. They're always hex, including in PR #44.

Run it with one command: `./run.sh <bodies_dir>`. This pins it to one core at nice 10. Add `CONTENDED=1` to run a same-core busy loop as well, so the bench gets about 50% of the core: a proxy for v10, a busy 2-vCPU seat. Also included:
- `heavy.py`: blocks with 50 or more transactions.
- `mem.py <codec> <enc>`: peak RSS delta.

Labels:
- **measured**: on the Grok box, an 8-vCPU Xeon, Python 3.13, libzstd 1.5.7, lz4 1.9.4, brotli 1.2.1, snappy, with one pinned core.
- **(est)**: binary rows are a positional msgpack estimate of a schema'd binary wire (hex/b64 to raw bytes, no field names). The node doesn't implement it.

Data:
- 300 bodies, heights 887,811–888,110.
- Dictionary trained on the older 200; every figure below is on the held-out newest 100 (888,011–888,110, mean 17.8 tx/block).

## Key results (measured, held-out 100 blocks)
Today's average block body is 47,471 B. Today's average live gossip bundle (header + by-id body + 6 votes + tx gossip + inv) is 68,793 B per block per link. Its parts:

| Part | Share of today's bundle |
|---|---|
| tx gossip | 43.2% |
| by-id body | 26.6% |
| header | 15.8% |
| votes | 12.7% |
| inv | 1.8% |

| encoding | codec | block B | block vs today | bundle B | bundle vs today | bundle c+d µs (1 core) | same, contended ½ core |
|---|---|---|---|---|---|---|---|
| hex JSON (today) | none | 47,471 | 0 | 68,793 | 0 | – | – |
| hex JSON | lz4 | 38,682 | −18.5% | 63,958 | −7.0% | 92 | – |
| hex JSON | zstd-1 | 20,991 | −55.8% | 36,152 | −47.4% | 252 | 403 |
| hex JSON | zstd-3 | 20,865 | −56.0% | 36,466 | −47.0% | 368 | 752 |
| PR #44 lean JSON | none | 33,868 | −28.7% | 62,877 | −8.6% | – | – |
| PR #44 | lz4 | 29,414 | −38.0% | 61,677 | −10.3% | 79 | 161 |
| PR #44 | snappy | 32,108 | −32.4% | 62,416 | −9.3% | 41 | – |
| PR #44 | zstd-3 | 20,968 | −55.8% | 35,244 | −48.8% | 414 | 672 |
| PR #44 | zstd-3 + dict | 19,372 | −59.2% | 29,394 | −57.3% | 762 | 1,316 |
| PR #44 | zstd-19 | 20,632 | −56.5% | 34,540 | −49.8% | 4,984 | 9,468 |
| PR #44 | brotli-11 | 18,915 | −60.2% | 32,853 | −52.2% | 64,562 | 125,838 |
| lean, no packer pk | zstd-3 | 19,814 | −58.3% | 33,336 | −51.5% | 370 | – |
| binary (est) | none | 20,783 | −56.2% | 31,247 | −54.6% | – | – |
| binary (est) | zstd-3 | 18,901 | −60.2% | 30,352 | −55.9% | 113 | 194 |
| binary no pk (est) | zstd-3 + dict | 17,891 | −62.3% | 27,808 | −59.6% | 156 | – |

**Per-link streaming zstd** (one context per connection, flushed per message) beats per-message compression because the header, by-id body, inv and tx messages repeat tx ids, the packer key and signature, and the parent cert:

| encoding | stream | bundle B | vs today | c+d µs (1 core) | contended |
|---|---|---|---|---|---|
| hex JSON (today) | zstd-1 | 22,085 | −67.9% | 201 | 507 |
| PR #44 | zstd-1 | 20,730 | −69.9% | 214 | 379 |
| PR #44 | zstd-3 | 21,560 | −68.7% | 433 | 851 |
| binary (est) | zstd-3 | 19,399 | −71.8% | 131 | 370 |
| binary no pk (est) | zstd-3 | 19,276 | **−72.0%** | 128 | 297 |

The **ceiling** comes from the unique Falcon signature bytes a link must carry per block: tx sigs, 6 votes, packer_sig and batch_sig. That's 16,912 B per block (est), so the most any lossless encoding can save is about −75.4% (est). The binary + stream case is within about 2.4 KB of that.

Heavy blocks (10 blocks with 50 or more transactions, mean 60.1): today 167,222 B. PR #44 + zstd-3 stream gives 57,052 B (−65.9%). Binary + stream gives −69.1%. The signature floor is −73.3%.

**Signatures against structure** (zstd-3, hex body):

| Part | zstd-3 size of raw |
|---|---|
| signature/key hex | 49.9% (just undoes the hex) |
| signature/key raw bytes | 96.9% (barely compresses) |
| JSON structure without signatures | 21.6% (brotli-11: 18.9%) |

**Memory** (measured, peak RSS delta, 100 blocks):

| Codec | Peak RSS delta |
|---|---|
| lz4 / snappy | about 0.6 MiB |
| zstd-1 | 1.4 MiB |
| zstd-3 | 1.6 MiB |
| zstd-19 | 3.6 MiB |
| brotli-5 | 4.6 MiB |
| brotli-11 | 7.6 MiB |

Streaming per link (est, library): the zstd-3 compressor is about 1.3 MiB, plus the decoder window, 2 MiB at the default window log of 21, so about 3.3 MiB per link. With 10 links that's about 33 MiB per seat. A window log of 17 costs about 0.3 pp of ratio.

## Findings
1. **With compression, the PR #44 signature spelling hardly matters.** zstd turns hex back into almost-binary. PR #44's value is uncompressed bodies (storage, catch-up, any peer without the capability) and dropping the Merkle paths.
2. **Live gossip is mostly not block bodies.** By-id bodies carry no transactions, so mempool tx gossip, the header and the votes are 73% of the bundle. Compressing the transport covers all of them; changing the block encoding doesn't.
3. zstd-1 or zstd-3 is the sweet spot:
   - zstd-9 and zstd-19 add almost nothing.
   - brotli-11 is about 150× zstd-3's CPU for 2–4 pp.
   - lz4 and snappy barely help on hex JSON.
4. **CPU on a v10-like core (est from the contended figures above):**
   - PR #44 + zstd-3 stream: about 0.85 ms per block per link.
   - That's about 20 blocks/min × 8 links ≈ 0.14 s per minute, about 0.2% of one core.
   - At 98 tx/block (about 5× bytes) it's about 1–1.5%.
   - Small next to Falcon verification. Memory is the bigger cost: about 3 MiB per link.

## Staged path (recommendation)
1. **Next, safe:** per-link zstd stream (level 1–3, window log 20 or lower) on the TCP transport.
   - Gate it on a negotiated `Hello.capabilities` entry such as `zstd-stream-v1`, used only when both ends advertise it.
   - Use length-prefixed binary frames after the handshake. Don't base64 inside the line protocol, which would add 33%.
   - No consensus change and no activation height; old peers keep plain lines.
   - Expected: about −68% to −70% of live gossip bytes per link (measured model).
2. Ship PR #44 alongside it for storage and catch-up (−28.7% uncompressed). Also compress `LedgersBatch` and snapshot chunks with zstd-3: −56% to −59% per body.
3. **Optional:** a trained dictionary for per-message compression, if streaming state per link is unwanted. That gives −57% at about 2× CPU. Needs a dictionary-version capability.
4. **Ceiling work:** binary framing plus dropping `packer_public_key` gets −72% (est). That's only about 3 pp better than step 1, for a wire-format change. Beyond about −75% you'd need fewer signature bytes: aggregation, which the earlier bench found doesn't pay at 6 seats.
