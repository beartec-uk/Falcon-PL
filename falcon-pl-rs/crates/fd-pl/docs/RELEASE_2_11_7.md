# Falcon PL 2.11.7: lean tx gossip + opt-in zstd peer stream (testnet 2300)

**No activation height. No consensus change.** Both features are negotiated
per peer connection through Hello `capabilities`, with plain legacy fallback,
so 2.11.7 and 2.11.6 seats interoperate in any mix. Hashes, roots, signed
messages, tx ids and block bodies are unchanged (block bodies keep the 2.11.6
lean rule from 923,200).

## Lean mempool + lean tx gossip (PR #55, `lean-tx-gossip-v1`)

* Mempool holds carried public keys and signatures as raw bytes (canonical hex
  only; anything else verbatim) and rebuilds the exact inserted tx on demand.
* `submit_tx` / `txs_batch` / mempool replies are sent with `b64:` signatures
  and keys **only** on a socket whose peer advertised `lean-tx-gossip-v1`;
  every other peer (2.11.6 and older, ctl, loadgen, RPC) gets hex. Received
  `b64:` gossip is normalised back to the sender's exact hex before anything
  else runs; non-canonical base64 is refused.
* On by default; `FPL_LEAN_TX_GOSSIP=0` turns lean sending off.
* Measured (400 real Falcon-512 txs, counting allocator): mempool
  3,491 B/tx → 1,939 B/tx (−44%). Wire: `submit_tx` 3,351 → 2,326 B (−31%);
  `txs_batch` ×32 3,326 → 2,301 B/tx with key (−31%), 1,532 → 1,101 B/tx
  key-stripped (−28%).

## zstd peer stream (PR #45, `zstd-stream-v1`, opt-in)

* **Off by default.** A node sends it only with `FPL_WIRE_ZSTD=1` (level
  `FPL_WIRE_ZSTD_LEVEL`, 1..=3, default 3) and only to a peer that advertised
  it too. Each side switches its own send direction after reading the peer's
  Hello; peers without the capability get byte-identical plain NDJSON.
* Bounded: 128 KiB window, frames ≤ 8 MiB, decoded output ≤ 48 MiB per frame;
  any decode error ends the session (normal redial).
* Measured (2.11.7 tree, test binaries on the build box):
  * 128 real lean bodies from testnet 2300 (h 923,463–923,590, 2,542 txs):
    4,693,074 B → 2,750,530 B (58.6%, −41.4%).
  * 20-tx gossip bundle (txs + header + body + 6 votes): 157,281 B →
    53,263 B (33.9%).
  * 20 `submit_tx` lines: hex 67,182 B; lean 46,676 B; zstd(hex) 33,868 B;
    zstd(lean) 33,396 B. With zstd on, lean tx gossip adds only ~1.4% on top.
  * Context memory per connection: 1,879 KiB (level 1/2), 2,007 KiB (level 3).

## Interop with 2.11.6

* 2.11.6 only checks Hello for `utc-header-v5`; extra capability tokens are
  ignored. A 2.11.7 node never sends a zstd marker, a frame or a `b64:` tx
  signature to a peer that did not advertise the matching capability.
* Test `inbound_session_2_11_6_peer_interop_plain_hex`: a 2.11.7 node with
  zstd and lean gossip both on, talking to a peer with the exact 2.11.6
  capability set, answers in plain JSON lines with hex sigs and accepts the
  peer's hex tx gossip.

## Rollout

Published as Latest; seats with auto-upgrade on (hourly, up to 15 min jitter)
take it. No height to meet. zstd stays off until an operator sets
`FPL_WIRE_ZSTD=1` on both ends of a link.

Version 2.11.6 → 2.11.7 (crate, lock, PRODUCT_VERSION, installer).
