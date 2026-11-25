# Falcon PL 2.11.8: zstd peer stream on by default (testnet 2300)

**No activation height. No consensus change.** This is the same negotiated
`zstd-stream-v1` as 2.11.7, now on by default. A node advertises the
capability and compresses a link only after the peer does the same. Peers that
do not advertise it (2.11.6 and older, 2.11.7 with zstd left off, ctl,
loadgen, RPC) still get byte-identical plain NDJSON. Hashes, roots, signed
messages, tx ids and block bodies are unchanged.

## What changed

* `FPL_WIRE_ZSTD` defaults to on. `FPL_WIRE_ZSTD=0` turns this node's
  advertise/send off. `FPL_WIRE_ZSTD=1` still turns it on.
* Negotiation, framing, bounds and fallback are unchanged from 2.11.7.
* Level is still `FPL_WIRE_ZSTD_LEVEL` (1..=3, default 3).
* Outside nodes and fresh 2.11.8 installs start compressing with any peer
  that also advertises `zstd-stream-v1`, with no operator flag.

## Measured (unchanged from 2.11.7; this release only flips the default)

* 128 real lean bodies from testnet 2300 (h 923,463–923,590, 2,542 txs):
  4,693,074 B → 2,750,530 B (58.6%, −41.4%).
* 20-tx gossip bundle (txs + header + body + 6 votes): 157,281 B →
  53,263 B (33.9%).
* 20 `submit_tx` lines: hex 67,182 B; lean 46,676 B; zstd(hex) 33,868 B;
  zstd(lean) 33,396 B. With zstd on, lean tx gossip adds only ~1.4% on top.
* Context memory per connection: 1,879 KiB (level 1/2), 2,007 KiB (level 3).

## Interop

* Test `inbound_session_2_11_6_peer_interop_plain_hex`: a 2.11.8 node with
  zstd at its default (on) and lean gossip on, talking to a peer with the
  exact 2.11.6 capability set, answers in plain JSON lines with hex sigs
  and accepts the peer's hex tx gossip.
* Tests also cover explicit `FPL_WIRE_ZSTD=0` (no advertise, plain frames
  even to a capable peer) and explicit `FPL_WIRE_ZSTD=1`.

## Rollout

Published as Latest; seats with auto-upgrade on (hourly, up to 15 min jitter)
take it. No height to meet. 2.11.7 seats that already have `FPL_WIRE_ZSTD=1`
keep compressing; 2.11.8 does the same with the flag unset. `FPL_WIRE_ZSTD=0`
is the off switch.

Version 2.11.7 → 2.11.8 (crate, lock, PRODUCT_VERSION, installer).
