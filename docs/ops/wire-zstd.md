# zstd-stream-v1 (p2p wire, opt-in)

- Off by default. Enable per node with `FPL_WIRE_ZSTD=1` (level via `FPL_WIRE_ZSTD_LEVEL`, clamped 1..=3, default 3).
- Negotiation: an enabled node adds `zstd-stream-v1` to its Hello `capabilities`. A side switches its *own send direction* only after it has read the peer's Hello carrying the capability. It writes one plain line `#zstd-stream-v1`, then frames of `u32 BE length || zstd bytes` (one flushed frame per JSON line, one streaming context per connection).
- A receiver honours the marker only if it advertised the capability itself. Old peers and ctl/loadgen RPC clients never send the capability, so they get byte-identical plain NDJSON.
- Bounds: window_log 17 (decoder WindowLogMax 17; frames that need a bigger window are refused), frame ≤ 8 MiB, decoded output per frame/partial line ≤ 48 MiB (`PIECE_MAX_TOTAL`). Measured context memory: 1,879 KiB (L1/L2) and 2,007 KiB (L3) per connection, which is ≤ 3 MiB.
- Errors: a corrupt frame, a bad length or an over-limit output ends the session (the normal redial path). After a line has been encoded it must be sent, so backpressure shedding turns into Shed (redial) and never a silent drop.
- Measured compression: a 20-tx gossip bundle went from 157,287 B to 53,212 B (33.8%); 300 real block bodies went from 14,418,486 B to 6,192,722 B (42.9%).
