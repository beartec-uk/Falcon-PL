# Falcon PL 2.11.9: a slow peer no longer resets the session (testnet 2300)

**No activation height. No consensus change. Wire format unchanged.** The
bytes on the wire are the same as 2.11.6–2.11.8 (plain NDJSON, or
`zstd-stream-v1` frames when both ends advertise it), so 2.11.9 runs in any
mix with those releases. Only the local decision of when to reset a socket
changes.

## Root cause

`write_or_shed` (`crates/fd-pl/src/bin/falcon_pl_node.rs`) gave every line a
2 s hold (`PIPE_SHED_HOLD`). If the peer stopped reading for longer than that:

* a line the kernel had **partly** taken was shed as `reason=torn`, plain or
  compressed;
* a must-send line (dish, ledger body, header, pieces) waiting behind a
  >256 KB send queue, or untouched after 2 s, was shed as `reason=body`;
* any line seeing a send queue over `PIPE_SHED_BYTES` (1 MB) was shed as
  `reason=send`.

Every shed costs an 8 s blackhole, the session's queued lines and a mempool
re-sync. #58 (2.11.8) only covered an optional line the kernel took none of on
a compressed session. Live after 2.11.8, the seat on falcon1 logged 40 torn
sheds in 28 min (to v10 and v6) and 5 body sheds to the hil-2-1 relay with
~265 KB unsent; the peers' own logs showed them pausing reads (up to 2.7 MB
unread on their sockets) for a few seconds at a time. Each reset made the next
pause more likely (re-sync traffic), and blocks averaged 51.8 s against 15.0 s
with zstd off.

## What changed

* A line the kernel has started taking is kept and finished before the next
  line (dropping it mid-frame would corrupt a zstd stream or a JSON line). It
  sheds only after the kernel takes no byte of it for `PIPE_STUCK_HOLD` (8 s).
* Must-send and catch-up lines get the same 8 s no-progress hold (was 2 s).
  A peer that has really stopped still gets shed.
* An optional line (vote, tx relay, inventory) seeing a send queue over
  `PIPE_SHED_BYTES` is dropped at once; the session stays up. Was a shed.
* An optional line on a compressed session that cannot get socket room within
  2 s is dropped (as in 2.11.8, but never a shed now).
* An untouched optional line on a plain session is still dropped after 2 s.
* Backlog drops are logged at most once per interval (`backlog drop optional`).

## Measured

* New tests (fail on the 2.11.8 `write_or_shed`, pass on 2.11.9):
  `compressed_torn_optional_line_finishes_without_shed`,
  `plain_torn_optional_line_finishes_without_shed`,
  `compressed_backlog_over_shed_bytes_drops_optional_without_shed`,
  `plain_backlog_over_shed_bytes_drops_optional_without_shed`,
  `must_send_still_sheds_after_the_hold`,
  `compressed_must_send_survives_short_reader_pause`.
* Throttled-reader soak (`throttled_reader_soak`, ignored by default; one
  compressed session, kernel buffers capped to the live ~300 KB, reader reads
  1 s then pauses 6 s, 6 KB tx lines plus a 150 KB body every second, 60 s):
  2.11.8 code 4 sheds (3 torn, 1 body), 239 lines delivered; 2.11.9 code 0
  sheds, 832 lines delivered. With 4 s pauses both had 0 sheds.
* Per-line zstd flush does not inflate lines (`per_line_frames_do_not_inflate_lines`):
  on the 20-tx real-shaped bundle every frame is smaller than its plain line
  (the closest is still 690 B smaller); 157,305 B → 53,263 B.

## Rollout

Published as Latest; seats with auto-upgrade on take it. No height to meet.
zstd stays on by default (`FPL_WIRE_ZSTD=0` is still the off switch).

Version 2.11.8 → 2.11.9 (crate, lock, PRODUCT_VERSION, installer).
