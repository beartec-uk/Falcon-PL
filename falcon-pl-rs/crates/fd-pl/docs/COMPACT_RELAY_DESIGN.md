# Compact block relay (2.11.18, design + slice 1)

## Problem
Under load the leader sends the full sealed body (lean Merkle batch, ~1.2 KB/tx, ~0.48 MB at 400 txs,
~1.2 MB at 800) to every body-lane seat. Four of nine seats share one home uplink (falcon1 on WiFi at
~89 Mbit/s); at caps 500-600 seats missed bodies, catch-up from the v1 hub stalled, and turns were missed.
Peers already hold almost every tx in their mempool from gossip.

## Design
1. **Leader**: after sealing, send `LedgerBodyById` (the body with `txs` cleared: header, `tx_ids`,
   `batch_root`, `batch_sig`) on the body lane instead of `LedgerBody`. Only for lean batch bodies
   (no per-tx paths) or plain bodies; pre-lean batch bodies go out in full. Header/OK fan-out is unchanged.
2. **Receiver**: rebuild from mempool + `body_fill`. For batch bodies, normalise each tx to the exact wire
   form the packer sealed (lean `b64:` sigs; key left off when the parent state already holds it), so the
   rebuilt body is byte-identical to the full body; then the normal `ProposeLedger`/accept path runs every
   check (tx root, batch sig, state root). Nothing is trusted from the shell that accept would not check.
3. **Missing ids**: one `NeedTxsByIds` on the body-pull lane -> `TxsByIds` (existing messages).
4. **Fallback**: if the id pull does not complete the body, the existing periodic `NeedLedgerBody` pull
   fires after ~800 ms and the full body is served (existing path). A tampered/mismatched shell fails accept
   exactly like a tampered body.
5. **Rollout gate**: `--compact-body-relay` (default off). Older receivers already parse `LedgerBodyById`
   but do not normalise; turn the flag on only once every seat runs 2.11.18.

## Expected size
Shell ~70 B/tx of ids plus ~5 KB fixed (packer key, sigs, roots): ~33 KB at 400 txs, ~61 KB at 800,
versus ~0.48 / ~1.2 MB full. Measured numbers are in the slice-1 test output (`COMPACT ...`).

## Slice 1 (this branch)
- `Node::compact_relay_eligible`, `Node::compact_shell`, normalising `assemble_body_by_id`.
- Leader path behind `--compact-body-relay`; receiver arms a full-body pull when ids are missing.
- Tests: byte-identical rebuild + accept (bound/unbound keys, lean and pre-lean), missing-id pull,
  incomplete pull -> fallback, tampered shell rejected, size.

## Next slices
- Per-peer capability in Hello so mixed fleets can use compact to upgraded peers only.
- Serve `NeedTxsByIds` from any seat (not just the packer) and prefer the nearest peer.
- Metrics: compact hit rate, ids pulled, fallbacks; health fields.
- Multi-seat soak on a local mesh (brain loopback seats) before any testnet flag flip.
