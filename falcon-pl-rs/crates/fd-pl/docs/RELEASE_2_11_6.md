# Falcon PL 2.11.6: lean block body encoding at 923,200 (testnet 2300)

Consensus change **gated by `TESTNET_2300_LEAN_BODY_FROM_HEIGHT` = 923,200**
(testnet 2300). Below 923,200 every body is written and checked exactly as in
2.11.5, so 2.11.5 and 2.11.6 seats interoperate until then. **Every seat must
run 2.11.6 before 923,200**: from that height packers write lean bodies and a
2.11.5 (or older) node rejects them.

## What changes (PR #44)

* From the height the packer writes tx signatures as `b64:` + canonical padded
  base64 instead of hex, and leaves `batch_paths` off the body (receivers
  rebuild the payload Merkle root from the txs they already hold).
* No hash, root or signed message changes: `ledger_hash`, `inner_hash`,
  `cert_hash` and the state root never cover tx signature spelling, and the
  `batch_root` sig half is still computed over canonical hex.
* Verifiers only see hex (`Tx::sig_hex()`). Votes, certs, PoP, `packer_sig`
  and `packer_public_key` are untouched. Mempool and tx gossip stay hex.
* Legacy bodies stay valid at every height; a lean signature below the height,
  a non-canonical b64 signature, or a partial path set is rejected.
* Measured on 300 real testnet 2300 bodies (h 887,811–888,110): 14,408,586 B →
  10,223,063 B (71.0%, −29.0%), all valid before and after activation.

RPC / explorer / walletd consumers will see `b64:` tx signatures in blocks at
or above 923,200 (`crypto::sig_to_hex` converts back).

## Activation height

Tip 920,972 at 06:01 GMT on 20 Nov 2026. Measured 24 h average 12.1 s/block
(913,917 at 06:19 GMT 19 Nov → 920,966 at 06:00 GMT 20 Nov); last 20 min
~15 s/block. 923,200 is 2,228 blocks ahead: ≈ 13:30 GMT at 12.1 s/block,
≈ 15:25 GMT at 15 s, and no earlier than ≈ 12:10 GMT even at 10 s/block, which
leaves at least four hourly auto-upgrade cycles after publication. Clear of
the BTC4 most-work rail at 930,000.

## Rollout

Published as Latest; seats and operators with auto-upgrade on (hourly,
up to 15 min jitter) take it within the hour. A seat whose auto-upgrade fails
is upgraded with `falcon-node upgrade`, one seat at a time, v1 last.

Version 2.11.5 → 2.11.6 (crate, lock, PRODUCT_VERSION, installer).
