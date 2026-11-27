# Falcon PL 2.11.21

**Consensus change at H = 1,021,322** (testnet 2300). Every committee seat must run 2.11.21 before the tip reaches H. A seat still on 2.11.20 computes different lend reward weights from the first settle at or after H, so its state root diverges. Before H, 2.11.20 and 2.11.21 seats mix freely: Hello compatibility is unchanged, and apply is byte-identical below H.

## Changes
- **Lend reward weighting at the live pool price (#70).** From H, the v2 settle values lend supply with the deepest FPL pool's spot price. This is the same source the borrow/LTV check uses. It is taken at the market's own scale: BTC4 is per 1e6 sats before the 2.10.4 rescale and per 1e8 after, so the value is the same either way. When an asset has no pool, the stored price is used. Before H, nothing changes.
- Status exposes `lend_live_price_from_height` so the seat roll can confirm every seat reports H.

## Activation
- H = tip 1,011,322 (read from https://falcon-fpl.com/api/status at 02:38:02 GMT, 27 Nov 2026) + 10,000. At about 3.75 s per block, that is roughly 10.4 h.
- Stop line: H − 500 = 1,020,822. If the tip reaches it before every seat reports H, stop and cut a higher H in a new rollout commit.
- Portable build only (`scripts/release/build-portable.sh`, `RUSTFLAGS` unset).
- External validators (the bonded seats not run by BEARTEC) must also update before H.

## Tests
`cargo test -p fd-pl --lib`, including `lend_live_price_tests` (9).
