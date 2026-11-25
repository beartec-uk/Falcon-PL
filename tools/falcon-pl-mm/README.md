# falcon-pl-mm

Pair-generic testnet market-maker (`mm.py`) and taker flow (`mmtaker.py`) for Falcon PL.

- **Pair-generic config:** Set `PAIR` (e.g. `BTC4-FPL`, `USDC-FPL`, `ETH-FPL`), optional `BASE_ASSET`, and `BASE_DECIMALS` (or `BASE_RAW_PER_COIN`).
- **18-decimal precision:** Uses integer / `Decimal` arithmetic (`prec=50`) so high-decimal assets such as `ETH-FPL` (`10**18`) do not suffer float precision loss.
- **Read/write split:** Reads (`fpl_status`, `fpl_orderBook`, `fpl_openOrders`, `fpl_getAccount`) use Falcon Cloud JSON-RPC (`https://rpc.falcon-fpl.com/v1/rpc`) via `FALCON_CLOUD_API_KEY` or `FALCON_CLOUD_API_KEY_FILE`; writes (`place-order`, `cancel-order`) go through `falcon-pl-ctl` to stay clear of the Free tier's 10 tx/min cap.
