# falcon-pl-mm

Pair-generic testnet market-maker (`mm.py`) and taker flow (`mmtaker.py`) for Falcon PL.

- **Pair-generic config:** Set `PAIR` (e.g. `BTC4-FPL`, `USDC-FPL`, `ETH-FPL`), optional `BASE_ASSET`, and `BASE_DECIMALS` (or `BASE_RAW_PER_COIN`).
- **18-decimal precision:** Uses integer / `Decimal` arithmetic (`prec=50`) so high-decimal assets such as `ETH-FPL` (`10**18`) do not suffer float precision loss.
- **Read/write split:** Reads (`fpl_status`, `fpl_orderBook`, `fpl_openOrders`, `fpl_getAccount`) use Falcon Cloud JSON-RPC (`https://rpc.falcon-fpl.com/v1/rpc`) via `FALCON_CLOUD_API_KEY` or `FALCON_CLOUD_API_KEY_FILE`; writes (`place-order`, `cancel-order`) go through `falcon-pl-ctl` to stay clear of the Free tier's 10 tx/min cap.

## falcon-mm (Phase A)

One service that covers every f-asset/FPL book: per-pair config, inventory targets, a rebalancer, per-pair pause, daily caps, and alerts to #node-alerts.

It absorbs the one-sided-book taker fix (Falcon-PL #66): if a book has only bids or only asks, the taker still trades the remaining side when it has inventory.

### Modes

- `shadow` (default): compute maker, taker, wallet transfers and capped AMM swaps, and log them as `SHADOW …`. No chain writes. Run this alongside the existing six units.
- `dry-run`: same write suppression (legacy `DRY_RUN=1` on the pair scripts).
- `live`: submit through `falcon-pl-ctl`. Do not enable this until shadow is healthy and a pair has been migrated with a backup. Leave the old unit running until fills on that pair keep going.

### Rebalance

1. Move surplus between our own wallets first, never taking a donor below its target.
2. If we are still short overall in one f-asset and long in another, plan a `swap-route` through FPL. Each leg is capped at `amm_max_pool_frac` (default 2%) of the input-side pool reserve.

Copy `config.example.json` to `/etc/falcon-mm/config.json` and fill wallet names from the live unit env files. Put the Cloud API key and Discord webhook in 0600 files (`cloud_api_key_file`, `discord_env_file`). The service never prints keys, seeds, or webhook URLs.

Pause a pair with `"paused": true` or by creating its `pause_file`. Daily caps reset on the Europe/London calendar day.

### Run

```
python3 tools/falcon-pl-mm/falcon_mm.py /etc/falcon-mm/config.json
python3 tools/falcon-pl-mm/falcon_mm.py /etc/falcon-mm/config.json --once
python3 -m unittest tools/falcon-pl-mm/test_mm.py tools/falcon-pl-mm/test_falcon_mm.py
```

Existing units (`falcon-pl-mm`, `falcon-pl-mmtaker`, and the ETH/USDC copies) stay in place until a pair is proven. If you have to stop a process, kill the exact PID only — never `pkill`.
