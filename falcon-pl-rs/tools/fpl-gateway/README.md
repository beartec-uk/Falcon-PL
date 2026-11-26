# fpl-gateway: Falcon Cloud RPC gateway

BEARTEC Build Plan step 3. A keyed, rate-limited, metered HTTPS JSON-RPC front for a
Falcon PL node. **Falcon PL is a testnet.** FPL testnet tokens have no monetary
value; the paid tiers buy RPC capacity and support, not tokens.

```
client --HTTPS--> Caddy :443 --> fpl-gatewayd 127.0.0.1:8545 --wire JSON--> node 127.0.0.1:19312
                                   metrics 127.0.0.1:9187
```

## Hosting plan
Runs on the **Helsinki public seed host (5.78.142.246)**, next to the seed node.
Source of truth: `crates/fd-pl/scripts/network-2300.env` (Public door: Helsinki 8 GB relay,
v12 listens locally) and `scripts/pl-seat-relay.py` (v12 :19312 is that host's own node).
The gateway talks only to that local node over loopback; it never dials seats over
Tailscale and never touches the relay. Install steps: `deploy/INSTALL.md` (not yet run).

## Tiers (prices approved; limits are PROPOSALS for Scott)

| Tier | Price | Sustained | Burst | Monthly quota (units) | `fpl_submitTx` |
|---|---|---|---|---|---|
| Free | £0 | 5 req/s | 10 | 300,000 | 10 / min |
| Builder | £29 / month | 25 req/s | 50 | 5,000,000 | 120 / min |
| Scale | £199 / month | 100 req/s | 200 | 50,000,000 | 600 / min |

One read = 1 unit; `fpl_submitTx` = 5 units. Quotas reset on the 1st of each month,
00:00 UTC. Request body cap 64 KiB. All values live in `gateway.toml`.

## API
`POST /v1/rpc`, JSON-RPC 2.0, key in `Authorization: Bearer fplk_...` or `X-API-Key`.

| Method | Node message | Params |
|---|---|---|
| `fpl_status` | `status_req` then slimmed (tip, version, rails only; never the account or AMM dump) | none |
| `fpl_health` | `health_req` | `warnings` (max 64) |
| `fpl_getAccount` | `account_query` | `account` |
| `fpl_orderBook` | `order_book_query` | `pair`, `levels` (max 200) |
| `fpl_openOrders` | `open_orders_query` | `account` |
| `fpl_fills` | fills-store when `[market_data]` is on, else the node ring | `pair?`, `account?`, `from?`, `to?`, `cursor?`, `limit` (max 500 on the store, 200 on the node) |
| `fpl_pairs` | fills-store | none |
| `fpl_ticker` | fills-store 24h stats (observer time) | `pair?` |
| `fpl_candles` | fills-store (observer time, not verified UTC) | `pair`, `interval` (`1m`/`5m`/`15m`/`1h`/`4h`/`1d`), `from?`, `to?`, `limit` (max 500) |
| `fpl_submitTx` | `submit_tx` | `tx` (signed tx object) |

Nothing else is reachable: no admin (`WireMsg::is_admin`), mesh, snapshot or ctl
messages. Params can't set `type`. Errors: -32001 auth, -32005 rate/quota (HTTP 429 +
`Retry-After`), -32601 method not allowed, -32602 params, -32002 node unavailable (502).

Other routes: `GET /v1/health` (gateway + node probe, no key), `GET /v1/tiers`,
`GET /v1/usage` (caller's own month-to-date usage), `POST /v1/stream/session`
(short-lived SSE ticket), `GET /v1/stream?channels=book:BTC4-FPL,trades:BTC4-FPL,ticker:BTC4-FPL`
(SSE; send the API key or a ticket), `GET /metrics` on the metrics
listener, `POST /v1/billing/stripe/webhook` (stub; 404 unless enabled).

Streaming is charged at 1 unit to open and 1 unit per minute while open.
Free keys may hold 2 concurrent streams (Builder 4, Scale 8).
Candle and 24h times are **observer** arrival, not verified trade time.

`fpl_status` is forced `brief` at the node and then trimmed in the gateway so
Cloud users get tip height, version, and a slim rails summary only.

[market_data] (off by default) points at the fills-store API on beartec-brain:

```toml
[market_data]
enabled = true
url = "http://100.96.215.37:9478"
token_env = "FPL_GATEWAY_MARKET_TOKEN"
timeout_ms = 5000
```

## Abuse limits (`[abuse]`, all optional)
Unauthenticated surfaces are capped so they can't be used to hammer the node:

| Key | Default | Meaning |
|---|---|---|
| `health_rps` / `health_burst` | 5 / 20 | gateway-wide bucket for `GET /v1/health` (429 + `Retry-After`) |
| `health_max_concurrent` | 2 | node probes in flight; extra callers get the cached answer (503 if none) |
| `health_cache_ms` | 1000 | health result cache; repeat calls inside it never reach the node |
| `unauth_ip_rps` / `unauth_ip_burst` | 1 / 10 | missing/invalid key, per client IP (last `X-Forwarded-For` hop, set by Caddy) |
| `unauth_global_rps` / `unauth_global_burst` | 20 / 50 | missing/invalid key, gateway-wide |
| `max_tracked_ips` | 10000 | per-IP map is cleared when it grows past this |

Over budget, a bad/missing key gets 429 (-32005) instead of 401. Valid keys are never
affected by the unauthenticated budget.

CORS: `cors_origins` defaults to `["https://falcon-fpl.com", "https://www.beartec.uk"]`
(exact match, origin echoed). `"*"` still works but must be set explicitly and logs a warning.

Node replies: `fpl_orderBook`, `fpl_openOrders` and `fpl_fills` all accept the node's
`order_book` reply (what fd-pl v2.10.4 sends; checked against the live seed node);
`open_orders` / `fills` are accepted for forward compatibility. A reply of any other
type returns 502 "unexpected node reply" instead of being passed through.

## Keys and metering
Keys are `fplk_` + 64 hex, shown once by `fpl-gatewayd new-key`, stored only as
SHA-256 in `keys.json`, reloaded on SIGHUP. Usage per key/month is written atomically
to `/var/lib/fpl-gateway/usage.json` every 30 s and on shutdown.

## Portal keys (`[portal]`, off by default)

Self-serve keys bought via Stripe are minted by the Falcon Cloud portal
(Falcon-faucet-wallet, Postgres `falcon_cloud_keys` = SSOT). With
`[portal] enabled = true` the gateway polls the portal's internal export
(hashes only, never plaintext) every `interval_secs` and merges it with
`keys.json`:

```toml
[portal]
enabled = true
url = "https://falcon-fpl.com/api/falcon-cloud/internal/keys"
token_env = "FPL_GATEWAY_PORTAL_TOKEN"   # env var NAME; value = portal's FALCON_CLOUD_EXPORT_TOKEN
interval_secs = 60
timeout_ms = 5000
```

- `keys.json` (ops/local keys) always wins: a portal row with the same `id` or `sha256` is ignored.
- `disabled = true` rows and rows with an unknown/null tier never authenticate.
- Fetch failure keeps the last good portal snapshot (fail-static); restart starts with keys.json only until the first successful pull.
- SIGHUP still reloads `keys.json` and re-merges the current portal snapshot.

## Tests
```bash
scripts/test.sh     # cargo test --locked --all-targets: unit + mock-node integration
```
Standalone cargo workspace like `tools/fpl-operator`. No CI.
