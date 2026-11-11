# Discord alerts for the bridges (ETH/USDC relayer, BTC4 watch)

Optional. Same channel and rules as the node alerts on falcon-fpl.com
(Falcon-faucet-wallet `docs/NETWORK-HEALTH.md`): one post per problem, one ✅
recovery note when it clears, mentions off, up to 10 embeds per message.

## Config

| What | Where |
|---|---|
| Webhook | env `DISCORD_HEALTH_WEBHOOK_URL`, the node alerts' key. Read once at start. Unset = no-op (no posts, no state file). Must be `https://`. Never logged. |
| On a host | a root-only env file, `/etc/falcon-pl-alerts/discord.env` (0600), loaded by systemd `EnvironmentFile=`. Not in the repo, not in a unit file. |
| ETH dedupe state | `ETH_DISCORD_STATE`, default `run/bridge/eth-unminted-discord.json` |
| BTC dedupe state | `BTC_DISCORD_STATE`, default `/var/lib/falcon-pl-btc-alert-watch/discord.json` |

Shared code: `scripts/fpl_discord_notify.py`.

## Alerts

ETH/USDC (`scripts/pl-eth-lc-relayer.py daemon`), driven by the existing scans,
so the thresholds are the existing ones (`ETH_V3_UNMINTED_SEC`, default 1800;
`ETH_UNMINTED_DEPOSIT_SEC` for V1/V2):

- `eth:v3:<deposit_id>` / `eth:v12:<txid>`: deposit unminted past the threshold.
  Recovery only on positive evidence (`eth_v3_resolutions` / ETH-USDC
  `spent_deposits`), never because a throttled or partial scan did not list it.

BTC4 testnet4 (`scripts/pl-btc-alert-watch.py`, new read-only unit
`falcon-pl-btc-alert-watch.service`):

- `btc4:headers:stale`: rail tip behind the testnet4 explorer tip and unchanged
  for `BTC_HEADER_STALE_SEC` (1800). Why 1800 is in the script docstring.
- `btc4:submitter:<unit>:stopped`: unit not active for `BTC_SUBMITTER_DOWN_SEC` (120).
- `btc4:submitter:<unit>:failing`: `BTC_SUBMITTER_RESTARTS` (3) restarts in
  `BTC_SUBMITTER_WINDOW_SEC` (900).
- `btc4:deposit:<confirm txid>`: intake request `awaiting_mint` (>= 6 confs) for
  `BTC_UNMINTED_SEC` (1800) and not in BTC4 `spent_deposits`.

Many problems at once are batched (10 per message, at most 3 messages per pass,
2 s apart, 429 `retry_after` honoured); the rest go on the next pass.

## One-shot test messages

```
pl-eth-lc-relayer.py discord-test
pl-btc-alert-watch.py --test headers-stale
pl-btc-alert-watch.py --test submitter-stopped
pl-btc-alert-watch.py --test submitter-failing
pl-btc-alert-watch.py --test deposit-unminted
```

Each sends one message labelled `TEST: … (no action needed)` and touches no
alert state. The relayer one is
`TEST: Falcon relayer unminted-deposit alert (no action needed)`.

## Tests

```
python3 falcon-pl-rs/crates/fd-pl/scripts/test_fpl_discord_alerts.py
```

Offline. The webhook is a mock HTTP server on 127.0.0.1.

## Rollout (production: needs Scott's OK; falcon1 also hosts BTC services)

The webhook value lives in the Vercel env of the falcon-fpl.com project
(`DISCORD_HEALTH_WEBHOOK_URL`); it is not on falcon1 today. Scott puts it (or a
new webhook for the same channel) into the env file himself. Agents do not
copy it out of Vercel.
