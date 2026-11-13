# BTC4 bridge load generator (testnet 2300)

Extension of the existing Falcon PL loadgen for the BTC4 peg-in/peg-out bridge. Test id FPL-BTC4-BRIDGE-LOAD-2026-11-13.

- `falcon_pl_bridge_loadgen.py [config.env] once|run|pegout`
  - `once`: TC-1 (one peg-in then peg-out); `pegout`: peg-out only; `run`: batch loop.
  - Do NOT run it with `--help`: any unknown first arg is treated as a config path and the default command `run` starts.
- Batches: BATCH_SIZE_A (10) then BATCH_SIZE_B (20) legs, spread randomly over BATCH_WINDOW_SECS (3600), BATCH_GAP_SECS (21600) between batches.
- Every new wallet gets gen-wallet, FPL funding, PayToKey + key bind (ensure_key_bound) before any leg.
- Safety: PAUSE file, MAX_UNFINALIZED_CLAIMS, MAX_SPEND_SATS_PER_DAY, rail-lag gate, only touches loadtestNN accounts.
- Alerts: DISCORD_HEALTH_WEBHOOK_URL read from a 0600 `discord.env` sidecar (never in repo or logs).
- Install: copy to /home/falcon/loadgen/bridge, systemd unit `falcon-pl-bridge-loadgen.service`.
No bridge/operator/node code is changed.
