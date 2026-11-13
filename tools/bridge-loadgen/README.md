# BTC4 bridge load generator (testnet 2300)

Extension of the existing Falcon PL loadgen for the BTC4 peg-in/peg-out bridge. Test id FPL-BTC4-BRIDGE-LOAD-2026-11-13.

- `falcon_pl_bridge_loadgen.py [config.env] once|run|pegout`
  - `once`: TC-1 (one peg-in then peg-out); `pegout`: peg-out only; `run`: batch loop.
  - Do NOT run it with `--help`: any unknown first arg is treated as a config path and the default command `run` starts.
- Batches: BATCH_SIZE_A (10) then BATCH_SIZE_B (20) legs, evenly spaced over BATCH_WINDOW_SECS (3600) with a small jitter inside each slot (BATCH_JITTER_FRAC, 0.25), BATCH_GAP_SECS (21600) between batches.
- Peg-in pacing: at most MAX_CONCURRENT_PEGIN_CEREMONIES (1) of our peg-ins may be between "funding sent" and "ceremony finished" (states in PEGIN_GATE_STATES, default awaiting_funding..signed). The slot is taken *before* the funding tx is broadcast, because the intake starts the ceremony when the funding confirms, and fundings that confirm in the same block would otherwise run their ceremonies at the same time (each coordinator uses about 4 GB; four at once OOM-killed one on 13 Nov 2026). Peg-ins left in flight by a previous process (legs.jsonl + intake) also count. A peg-in that cannot get a slot within PEGIN_GATE_WAIT_SECS (default = window) is recorded as `skipped`. Peg-outs are not gated; they keep the MAX_UNFINALIZED_CLAIMS cap.
- Stall alerts: a peg-in that stays in funded/ceremony_pubkeys/awaiting_signature/signed for PEGIN_STALL_ALERT_SECS (1800) raises one Discord alert per state. A leg timeout (LEG_TIMEOUT_SECS) raises an alert naming the stuck state (e.g. `signed`, which means the coordinator probably died).
- Tests: `python3 -m unittest discover -s tools/bridge-loadgen/tests -v`
- Every new wallet gets gen-wallet, FPL funding, PayToKey + key bind (ensure_key_bound) before any leg.
- Safety: PAUSE file, MAX_UNFINALIZED_CLAIMS, MAX_SPEND_SATS_PER_DAY, rail-lag gate, only touches loadtestNN accounts.
- Alerts: DISCORD_HEALTH_WEBHOOK_URL read from a 0600 `discord.env` sidecar (never in repo or logs).
- Install: copy to /home/falcon/loadgen/bridge, systemd unit `falcon-pl-bridge-loadgen.service`.
No bridge/operator/node code is changed.
