# fpl-bridge (M2 regtest harness)
Upstream BitVM pinned at 7d1ca3660cac08aab62e76f3aa4daec0d7403ecc (MIT, see patches/BitVM-LICENSE-MIT),
fetched by `scripts/fetch-bitvm.sh` into `vendor/BitVM` (gitignored), then `git apply patches/*.patch`.
- `esplora_shim.py`: Esplora REST subset over local bitcoind regtest (port 8094, /regtest/api).
- patch: test faucet funds via local `bitcoin-cli` when `FPL_BTC_DATADIR` is set.

## Intake ceremony supervision (2026-11-13 OOM incident)

`intake/fpl_bridge_intake.py` now supervises BitVM2 ceremonies so a request cannot hang:

- **Concurrency cap:** `funded -> ceremony_pubkeys` is deferred while `FPL_MAX_CEREMONIES` (2) ceremony coordinators are live, or while free memory (min of host MemAvailable and the unit's cgroup headroom), minus the growth still to come from coordinators that are ramping up, is below `FPL_CEREMONY_MEM_MB` (4608) + `FPL_MEM_HEADROOM_MB` (1024). Waiting requests keep no kickoff reserved.
- **Coordinator supervision:** if a request is in a ceremony state without `final.json` and no live coordinator is found by /proc scan, the supervisor alerts and restarts the coordinator with exponential backoff, up to `FPL_COORD_MAX_RETRIES` (3) times, and only when a slot is free. This is only possible before `graphs.json` is published. After that, the participants' RAM-only nonces are tied to the graph, so the request is failed instead. If the local participant (RAM-only n-of-n key) is gone, the request is also failed.
- **Stage timeouts:** every non-terminal state has a timeout (`FPL_STAGE_TIMEOUT_<STATE>`). Pre-broadcast states time out to `failed`, which releases the kickoff and funding reservation and kills the local ceremony processes. This only happens after checking that neither peg-in tx is on chain or in the mempool. Post-broadcast states are never auto-failed, because the graph still needs the kickoff. They are flagged `stalled` and re-alerted every `FPL_STALL_REALERT_SECS`.
- **Alerts:** coordinator death, restart, failure and stall are logged and posted to the Discord health webhook (`FPL_DISCORD_WEBHOOK_URL` / `DISCORD_HEALTH_WEBHOOK_URL` or a 0600 `FPL_DISCORD_ENV_FILE`). The URL is never logged.
- `python3 intake/fpl_bridge_intake.py --plan` prints, read-only, what the supervisor would do to each live request.
- Tests: `intake/test_ceremony_supervision.py` (unit, fake /proc) and `intake/test_ceremony_oom_sim.py` (real processes; the coordinator is SIGKILLed like the OOM killer would; set `FPL_TEST_REAL_OOM=1` as root with systemd for a real memcg kill).
