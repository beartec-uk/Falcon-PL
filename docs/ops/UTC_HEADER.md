# UTC signed header (v5) — design notes & unfinished gates

**Status:** implementation started; **activation disabled** (`TESTNET_2300_UTC_FROM_HEIGHT = u64::MAX`, `TESTNET_2300_UTC_HELLO_ENFORCE_FROM_HEIGHT = u64::MAX`).
**Not production-ready.** Do not merge as “UTC live”. Do not bake a near-term `H_utc` until every seat is on a UTC-capable binary.

## What this change does

- Adds `Ledger.sealed_utc_ms` / `LedgerHeader.sealed_utc_ms` (serde default 0, omitted when zero).
- Defines `pl-ledger:v5|…|utc:{sealed_utc_ms}` in `utc_header::header_msg_v5`.
- When activation is **unarmed**, pack/verify continue to use **v4** preimages; field stays 0; mainnet/testnet behaviour matches pre-change binaries for sealed hashes.
- When activation is **armed** (`height >= H_utc`, `H_utc != u64::MAX`):
  - packer signs v5; `inner_hash` / `ledger_hash` / OK votes over `ledger_hash` cover UTC;
  - `seed_v2` uses the same domain-selected message;
  - live staging applies signed skew (5s ahead / 60s behind) vs OS wall; commit/catch-up apply **historical-only** rules (no wall rejection on replay).
- Preserves `sealed_at_ms` as synthetic chain physics / reward time unchanged.
- Status exposes `tip_sealed_at_ms` + quality `chain_physics`, and `tip_sealed_utc_ms` only when non-zero.

## Activation (must stay unset on live)

| Knob | Live 2300 | Devnet / tests |
|------|-----------|----------------|
| `TESTNET_2300_UTC_FROM_HEIGHT` | `u64::MAX` (disabled) | n/a |
| `TESTNET_2300_UTC_HELLO_ENFORCE_FROM_HEIGHT` | `u64::MAX` (disabled) | n/a |
| `FPL_UTC_FROM_HEIGHT` | **ignored** on 2300 | honoured on other network ids |
| `FPL_UTC_MAX_AHEAD_MS` / `FPL_UTC_MAX_BEHIND_MS` | ignored on 2300 | optional overrides |
| `FPL_UTC_HELLO_ENFORCE_FROM_HEIGHT` | **ignored** on 2300 | honoured on other network ids |

Arming requires a **separate** commit after every 2300 seat advertises `utc-header-v5` — not this PR. Baking today’s tip would make UTC activate immediately if that height has already passed by deploy time.

## Skew / bootstrap

| Rule | Status | Rationale sketch |
|------|--------|------------------|
| Max ahead of checker wall | **signed off 2026-11-07:** 5_000 ms | Refuse future-dated tips; matches existing `SEALED_AT_MAX_AHEAD_MS` order |
| Max behind checker wall (live only) | **signed off 2026-11-07:** 60_000 ms | Tolerate short stalls / NTP wobble; long stall → operational recovery |
| Parent monotonicity | PROPOSED: child ≥ parent when parent UTC > 0 | Prevent rewind of committed wall timeline |
| First block at `H_utc` | parent UTC may be 0; absolute skew only | Bootstrap without inventing parent UTC |
| Historical replay | no wall skew | Deterministic catch-up / archive restore |
| Stalled chain | no auto-widen on 2300 | Widening needs coordinated signoff; replay still works |

**Still open (not signed off):** whether monotonicity allows equal timestamps; monitoring alerts for tip UTC freshness.

## Test coverage in this PR (`utc_header` unit tests)

- Disabled-by-default on 2300; activation boundary
- v5 extends v4; mutated UTC changes commitment / inner hash
- Historical inactive rejects non-zero; active requires UTC + monotonic / first-anchor bootstrap
- Live skew boundaries; historical accepts ancient stamps wall would reject
- HMAC signature covers UTC field
- Stalled-chain: live BehindWall vs historical OK (operational recovery, not auto-widen)

## Unfinished gates (exact)

Consensus gates (t568u pass):

1. ~~**Hello / min-release peer gate**~~ — **DONE (code, unarmed).** `utc_header::utc_hello_hard_close_from` + `Node::hello_utc_capability_reject`: when Hello enforce is armed, peers lacking `utc-header-v5` are hard-closed from `min(enforce_from, H_utc − PROPOSED_UTC_HELLO_LEAD_BLOCKS)`. Closing the session is how Pack/OK from such peers is refused (`Node::utc_refuse_peer_pack_ok`, same predicate). `PROPOSED_UTC_HELLO_LEAD_BLOCKS = 1_000` is **signed off 2026-11-07**. Enforce unarmed (default; baked 2300 constant is `u64::MAX`) ⇒ advertise / soft-gap only, never hard close.
2. ~~**Injectable pack wall clock**~~ — **DONE.** `Node.utc_pack_clock: UtcPackClock { System | Frozen(ms) | Offset(ms) }` drives both `seal_v4_ledger` V5 stamping and live admission (`check_sealed_utc_live`). Production constructors (`Node::new`, snapshot load) use `System`. Tests inject per-Node clocks with no process-global state.
3. ~~**QC attestation wording**~~ — **DONE (docs).** See “QC / slash coverage” below. No new slashing rule.
4. **Devnet fork rehearsal** — **script DONE, process evidence: see milestone t568u.** `docs/ops/tools/utc_fork_rehearsal.sh` (2200 loopback, old binary from `OLD_REF`).
5. **Gossip / snapshot / disk round-trip soak** under armed devnet — restart evidence exists (t286u); long soak not done.

Policy items:

6. ~~**`H_utc` assignment for 2300**~~ — **rule signed off 2026-11-07; value not baked.** After every seat advertises `utc-header-v5`, a separate arming commit sets `TESTNET_2300_UTC_FROM_HEIGHT = T + 1_000`, where `T` is the live 2300 tip at that moment. Optional extra buffer `B` (blocks) may be added if a seat is still restarting: `H_utc = T + 1_000 + B`. Stays `u64::MAX` in this PR.
7. ~~**Hello-enforce height for 2300**~~ — **rule signed off 2026-11-07; value not baked.** Same arming commit sets `TESTNET_2300_UTC_HELLO_ENFORCE_FROM_HEIGHT = H_utc − 1_000` (`T + B`). Env overrides stay ignored on 2300. Stays `u64::MAX` in this PR.
8. ~~**Exact skew signoff**~~ — **DONE (2026-11-07):** 5_000 ms ahead / 60_000 ms behind. Parent monotonicity (child ≥ parent, equal allowed) remains PROPOSED.
9. ~~**Hello lead window signoff**~~ — **DONE (2026-11-07):** `PROPOSED_UTC_HELLO_LEAD_BLOCKS = 1_000`.
10. ~~**Release tag / version bump**~~ — **bumped 2026-11-07:** UTC shipped as `2.11.0`. Follow-up `2.11.1` (installer wire-compat for later 2.x, drop dead seed `:19311`). Follow-up `2.11.2` (unicast recert assist, one help per peer per height). Do not arm 2300.

Downstream (not consensus): explorer 1970 fix (P0, faucet #187), permanent fill IDs + cursor API (P2), public height+hash→UTC API (P3, after live H_utc), Crypto candles (P4; #618 must not claim `utc_committed`).

## 2300 arming rule (signed off 2026-11-07)

Worked example from live tip **825,993** at 08:34 Europe/Dublin on 7 Nov 2026 (`T = 825993`, `B = 0`): Hello-enforce would be **825,993** and `H_utc` would be **826,993**. Those numbers are an illustration only — they must be recomputed from the tip at the arming commit, after every seat is UTC-capable. They are not compiled into this binary.

Recommended operational order: ship this unarmed binary (optional quiet window while seats upgrade) → confirm every seat advertises `utc-header-v5` → then the arming commit above → only then resume heavy load if it was paused.

## QC / slash coverage (v5 wording)

- Once v5 is armed at a height, the packer signs the v5 preimage, which includes `|utc:{sealed_utc_ms}`. `inner_hash` and `ledger_hash` are derived from that preimage.
- OK votes (and therefore the QC / `LedgerCert`) sign `ledger_hash`. So an OK vote on a v5 ledger **attests to `sealed_utc_ms`** exactly as it attests to tx_root, state_root and committee root.
- Mutating `sealed_utc_ms` after sealing changes `ledger_hash`: the packer signature fails `verify_packer`, and every existing OK vote / QC no longer matches — the QC is invalid for the mutated ledger (tested: `rehearsal_multinode_network_utc_qc_agreement`, `mutated_utc_changes_commitment`).
- Two different `sealed_utc_ms` values at the same height by the same packer are two different ledger hashes: this is the **existing** equivocation / double-sign evidence shape, no UTC-specific slash rule is added. Pre-activation (v4) ledgers carry `sealed_utc_ms = 0` and are not covered.

## Ready / not-ready

| Claim | Status |
|-------|--------|
| Field exists on Ledger wire | yes (default 0) |
| v5 domain + test harness | yes |
| Live activation on 2300 | **no** (`u64::MAX`) |
| Skew numbers (5s ahead / 60s behind) | **signed off 2026-11-07** (unused until armed) |
| Hello lead window (1_000 blocks) | **signed off 2026-11-07** (unused until Hello-enforce is armed) |
| Arming heights | **rule signed off** (`H_utc = T+1000+B`, enforce = `H_utc-1000`); not baked |
| Release tag | **2.11.0 shipped;** follow-up `2.11.1` (installer wire-compat + drop `:19311`); follow-up `2.11.2` (recert-assist unicast) |
| Market API / candles ready | **no** |
| Safe to merge as draft for review | intended |
| Safe to deploy / arm | **no** |


## Milestone t281u (capability + rehearsal harness)

Added (still draft / unarmed on 2300):

- Hello `capabilities` (advertises `utc-header-v5`); hard close only when
  `Node.utc_hello_enforce_from_height` armed (default `u64::MAX`).
- Thread-local wall + `from_height` overrides for deterministic rehearsal
  (no process-global env races).
- `utc_rehearsal_tests` — **in-process simulation harness** (not multi-node soak):
  pre/post activation, forged utc, serde restart, live vs historical skew,
  soft capability gap vs hard enforce, seed_v2 binds utc, production defaults unarmed.

Still unfinished: real multi-node isolated process soak, injectable Node pack
clock beyond thread override, QC wording pass, P0 explorer, P2 fill IDs, H_utc.


## Milestone t284u — multi-node rehearsal

- `docs/ops/tools/utc_multinode_rehearsal.sh`: real multi-process loopback nodes on
  `127.0.0.1:29101+`, network_id=2200, hmac-dev, scratch `/tmp/falcon-utc-mn-*`.
  Status UTC metadata + Hello `utc-header-v5` + old-peer Hello vs private-net
  `FPL_UTC_HELLO_ENFORCE_FROM_HEIGHT` (2300 still ignores env).
- In-process `rehearsal_multinode_network_utc_qc_agreement`: 6-seat Network seals
  across H_utc with agreed tip hash + sealed_utc_ms + QC.
- Production H_utc / Hello enforce on 2300 remain `u64::MAX`.

## Milestone t286u — restart / compat (process evidence PASS)

- `docs/ops/tools/utc_restart_compat_rehearsal.sh` + `utc_hello_compat_probe.py`.
- **Unit** (`cargo test -p fd-pl --lib utc_`): 26/26 PASS — malformed/future/backward admission, historical replay outside live skew, Hello soft/hard, serde UTC round-trip. Distinct from process soak.
- **Process** (beartec-brain art `/tmp/falcon-utc-rr-artifacts-20261106T075728Z`, head `fb50253`):
  - Baseline 6-seat tip agreement past H_utc=2 with `utc_committed` (not counted as restart evidence alone).
  - Same-seat SnapshotSave → kill → reload: tip/hash/`sealed_utc_ms` restored (catchup_ok); log `loading snapshot` then `snapshot saved … tip=N` (N≥H_utc).
  - Hello: capable peer OK; old-empty/omit caps → Close (EOF + v1 log `utc-header-v5`); wrong network Close.
  - Isolation: `127.0.0.1:29201-29206` only, network_id=2200.
- Fixes on draft: force admin SnapshotSave before kill; v4 freeze debug_assert compares **sets** (order from sealed next-6) so debug restart does not panic.
- Production H_utc / Hello enforce on 2300 remain `u64::MAX`.

## P2 history API design (PR-only sketch — not implemented / not #618)

Goal: durable fill + block time queries **after** honesty labels exist; **do not** treat `latest`/`limit=200` ring as archive.

| Surface | Intent | Non-goal |
|---------|--------|----------|
| Fill ID | Stable id (height + index or hash) for cursor pagination | Equating RECENT_FILLS=200 with complete history |
| Cursor | Opaque durable cursor over ordered fills | Breaking existing ring endpoints without versioning |
| Block time | Return `sealed_at_ms` (physics) + optional `sealed_utc_*` when quality utc_committed | Inventing wall UTC from physics |
| Archive capacity | Inspect before promising depth | Silent truncation disguised as full history |

Implementation stays a **separate draft PR** after P0 honesty (#187 faucet) and unarmed #27 review. Crypto #618 candles remain blocked until live `utc_committed`.


## Milestone t568u — consensus gates (pack clock, Hello window, QC wording, fork script)

- Injectable `Node.utc_pack_clock` on the real seal + live admission path. Tests:
  `rehearsal_node_pack_clock_frozen_drives_sealed_utc_and_commitment` (6-seat Network, Frozen clock far from real wall ⇒ every seat seals `sealed_utc_ms == T`, QC at H, hash differs for T+1, pre-H hashes identical),
  `rehearsal_pack_clock_offset_and_frozen_unit`, `rehearsal_node_pack_clock_skewed_peer_rejected_by_live_admission`.
- Hello lead window: `rehearsal_hello_lead_window_matrix` (unarmed ⇒ Pass everywhere; armed non-2300 ⇒ Pass before `H−lead`, Close at/after; capable peers Pass), `rehearsal_hello_lead_window_inert_on_2300_defaults` (env set + test H override on 2300 still never closes).
- `docs/ops/tools/utc_fork_rehearsal.sh` — MODE=soft|enforce mixed old/new binaries on 2200.
- 2300: `TESTNET_2300_UTC_FROM_HEIGHT` and Hello enforce remain `u64::MAX`.

### t568u fork rehearsal — process evidence (box, 2026-11-07 ~04:36–04:39 UTC)

`utc_fork_rehearsal.sh`, loopback `127.0.0.1:29201-29206`, network_id 2200, H_utc=8,
NEW = this branch (v1–v4), OLD = `origin/main` @ `4321534` (v5–v6, no `utc-header-v5`).

| Mode | Observed | Interpretation |
|------|----------|----------------|
| `soft` (enforce unarmed) | All 6 seats agree through tip 7, then **halt at H_utc**: old v5 won h=8 and packed a v4-preimage ledger; every new seat logs `ingest fail h=8 … bad packer sig`. No seat committed h=8. | Mixed binaries at H_utc ⇒ liveness halt (no QC across the split), not a silent fork. This is why Hello enforce must be armed before H_utc. |
| `enforce` (`FPL_UTC_HELLO_ENFORCE_FROM_HEIGHT=8`, lead 1000 ⇒ close_from 0) | New seats logged 872 `utc-header-v5 capability required` Hello closes. New seats v1–v4 reached tip 8 (= H_utc) with one agreed hash; old seats isolated at tip 2. | Old peers cut off before activation; new side continues where it holds enough seats for soft QC; old side stalls isolated. |

Caveats: debug binaries, 4/2 split, single short run, `tip_sealed_utc_ms` not read by the summary (status field shown `None`). Not a soak. Nothing touched 2300.
