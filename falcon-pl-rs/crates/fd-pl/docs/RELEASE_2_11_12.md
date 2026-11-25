# Falcon PL 2.11.12: packer self-pass and gap-fill (testnet 2300)

**No activation height. No consensus change. Rolling-upgrade compatible with 2.11.11.**
4-of-6 commit QC and the packer lottery are unchanged. `missed_turns` is still
charged to the skipped round-0 seat when someone else seals the height.

## Why
The 23 Nov 2026 stage-2 run (20 wallets, intake split across v1/v3/v12/v13)
sealed short blocks (`walk_ready=false`, `min_depth=1`) because per-wallet
sequences arrived with holes. NeedTxs only pulled a walk-shaped export from
hubs, and `short_pack_hole` required a hub pool ≥ 400, so a 290-tx pool with
a 239 walk used the 800 ms grace and sealed. Silent or weak lottery winners
also sat out the ~12 s silence timeout before a view-change.

## What changed (local / wire-compatible)
* **Packer self-pass.** A current-round proposer that cannot pack in budget
  (no consecutive walk after the live pack window, `pack_over_budget`, or
  `force_memory_pressure`) immediately signs the existing ViewChange path
  instead of waiting the silence timeout. Committee peers that see that
  *signed* packer ViewChange follow immediately. 2.11.11 peers ignore the
  hint and still wait the full silence window. 4-of-6 still required.
* **Gap-fill pull.** When the packable walk is shorter than the local pool,
  NeedTxs may include `missing: [{account, sequence}]`. Empty `missing` is
  omitted, so the bytes match 2.11.11. A 2.11.11 peer ignores the unknown
  field and still serves the walk. 2.11.12 entries (including non-hubs)
  return the named head even when it is not in their walk. Pulls and grace
  still stop at `thin_walk_hold_ms` / `heads_stalled_before_skip`.
* **Local pool > packable is a hole.** Adaptive grace and further NeedTxs
  pulls no longer require a hub advertisement ≥ `pace_mempool_txs` (400).
* **NeedTxs / gap-fill logs** are rate-limited `info` (once per second).

## Config plan (applied at rollout, not in this binary)
Public / portal / loadgen entry seats should be hubs (or listed in every
packer's `--hubs`) so their inventory is dished and is a NeedTxs target.
Apply the `node.args` edit in the same restart as `falcon-node upgrade`
(one host at a time). Expected extra traffic: v12/v13 will dish and serve
NeedTxs; pieced/lane pressure may rise there.

Hub set (v1, v3, v12, v13):
`100.95.77.59:19301,100.115.112.95:19303,100.108.39.55:19312,100.106.108.37:19313`

Exact `--hubs` / `--hub` diffs vs 2.11.11 `node.args` (30 Oct):

* **v1** (already `--hub`): `--hubs 100.115.112.95:19303` → `--hubs 100.115.112.95:19303,100.108.39.55:19312,100.106.108.37:19313`
* **v3** (already `--hub`): `--hubs 100.95.77.59:19301,100.115.112.95:19303` → add `,100.108.39.55:19312,100.106.108.37:19313`
* **v6, v10, v11, scottdog** (not hubs): same `--hubs` expansion as v3. **v11 is not adopted** (`falcon-pl-v11.service` still starts `falcon-pl-val` from the 2300 tree); change its unit and restart only after the adopted seats on that host are healthy.
* **v12, v13**: add `--hub` (keep `--join`); expand `--hubs` the same way.

## Follow-as-work
A signed packer self-pass is treated as work on followers even when their
local pool is empty (missing heads often sit on other entry seats). Without
that, only the packer would vote early and the other five would still wait
the silence timeout.

## Tests
* `local_pool_deeper_than_walk_is_a_hole`, `one_head_equal_to_pool_is_not_a_local_hole`
* `serve_need_txs_fills_named_missing_head`, `packer_absorbs_gap_fill_and_walk_becomes_packable`
* `need_txs_empty_missing_serializes_like_2_11_11` (mixed-version bytes)
* `packer_self_pass_votes_before_silence_timeout`
* `packer_self_pass_memory_pressure_and_over_budget`
* `follower_votes_immediately_on_packer_self_pass_legacy_waits`
* `missed_turns_still_charged_after_self_pass_view_change`
