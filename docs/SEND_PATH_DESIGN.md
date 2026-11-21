# Falcon PL: a send path that scales (design)

Base: beartec-uk/Falcon-PL main e0d6ecb (2.11.9). File refs are
`crates/fd-pl/src/bin/falcon_pl_node.rs` (node.rs below) unless noted. Times are GMT, 21 Nov 2026.
Every number below was measured. Where something is a guess, it says so.

## 1. What the code does today

| Area | Code | Behaviour |
|---|---|---|
| Session threading | node.rs 4182 `peer_writer_loop`, 4256 `peer_session`, 4838 inbound `writer_task` | One tokio task per socket writes; a separate read task. No shared writer, no cross-socket scheduling. |
| Who dials | node.rs 4731 `we_dial` (`my_id < peer_id`) | The lowest id dials. **v1 dials every seat**, so all of v1's seat links are *outbound* `peer_session`s; everything inbound to v1 is a client or an outside peer. |
| Outbound lane order | node.rs 4487-4489 (biased select) | catch-up reply, then other replies (incl. **pieced** replies), then **cons (votes)**, then NeedLedgers, then body, then tx. Votes queue behind catch-up/reply lines on the same socket. |
| Inbound lane order | node.rs ~4877 | catch-up reply, then reply, then fanout (votes, bodies and tx mixed in one `inbound_rx`). |
| Per-line write | node.rs 265 `write_or_shed`, 409 `emit_or_shed` | Head-of-line: one line is written to completion. Must-send/catch-up/encoded-zstd lines wait up to `PIPE_STUCK_HOLD` 8 s (117-122), then **shed** (RST + `BLACKHOLE_SECS` 8 s, 133). Optional plain lines are dropped after 2 s; optional compressed lines are dropped *before* encoding (#58, 2.11.9). |
| Must-send set | node.rs 211 `line_must_send` | ledgers_batch, snapshot_chunk, ledger_body, LedgerBodyById, TxsByIds, TxsBatch, propose_ledger, and **every `piece` line**. A 1.5 MB LedgersBatch (lib.rs 9487 `CATCHUP_BATCH_MAX_BYTES`) becomes ~63 must-send pieces of 24 KB raw / 48 KB line (pieces.rs 18-28). |
| Second shed path | node.rs 477 `pipe_stuck`, called at the top of every writer loop (4427, ~4851) | Sheds when unsent **or unread** > 1 MB (`PIPE_SHED_BYTES`, 116) and not moving for `PIPE_SHED_HOLD` = **2 s**. 2.11.9 moved write_or_shed to 8 s but left this one at 2 s. |
| Serving outside peers | node.rs 5723 NeedLedgers handler; 4960-5050 inbound reader | Any Hello'd or non-Hello'd client may send NeedLedgers and gets up to 1.5 MB per request. The only brake is "inbound queue > 256 KB" for that one session. **No upload budget, no seat/non-seat distinction, no global cap.** |
| zstd framing | wire_zstd.rs 1-20, 109 `Compressor::frame`, 222 `encode` | One streaming context per direction. Each line becomes one flushed frame (`u32 len ‖ zstd`). Once a line is encoded it has to be sent, or the stream is broken. |

## 2. What we measured on falcon1 (v1) — read-only

* **falcon1's uplink is Wi-Fi on a home LAN.** Its uplink is `wlp2s0` 192.168.0.34; brain (.38) and falcon2 (.18, hosts v3 and scottdog) are on the same /24.
  Total NIC tx was **3,923 kB/s** (tailscale0 3,495 kB/s) over a 10 s sample at ~17:05.
* Per-socket v1 upload in that 10 s sample (ss bytes_acked deltas):
  * Seat links (outbound): v13 748 kB/s, v10 561 kB/s (289 KB send-q), v6 337, v3 301, v12 67, for about **2.0 MB/s** in total.
  * Inbound flows from the v12 host's relay (`falcon-pl-seat-relay.service`, `/usr/local/lib/falcon-pl/pl-seat-relay.py`, pid 274281) came to **855 + 272 + 117 + 75 = 1,319 kB/s** (send-q up to 240 KB).
    The relay forwards ports 19301/03/06/07/13 for four sources: 117.1.193.44, 193.117.230.208, 88.198.67.189 and 89.167.109.241 (spn, our seat).
  * In other words, **about 40% of v1's upload went to relayed peers, and 3 of the 4 sources behind the relay are not our seats.**
* Earlier, per-socket capture on v1 (15:3x): one relayed session sent **21.8 MB in 20 s plain**: `piece` 852, `pong` 67 and `propose_header` 17 lines. That is about 1.09 MB/s of must-send catch-up pieces to an outside peer that does not negotiate zstd.
* Sheds on v1 after zstd went on (15:28-15:56), all *outbound to seats*:

  | Seat | body | torn | send |
  |---|---|---|---|
  | v10 | 14 | 15 | 3 |
  | v13 | 14 | 0 | 0 |
  | v6 | 10 | 3 | 1 |
  | v3 | 0 | 0 | 4 |
  | v12 | 1 | 1 | 0 |

  One sample showed `reason=torn unsent=340488 unread=0`: the peer had read everything, and the bytes were sitting in v1's own send queue.
* CPU: falcon1 has 12 cores and a load average of 2.1; v1 uses 1.1-1.8 cores. Seat links are tailscale *direct*, not DERP. So it isn't CPU, and it isn't the relay path inside tailscale.
* With zstd on six seats (v12, spn, v6, v13, v10, brain) and **v1 off**: 11.9-12.0 s/block, max stall 47-72 s, 0-1 torn.
  After v3 and scottdog (both falcon2, same LAN) went on: 16.1 s/block. After v1 went on: **48.9 s/block, max stall 320 s**.

**Conclusion (measured plus reasoning):** v1's sends are bounded by a shared, modest uplink. Unbudgeted catch-up serving to outside peers takes about 40% of it. Votes and bodies to seats then wait in v1's kernel queues behind that traffic, and behind catch-up/reply lines on the same socket (lane order at 4487). Those waits cross the 8 s must-send hold (body/torn) or the 2 s `pipe_stuck` hold (send), and each one becomes a session reset that costs 8 s more.
zstd makes this worse in two ways. Its encoded frames can't be skipped once written. And its compression context means the link has to keep up rather than shed, so links that used to drop optional lines now hold must-finish frames. The seats with few links and fast uplinks are fine, which is consistent with all this.

## 3. Components evaluated

| Component | Verdict | Why |
|---|---|---|
| Priority lanes per peer (consensus > block/header > tx > catch-up/snapshot), one connection with a weighted scheduler and bounded per-lane queues | **Accept (P1 in part, P2 in full)** | The lanes already exist as mpsc channels (PeerOut 1096). Only the *order* and the *byte budgets* are wrong for a hub. P1 puts cons first. P2 swaps the biased select for a deficit-round-robin scheduler with per-lane byte budgets. |
| Separate TCP connections per lane | **Reject for now** | It would double sockets, dials, Hello gating and blackhole logic (4182-4253). TCP flows to the same peer share one bottleneck anyway, so it only helps head-of-line blocking. Pieces (≤ 48 KB) plus a scheduler give the same result on one socket. |
| Never reset a session for an optional lane | **Accept (P1)** | 2.11.9 already drops optional lines. P1 moves `pipe_stuck` to the 8 s hold, and stops serving optional catch-up to outsiders before it's encoded (refuse the NeedLedgers instead). |
| Non-blocking writer with credit/backpressure instead of 2 s/8 s timers | **Accept (P2)** | The writer still blocks one line at a time (385). P2 keeps per-lane deques and writes when POLLOUT says so, with no timeout-driven shed for anything except a peer that accepts 0 bytes for 30 s (a dead peer). |
| zstd per message vs streaming context with flush points | **Keep streaming, encode late (already), add a `zstd-frame-v2` capability in P3** | The stream ratio was measured at −41.4% on lean blocks. With *drop-before-encode* plus lanes, the only lines that get encoded are ones we've committed to send. A P3 independent-frame mode (per-message context reset, dictionary) lets even a half-sent frame be abandoned. That costs compression ratio, so it should be negotiated, not the default. |
| Per-peer and global upload budgets; quotas for non-seat peers | **Accept (P1)** | This is the main measured cause: about 1.3 MB/s of v1's ~3.4 MB/s went to the relay, much of it to outsiders. P1 adds a token bucket per non-seat session plus one global non-seat bucket, and refuses NeedLedgers from non-seats while the global bucket is in deficit. |
| Serve catch-up/snapshots from relay/archive nodes, not committee seats | **Accept (P3)** | Seats should not be the public fan-out. The relay on v12's host already concentrates outsiders. P3 points it at a non-seat archive/edge node instead of at the five seats. That is an ops/config change plus `--serve-public` (see Phase 2-3 below; default on until full nodes exist). |
| Topology: seat mesh plus edge nodes, falcon2 two seats on one host | **Accept (P3, ops)** | falcon1 and falcon2 sit behind one home uplink on Wi-Fi. Moving v1 (the dial hub) or falcon2's second seat to a wired/DC host is the largest single capacity gain. Code can't create bandwidth. |
| Adaptive compression (skip small or latency-critical lines) | **Accept (P2, local only)** | A vote line is about 1 KB, where zstd saves little and adds a flush. A raw frame inside the zstd stream needs a frame-type byte, which is a wire change, so it goes behind a `zstd-stream-v2` capability. P2 keeps v1 framing and only changes the level per lane locally. |
| Metrics and alerts | **Accept (P1 minimal, P2 full)** | P1: observer bytes, paced ms and refused NeedLedgers, added to the existing 150-tick `mesh sockets` log (node.rs ~4134). P2: per-lane queue depth, drops and sheds in `health`, with an alert on `uplink_busy` > 80% for 5 min. |
| Load test (2x/5x seats, 24+ tx/s) on brain at nice 19 | **Accept** | P1 ships a shared-uplink soak (`uplink_fanout_soak`) that models v1: zstd seat sessions plus plain outside pullers through one rate-limited uplink, old vs new. P2/P3 add a multi-process 18/45-seat localnet on brain. |

## 4. Phased plan

### Phase 1: make v1 + zstd stable (this PR)
Scope (node.rs only, no wire change, no activation height, no new capability needed):
1. **Upload budgets for non-seat peers.** `UploadBudget` (a token bucket that allows bounded debt).
   * An inbound session is a *seat* once its Hello id is in `validators`. Every other session (outside peers, relayed outsiders, ctl/load clients) is an observer.
   * The observer writer paces each line through a per-session bucket (`FPL_OBSERVER_SESSION_KBPS`, default 256) and a global bucket (`FPL_OBSERVER_UPLOAD_KBPS`, default 768). 0 means unlimited, which is the 2.11.9 behaviour.
   * Because pacing keeps the kernel queue low, paced sessions never shed.
2. **Drop before encode for observers.** NeedLedgers from a non-seat while the global observer bucket is more than 1 s in debt returns nothing (counted). Nothing is built, pieced or encoded, and the observer re-asks later (its own pull timer, LEDGER_SLOW_MS 154).
3. **Votes first on outbound sessions.** The biased select order becomes cons, then catch-up reply, then reply, then NeedLedgers, then body, then tx. Votes are small and bounded by `WIRE_QUEUE_BYTES`; catch-up can't starve because cons is rate-bound by rounds.
4. **`pipe_stuck` uses `PIPE_STUCK_HOLD` (8 s) instead of 2 s**, matching 2.11.9's write path. A queue over 1 MB that is still draining was already exempt; one that stays put for 2-8 s now gets the same grace as a must-send line.
5. **Metrics:** observer_bytes, observer_paced_ms and observer_refused added to the mesh-sockets log line.

Wire compatibility: unchanged bytes on the wire. Mixed 2.11.9/2.11.10 nets interoperate, and it doesn't need a hard fork.
Risk: an outside joiner syncs more slowly (≤ 768 kB/s shared, about 0.5 batch/s). That's acceptable; a seat is never paced. Lane reorder risk: a lagging *seat's* LedgersBatch now waits behind votes. Votes are under 1 KB at a few per second, so this is negligible.
Tests: unit tests for the bucket, `pipe_stuck` grace (fails on 2.11.9) and observer refusal; the full brain workspace plus snark; and the `uplink_fanout_soak` old vs new.
Effort: about a day including tests and soak.

### Phase 2 and 3: separate node roles so validators are not the gate

**Target:** 30 validators plus at least 5 independently run full/archive nodes, with anyone free to add more.
Validators do consensus and talk to each other. The public talks to full/archive nodes.
No validator, and no single operator, is the only way into the network.
#60 is the **interim protection**: it caps what outsiders can pull *from a seat* until full nodes exist. After Phase 3 a seat serves outsiders only as a last resort.

#### What exists today (code)
- **Roles already exist but are conflated.** `NodeRole { Archive, Hub, Val }` (lib.rs 781-829) plus `--role`, `--archive` and `--hub` (node.rs 1178-1191, 2569-2592).
  - `Val` caps the chain at `VAL_MAX_CHAIN` = 128 (lib.rs 791, node.rs 2965).
  - Roles are advertised in Pong (`pong_with_role`, node.rs ~5716) and Hello (`archive`, `is_hub`, `snap_height`).
  - Live, **v1 is a validator, the archive and the universal dialer all at once**. The relay docstring says "v1 :19301 is the archive. Observers pull the join snapshot from it" (scripts/pl-seat-relay.py 1-5).
- **Dial rule:** `we_dial(my, peer) = my < peer` (node.rs ~4731), so the lowest id (v1) dials all seats. Inbound from a lower id is refused ("we dial them").
- **Compact bodies already exist.** `LedgerBodyById` carries header plus tx ids, `assemble_body_by_id` builds the body from the local mempool, and misses are pulled with `NeedTxsByIds` → `TxsByIds` (node.rs ~5579-5615, ~6337-6354).
  - The dish (`TxsBatch`) is pushed first (`fan_pre_dish` ~2407, `DISH_GATE`).
  - So the hub still pushes the txs. What's missing is *announce, then pull* to every validator.
- **Tx intake:** `SubmitTx` → `fan_tx` (node.rs ~1884) goes to hubs first (`hub_peer_idxs`, ~1957, ~3020), then the mesh.
- **Catch-up source selection:** `catchup_candidates(&peers, &hub_peer_idxs)` (~1725). Snapshot pulls prefer archive-tagged peers (`fan_catchup` ~1595-1705). An untagged relay port is treated as a seed (~1604, ~1788).
- **Committee:** `committee_size` (lib.rs 3462, default 6 at 3549). The committee is selected from the validator set (lib.rs ~8819-8840).
- **Public entry:** `pl-seat-relay.py` forwards public 193xx ports straight to seats over tailscale (ROUTES in pl-seat-relay.py 9-16).

#### Roles (what each one serves)
| Role | Consensus | Talks to | Serves | Chain held |
|---|---|---|---|---|
| `validator` | votes/proposes if bonded and in committee | validator mesh plus ≤ K "sentry" full nodes it chooses | consensus lanes; compact bodies and `TxsByIds` to validators; *nothing public by default* (`--serve-public=false`) | short tail (VAL_MAX_CHAIN) |
| `full` | no | anyone | public sync (NeedLedgers/LedgersBatch), headers, RPC (status/account/submit), tx intake → forwards to validators, mempool relay | full RAM tail |
| `archive` | no | anyone | everything `full` serves plus join snapshots, history and disk bodies | full history plus snapshots |

`hub` becomes `full` (tx intake). The existing `Hub` maps to `full`, and `Archive` stays. A validator *may* also run `--serve-public` (small nets, today's testnet). That's the compatibility default until full nodes exist.

#### P2a: role flag and capability (2.12.0, no hard fork)
- **Flag:** `--role validator|full|archive`, parsed by `NodeRole::parse`. The old `val/hub/archive` spellings stay valid.
- **Capability:** the Hello capability `role-v1:<role>` is added in `utc_header::local_hello_capabilities` (utc_header.rs 343). Peers without it are treated as today.
- **Public serving off on validators:** a validator with `--serve-public=false`:
  - answers NeedLedgers/NeedSnapshot/RPC only from bonded validator ids (today's #60 `observer` flag, made a hard choice);
  - otherwise replies `Redirect{full_nodes}`. `Redirect` is a new message sent only to peers that advertise `role-v1`. Older peers just get nothing, as #60 already does when over budget.
- **Full nodes forward txs:** a full node forwards `SubmitTx` to validators on a dedicated `tx-intake` lane.
  - That lane has a per-source budget and dedup through the existing `remember_tx_relay`/`hold_unsent_tx_line` (~1848, ~1979).
  - Validators accept tx gossip from full nodes, rate-limited per source.

#### P2b: validator mesh and dial rule (2.12.x, capability `mesh-v2`)
- **No universal dialer.** Each validator dials D = 8 peers chosen by `hash(epoch_seed, my_id, peer_id)` rank (rendezvous hashing). The mesh is stable within an epoch and rotates between epochs.
  - Inbound is accepted from anyone in the validator set. With 30 validators and D = 8 that is about 16 links per validator, with diameter ≤ 3.
  - The committee is fully connected: each committee member also dials the other committee members (6 today), so vote latency stays one hop.
  - This replaces `we_dial` (lowest id dials) only between two `mesh-v2` peers. A mixed net keeps the old rule.
- **Gossip:** votes, headers and compact bodies are flooded on the mesh with a seen-set, using the existing per-lane dedup.
- **Sentries:** a validator may list sentry full nodes (`--sentries`). They are its only non-validator links, so the validator's IP need not be public. This is the Cosmos sentry pattern.

#### P2c: compact blocks everywhere (2.12.x, capability `compact-v1`)
- The packer announces `LedgerBodyById` (header plus tx ids) to the mesh instead of pushing the `TxsBatch` dish to everyone.
  - Each validator assembles the body from its own mempool and pulls the misses with `NeedTxsByIds` from the announcer *or any mesh peer that has them*.
  - All of these messages already exist (node.rs ~5579-5615).
- Expected effect (to be measured): body fan-out from the packer falls from N × body to N × (header + ids). A block of 20 tx × ~8 KB is about 160 KB as a body versus about 1-2 KB of ids. Misses are pulled from the mesh, not all from the hub.
- Fallback: a peer without `compact-v1` keeps getting the current dish plus body.

#### P2d: send scheduler (unchanged from the earlier P2)
- Per-session `LaneScheduler` with deficit round robin and per-lane byte caps.
- Writes only on POLLOUT. The only shed left is "0 bytes for 30 s".
- Pieces are schedulable units.
- Replaces the biased select at node.rs ~4487 and ~4877. It runs behind `FPL_SEND_SCHED=1` first, then becomes the default.

#### P3: public edge (2.13, mostly ops; no consensus change)
- **Seeds:** a signed seed list (`seeds.json` in falcon-pl-releases, verified with the existing minisign key) lists full/archive nodes only.
  - `--seeds` / the installer default point new nodes at it.
  - Anyone can run a full node and ask to be listed. Listing is a public PR, and nodes also learn peers from peers through `GetPeers`/`Peers`, gated by the `peers-v1` capability. That way the list isn't a single gate.
- **Relay:** `pl-seat-relay.py` ROUTES move from seats to full/archive nodes. Validator ports stop being published. v1's archive role moves to a dedicated archive host, so v1 stops being "the archive" (pl-seat-relay.py docstring).
- **RPC:** ctl/explorer/loadgen point at full nodes. Validators keep admin sockets only (`--admin-sock`, node.rs ~4142).
- **Hosting:** run validators on wired/DC uplinks. falcon1 and falcon2 are on home Wi-Fi/LAN (measured 3.9 MB/s total on falcon1); with roles split they can be full nodes.
- **Five-operator target:**
  - Scott runs 1-2 archives.
  - At least 3 more full nodes come from other operators: the installer gets a `--role full` path and a doc.
  - The release notes state measured requirements only.

#### Wire compatibility
Every new behaviour is behind a Hello capability: `role-v1`, `mesh-v2`, `compact-v1`, `peers-v1`. Peers without one see today's bytes.
The consensus rules, ledger format and committee selection don't change, so there is no hard fork and no activation height. The rollout order is:
1. Full/archive nodes go up first on 2.12, serving public traffic while seats still serve.
2. The relay and seeds switch over.
3. Validators set `--serve-public=false` one at a time, v1 last.
4. `mesh-v2` takes over once every validator advertises it.

#### Load test on brain (nice 19 / ionice idle, without stopping Dave's jobs)
- **Localnet:** 30 validator processes (committee 6, as `committee_size`), 5 full nodes (2 archive) and 1 loadgen on 127.0.0.x.
- **Shaping:** a `tc netem` uplink per validator: 3-8 MB/s, 20-80 ms RTT, 1% loss on 5 of them to mimic home links. It applies only to the localnet's loopback aliases/veths, never to brain's real interfaces.
- **Load:**
  - 24, 36 and 50 tx/s for 30 min each.
  - Plus 20 outside pullers (ctl sync loops) hitting the full nodes only.
  - Plus a validator restart every 5 min, so catch-up happens under load.
- **Compare:**
  - (a) today's 2.11.9 topology, with every node a validator, lowest id dials and outsiders on validators;
  - (b) #60;
  - (c) P2a + P2b;
  - (d) P2a-P2d.
- **Pass criteria:**
  - p99 block interval ≤ 2× the target;
  - 0 sheds on validator links;
  - votes delivered ≥ 99.9%;
  - tx delivered ≥ 99%;
  - no validator over 60% of its uplink;
  - full nodes take 100% of public bytes in (c)/(d).
- **Brain budget:** about 36 processes × ~150 MB, roughly 6 GB RAM. CPU at nice 19 will be slow because Dave's jobs run at a load of about 22. That's acceptable: report wall time, and don't pause his jobs unless Scott asks Dave.

#### Phases, effort and risk
| Phase | Scope | Effort | Main risk |
|---|---|---|---|
| P1 (#60, interim) | budgets for outsiders on seats, votes first, 8 s pipe_stuck | done (draft) | a slower outside joiner |
| P2a | role flag/cap, `--serve-public`, Redirect, full-node tx forward | 3-4 days | a joiner stuck if no full node is reachable (fallback: serve with #60 budget) |
| P2b | rendezvous mesh dial, committee full mesh, sentries | 4-6 days | partitions during the mixed-dial period; needs chaos tests |
| P2c | compact-block announce and pull everywhere | 3-5 days | miss storms when mempools diverge (bound with a per-block pull budget; fall back to the full body after 2 misses) |
| P2d | lane scheduler | 3-5 days | starvation bugs (property tests) |
| P3 | seeds/relay/RPC/hosting, installer `--role full`, peer exchange | 1-2 weeks incl. ops | operator coordination; seed-list governance |
| Load test | brain localnet 30 + 5 | 2-3 days to build, then reused | brain contention with Dave's jobs |

## 5. Results (Phase 1)
See section 6.

## 6. Phase 1 measured results


**Tests**
| Where | Commit | Result |
|---|---|---|
| Box, workspace except snark | b08677c | 861 passed, 0 failed, 5 ignored (2.11.9: 857/0/4 + 4 new + 1 ignored soak) |
| beartec-brain workspace (nice 19 / ionice idle) | b7a7333 | 861 passed, 0 failed, 5 ignored |
| beartec-brain workspace | b08677c | 861 passed, 0 failed, 5 ignored |
| beartec-brain snark | b7a7333 (b08677c only changes the ignored soak test in the node bin; snark does not build it) | 29 passed, 0 failed, 0 ignored (finished 18:51:40) |
| Old-code check | e0d6ecb + the new test | **FAILS**: `shed after 2.02 s (2 s hold)` |
| Old-code check | b08677c | passes |
| Portable build (brain, not a release) | b08677c | ok: glibc_min 2.34, avx512 node 0 / ctl 0, rustflags unset, dirty 0 (not signed, not published) |

**`uplink_fanout_soak`** (box, 120 s per run)
- Setup: one shared uplink at 3,900 kB/s (v1's measured NIC tx). Seat links run zstd and carry 4 votes/s, 20 tx/s × 8 KB, a 120 KB body every 12 s and a 63-piece LedgersBatch every 10 s. Plain outside pullers request 48 KB pieces as fast as they're taken.
- Seat readers pause for 4 s every 10 s.
- "old" means 2.11.9 behaviour: catch-up ahead of votes, a 2 s `pipe_stuck` hold and no budgets.
- This is a model of the writer loop (same `write_or_shed`/`ZWire`/`pipe_stuck_for`), not the full node.

| Case | Mode | Votes delivered | Vote p50 / p99 / max | Tx delivered | Body p50 / p99 | Sheds | Outside peers |
|---|---|---|---|---|---|---|---|
| 6 seats + 3 outside | old | 2798/2798 | 18 / 3917 / 4810 ms | 100% | 196 / 3457 ms | 0 | 2838 kB/s |
| | new | 2796/2796 | **1** / 3848 / 4002 ms | 100% | **4** / 3439 ms | 0 | 774 kB/s |
| + 4 s uplink stall every 20 s, autotuned sndbuf, 16 KB tx | old | 2528/2562 (98.7%) | 527 / 7017 / 8541 ms | 98.3% | 3293 / 7031 ms | **3 (body)** | 1547 kB/s |
| | new | 2768/2788 (99.3%) | **13** / 7432 / 8006 ms | 98.9% | **642** / 6934 ms | **0** | 704 kB/s |
| 2x: 12 seats + 6 outside | old | 5568/5591 (99.6%) | 755 / 5275 / 7139 ms | 99.6% | 1242 / 5190 ms | 0 | 1741 kB/s |
| | new | 5587/5587 | **1** / 3852 / 4003 ms | 100% | **4** / 3488 ms | 0 | 774 kB/s |
| 5x: 30 seats + 15 outside | old | 9466/13953 (**67.8%**) | 22239 / 70409 / 82309 ms | **6.4%** | 10013 / 75500 ms | 0 | 1326 kB/s |
| | new | 13641/13961 (**97.7%**) | 3191 / 7061 / 7640 ms | 20.1% | 7556 / 14066 ms | 0 | 772 kB/s |

How to read this:
- The p99 latencies of about 3.8 s in the no-stall rows come from the 4 s reader pause, the same in both modes.
- Phase 1 makes votes and bodies independent of outside-peer load: vote p50 goes from 18–755 ms to 1 ms, and outside peers are held to the 768 kB/s budget.
- The model reproduces sheds only with uplink stalls (3 body sheds old, 0 new). It doesn't reproduce the 66 sheds/28 min seen live, so how many live sheds Phase 1 removes still has to be measured on a canary.
- At 5x, tx delivery is bounded by the uplink itself (20% new vs 6% old). That is Phase 2/3 territory: scheduler, edge serving and moving v1 off home Wi-Fi.

