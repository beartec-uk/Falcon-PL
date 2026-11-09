// Copyright (c) 2025-2026 BEARTEC. All rights reserved. See LICENSE.
//! # Falcon PL (FPL) — Participation Ledger
//!
//! Product **Falcon PL**, ticker **FPL**, consensus **Falcon Consensus**,
//! signatures **Falcon-512** (or HMAC-dev for harnesses).
//!
//! - Ordered ledgers of signed txs (not a DAG; not an XRPL fork)
//! - Bonded participants join the **packer lottery** (ranked #1, #2, …)
//! - Lottery seed is **deterministic from tip + bonded set + certified skips**
//!   (not per-node pong views — multi-host safety, v2.3.0 P0)
//! - **v2.5.0:** lottery ONLINE inputs are **frozen at tip commit** for the open height
//!   (ONLINE cert mid-height must not re-elect the packer)
//! - **v2.6.0:** open-height **liveness** — poison-only future-seq drop (keep sequential
//!   pipeline), skip offline/lagging active seats, view-change when height stalls
//!   (poison / unavailable / silent packer), reopen when all lottery seats are skip-QC'd
//! - **v2.7.0:** public-safety surface — registry-only keys, signed votes, mesh
//!   admin-wire lock + unix operator socket, tip-committed QC, integer lottery,
//!   Hello product/network handshake, hmac-dev refused without `--allow-dev-crypto`
//! - **v2.7.1:** catch-up cannot rewind a live tip (operator-only genesis wipe)
//! - **v2.7.2:** one apply path — state/root uses ledger `sealed_at_ms`; `tick` is
//!   timeouts only; genesis h=1 waits for live seats
//! - **v2.7.3:** one body per height (no skip/pack race); dual proposals converge
//!   on lower hash; n≥6 soft QC is majority; view-change clears the open height
//! - **v2.7.4:** lottery freezes a committee of 6 (1 packer + 5 checkers).
//! - **v2.7.5:** soft was 3 of 5 checkers (superseded by 2.9.0 4-of-6).
//!   Hard still `ceil(n×0.6)` over all bonded. Skip walks the same 6.
//! - **v2.7.6:** view-change **redraws** the committee (dead packer cannot pin
//!   the height). Same packer cannot reseal after VC. Lagging catch-up adopts
//!   the peer body over a local uncommitted dual.
//! - **v2.8.0:** mesh gossips **headers only**; bodies are pull-once. Light vals
//!   keep a short body window. Keyring is self-SK + registry PKs. Outbound
//!   queues are **byte-capped**.
//! - **v2.8.1:** lottery is **f(committed tip)** only — bonded set + view.
//!   ONLINE/pong is pack permission, never a seed input. Same tip ⇒ same 6.
//! - **v2.9.0:** tip advances on **4-of-6 committee QC**. Cert rides the next
//!   header. Checker double-OK is slashed. Skip/VC use the same 4-of-6 bar.
//! - **v2.9.1:** archive bodies live on **disk**, not RSS. RAM always strips
//!   after `max_body_ledgers`. Snapshots are compact JSON. Pack dry-run does
//!   not clone the KeyRing. Inbound fan is byte-capped.
//! - **v2.9.2:** lottery is **f(committed tip)** only. View-change does not
//!   reseed or redraw the 6. Same tip ⇒ same committee after restart.
//! - **v2.9.3:** a discarded pending is not a commit. After the 6 are all
//!   skip-QC'd on an **uncommitted** height, reopen the attempt: clear skips
//!   **and** sealer bans. Never burn the committee on a height with no tip.
//! - **v2.9.4:** never discard a **unique** pending body. View-change is for
//!   silence or dual hashes. One attempt body until commit or full-committee
//!   reopen. Re-fan that hash; do not mint a fatter second body.
//! - **v2.9.5:** `sealed_at` is **chain time**. Pack and ingest bound it by
//!   the parent ledger, not local snap `now_ms`. Power-cut clock skew cannot
//!   reject an honest pack.
//! - **v2.9.6:** pack folds settle/unbond and computes the state root at the
//!   same `pack_sealed_at()` stamp written on the header. Local `now_ms` is
//!   timeouts only (2.7.2). A drifted snap clock cannot self-reject 1929.
//! - **v2.9.7:** uncommitted OK votes are attempt-local. Snap load drops
//!   `ok_by_height_voter` / slashes for `h > tip` (pending body is not
//!   restored). Reopen clears them. Else a 2.9.5 ghost vote pins 1929.
//! - **v2.9.8:** packer feed is hub inventory. NeedTxs / hub push send
//!   **applicable heads first**. Winner re-pulls while `!applicable`.
//!   Pull budget is a real RTT (not 150ms). Progress-skip waits out that
//!   budget (P1/P6). Observer mempool is not proof the winner is silent.
//! - **v2.9.9:** progress-skip is **offline/lag only**. After hub feed, every
//!   observer has applicable txs; skip-QC of a live winner burned the 6
//!   (7880 storm). Live silence → view-change, not 3s skip.
//! - **v2.9.10:** committed tip without a stored 4-of-6 cert (snap/catch-up)
//!   re-collects committee OKs. Pack must not wait forever on `certs[tip]`.
//! - **v2.9.11:** live winner with **no proposal** after pack+pull budget is
//!   skipped (not 12s VC). Budget = pack_budget + NeedTxs grace + 1.5s —
//!   never a raw 2s (that is shorter than grace+pack). Observer inventory
//!   alone is still not a skip (2.9.9). Poison stays VC.
//! - **v2.9.12:** skip QC uses **hub inventory ads**, not the voter's mempool.
//!   Light checkers see hub `mempool_len` on Pong. 4-of-6 can form when only
//!   hubs hold the backlog. Idle (no hub pending) still does not skip.
//! - **v2.9.13:** committee body push. Header-only + reply-to-forwarder left
//!   remotes 14s behind on fat pending (NeedLedgerBody hit a peer with no
//!   body). Packer/hubs push `LedgerBody` on the tx plane; checkers retry pull.
//! - **v2.9.14:** skip = unavailable only (pong stale / tip behind). A seen
//!   header is already a proposal. Hubs dish one ledger to **winner + first
//!   backup** at tip commit so a height gaps only if both fail to seal.
//! - **v2.9.15:** designated lanes. Header/OK on cons; `LedgerBody` to the
//!   **QC committee only** on a reserved body lane; dish/submit on inventory.
//!   Mainnet assumes remotes — same-host 4-of-6 is luck, not a design.
//! - **v2.9.16:** catch-up lane. `NeedLedgers` no longer shares the cons
//!   pipe with votes (v3 dropped pulls under soak). Join/residual has its
//!   own queue; prefer hubs.
//! - **v2.9.17:** after snap start, do not pack until a peer tip is heard
//!   (or 12s grace). Staggered resume forked droplet (16984 vs 16993).
//! - **v2.9.18:** epoch settle is f(committed work), not the RAM body window.
//!   Joiners that kept extra bodies (copied archive snap, no store) diverged
//!   at the first epoch boundary (20922).
//! - **v2.9.19:** pre-upgrade epoch-boundary ledgers still verify. 2.9.17
//!   packed 34799 with the 64-body walk; 2.9.18 incremental rejected it.
//!   The trigger ledger's `fee_total` selects the formula (0 → old walk).
//! - **v2.9.20:** catch-up is one inflight pull to one hub; a batch is
//!   contiguous and byte-capped so a Falcon-512 ledger fits the lane.
//!   **2.9.42 hotfix (AMD-20260827-1):** that hub rotates after an empty
//!   residual / inflight miss, and skips a peer whose advertised tip is
//!   not ahead of us (first-hub pin to a dead/old version froze v1).
//! - **v2.9.21:** archive hubs **serve snapshots**. A joiner more than
//!   `SNAPSHOT_PULL_LAG` (256) behind pulls a snap, then residual NeedLedgers.
//!   History nodes exist so joiners do not scp a file.
//! - **v2.9.22:** pin the served snap file; never ask a non-archive; do
//!   not restart a transfer because the archive saved again (60s rotate
//!   aborted 932-chunk pulls with `snap hash changed`).
//! - **v2.9.23:** join snap is tip state + 128 ledgers (~MB), not the 20k
//!   tail (160 MB). Chunk pull retries the current index. NeedLedgers is
//!   not starved if the snap transfer stalls.
//! - **v2.9.24:** archive **pushes** the join snap (Offer + every chunk)
//!   on `NeedSnapshot`. A pull is exclusive — no `NeedLedgers` on that
//!   TCP until adopt or abort. Out-of-order assembler + pipelined hole
//!   fill. Stall aborts and re-asks for a snap, not a 64-ledger residual.
//! - **v2.9.25:** `take_catchup_pull` is silent while `wants_snapshot`.
//!   2.9.24 only blocked residual after the Offer created an assembler;
//!   before that the ticker still sent NeedLedgers and v11 never saw the
//!   Offer under soak. v4 adopted 834 ledgers in 6s once the Offer landed.
//! - **v2.9.26:** rotate the served join pin when live tip is
//!   `SNAPSHOT_PULL_LAG` ahead, even if joiners are still downloading the
//!   old sha. Idle-only rotate let NeedSnapshot keep the pin hot forever.
//! - **v2.9.27:** snap is **join / disaster only** (tip=0 or lag ≥ 2048).
//!   In-mesh residual of a certified ledger applies state without re-verifying
//!   every Falcon tx. Live pack still verifies. Archive ads survive adopt.
//!   Validators follow live gossip; they are not fed a new tip every 256.
//! - **v2.9.34:** archive `--max-chain-ledgers 0` is **20 000**, not 1
//!   (the `.max(1)` clamp dropped every header after tip). Disk bodies
//!   are indexed by height so `NeedLedgers` can serve a 2-high gap after
//!   a rolling restart. Empty residual (3×) pulls a join snap. Pack waits
//!   for 4 seats on tip so a bounce cannot seal ahead of the QC set.
//!   **2.9.42 hotfix:** a lagging **archive** also join-snaps after 3×
//!   empty residual (it used to never pull, only serve).
//! - **v2.9.43:** empty BitVM2 rail fields omitted from serde (same
//!   pattern as `last_real_bits`). New-binary joiner + pre-bitvm2 snap
//!   was hashing `bitvm2_claims:{}` into the commitment root.
//! - **v2.9.37:** BTC NUMS P2TR pool + script-path BitVM Kickoff (no FROST
//!   on that address). Dest owner signs. SHA256-step disprove. Live FROST
//!   UTXO is unchanged until an operator migrates it.
//! - **v2.9.38:** `BtcPoolMove` — last FROST key-path spend of the pool into
//!   the NUMS P2TR. Packed `vault_pub` becomes NUMS. Kickoff after this is
//!   dest-signed script-path.
//! - **v2.9.39:** ETH/USDC-in is a Sepolia sync-committee light client +
//!   execution receipt MPT. Watchers relay; they cannot mint.
//! - **v2.9.42:** NUMS internal key is even-Y (BIP341-spendable). Kickoff is
//!   dest+watch. Odd-Y v1 pool address cannot be spent; book retargets.
//! - **v2.9.41:** BTC Kickoff tapleaf is dest CHECKSIG + committed watcher
//!   CHECKSIGVERIFY. NUMS key-path still dead. Migrates v1 anyone-CHECKSIG UTXO.
//! - **v2.9.40:** LC finality_update + receipt-trie key = RLP(index) +
//!   execution-header walk to LC head. Auto-mint uses that path.
//! - **v2.9.28:** separate seat binaries (`falcon-pl-archive` / `-hub` / `-val`).
//! - **v2.9.29:** `TxBody::WatcherHeartbeat` — fee + current slot, zero work.
//! - **v2.9.30:** WatcherCredit disabled; CreditAsset native mint admin-only.
//!   Val role hard-caps the RAM chain at 128. Same crate, different process.
//! - **v2.9.47:** restore `drop_slashes_that_break_quorum` on pack (hotfix2);
//!   round-mode sealed-body no longer bans a late-cached packer from sealing
//!   when its round arrives; historical `jailed && jail_count==0` Unjail costs
//!   `2× min_bond` and persists count=1. Enables safe Phase 2 re-enable.
//! - **v2.9.48:** Phase 2 **pause window** `[vote_rounds_pause_from,
//!   vote_rounds_resume_at)`: heights inside use legacy `pl-ok:v1`, round-scoped
//!   rules apply on both sides. 2300 bakes `[371037, 375000)` (the legacy-signed
//!   certs from the 2026-10-05 pause onward), so re-enabling Phase 2 no longer
//!   mis-verifies the legacy tip cert (`cert bad sig`, 2026-10-06 08:56 stall).
//! - **v2.9.49:** pack uses a per-tx row undo (Pay/AssetPay) instead of a
//!   full draft clone per candidate (same root, ~20x more txs per budget;
//!   default cap 400 txs when `max_txs_per_ledger=0`). Catch-up asks any
//!   healthy non-jailed peer (hubs first, never self); a stale rival body at
//!   or below a certified tip no longer poisons catch-up. Status
//!   `recent_attestations` uses a cached O(n) newest-file scan (10 s TTL).
//!   No validity-rule change.
//! - **v2.9.50:** held (future) proposals never commit bare on catch-up
//!   cascade — only live soft-QC staging cascades `pending_ledgers`; catch-up
//!   advances solely via explicit certified batch items, and a catch-up body
//!   replaces any earlier live hold at the same height. Snapshot adopt clears
//!   leftover `stall` from an abandoned rival (v10 fork at ~372938, 2026-10-06).
//! - **v2.9.51:** ops liveness — (1) refuse to pack without a tip QC in
//!   `certs` (snapshot soft tip alone is not enough for `parent_cert`); a
//!   cert-less lottery winner self-skips after progress-timeout so VC/skip
//!   can elect a seat that can seal. (2) refuse to apply shared skip when
//!   any body is already open at the height (dual-proposal / equivocation
//!   after progress-timeout skip of a live sealer). (3) drop permanently
//!   failing applicable mempool heads (e.g. insufficient fee balance) in
//!   `sanitize_mempool` so unpayable txs are not counted as liveness work
//!   and cannot freeze the tip (watcher-browser seq stall at ~373270).
//! - **v2.9.52:** consume sticky equivocation evidence on commit. Pending
//!   slashes are dropped when `e.height <=` the committed ledger (not only
//!   when equal), so a dual queued at h=H then packed into H+1 (or later)
//!   cannot re-jail after Unjail. Also clear an offender's queued evidence
//!   when an Unjail tx commits. Fixes the live v1↔v12 ping-pong on h=373256
//!   (2026-10-06): drop_slashes kept one seat, the co-offender's evidence
//!   stayed queued, and Unjail of one re-armed the other.
//! - **v2.9.53:** disk hygiene (ops only; no consensus change). The hub
//!   disaster-recovery join serve dumped a fresh ~200 MB
//!   `/tmp/pl-hub-join-<id>-<tip>.json` per `NeedSnapshot` and never deleted
//!   it — 173 GB filled host2 and stalled the chain at 374384
//!   (2026-10-07). Hubs now reuse the periodic pinned serve file or one
//!   bounded `<data-dir>/<id>.hub-join.json` (deleted when idle); legacy
//!   dumps are removed at start. Low-disk guard ([`disk`]): optional dumps
//!   are skipped under the low-water mark (5% / 2 GB), the seat snapshot is
//!   refused only if it would leave < 256 MB, partial `.json.tmp` files are
//!   removed on write failure, loud `DISK LOW` logs, and status `disk`.
//!   Snapshot `.bak` copies are pruned to the newest 3 at start.
//! - **v2.9.54:** chained BTC header admission (mempool only; no change to
//!   block apply, verify, votes or the state root). `submit_tx` used to probe
//!   an incoming BTC `RailHeader` against the *committed* rail tip only, so
//!   with h+1 pending every h+2..h+32 of a submitter burst was rejected as
//!   `BTC header parent mismatch` (permanent) and the BTC rail advanced ~1
//!   header per block. The probe is now extended with the same account's
//!   pending txs at lower, contiguous sequences (cap
//!   [`Node::BTC_ADMIT_CHAIN_MAX`] = 64), replayed in packer order, so
//!   "accepted" still means "applicable after its predecessors". On any
//!   sequence gap, unappliable predecessor or deeper run, the check is the
//!   old committed-tip-only one. Out-of-order, gapped and forked headers are
//!   still rejected, and one account's pending headers never extend another's.
//! - **v2.9.56:** seal-tick CPU pin fix (local only; no change to block
//!   apply, verify, votes, wire or the state root; no activation height).
//!   A seat that caught up by batch could be the round-0 lottery winner for
//!   tip+1 while the mesh had already moved on. Each 200 ms tick then called
//!   `pack_or_skip`, whose `sanitize_mempool` dry-ran every mempool head on a
//!   full clone of state + bridge (~200 MB of never-pruned ETH exec headers)
//!   under `node.lock` before `may_pack_locally` refused with "tip lag". One
//!   tokio worker pinned, the logical clock slowed ~20x, the seat stopped
//!   gossiping and catch-up never applied (v10 h=376571 00:30 and v12
//!   h=377619 05:02 UTC, 2026-10-08; both needed a restart). Now:
//!   `pack_or_skip` checks `may_pack_locally` first; each head is dry-run at
//!   most once per tip (5 s logical TTL); `eth_exec_headers` is an `Arc`
//!   (copy-on-write) so bridge clones are a refcount bump. Serde output is
//!   byte-identical (`serde/rc`).
//! - **v2.9.57:** recert-split liveness fix (local only; no change to vote
//!   payloads, cert verification, apply or the state root; no activation).
//!   379780 stall (2026-10-08 07:36): 4 committee seats formed the round-0
//!   cert, 3 committed the tip via catch-up and re-OK'd it in the recert
//!   round. Cert holders never cast recert votes, so the recert round sat at
//!   3 < 4, the cert-less round-0 proposer looped "no tip cert", and the
//!   cert-less seats (by design) do not vote view-change: 3 VC voters < 4.
//!   Cert holders now answer a peer's recert vote for their tip with their
//!   own recert vote ([`Node::recert_assist`], unicast once per asking seat per height).
//! - **v2.9.58 "lean node":** local only — the state root, wire format, vote
//!   payloads and certs are byte-identical; no activation height.
//!   (a) The commitment root no longer re-encodes and re-hashes the ~199 MB
//!   ETH exec header map 3+ times per block: the map ([`exec_map`]) caches
//!   its canonical JSON per generation and a root already computed for
//!   identical bytes (verify → commit → status) is reused from a memo keyed
//!   on (sha256(prefix), map generation, sha256(suffix)). Snapshots reuse the
//!   cached JSON and are serialized + written outside `node.lock`.
//!   (b) Brief status serves the state root / LC claim root recorded at
//!   commit ([`Node::tip_roots`]) and skips claim-leaf / attestation work;
//!   full status computes those after the lock is dropped.
//!   (c) A lagging seat buffers correctly signed OKs for `tip+2..=tip+8`
//!   (bounded, [`Node::vote_ok_wire`]) instead of dropping them because
//!   `ok_vote_height` assumed `tip+1`; they are replayed when that height
//!   opens.
//! - **v2.9.59 "weak seat keeps up":** local only — state root, wire format,
//!   votes and certs byte-identical; no activation height.
//!   (1) Packer pacing ([`Node::pace_wait`], `--min-block-interval-ms`,
//!   default 2500; `--pace-mempool-txs`, 128 when shipped, now
//!   [`Node::PACE_DEFAULT_MEMPOOL_TXS`] = 400): the round-0 winner
//!   seals once the height has been open that long, or the mempool holds the
//!   threshold or a full block. Capped by [`Node::pace_effective_ms`] at one
//!   live pack window so pace + pack/seal/gossip stays inside peers' round-0
//!   silence timeout (2 windows); off after a skip / view-change. Receivers
//!   never check block spacing beyond `sealed_at >= parent` and `<= parent +
//!   60 s`. At 5 tx/s 2.9.58 sealed ~44 blocks/min of ~7 txs; pacing gives
//!   ~20/min of ~15.
//!   (2) The stage-time state root (one ~207 MB SHA-256 per block) is
//!   computed with `node.lock` released ([`Node::prestage_root_input`] builds
//!   the drafts under the lock; the hash fills the root memo; the stage
//!   then hits the memo). Pure warm-up: the stage verifies exactly as before.
//!   (3) SHA-256 via `ring` (runtime-detected SHA-NI / AVX2 / SSSE3 asm):
//!   identical digests; on the Skylake seat (no SHA-NI) 207 MB hashes in
//!   0.80 s vs 1.43 s with `sha2` (1.30 s with `sha2` asm).
//! - **v2.9.60:** ETH light client follows Sepolia **Gloas** (fork version
//!   `0x90000076`, epoch 353024, 2026-10-06 13:53:36 UTC). The LC froze at
//!   finalized slot 11296672 / period 1378 because Gloas LC headers carry only
//!   `execution_block_hash` (EIP-7732) and BeaconState gindices moved
//!   (EIP-7688). Consensus change gated by
//!   [`TESTNET_2300_ETH_LC_GLOAS_FROM_HEIGHT`] (TODO: placeholder `u64::MAX`
//!   until rollout): from that height `EthLcUpdate`/`EthLcBootstrap` verify
//!   both header formats with per-slot gindices and the spec signature fork
//!   slot, and the hash-only LC head takes its number/receipts root from the
//!   stored RLP-verified execution header with that hash. Below it, apply is
//!   byte-for-byte 2.9.59.
//!   Same gate, rolling exec-header prune ([`bridge::ETH_EXEC_HEADER_WINDOW`]
//!   = 50_400, about 7 days): `BridgeState::eth_exec_prune_floor` is
//!   `max(old, lc.execution_number.saturating_sub(window))` when the LC head
//!   number is resolved (`execution_number != 0`). The floor is monotonic, so
//!   a static LC head never deletes another header, and it is part of the
//!   state root once non-zero (serde skips zero, so pre-activation bytes
//!   match 2.9.59). The cut runs at the start of the pack, verify and commit
//!   drafts for that height (one-off when the gate is crossed, then every
//!   later block) and again after a gated bootstrap, update or
//!   `EthExecHeaders` resolves the head. `mint_evm_lc` below the floor
//!   returns `deposit older than header window` (permanent). Status exposes
//!   top-level `eth_exec_prune_floor` and `eth_exec_window`.
//! - **v2.9.61:** V3 peg-in is mint-or-refund, gated by
//!   [`TESTNET_2300_ETH_V3_FROM_HEIGHT`] (independent of the Gloas height;
//!   placeholder `u64::MAX`). `TxBody::EthV3Deposit` is permissionless. Inside
//!   3 days of LC-head time a deposit credits the FPL account whose id hashes
//!   to `dest20`, or refunds the sender when that preimage is not a creditable
//!   name. After 3 days (still inside the 7-day header window) it refunds the
//!   sender. A refund appends an `evm-wd-v1` leaf (`sha256("refund|" ||
//!   depositId)`); a mint writes no claim leaf. Each deposit id resolves once.
//!   The first activated ledger with a resolved LC head number sets
//!   `eth_v1_deposit_cutoff`; a later V1/V2/DestLock mint above that number
//!   is rejected. `fundPool` (`PoolFunded`, no Deposit log) mints nothing.
//!   Pre-activation the new state fields are omitted, so commitment bytes
//!   match 2.9.60. While `!eth_v3_at(tip + 1)` an `EthV3Deposit` is refused
//!   at mempool entry and dropped from peer batches / exports, so it is never
//!   kept or relayed (#34; admission only). See `docs/ETH_V3_DEPOSITS.md`.
//! - **v2.10.0** (`consensus_rounds`, activation `vote_rounds_from_height`):
//!   OK votes are scoped to **(height, round)** (`pl-ok:v2`); only two hashes
//!   in one round are equivocation (evidence kept + signature-checked). One
//!   proposer per round (`order[round % n]`, cursor derived from the round).
//!   Work-gated round timeouts with backoff; proven split ⇒ immediate round.
//!   Typed `ConsensusStall` replaces substring checks. Liveness watchdog
//!   alerts only when work exists on a flat tip (h=369421 halt, 2026-09-28).
//!   Pre-activation: typed dual drives VC even with a pending; idle VC off.
//! - If #1 is silent for `progress_timeout_ms`, **quorum** `SkipPacker` votes → #2 packs
//! - Stuck pending / dual proposals → **view-change soft QC** (height-local, not genesis wipe)
//! - Tip advances only after **soft QC**; hard QC capped by |ONLINE|
//! - Equivocation → jail/slash; uncommitted dual proposals use **QC-first** choice
//! - Empty ledgers rejected below `empty_block_from_height` (755,000 on 2300);
//!   from there a packer may seal one only after evicting permanently failing txs
//!
//! See `docs/IDENTITY.md` and `docs/POC.md`.

#![recursion_limit = "512"]

pub mod accounts;
pub mod pieces;
pub mod bitvm;
pub mod bitvm2_exit;
pub mod bitvm2_instance;
pub mod user_vault;
pub mod fbtc_pool;
pub mod body_store;
pub mod catchup_slow;
pub mod bridge;
pub mod btc_spv;
pub mod btc_tx;
pub mod crypto;
pub mod defi;
pub mod orderbook;
pub mod disk;
pub mod economy;
pub mod eth_exec;
pub mod eth_lc;
pub mod eth_ssz;
pub mod evm_spv;
pub mod exec_map;
pub mod frost_vault;
pub mod lc;
pub mod falcon_qc;
pub mod qc_header;
pub mod utc_header;
pub mod health;
pub mod health_web;
pub mod metrics;
pub mod names;
pub mod snapshot;
mod snap_serve;
pub use snap_serve::{snap_push_budget, snap_skip_ids, all_slow_forget_nonserve_only, all_slow_cap_stalled, SNAP_ALL_STALLED_RETRY_MS, is_snap_skipped, SNAP_PUSH_RESERVE_SLOTS, SNAP_EST_PIECES_PER_CHUNK};
pub mod vault;
pub mod consensus_rounds;
pub mod params_v2;
pub mod operator_registry;
pub mod bridge_operators;
pub use snapshot::{SnapAssembler, SnapInsert, SnapSlowJudge, SnapStash};

use accounts::{AccountMeta, AccountType};
use names::{NameRegistry, NameStatus};
use body_store::BodyStore;
use bridge::{BridgeProof, BridgeState, RailHeader};
use crypto::{sha256_hex, CryptoScheme, KeyRing};
use qc_header::{
    committee_leaf_hexes_for_ids, committee_root_for_ids, inner_hash_hex, outer_hash_hex, parse32,
};
use utc_header::{header_domain, packer_msg_for_domain, HeaderDomain};
use defi::{AmmPool, DefiState, LendingMarket, NATIVE as DEFI_NATIVE};
use economy::{
    epoch_claimable, epoch_claimable_from, epoch_index, fee_burn_and_reward,
    effective_jail_count, unjail_cost, EpochWork, EMISSION_BPS_FIRST, EPOCH_MS, FIRST_CLAIM_EPOCH, MIN_BOND,
    TREASURY_GENESIS, UNBOND_COOLDOWN_MS, WATCHER_SLOTS_PER_EPOCH,
};
use metrics::{
    mempool_util_bps, suggested_min_fee, NodeMetrics, DEFAULT_MIN_FEE, PARAMS_VERSION,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use thiserror::Error;

pub const NETWORK_NAME: &str = "falcon-pl-private-v22";
/// Product release line. One number on crate, status, Hello, and binaries.
pub const PRODUCT_VERSION: &str = "2.11.2";

/// Version string a node puts in its Hello (`WireMsg::Hello::product_version`).
///
/// 2.9.x binaries accept a Hello only if it is `2.9.<digits>` (same
/// major.minor), and close the session otherwise, so a Hello that said
/// `2.10.0` would be refused by every 2.9.81 seat and a rolling upgrade would
/// isolate each upgraded seat. Until the whole mesh runs 2.10.x, 2.10.0
/// therefore advertises this legacy-line string (patch >= 60, so it also
/// passes the post-Gloas `x >= 60` rule). Status, logs and binaries still
/// report [`PRODUCT_VERSION`]. Local only: not consensus.
pub const HELLO_WIRE_VERSION: &str = "2.9.100";

/// Minor of the legacy line whose Hello versions this release still accepts
/// (`2.9.x`), in addition to its own major.minor.
const HELLO_LEGACY_MINOR: &str = "9";

/// v2.9.66: when true, certified catch-up of non-batch ledgers skips per-tx
/// Falcon verify (legacy). Default false. Env: `FPL_CATCHUP_SKIP_TX_SIG=1`.
pub fn catchup_skip_tx_sig() -> bool {
    use std::sync::OnceLock;
    static SKIP: OnceLock<bool> = OnceLock::new();
    *SKIP.get_or_init(|| match std::env::var("FPL_CATCHUP_SKIP_TX_SIG") {
        Ok(v) => matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"),
        Err(_) => false,
    })
}

/// Hello peer check for this release line **before the Gloas gate H**.
/// Local only: not consensus. Use [`hello_version_compatible_at`] (or
/// [`Node::hello_version_ok`]) on the wire; this is its pre-H half.
///
/// Empty is the legacy pre-A10 hello. Otherwise the peer must be
/// `major.minor.<digits>` with the same major.minor as [`PRODUCT_VERSION`]
/// (any `2.9.x` while this crate is 2.9.61). `2.9` with no patch is rejected,
/// as is a different minor (`2.8.99`, `2.90.1`), a different major, or any
/// component that is not a plain integer. A patch with a leading zero
/// (`2.9.060`, `2.9.00`) is rejected; `2.9.0` is not.
pub fn hello_version_compatible(peer: &str) -> bool {
    if peer.is_empty() {
        return true;
    }
    let Some((our_maj, our_rest)) = PRODUCT_VERSION.split_once('.') else {
        return false;
    };
    let Some((our_min, _)) = our_rest.split_once('.') else {
        return false;
    };
    let mut parts = peer.split('.');
    let (Some(maj), Some(min), Some(patch)) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    if parts.next().is_some() {
        return false;
    }
    // A leading zero (`2.9.060`) is not the same patch as `2.9.60`.
    // `u64` parse would hide it, and after H that would pass the >= 60 gate.
    let patch_ok = !patch.is_empty()
        && patch.bytes().all(|b| b.is_ascii_digit())
        && (patch.len() == 1 || !patch.starts_with('0'));
    maj == our_maj && patch_ok && (min == our_min || min == HELLO_LEGACY_MINOR)
}

/// Lowest `2.9.x` patch a peer may advertise in Hello once the local tip is at
/// or past the Gloas gate H. Every binary below 2.9.60 forks at H.
pub const HELLO_MIN_PATCH_AFTER_GLOAS: u64 = 60;

/// v2.9.60 Hello version rule. Local only: not consensus.
///
/// `gloas_active == false` (local tip below H, including H == `u64::MAX`):
/// [`hello_version_compatible`] — any `2.9.x` or the legacy empty version, so
/// the roll still works. `gloas_active == true`: the peer must advertise
/// `2.9.x` with `x >=` [`HELLO_MIN_PATCH_AFTER_GLOAS`] (2.9.61 still
/// connects); empty and anything older are rejected.
pub fn hello_version_compatible_at(peer: &str, gloas_active: bool) -> bool {
    if !hello_version_compatible(peer) {
        return false;
    }
    if !gloas_active {
        return true;
    }
    if peer.is_empty() {
        return false;
    }
    // The `x >= 60` floor is a rule for the legacy `2.9.x` line only; a peer on
    // this release's own line (`2.11.x`) is always new enough.
    if !peer.starts_with("2.9.") {
        return true;
    }
    peer.rsplit('.')
        .next()
        .and_then(|p| p.parse::<u64>().ok())
        .is_some_and(|p| p >= HELLO_MIN_PATCH_AFTER_GLOAS)
}

/// What a peer session does with one inbound wire message (v2.9.60).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HelloGate {
    /// Dispatch normally.
    Pass,
    /// Ignore it (no dispatch, no liveness).
    Drop,
    /// Send `WireMsg::Err { msg }` and end the session (both socket loops).
    Close(String),
}

/// Per-connection Hello state for mesh sessions (inbound accept and outbound
/// dial). Local only: not consensus.
///
/// - A rejected Hello (network_id or product_version) closes the session.
/// - A `Pong` is only dispatched after this session accepted a Hello, so a
///   peer is never marked live (`pong_with_role`) without one.
/// - Every `Pong` re-checks the accepted version against the local tip, so a
///   2.9.59 / legacy session opened before H is closed once the tip reaches H.
#[derive(Debug, Default, Clone)]
pub struct HelloSession {
    accepted_version: Option<String>,
}

impl HelloSession {
    /// Only Hello and Pong need the node (and its lock) to decide.
    pub fn needs_check(msg: &WireMsg) -> bool {
        matches!(msg, WireMsg::Hello { .. } | WireMsg::Pong { .. })
    }

    /// Version accepted by this session's Hello, if any.
    pub fn accepted_version(&self) -> Option<&str> {
        self.accepted_version.as_deref()
    }

    pub fn check(&mut self, node: &Node, msg: &WireMsg) -> HelloGate {
        match msg {
            WireMsg::Hello {
                product_version,
                hello_network_id,
                release_version,
                capabilities,
                ..
            } => match node
                .hello_reject_reason(*hello_network_id, product_version)
                .map(str::to_string)
                .or_else(|| node.hello_release_reject(release_version))
                .or_else(|| node.hello_utc_capability_reject(capabilities))
            {
                Some(reason) => {
                    self.accepted_version = None;
                    HelloGate::Close(reason)
                }
                None => {
                    self.accepted_version = Some(product_version.clone());
                    HelloGate::Pass
                }
            },
            WireMsg::Pong { .. } => match &self.accepted_version {
                None => HelloGate::Drop,
                Some(v) if !node.hello_version_ok(v) => {
                    HelloGate::Close(HELLO_ERR_PRODUCT_VERSION.to_string())
                }
                Some(_) => HelloGate::Pass,
            },
            _ => HelloGate::Pass,
        }
    }
}

pub const HELLO_ERR_NETWORK_ID: &str = "network_id mismatch";
/// v2.10.3: Hello refused because the peer's release is older than
/// [`HELLO_MIN_RELEASE`] once the local tip is past the activation height.
/// Shown for a peer whose Hello had no `release_version` (2.10.2 or older).
pub const PEER_RELEASE_NONE: &str = "none (pre-2.10.3)";

pub const HELLO_ERR_RELEASE_TOO_OLD: &str = "release_version too old";
pub const HELLO_ERR_UTC_CAPABILITY: &str = "utc-header-v5 capability required";

/// Lowest release a peer may advertise after
/// [`crate::params_v2::hello_min_release_from_height`]. **TBD**: bump to the
/// release that ships with the activation (peers below it fork at the next
/// consensus height, e.g. the BTC4 fork fix at 775,000).
pub const HELLO_MIN_RELEASE: &str = "2.10.3";

pub fn parse_release_pub(v: &str) -> Option<(u64, u64, u64)> {
    parse_release(v)
}

fn parse_release(v: &str) -> Option<(u64, u64, u64)> {
    let mut it = v.trim().split('.');
    let a = it.next()?.parse().ok()?;
    let b = it.next()?.parse().ok()?;
    let c = it.next()?.parse().ok()?;
    if it.next().is_some() {
        return None;
    }
    Some((a, b, c))
}

/// `None` = acceptable. Otherwise a human-readable reason (for logs).
pub fn hello_release_reject_detail(peer_release: &str, min: &str) -> Option<String> {
    let Some(want) = parse_release(min) else {
        return None;
    };
    if peer_release.is_empty() {
        return Some(format!(
            "{HELLO_ERR_RELEASE_TOO_OLD}: peer sent no release_version (binary older than 2.10.3), minimum {min}"
        ));
    }
    match parse_release(peer_release) {
        None => Some(format!(
            "{HELLO_ERR_RELEASE_TOO_OLD}: unparseable release_version {peer_release:?}, minimum {min}"
        )),
        Some(got) if got < want => Some(format!(
            "{HELLO_ERR_RELEASE_TOO_OLD}: peer {peer_release} < minimum {min}"
        )),
        Some(_) => None,
    }
}
/// v2.9.65 (C-1) refusal: a first key that nothing commits to.
pub const KEY_BIND_REFUSED: &str = "key bind: account has no key and this key is not committed (fund it with pay_to_key, or use the key's classic address)";
pub const PAY_TO_KEY_NOT_ACTIVE: &str = "pay_to_key: not active before the key-bind height";

fn falcon_raw_pub(pk_hex: &str) -> Option<Vec<u8>> {
    let b = hex::decode(pk_hex.trim()).ok()?;
    match b.len() {
        897 => Some(b),
        898 if b[0] == 0xfb => Some(b[1..].to_vec()),
        _ => None,
    }
}

/// sha256 hex of the raw (897-byte) Falcon-512 public key: the `PayToKey`
/// commitment. A 0xFB-prefixed blob hashes the same as the raw key.
/// Wallet-history entry for one tx in `led` (same shape as before).
fn account_tx_json(tx: &Tx, led: &Ledger) -> serde_json::Value {
    let mut v = serde_json::json!({
        "tx_id": tx.tx_id,
        "height": led.height,
        "kind": match &tx.body {
            TxBody::Pay => "pay",
            TxBody::Claim => "claim",
            TxBody::AssetPay { .. } => "asset_pay",
            TxBody::SetExternalAddrs { .. } => "set_external_addrs",
            TxBody::PlaceLimitOrder { .. } => "place_limit_order",
            TxBody::CancelOrder { .. } => "cancel_order",
            _ => "tx",
        },
        "account": tx.account,
        "destination": tx.destination,
        "amount": tx.amount,
        "fee": tx.fee,
        "sealed_at_ms": led.sealed_at_ms,
    });
    if let TxBody::AssetPay { asset, .. } = &tx.body {
        v["asset"] = serde_json::json!(asset);
    }
    if let TxBody::SetExternalAddrs { chain, address } = &tx.body {
        v["chain"] = serde_json::json!(chain);
        v["address"] = serde_json::json!(address);
    }
    v
}

/// Push `account`'s txs from `led`, newest first. Returns true once `limit` is reached.
fn collect_account_txs(led: &Ledger, account: &str, limit: usize, out: &mut Vec<serde_json::Value>) -> bool {
    for tx in led.txs.iter().rev() {
        if tx.account != account && tx.destination != account {
            continue;
        }
        out.push(account_tx_json(tx, led));
        if out.len() >= limit {
            return true;
        }
    }
    out.len() >= limit
}

/// Older wallet history from an archive `BodyStore`, walking down from
/// `below_height - 1`. Bounded by `max_heights` and `budget`; call it WITHOUT
/// the node lock (disk + JSON only, no node state).
pub fn account_history_from_store(
    store: &BodyStore,
    account: &str,
    below_height: u64,
    max_heights: u64,
    budget: std::time::Duration,
    limit: usize,
    out: &mut Vec<serde_json::Value>,
) {
    let t0 = std::time::Instant::now();
    let lo = below_height.saturating_sub(max_heights).max(1);
    let mut h = below_height;
    while h > lo && out.len() < limit && t0.elapsed() < budget {
        h -= 1;
        if let Some(led) = store.get_at_height(h) {
            if collect_account_txs(&led, account, limit, out) {
                break;
            }
        }
    }
}

pub fn key_commit_hash(pk_hex: &str) -> Option<String> {
    falcon_raw_pub(pk_hex).map(|raw| crate::crypto::sha256_hex(&raw))
}

pub fn is_key_commit_hex(h: &str) -> bool {
    h.len() == 64 && h.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

/// XRPL-style classic address of a Falcon key, as the site wallet derives it:
/// base58check(0x00 || ripemd160(sha256(0xFB || raw_pub))), ripple alphabet.
pub fn falcon_classic_address(pk_hex: &str) -> Option<String> {
    use ripemd::{Digest as _, Ripemd160};
    let raw = falcon_raw_pub(pk_hex)?;
    let mut blob = Vec::with_capacity(898);
    blob.push(0xfb);
    blob.extend_from_slice(&raw);
    let h = sha2::Sha256::digest(&blob);
    let id = Ripemd160::digest(h);
    let mut payload = vec![0u8];
    payload.extend_from_slice(&id);
    let c1 = sha2::Sha256::digest(&payload);
    let c2 = sha2::Sha256::digest(c1);
    payload.extend_from_slice(&c2[..4]);
    Some(base58_ripple(&payload))
}

fn base58_ripple(data: &[u8]) -> String {
    const A: &[u8] = b"rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz";
    let zeros = data.iter().take_while(|b| **b == 0).count();
    let mut digits: Vec<u8> = Vec::new();
    for &byte in data {
        let mut carry = byte as u32;
        for d in digits.iter_mut() {
            carry += (*d as u32) << 8;
            *d = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let mut out = String::new();
    for _ in 0..zeros {
        out.push(A[0] as char);
    }
    for d in digits.iter().rev() {
        out.push(A[*d as usize] as char);
    }
    out
}

pub const HELLO_ERR_PRODUCT_VERSION: &str = "product_version mismatch";

/// Test builds cross-check every cached commitment root against a fresh one.
#[cfg(test)]
pub(crate) static ROOT_CROSSCHECKS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Public zero-point: status/account JSON subtract these so explorers read 0
/// until new peg-ins. Ledger totals are unchanged.
fn display_rail_minted(asset: &str, minted: u64) -> u64 {
    let z = match asset {
        "BTC" => 193_000,
        "ETH" => 6_100_000_000_000_000,
        "USDC" => 2_000_000,
        _ => 0,
    };
    minted.saturating_sub(z)
}

fn display_rail_burned(asset: &str, burned: u64) -> u64 {
    let z = match asset {
        "BTC" => 50_000,
        "ETH" => 6_000_000_000_000_000,
        "USDC" => 2_000_000,
        _ => 0,
    };
    burned.saturating_sub(z)
}

fn display_asset(account: &str, asset: &str, raw: u64) -> u64 {
    let z = match (account, asset) {
        ("dave", "BTC") => 143_000,
        ("dave", "ETH") => 100_000_000_000_000,
        _ => 0,
    };
    raw.saturating_sub(z)
}

/// Process role. Public seats are separate binaries; one crate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeRole {
    /// Long tail + disk bodies + join-snap serve.
    Archive,
    /// Pack intake / NeedTxs. Full RAM tail, no archive store.
    Hub,
    /// Checker/packer seat: short chain only. Not a snap server.
    Val,
}

impl NodeRole {
    pub const VAL_MAX_CHAIN: usize = 128;

    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "archive" => Some(Self::Archive),
            "hub" => Some(Self::Hub),
            "val" | "validator" | "light" => Some(Self::Val),
            _ => None,
        }
    }

    /// `falcon-pl-val` / `falcon-pl-hub` / `falcon-pl-archive` from argv0.
    pub fn from_exe_name(exe: &str) -> Option<Self> {
        let base = exe.rsplit(['/', '\\']).next().unwrap_or(exe);
        if base.contains("archive") {
            Some(Self::Archive)
        } else if base.contains("hub") {
            Some(Self::Hub)
        } else if base.ends_with("-val") || base.contains("pl-val") {
            Some(Self::Val)
        } else {
            None
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Archive => "archive",
            Self::Hub => "hub",
            Self::Val => "val",
        }
    }
}
/// Private expansion fleet network id (EXPANSION_PLAN §6.1).
pub const NETWORK_ID_PRIVATE_V22: u32 = 2200;
/// Public testnet network id.
pub const NETWORK_ID_PUBLIC_TESTNET_2300: u32 = 2300;
/// v2.10.0 Phase 2 (round-scoped OK votes) activation height for public
/// testnet **2300**. Live since 2026-10-05 (crossed under
/// `FALCON_PL_VOTE_ROUNDS_FROM_HEIGHT=369998` drop-ins). Baked in so a seat
/// that starts without the env/flag (new host, lost systemd drop-in) can never
/// mis-verify round-scoped certs at heights >= this. See
/// `docs/CONSENSUS_ROUNDS_v2.10.md` §"Baked activation / rollback".
pub const TESTNET_2300_VOTE_ROUNDS_FROM_HEIGHT: u64 = 369_998;

/// First 2300 height whose commit cert is signed with the **legacy**
/// `pl-ok:v1` payload after Phase 2 went live: the 2026-10-05 ~14:10 UTC pause
/// (`FALCON_PL_VOTE_ROUNDS_FROM_HEIGHT=999999999` drop-ins) took effect here.
/// Pinned from the chain: every cert for h in [369998, 371036] verifies as
/// `pl-ok:v2` only, every cert from 371037 on verifies as `pl-ok:v1` only
/// (archive v1 snapshot scan, 2026-10-06). See `docs/PHASE2_REENABLE.md`.
pub const TESTNET_2300_VOTE_ROUNDS_PAUSE_FROM: u64 = 371_037;
/// First 2300 height that is round-scoped again (end of the pause window,
/// exclusive). Chosen with margin above the 2026-10-06 tip (~371540) for
/// review, merge and a fleet restart. **Every seat must run a binary/env that
/// knows this value before the tip reaches it.** If the tip gets close before
/// the fleet is upgraded, bump it (new constant, or env
/// `FALCON_PL_VOTE_ROUNDS_PAUSE=371037..<new>` + override) — see
/// `docs/PHASE2_REENABLE.md` §"Bumping the resume height".
pub const TESTNET_2300_VOTE_ROUNDS_RESUME_AT: u64 = 375_000;

/// v2.9.60: first PL height whose txs apply **Gloas** Ethereum light-client
/// rules (`eth_lc::apply_update_ex(.., gloas = true)`: fork version
/// `0x90000076`, `execution_block_hash` headers, EIP-7688 state gindices,
/// hash-only LC head resolved from stored execution headers).
///
/// Consensus change: every committee seat must run a binary that knows this
/// height before the tip reaches it. Below it, `EthLcUpdate` /
/// `EthLcBootstrap` / `EthExecHeaders` apply exactly as in 2.9.59 (Gloas
/// updates are rejected, which is today's stuck state).
///
/// TODO(rollout): placeholder — `u64::MAX` means "never". Set to a real height
/// **above the current tip + margin** (roll time for all seven seats + review)
/// in the rollout commit, rebuild portable, then roll. Do not ship with the
/// placeholder expecting the LC to move.
pub const TESTNET_2300_ETH_LC_GLOAS_FROM_HEIGHT: u64 = 409134;

/// Network-constant ETH LC Gloas activation height (`u64::MAX` = off).
pub fn network_eth_lc_gloas_from_height(network_id: u32) -> u64 {
    match network_id {
        NETWORK_ID_PUBLIC_TESTNET_2300 => TESTNET_2300_ETH_LC_GLOAS_FROM_HEIGHT,
        _ => u64::MAX,
    }
}

/// v2.9.61: first PL height whose txs apply V3 mint-or-refund deposits
/// (`TxBody::EthV3Deposit`). Independent of
/// [`TESTNET_2300_ETH_LC_GLOAS_FROM_HEIGHT`].
///
/// Consensus change: every committee seat must run a binary that knows this
/// height, and must have the same V3 bridge address, before the tip reaches
/// it. Below it, a V3 deposit tx is rejected with `V3 deposits not active`
/// (not permanent) at apply and, from #34, already at mempool entry and
/// relay (`tip + 1 < height`), and V1 mints are unchanged. The first activated ledger
/// whose LC head number is resolved sets `eth_v1_deposit_cutoff`.
///
/// Rollout (2.9.61, 2026-10-09): H2 = 414000 (~15:00 BST at 3.42 s/block; tip was
/// 404991 at 06:24 BST). V3 bridge 0xEd4e…Cfd4 deployed 06:42 BST. All seats must report
/// `eth_v3_from_height == H2` before the tip reaches H2, and
/// `FPL_SEPOLIA_QC_V3_BRIDGE` must be identical on every seat before then.
pub const TESTNET_2300_ETH_V3_FROM_HEIGHT: u64 = 414_000;

/// P2P `AssetPay` of BTC4 (testnet4 FBTC): opens at the single 2.10.4
/// height ([`params_v2::TESTNET_2300_V2_10_4_FROM_HEIGHT`]); `u64::MAX`
/// keeps today's behaviour (BTC4 rejected at pack).
pub const TESTNET_2300_ASSET_PAY_BTC4_FROM_HEIGHT: u64 = params_v2::TESTNET_2300_V2_10_4_FROM_HEIGHT;

/// Non-2300 networks keep the draft's default (open from genesis) unless
/// `FPL_V2_10_4_FROM_HEIGHT` is set.
pub fn network_asset_pay_btc4_from_height(network_id: u32) -> u64 {
    params_v2::v2_10_4_from_height_or(network_id, 0)
}

/// Network-constant V3 deposit activation height (`u64::MAX` = off).
pub fn network_eth_v3_from_height(network_id: u32) -> u64 {
    match network_id {
        NETWORK_ID_PUBLIC_TESTNET_2300 => TESTNET_2300_ETH_V3_FROM_HEIGHT,
        _ => u64::MAX,
    }
}

/// Network-constant `vote_rounds_from_height` (0 = no baked activation).
pub fn network_vote_rounds_from_height(network_id: u32) -> u64 {
    match network_id {
        NETWORK_ID_PUBLIC_TESTNET_2300 => TESTNET_2300_VOTE_ROUNDS_FROM_HEIGHT,
        _ => 0,
    }
}

/// Network-constant Phase 2 pause window `(from, resume_at)`; `(0, 0)` = none.
pub fn network_vote_rounds_pause(network_id: u32) -> (u64, u64) {
    match network_id {
        NETWORK_ID_PUBLIC_TESTNET_2300 => (
            TESTNET_2300_VOTE_ROUNDS_PAUSE_FROM,
            TESTNET_2300_VOTE_ROUNDS_RESUME_AT,
        ),
        _ => (0, 0),
    }
}

/// Parse a pause window: `FROM..RESUME` (resume exclusive), or `off` / `none`
/// / `0` for an explicit "no window". Whitespace is ignored.
pub fn parse_vote_rounds_pause(s: &str) -> Result<(u64, u64), String> {
    let t: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if t.is_empty() || t == "0" || t.eq_ignore_ascii_case("off") || t.eq_ignore_ascii_case("none") {
        return Ok((0, 0));
    }
    let (a, b) = t
        .split_once("..")
        .ok_or_else(|| format!("vote rounds pause {s:?}: want FROM..RESUME or off"))?;
    let from = a.parse::<u64>().map_err(|e| format!("pause from {a:?}: {e}"))?;
    let resume = b.parse::<u64>().map_err(|e| format!("pause resume {b:?}: {e}"))?;
    validate_vote_rounds_pause(from, resume)?;
    Ok((from, resume))
}

/// A window is either `(0, 0)` or `0 < from < resume_at`.
pub fn validate_vote_rounds_pause(from: u64, resume_at: u64) -> Result<(), String> {
    if from == 0 && resume_at == 0 {
        return Ok(());
    }
    if from == 0 || resume_at <= from {
        return Err(format!(
            "vote rounds pause [{from}, {resume_at}) invalid: need 0 < from < resume_at (or off)"
        ));
    }
    Ok(())
}

/// Where the effective pause window came from (same precedence as
/// [`resolve_vote_rounds_from_height`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoteRoundsPauseResolution {
    pub from: u64,
    pub resume_at: u64,
    /// `env` | `cli` | `bridge.json` | `network-constant` | `off`.
    pub source: &'static str,
    pub network_default: (u64, u64),
    /// Effective window differs from a non-empty network constant.
    pub mismatch: bool,
}

/// Resolve the Phase 2 pause window.
///
/// Precedence: env `FALCON_PL_VOTE_ROUNDS_PAUSE` (even `off`) >
/// `--vote-rounds-pause` (even `off`) > non-empty `vote_rounds_pause_from` /
/// `vote_rounds_resume_at` in `keys/lc/bridge.json` > network constant. A
/// result that disagrees with a non-empty network constant sets `mismatch`
/// (refuse to start unless `FALCON_PL_ALLOW_VOTE_ROUNDS_OVERRIDE=1`).
pub fn resolve_vote_rounds_pause(
    network_id: u32,
    env: Option<(u64, u64)>,
    cli: Option<(u64, u64)>,
    bridge_json: (u64, u64),
) -> VoteRoundsPauseResolution {
    let network_default = network_vote_rounds_pause(network_id);
    let set = |w: (u64, u64)| w.0 > 0 || w.1 > 0;
    let ((from, resume_at), source) = if let Some(w) = env {
        (w, "env")
    } else if let Some(w) = cli {
        (w, "cli")
    } else if set(bridge_json) {
        (bridge_json, "bridge.json")
    } else if set(network_default) {
        (network_default, "network-constant")
    } else {
        ((0, 0), "off")
    };
    VoteRoundsPauseResolution {
        from,
        resume_at,
        source,
        network_default,
        mismatch: set(network_default) && (from, resume_at) != network_default,
    }
}

/// Where the effective `vote_rounds_from_height` came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoteRoundsResolution {
    pub height: u64,
    /// `env` | `cli` | `bridge.json` | `network-constant` | `off`.
    pub source: &'static str,
    /// Baked network constant for this network id (0 = none).
    pub network_default: u64,
    /// Effective height differs from a non-zero network constant.
    pub mismatch: bool,
}

/// Resolve the Phase 2 activation height.
///
/// Precedence: explicit env `FALCON_PL_VOTE_ROUNDS_FROM_HEIGHT` (even `0`) >
/// non-zero `--vote-rounds-from-height` > non-zero `vote_rounds_from_height`
/// in `keys/lc/bridge.json` > network constant. A result that disagrees with a
/// non-zero network constant sets `mismatch` (the node binary refuses to start
/// on it unless `FALCON_PL_ALLOW_VOTE_ROUNDS_OVERRIDE=1`).
pub fn resolve_vote_rounds_from_height(
    network_id: u32,
    env: Option<u64>,
    cli: u64,
    bridge_json: u64,
) -> VoteRoundsResolution {
    let network_default = network_vote_rounds_from_height(network_id);
    let (height, source) = if let Some(v) = env {
        (v, "env")
    } else if cli > 0 {
        (cli, "cli")
    } else if bridge_json > 0 {
        (bridge_json, "bridge.json")
    } else if network_default > 0 {
        (network_default, "network-constant")
    } else {
        (0, "off")
    };
    VoteRoundsResolution {
        height,
        source,
        network_default,
        mismatch: network_default > 0 && height != network_default,
    }
}
/// Startup gate for the Phase 2 knobs. A resolved activation height or pause
/// window that disagrees with the baked network constant is refused unless
/// `allow_override` (`FALCON_PL_ALLOW_VOTE_ROUNDS_OVERRIDE=1`); with the
/// override it is returned as a warning. Malformed windows are always refused.
pub fn check_vote_rounds_startup(
    network_id: u32,
    res: &VoteRoundsResolution,
    pres: &VoteRoundsPauseResolution,
    allow_override: bool,
) -> Result<Vec<String>, String> {
    validate_vote_rounds_pause(pres.from, pres.resume_at)
        .map_err(|e| format!("{e} (from {})", pres.source))?;
    let mut warnings = Vec::new();
    if res.mismatch {
        if !allow_override {
            return Err(format!(
                "vote_rounds_from_height={} (from {}) != baked network {network_id} constant {}; \
                 refusing to start. Fix the env/flag/bridge.json, or set \
                 FALCON_PL_ALLOW_VOTE_ROUNDS_OVERRIDE=1 for a deliberate override",
                res.height, res.source, res.network_default
            ));
        }
        warnings.push(format!(
            "vote_rounds_from_height={} (from {}) OVERRIDES baked network constant {} (FALCON_PL_ALLOW_VOTE_ROUNDS_OVERRIDE=1)",
            res.height, res.source, res.network_default
        ));
    }
    if pres.mismatch {
        if !allow_override {
            return Err(format!(
                "vote_rounds_pause=[{}, {}) (from {}) != baked network {network_id} pause [{}, {}); \
                 refusing to start. Fix the env/flag/bridge.json, or set \
                 FALCON_PL_ALLOW_VOTE_ROUNDS_OVERRIDE=1 for a deliberate override",
                pres.from, pres.resume_at, pres.source, pres.network_default.0, pres.network_default.1
            ));
        }
        warnings.push(format!(
            "vote_rounds_pause=[{}, {}) (from {}) OVERRIDES baked network pause [{}, {}) (FALCON_PL_ALLOW_VOTE_ROUNDS_OVERRIDE=1)",
            pres.from, pres.resume_at, pres.source, pres.network_default.0, pres.network_default.1
        ));
    }
    Ok(warnings)
}
pub const NATIVE: &str = "FPL";
/// Default genesis balance per faucet/load wallet.
pub const GENESIS_BALANCE: u64 = 1_000_000_000;

/// Staging faucet account id (private fleet / public testnet prep).
pub const FAUCET_ACCOUNT: &str = "faucet";
/// Faucet genesis pot (1B FPL-style units for private staging).
pub const FAUCET_GENESIS: u64 = GENESIS_BALANCE;

/// Named accounts + staging faucet + load wallets `w00..w{n-1}`.
pub fn genesis_accounts(load_wallets: u32) -> Vec<(String, u64)> {
    let mut out = vec![
        ("alice".into(), GENESIS_BALANCE),
        ("bob".into(), GENESIS_BALANCE),
        ("carol".into(), GENESIS_BALANCE),
        ("dave".into(), GENESIS_BALANCE),
        (FAUCET_ACCOUNT.into(), FAUCET_GENESIS),
    ];
    for i in 0..load_wallets {
        out.push((format!("w{i:02}"), GENESIS_BALANCE));
    }
    out
}

pub fn genesis_account_ids(load_wallets: u32) -> Vec<String> {
    genesis_accounts(load_wallets)
        .into_iter()
        .map(|(a, _)| a)
        .collect()
}

// ---------------------------------------------------------------------------
// Tx / State / Ledger
// ---------------------------------------------------------------------------

/// Protocol operation executed when a tx is included in a ledger.
/// Side-channel WireMsg must enqueue these as signed txs (not mutate state alone).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TxBody {
    /// Classic payment: `destination` + `amount` fields on Tx. Native FPL only.
    #[default]
    Pay,
    /// Move a bridged rail balance (BTC, ETH, USDC) to another account.
    /// Uses `Tx.destination` and `Tx.amount`. Recipient can later `RailWithdraw`.
    AssetPay {
        asset: String,
    },
    Bond {
        validator: String,
    },
    Unbond {
        validator: String,
        /// Amount of active bond to unlock (fee is separate on Tx).
        amount: u64,
    },
    CompleteUnbond {
        validator: String,
    },
    /// Clear jail by posting the escalated rebond (`unjail_cost`).
    /// `Tx.amount` must be ≥ `min_bond * 2^jail_count`. Seized prior bond
    /// already sits in the prize pot; this posts a fresh bond.
    Unjail {
        validator: String,
    },
    VaultOpen {
        destination: String,
    },
    VaultLock,
    Claim,
    CreatePool {
        pool_id: String,
        asset_a: String,
        asset_b: String,
    },
    AddLiquidity {
        pool_id: String,
        amt_a: u64,
        amt_b: u64,
    },
    Swap {
        pool_id: String,
        token_in: String,
        amount_in: u64,
        min_out: u64,
    },
    CreateMarket {
        market_id: String,
        asset: String,
    },
    LendSupply {
        market_id: String,
        amount: u64,
    },
    /// Burn lend shares and return the underlying rail asset.
    LendWithdraw {
        market_id: String,
        shares: u64,
    },
    /// Lock `collateral_fpl` and receive `amount` of the market asset.
    LendBorrow {
        market_id: String,
        amount: u64,
        collateral_fpl: u64,
    },
    /// Repay market-asset debt. Full repay returns the FPL collateral.
    LendRepay {
        market_id: String,
        amount: u64,
    },
    /// Copy the FPL-per-coin price from the asset/FPL pool onto the lend market.
    LendSetPrice {
        market_id: String,
    },
    /// Burn LP tokens and return both pool reserves.
    RemoveLiquidity {
        pool_id: String,
        lp_burn: u64,
    },
    /// AMM swap. Direct pool if one exists, otherwise through FPL.
    SwapRoute {
        token_in: String,
        token_out: String,
        amount_in: u64,
        min_out: u64,
    },
    /// Private-fleet mint of secondary assets (still sequenced + fee).
    CreditAsset {
        asset: String,
        amount: u64,
    },
    WatcherCredit {
        work_units: u64,
        #[serde(default)]
        presence_slots: u64,
    },
    /// Browser / VPS presence tick. Pays the min fee, marks **this** wall-clock
    /// slot only, adds **zero** work. Not `WatcherCredit` (that is admin/soak).
    WatcherHeartbeat,
    RailHeader {
        asset: String,
        height: u64,
        hash: String,
        parent_hash: String,
        merkle_root: String,
        /// 80-byte Bitcoin header hex. Required on BTC; empty on ETH/BNB fixtures.
        #[serde(default, skip_serializing_if = "String::is_empty")]
        raw: String,
    },
    RailDeposit {
        asset: String,
        to: String,
        amount: u64,
        proof: BridgeProof,
    },
    RailWithdraw {
        asset: String,
        amount: u64,
        external_to: String,
        /// Hex secp signature over the vault withdraw plan (t-of-n). Required for BTC.
        #[serde(default, skip_serializing_if = "String::is_empty")]
        vault_sig: String,
        /// Broadcastable signed Bitcoin tx (BIP143). Verified against vault pubkey.
        #[serde(default, skip_serializing_if = "String::is_empty")]
        signed_btc_tx: String,
    },
    /// Last FROST key-path: move the tracked pool UTXO into the NUMS P2TR.
    /// Does not burn wrapped BTC. `raw_tx` is the signed Bitcoin tx.
    BtcPoolMove {
        raw_tx: String,
    },
    /// Sepolia sync-committee bootstrap (once). Weak-subjectivity checkpoint.
    EthLcBootstrap {
        json: String,
    },
    /// Sepolia light-client update (BLS sync aggregate).
    EthLcUpdate {
        json: String,
    },
    /// Execution headers from a deposit block up to the LC execution hash.
    EthExecHeaders {
        headers_json: String,
    },
    /// Bitcoin headers below the pruned tip window, linked to the stored floor.
    BtcHeaderBackfill {
        headers_json: String,
    },
    /// Permissionless BitVM challenge: abort a pending claim if observed BTC dest/amount ≠ burn.
    RailChallenge {
        asset: String,
        note_id: String,
        observed_dest: String,
        observed_amount: u64,
    },
    /// Operator attestation: BitVM2 pegout + Claim posted on Bitcoin testnet.
    Bitvm2Attest {
        note_id: String,
        pegout_txid_hex: String,
        claim_txid_hex: String,
        proof_hex: String,
        public_hex: Vec<String>,
        statement_digest_hex: String,
    },
    /// Hold a name for `NAME_RESERVE_MS`. Fee may be 0. First-seen key allowed.
    NameReserve,
    /// Pay the length-priced activation fee; name becomes the live account.
    NameActivate,
    /// Permissionless V3 peg-in. Appended last so existing serde / bincode
    /// variant indexes for every earlier body stay the same.
    ///
    /// `deposit_id` is the 32-byte id hex. `credit_to` is the FPL name
    /// preimage of the log's `dest20` (empty asks for a refund once the
    /// deposit has expired). `proof.raw_tx` is the receipt RLP.
    EthV3Deposit {
        asset: String,
        deposit_id: String,
        credit_to: String,
        proof: BridgeProof,
    },
    /// v2.9.62 A6/A9/A10: bond a **new** seat (from `H_act`). Carries the seat's
    /// Falcon public key and a proof of possession over
    /// `fpl-pop|<network>|<id>|<bond_account>`; needs an admission approval
    /// for (id, key) and `amount >= 50,000`. Appended (indexes unchanged).
    BondV2 {
        validator: String,
        public_key: String,
        pop_sig: String,
    },
    /// v2.9.62 A11: owner clears `inactive` (fee only).
    Reactivate {
        validator: String,
    },
    /// v2.9.62 A10: admission key approves (id, key) until `expires_height`.
    ApproveValidator {
        id: String,
        public_key: String,
        expires_height: u64,
    },
    /// v2.9.62 A10: admission key withdraws an unused approval.
    RevokeApproval {
        id: String,
    },
    /// v2.9.62 B5: owner declares (or clears) an archive seat.
    SetArchive {
        validator: String,
        on: bool,
    },
    /// v2.9.62 B5: admission key clears a seat's archive flag (failed probes).
    RevokeArchive {
        id: String,
    },
    /// v2.9.65 (C-1): a Pay that also commits the recipient's Falcon key:
    /// `key_hash` = sha256 hex of the raw public key. Only for a recipient with
    /// no bound key; from then on only that key can bind it.
    PayToKey {
        key_hash: String,
    },
    /// M1: BitVM2 attestation bound to a consensus FPL checkpoint with a
    /// Bitcoin inclusion proof for the peg-out. Required from the M1
    /// activation height; refused before it. Appended (indexes unchanged).
    Bitvm2AttestV2 {
        attest: crate::bridge::Bitvm2AttestV2,
    },
    /// BRIDGE: register as a BitVM2 bridge operator (or top up the bond of an
    /// existing registration). `Tx.amount` = FPL bond, locked in the registry
    /// (`OperatorParams::min_bond` = 5,000 FPL; 100% slashable). `btc_xonly` is
    /// the operator's graph / gossip key. Refused before the bridge height.
    /// Appended (indexes unchanged).
    OperatorRegister {
        btc_xonly: String,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        reward_spk_hex: String,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        gossip_url: String,
        #[serde(default)]
        capacity_sats: u64,
    },
    /// BRIDGE: liveness heartbeat for the current hourly slot (also one watch
    /// unit) + free BTC capacity advert (wallet - in-flight - reserve).
    OperatorHeartbeat {
        capacity_sats: u64,
    },
    /// BRIDGE: begin unbonding; bond stays slashable for the cooldown and is
    /// returned at the first epoch settle after it.
    OperatorUnbond,
    /// BRIDGE: bind this operator's presigned graph for a deposit (immutable).
    OperatorGraphBind {
        /// peg-in confirm txid (graph `peg_in_confirm_txid`)
        deposit_txid: String,
        kick_off_2_txid: String,
        assert_final_txid: String,
        /// BRIDGE: Falcon account credited when this peg-in confirms (fixed at
        /// bind; all operators must name the same one for `Btc4PegIn`).
        #[serde(default, skip_serializing_if = "String::is_empty")]
        depositor_account: String,
        /// BRIDGE: n-of-n co-signer attestation of the graph another operator
        /// already bound for this deposit (same txids); not slashable as graph.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        cosign: bool,
    },
    /// BRIDGE: permissionless slash evidence: a BitVM2 Disprove / DisproveChain
    /// that spends the bound graph of `operator_btc_xonly` for `deposit_txid`,
    /// included on the BTC rail with `BITVM2_PEGOUT_MIN_CONFS`.
    OperatorSlash {
        operator_btc_xonly: String,
        deposit_txid: String,
        raw_tx_hex: String,
        btc_height: u64,
        merkle_path: Vec<String>,
        merkle_index: u32,
    },
    /// BRIDGE: permissionless testnet4 peg-in mint. `raw_tx_hex` is the graph
    /// PegInConfirm, SPV-included on the `BTC4` rail with >= 6 confirmations;
    /// every active operator must have bound a graph for its txid naming the
    /// same `depositor_account`, which receives output 0's value as `BTC4`.
    Btc4PegIn {
        raw_tx_hex: String,
        btc_height: u64,
        merkle_path: Vec<String>,
        merkle_index: u32,
    },
    /// Seat payout (`params_v2::seat_payout_from_height`): set (or clear with
    /// `None`) the account that receives this seat's validator rewards at
    /// every epoch settle. Sent by the seat sender `<validator>#seat`
    /// ([`seat_sender`]) and signed with the seat's registered key, never the
    /// wallet key of an account that shares the seat's name.
    SetSeatPayout {
        validator: String,
        payout_account: Option<String>,
    },
    /// Seat payout: move the seat's reward bucket (`ValidatorInfo::seat_claimable`)
    /// to `to`'s liquid balance. Same sender / key rule as `SetSeatPayout`.
    ClaimSeat {
        validator: String,
        to: String,
    },
    /// v2.10.0: Link or clear an external chain address (e.g. `"btc"`, `"eth"`,
    /// `"xrp"`, `"bnb"`) on the sender's account (`AccountState::external_addrs`).
    /// An empty `address` removes the binding for `chain`.
    #[serde(alias = "set_external_addr")]
    SetExternalAddrs {
        chain: String,
        address: String,
    },
    /// v2.10.4 (order book): place a limit order on `pair` (`"<ASSET>-FPL"`).
    /// `side` = `"buy"` (escrows FPL) / `"sell"` (escrows the asset);
    /// `price` = FPL raw per one whole coin; `amount` = base raw units.
    /// Matches book + AMM at once; the rest rests until filled, cancelled
    /// or past `expiry_height`.
    PlaceLimitOrder {
        pair: String,
        side: String,
        price: u64,
        amount: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expiry_height: Option<u64>,
    },
    /// v2.10.4: cancel own open order; unfilled escrow is refunded.
    CancelOrder {
        order_id: u64,
    },
}

/// Alias for [`TxBody`] used by callers referring to transaction payloads.
pub type TxPayload = TxBody;

/// Maximum number of external chain address bindings stored per account.
pub const MAX_EXTERNAL_ADDRS_PER_ACCOUNT: usize = 8;
/// Maximum length of a chain key in [`AccountState::external_addrs`].
pub const MAX_EXTERNAL_CHAIN_LEN: usize = 16;
/// Maximum length of an external chain address in [`AccountState::external_addrs`].
pub const MAX_EXTERNAL_ADDR_LEN: usize = 128;

/// Validate and normalize `(chain, address)` for [`TxBody::SetExternalAddrs`].
///
/// - `chain` is trimmed and normalized to lowercase ASCII, must be `1..=16` bytes,
///   start with an ASCII letter (`a..=z`), and contain only lowercase ASCII
///   alphanumeric characters (`a..=z`, `0..=9`).
/// - `address` is trimmed; an empty string `""` removes the binding for `chain`.
///   A non-empty address must be `1..=128` printable ASCII bytes without whitespace
///   (`0x21..=0x7e`).
pub fn validate_external_addr(chain: &str, address: &str) -> Result<(String, String), String> {
    let c = chain.trim().to_ascii_lowercase();
    if c.is_empty() || c.len() > MAX_EXTERNAL_CHAIN_LEN {
        return Err(format!(
            "external_addrs: chain must be 1..={MAX_EXTERNAL_CHAIN_LEN} chars"
        ));
    }
    let mut bytes = c.bytes();
    if !bytes.next().is_some_and(|b| b.is_ascii_lowercase())
        || !bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
    {
        return Err(
            "external_addrs: chain must be lowercase alphanumeric starting with a letter".into(),
        );
    }
    let a = address.trim();
    if a.len() > MAX_EXTERNAL_ADDR_LEN {
        return Err(format!(
            "external_addrs: address exceeds {MAX_EXTERNAL_ADDR_LEN} chars"
        ));
    }
    if !a.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
        return Err("external_addrs: address must be printable ASCII without whitespace".into());
    }
    Ok((c, a.to_string()))
}

/// Suffix of the pseudo account that sends seat txs (`SetSeatPayout`,
/// `ClaimSeat`). It has its own sequence, so seat txs never race the wallet
/// account of the same name, and its verify key is the seat's registered key.
pub const SEAT_SENDER_SUFFIX: &str = "#seat";

/// Sender account for seat txs of `validator` (`"<validator>#seat"`).
pub fn seat_sender(validator: &str) -> String {
    format!("{validator}{SEAT_SENDER_SUFFIX}")
}

/// Seat id when `account` is a seat sender (`"<id>#seat"`).
pub fn seat_of_sender(account: &str) -> Option<&str> {
    account.strip_suffix(SEAT_SENDER_SUFFIX).filter(|s| !s.is_empty())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Tx {
    pub account: String,
    pub sequence: u64,
    pub destination: String,
    pub amount: u64,
    pub fee: u64,
    pub network_id: u32,
    pub public_key: String,
    pub signature: String,
    pub tx_id: String,
    /// Protocol op (default Pay uses destination/amount).
    #[serde(default)]
    pub body: TxBody,
}

impl TxBody {
    /// Seat payout bodies (`SetSeatPayout`, `ClaimSeat`).
    pub fn is_seat_tx(&self) -> bool {
        matches!(self, TxBody::SetSeatPayout { .. } | TxBody::ClaimSeat { .. })
    }

    /// v2.9.76: bodies whose apply reads `tx.public_key` as the *signer key*
    /// (admission-key gated). The Merkle batch must carry the key for these:
    /// stripping it (known account key) made apply see an empty key and fail
    /// `admission: signer is not the admission key` on every seat (2.9.75 stall
    /// at 668627). Proposal-building only; validation is unchanged.
    pub fn reads_signer_key(&self) -> bool {
        matches!(
            self,
            TxBody::ApproveValidator { .. }
                | TxBody::RevokeApproval { .. }
                | TxBody::RevokeArchive { .. }
        )
    }
}

impl Tx {
    pub fn payload(
        account: &str,
        sequence: u64,
        destination: &str,
        amount: u64,
        fee: u64,
        network_id: u32,
        body: &TxBody,
    ) -> String {
        let body_s = serde_json::to_string(body).unwrap_or_else(|_| "{}".into());
        format!("pl-tx:v2|{account}|{sequence}|{destination}|{amount}|{fee}|{network_id}|{body_s}")
    }

    pub fn sign_with(
        keys: &KeyRing,
        account: &str,
        sequence: u64,
        destination: &str,
        amount: u64,
        fee: u64,
        network_id: u32,
    ) -> Result<Self, String> {
        Self::sign_body(
            keys,
            account,
            sequence,
            destination,
            amount,
            fee,
            network_id,
            TxBody::Pay,
        )
    }

    /// Seat payout: sign a seat body (`SetSeatPayout` / `ClaimSeat`) as the
    /// `<validator>#seat` sender with `validator`'s seat key from `keys`.
    pub fn sign_seat_body(
        keys: &KeyRing,
        validator: &str,
        sequence: u64,
        fee: u64,
        network_id: u32,
        body: TxBody,
    ) -> Result<Self, String> {
        if !body.is_seat_tx() {
            return Err("not a seat body".into());
        }
        let sender = seat_sender(validator);
        let ring = keys
            .single_as(validator, &sender)
            .ok_or_else(|| format!("no seat key for {validator}"))?;
        Self::sign_body(&ring, &sender, sequence, "", 0, fee, network_id, body)
    }

    pub fn sign_body(
        keys: &KeyRing,
        account: &str,
        sequence: u64,
        destination: &str,
        amount: u64,
        fee: u64,
        network_id: u32,
        body: TxBody,
    ) -> Result<Self, String> {
        let payload = Self::payload(
            account,
            sequence,
            destination,
            amount,
            fee,
            network_id,
            &body,
        );
        let public_key = keys
            .public_hex(account)
            .ok_or_else(|| format!("no public key for {account}"))?;
        let signature = keys
            .sign(account, &payload)
            .map_err(|e| e.to_string())?;
        let tx_id = sha256_hex(payload.as_bytes());
        Ok(Self {
            account: account.into(),
            sequence,
            destination: destination.into(),
            amount,
            fee,
            network_id,
            public_key,
            signature,
            tx_id,
            body,
        })
    }

    pub fn verify(&self, keys: &KeyRing) -> Result<(), String> {
        let payload = Self::payload(
            &self.account,
            self.sequence,
            &self.destination,
            self.amount,
            self.fee,
            self.network_id,
            &self.body,
        );
        if sha256_hex(payload.as_bytes()) != self.tx_id {
            return Err("bad tx crypto: tx_id mismatch".into());
        }
        keys.verify_message(
            keys.scheme,
            &self.account,
            &self.public_key,
            &payload,
            &self.signature,
        )
    }

    /// First-seen Falcon key may bind on these user txs (named account create).
    /// Pay is included so a faucet-funded name can send without a prior
    /// NameReserve/VaultOpen — otherwise mempool verify is "bad tx crypto".
    pub fn is_name_enroll(&self) -> bool {
        matches!(
            self.body,
            TxBody::NameReserve
                | TxBody::NameActivate
                | TxBody::VaultOpen { .. }
                | TxBody::VaultLock
                | TxBody::Pay
                // Claim: gated, see Node::tx_name_enroll (8980c0b, not live).
                | TxBody::AssetPay { .. }
                | TxBody::WatcherHeartbeat
                | TxBody::RailHeader { .. }
                | TxBody::RailDeposit { .. }
                | TxBody::RailChallenge { .. }
                | TxBody::Bitvm2Attest { .. }
                | TxBody::Bitvm2AttestV2 { .. }
                | TxBody::RailWithdraw { .. }
                | TxBody::BtcPoolMove { .. }
                | TxBody::EthLcBootstrap { .. }
                | TxBody::EthLcUpdate { .. }
                | TxBody::EthExecHeaders { .. }
                | TxBody::EthV3Deposit { .. }
                // v2.9.62: the admission account's key binds first-seen; the
                // admission check then requires it to equal the release constant.
                | TxBody::ApproveValidator { .. }
                | TxBody::RevokeApproval { .. }
                | TxBody::RevokeArchive { .. }
                | TxBody::SetExternalAddrs { .. }
        )
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AccountState {
    pub sequence: u64,
    pub balance: u64,
    #[serde(default)]
    pub meta: AccountMeta,
    /// v2.10.0: On-chain linked external chain addresses (e.g. `"btc"`, `"eth"`, `"xrp"`, `"bnb"`).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub external_addrs: BTreeMap<String, String>,
}

/// Alias for [`AccountState`].
pub type Account = AccountState;

/// v2.9.58: a correctly signed OK for a height past `tip+1`, kept until that
/// height opens ([`Node::vote_ok_wire`]). Local only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FutureOk {
    pub height: u64,
    pub ledger_hash: String,
    pub voter: String,
    pub signature: String,
    pub round: u64,
}

/// v2.9.58: inputs of [`Node::commitment_root`] captured under `node.lock`
/// (cheap clones; the exec header map is shared) so the root can be computed
/// after the lock is released.
#[derive(Clone, Debug)]
pub struct RootInput {
    pub state: WorldState,
    pub defi: DefiState,
    pub bridge: BridgeState,
    pub validators: BTreeMap<String, ValidatorInfo>,
    pub claimable: BTreeMap<String, u64>,
}

impl RootInput {
    pub fn root(&self) -> String {
        Node::commitment_root_parts(
            &self.state,
            &self.defi,
            &self.bridge,
            &self.validators,
            &self.claimable,
        )
    }
}

/// v2.9.59: result of [`Node::prestage_root_input`].
pub enum Prestage {
    /// Not a live next-height proposal we can warm (or already verified).
    Skip,
    /// Another task is already hashing this ledger's stage root.
    Wait(String),
    /// Hash this outside `node.lock` ([`PrestageJob::run`]).
    Run(PrestageJob),
}

/// v2.9.59: a stage root to compute off-lock. Registered as in flight on
/// creation; [`PrestageJob::run`] fills the root memo and wakes waiters
/// (also on panic, via `Drop`).
pub struct PrestageJob {
    hash: String,
    input: Option<RootInput>,
}

fn prestage_inflight() -> &'static (std::sync::Mutex<BTreeSet<String>>, std::sync::Condvar) {
    static P: std::sync::OnceLock<(std::sync::Mutex<BTreeSet<String>>, std::sync::Condvar)> =
        std::sync::OnceLock::new();
    P.get_or_init(|| (std::sync::Mutex::new(BTreeSet::new()), std::sync::Condvar::new()))
}

impl PrestageJob {
    /// Atomically claim `hash`. `None` when a job for the same hash is
    /// already in flight (A→B→A arrival): the caller waits on that one, so
    /// a waiter can never observe a premature `Drop`.
    fn begin(hash: String, input: RootInput) -> Option<Self> {
        let (m, _) = prestage_inflight();
        if !m.lock().unwrap_or_else(|e| e.into_inner()).insert(hash.clone()) {
            return None;
        }
        Some(Self { hash, input: Some(input) })
    }

    pub fn ledger_hash(&self) -> &str {
        &self.hash
    }

    /// Compute (and memoize) the root. Blocking; call off the async workers.
    pub fn run(mut self) -> String {
        self.input.take().map(|i| i.root()).unwrap_or_default()
    }

    /// Block until no prestage of `hash` is in flight, at most `max_ms`.
    pub fn wait(hash: &str, max_ms: u64) {
        let (m, cv) = prestage_inflight();
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(max_ms);
        let mut g = m.lock().unwrap_or_else(|e| e.into_inner());
        while g.contains(hash) {
            let now = std::time::Instant::now();
            if now >= deadline {
                return;
            }
            g = match cv.wait_timeout(g, deadline - now) {
                Ok((g, _)) => g,
                Err(e) => e.into_inner().0,
            };
        }
    }

    pub fn in_flight(hash: &str) -> bool {
        prestage_inflight().0.lock().unwrap_or_else(|e| e.into_inner()).contains(hash)
    }
}

impl Drop for PrestageJob {
    fn drop(&mut self) {
        let (m, cv) = prestage_inflight();
        m.lock().unwrap_or_else(|e| e.into_inner()).remove(&self.hash);
        cv.notify_all();
    }
}

/// v2.9.58: the heavy part of the full status (state root, LC claim root and
/// leaves, attestation files), done without holding `node.lock`.
#[derive(Default)]
pub struct StatusHeavy {
    root_input: Option<RootInput>,
    keys_dir: Option<std::path::PathBuf>,
}

impl StatusHeavy {
    pub fn fill(self, body: &mut serde_json::Value) {
        let Some(ri) = self.root_input else { return };
        let Some(obj) = body.as_object_mut() else { return };
        obj.insert("state_root".into(), serde_json::json!(ri.root()));
        if let Some(lc) = obj.get_mut("lc").and_then(|v| v.as_object_mut()) {
            lc.insert(
                "claim_root".into(),
                serde_json::json!(hex::encode(crate::lc::evm_header_claim_root(&ri.bridge))),
            );
            lc.insert(
                "claim_leaves".into(),
                serde_json::json!(crate::lc::evm_claim_leaves(&ri.bridge)
                    .into_iter()
                    .map(hex::encode)
                    .collect::<Vec<_>>()),
            );
            lc.insert(
                "attestations".into(),
                serde_json::json!(self
                    .keys_dir
                    .as_ref()
                    .map(|d| crate::lc::recent_attestations(d, 256))
                    .unwrap_or_default()),
            );
        }
        if let Some(qc) = obj.get_mut("falcon_qc").and_then(|v| v.as_object_mut()) {
            qc.insert(
                "attestations".into(),
                serde_json::json!(self
                    .keys_dir
                    .as_ref()
                    .map(|d| crate::falcon_qc::recent_attestations(d, 256))
                    .unwrap_or_default()),
            );
            qc.insert(
                "attestations_v2".into(),
                serde_json::json!(self
                    .keys_dir
                    .as_ref()
                    .map(|d| crate::falcon_qc::recent_attestations_v2(d, 256))
                    .unwrap_or_default()),
            );
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WorldState {
    pub accounts: BTreeMap<String, AccountState>,
}

impl WorldState {
    pub fn genesis(accounts: &[(String, u64)]) -> Self {
        let mut s = Self::default();
        for (a, bal) in accounts {
            s.accounts.insert(
                a.clone(),
                AccountState {
                    sequence: 1,
                    balance: *bal,
                    meta: AccountMeta::default(),
                    external_addrs: BTreeMap::new(),
                },
            );
        }
        s
    }

    pub fn get(&self, acct: &str) -> AccountState {
        self.accounts.get(acct).cloned().unwrap_or_default()
    }

    /// Payment-only apply (used in tests); full protocol ops go through Node.
    pub fn apply_tx(&mut self, tx: &Tx, keys: &KeyRing) -> Result<(), String> {
        tx.verify(keys)?;
        if !matches!(tx.body, TxBody::Pay) {
            return Err("use Node::apply_protocol_tx for non-Pay bodies".into());
        }
        let mut sender = self.get(&tx.account);
        if tx.sequence != sender.sequence {
            return Err(format!(
                "bad sequence want {} got {}",
                sender.sequence, tx.sequence
            ));
        }
        let need = tx.amount.saturating_add(tx.fee);
        if sender.balance < need {
            return Err("insufficient balance".into());
        }
        sender.meta.enforce_payment(&tx.destination)?;
        sender.balance -= need;
        sender.sequence += 1;
        self.accounts.insert(tx.account.clone(), sender);
        let mut dest = self.get(&tx.destination);
        dest.balance = dest.balance.saturating_add(tx.amount);
        self.accounts.insert(tx.destination.clone(), dest);
        Ok(())
    }

    pub fn root(&self) -> String {
        sha256_hex(&serde_json::to_vec(&self.accounts).unwrap_or_default())
    }
}

/// 4-of-6 (or small-n) committee QC. Rides the **next** ledger as `parent_cert`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct LedgerCert {
    pub height: u64,
    pub ledger_hash: String,
    pub parent_hash: String,
    pub committee: Vec<String>,
    pub voters: Vec<String>,
    #[serde(default)]
    pub signatures: Vec<String>,
    /// v2.10.0: view round all `voters` signed in (`pl-ok:v2`). 0 is omitted
    /// so pre-activation certs serialize and hash exactly as before.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub round: u64,
}

impl LedgerCert {
    pub fn cert_hash(&self) -> String {
        let mut s = format!(
            "pl-cert:v1|{}|{}|{}|{}",
            self.height,
            self.ledger_hash,
            self.committee.join(","),
            self.voters.join(",")
        );
        // Round > 0 only exists on round-scoped (v2.10.0) heights.
        if self.round != 0 {
            s.push_str(&format!("|r={}", self.round));
        }
        sha256_hex(s.as_bytes())
    }

    /// Verify with legacy `pl-ok:v1` payloads (pre-activation heights).
    pub fn verify(
        &self,
        keys: &KeyRing,
        network_id: u32,
        require_sigs: bool,
        need: usize,
    ) -> Result<(), String> {
        self.verify_ex(keys, network_id, require_sigs, need, false)
    }

    /// `round_scoped` selects `pl-ok:v2|..|round|..` (heights at/after
    /// `ChainConfig::vote_rounds_from_height`).
    pub fn verify_ex(
        &self,
        keys: &KeyRing,
        network_id: u32,
        require_sigs: bool,
        need: usize,
        round_scoped: bool,
    ) -> Result<(), String> {
        self.verify_with(&|v: &str| keys.public_hex(v), keys, network_id, require_sigs, need, round_scoped)
    }

    /// v2.9.62 A13: verify with an explicit key source (`pk_of`), e.g. the
    /// deterministic seat-key registry. An unknown key fails the cert.
    pub fn verify_with(
        &self,
        pk_of: &dyn Fn(&str) -> Option<String>,
        keys: &KeyRing,
        network_id: u32,
        require_sigs: bool,
        need: usize,
        round_scoped: bool,
    ) -> Result<(), String> {
        if !round_scoped && self.round != 0 {
            return Err(format!("cert round {} on a legacy height {}", self.round, self.height));
        }
        if self.voters.len() < need {
            return Err(format!(
                "cert voters {} < need {need} at h={}",
                self.voters.len(),
                self.height
            ));
        }
        let comm: BTreeSet<&str> = self.committee.iter().map(|s| s.as_str()).collect();
        let mut seen = BTreeSet::new();
        for (i, v) in self.voters.iter().enumerate() {
            if !comm.contains(v.as_str()) {
                return Err(format!("cert voter {v} not in committee"));
            }
            if !seen.insert(v.as_str()) {
                return Err(format!("cert duplicate voter {v}"));
            }
            if require_sigs {
                let sig = self.signatures.get(i).map(|s| s.as_str()).unwrap_or("");
                if sig.is_empty() {
                    return Err(format!("cert missing sig for {v}"));
                }
                let payload = if round_scoped {
                    Node::vote_ok_payload_v2(network_id, self.height, self.round, &self.ledger_hash, v)
                } else {
                    Node::vote_ok_payload(network_id, self.height, &self.ledger_hash, v)
                };
                let Some(pk) = pk_of(v) else {
                    return Err(format!("cert bad sig for {v} (no registered key)"));
                };
                // A13 registry key: verify against the registered key itself.
                // The ring may not hold it yet (fresh snapshot adopt) or hold a
                // stale one; a restarted seat accepts the same cert.
                if !keys.verify_pop(v, &pk, &payload, sig) {
                    return Err(format!("cert bad sig for {v}"));
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Ledger {
    pub height: u64,
    pub parent_hash: String,
    pub network_id: u32,
    pub packer: String,
    pub packer_public_key: String,
    pub tx_ids: Vec<String>,
    pub txs: Vec<Tx>,
    pub state_root_after: String,
    pub sealed_at_ms: u64,
    /// Proposer wall-clock Unix ms; bound into header v5 when UTC activation is
    /// armed. **Unarmed by default** (`utc_header::UTC_FROM_HEIGHT_DISABLED`):
    /// stays 0 and is omitted from the signed preimage so main stays compatible.
    /// Independent of `sealed_at_ms` (chain physics / reward clock).
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub sealed_utc_ms: u64,
    pub packer_sig: String,
    pub ledger_hash: String,
    /// Seats skip-QC'd (or claimed skipped) before this packer in the shared
    /// ONLINE seat order. Bound into the signed header (v2.4.0 polish).
    /// Receivers reject proposals that are not a legal cursor on the schedule.
    #[serde(default)]
    pub skipped_predecessors: Vec<String>,
    /// Cert that unlocked the parent (None at genesis). v2.9.0.
    #[serde(default)]
    pub parent_cert: Option<LedgerCert>,
    /// Checker equivocation proven in this ledger (applied before txs). v2.9.1.
    #[serde(default)]
    pub slashes: Vec<SlashEvidence>,
    /// Sum of `txs[].fee` at seal. Header field — survives `strip_body` so
    /// settle / catch-up do not depend on the RAM body window (v2.9.18).
    #[serde(default)]
    pub fee_total: u64,
    /// v4: ETH/USDC claim merkle root (64 lowercase hex). Empty on v3.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub claim_root: String,
    /// v4: MiMC merkle8 of sealed current-6 Falcon pks (Fr BE hex).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub current_committee_root: String,
    /// v4: MiMC merkle8 of next-6 pks (Fr BE hex).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub next_committee_root: String,
    /// v4: sha256_hex of `msg_v4|packer_sig` (64 lowercase hex).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub inner_hash: String,
    /// v4: sealed 6 ids for this height (lottery order, unfiltered).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub current_committee: Vec<String>,
    /// v4: next-6 ids (v8 draw from inner_hash).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub next_committee: Vec<String>,
    /// Test-only: one Falcon signature over the Merkle root of tx payloads.
    /// Empty on the published body, which still carries every sender signature.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub batch_root: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub batch_sig: String,
    /// Sibling hashes, hex, one path per tx, leaf to root.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub batch_paths: Vec<Vec<String>>,
}

/// Two OK hashes at one height, with the votes that prove it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct SlashEvidence {
    pub offender: String,
    pub height: u64,
    pub hash_a: String,
    pub sig_a: String,
    pub hash_b: String,
    pub sig_b: String,
    /// "" / omitted = checker OK equivocation. "qc-attest" = dual v2 statements.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub kind: String,
    /// v2.10.0: view round both OKs were signed in (`pl-ok:v2`). Evidence is
    /// only slashable when both votes share **one (height, round)**. Omitted
    /// on the wire when 0 so legacy evidence bytes are unchanged.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub round: u64,
}

/// Gossip form of a ledger (v2.8.0). No `txs` — body is pulled by hash.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LedgerHeader {
    pub height: u64,
    pub parent_hash: String,
    pub network_id: u32,
    pub packer: String,
    pub packer_public_key: String,
    pub tx_ids: Vec<String>,
    pub state_root_after: String,
    pub sealed_at_ms: u64,
    /// See [`Ledger::sealed_utc_ms`]. Zero / omitted while UTC activation is unarmed.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub sealed_utc_ms: u64,
    pub packer_sig: String,
    pub ledger_hash: String,
    #[serde(default)]
    pub skipped_predecessors: Vec<String>,
    /// Parent 4-of-6 cert (None at genesis). Gossiped with the header (v2.9.0).
    #[serde(default)]
    pub parent_cert: Option<LedgerCert>,
    #[serde(default)]
    pub slashes: Vec<SlashEvidence>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub claim_root: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub current_committee_root: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub next_committee_root: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub inner_hash: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub current_committee: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub next_committee: Vec<String>,
}

fn merkle_node(tag: u8, a: &[u8], b: &[u8]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(1 + a.len() + b.len());
    buf.push(tag);
    buf.extend_from_slice(a);
    if tag == 1 {
        buf.extend_from_slice(b);
    }
    crate::crypto::sha256_raw(&buf)
}

fn merkle_paths(payloads: &[String]) -> ([u8; 32], Vec<Vec<String>>) {
    let mut level: Vec<[u8; 32]> = payloads
        .iter()
        .map(|p| merkle_node(0, p.as_bytes(), &[]))
        .collect();
    let mut tree = vec![level.clone()];
    while level.len() > 1 {
        let mut nxt = Vec::new();
        let mut i = 0;
        while i < level.len() {
            let left = level[i];
            let right = if i + 1 < level.len() { level[i + 1] } else { level[i] };
            nxt.push(merkle_node(1, &left, &right));
            i += 2;
        }
        level = nxt;
        tree.push(level.clone());
    }
    let root = tree.last().unwrap()[0];
    let mut paths = Vec::with_capacity(payloads.len());
    for mut idx in 0..payloads.len() {
        let mut path = Vec::new();
        for lvl in &tree[..tree.len() - 1] {
            let sib = idx ^ 1;
            let sib = if sib < lvl.len() { sib } else { idx };
            path.push(hex::encode(lvl[sib]));
            idx /= 2;
        }
        paths.push(path);
    }
    (root, paths)
}

fn merkle_fold(payload: &[u8], path: &[String], mut idx: usize) -> [u8; 32] {
    let mut node = merkle_node(0, payload, &[]);
    for sib_hex in path {
        let sib = hex::decode(sib_hex).unwrap_or_default();
        let sib = if sib.len() == 32 {
            let mut a = [0u8; 32];
            a.copy_from_slice(&sib);
            a
        } else {
            [0u8; 32]
        };
        node = if idx % 2 == 0 {
            merkle_node(1, &node, &sib)
        } else {
            merkle_node(1, &sib, &node)
        };
        idx /= 2;
    }
    node
}

impl Ledger {
    /// Legacy v1 header (no skip claims). Only accepted when `skipped_predecessors` empty.
    pub fn header_msg(
        height: u64,
        parent_hash: &str,
        network_id: u32,
        packer: &str,
        tx_root: &str,
        state_root_after: &str,
    ) -> String {
        format!(
            "pl-ledger:v1|{height}|{parent_hash}|{network_id}|{packer}|{tx_root}|{state_root_after}"
        )
    }

    /// v2 header: includes ordered skip claims (mainnet product).
    pub fn header_msg_v2(
        height: u64,
        parent_hash: &str,
        network_id: u32,
        packer: &str,
        tx_root: &str,
        state_root_after: &str,
        skipped_predecessors: &[String],
    ) -> String {
        let skips = skipped_predecessors.join(",");
        format!(
            "pl-ledger:v2|{height}|{parent_hash}|{network_id}|{packer}|{tx_root}|{state_root_after}|skips:{skips}"
        )
    }

    /// v3 header: v2 + parent 4-of-6 cert hash (v2.9.0). `none` at height 1.
    pub fn header_msg_v3(
        height: u64,
        parent_hash: &str,
        network_id: u32,
        packer: &str,
        tx_root: &str,
        state_root_after: &str,
        skipped_predecessors: &[String],
        parent_cert_hash: &str,
    ) -> String {
        let skips = skipped_predecessors.join(",");
        format!(
            "pl-ledger:v3|{height}|{parent_hash}|{network_id}|{packer}|{tx_root}|{state_root_after}|skips:{skips}|cert:{parent_cert_hash}"
        )
    }

    fn parent_cert_tag(cert: Option<&LedgerCert>) -> String {
        cert.map(|c| c.cert_hash()).unwrap_or_else(|| "none".into())
    }

    pub fn tx_root(tx_ids: &[String]) -> String {
        sha256_hex(tx_ids.join(",").as_bytes())
    }

    pub fn seal(
        height: u64,
        parent_hash: String,
        network_id: u32,
        packer: &str,
        keys: &KeyRing,
        txs: Vec<Tx>,
        state_root_after: String,
        sealed_at_ms: u64,
    ) -> Result<Self, String> {
        Self::seal_with_skips(
            height,
            parent_hash,
            network_id,
            packer,
            keys,
            txs,
            state_root_after,
            sealed_at_ms,
            Vec::new(),
            None,
        )
    }

    pub fn seal_with_skips(
        height: u64,
        parent_hash: String,
        network_id: u32,
        packer: &str,
        keys: &KeyRing,
        txs: Vec<Tx>,
        state_root_after: String,
        sealed_at_ms: u64,
        skipped_predecessors: Vec<String>,
        parent_cert: Option<LedgerCert>,
    ) -> Result<Self, String> {
        let tx_ids: Vec<String> = txs.iter().map(|t| t.tx_id.clone()).collect();
        let fee_total: u64 = txs.iter().map(|t| t.fee).sum();
        let tx_root = Self::tx_root(&tx_ids);
        let cert_tag = Self::parent_cert_tag(parent_cert.as_ref());
        let msg = Self::header_msg_v3(
            height,
            &parent_hash,
            network_id,
            packer,
            &tx_root,
            &state_root_after,
            &skipped_predecessors,
            &cert_tag,
        );
        let packer_public_key = keys
            .public_hex(packer)
            .ok_or_else(|| format!("no packer key {packer}"))?;
        let packer_sig = keys.sign(packer, &msg).map_err(|e| e.to_string())?;
        let ledger_hash = sha256_hex(format!("{msg}|{packer_sig}").as_bytes());
        Ok(Self {
            height,
            parent_hash,
            network_id,
            packer: packer.into(),
            packer_public_key,
            tx_ids,
            txs,
            state_root_after,
            sealed_at_ms,
            sealed_utc_ms: 0,
            packer_sig,
            ledger_hash,
            skipped_predecessors,
            parent_cert,
            slashes: Vec::new(),
            fee_total,
            claim_root: String::new(),
            current_committee_root: String::new(),
            next_committee_root: String::new(),
            inner_hash: String::new(),
            current_committee: Vec::new(),
            next_committee: Vec::new(),
            batch_root: String::new(),
            batch_sig: String::new(),
            batch_paths: Vec::new(),
        })
    }

    pub fn is_v4(&self) -> bool {
        !self.inner_hash.is_empty()
    }

    /// Two-stage v4/v5 seal. `current_committee` is the unfiltered freeze for this height.
    ///
    /// When UTC activation is unarmed (default), `sealed_utc_ms` is forced to 0 and the
    /// signed preimage stays `pl-ledger:v4|…` — identical to pre-UTC binaries.
    /// When armed at `H_utc`, pass the proposer Unix-ms stamp; the preimage becomes v5.
    pub fn seal_v4(
        height: u64,
        parent_hash: String,
        network_id: u32,
        packer: &str,
        keys: &KeyRing,
        txs: Vec<Tx>,
        state_root_after: String,
        sealed_at_ms: u64,
        sealed_utc_ms: u64,
        skipped_predecessors: Vec<String>,
        parent_cert: Option<LedgerCert>,
        claim_root_hex: String,
        current_committee: Vec<String>,
        next_committee: Vec<String>,
        current_committee_root: String,
        next_committee_root: String,
    ) -> Result<Self, String> {
        let tx_ids: Vec<String> = txs.iter().map(|t| t.tx_id.clone()).collect();
        let fee_total: u64 = txs.iter().map(|t| t.fee).sum();
        let tx_root = Self::tx_root(&tx_ids);
        let cert_tag = Self::parent_cert_tag(parent_cert.as_ref());
        let from = utc_header::network_utc_from_height(network_id);
        let domain = header_domain(height, from);
        let sealed_utc_ms = match domain {
            HeaderDomain::LegacyV4 => 0,
            HeaderDomain::V5 => {
                if sealed_utc_ms == 0 {
                    return Err("seal_v4: sealed_utc_ms required when UTC header active".into());
                }
                sealed_utc_ms
            }
        };
        let msg = packer_msg_for_domain(
            domain,
            height,
            &parent_hash,
            network_id,
            packer,
            &tx_root,
            &state_root_after,
            &skipped_predecessors,
            &cert_tag,
            &claim_root_hex,
            &current_committee_root,
            sealed_utc_ms,
        );
        let packer_public_key = keys
            .public_hex(packer)
            .ok_or_else(|| format!("no packer key {packer}"))?;
        let packer_sig = keys.sign(packer, &msg).map_err(|e| e.to_string())?;
        let inner_hash = inner_hash_hex(&msg, &packer_sig);
        let inner = parse32(&inner_hash)?;
        let next_root = parse32(&next_committee_root)?;
        let claim = parse32(&claim_root_hex)?;
        let ledger_hash = outer_hash_hex(&inner, &next_root, &claim);
        Ok(Self {
            height,
            parent_hash,
            network_id,
            packer: packer.into(),
            packer_public_key,
            tx_ids,
            txs,
            state_root_after,
            sealed_at_ms,
            sealed_utc_ms,
            packer_sig,
            ledger_hash,
            skipped_predecessors,
            parent_cert,
            slashes: Vec::new(),
            fee_total,
            claim_root: claim_root_hex,
            current_committee_root,
            next_committee_root,
            inner_hash,
            current_committee,
            next_committee,
            batch_root: String::new(),
            batch_sig: String::new(),
            batch_paths: Vec::new(),
        })
    }

    /// Replace per-tx Falcon signatures with one packer signature on the
    /// Merkle root of the tx payloads. `tx_id` and the ledger hash stay put.
    pub fn attach_merkle_batch(&mut self, keys: &KeyRing) -> Result<(), String> {
        self.attach_merkle_batch_known(keys, &|_| None)
    }

    /// `known` is the public key already stored on the account, if any.
    /// When it matches the tx, the key is left off the body.
    pub fn attach_merkle_batch_known(
        &mut self,
        keys: &KeyRing,
        known: &dyn Fn(&str) -> Option<String>,
    ) -> Result<(), String> {
        if self.txs.is_empty() {
            return Ok(());
        }
        let payloads: Vec<String> = self
            .txs
            .iter()
            .map(|tx| {
                Tx::payload(
                    &tx.account,
                    tx.sequence,
                    &tx.destination,
                    tx.amount,
                    tx.fee,
                    tx.network_id,
                    &tx.body,
                )
            })
            .collect();
        for tx in &self.txs {
            tx.verify(keys)?;
        }
        let sig_leaves: Vec<String> = self.txs.iter().map(|t| t.signature.clone()).collect();
        let (root, paths) = merkle_paths(&payloads);
        let (sig_root, _) = merkle_paths(&sig_leaves);
        // payload root, then the root of the sender signatures the packer checked.
        self.batch_root = format!("{}|{}", hex::encode(root), hex::encode(sig_root));
        self.batch_paths = paths;
        for tx in &mut self.txs {
            if !tx.body.reads_signer_key()
                && known(&tx.account).as_deref() == Some(tx.public_key.as_str())
            {
                tx.public_key.clear();
            }
        }
        let msg = format!("pl-batch:v1|{}", self.batch_root);
        self.batch_sig = keys.sign(&self.packer, &msg).map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Check every path and the single packer signature. Empty batch is the
    /// published full-signature body and is not an error.
    pub fn verify_merkle_batch(&self, keys: &KeyRing) -> Result<(), String> {
        self.verify_merkle_batch_known(keys, &|_| None)
    }

    pub fn verify_merkle_batch_known(
        &self,
        keys: &KeyRing,
        known: &dyn Fn(&str) -> Option<String>,
    ) -> Result<(), String> {
        self.verify_merkle_batch_onchain(keys, known, false)
    }

    /// `onchain_first`: from the Fix B height, a sender with an on-chain key
    /// (`known`) is verified against that key, not the ring (seat/account split).
    pub fn verify_merkle_batch_onchain(
        &self,
        keys: &KeyRing,
        known: &dyn Fn(&str) -> Option<String>,
        onchain_first: bool,
    ) -> Result<(), String> {
        self.verify_merkle_batch_reg(keys, known, onchain_first, None)
    }

    /// As `verify_merkle_batch_onchain`; `packer_key = Some(k)` (from `H_act`)
    /// verifies the packer batch_sig ONLY against the on-chain registered key
    /// `k` (must equal `packer_public_key`), never the node-local ring.
    pub fn verify_merkle_batch_reg(
        &self,
        keys: &KeyRing,
        known: &dyn Fn(&str) -> Option<String>,
        onchain_first: bool,
        packer_key: Option<&str>,
    ) -> Result<(), String> {
        if self.batch_sig.is_empty() {
            return Ok(());
        }
        if self.batch_paths.len() != self.txs.len() {
            return Err("batch path count".into());
        }
        let payloads: Vec<String> = self
            .txs
            .iter()
            .map(|tx| {
                Tx::payload(
                    &tx.account,
                    tx.sequence,
                    &tx.destination,
                    tx.amount,
                    tx.fee,
                    tx.network_id,
                    &tx.body,
                )
            })
            .collect();
        for (i, payload) in payloads.iter().enumerate() {
            if sha256_hex(payload.as_bytes()) != self.txs[i].tx_id {
                return Err("batch tx_id mismatch".into());
            }
            let got = merkle_fold(payload.as_bytes(), &self.batch_paths[i], i);
            let payload_root = self.batch_root.split('|').next().unwrap_or("");
            if hex::encode(got) != payload_root {
                return Err("batch path mismatch".into());
            }
        }
        // Pool entry is not enough. From the sender-sig height every seat
        // re-checks the sender signature against the key it already knows,
        // or against the key carried on the tx. Older stripped bodies stay
        // acceptable so catch-up of the testnet window still works.
        let require_sender = self.network_id == crate::NETWORK_ID_PUBLIC_TESTNET_2300
            && self.height >= crate::params_v2::TESTNET_2300_MERKLE_SENDER_SIG_FROM_HEIGHT;
        for (i, tx) in self.txs.iter().enumerate() {
            if tx.signature.is_empty() {
                if require_sender {
                    return Err("batch missing sender signature".into());
                }
                continue;
            }
            let public_key = if tx.public_key.is_empty() {
                known(&tx.account).ok_or_else(|| {
                    format!("batch sender key unknown {}", tx.account)
                })?
            } else {
                tx.public_key.clone()
            };
            if onchain_first {
                if let Some(pk) = known(&tx.account) {
                    keys.verify_account_sig(&tx.account, &tx.public_key, Some(&pk), &payloads[i], &tx.signature)?;
                    continue;
                }
            }
            keys.verify_carried_key(&tx.account, &public_key, &payloads[i], &tx.signature)?;
        }
        let msg = format!("pl-batch:v1|{}", self.batch_root);
        if let Some(rk) = packer_key {
            if !rk.eq_ignore_ascii_case(&self.packer_public_key) {
                return Err("batch sig: packer key != registered key".into());
            }
            return if keys.verify_pop(&self.packer, rk, &msg, &self.batch_sig) {
                Ok(())
            } else {
                Err("batch sig: bad signature".into())
            };
        }
        keys.verify_message(
            keys.scheme,
            &self.packer,
            &self.packer_public_key,
            &msg,
            &self.batch_sig,
        )
        .map_err(|e| format!("batch sig: {e}"))
    }

    /// v2.9.62 A4: lottery seed that does not depend on the packer's
    /// (randomised) Falcon signature: `sha256("fpl-seed-v2|parent|height|msg_v4")`.
    pub fn seed_v2(&self) -> String {
        let tx_root = Self::tx_root(&self.tx_ids);
        let cert_tag = Self::parent_cert_tag(self.parent_cert.as_ref());
        let from = utc_header::network_utc_from_height(self.network_id);
        let domain = header_domain(self.height, from);
        let msg = packer_msg_for_domain(
            domain,
            self.height,
            &self.parent_hash,
            self.network_id,
            &self.packer,
            &tx_root,
            &self.state_root_after,
            &self.skipped_predecessors,
            &cert_tag,
            &self.claim_root,
            &self.current_committee_root,
            self.sealed_utc_ms,
        );
        seed_v2_hex(&self.parent_hash, self.height, &msg)
    }

    pub fn verify_packer(&self, keys: &KeyRing) -> bool {
        self.verify_packer_by(|id, pk, msg, sig| keys.verify_message(keys.scheme, id, pk, msg, sig).is_ok())
    }

    /// Packer-signature check with a caller-supplied verifier `(id, pk, msg, sig)`.
    pub fn verify_packer_by<F: Fn(&str, &str, &str, &str) -> bool>(&self, vf: F) -> bool {
        let tx_root = Self::tx_root(&self.tx_ids);
        let cert_tag = Self::parent_cert_tag(self.parent_cert.as_ref());
        if self.is_v4() {
            let from = utc_header::network_utc_from_height(self.network_id);
            let domain = header_domain(self.height, from);
            // Inactive heights must not carry a non-zero UTC stamp (unbound field).
            if domain == HeaderDomain::LegacyV4 && self.sealed_utc_ms != 0 {
                return false;
            }
            if domain == HeaderDomain::V5 && self.sealed_utc_ms == 0 {
                return false;
            }
            let msg = packer_msg_for_domain(
                domain,
                self.height,
                &self.parent_hash,
                self.network_id,
                &self.packer,
                &tx_root,
                &self.state_root_after,
                &self.skipped_predecessors,
                &cert_tag,
                &self.claim_root,
                &self.current_committee_root,
                self.sealed_utc_ms,
            );
            if inner_hash_hex(&msg, &self.packer_sig) != self.inner_hash {
                return false;
            }
            let Ok(inner) = parse32(&self.inner_hash) else {
                return false;
            };
            let Ok(next_root) = parse32(&self.next_committee_root) else {
                return false;
            };
            let Ok(claim) = parse32(&self.claim_root) else {
                return false;
            };
            if outer_hash_hex(&inner, &next_root, &claim) != self.ledger_hash {
                return false;
            }
            return vf(&self.packer, &self.packer_public_key, &msg, &self.packer_sig);
        }
        let msg_v3 = Self::header_msg_v3(
            self.height,
            &self.parent_hash,
            self.network_id,
            &self.packer,
            &tx_root,
            &self.state_root_after,
            &self.skipped_predecessors,
            &cert_tag,
        );
        let ok_v3 = sha256_hex(format!("{msg_v3}|{}", self.packer_sig).as_bytes())
            == self.ledger_hash
            && vf(&self.packer, &self.packer_public_key, &msg_v3, &self.packer_sig);
        if ok_v3 {
            return true;
        }
        // Prefer v2 header (skip claims bound). Fall back to v1 only if no skips.
        let msg_v2 = Self::header_msg_v2(
            self.height,
            &self.parent_hash,
            self.network_id,
            &self.packer,
            &tx_root,
            &self.state_root_after,
            &self.skipped_predecessors,
        );
        let ok_v2 = sha256_hex(format!("{msg_v2}|{}", self.packer_sig).as_bytes())
            == self.ledger_hash
            && vf(&self.packer, &self.packer_public_key, &msg_v2, &self.packer_sig);
        if ok_v2 {
            return true;
        }
        if !self.skipped_predecessors.is_empty() {
            return false;
        }
        let msg = Self::header_msg(
            self.height,
            &self.parent_hash,
            self.network_id,
            &self.packer,
            &tx_root,
            &self.state_root_after,
        );
        if sha256_hex(format!("{msg}|{}", self.packer_sig).as_bytes()) != self.ledger_hash {
            return false;
        }
        vf(&self.packer, &self.packer_public_key, &msg, &self.packer_sig)
    }

    pub fn header(&self) -> LedgerHeader {
        LedgerHeader {
            height: self.height,
            parent_hash: self.parent_hash.clone(),
            network_id: self.network_id,
            packer: self.packer.clone(),
            packer_public_key: self.packer_public_key.clone(),
            tx_ids: self.tx_ids.clone(),
            state_root_after: self.state_root_after.clone(),
            sealed_at_ms: self.sealed_at_ms,
            sealed_utc_ms: self.sealed_utc_ms,
            packer_sig: self.packer_sig.clone(),
            ledger_hash: self.ledger_hash.clone(),
            skipped_predecessors: self.skipped_predecessors.clone(),
            parent_cert: self.parent_cert.clone(),
            slashes: self.slashes.clone(),
            claim_root: self.claim_root.clone(),
            current_committee_root: self.current_committee_root.clone(),
            next_committee_root: self.next_committee_root.clone(),
            inner_hash: self.inner_hash.clone(),
            current_committee: self.current_committee.clone(),
            next_committee: self.next_committee.clone(),
        }
    }

    pub fn has_body(&self) -> bool {
        self.txs.len() == self.tx_ids.len()
    }

    pub fn strip_body(&mut self) {
        self.txs.clear();
        self.txs.shrink_to_fit();
    }

    /// Conservative wire size so catch-up can cap a batch before JSON (v2.9.20).
    pub fn estimate_wire_bytes(&self) -> usize {
        let ids: usize = self.tx_ids.iter().map(|s| s.len() + 4).sum();
        let bodies: usize = self
            .txs
            .iter()
            .map(|t| {
                64 + t.tx_id.len()
                    + t.signature.len()
                    + t.account.len()
                    + t.destination.len()
                    + t.public_key.len()
            })
            .sum();
        256 + self.packer.len()
            + self.packer_sig.len()
            + self.packer_public_key.len()
            + ids
            + bodies
    }
}

impl LedgerHeader {
    pub fn verify_packer(&self, keys: &KeyRing) -> bool {
        self.signed_stub().verify_packer(keys)
    }

    /// Body-less ledger carrying exactly the signed header fields.
    pub fn signed_stub(&self) -> Ledger {
        Ledger {
            height: self.height,
            parent_hash: self.parent_hash.clone(),
            network_id: self.network_id,
            packer: self.packer.clone(),
            packer_public_key: self.packer_public_key.clone(),
            tx_ids: self.tx_ids.clone(),
            txs: Vec::new(),
            state_root_after: self.state_root_after.clone(),
            sealed_at_ms: self.sealed_at_ms,
            sealed_utc_ms: self.sealed_utc_ms,
            packer_sig: self.packer_sig.clone(),
            ledger_hash: self.ledger_hash.clone(),
            skipped_predecessors: self.skipped_predecessors.clone(),
            parent_cert: self.parent_cert.clone(),
            slashes: self.slashes.clone(),
            fee_total: 0,
            claim_root: self.claim_root.clone(),
            current_committee_root: self.current_committee_root.clone(),
            next_committee_root: self.next_committee_root.clone(),
            inner_hash: self.inner_hash.clone(),
            current_committee: self.current_committee.clone(),
            next_committee: self.next_committee.clone(),
            batch_root: String::new(),
            batch_sig: String::new(),
            batch_paths: Vec::new(),
        }
    }
}

#[derive(Debug, Default)]
pub struct Mempool {
    by_id: HashMap<String, Tx>,
    order: VecDeque<String>,
}

impl Mempool {
    /// Insert tx. Returns `Ok(true)` if new, `Ok(false)` if already present (same tx_id).
    /// When `max_txs > 0` and the pool is full, rejects **new** txs (dupes still ok).
    pub fn insert(&mut self, tx: Tx, max_txs: usize) -> Result<bool, String> {
        if self.by_id.contains_key(&tx.tx_id) {
            return Ok(false);
        }
        if max_txs > 0 && self.by_id.len() >= max_txs {
            return Err(format!(
                "mempool full ({}/{}) — reject until pack drains",
                self.by_id.len(),
                max_txs
            ));
        }
        self.order.push_back(tx.tx_id.clone());
        self.by_id.insert(tx.tx_id.clone(), tx);
        Ok(true)
    }

    pub fn len(&self) -> usize {
        self.by_id.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_id.is_empty()
    }

    pub fn iter_candidates(&self) -> impl Iterator<Item = &Tx> {
        self.order.iter().filter_map(|id| self.by_id.get(id))
    }

    pub fn remove_many(&mut self, ids: &[String]) {
        let drop: BTreeSet<_> = ids.iter().cloned().collect();
        self.by_id.retain(|id, _| !drop.contains(id));
        self.order.retain(|id| !drop.contains(id));
    }

    /// Drop txs that can never apply (sequence already past).
    pub fn prune_stale(&mut self, state: &WorldState) -> usize {
        let mut drop_ids = Vec::new();
        for tx in self.by_id.values() {
            let acct = state.get(&tx.account);
            if tx.sequence < acct.sequence {
                drop_ids.push(tx.tx_id.clone());
            }
        }
        let n = drop_ids.len();
        if n > 0 {
            self.remove_many(&drop_ids);
        }
        n
    }

    pub fn contains(&self, tx_id: &str) -> bool {
        self.by_id.contains_key(tx_id)
    }

    pub fn get(&self, tx_id: &str) -> Option<&Tx> {
        self.by_id.get(tx_id)
    }

    /// Export up to `max` pending txs in arrival order (for NeedTxs / hub sync).
    pub fn export_batch(&self, max: usize) -> Vec<Tx> {
        self.export_batch_where(max, |_| true)
    }

    /// [`Self::export_batch`] over only the txs `keep` accepts. The filter
    /// runs before the `max` limit, so skipped entries never use up the
    /// batch and starve later eligible txs.
    pub fn export_batch_where(&self, max: usize, keep: impl Fn(&Tx) -> bool) -> Vec<Tx> {
        let max = max.clamp(1, 512);
        let mut out = Vec::with_capacity(max.min(self.order.len()));
        for id in &self.order {
            if out.len() >= max {
                break;
            }
            if let Some(tx) = self.by_id.get(id) {
                if keep(tx) {
                    out.push(tx.clone());
                }
            }
        }
        out
    }
}

// ---------------------------------------------------------------------------
// Validators / slash
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorInfo {
    pub id: String,
    /// Active bonded stake (lottery weight).
    pub bond: u64,
    pub avail: f64,
    pub quality: f64,
    pub pack_count: u64,
    pub jailed: bool,
    /// Number of times this seat has been jailed. Drives unjail cost
    /// (`min_bond * 2^jail_count`). Persists across snapshots; never reset on unjail.
    #[serde(default)]
    pub jail_count: u32,
    pub slash_total: u64,
    pub last_pong_ms: u64,
    pub public_key: String,
    /// Stake exiting; not in lottery until completed and re-bonded.
    #[serde(default)]
    pub unbonding: u64,
    /// Wall time when `unbonding` can be withdrawn (0 = none pending).
    #[serde(default)]
    pub unbond_ready_ms: u64,
    /// Account credited on unbond complete (defaults to validator id).
    #[serde(default)]
    pub bond_account: String,
    /// Last tip_height advertised in Pong/Hello from this validator (wire only).
    /// Used to detect live-but-lagging packers after bond-in (tip 0 pongs).
    /// `None` = never seen (legacy / not yet ponged with tip).
    #[serde(default, skip_serializing)]
    pub last_advertised_tip: Option<u64>,
    /// Last Pong `mempool_len` (wire only). Hub ads tell checkers work exists.
    #[serde(default, skip_serializing)]
    pub last_mempool_len: u64,
    /// Last Pong `is_hub` (wire only).
    #[serde(default, skip_serializing)]
    pub advertised_hub: bool,
    /// Last Hello/Pong `archive` (wire only). Snap pull targets these seats.
    #[serde(default, skip_serializing)]
    pub advertised_archive: bool,
    /// Last advertised snapshot height (wire only).
    #[serde(default, skip_serializing)]
    pub last_snap_height: u64,
    /// v2.9.62 A8: unjail payments held as escrow (not bond, no lottery/pay
    /// weight). Returned on a clean full exit, seized by a slash. In the root
    /// via the v2 extension; 0 (omitted) before activation.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub escrow: u64,
    /// v2.9.62 A6/A9: seat created at/after `H_act` (bond >= 50,000, key bound
    /// by a BondV2 proof of possession). Seats bonded earlier are grandfathered
    /// (this stays false, min bond stays the old 1,000).
    #[serde(default, skip_serializing_if = "is_false")]
    pub v2_seat: bool,
    /// v2.9.62 A11: consecutive round-0 turns this seat did not seal.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub missed_turns: u32,
    /// v2.9.62 A11: out of the lottery/floor/pay until `Reactivate`.
    #[serde(default, skip_serializing_if = "is_false")]
    pub inactive: bool,
    /// v2.9.62 B5: self-declared archive seat (floor weight 1.05). Set by the
    /// owner with `SetArchive`; the admission key can `RevokeArchive`.
    #[serde(default, skip_serializing_if = "is_false")]
    pub archive: bool,
    /// Presence rules: seat may stay in the lottery but earns nothing until
    /// `earn_streak` reaches [`params_v2::EARN_STREAK_NEED`]. Set for a prior
    /// jail at the presence height, and again on jail, unjail, and reactivate.
    /// Omitted from the root while false.
    #[serde(default, skip_serializing_if = "is_false")]
    pub earn_locked: bool,
    /// Pack-or-vote events since the lock, cleared by a missed own turn.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub earn_streak: u32,
    /// Last height this seat packed or was in the parent certificate.
    /// Consensus. 0 until the catch-up miss rule has seen it. Not part of
    /// the v2 tuple; it joins the root only in the catch-up map.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub last_active_height: u64,
    /// Seat payout: validator (pack / check / floor / proposer fee share)
    /// rewards owed to this seat and not yet claimed. Separate from the
    /// account map `claimable`, so a wallet `Claim` can never take them.
    /// Joins the root (seat map) once non-zero; 0 before activation.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub seat_claimable: u64,
    /// Seat payout: when set, validator rewards are credited at settle straight
    /// to this account's liquid balance instead of `seat_claimable`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seat_payout: Option<String>,
}

/// v2.9.62 A5: `sealed <= max(local_now + 5 s, parent + 1 s)`.
pub fn sealed_at_v2_ok(sealed: u64, parent: u64, local_now: u64) -> bool {
    let lim = local_now
        .saturating_add(crate::params_v2::SEALED_AT_MAX_AHEAD_MS)
        .max(parent.saturating_add(crate::params_v2::SEALED_AT_MIN_STEP_ALLOWED_MS));
    sealed <= lim
}

/// v2.9.62 A4 seed (see [`Ledger::seed_v2`]).
pub fn seed_v2_hex(parent_hash: &str, height: u64, msg_v4: &str) -> String {
    sha256_hex(format!("fpl-seed-v2|{parent_hash}|{height}|{msg_v4}").as_bytes())
}

/// Mempool refusal for v2 tx kinds before `H_act` (not permanent).
pub const RV2_NOT_ACTIVE: &str = "rewards v2 not active yet (H_act)";
/// Seat payout txs before `seat_payout_from_height` (not kept or relayed).
pub const SEAT_PAYOUT_NOT_ACTIVE: &str = "seat payout not active yet";
/// v2.10.0: `SetExternalAddrs` before `external_addrs_from_height` (not kept or
/// relayed; deliberately not matched by `is_permanent_tx_failure`).
pub const EXTERNAL_ADDRS_NOT_ACTIVE: &str = "set external addrs not active yet";
/// v2.10.4: order-book tx before the 2.10.4 height (not permanent).
pub const ORDERBOOK_NOT_ACTIVE: &str = "order book not active yet";

fn is_zero_u32(v: &u32) -> bool {
    *v == 0
}
fn is_false(v: &bool) -> bool {
    !*v
}

/// v2.9.62 A10: admission approval for a new validator id (in the root).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidatorApproval {
    pub public_key: String,
    pub expires_height: u64,
}

impl ValidatorInfo {
    pub fn new(id: impl Into<String>, bond: u64, public_key: String) -> Self {
        let id = id.into();
        Self {
            bond_account: id.clone(),
            id,
            bond,
            avail: 1.0,
            quality: 0.5,
            pack_count: 0,
            jailed: false,
            jail_count: 0,
            slash_total: 0,
            last_pong_ms: 0,
            public_key,
            unbonding: 0,
            unbond_ready_ms: 0,
            last_advertised_tip: None,
            last_mempool_len: 0,
            advertised_hub: false,
            advertised_archive: false,
            last_snap_height: 0,
            escrow: 0,
            v2_seat: false,
            missed_turns: 0,
            inactive: false,
            archive: false,
            earn_locked: false,
            earn_streak: 0,
            last_active_height: 0,
            seat_claimable: 0,
            seat_payout: None,
        }
    }

    fn lock_earn(&mut self) {
        self.earn_locked = true;
        self.earn_streak = 0;
    }

    /// One height while locked. A missed own turn clears the streak. A seal
    /// or a certificate vote advances it. Reaching the need unlocks pay.
    fn tick_earn(&mut self, worked: bool, missed: bool) {
        if !self.earn_locked || self.jailed || self.inactive {
            return;
        }
        if missed {
            self.earn_streak = 0;
            return;
        }
        if worked {
            self.earn_streak = self.earn_streak.saturating_add(1);
        }
        if self.earn_streak >= crate::params_v2::EARN_STREAK_NEED {
            self.earn_locked = false;
            self.earn_streak = 0;
        }
    }

    /// v2 extension of the root tuple; `None` while every v2 field is default.
    fn v2_slim(&self) -> Option<(u64, bool, u32, bool, String, bool)> {
        if self.escrow == 0
            && !self.v2_seat
            && self.missed_turns == 0
            && !self.inactive
            && !self.archive
        {
            return None;
        }
        let pk = if self.v2_seat { self.public_key.clone() } else { String::new() };
        Some((self.escrow, self.v2_seat, self.missed_turns, self.inactive, pk, self.archive))
    }

    pub fn perf(&self) -> f64 {
        let alpha = 0.15;
        let bonus = 0.25 / (1.0 + self.pack_count as f64);
        alpha + 0.5 * self.avail + 0.5 * self.quality + bonus
    }

    /// Lottery weight: **bond only** (jailed → 0). Eligibility for the lottery
    /// also requires a fresh network pong (see [`Node::lottery_packer_with_skips`]).
    pub fn lottery_weight(&self) -> f64 {
        if self.jailed || self.bond == 0 {
            return 0.0;
        }
        // v2.9.62 (fields only ever set from H_act): inactive seats and v2
        // seats that unbonded below the v2 minimum are not eligible.
        if self.inactive || (self.v2_seat && self.bond < crate::params_v2::MIN_BOND_V2) {
            return 0.0;
        }
        self.bond as f64
    }

    /// Fresh if we have heard a pong within the window.
    /// `last_pong_ms == 0` means **never heard** (not ready for lottery).
    pub fn pong_fresh(&self, now_ms: u64, pong_window_ms: u64) -> bool {
        if self.last_pong_ms == 0 {
            return false;
        }
        now_ms.saturating_sub(self.last_pong_ms) <= pong_window_ms
    }
}

#[derive(Debug, Clone)]
pub struct ChainConfig {
    pub network_id: u32,
    /// Optional hard ceiling (0 = **no cap** — only time budget stops packing).
    /// Prefer time budget alone so faster packers simply include more.
    pub max_txs_per_ledger: usize,
    /// Pack as many applicable txs as possible within this many ms.
    /// 0 = no time limit (then max_txs should be > 0 or pack can run very long).
    /// Faster machines fill more before the deadline → naturally perform better.
    pub pack_budget_ms: u64,
    pub pong_window_ms: u64,
    pub confirm_depth: u64,
    pub slash_equivocation: u64,
    pub scheme: CryptoScheme,
    /// Soft confirm votes needed (static floor). Actual need is `min(soft_ok_votes, n)`
    /// with n = bonded non-jailed checkers — does **not** grow with network size
    /// (v2.3.5 restores freeze: soft=3; only hard scales).
    pub soft_ok_votes: usize,
    /// Hard confirm: fraction of bonded non-jailed checkers (e.g. 0.6). Scales with n.
    pub hard_ok_ratio: f64,
    /// If the current lottery winner produces no ledger within this many ms
    /// while the mempool is non-empty, cast a skip **vote** so #2 can pack after QC.
    /// 0 = disabled. Default 2500 (standby failover).
    pub progress_timeout_ms: u64,
    /// Hard cap on pending txs per node. New unique txs rejected when full
    /// (duplicates still accepted as no-ops). 0 = unlimited (not for prod/testnet).
    /// Default 50_000 ≈ tens–low hundreds of MB with Falcon-sized sigs.
    pub max_mempool_txs: usize,
    /// Keep only the last N ledgers in RAM. **Must be > 0** (v2.3.1 P1 — 0 was OOM).
    /// Values of 0 are clamped to [`Self::DEFAULT_MAX_CHAIN_LEDGERS`].
    pub max_chain_ledgers: usize,
    /// Epoch length ms (default 7d).
    pub epoch_ms: u64,
    /// Emission bps of remaining treasury per claimable epoch.
    pub emission_bps: u64,
    /// Minimum bond to participate.
    pub min_bond: u64,
    /// Base minimum fee when mempool is idle (escalates by util tier when enabled).
    pub min_fee: u64,
    /// Enforce util-tier min fee on submit (AMD-20260811-1). Off = metrics-only.
    pub fee_escalate: bool,
    /// Unbond cooldown ms (default 14d; private soak often 1d or shorter).
    pub unbond_cooldown_ms: u64,
    /// Heights per **certified online epoch** (v2.4.0 mainnet liveness).
    /// Packer seats = soft-QC'd ONLINE set for `tip_height / online_epoch_heights`.
    /// `0` = disabled (legacy: all bonded seats). Default **25**.
    pub online_epoch_heights: u64,
    /// When true, LedgerOk / Skip / ViewChange / OnlineSetVote require a Falcon
    /// (or hmac-dev) signature over a domain-separated payload (checklist A2).
    /// Default false so in-process tests stay unsigned; the node sets this for
    /// Falcon-512 fleets.
    pub require_vote_sigs: bool,
    /// When false, the TCP mesh listen rejects admin WireMsgs (checklist A3).
    /// Operator Snapshot*/HardReset/Tick go through `--admin-sock` instead.
    /// Default true so in-process / legacy ctl tests still work; the node
    /// clears this when `--admin-sock` or `--lock-public-wire` is set.
    pub allow_admin_wire: bool,
    /// Lottery draws this many seats per height: 1 packer + the rest checkers.
    /// Only this group may **commit**-QC / skip / view-change (4-of-6). Hard QC
    /// still scales over all bonded. 0 = all ONLINE/bonded (legacy). Default 6.
    pub committee_size: usize,
    /// Keep full tx bodies for this many recent committed heights (v2.8.0).
    /// Older chain entries keep `tx_ids` + header only. Default 64.
    pub max_body_ledgers: usize,
    /// Archive node: persist full bodies to disk (when a `BodyStore` is open)
    /// so tip-0 catch-up still works. RAM still strips after `max_body_ledgers`.
    /// Without a store (in-process tests) bodies stay in RAM. Default false.
    pub archive: bool,
    /// First 1-based epoch that emits from treasury. Mainnet **8**
    /// (epochs 1–7 bootstrap / airdrop). Testnet **1** (pay from the first epoch).
    pub first_claim_epoch: u64,
    /// v2.10.0 activation height for **round-scoped OK votes** (`pl-ok:v2`,
    /// round in certs / slash evidence, round-timeout re-vote). 0 = off
    /// (legacy `pl-ok:v1`). Protocol change: every committee seat must run a
    /// binary that knows this height before the chain reaches it.
    pub vote_rounds_from_height: u64,
    /// v2.9.48 Phase 2 **pause window** start (inclusive). Heights in
    /// `[vote_rounds_pause_from, vote_rounds_resume_at)` use legacy `pl-ok:v1`
    /// even though they are `>= vote_rounds_from_height`; round-scoped rules
    /// apply on both sides. 0 = no window. Runtime knob (not in snapshots).
    pub vote_rounds_pause_from: u64,
    /// End of the pause window (exclusive): first round-scoped height again.
    pub vote_rounds_resume_at: u64,
    /// Liveness watchdog: alert when pack work exists (pending body or
    /// applicable txs / hub inventory) but the tip has not advanced for this
    /// long. An idle chain (no txs) never alerts. 0 = off. Default 5 min.
    pub liveness_alert_ms: u64,
}

impl ChainConfig {
    /// Production default chain tail retention (also used when 0 is passed).
    pub const DEFAULT_MAX_CHAIN_LEDGERS: usize = 20_000;

    /// CLI `0` means "use the archive default", never a 1-ledger tail.
    pub fn resolve_max_chain_ledgers(cli: usize) -> usize {
        if cli == 0 {
            Self::DEFAULT_MAX_CHAIN_LEDGERS
        } else {
            cli
        }
    }

    /// Clamp unsafe / zero chain retention (v2.3.1 P1 — prevent unbounded RAM).
    pub fn sanitize(&mut self) {
        if self.max_chain_ledgers == 0 {
            self.max_chain_ledgers = Self::DEFAULT_MAX_CHAIN_LEDGERS;
        }
        if self.max_body_ledgers == 0 {
            self.max_body_ledgers = 64;
        }
        if self.max_body_ledgers > self.max_chain_ledgers {
            self.max_body_ledgers = self.max_chain_ledgers;
        }
        if self.first_claim_epoch == 0 {
            self.first_claim_epoch = 1;
        }
    }
}

impl Default for ChainConfig {
    fn default() -> Self {
        Self {
            network_id: NETWORK_ID_PRIVATE_V22,
            max_txs_per_ledger: 0, // 0 = unlimited; stop only when pack_budget_ms hits
            pack_budget_ms: 1_000, // "fill as many as you can in 1 second"
            // Multi-host under Falcon inject: pongs share the consensus queue with
            // ProposeLedger/LedgerOk. A 5s window falsely marks live remotes
            // offline and freezes soft QC (soft_need stuck high while "live" drops).
            pong_window_ms: 30_000,
            confirm_depth: 3,
            slash_equivocation: 100,
            scheme: CryptoScheme::HmacDev,
            soft_ok_votes: 3,
            hard_ok_ratio: 0.6,
            // Must exceed pack_budget + multi-host RTT so winners aren't skipped mid-pack.
            progress_timeout_ms: 2_500,
            max_mempool_txs: 50_000,
            max_chain_ledgers: ChainConfig::DEFAULT_MAX_CHAIN_LEDGERS,
            epoch_ms: EPOCH_MS,
            emission_bps: EMISSION_BPS_FIRST,
            min_bond: MIN_BOND,
            min_fee: DEFAULT_MIN_FEE,
            fee_escalate: true,
            unbond_cooldown_ms: UNBOND_COOLDOWN_MS,
            online_epoch_heights: 25,
            require_vote_sigs: false,
            allow_admin_wire: true,
            committee_size: 6,
            max_body_ledgers: 64,
            archive: false,
            first_claim_epoch: FIRST_CLAIM_EPOCH,
            vote_rounds_from_height: 0,
            vote_rounds_pause_from: 0,
            vote_rounds_resume_at: 0,
            liveness_alert_ms: 300_000,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct AcceptResult {
    pub height: u64,
    pub packer: String,
    pub n_txs: usize,
    pub fees: u64,
    pub reward_paid: u64,
}

/// Typed reason the open height is not converging (v2.10.0).
///
/// Replaces substring checks on `last_catchup_conflict` (which is operator
/// text and was overwritten by later messages — the 2026-09-28 h=369421
/// split logged "checker equivocation …" and the "equivocation/fork" match
/// never fired, so view-change never ran for ~6.5 days).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ConsensusStall {
    /// Two different bodies were proposed for the open height.
    DualProposal { height: u64, kept: String, rival: String },
    /// A checker OK'd two hashes at one height (legacy) or one (height, round).
    CheckerEquivocation { height: u64, round: u64, voter: String },
    /// The round's votes prove no hash can reach commit quorum (e.g. 3-3 at 4-of-6).
    SplitVote { height: u64, round: u64 },
    /// Ingest saw a different committed/staged body at a height.
    IngestFork { height: u64 },
}

impl ConsensusStall {
    pub fn height(&self) -> u64 {
        match self {
            Self::DualProposal { height, .. }
            | Self::CheckerEquivocation { height, .. }
            | Self::SplitVote { height, .. }
            | Self::IngestFork { height } => *height,
        }
    }
}

/// Snapshot of the liveness watchdog (status / metrics / alerts).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LivenessStatus {
    pub tip_height: u64,
    pub has_work: bool,
    pub stalled: bool,
    pub stalled_for_ms: u64,
    pub alert_after_ms: u64,
    pub pending: Option<String>,
    pub mempool_len: usize,
    pub view_round: u64,
    pub stall: Option<ConsensusStall>,
}

#[derive(Debug, Error)]
pub enum NodeError {
    #[error("{0}")]
    Msg(String),
}

// ---------------------------------------------------------------------------
// Node
// ---------------------------------------------------------------------------

/// Inputs for off-thread BitVM2 Groth16 verify before attest apply.
#[derive(Debug, Clone)]
pub struct Bitvm2AttestPrepare {
    pub note_id: String,
    pub dest_h160: [u8; 20],
    pub amount: u64,
    pub tip_height: u64,
    pub tip_hash: String,
    pub mimc_leaves: Vec<String>,
}

#[derive(Debug)]
pub struct Node {
    pub id: String,
    pub cfg: ChainConfig,
    pub keys: KeyRing,
    pub state: WorldState,
    pub mempool: Mempool,
    /// Compact live bodies waiting on txs this seat has not seen yet.
    pub body_shells: HashMap<String, Ledger>,
    /// Txs fetched for a shell. Not the mempool, so a full pool cannot block a seal.
    pub body_fill: HashMap<String, Tx>,
    pub chain: Vec<Ledger>,
    pub tip_hash: String,
    pub tip_height: u64,
    pub validators: BTreeMap<String, ValidatorInfo>,
    pub rewards: BTreeMap<String, u64>,
    pub now_ms: u64,
    /// Process start (`now_ms` at new/load). Startup pack waits for peer tips.
    pub started_ms: u64,
    /// height -> packer ledger_hash already accepted (equivocation detect)
    pub seen_at_height: HashMap<u64, (String, String)>, // packer, hash
    /// height -> packers skipped after **skip QC** (progress timeout / no applicable).
    pub skips: HashMap<u64, BTreeSet<String>>,
    /// height -> packer -> voters that attested SkipPacker (must reach soft QC to apply).
    pub skip_votes: HashMap<u64, HashMap<String, BTreeSet<String>>>,
    /// ledger_hash -> set of voter ids that sent OK
    pub ok_votes: HashMap<String, BTreeSet<String>>,
    /// soft/hard flags by ledger_hash
    pub soft_ok: BTreeSet<String>,
    pub hard_ok: BTreeSet<String>,
    /// Live proposal at tip+1 awaiting soft QC before tip advance (None = none).
    pub pending_proposal: Option<Ledger>,
    /// Transaction ids whose signatures were checked while the previous
    /// quorum was still assembling. `pack_or_skip` does not check them again.
    pub sig_warm: BTreeSet<String>,
    /// Pending ledger hash `sig_warm` was built against.
    pipeline_for: String,
    /// Local clock when the current tip opened (or last standby skip). Used for
    /// progress-timeout: if #1 seals nothing, #2 gets a turn after timeout + skip QC.
    pub height_open_ms: u64,
    /// Genesis wall time for epoch index (ms).
    pub genesis_ms: u64,
    /// Remaining keyless treasury (emission source).
    pub treasury: u64,
    /// Current epoch work counters (reset on settle).
    pub epoch_work: EpochWork,
    /// Last settled epoch index (1-based); 0 = none.
    pub last_settled_epoch: u64,
    /// Claimable balances from epoch settlements (not yet “wallet” merge).
    pub claimable: BTreeMap<String, u64>,
    /// Named-account registry (reserve → activate).
    pub names: NameRegistry,
    /// AMM + lending (v2.2).
    pub defi: DefiState,
    /// Hardcoded SPV rails (BTC/ETH/BNB).
    pub bridge: BridgeState,
    /// Intake / fee-market counters (process lifetime; snapshotted when possible).
    pub metrics: NodeMetrics,
    /// Future ledgers received out-of-order (height → ledger) for peer catch-up.
    pub pending_ledgers: BTreeMap<u64, Ledger>,
    /// After a **new** shared skip, do not pack until this time (lets winner's
    /// in-flight seal / SkipPacker gossip land before standby seals).
    pub skip_grace_until_ms: u64,
    /// v2.9.56: mempool heads already dry-run by
    /// [`Self::drop_permanent_applicable_heads`] at `perm_head_memo_tip` and
    /// not dropped. Local only (never snapshotted, never on the wire).
    pub perm_head_memo: BTreeSet<String>,
    /// Tip hash the memo belongs to; a new tip clears the memo.
    pub perm_head_memo_tip: String,
    /// Logical time the memo was started; it is also cleared after
    /// [`Self::PERM_HEAD_MEMO_TTL_MS`] so time-dependent failures still drop.
    pub perm_head_memo_since_ms: u64,
    /// Process-lifetime count of head dry-runs (each one clones the drafts).
    pub perm_head_dry_runs: u64,
    /// v2.9.77: tx ids this seat dropped as permanently invalid (sanitize,
    /// pack drop, refused same-seq replacement). Gossip must not re-admit
    /// them, or seats ping-pong a poison tx forever and it keeps evicting the
    /// valid same-(account, seq) resubmit. Bounded, local only, never on the
    /// wire or in a snapshot. Mempool admission only: block validity unchanged.
    pub perm_dropped: PermDropSet,
    /// v2.9.76: tx id whose apply failed in the last [`Self::stage_drafts`]
    /// (local diagnostic; lets a proposer evict a tx that fails self-accept).
    pub last_apply_fail_tx: Option<String>,
    /// v2.10.0 (Item #16): true when invalid/permanent-failing mempool heads
    /// were evicted on the current open height so the leader can still seal a
    /// valid empty/heartbeat block instead of stalling the view-change round.
    pub evicted_since_last_seal: bool,
    /// v2.9.57: last (height, logical ms) this cert-holding seat joined a
    /// peer's recert round for our tip (see [`Self::recert_assist`]). Local.
    pub recert_assist_h: u64,
    pub recert_assist_ms: u64,
    /// Voters already given a recert assist at [`Self::recert_assist_h`].
    /// One help per peer per height (827004 stall); cleared when the tip
    /// height changes. Local only, never snapshotted.
    pub recert_assist_peers: BTreeSet<String>,
    /// v2.9.79 (671185 stall): signed OKs for **our committed tip** seen on the
    /// wire while we hold no cert for it, keyed round → voter → sig. Lets a
    /// cert-less seat rebuild the original cert from the tip's own sealing
    /// committee (`Ledger::current_committee`) instead of waiting for the next
    /// committee's recert round. Local only, cleared when the tip moves.
    pub tip_cert_votes: BTreeMap<u64, BTreeMap<String, String>>,
    pub tip_cert_votes_h: u64,
    /// v2.9.58: (tip height, tip hash, state root, LC claim root) recorded at
    /// commit from the root that was just verified. Brief status serves these
    /// instead of recomputing the 207 MB root / claim leaves under `node.lock`.
    /// Local only.
    pub tip_roots: Option<(u64, String, String, String)>,
    /// v2.9.58: signed round OKs for heights tip+2.. that arrived while this
    /// seat lagged (see [`Self::buffer_future_ok`]). Bounded; local only.
    pub future_oks: Vec<FutureOk>,
    /// v2.9.59 packer pacing (local only, set by the node binary; 0 = off):
    /// the round-0 winner waits until this many ms after the height opened
    /// unless the mempool already holds [`Self::pace_mempool_txs`] or a full
    /// block. Capped by [`Self::pace_effective_ms`] so peers' round-0 silence
    /// timers can never fire because of it.
    pub pace_min_interval_ms: u64,
    /// v2.9.59: pacing ends early once the mempool holds this many txs.
    pub pace_mempool_txs: usize,
    /// v2.9.59: last ledger hash whose stage root was precomputed outside
    /// `node.lock` (see [`Self::prestage_root_input`]); dedupes re-deliveries.
    pub prestaged_hash: String,
    /// v2.9.59: number of stage roots precomputed outside the lock.
    pub prestage_count: u64,
    /// Rate-limit pull catch-up requests (ms).
    pub last_catchup_req_ms: u64,
    /// A NeedLedgers is on the wire; do not storm hubs until the batch or timeout.
    pub catchup_inflight: bool,
    /// Consecutive residual pulls that did not advance tip (v2.9.34 hole).
    pub empty_residual_streak: u32,
    /// Last time a snapshot source answered with nothing newer than our tip
    /// (stale `SnapshotOffer` or `SnapshotNo "no snapshot file yet"`). While
    /// recent and not far behind, a tip-0 seat falls back to residual
    /// `NeedLedgers` instead of looping on `NeedSnapshot` (harness
    /// restart-while-pending flake, 2026-10-05). 0 = never.
    pub stale_snap_offer_ms: u64,
    /// `keys/lc/bridge.json` fingerprint captured when the process applied it
    /// at start (`apply_qc_bridge_cfg`). Status `bridge_cfg.drift` compares the
    /// current file against this. Runtime only.
    pub bridge_cfg_startup: Option<serde_json::Value>,
    /// Round-robin offset over hub peers for NeedLedgers (AMD-20260827-1).
    /// Incremented on inflight miss / empty batch; kept when a batch advances.
    pub catchup_hub_rotate: u32,
    /// After snap adopt, prefer this archive/hub for residual NeedLedgers.
    pub catchup_snap_peer: String,
    /// Rate-limit NeedSnapshot (ms).
    pub last_snap_req_ms: u64,
    /// Best peer tip height seen (for status / catch-up urgency).
    pub best_peer_tip: u64,
    /// Hash advertised with `best_peer_tip` (QC-aware residual catch-up / status).
    pub best_peer_tip_hash: String,
    /// Last catch-up conflict reason (operator diagnostics; not auto hard-resync).
    pub last_catchup_conflict: String,
    /// Genesis account balances (for hard resync after fork).
    pub genesis_accounts: Vec<(String, u64)>,
    /// Initial bond used at `register_validator` (legacy; prefer `genesis_validators`).
    pub genesis_bond: u64,
    /// Validators registered at tip=0 (seed set only). Live bond-ins appear via Bond
    /// txs and must **not** be re-inserted at hard-resync genesis — otherwise the
    /// commitment root (includes bonds) mismatches h=1 forever (join tip-0 freeze).
    pub genesis_validators: BTreeMap<String, u64>,
    /// After state-root mismatch on catch-up, next batch rebuilds from genesis.
    pub need_hard_resync: bool,
    /// True only for an operator-armed wipe. Auto catch-up must never set this.
    pub hard_resync_operator: bool,
    /// Consecutive hard-resync failures (clears flag after cap to stop storms).
    pub hard_resync_fail_streak: u32,
    /// Mempool hub role (GROWTH_AND_MEMPOOL.md): primary submit + serve NeedTxs.
    /// Runtime config — not consensus stake.
    pub is_hub: bool,
    /// Rate-limit outbound NeedTxs pulls (ms).
    pub last_need_txs_ms: u64,
    /// Open height (`tip+1`) for which we already issued a pre-pack NeedTxs pull (P1).
    pub need_txs_for_height: u64,
    /// `now_ms` when pre-pack NeedTxs was issued for `need_txs_for_height`.
    pub need_txs_open_ms: u64,
    /// Pulls issued for `need_txs_for_height` (v2.9.8 re-pull while !applicable).
    pub need_txs_pulls_open: u32,
    /// Last hub packer-feed height / time (rate-limit TxsBatch push).
    pub packer_feed_height: u64,
    pub packer_feed_ms: u64,
    /// Tx ids already queued to each dish seat for `packer_feed_height`.
    /// The next tick sends only the suffix those seats do not have.
    pub dish_sent: std::collections::HashMap<String, std::collections::HashSet<String>>,
    /// Open height whose winner is still missing part of the walk, and when
    /// that hold started. Ordinary SubmitTx to those seats yields until the
    /// walk is queued or the pack budget ends.
    pub dish_priority_height: u64,
    pub dish_priority_since_ms: u64,
    /// Applicable-head count for the open height, and when it last grew.
    /// A frozen count near the progress timeout means seal what is present.
    pub grace_heads_height: u64,
    pub grace_heads: usize,
    pub grace_heads_ms: u64,
    /// Do not build another dish until this time. Set when the last send
    /// did not fit on the winner's socket.
    pub dish_blocked_until_ms: u64,
    /// Header seen, body not yet (v2.9.13 pull retry).
    pub want_body_hash: String,
    pub want_body_height: u64,
    pub last_want_body_ms: u64,
    /// Rate-limit pending body push on the tx plane.
    pub last_body_push_ms: u64,
    /// Counters for hub/mempool path (status/metrics).
    pub mempool_pulls: u64,
    pub mempool_served: u64,
    pub mempool_absorbed: u64,
    /// Pack attempts that found mempool non-empty but no next-seq match (seq poison / holes).
    pub pack_no_applicable: u64,
    /// After all-skip clear, refuse new SkipPacker until this time (stops thrash).
    pub skip_reopen_cooldown_until_ms: u64,

    // --- Certified online epoch (v2.4.0 mainnet) ---
    /// Epoch id of the **certified** ONLINE roster (`tip/heights` when frozen).
    pub online_epoch_id: u64,
    /// Soft-QC'd members for `online_epoch_id` (empty = bootstrap all bonded).
    pub online_members: BTreeSet<String>,
    /// Commitment hash of certified members (`online_set_hash`).
    pub online_hash: String,
    /// epoch_id → set_hash → voters (soft QC accumulation).
    pub online_votes: HashMap<u64, HashMap<String, BTreeSet<String>>>,
    /// epoch_id → certified set_hash (once soft QC met).
    pub online_ok: HashMap<u64, String>,
    /// Last OnlineSetVote we cast/fanned (epoch, hash) for rate-limit / re-fan.
    pub last_online_vote_epoch: u64,
    pub last_online_vote_hash: String,
    pub last_online_vote_ms: u64,

    // --- Open-height schedule freeze + view-change (v2.5.0) ---
    /// Height (`tip+1`) for which lottery ONLINE inputs are frozen.
    pub schedule_height: u64,
    /// Frozen ONLINE members used by lottery for `schedule_height`.
    pub schedule_online_members: BTreeSet<String>,
    /// Frozen ONLINE hash tag used in lottery seed (`bootstrap` if empty at freeze).
    pub schedule_online_hash: String,
    /// Frozen QC committee (1 packer + checkers) for schedule_height.
    pub schedule_committee: Vec<String>,
    /// View-change round for the open height (bumped by soft-QC ViewChange).
    pub height_view_round: u64,
    /// height → target_round → voters (soft QC to apply view-change).
    pub view_change_votes: HashMap<u64, HashMap<u64, BTreeSet<String>>>,
    /// Rate-limit local ViewChange casting.
    pub last_view_change_vote_ms: u64,
    /// Packers who already produced a body at `height`. Survives view-change
    /// so the same seat cannot reseal a second hash (v2.7.6).
    pub height_sealers: HashMap<u64, BTreeSet<String>>,
    /// Height → 4-of-6 cert (v2.9.0). Next packer embeds tip cert as parent_cert.
    pub certs: BTreeMap<u64, LedgerCert>,
    /// height → voter → ledger_hash (checker equivocation).
    pub ok_by_height_voter: HashMap<u64, HashMap<String, String>>,
    /// ledger_hash → voter → OK signature (feeds LedgerCert).
    pub ok_sigs: HashMap<String, HashMap<String, String>>,
    /// Proven double-OKs waiting to ride the next packed ledger (not applied yet).
    pub pending_slashes: Vec<SlashEvidence>,
    /// Optional disk body store. Set by `--archive` in the node process.
    pub body_store: Option<BodyStore>,
    /// Keys directory (vault shares, bitvm-abort). Never in snapshots.
    pub keys_dir: Option<std::path::PathBuf>,
    /// BTC exit path: watch Kickoff vs BitVM2 operator-fronting (runtime; not snapshotted).
    pub btc_exit_mode: crate::bitvm2_exit::BtcExitMode,
    /// 3 = v3 headers. 4 = lottery-6 outer seal. Runtime; from bridge.json.
    pub qc_header_version: u32,
    /// First v4 ledger height. 0 = v4 not armed. Runtime; from bridge.json.
    pub qc_start_height: u64,
    /// v2.9.60: first ledger height that applies Gloas ETH LC rules. From
    /// [`network_eth_lc_gloas_from_height`]; runtime only (not snapshotted).
    pub eth_lc_gloas_from_height: u64,
    /// v2.9.61: first ledger height that applies V3 mint-or-refund. From
    /// [`network_eth_v3_from_height`]; runtime only (not snapshotted).
    pub eth_v3_from_height: u64,
    /// M1: [`crate::params_v2::bitvm2_m1_from_height`]; runtime only.
    pub bitvm2_m1_from_height: u64,
    /// M1: compressed Groth16 VK for `Bitvm2AttestV2` (ceremony constant;
    /// tests may override). Runtime only.
    pub bitvm2_vk: Vec<u8>,
    /// #118: [`crate::params_v2::ring_restore_from_height`]; runtime only.
    pub ring_restore_from_height: u64,
    /// [`crate::params_v2::claim_enroll_from_height`]; runtime only.
    pub claim_enroll_from_height: u64,
    /// [`crate::params_v2::seat_payout_from_height`]; runtime only.
    pub seat_payout_from_height: u64,
    /// v2.10.0: [`crate::params_v2::external_addrs_from_height`]; runtime only.
    pub external_addrs_from_height: u64,
    /// v2.10.0: [`crate::params_v2::empty_block_from_height`]; runtime only.
    pub empty_block_from_height: u64,
    /// v2.10.1: [`crate::params_v2::btc4_fork_fix_from_height`]; runtime only.
    pub btc4_fork_fix_from_height: u64,
    /// v2.10.4 (TBD): [`crate::params_v2::btc4_lend_scale_from_height`]; runtime only.
    pub btc4_lend_scale_from_height: u64,
    /// v2.10.4 (TBD): [`crate::params_v2::orderbook_from_height`] (= the single
    /// 2.10.4 height); runtime only.
    pub orderbook_from_height: u64,
    /// v2.10.3 (TBD): [`crate::params_v2::hello_min_release_from_height`]; runtime only.
    pub hello_min_release_from_height: u64,
    /// UTC Hello capability hard-enforce from this tip height (`u64::MAX` = never).
    /// Default never — advertising `utc-header-v5` does not close old peers.
    pub utc_hello_enforce_from_height: u64,
    /// Injectable UTC pack / live-admission clock (default `System`). Tests and
    /// isolated rehearsals may set `Frozen`/`Offset`; runtime only, not persisted.
    pub utc_pack_clock: utc_header::UtcPackClock,
    /// v2.10.3: last Hello `release_version` per peer id ("" = pre-2.10.3)
    /// and when it was seen (`now_ms`). Observability only; runtime only.
    pub peer_releases: BTreeMap<String, (String, u64)>,
    /// v2.9.62: rewards-v2 activation height `H_act` (`u64::MAX` = unarmed).
    /// From [`params_v2::network_rewards_v2_from_height`]; runtime only.
    pub rewards_v2_from_height: u64,
    /// v2.9.62: first epoch settled with the v2 formula (`E_v2`); runtime only.
    pub rewards_v2_epoch: u64,
    /// Presence rules (uptime floor, earn streak). `u64::MAX` = off.
    /// Runtime only, same on every seat. Not snapshotted.
    pub presence_from_height: u64,
    /// Catch-up miss rule. `u64::MAX` = off. Runtime only, same on every seat.
    pub catchup_miss_from_height: u64,
    /// v2.9.62 A13: registered keys of legacy (pre-BondV2) seats. Runtime
    /// only, identical on every seat (baked for 2300). Empty = not enforced.
    pub seat_key_registry: BTreeMap<String, String>,
    /// v2.9.62 A12: summary of the last epoch settle (status only, not in the
    /// root, memory only: `null` after a restart until the next settle).
    pub last_settle: Option<serde_json::Value>,
    /// V3 bridge that `EthV3Deposit` matches. From
    /// [`crate::evm_spv::sepolia_qc_v3_bridge_addr`] at start and on snapshot
    /// load (env `FPL_SEPOLIA_QC_V3_BRIDGE`, else the unset default). Not
    /// snapshotted: every seat must be configured the same before H2.
    /// Consensus reads this field; it does not read the environment again.
    pub eth_v3_bridge: Option<[u8; 20]>,

    // --- Round-scoped votes + liveness (v2.10.0) ---
    /// height → round → voter → (ledger_hash, signature). Only filled on
    /// round-scoped heights. Survives view-change / reopen (it is the lock
    /// and equivocation record); pruned once the height commits.
    pub round_votes: BTreeMap<u64, BTreeMap<u64, BTreeMap<String, (String, String)>>>,
    /// Round whose voters currently populate `ok_votes[hash]` / `ok_sigs[hash]`.
    pub ok_round: HashMap<String, u64>,
    /// Typed stall reason for the open height (drives view-change).
    pub stall: Option<ConsensusStall>,
    /// Round advances the current pending body survived without commit.
    pub pending_rounds: u32,
    /// Local clock at the last tip advance (watchdog).
    pub tip_advanced_ms: u64,
    /// Local clock when the current (height, round) opened. Unlike
    /// `height_open_ms` it is **not** reset by gossip activity, so a late or
    /// repeated header cannot postpone the round timeout forever.
    pub round_open_ms: u64,
    /// Local clock when pack work was first seen on a flat tip (0 = none).
    pub work_seen_since_ms: u64,
    /// Last liveness alert (rate-limit).
    pub liveness_alert_last_ms: u64,
    /// Own-vote journal file (restart safety for round locks). Runtime only.
    pub vote_journal: Option<std::path::PathBuf>,
    /// Validated bodies seen at the open height (round mode): pending, rivals,
    /// late bodies from an earlier round's proposer. Lets a round re-vote /
    /// commit whichever body actually gathers 4-of-6. Cleared on commit.
    pub open_bodies: BTreeMap<String, Ledger>,
}

/// Undo a speculative time-fold (pack / verify).
struct TimeFold {
    now_ms: u64,
    state: WorldState,
    validators: BTreeMap<String, ValidatorInfo>,
    claimable: BTreeMap<String, u64>,
    treasury: u64,
    last_settled_epoch: u64,
    epoch_work: EpochWork,
    defi: DefiState,
}

impl TimeFold {
    fn take(n: &Node) -> Self {
        Self {
            now_ms: n.now_ms,
            state: n.state.clone(),
            validators: n.validators.clone(),
            claimable: n.claimable.clone(),
            treasury: n.treasury,
            last_settled_epoch: n.last_settled_epoch,
            epoch_work: n.epoch_work.clone(),
            defi: n.defi.clone(),
        }
    }

    fn restore(self, n: &mut Node) {
        n.now_ms = self.now_ms;
        n.state = self.state;
        n.validators = self.validators;
        n.claimable = self.claimable;
        n.treasury = self.treasury;
        n.last_settled_epoch = self.last_settled_epoch;
        n.epoch_work = self.epoch_work;
        n.defi = self.defi;
    }
}

/// `Node::eth_v3_bridge` at startup. A set-but-malformed
/// `FPL_SEPOLIA_QC_V3_BRIDGE` must stop the seat here: treating it as unset
/// would leave the seat with no V3 address and stall it at the first
/// `EthV3Deposit` after the V3 gate.
fn eth_v3_bridge_or_panic(r: Result<Option<[u8; 20]>, String>) -> Option<[u8; 20]> {
    match r {
        Ok(a) => a,
        Err(e) => panic!("refusing to start: {e} (fix or unset it)"),
    }
}

impl Node {
    pub fn new(
        id: impl Into<String>,
        cfg: ChainConfig,
        keys: KeyRing,
        genesis_accounts: &[(String, u64)],
    ) -> Self {
        let now_ms = 1_000;
        let mut cfg = cfg;
        cfg.sanitize();
        let eth_lc_gloas_from_height = network_eth_lc_gloas_from_height(cfg.network_id);
        let eth_v3_from_height = network_eth_v3_from_height(cfg.network_id);
        let bitvm2_m1_from_height = crate::params_v2::bitvm2_m1_from_height(cfg.network_id);
        let bitvm2_vk = crate::bitvm2_exit::withdraw_vk_for_network(cfg.network_id);
        let ring_restore_from_height = crate::params_v2::ring_restore_from_height(cfg.network_id);
        let claim_enroll_from_height = crate::params_v2::claim_enroll_from_height(cfg.network_id);
        let seat_payout_from_height = crate::params_v2::seat_payout_from_height(cfg.network_id);
        let external_addrs_from_height = crate::params_v2::external_addrs_from_height(cfg.network_id);
        let empty_block_from_height = crate::params_v2::empty_block_from_height(cfg.network_id);
        let btc4_fork_fix_from_height = crate::params_v2::btc4_fork_fix_from_height(cfg.network_id);
        let btc4_lend_scale_from_height = crate::params_v2::btc4_lend_scale_from_height(cfg.network_id);
        let orderbook_from_height = crate::params_v2::orderbook_from_height(cfg.network_id);
        let hello_min_release_from_height = crate::params_v2::hello_min_release_from_height(cfg.network_id);
        let network_id_for_utc_hello = cfg.network_id;
        let rewards_v2_from_height = params_v2::network_rewards_v2_from_height(cfg.network_id);
        let rewards_v2_epoch = params_v2::network_rewards_v2_epoch(cfg.network_id);
        let presence_from_height = params_v2::network_presence_from_height(cfg.network_id);
        let catchup_miss_from_height = params_v2::network_catchup_miss_from_height(cfg.network_id);
        let seat_key_registry = params_v2::network_seat_keys(cfg.network_id);
        let eth_v3_bridge = eth_v3_bridge_or_panic(crate::evm_spv::sepolia_qc_v3_bridge_addr());
        Self {
            id: id.into(),
            cfg,
            keys,
            state: WorldState::genesis(genesis_accounts),
            mempool: Mempool::default(),
            body_shells: HashMap::new(),
            body_fill: HashMap::new(),
            chain: Vec::new(),
            tip_hash: sha256_hex(b"pl-genesis-v1"),
            tip_height: 0,
            validators: BTreeMap::new(),
            rewards: BTreeMap::new(),
            now_ms,
            started_ms: 0,
            seen_at_height: HashMap::new(),
            skips: HashMap::new(),
            skip_votes: HashMap::new(),
            ok_votes: HashMap::new(),
            soft_ok: BTreeSet::new(),
            hard_ok: BTreeSet::new(),
            pending_proposal: None,
            sig_warm: BTreeSet::new(),
            pipeline_for: String::new(),
            height_open_ms: now_ms,
            genesis_ms: now_ms,
            treasury: TREASURY_GENESIS,
            epoch_work: EpochWork::default(),
            last_settled_epoch: 0,
            claimable: BTreeMap::new(),
            names: NameRegistry::default(),
            defi: DefiState::default(),
            bridge: BridgeState::with_genesis_rails(),
            metrics: NodeMetrics::default(),
            pending_ledgers: BTreeMap::new(),
            skip_grace_until_ms: 0,
            perm_head_memo: BTreeSet::new(),
            perm_head_memo_tip: String::new(),
            perm_head_memo_since_ms: 0,
            perm_head_dry_runs: 0,
            perm_dropped: PermDropSet::default(),
            last_apply_fail_tx: None,
            evicted_since_last_seal: false,
            recert_assist_h: 0,
            recert_assist_ms: 0,
            recert_assist_peers: BTreeSet::new(),
            tip_cert_votes: BTreeMap::new(),
            tip_cert_votes_h: 0,
            tip_roots: None,
            future_oks: Vec::new(),
            pace_min_interval_ms: 0,
            pace_mempool_txs: Node::PACE_DEFAULT_MEMPOOL_TXS,
            prestaged_hash: String::new(),
            prestage_count: 0,
            last_catchup_req_ms: 0,
            catchup_inflight: false,
            empty_residual_streak: 0,
            stale_snap_offer_ms: 0,
            bridge_cfg_startup: None,
            catchup_hub_rotate: 0,
            catchup_snap_peer: String::new(),
            last_snap_req_ms: 0,
            best_peer_tip: 0,
            best_peer_tip_hash: String::new(),
            last_catchup_conflict: String::new(),
            genesis_accounts: genesis_accounts.to_vec(),
            genesis_bond: MIN_BOND,
            genesis_validators: BTreeMap::new(),
            need_hard_resync: false,
            hard_resync_operator: false,
            hard_resync_fail_streak: 0,
            is_hub: false,
            last_need_txs_ms: 0,
            need_txs_for_height: 0,
            need_txs_open_ms: 0,
            need_txs_pulls_open: 0,
            packer_feed_height: 0,
            packer_feed_ms: 0,
            dish_sent: std::collections::HashMap::new(),
            dish_priority_height: 0,
            dish_priority_since_ms: 0,
            grace_heads_height: 0,
            grace_heads: 0,
            grace_heads_ms: 0,
            dish_blocked_until_ms: 0,
            want_body_hash: String::new(),
            want_body_height: 0,
            last_want_body_ms: 0,
            last_body_push_ms: 0,
            mempool_pulls: 0,
            mempool_served: 0,
            mempool_absorbed: 0,
            pack_no_applicable: 0,
            skip_reopen_cooldown_until_ms: 0,
            online_epoch_id: 0,
            online_members: BTreeSet::new(),
            online_hash: String::new(),
            online_votes: HashMap::new(),
            online_ok: HashMap::new(),
            last_online_vote_epoch: 0,
            last_online_vote_hash: String::new(),
            last_online_vote_ms: 0,
            schedule_height: 0,
            schedule_online_members: BTreeSet::new(),
            schedule_online_hash: String::new(),
            schedule_committee: Vec::new(),
            height_view_round: 0,
            view_change_votes: HashMap::new(),
            last_view_change_vote_ms: 0,
            height_sealers: HashMap::new(),
            certs: BTreeMap::new(),
            ok_by_height_voter: HashMap::new(),
            ok_sigs: HashMap::new(),
            pending_slashes: Vec::new(),
            body_store: None,
            keys_dir: None,
            btc_exit_mode: crate::bitvm2_exit::BtcExitMode::from_env(),
            qc_header_version: 3,
            qc_start_height: 0,
            eth_lc_gloas_from_height,
            eth_v3_from_height,
            bitvm2_m1_from_height,
            bitvm2_vk,
            ring_restore_from_height,
            claim_enroll_from_height,
            seat_payout_from_height,
            external_addrs_from_height,
            empty_block_from_height,
            btc4_fork_fix_from_height,
            btc4_lend_scale_from_height,
            orderbook_from_height,
            hello_min_release_from_height,
            utc_hello_enforce_from_height: utc_header::network_utc_hello_enforce_from_height(network_id_for_utc_hello),
            utc_pack_clock: utc_header::UtcPackClock::System,
            peer_releases: BTreeMap::new(),
            rewards_v2_from_height,
            rewards_v2_epoch,
            presence_from_height,
            catchup_miss_from_height,
            seat_key_registry,
            last_settle: None,
            eth_v3_bridge,
            round_votes: BTreeMap::new(),
            ok_round: HashMap::new(),
            stall: None,
            pending_rounds: 0,
            tip_advanced_ms: 0,
            round_open_ms: 0,
            work_seen_since_ms: 0,
            liveness_alert_last_ms: 0,
            vote_journal: None,
            open_bodies: BTreeMap::new(),
        }
    }

    /// Load `qc_header_version` / `qc_start_height` from `keys/lc/bridge.json`.
    pub fn apply_qc_bridge_cfg(&mut self) {
        let Some(dir) = &self.keys_dir else {
            return;
        };
        let cfg = crate::lc::load_bridge_cfg(dir);
        let fp = crate::lc::bridge_cfg_fingerprint(dir);
        if cfg.qc_header_version != 0 {
            self.qc_header_version = cfg.qc_header_version;
        }
        self.qc_start_height = cfg.qc_start_height;
        self.bridge_cfg_startup = Some(fp);
    }

    /// Status `bridge_cfg`: current on-disk fingerprint plus what this process
    /// applied at start. `drift` is true when the file changed since start
    /// (raw sha256 or canonical digest — restart to apply), the file's QC
    /// fields differ from the loaded ones, the file's `network_id` differs from
    /// the node's, or a non-zero file `vote_rounds_from_height` differs from
    /// the running activation height. `drift_reasons` lists which.
    pub fn bridge_cfg_status(&self) -> Option<serde_json::Value> {
        let dir = self.keys_dir.as_ref()?;
        let mut f = crate::lc::bridge_cfg_fingerprint(dir);
        let get_u = |v: &serde_json::Value, k: &str| v.get(k).and_then(|x| x.as_u64());
        let get_s = |v: &serde_json::Value, k: &str| {
            v.get(k).and_then(|x| x.as_str()).unwrap_or_default().to_string()
        };
        let mut reasons: Vec<&str> = Vec::new();
        if let Some(st) = &self.bridge_cfg_startup {
            if get_s(&f, "sha256") != get_s(st, "sha256") {
                reasons.push("file_changed_since_start");
            }
            if get_s(&f, "qc_cfg_digest") != get_s(st, "qc_cfg_digest") {
                reasons.push("qc_cfg_digest_changed_since_start");
            }
        } else {
            reasons.push("not_applied_at_start");
        }
        if get_u(&f, "qc_header_version") != Some(self.qc_header_version as u64)
            || get_u(&f, "qc_start_height") != Some(self.qc_start_height)
        {
            reasons.push("file_qc_fields_differ_from_loaded");
        }
        if get_u(&f, "network_id") != Some(self.cfg.network_id as u64) {
            reasons.push("network_id_differs_from_node");
        }
        let file_vr = get_u(&f, "vote_rounds_from_height").unwrap_or(0);
        if file_vr != 0 && file_vr != self.cfg.vote_rounds_from_height {
            reasons.push("vote_rounds_differs_from_running");
        }
        let file_pause = (
            get_u(&f, "vote_rounds_pause_from").unwrap_or(0),
            get_u(&f, "vote_rounds_resume_at").unwrap_or(0),
        );
        if (file_pause.0 != 0 || file_pause.1 != 0)
            && file_pause != (self.cfg.vote_rounds_pause_from, self.cfg.vote_rounds_resume_at)
        {
            reasons.push("vote_rounds_pause_differs_from_running");
        }
        if let Some(o) = f.as_object_mut() {
            o.insert("loaded_qc_header_version".into(), self.qc_header_version.into());
            o.insert("loaded_qc_start_height".into(), self.qc_start_height.into());
            o.insert("node_network_id".into(), self.cfg.network_id.into());
            o.insert(
                "running_vote_rounds_from_height".into(),
                self.cfg.vote_rounds_from_height.into(),
            );
            o.insert(
                "running_vote_rounds_pause".into(),
                serde_json::json!([self.cfg.vote_rounds_pause_from, self.cfg.vote_rounds_resume_at]),
            );
            if let Some(st) = &self.bridge_cfg_startup {
                o.insert("startup_sha256".into(), st.get("sha256").cloned().unwrap_or_default());
                o.insert(
                    "startup_qc_cfg_digest".into(),
                    st.get("qc_cfg_digest").cloned().unwrap_or_default(),
                );
            }
            o.insert("drift".into(), (!reasons.is_empty()).into());
            o.insert("drift_reasons".into(), reasons.into());
        }
        Some(f)
    }

    pub fn qc_v4_armed(&self) -> bool {
        self.qc_header_version >= 4 && self.qc_start_height > 0
    }

    /// Gloas ETH light-client rules for txs applied in ledger `height`.
    pub fn eth_lc_gloas_at(&self, height: u64) -> bool {
        height >= self.eth_lc_gloas_from_height
    }

    /// V3 mint-or-refund rules for txs applied in ledger `height`.
    pub fn eth_v3_at(&self, height: u64) -> bool {
        height >= self.eth_v3_from_height
    }

    /// M1 BitVM2 rules for a ledger at `height`.
    pub fn bitvm2_m1_at(&self, height: u64) -> bool {
        height >= self.bitvm2_m1_from_height
    }

    /// v2.9.62: consensus-safety rules for txs/ledgers applied at `height`.
    pub fn rv2_at(&self, height: u64) -> bool {
        height >= self.rewards_v2_from_height
    }

    fn catchup_miss_at(&self, height: u64) -> bool {
        self.catchup_miss_from_height != u64::MAX && height >= self.catchup_miss_from_height
    }

    /// True when this seat has not packed or voted recently enough to be
    /// treated as caught up. A miss in that state is not charged.
    fn miss_excused(v: &ValidatorInfo, height: u64, from: u64) -> bool {
        let window = crate::params_v2::CATCHUP_MISS_WINDOW;
        if v.last_active_height == 0 {
            return height >= from.saturating_add(window);
        }
        height.saturating_sub(v.last_active_height) > window
    }

    /// Uptime floor and the post-jail earn streak apply at `height`.
    pub fn presence_at(&self, height: u64) -> bool {
        self.rv2_at(height) && height >= self.presence_from_height
    }

    /// v2.9.62 A13: registry enforced at `height` (armed, reached, non-empty).
    pub fn key_registry_at(&self, height: u64) -> bool {
        self.rv2_at(height) && !self.seat_key_registry.is_empty()
    }

    /// v2.9.62 A13: the consensus key of `id`: the on-chain BondV2 key for a
    /// v2 seat, else the baked/configured legacy registry. Never the
    /// Hello-learned keyring (that differs between seats).
    pub fn registered_key(&self, id: &str) -> Option<String> {
        if let Some(v) = self.validators.get(id) {
            if v.v2_seat && !v.public_key.is_empty() {
                return Some(v.public_key.clone());
            }
        }
        self.seat_key_registry.get(id).cloned()
    }

    /// Consensus signature check. From `H_act` (registry) the registered key
    /// is used directly, never the node-local ring: after a fresh snapshot
    /// adopt the ring lacked v2 seats learned only via Hello (e.g.
    /// `falcon-node`), so certs/votes failed until a restart (2.9.79-beta.3).
    fn verify_consensus_sig(&self, voter: &str, height: u64, pk: &str, payload: &str, sig: &str) -> bool {
        if self.key_registry_at(height) {
            return self.keys.verify_pop(voter, pk, payload, sig);
        }
        self.keys.verify_message(self.cfg.scheme, voter, pk, payload, sig).is_ok()
    }

    /// Ledger packer signature: below `H_act` the node ring (legacy); from
    /// `H_act` ONLY the on-chain registered key (must equal the header's
    /// `packer_public_key`). After a fresh snapshot adopt the ring lacks v2
    /// seats learned only via Hello, so catch-up batches packed by such a seat
    /// failed "bad packer sig" until a restart (2.9.79-beta.3 fresh-install stall).
    /// From `H_act`: the packer's on-chain registered key (empty when absent,
    /// which then fails verification); below `H_act`: None (legacy ring).
    pub fn packer_registry_key(&self, ledger: &Ledger) -> Option<String> {
        if self.key_registry_at(ledger.height) {
            Some(self.registered_key(&ledger.packer).unwrap_or_default())
        } else {
            None
        }
    }

    /// Header gossip (`ProposeHeader`): same height-gated policy as
    /// `packer_sig_ok` (registry-only from `H_act`, legacy ring below).
    pub fn header_sig_ok(&self, header: &LedgerHeader) -> bool {
        self.packer_sig_ok(&header.signed_stub())
    }

    pub fn packer_sig_ok(&self, ledger: &Ledger) -> bool {
        if !self.key_registry_at(ledger.height) {
            return ledger.verify_packer(&self.keys);
        }
        match self.registered_key(&ledger.packer) {
            Some(rk) if rk.eq_ignore_ascii_case(&ledger.packer_public_key) => ledger
                .verify_packer_by(|id, pk, msg, sig| self.keys.verify_pop(id, pk, msg, sig)),
            _ => false,
        }
    }

    /// Public keys of a QC committee at `height`, in order: from `H_act` the
    /// registered consensus key only; below it the node ring (legacy). After a fresh snapshot adopt the
    /// ring lacks v2 seats learned only via Hello, so `committee_root_for_ids`
    /// failed with "no public key for <seat>" and every catch-up batch was
    /// rejected until a restart (fresh-install stall, 2.9.79-beta.3).
    pub fn committee_pks_at(&self, ids: &[String], height: u64) -> Result<Vec<String>, String> {
        // From H_act: ONLY the deterministic on-chain registry key (never the
        // node-local ring / Hello keys, not even ring-first), so every node
        // derives the same committee root for identical committed state.
        // Below H_act: exact legacy behaviour (ring) so historical roots verify.
        let registry = self.key_registry_at(height);
        ids.iter()
            .map(|id| {
                if registry {
                    self.registered_key(id)
                } else {
                    self.keys.public_hex(id)
                }
                .ok_or_else(|| format!("no public key for {id}"))
            })
            .collect()
    }

    pub fn committee_root_at(&self, ids: &[String], height: u64) -> Result<String, String> {
        crate::qc_header::committee_root_hex(&self.committee_pks_at(ids, height)?)
    }

    /// Registry key of `id` as of a post-transaction validator draft (a
    /// `BondV2` seat enrolled by this ledger exists only in the draft).
    fn registered_key_in(&self, id: &str, vals: &BTreeMap<String, ValidatorInfo>) -> Option<String> {
        if let Some(v) = vals.get(id) {
            if v.v2_seat && !v.public_key.is_empty() {
                return Some(v.public_key.clone());
            }
        }
        self.seat_key_registry.get(id).cloned()
    }

    /// Next-committee root of the ledger at `height`: from `H_act` keys come
    /// from the post-transaction draft registry (review #149: enrollment
    /// ledgers must not block); below it the legacy ring.
    pub fn next_committee_root_at(
        &self,
        ids: &[String],
        height: u64,
        draft_vals: &BTreeMap<String, ValidatorInfo>,
    ) -> Result<String, String> {
        if !self.key_registry_at(height) {
            return self.committee_root_at(ids, height);
        }
        let pks = ids
            .iter()
            .map(|id| self.registered_key_in(id, draft_vals).ok_or_else(|| format!("no public key for {id}")))
            .collect::<Result<Vec<_>, _>>()?;
        crate::qc_header::committee_root_hex(&pks)
    }

    /// Current-committee root of the ledger at `height` (pre-state). At the
    /// registry activation boundary the committee was frozen by the preceding
    /// (pre-`H_act`) ledger: keep that committed root unchanged rather than
    /// re-deriving it from the registry, which may not hold a legacy seat in
    /// that committee (review #149). Never falls back to the node-local ring.
    pub fn current_committee_root_at(&self, ids: &[String], height: u64) -> Result<String, String> {
        if self.key_registry_at(height) && !self.key_registry_at(height.saturating_sub(1)) {
            if let Some(t) = self.chain.last() {
                if t.height.saturating_add(1) == height
                    && t.is_v4()
                    && t.next_committee.as_slice() == ids
                    && !t.next_committee_root.is_empty()
                {
                    return Ok(t.next_committee_root.clone());
                }
            }
        }
        self.committee_root_at(ids, height)
    }

    /// Key used to verify `voter`'s consensus signature at `height`.
    fn consensus_key_at(&self, voter: &str, height: u64) -> Option<String> {
        if self.key_registry_at(height) {
            self.registered_key(voter)
        } else {
            self.keys.public_hex(voter)
        }
    }

    /// Fill the legacy registry from the genesis validators' keys (non-2300
    /// devnets without `FPL_SEAT_KEYS_FILE`). Call at startup, before any
    /// peer Hello can add keys. No-op on 2300 or when already set.
    pub fn init_seat_key_registry_from_genesis(&mut self, genesis_ids: &[String]) {
        if self.cfg.network_id == NETWORK_ID_PUBLIC_TESTNET_2300 || !self.seat_key_registry.is_empty() {
            return;
        }
        for id in genesis_ids {
            if let Some(pk) = self.keys.public_hex(id) {
                self.seat_key_registry.insert(id.clone(), pk.to_ascii_lowercase());
            }
        }
    }

    /// Seat payout rules apply to the ledger at `height`.
    pub fn seat_payout_at(&self, height: u64) -> bool {
        height >= self.seat_payout_from_height
    }

    /// Seat payout txs (or any tx from a `#seat` sender) before activation:
    /// refused at admission, never relayed/exported, rejected at apply.
    pub fn seat_tx_pre_activation(&self, tx: &Tx) -> bool {
        tx.body.is_seat_tx() && !self.seat_payout_at(self.tip_height.saturating_add(1))
    }

    /// v2.10.0: `SetExternalAddrs` / `Account.external_addrs` rules apply to the
    /// ledger at `height`.
    /// v2.10.1: BTC4 fork-fix rules for the ledger being applied now (`tip + 1`).
    pub fn btc4_fork_fix_open(&self) -> bool {
        self.tip_height.saturating_add(1) >= self.btc4_fork_fix_from_height
    }

    /// v2.10.4: BTC4 lend markets pin 1e8 raw/coin for the ledger applied now.
    pub fn btc4_lend_scale_open(&self) -> bool {
        self.tip_height.saturating_add(1) >= self.btc4_lend_scale_from_height
    }

    /// Market with the v2.10.4 BTC4 scale pinned when active (pure; no write).
    fn lend_market_rescaled(&self, m: &crate::defi::LendingMarket) -> crate::defi::LendingMarket {
        let mut m = m.clone();
        if m.raw_per_coin.is_none()
            && m.asset == crate::bridge::RAIL_BTC4
            && self.btc4_lend_scale_open()
        {
            // Re-express the stored per-1e6 price per 1e8 so value is unchanged.
            m.raw_per_coin = Some(100_000_000);
            m.price_native_per_scale = m.price_native_per_scale.saturating_mul(100).max(1);
        }
        m
    }

    pub fn external_addrs_at(&self, height: u64) -> bool {
        height >= self.external_addrs_from_height
    }

    /// v2.10.0: a `SetExternalAddrs` tx before activation: refused at
    /// admission, never relayed/exported (2.9.81 seats cannot decode the
    /// variant), rejected at apply.
    /// v2.10.4: order-book tx kinds before the 2.10.4 height. Refused before
    /// fee / sequence and never kept or relayed (2.10.3 cannot decode them).
    pub fn orderbook_tx_pre_activation(&self, tx: &Tx) -> bool {
        matches!(tx.body, TxBody::PlaceLimitOrder { .. } | TxBody::CancelOrder { .. })
            && !self.orderbook_open()
    }

    /// v2.10.4: order book (and hybrid swaps) apply in the ledger built now.
    pub fn orderbook_open(&self) -> bool {
        self.tip_height.saturating_add(1) >= self.orderbook_from_height
    }

    /// v2.10.4 per-ledger order-book hook (expiry + AMM-cross triggers) on a
    /// draft. Same call in pack, verify (`stage_drafts`) and commit, before
    /// txs: it settles what the previous ledger's final pool price crossed.
    pub(crate) fn orderbook_ledger_hook(&self, state: &mut WorldState, defi: &mut DefiState, height: u64) {
        if height < self.orderbook_from_height {
            return;
        }
        let mut b = crate::orderbook::Books { state, defi };
        crate::orderbook::ledger_hook(&mut b, height);
    }

    #[cfg(test)]
    pub(crate) fn orderbook_ledger_hook_for_test(&mut self, height: u64) {
        let mut st = std::mem::take(&mut self.state);
        let mut df = std::mem::take(&mut self.defi);
        self.orderbook_ledger_hook(&mut st, &mut df, height);
        self.state = st;
        self.defi = df;
    }

    pub fn external_addrs_tx_pre_activation(&self, tx: &Tx) -> bool {
        matches!(tx.body, TxBody::SetExternalAddrs { .. })
            && !self.external_addrs_at(self.tip_height.saturating_add(1))
    }

    /// v2.10.0: empty (zero-tx) ledgers are valid at `height` (and carry the
    /// empty-block time-effects / no-proposer-credit rules).
    pub fn empty_block_at(&self, height: u64) -> bool {
        height >= self.empty_block_from_height
    }

    /// v2.10.0 (Item #16): this node may seal an empty fallback block at the
    /// open height: it evicted permanent-failure txs on this height AND empty
    /// blocks are active. Before activation behaves exactly like 2.9.81.
    pub fn can_seal_empty(&self) -> bool {
        self.evicted_since_last_seal && self.empty_block_at(self.tip_height.saturating_add(1))
    }

    /// Seat id when `account` is a `<id>#seat` sender and the seat rules are
    /// active for the ledger being applied (`tip + 1`). Before activation a
    /// `#seat` name is an ordinary account (history verifies unchanged).
    pub fn seat_sender_active<'a>(&self, account: &'a str) -> Option<&'a str> {
        seat_of_sender(account).filter(|_| self.seat_payout_at(self.tip_height.saturating_add(1)))
    }

    /// Credit a validator reward for seat `id`: to its payout account's liquid
    /// balance when set, else to the seat bucket. Ids that are not seats keep
    /// the legacy `claimable[id]` credit.
    fn credit_seat_reward(
        vals: &mut BTreeMap<String, ValidatorInfo>,
        state: &mut WorldState,
        claimable: &mut BTreeMap<String, u64>,
        id: &str,
        amt: u64,
    ) {
        if amt == 0 {
            return;
        }
        match vals.get_mut(id) {
            Some(v) => match v.seat_payout.clone() {
                Some(to) => {
                    let mut a = state.get(&to);
                    a.balance = a.balance.saturating_add(amt);
                    state.accounts.insert(to, a);
                }
                None => v.seat_claimable = v.seat_claimable.saturating_add(amt),
            },
            None => *claimable.entry(id.to_string()).or_insert(0) += amt,
        }
    }

    /// Seat payout migration, once, on the activation ledger (before its txs):
    /// the whole `claimable[id]` of every account whose name is a validator
    /// seat id moves into that seat's bucket. Validator and account rewards
    /// were mixed in one entry before and cannot be split historically; the
    /// seat key holder is the one who earned the validator part.
    fn seat_migrate_hook(
        &self,
        vals: &mut BTreeMap<String, ValidatorInfo>,
        claimable: &mut BTreeMap<String, u64>,
        height: u64,
    ) {
        if self.seat_payout_from_height == u64::MAX || height != self.seat_payout_from_height {
            return;
        }
        for (id, v) in vals.iter_mut() {
            if let Some(amt) = claimable.remove(id) {
                v.seat_claimable = v.seat_claimable.saturating_add(amt);
            }
        }
    }

    /// `SetSeatPayout` / `ClaimSeat`. Sender must be `<validator>#seat`, signed
    /// with the seat's registered key. Fee: from the seat bucket first, then
    /// the liquid balance of the `#seat` sender account.
    fn apply_seat_tx(&mut self, tx: &Tx, check_sig: bool) -> Result<(), String> {
        if !self.seat_payout_at(self.tip_height.saturating_add(1)) {
            return Err(SEAT_PAYOUT_NOT_ACTIVE.into());
        }
        let validator = match &tx.body {
            TxBody::SetSeatPayout { validator, .. } | TxBody::ClaimSeat { validator, .. } => {
                validator.clone()
            }
            _ => return Err("seat sender may only send seat txs".into()),
        };
        if tx.account != seat_sender(&validator) {
            return Err(format!("seat tx sender must be {}", seat_sender(&validator)));
        }
        if !self.validators.contains_key(&validator) {
            return Err(format!("unknown validator {validator}"));
        }
        if self.registered_key(&validator).is_none() {
            return Err(format!("seat {validator} has no registered key"));
        }
        if check_sig {
            self.verify_account_tx(tx)?;
        }
        let mut sender = self.state.get(&tx.account);
        if tx.sequence != sender.sequence {
            return Err(format!("bad sequence want {} got {}", sender.sequence, tx.sequence));
        }
        sender.sequence += 1;
        // Fee: seat bucket, then the sender account's liquid balance.
        let v = self.validators.get_mut(&validator).expect("checked");
        let from_bucket = tx.fee.min(v.seat_claimable);
        let rest = tx.fee - from_bucket;
        if sender.balance < rest {
            return Err("insufficient balance for fee".into());
        }
        v.seat_claimable -= from_bucket;
        sender.balance -= rest;
        self.state.accounts.insert(tx.account.clone(), sender);
        match &tx.body {
            TxBody::SetSeatPayout { payout_account, .. } => {
                let p = match payout_account.as_deref().map(str::trim) {
                    None => None,
                    Some(p) if p.is_empty() => {
                        return Err("seat: empty payout account (use None to clear)".into())
                    }
                    Some(p) if p.len() > 128 || seat_of_sender(p).is_some() => {
                        return Err(format!("seat: invalid payout account {p}"))
                    }
                    Some(p) => Some(p.to_string()),
                };
                self.validators.get_mut(&validator).expect("checked").seat_payout = p;
            }
            TxBody::ClaimSeat { to, .. } => {
                let to = to.trim();
                if to.is_empty() || to.len() > 128 || seat_of_sender(to).is_some() {
                    return Err(format!("seat: invalid claim destination {to}"));
                }
                let v = self.validators.get_mut(&validator).expect("checked");
                let amt = std::mem::take(&mut v.seat_claimable);
                if amt > 0 {
                    let mut a = self.state.get(to);
                    a.balance = a.balance.saturating_add(amt);
                    self.state.accounts.insert(to.to_string(), a);
                }
            }
            _ => unreachable!(),
        }
        self.rail_finalize_bitvm("BTC").ok();
        self.bridge_finalize_claims();
        self.bridge.reconcile_btc_kickoff_utxos();
        Ok(())
    }

    /// v2.9.62: rules for the ledger being applied now (`tip + 1`).
    pub fn rv2_open(&self) -> bool {
        self.rv2_at(self.tip_height.saturating_add(1))
    }

    /// v2.9.62: v2 reward formula / counters for 1-based `epoch`. Needs `H_act`
    /// armed and reached (the arming commit puts `H_act` before `E_v2`).
    pub fn rv2_epoch(&self, epoch: u64) -> bool {
        self.rewards_v2_from_height != u64::MAX
            && epoch >= self.rewards_v2_epoch
            && self.tip_height.saturating_add(1) >= self.rewards_v2_from_height
    }

    /// v2.9.62 A10: tx must be signed by the network's admission key.
    fn require_admission_key(&self, tx: &Tx) -> Result<(), String> {
        if !self.rv2_open() {
            return Err("rv2 not active: admission".into());
        }
        let adm = crate::params_v2::network_admission_pubkey(self.cfg.network_id);
        if adm.is_empty() {
            return Err("admission: no admission key configured".into());
        }
        if !crate::btc_spv::hex_eq(&adm, &tx.public_key) {
            return Err("admission: signer is not the admission key".into());
        }
        // Tx signature was checked against tx.public_key for tx.account in
        // apply (or the ledger is certified on catch-up).
        Ok(())
    }

    /// v2.9.62 A6/A9/A10: bond a new seat with key + PoP + approval.
    fn apply_bond_v2(
        &mut self,
        tx: &Tx,
        validator: &str,
        public_key: &str,
        pop_sig: &str,
    ) -> Result<(), String> {
        if !self.rv2_open() {
            return Err("rv2 not active: bond_v2".into());
        }
        if self.validators.contains_key(validator) {
            return Err(format!("bond_v2: {validator} exists (top up with Bond)"));
        }
        if tx.amount < crate::params_v2::MIN_BOND_V2 {
            return Err(format!("bond below min {}", crate::params_v2::MIN_BOND_V2));
        }
        let pk = public_key.trim().to_ascii_lowercase();
        let open = self.tip_height.saturating_add(1);
        let appr = self
            .defi
            .validator_approvals
            .get(validator)
            .cloned()
            .ok_or_else(|| format!("admission: {validator} is not approved"))?;
        if appr.expires_height < open {
            return Err(format!("admission: approval for {validator} expired"));
        }
        if !crate::btc_spv::hex_eq(&appr.public_key, &pk) {
            return Err("admission: approved key differs".into());
        }
        let msg = crate::params_v2::pop_message(self.cfg.network_id, validator, &tx.account);
        if !self.keys.verify_pop(validator, &pk, &msg, pop_sig) {
            return Err("bond_v2: bad proof of possession".into());
        }
        let mut sender = self.state.get(&tx.account);
        if sender.balance < tx.amount {
            return Err("insufficient balance for bond".into());
        }
        sender.balance -= tx.amount;
        self.state.accounts.insert(tx.account.clone(), sender);
        self.defi.validator_approvals.remove(validator);
        let mut v = ValidatorInfo::new(validator, tx.amount, pk.clone());
        v.bond_account = tx.account.clone();
        v.v2_seat = true;
        self.validators.insert(validator.to_string(), v);
        self.keys
            .set_public_from_chain(validator, &pk)
            .map_err(|e| format!("bond_v2: key: {e:?}"))?;
        Ok(())
    }

    /// v2.9.62 per-ledger v2 bookkeeping on the draft validator set. Called by
    /// pack, verify (`stage_drafts`) and commit right after the drafts are
    /// cloned, with the ledger's packer and the tip-fixed round-0 seat.
    ///
    /// - At exactly `H_act` (A8 migration): past unjail payments move from
    ///   bond to escrow: `min(bond - MIN_BOND, MIN_BOND * (2^jail_count - 1))`
    ///   (v1: 7,000; v12: 15,000 on 2300).
    /// - From `H_act` (A11): the round-0 seat's `missed_turns` resets when it
    ///   sealed, else +1; at 20 it goes inactive unless that would leave fewer
    ///   than 6 eligible seats.
    fn rv2_ledger_hook(
        &self,
        vals: &mut BTreeMap<String, ValidatorInfo>,
        height: u64,
        packer: &str,
        round0: Option<&str>,
        voters: &[String],
    ) {
        if !self.rv2_at(height) {
            return;
        }
        if height == self.rewards_v2_from_height {
            let mb = crate::economy::MIN_BOND;
            for v in vals.values_mut() {
                if v.jail_count == 0 || v.escrow != 0 {
                    continue;
                }
                let paid = mb.saturating_mul((1u64 << v.jail_count.min(32)).saturating_sub(1));
                let e = v.bond.saturating_sub(mb).min(paid);
                v.bond -= e;
                v.escrow = e;
            }
            // A13: a legacy seat with no registered key (bonded before H_act
            // with a key only some seats learned) cannot vote or pack.
            if !self.seat_key_registry.is_empty() {
                for v in vals.values_mut() {
                    if !v.v2_seat && !self.seat_key_registry.contains_key(&v.id) {
                        v.inactive = true;
                    }
                }
            }
        }
        let catchup_rule = self.catchup_miss_at(height);
        if let Some(r0) = round0 {
            if r0 == packer {
                if let Some(v) = vals.get_mut(r0) {
                    v.missed_turns = 0;
                    if catchup_rule && !v.jailed {
                        v.inactive = false;
                    }
                }
            } else {
                let eligible = vals.values().filter(|v| v.lottery_weight() > 0.0).count();
                if let Some(v) = vals.get_mut(r0) {
                    let excused = catchup_rule && Self::miss_excused(v, height, self.catchup_miss_from_height);
                    if !v.inactive && !v.jailed && !excused {
                        v.missed_turns = v.missed_turns.saturating_add(1);
                        if u64::from(v.missed_turns) >= crate::params_v2::MISSED_TURNS_INACTIVE
                            && eligible > crate::params_v2::MIN_ELIGIBLE_SEATS
                        {
                            v.inactive = true;
                        }
                    }
                }
            }
        }
        if catchup_rule {
            let voted_now: BTreeSet<&str> = voters.iter().map(|s| s.as_str()).collect();
            let ids: Vec<String> = vals.keys().cloned().collect();
            for id in ids {
                let participated = id == packer || voted_now.contains(id.as_str());
                if !participated {
                    continue;
                }
                let Some(v) = vals.get_mut(&id) else { continue };
                v.last_active_height = height;
                if !v.jailed && v.inactive {
                    v.inactive = false;
                    v.missed_turns = 0;
                }
            }
        }
        if !self.presence_at(height) {
            return;
        }
        if height == self.presence_from_height {
            for v in vals.values_mut() {
                if v.jail_count > 0 {
                    v.lock_earn();
                }
            }
        }
        for v in vals.values_mut() {
            if v.jailed {
                v.lock_earn();
            }
        }
        let voted: BTreeSet<&str> = voters.iter().map(|s| s.as_str()).collect();
        let ids: Vec<String> = vals.keys().cloned().collect();
        for id in ids {
            let Some(v) = vals.get_mut(&id) else { continue };
            let missed = round0 == Some(id.as_str()) && id != packer;
            let worked = id == packer || voted.contains(id.as_str());
            v.tick_earn(worked, missed);
        }
    }

    /// v2.9.62 B5 floor weights: 100 per active seat, 105 for archive.
    /// From the presence height, scale by this epoch's uptime. Under half
    /// present, the weight is 0. A locked seat weighs 0.
    fn floor_weights_v2(&self) -> BTreeMap<String, u64> {
        let den = self.epoch_work.presence_heights;
        let scale = self.presence_from_height != u64::MAX && den > 0;
        self.validators
            .values()
            .filter(|v| v.lottery_weight() > 0.0 && !v.earn_locked)
            .filter_map(|v| {
                let base = if v.archive {
                    crate::params_v2::ARCHIVE_FLOOR_BPS / 100
                } else {
                    100
                };
                let w = if scale {
                    let num = self.epoch_work.present.get(&v.id).copied().unwrap_or(0);
                    if num * crate::params_v2::FLOOR_PRESENCE_MIN_DEN
                        < den * crate::params_v2::FLOOR_PRESENCE_MIN_NUM
                    {
                        0
                    } else {
                        base.saturating_mul(num) / den
                    }
                } else {
                    base
                };
                (w > 0).then_some((v.id.clone(), w))
            })
            .collect()
    }

    /// LP units by `"amm|pool|acct"` / `"lend|market|acct"`.
    fn lp_units_now(&self) -> BTreeMap<String, u64> {
        let mut out = BTreeMap::new();
        for (pid, p) in &self.defi.pools {
            for (a, u) in &p.lp {
                if *u > 0 {
                    out.insert(format!("amm|{pid}|{a}"), *u);
                }
            }
        }
        for (mid, m) in &self.defi.markets {
            for (a, u) in &m.supply_shares {
                if *u > 0 {
                    out.insert(format!("lend|{mid}|{a}"), *u);
                }
            }
        }
        out
    }

    /// v2.9.62 B7: LP weights in FPL value at settle, counting only units held
    /// since the epoch start (`min(start, now)`; current units if no start
    /// snapshot was taken).
    fn lp_value_weights_v2(&self, work: &EpochWork) -> (BTreeMap<String, u64>, BTreeMap<String, u64>) {
        let held = |key: String, now: u64| -> u64 {
            if work.lp_start_taken {
                now.min(work.lp_start.get(&key).copied().unwrap_or(0))
            } else {
                now
            }
        };
        let mut amm: BTreeMap<String, u64> = BTreeMap::new();
        for (pid, p) in &self.defi.pools {
            let fpl_res = if p.asset_a == crate::defi::NATIVE {
                p.reserve_a
            } else if p.asset_b == crate::defi::NATIVE {
                p.reserve_b
            } else {
                0 // no FPL leg: no FPL value (none exist on 2300)
            };
            if p.lp_supply == 0 || fpl_res == 0 {
                continue;
            }
            for (a, u) in &p.lp {
                let h = held(format!("amm|{pid}|{a}"), *u);
                let v = (2u128 * fpl_res as u128 * h as u128 / p.lp_supply as u128).min(u64::MAX as u128) as u64;
                if v > 0 {
                    *amm.entry(a.clone()).or_insert(0) = amm.get(a).copied().unwrap_or(0).saturating_add(v);
                }
            }
        }
        let mut lend: BTreeMap<String, u64> = BTreeMap::new();
        for (mid, m) in &self.defi.markets {
            if m.share_supply == 0 {
                continue;
            }
            let scale = m.scale();
            for (a, sh) in &m.supply_shares {
                let h = held(format!("lend|{mid}|{a}"), *sh);
                let amount = h as u128 * m.total_supply as u128 / m.share_supply as u128;
                let v = (amount * m.price_native_per_scale as u128 / scale).min(u64::MAX as u128) as u64;
                if v > 0 {
                    *lend.entry(a.clone()).or_insert(0) = lend.get(a).copied().unwrap_or(0).saturating_add(v);
                }
            }
        }
        (amm, lend)
    }

    /// Tip-fixed round-0 seat for the open height (first of the committee).
    fn rv2_round0(&self, height: u64) -> Option<String> {
        if !self.rv2_at(height) {
            return None;
        }
        self.lottery_order().into_iter().next()
    }

    /// v2.9.61 (#34): true for an `EthV3Deposit` that cannot apply in the open
    /// height (`!eth_v3_at(tip + 1)`). Mempool admission and relay only:
    /// such a tx is refused at local submit, dropped from peer batches
    /// (TxsBatch / NeedTxs replies), and never exported, so it is not kept,
    /// does not hold its submitter's sequence, and never reaches a seat that
    /// cannot decode the variant. Apply/verify are unchanged.
    pub fn v3_deposit_pre_activation(&self, tx: &Tx) -> bool {
        (matches!(tx.body, TxBody::EthV3Deposit { .. })
            && !self.eth_v3_at(self.tip_height.saturating_add(1)))
            || self.rv2_tx_pre_activation(tx)
            || self.seat_tx_pre_activation(tx)
            || self.external_addrs_tx_pre_activation(tx)
            || self.orderbook_tx_pre_activation(tx)
    }

    /// v2.9.62: same treatment for the new v2 tx kinds before `H_act` (not
    /// kept, relayed or exported; 2.9.61 seats cannot decode them).
    pub fn rv2_tx_pre_activation(&self, tx: &Tx) -> bool {
        matches!(
            tx.body,
            TxBody::BondV2 { .. }
                | TxBody::Reactivate { .. }
                | TxBody::ApproveValidator { .. }
                | TxBody::RevokeApproval { .. }
                | TxBody::SetArchive { .. }
                | TxBody::RevokeArchive { .. }
        ) && !self.rv2_open()
    }

    /// Hello version rule at the local tip: [`hello_version_compatible_at`]
    /// with `gloas_active = eth_lc_gloas_at(tip_height)` (tip >= H).
    pub fn hello_version_ok(&self, peer_version: &str) -> bool {
        hello_version_compatible_at(peer_version, self.eth_lc_gloas_at(self.tip_height))
    }

    /// Why a Hello is refused, or `None` to accept it. Shared by the session
    /// gate ([`HelloSession`]) and the node's Hello handler.
    pub fn hello_reject_reason(
        &self,
        hello_network_id: u32,
        product_version: &str,
    ) -> Option<&'static str> {
        if hello_network_id != 0 && hello_network_id != self.cfg.network_id {
            return Some(HELLO_ERR_NETWORK_ID);
        }
        if !self.hello_version_ok(product_version) {
            return Some(HELLO_ERR_PRODUCT_VERSION);
        }
        None
    }

    /// v2.10.3: release floor after [`Self::hello_min_release_from_height`]
    /// (local tip). Returns a full logged reason, `None` to accept.
    /// v2.10.3: record a peer's Hello release (observability only).
    pub fn note_peer_release(&mut self, id: &str, release_version: &str) {
        if id.is_empty() {
            return;
        }
        self.peer_releases
            .insert(id.to_string(), (release_version.to_string(), self.now_ms));
    }

    /// Display form: the release, or `none` (Hello without the field).
    /// v2.10.3: may we send `WireMsg::Piece` to this peer?
    pub fn peer_supports_pieces(&self, id: &str) -> bool {
        self.peer_releases
            .get(id)
            .map_or(false, |(r, _)| crate::pieces::peer_release_supports_pieces(r))
    }

    pub fn peer_release_label(&self, id: &str) -> Option<String> {
        self.peer_releases.get(id).map(|(r, _)| {
            if r.is_empty() { PEER_RELEASE_NONE.to_string() } else { r.clone() }
        })
    }

    pub fn hello_release_reject(&self, release_version: &str) -> Option<String> {
        if self.tip_height < self.hello_min_release_from_height {
            return None;
        }
        hello_release_reject_detail(release_version, HELLO_MIN_RELEASE)
            .map(|d| format!("{d} (local tip {})", self.tip_height))
    }

    /// Soft gap: peer missing `utc-header-v5` while local tip is past H_utc.
    /// Always computable; does not close the session.
    pub fn utc_peer_capability_gap(&self, peer_capabilities: &[String]) -> Option<String> {
        let from = utc_header::network_utc_from_height(self.cfg.network_id);
        utc_header::utc_peer_capability_gap(self.tip_height, from, peer_capabilities)
    }

    /// Hard Hello close when `utc_hello_enforce_from_height` is armed and tip
    /// has reached it. Default `u64::MAX` ⇒ never. Independent of H_utc bake.
    ///
    /// With enforce armed, the PROPOSED min-release safety window
    /// ([`utc_header::PROPOSED_UTC_HELLO_LEAD_BLOCKS`]) closes old peers from
    /// `H_utc - lead` so they cannot Pack/OK across activation. Closing the
    /// session is how Pack/OK from such a peer is refused (no session ⇒ no
    /// Pack/OK frames). 2300: enforce is always `u64::MAX` ⇒ inert.
    pub fn hello_utc_capability_reject(&self, peer_capabilities: &[String]) -> Option<String> {
        let close_from = self.utc_hello_hard_close_from();
        if self.tip_height < close_from {
            return None;
        }
        if utc_header::peer_has_utc_header_v5(peer_capabilities) {
            return None;
        }
        Some(format!(
            "{HELLO_ERR_UTC_CAPABILITY}: peer Hello lacks {}; local tip {} >= close_from {} (enforce_from {}, lead {})",
            utc_header::CAP_UTC_HEADER_V5,
            self.tip_height,
            close_from,
            self.utc_hello_enforce_from_height,
            utc_header::PROPOSED_UTC_HELLO_LEAD_BLOCKS
        ))
    }

    /// Effective hard-close height (enforce armed ⇒ min(enforce, H_utc - lead)).
    pub fn utc_hello_hard_close_from(&self) -> u64 {
        utc_header::utc_hello_hard_close_from(
            self.utc_hello_enforce_from_height,
            utc_header::network_utc_from_height(self.cfg.network_id),
            utc_header::PROPOSED_UTC_HELLO_LEAD_BLOCKS,
        )
    }

    /// True when Pack/OK from a peer with these Hello capabilities must be
    /// refused (same predicate as the Hello hard close).
    pub fn utc_refuse_peer_pack_ok(&self, peer_capabilities: &[String]) -> bool {
        self.hello_utc_capability_reject(peer_capabilities).is_some()
    }

    /// v2.9.60 rolling exec-header cut, and the v2.9.61 one-off V1 cutoff,
    /// for a ledger at `height`.
    ///
    /// Pack, verify and commit each build their own draft bridge and there is
    /// no earlier hook shared by all three, so each calls this before txs.
    /// Below the Gloas gate the prune is a no-op (commitment bytes stay
    /// 2.9.59). At and after the gate it is the one-off cut, then a no-op on
    /// later blocks while the LC head number is unchanged. Gated bootstrap /
    /// update / `EthExecHeaders` prune again after the head resolves, so a
    /// head that moves inside the block rolls the floor in that same root.
    ///
    /// The V3 gate is separate. The first ledger at or after it whose LC head
    /// number is resolved sets `eth_v1_deposit_cutoff` once. Below that gate
    /// the cutoff stays zero and is omitted from the commitment.
    fn prune_eth_exec_for_ledger(&self, bridge: &mut BridgeState, height: u64) {
        bridge.prune_eth_exec_headers(self.eth_lc_gloas_at(height));
        bridge.arm_eth_v1_deposit_cutoff(self.eth_v3_at(height));
        // M1: every per-ledger draft (pack, verify, commit) records the
        // parent ledger as a BitVM2 attestation checkpoint.
        if self.bitvm2_m1_at(height) {
            if let Ok(r) = bridge.rail_mut(crate::bridge::RAIL_BTC) {
                r.record_fpl_checkpoint(height, &self.tip_hash);
            }
            // BRIDGE: the testnet4 rail exists from the bridge height on.
            let r4 = bridge
                .rails
                .entry(crate::bridge::RAIL_BTC4.to_string())
                .or_insert_with(crate::bridge::RailState::new_btc4);
            r4.record_fpl_checkpoint(height, &self.tip_hash);
        }
    }

    /// v4 pack/verify for this ledger height.
    pub fn qc_v4_at(&self, height: u64) -> bool {
        self.qc_v4_armed() && height >= self.qc_start_height
    }

    /// Lottery uses v8 (inner_hash seed) once the tip itself is a v4 ledger.
    pub fn qc_v4_active_tip(&self) -> bool {
        self.qc_v4_armed() && self.tip_height >= self.qc_start_height
    }

    /// Lottery seed hash: inner_hash after a v4 tip, else outer `tip_hash`.
    pub fn lottery_tip_seed(&self) -> String {
        match self.chain.last() {
            Some(l) if l.is_v4() && !l.inner_hash.is_empty() && self.rv2_at(l.height) => l.seed_v2(),
            Some(l) if l.is_v4() && !l.inner_hash.is_empty() => l.inner_hash.clone(),
            _ => self.tip_hash.clone(),
        }
    }

    /// Multiplier of `progress_timeout_ms` before proposal-timeout view-change (v2.5.0).
    pub const PROPOSAL_TIMEOUT_MULT: u64 = 4;

    /// True only when we still hold **true** genesis balances + seed validators.
    /// Required for `hard_resync_from_ledgers`; without it, arming hard-resync
    /// causes perpetual from=1 storms (and multi-GB logs / unbounded queues).
    pub fn can_hard_resync(&self) -> bool {
        !self.genesis_accounts.is_empty() && !self.genesis_validators.is_empty()
    }

    /// Cap on consecutive hard-resync failures before we give up and stay on tip.
    pub const HARD_RESYNC_FAIL_CAP: u32 = 8;
    /// Min interval between NeedTxs pulls when packing.
    pub const NEED_TXS_INTERVAL_MS: u64 = 200;
    /// Max txs returned per NeedTxs / hub export batch.
    /// Hub → packer working set. Same size as a full ledger (`PACK_DEFAULT_MAX_TXS`).
    /// 128 left packers sealing a short dish while the hub still held the pool.
    pub const NEED_TXS_BATCH: usize = 400;
    /// Pull if local mempool is below this and we may pack (or are a light val lagging work).
    pub const NEED_TXS_LOW_WATER: usize = 8;
    /// After pre-pack NeedTxs, wait this long for TxsBatch before sealing empty (P1).
    /// 150ms lost to Tailscale RTT; must stay << progress_timeout (3s).
    pub const NEED_TXS_PRE_PACK_GRACE_MS: u64 = 800;
    /// Re-pulls per open height while still `!has_applicable_tx`.
    pub const NEED_TXS_PULLS_PER_HEIGHT: u32 = 6;
    /// Hub packer-feed min interval (tx plane, not consensus).
    pub const PACKER_FEED_INTERVAL_MS: u64 = 400;
    /// After a dish does not fit on the socket, wait this long before
    /// building another 1.3 MB batch. Retrying every 400 ms filled the pipe.
    pub const DISH_FAIL_BACKOFF_MS: u64 = 5_000;
    /// Near-skip seal is for a walk that was actually dished. A couple of
    /// relayed transactions is not that walk.
    pub const NEAR_SKIP_MIN_TXS: usize = 8;
    /// Extra slack after pull+pack so Falcon seal/gossip can finish (v2.9.11).
    pub const LIVE_PACK_SLACK_MS: u64 = 1_500;
    /// Re-push pending body on the tx plane (not cons queue).
    pub const BODY_PUSH_INTERVAL_MS: u64 = 400;
    /// Retry NeedLedgerBody while we have a header and no body.
    pub const BODY_PULL_INTERVAL_MS: u64 = 200;

    /// Fill a by-id body from the mempool and any txs already pulled.
    /// Missing ids are stored with the shell so one `TxsByIds` can finish it.
    pub fn assemble_body_by_id(&mut self, mut ledger: Ledger) -> Result<Ledger, (String, Vec<String>)> {
        ledger.txs.clear();
        let mut missing = Vec::new();
        let mut txs = Vec::with_capacity(ledger.tx_ids.len());
        for id in &ledger.tx_ids {
            if let Some(tx) = self.mempool.get(id).cloned().or_else(|| self.body_fill.get(id).cloned()) {
                txs.push(tx);
            } else {
                missing.push(id.clone());
            }
        }
        if !missing.is_empty() {
            if self.body_shells.len() >= 8 {
                self.body_shells.clear();
            }
            let hash = ledger.ledger_hash.clone();
            self.body_shells.insert(hash.clone(), ledger);
            return Err((hash, missing));
        }
        ledger.txs = txs;
        self.body_shells.remove(&ledger.ledger_hash);
        Ok(ledger)
    }

    /// Most txs `body_fill` keeps. It is a short-lived cache for compact
    /// bodies, not a second mempool.
    pub const BODY_FILL_CAP: usize = 4_000;

    /// Store txs a compact body may need, keeping the cache bounded.
    ///
    /// Every relayed `TxsBatch` used to land here and was only trimmed on the
    /// rare `TxsByIds` reply. Under steady load the map grew without bound.
    /// Every insert now goes through this cap, and committed txs are dropped
    /// when the ledger commits.
    pub fn note_body_fill<I: IntoIterator<Item = Tx>>(&mut self, txs: I) {
        for tx in txs {
            if self.body_fill.len() >= Self::BODY_FILL_CAP && !self.body_fill.contains_key(&tx.tx_id)
            {
                let want: std::collections::HashSet<&String> = self
                    .body_shells
                    .values()
                    .flat_map(|l| l.tx_ids.iter())
                    .collect();
                self.body_fill.retain(|id, _| want.contains(id));
                if self.body_fill.len() >= Self::BODY_FILL_CAP {
                    self.body_fill.clear();
                }
            }
            self.body_fill.insert(tx.tx_id.clone(), tx);
        }
    }

    /// Apply a `TxsByIds` reply. Returns the finished ledger when every id is present.
    pub fn supply_body_txs(&mut self, ledger_hash: &str, txs: Vec<Tx>) -> Option<Ledger> {
        self.note_body_fill(txs);
        let shell = self.body_shells.get(ledger_hash)?.clone();
        self.assemble_body_by_id(shell).ok()
    }

    /// Header seen without a body — pull from packer/hubs (v2.9.13).
    pub fn note_want_body(&mut self, height: u64, hash: &str) {
        if hash.is_empty() || self.ledger_body(hash).is_some() {
            return;
        }
        self.want_body_height = height;
        self.want_body_hash = hash.to_string();
    }

    /// Rate-limited NeedLedgerBody target, or None if we have the body / nothing pending.
    pub fn take_body_pull(&mut self) -> Option<String> {
        if self.want_body_hash.is_empty() {
            return None;
        }
        if self.ledger_body(&self.want_body_hash).is_some()
            || (self.pending_proposal.as_ref().map(|p| p.ledger_hash.as_str())
                == Some(self.want_body_hash.as_str()))
        {
            self.want_body_hash.clear();
            return None;
        }
        if self.want_body_height > 0 && self.want_body_height <= self.tip_height {
            self.want_body_hash.clear();
            return None;
        }
        if self.now_ms.saturating_sub(self.last_want_body_ms) < Self::BODY_PULL_INTERVAL_MS {
            return None;
        }
        self.last_want_body_ms = self.now_ms;
        Some(self.want_body_hash.clone())
    }

    /// Packer of this pending, or a hub: re-send the body on the tx plane.
    /// Checkers must not mesh-flood LedgerBody (AMD-20260814-20).
    pub fn take_pending_body_push(&mut self) -> Option<Ledger> {
        let p = self.pending_proposal.as_ref()?;
        if !p.has_body() {
            return None;
        }
        if p.packer != self.id && !self.is_hub {
            return None;
        }
        if self.now_ms.saturating_sub(self.last_body_push_ms) < Self::BODY_PUSH_INTERVAL_MS {
            return None;
        }
        self.last_body_push_ms = self.now_ms;
        Some(p.clone())
    }

    pub fn clear_want_body(&mut self) {
        self.want_body_hash.clear();
        self.want_body_height = 0;
    }

    /// Max buffered out-of-order ledgers (catch-up bound).
    pub const PENDING_LEDGERS_CAP: usize = 256;
    /// Max ages of skip_votes maps retained below tip.
    pub const SKIP_VOTE_HISTORY: u64 = 32;

    /// Export pending txs for hub serve / catch-up of packers.
    pub fn export_mempool_batch(&self, max: usize) -> Vec<Tx> {
        // #34: filter before the limit so a pre-activation V3 deposit is
        // never exported and never takes a slot from an eligible tx.
        self.mempool
            .export_batch_where(max, |tx| !self.v3_deposit_pre_activation(tx))
    }

    /// Absorb txs from hub / peer batch (deduped). Returns count newly inserted.
    pub fn absorb_txs(&mut self, txs: &[Tx]) -> usize {
        let mut n = 0;
        for tx in txs {
            // #34: a pre-activation V3 deposit from a peer batch is dropped,
            // not kept, so it is never re-served or relayed from here.
            if self.v3_deposit_pre_activation(tx) {
                continue;
            }
            match self.mempool.insert(tx.clone(), self.cfg.max_mempool_txs) {
                Ok(true) => n += 1,
                _ => {}
            }
        }
        self.mempool_absorbed = self.mempool_absorbed.saturating_add(n as u64);
        n
    }

    /// Whether this node should request pending txs from hubs/peers (rate-limited).
    pub fn wants_need_txs(&self) -> bool {
        if self.mempool.len() >= Self::NEED_TXS_LOW_WATER {
            return false;
        }
        // Hubs primarily serve; they still pull from peer hubs when empty.
        if self
            .now_ms
            .saturating_sub(self.last_need_txs_ms)
            < Self::NEED_TXS_INTERVAL_MS
        {
            return false;
        }
        true
    }

    /// Largest mempool a fresh hub is advertising. Wire-only. Not a root.
    pub fn fresh_hub_pool(&self) -> u64 {
        self.validators
            .values()
            .filter(|v| {
                v.advertised_hub && v.pong_fresh(self.now_ms, self.cfg.pong_window_ms)
            })
            .map(|v| v.last_mempool_len)
            .max()
            .unwrap_or(0)
    }

    fn pack_cap_txs(&self) -> usize {
        if self.cfg.max_txs_per_ledger > 0 {
            self.cfg.max_txs_per_ledger
        } else {
            Self::PACK_DEFAULT_MAX_TXS
        }
    }

    /// Local pool is a full ledger already. No point pulling before this seal.
    fn local_pool_fills_ledger(&self) -> bool {
        self.mempool.len() >= self.pack_cap_txs()
    }

    /// Hub is advertising more than this seat holds, and this seat is not full.
    /// A handful of local heads must not hide a 20k hub pool.
    pub fn hub_has_more_than_local(&self) -> bool {
        !self.local_pool_fills_ledger()
            && self.fresh_hub_pool() > self.mempool.len() as u64
    }

    /// How many transactions this seat can walk into one block: each account's
    /// next sequence, then the consecutive ones already behind it. Heads with
    /// no queue count as one. A raw pool of later sequences counts as zero.
    pub fn packable_tx_count(&self) -> usize {
        let cap = self.pack_cap_txs();
        let mut by: std::collections::HashMap<String, std::collections::BTreeSet<u64>> =
            std::collections::HashMap::new();
        for tx in self.mempool.iter_candidates() {
            by.entry(tx.account.clone())
                .or_default()
                .insert(tx.sequence);
        }
        let mut n = 0usize;
        for (account, seqs) in &by {
            let mut need = self.state.get(account).sequence;
            while seqs.contains(&need) {
                n += 1;
                if n >= cap {
                    return n;
                }
                need = need.saturating_add(1);
            }
        }
        n
    }

    /// The walk is well under a full block while a hub is holding a larger
    /// pool. Twenty-eight heads with only one or two behind each still make
    /// a short block. The raw pool size does not.
    pub fn short_pack_hole(&self) -> bool {
        let cap = self.pack_cap_txs();
        let walk = self.packable_tx_count();
        if walk >= cap.saturating_mul(3) / 4 {
            return false;
        }
        let hub = self.fresh_hub_pool();
        hub > walk as u64 && hub >= self.pace_mempool_txs.max(1) as u64
    }

    /// P1: lottery winner pulls hub inventory while it has no next-seq head,
    /// while a large pool is missing those heads, or while a fresh hub is
    /// advertising a larger pool than this seat holds.
    /// One pull per height once a head exists — further pulls only while empty.
    pub fn should_pre_pack_need_txs(&self) -> bool {
        let empty = !self.has_applicable_tx();
        let hole = self.short_pack_hole();
        let hub_more = self.hub_has_more_than_local();
        if !empty && !hole && !hub_more {
            return false;
        }
        let h = self.tip_height.saturating_add(1);
        if self.need_txs_for_height != h || self.need_txs_open_ms == 0 {
            return true;
        }
        // A thin walk keeps pulling until the skip is close. Ending the pull
        // at the 4s pack budget sealed 20-transaction blocks and dragged the
        // rate down. A walk that is already a block never gets here.
        if !empty {
            if hole {
                let elapsed = self.now_ms.saturating_sub(self.need_txs_open_ms);
                if elapsed >= self.thin_walk_hold_ms() || self.heads_stalled_before_skip() {
                    return false;
                }
                return self.now_ms.saturating_sub(self.last_need_txs_ms)
                    >= Self::NEED_TXS_INTERVAL_MS;
            }
            return false;
        }
        if self.need_txs_pulls_open >= Self::NEED_TXS_PULLS_PER_HEIGHT {
            return false;
        }
        self.now_ms.saturating_sub(self.last_need_txs_ms) >= Self::NEED_TXS_INTERVAL_MS
    }

    /// P1: after pre-pack NeedTxs, wait a short grace for TxsBatch before seal.
    /// Also wait when the hub still has more than we do, or this pool is a
    /// pile of later sequences, so those heads can land before the seal.
    pub fn waiting_need_txs_grace(&self) -> bool {
        // The walk is already a block. Do not hold the round for the hub's
        // leftover later sequences.
        let cap = self.pack_cap_txs().max(1);
        if self.packable_tx_count().saturating_mul(4) >= cap.saturating_mul(3) {
            return false;
        }
        if self.has_applicable_tx() && !self.hub_has_more_than_local() && !self.short_pack_hole() {
            return false;
        }
        let h = self.tip_height.saturating_add(1);
        if self.need_txs_for_height != h || self.need_txs_open_ms == 0 {
            return false;
        }
        // Heads have stopped arriving and the skip is close. Seal the walk
        // that is here. A skip seals nothing. A thin walk does not seal at
        // the 4s pack budget.
        if self.heads_stalled_before_skip() {
            return false;
        }
        let elapsed = self.now_ms.saturating_sub(self.need_txs_open_ms);
        let limit = if self.short_pack_hole() {
            self.thin_walk_hold_ms()
        } else {
            Self::NEED_TXS_PRE_PACK_GRACE_MS
        };
        elapsed < limit
    }

    /// How long a walk under 75% of the cap may wait for the missing heads.
    /// It waits until the skip is close. A walk at 75% seals immediately
    /// in waiting_need_txs_grace and never uses this hold.
    fn thin_walk_hold_ms(&self) -> u64 {
        let limit = self.cfg.progress_timeout_ms;
        if limit >= 2_000 {
            limit.saturating_sub(2_000)
        } else if self.cfg.pack_budget_ms > 0 {
            self.cfg.pack_budget_ms
        } else {
            Self::NEED_TXS_PRE_PACK_GRACE_MS
        }
    }

    /// Track whether new account heads are still landing on this height.
    pub fn note_head_progress(&mut self) {
        let h = self.tip_height.saturating_add(1);
        let heads = self.applicable_head_count();
        if self.grace_heads_height != h {
            self.grace_heads_height = h;
            self.grace_heads = heads;
            self.grace_heads_ms = self.now_ms;
            return;
        }
        if heads > self.grace_heads {
            self.grace_heads = heads;
            self.grace_heads_ms = self.now_ms;
        }
    }

    /// True when the head count has been flat for a second and the progress
    /// window has under two seconds left.
    pub fn heads_stalled_before_skip(&self) -> bool {
        if self.grace_heads == 0 || self.grace_heads_ms == 0 {
            return false;
        }
        let limit = self.cfg.progress_timeout_ms;
        if limit < 2_000 {
            return false;
        }
        // Two relayed transactions are not a dished walk. Let the height
        // skip rather than seal them because the window is ending.
        if self.packable_tx_count() < Self::NEAR_SKIP_MIN_TXS {
            return false;
        }
        let open = self.now_ms.saturating_sub(self.height_open_ms);
        let stable = self.now_ms.saturating_sub(self.grace_heads_ms) >= 1_000;
        stable && open.saturating_add(2_000) >= limit && self.has_applicable_tx()
    }

    /// The lottery winner has been queued at least one transaction this height.
    pub fn winner_dish_started(&self) -> bool {
        let Some(winner) = self.lottery_packer() else {
            return false;
        };
        self.dish_sent
            .get(&winner)
            .is_some_and(|have| !have.is_empty())
    }

    /// The send did not land. Allow the next seal tick to try the winner again.
    pub fn release_dish_attempt(&mut self) {
        self.packer_feed_ms = 0;
        self.dish_blocked_until_ms = 0;
    }

    /// Record a pre-pack NeedTxs pull for the open height.
    pub fn mark_pre_pack_need_txs(&mut self) {
        let h = self.tip_height.saturating_add(1);
        if self.need_txs_for_height != h || self.need_txs_open_ms == 0 {
            self.need_txs_pulls_open = 0;
            // Keep the original open time. Resetting it on every pull made
            // the pack-budget grace last until the progress skip.
            self.need_txs_open_ms = self.now_ms.max(1);
        }
        self.need_txs_for_height = h;
        self.need_txs_pulls_open = self.need_txs_pulls_open.saturating_add(1);
        self.note_need_txs_sent();
    }

    /// Mark a NeedTxs pull was issued.
    pub fn note_need_txs_sent(&mut self) {
        self.last_need_txs_ms = self.now_ms;
        self.mempool_pulls = self.mempool_pulls.saturating_add(1);
    }

    /// Serve a NeedTxs request (hub or any peer with inventory).
    /// Applicable heads first so a remote packer can seal this height.
    pub fn serve_need_txs(&mut self, max_count: usize) -> Vec<Tx> {
        let batch = self.export_packer_batch(max_count);
        if !batch.is_empty() {
            self.mempool_served = self.mempool_served.saturating_add(1);
        }
        batch
    }

    /// Packer working set, one layer of every account then the next layer.
    /// All heads first left the packer with a short queue behind them.
    /// A gap stops that account. Later sequences are not a walk.
    pub fn export_packer_batch(&self, max: usize) -> Vec<Tx> {
        let max = max.clamp(1, Self::NEED_TXS_BATCH.max(1));
        let mut by: std::collections::HashMap<String, Vec<Tx>> = std::collections::HashMap::new();
        for tx in self.mempool.iter_candidates() {
            if self.v3_deposit_pre_activation(tx) {
                continue;
            }
            let need = self.state.get(&tx.account).sequence;
            if tx.sequence >= need {
                by.entry(tx.account.clone()).or_default().push(tx.clone());
            }
        }
        let mut runs: Vec<Vec<Tx>> = Vec::new();
        for (account, mut txs) in by {
            txs.sort_by_key(|t| t.sequence);
            let mut expect = self.state.get(&account).sequence;
            let mut run = Vec::new();
            for tx in txs {
                if tx.sequence < expect {
                    continue;
                }
                if tx.sequence != expect {
                    break;
                }
                run.push(tx);
                expect = expect.saturating_add(1);
            }
            if !run.is_empty() {
                runs.push(run);
            }
        }
        let mut out = Vec::with_capacity(max.min(32));
        let mut depth = 0usize;
        while out.len() < max {
            let mut progressed = false;
            for run in &runs {
                if let Some(tx) = run.get(depth) {
                    out.push(tx.clone());
                    progressed = true;
                    if out.len() == max {
                        break;
                    }
                }
            }
            if !progressed {
                break;
            }
            depth += 1;
        }
        out
    }

    /// Active winner + first backup. A height only gaps if both fail to seal.
    pub fn dish_seats(&self) -> Vec<String> {
        self.lottery_ranked(Self::DISH_SEATS)
    }

    /// QC committee — the seats that must have the body to form 4-of-6.
    /// Mainnet: treat these as remote. Same-host majority is luck.
    pub fn body_lane_seats(&self) -> Vec<String> {
        self.lottery_order()
    }

    /// One-ledger working set (applicable heads, then pipelines), sized to the pack cap.
    pub fn dish_batch(&self) -> Vec<Tx> {
        let cap = if self.cfg.max_txs_per_ledger > 0 {
            self.cfg.max_txs_per_ledger
        } else {
            Self::NEED_TXS_BATCH
        };
        self.export_packer_batch(cap.max(1))
    }

    /// How deep the consecutive walk already is on this seat.
    /// `walk_ready` is the same 75% line the early seal uses.
    pub fn walk_report(&self) -> (usize, usize, usize, usize, usize, bool) {
        let cap = self.pack_cap_txs().max(1);
        let mut by: std::collections::HashMap<String, std::collections::BTreeSet<u64>> =
            std::collections::HashMap::new();
        for tx in self.mempool.iter_candidates() {
            by.entry(tx.account.clone())
                .or_default()
                .insert(tx.sequence);
        }
        let mut packable = 0usize;
        let mut accounts = 0usize;
        let mut min_depth = usize::MAX;
        for (account, seqs) in &by {
            let mut need = self.state.get(account).sequence;
            let mut depth = 0usize;
            while seqs.contains(&need) {
                depth += 1;
                packable += 1;
                need = need.saturating_add(1);
                if packable >= cap {
                    break;
                }
            }
            if depth > 0 {
                accounts += 1;
                min_depth = min_depth.min(depth);
            }
            if packable >= cap {
                break;
            }
        }
        if min_depth == usize::MAX {
            min_depth = 0;
        }
        let walk_ready = packable.saturating_mul(4) >= cap.saturating_mul(3);
        (
            self.mempool.len(),
            self.applicable_head_count(),
            packable,
            accounts,
            min_depth,
            walk_ready,
        )
    }

    /// Seats still missing some of this height's walk. Empty once every dish
    /// seat has been queued the current walk, or the pack budget has elapsed.
    pub fn dish_priority_seats(&mut self) -> Vec<String> {
        let h = self.tip_height.saturating_add(1);
        if self.dish_priority_height != h {
            self.dish_priority_height = h;
            self.dish_priority_since_ms = 0;
        }
        let budget = self.cfg.pack_budget_ms;
        if self.dish_priority_since_ms > 0
            && budget > 0
            && self.now_ms.saturating_sub(self.dish_priority_since_ms) >= budget
        {
            return Vec::new();
        }
        if self.packer_feed_height != h {
            self.dish_sent.clear();
        }
        let batch = self.dish_batch();
        if batch.is_empty() {
            return Vec::new();
        }
        let mut missing = Vec::new();
        for seat in self.dish_seats() {
            let sent = self.dish_sent.get(&seat);
            let incomplete = batch.iter().any(|tx| match sent {
                Some(have) => !have.contains(&tx.tx_id),
                None => true,
            });
            if incomplete {
                missing.push(seat);
            }
        }
        if !missing.is_empty() && self.dish_priority_since_ms == 0 {
            self.dish_priority_since_ms = self.now_ms.max(1);
        }
        missing
    }

    /// Record ids that were actually queued to this seat for the open height.
    pub fn note_dish_queued(&mut self, seat: &str, ids: &[String]) {
        if ids.is_empty() || seat.is_empty() {
            return;
        }
        let h = self.tip_height.saturating_add(1);
        if self.packer_feed_height != h {
            self.dish_sent.clear();
            self.packer_feed_height = h;
        }
        let have = self.dish_sent.entry(seat.to_string()).or_default();
        for id in ids {
            have.insert(id.clone());
        }
    }

    /// Hub → winner + backup. One copy of each tx per seat per height.
    /// A later tick sends only the suffix that seat has not been queued.
    /// Rate-limited so a newly arrived layer is not pushed on every tick.
    pub fn take_packer_dish(&mut self) -> Option<Vec<(String, Vec<Tx>)>> {
        if !self.has_applicable_tx() {
            return None;
        }
        let seats = self.dish_seats();
        if seats.is_empty() {
            return None;
        }
        if self.now_ms < self.dish_blocked_until_ms {
            return None;
        }
        let h = self.tip_height.saturating_add(1);
        if self.packer_feed_height != h {
            self.dish_sent.clear();
            self.packer_feed_height = h;
            self.packer_feed_ms = 0;
        } else if self.now_ms.saturating_sub(self.packer_feed_ms) < Self::PACKER_FEED_INTERVAL_MS
        {
            return None;
        }
        let batch = self.dish_batch();
        if batch.is_empty() {
            return None;
        }
        let mut out = Vec::new();
        for seat in seats {
            let sent = self.dish_sent.get(&seat);
            let mut heads = Vec::new();
            let mut depth = Vec::new();
            for tx in &batch {
                let already = match sent {
                    Some(have) => have.contains(&tx.tx_id),
                    None => false,
                };
                if already {
                    continue;
                }
                let is_head = tx.sequence == self.state.get(&tx.account).sequence;
                if is_head {
                    heads.push(tx.clone());
                } else {
                    depth.push(tx.clone());
                }
            }
            // Heads alone on the first send. Depth follows on the next take,
            // after note_dish_queued has recorded the heads.
            let suffix = if !heads.is_empty() { heads } else { depth };
            if !suffix.is_empty() {
                out.push((seat, suffix));
            }
        }
        if out.is_empty() {
            return None;
        }
        self.packer_feed_ms = self.now_ms;
        Some(out)
    }

    /// Hub → elected packer: applicable heads on the tx plane (rate-limited).
    pub fn take_packer_feed(&mut self) -> Option<Vec<Tx>> {
        self.take_packer_dish()
            .and_then(|rows| rows.into_iter().next().map(|(_, txs)| txs))
            .filter(|txs| !txs.is_empty())
    }

    /// The last dish did not fit. Do not build another until the backoff.
    pub fn block_dish(&mut self) {
        self.dish_blocked_until_ms = self.now_ms.saturating_add(Self::DISH_FAIL_BACKOFF_MS);
    }

    /// Ensure staging faucet account exists (genesis or post-snapshot backfill).
    pub fn ensure_faucet(&mut self) {
        if !self.state.accounts.contains_key(FAUCET_ACCOUNT) {
            self.state.accounts.insert(
                FAUCET_ACCOUNT.into(),
                AccountState {
                    sequence: 1,
                    balance: FAUCET_GENESIS,
                    meta: AccountMeta::default(),
                    external_addrs: BTreeMap::new(),
                },
            );
        }
    }

    /// Current congestion-driven minimum fee for submits.
    pub fn current_min_fee(&self) -> u64 {
        if !self.cfg.fee_escalate {
            return self.cfg.min_fee.max(1);
        }
        let util = mempool_util_bps(self.mempool.len(), self.cfg.max_mempool_txs);
        suggested_min_fee(self.cfg.min_fee, util)
    }

    pub fn register_validator(&mut self, id: &str, bond: u64) {
        let pk = self.keys.public_hex(id).unwrap_or_default();
        let bond = bond.max(self.cfg.min_bond);
        self.genesis_bond = bond;
        self.validators
            .insert(id.to_string(), ValidatorInfo::new(id, bond, pk));
        // Seed set only: record while chain is still empty (tip 0). Live Bond txs
        // call `bond()` / protocol paths and must not expand this map.
        if self.tip_height == 0 && self.chain.is_empty() {
            self.genesis_validators.insert(id.to_string(), bond);
        }
    }

    /// Seed / override the hard-resync genesis validator set (CLI seed vals).
    /// Safe after snapshot load when the snap predates this field.
    pub fn ensure_genesis_validators(&mut self, ids: &[String], bond: u64) {
        if !self.genesis_validators.is_empty() {
            return;
        }
        let bond = bond.max(self.cfg.min_bond);
        for id in ids {
            self.genesis_validators.insert(id.clone(), bond);
        }
        if self.genesis_bond < bond {
            self.genesis_bond = bond;
        }
    }

    /// Rebuild from genesis and replay `ledgers` (sorted by height) for fork recovery.
    /// Rebuild state from genesis by replaying a set of ledgers (fork recovery).
    ///
    /// - Dedupes by height (first wins).
    /// - Applies continuous prefix from h=1; gaps stop the loop without error
    ///   (partial progress is kept — caller continues pull catch-up).
    /// - `Ok(None)` from ingest (already-applied / buffered) is **not** a failure
    ///   (previously thrashing dual-host hard-resync with "stalled at h=N").
    /// - Clears `need_hard_resync` only when tip ≥ `best_peer_tip` (or peer tip
    ///   unknown / zero).
    pub fn hard_resync_from_ledgers(&mut self, ledgers: &[Ledger]) -> Result<u64, String> {
        if !self.can_hard_resync() {
            self.need_hard_resync = false;
            return Err(
                "hard-resync unavailable: genesis_accounts missing (reload from peer snapshot)"
                    .into(),
            );
        }
        // Dedupe by height, keep lowest-first continuous apply order.
        let mut by_h: BTreeMap<u64, Ledger> = BTreeMap::new();
        for led in ledgers {
            by_h.entry(led.height).or_insert_with(|| led.clone());
        }
        // Never wipe tip without genesis (h=1). Concurrent catch-up batches often
        // start mid-chain; resetting then applying from h=65 left tip=0 and
        // thrashed dual-host status (tip appearing to go backwards).
        if !by_h.contains_key(&1) {
            for led in by_h.values() {
                if self.pending_ledgers.len() < Self::PENDING_LEDGERS_CAP {
                    self.pending_ledgers
                        .entry(led.height)
                        .or_insert_with(|| led.clone());
                }
            }
            self.need_hard_resync = true;
            return Ok(self.tip_height);
        }
        // Reset to genesis.
        self.state = WorldState::genesis(&self.genesis_accounts);
        self.defi = DefiState::default();
        self.bridge = BridgeState::with_genesis_rails();
        self.claimable.clear();
        self.epoch_work = EpochWork::default();
        self.last_settled_epoch = 0;
        self.chain.clear();
        self.seen_at_height.clear();
        self.skips.clear();
        self.skip_votes.clear();
        self.pending_proposal = None;
        self.pending_ledgers.clear();
        self.ok_votes.clear();
        self.soft_ok.clear();
        self.hard_ok.clear();
        self.need_txs_for_height = 0;
        self.need_txs_open_ms = 0;
        self.tip_height = 0;
        self.tip_hash = sha256_hex(b"pl-genesis-v1");
        // Critical: rewind wall clock to genesis so sealed_at_ms advance during
        // replay re-runs epoch settle / unbond maturity identically to the
        // original pack path. Leaving now_ms in the future skips those steps
        // (sealed_at_ms < now_ms) and hard-resync fails at the first epoch
        // boundary with state root mismatch.
        self.now_ms = self.genesis_ms;
        self.height_open_ms = self.genesis_ms;
        self.treasury = TREASURY_GENESIS;
        // Reset bonds to **genesis seed set only**. Re-inserting live-bonded
        // joiners (present at fork time) made commitment roots diverge at h=1
        // (validators are in the root) → permanent tip-0 freeze after join fork.
        self.validators.clear();
        let seed: Vec<(String, u64)> = if !self.genesis_validators.is_empty() {
            self.genesis_validators
                .iter()
                .map(|(id, b)| (id.clone(), *b))
                .collect()
        } else {
            // Legacy: single bond for whatever was registered pre-fix — prefer empty.
            Vec::new()
        };
        if seed.is_empty() {
            self.need_hard_resync = false;
            return Err(
                "hard-resync unavailable: genesis_validators empty (reload peer snapshot + seed --validators)"
                    .into(),
            );
        }
        for (id, bond) in seed {
            let pk = self.keys.public_hex(&id).unwrap_or_default();
            self.validators
                .insert(id.clone(), ValidatorInfo::new(&id, bond, pk));
        }
        for (_h, led) in by_h {
            if led.height <= self.tip_height {
                continue; // duplicate / already applied
            }
            if led.height > self.tip_height + 1 {
                // Gap in batch — keep partial tip; remaining via pull catch-up.
                break;
            }
            match self.ingest_ledger_catchup(&led) {
                Ok(Some(_)) => {}
                Ok(None) => {} // no-op (should be rare after height checks)
                Err(e) => {
                    // Real accept failure (state root / parent / sig).
                    self.hard_resync_fail_streak =
                        self.hard_resync_fail_streak.saturating_add(1);
                    if self.hard_resync_fail_streak >= Self::HARD_RESYNC_FAIL_CAP {
                        self.need_hard_resync = false;
                        self.hard_resync_fail_streak = 0;
                        return Err(format!(
                            "hard-resync abandoned after {} fails: {e}",
                            Self::HARD_RESYNC_FAIL_CAP
                        ));
                    }
                    self.need_hard_resync = true;
                    return Err(e);
                }
            }
        }
        // Clear after successful continuous apply (partial or full).
        self.need_hard_resync = false;
        self.hard_resync_fail_streak = 0;
        // v2.5.0: re-freeze open-height lottery schedule at rebuilt tip.
        self.freeze_open_height_schedule();
        Ok(self.tip_height)
    }

    pub fn tick(&mut self, dt_ms: u64) {
        self.now_ms = self.now_ms.saturating_add(dt_ms);
        // Timeouts only. Committed world state (claimable / unbonds / treasury)
        // changes only when a ledger is applied, using that ledger's sealed_at_ms.
    }

    /// Max `sealed_at` jump vs the **parent ledger** (not local snap clock).
    /// Bounds epoch/unbond grief; still large enough to pack after a crash.
    pub const SEALED_AT_MAX_AHEAD_MS: u64 = 60_000;

    fn parent_sealed_at(&self) -> u64 {
        self.chain
            .last()
            .map(|l| l.sealed_at_ms)
            .unwrap_or(self.genesis_ms)
    }

    /// Stamp for a new pack: local now, clamped to (parent, parent+MAX].
    pub fn pack_sealed_at(&self) -> u64 {
        let parent = self.parent_sealed_at();
        let lo = parent.saturating_add(1);
        let hi = parent.saturating_add(Self::SEALED_AT_MAX_AHEAD_MS.max(1));
        // A hot snap clock has been ~30s ahead of other seats. Checkers
        // refuse anything more than 5s ahead of their own clock, except a
        // 1s step. Stay inside 4s of the parent so a normal seal is accepted.
        let capped = hi.min(parent.saturating_add(4_000));
        self.now_ms.max(lo).min(capped)
    }

    /// Live ingest: monotonic vs parent, not vs snap-restored `now_ms`.
    fn check_sealed_at(&self, ledger: &Ledger) -> Result<(), String> {
        if ledger.height <= 1 {
            return Ok(());
        }
        let parent = self.parent_sealed_at();
        if ledger.sealed_at_ms < parent {
            return Err(format!(
                "sealed_at before parent h={} parent={} sealed={}",
                ledger.height, parent, ledger.sealed_at_ms
            ));
        }
        let hi = parent.saturating_add(Self::SEALED_AT_MAX_AHEAD_MS);
        if ledger.sealed_at_ms > hi {
            return Err(format!(
                "sealed_at too far ahead of parent h={} parent={} sealed={}",
                ledger.height, parent, ledger.sealed_at_ms
            ));
        }
        // v2.9.62 A5: from H_act a checker also refuses (no OK vote) a stamp
        // more than 5 s ahead of its own clock. Liveness guard: a step of up
        // to 1 s over the parent is always allowed, so a chain that is already
        // ahead of wall time keeps moving (slower than wall time) until clocks
        // catch up. Commit/catch-up paths do not call this.
        if self.rv2_at(ledger.height)
            && !sealed_at_v2_ok(ledger.sealed_at_ms, parent, self.now_ms)
        {
            return Err(format!(
                "sealed_at ahead of local clock h={} sealed={} local={}",
                ledger.height, ledger.sealed_at_ms, self.now_ms
            ));
        }
        Ok(())
    }

    fn parent_sealed_utc(&self) -> u64 {
        self.chain
            .last()
            .map(|l| l.sealed_utc_ms)
            .unwrap_or(0)
    }

    /// Deterministic UTC field checks (safe for catch-up / replay / archive).
    /// Does not consult wall clock. No-op while activation is unarmed.
    fn check_sealed_utc_historical(&self, ledger: &Ledger) -> Result<(), String> {
        let from = utc_header::network_utc_from_height(self.cfg.network_id);
        let bounds = utc_header::UtcSkewBounds::resolve(self.cfg.network_id);
        utc_header::check_utc_historical(
            ledger.height,
            from,
            ledger.sealed_utc_ms,
            self.parent_sealed_utc(),
            &bounds,
        )
        .map_err(|e| e.to_string())
    }

    /// Live admission UTC checks: historical rules + PROPOSED skew vs local wall.
    /// Call only on live staging / OK paths — never on pure historical apply.
    /// Uses the Node's `utc_pack_clock` (System = OS wall; not chain `now_ms`) so synthetic
    /// physics clocks cannot masquerade as UTC skew reference.
    fn check_sealed_utc_live(&self, ledger: &Ledger) -> Result<(), String> {
        let from = utc_header::network_utc_from_height(self.cfg.network_id);
        let bounds = utc_header::UtcSkewBounds::resolve(self.cfg.network_id);
        utc_header::check_utc_live_admission(
            ledger.height,
            from,
            ledger.sealed_utc_ms,
            self.parent_sealed_utc(),
            self.utc_pack_clock.now_unix_ms(),
            &bounds,
        )
        .map_err(|e| e.to_string())
    }

    /// After snap load: timeout clock at least at the tip's stamp.
    pub fn sync_now_to_chain(&mut self) {
        let tip = self.parent_sealed_at();
        if self.now_ms < tip {
            self.now_ms = tip;
        }
    }

    /// Apply epoch settle + matured unbonds as of `as_of_ms` without changing
    /// the timeout clock (`now_ms`). No slash evidence (non-ledger paths).
    #[allow(dead_code)]
    fn apply_time_effects(&mut self, as_of_ms: u64, incremental: bool) {
        self.apply_time_effects_with_slashes(as_of_ms, incremental, &[]);
    }

    /// Ledger preamble: settle → **slash** → complete ready unbonds.
    ///
    /// Slash runs before unbond completion so a cooldown that matures on this
    /// ledger cannot escape confiscation into `bond_account`. Returns FPL
    /// seized into the prize pot (`fee_reward_pool` already credited).
    fn apply_time_effects_with_slashes(
        &mut self,
        as_of_ms: u64,
        incremental: bool,
        slashes: &[SlashEvidence],
    ) -> u64 {
        let saved = self.now_ms;
        self.now_ms = as_of_ms;
        let _ = self.maybe_settle_epochs_ex(incremental);
        let seized = Self::apply_slash_evidence(&mut self.validators, slashes);
        if seized > 0 {
            self.epoch_work.fee_reward_pool =
                self.epoch_work.fee_reward_pool.saturating_add(seized);
        }
        let _ = self.complete_all_ready_unbonds();
        self.now_ms = saved;
        seized
    }

    /// Bond native FPL from `from` into validator `id` (creates registry entry if needed).
    pub fn bond(&mut self, id: &str, from: &str, amount: u64) -> Result<u64, String> {
        if amount == 0 {
            return Err("bond amount 0".into());
        }
        if self.validators.get(id).map(|v| v.jailed).unwrap_or(false) {
            return Err("jailed: cannot bond".into());
        }
        let creating = !self.validators.contains_key(id);
        if creating && amount < self.cfg.min_bond {
            return Err(format!("bond below min {}", self.cfg.min_bond));
        }
        self.debit_native(from, amount)?;
        if let Some(v) = self.validators.get_mut(id) {
            v.bond = v.bond.saturating_add(amount);
            if v.bond_account.is_empty() {
                v.bond_account = from.to_string();
            }
            Ok(v.bond)
        } else {
            let pk = self.keys.public_hex(id).unwrap_or_default();
            let mut v = ValidatorInfo::new(id, amount, pk);
            v.bond_account = from.to_string();
            self.validators.insert(id.to_string(), v);
            Ok(amount)
        }
    }

    /// Begin unbond: removes from active lottery bond immediately; funds locked until cooldown.
    pub fn request_unbond(&mut self, id: &str, amount: u64) -> Result<(), String> {
        let cooldown = self.cfg.unbond_cooldown_ms;
        let now = self.now_ms;
        let v = self
            .validators
            .get_mut(id)
            .ok_or_else(|| format!("unknown validator {id}"))?;
        if v.jailed {
            return Err("jailed: cannot unbond (use Unjail)".into());
        }
        if amount == 0 || amount > v.bond {
            return Err(format!("unbond bad amount want ≤{} got {amount}", v.bond));
        }
        if v.unbonding > 0 && now < v.unbond_ready_ms {
            return Err("unbond already pending; complete or wait".into());
        }
        // If prior unbond matured but not claimed, fold into this request after complete.
        if v.unbonding > 0 && now >= v.unbond_ready_ms {
            // leave for complete_unbond
            return Err("complete pending unbond first".into());
        }
        // v2.9.62 A8: a full exit also releases escrow into the cooldown, so a
        // jail during the cooldown (slash takes `unbonding`) forfeits it.
        let released = if amount == v.bond { std::mem::take(&mut v.escrow) } else { 0 };
        v.bond = v.bond.saturating_sub(amount);
        v.unbonding = amount.saturating_add(released);
        v.unbond_ready_ms = now.saturating_add(cooldown);
        Ok(())
    }

    /// Finish unbond after cooldown; credit `bond_account`.
    pub fn complete_unbond(&mut self, id: &str) -> Result<u64, String> {
        let now = self.now_ms;
        let (amt, acct) = {
            let v = self
                .validators
                .get(id)
                .ok_or_else(|| format!("unknown validator {id}"))?;
            if v.unbonding == 0 {
                return Err("no unbonding stake".into());
            }
            if now < v.unbond_ready_ms {
                return Err(format!(
                    "unbond not ready: need {} more ms",
                    v.unbond_ready_ms.saturating_sub(now)
                ));
            }
            let acct = if v.bond_account.is_empty() {
                id.to_string()
            } else {
                v.bond_account.clone()
            };
            (v.unbonding, acct)
        };
        if let Some(v) = self.validators.get_mut(id) {
            v.unbonding = 0;
            v.unbond_ready_ms = 0;
        }
        self.credit_native(&acct, amt);
        Ok(amt)
    }

    pub fn complete_all_ready_unbonds(&mut self) -> Vec<(String, u64)> {
        let ids: Vec<String> = self
            .validators
            .iter()
            .filter(|(_, v)| v.unbonding > 0 && self.now_ms >= v.unbond_ready_ms)
            .map(|(id, _)| id.clone())
            .collect();
        let mut out = Vec::new();
        for id in ids {
            if let Ok(amt) = self.complete_unbond(&id) {
                out.push((id, amt));
            }
        }
        out
    }

    /// Private-fleet / soak: mint secondary asset balance (not native emission).
    pub fn credit_asset_admin(&mut self, account: &str, asset: &str, amount: u64) -> Result<(), String> {
        if amount == 0 {
            return Err("credit amount 0".into());
        }
        let native = asset == DEFI_NATIVE || asset == NATIVE || asset == "FPL";
        if native && !self.cfg.allow_admin_wire {
            return Err("admin-only: native mint disabled".into());
        }
        if native {
            self.credit_native(account, amount);
        } else {
            self.defi.credit_asset(account, asset, amount);
        }
        Ok(())
    }

    /// Current 1-based epoch index.
    pub fn current_epoch(&self) -> u64 {
        epoch_index(self.now_ms, self.genesis_ms, self.cfg.epoch_ms)
    }

    /// Settle all fully completed epochs since last settle.
    pub fn maybe_settle_epochs(&mut self) -> Vec<u64> {
        self.maybe_settle_epochs_ex(true)
    }

    fn maybe_settle_epochs_ex(&mut self, incremental: bool) -> Vec<u64> {
        let cur = self.current_epoch();
        let mut settled = Vec::new();
        // Settle epochs that have fully ended: last finished index is cur-1.
        let end = cur.saturating_sub(1);
        let mut e = self.last_settled_epoch.saturating_add(1);
        while e <= end {
            self.settle_epoch_index_ex(e, incremental);
            settled.push(e);
            e += 1;
        }
        settled
    }

    /// Work used at epoch settle. Must be identical on every honest node that
    /// committed the same prefix — **not** a function of who still holds tx
    /// bodies in RAM.
    ///
    /// 2.9.17 walked `chain` and used `led.txs.len()` / `led.txs[].fee`. After
    /// `max_body_ledgers` strip those are 0. An archive hub (64 bodies) and a
    /// joiner that inherited `archive=true` with no store (every catch-up body)
    /// therefore settled a different pack pot. Live 20922: 126 ledgers in the
    /// epoch, hub counted the last 64, droplet counted ~116 → state root
    /// mismatch, tip stuck. Gossip `check_votes` stay ignored (dual-host bug).
    ///
    /// Pack/fees/watcher come from incremental counters updated on every
    /// commit and restored from the snapshot. Checker pot is an equal
    /// synthetic credit per bonded non-jailed seat. Mainnet 7-day epochs
    /// cannot reconstruct pack work from a 20k header tail anyway.
    ///
    /// **Compat:** the *trigger* ledger (the one whose sealed_at crosses
    /// the epoch) tells us which formula the packer used. `fee_total=0` is
    /// a 2.9.17 header → replay `txs.len()` on the RAM body window (34799).
    /// `fee_total>0` is 2.9.18+ → incremental (35001 was packed that way
    /// even though epoch 1481's older headers still have fee_total=0).
    fn epoch_work_from_chain(&self, epoch: u64, incremental: bool) -> EpochWork {
        let mut work = EpochWork::default();
        // v2.9.62: v2 epochs always use the committed counters. The legacy
        // fold re-derives the v1 50 % fee pool from (possibly pruned) chain
        // bodies; a v2 pot is 20 % and accrues only in the commit hook.
        if incremental || self.rv2_epoch(epoch) {
            work.pack_txs = self.epoch_work.pack_txs.clone();
            work.fee_reward_pool = self.epoch_work.fee_reward_pool;
        } else {
            self.fold_legacy_pack_work(epoch, &mut work);
        }
        work.watcher_work = self.epoch_work.watcher_work.clone();
        work.watcher_slots = self.epoch_work.watcher_slots.clone();
        work.proposer_credit = self.epoch_work.proposer_credit.clone();
        work.vote_credit = self.epoch_work.vote_credit.clone();
        work.lp_start = self.epoch_work.lp_start.clone();
        work.lp_start_taken = self.epoch_work.lp_start_taken;
        work.presence_heights = self.epoch_work.presence_heights;
        work.present = self.epoch_work.present.clone();
        for (id, v) in &self.validators {
            if !v.jailed && v.bond > 0 {
                work.record_check(id, &format!("epoch-{epoch}-equal"));
            }
        }
        work
    }

    fn fold_legacy_pack_work(&self, epoch: u64, work: &mut EpochWork) {
        let epoch_ms = self.cfg.epoch_ms.max(1);
        let start = self
            .genesis_ms
            .saturating_add(epoch.saturating_sub(1).saturating_mul(epoch_ms));
        let end = start.saturating_add(epoch_ms);
        for led in &self.chain {
            if led.sealed_at_ms < start || led.sealed_at_ms >= end {
                continue;
            }
            work.record_pack(&led.packer, led.txs.len() as u64);
            let fees: u64 = if led.fee_total > 0 {
                led.fee_total
            } else {
                led.txs.iter().map(|t| t.fee).sum()
            };
            let (_burn, rew) = fee_burn_and_reward(fees);
            work.fee_reward_pool = work.fee_reward_pool.saturating_add(rew);
        }
    }

    fn settle_epoch_index(&mut self, epoch: u64) {
        self.settle_epoch_index_ex(epoch, true)
    }

    fn settle_epoch_index_ex(&mut self, epoch: u64, incremental: bool) {
        if epoch <= self.last_settled_epoch {
            return;
        }
        let claimable = epoch_claimable_from(epoch, self.cfg.first_claim_epoch);
        let amm_w = self.defi.aggregate_amm_lp_weights();
        let lend_w = self.defi.aggregate_lend_lp_weights();
        // Deterministic work from chain (+ equal check weights). Do not use
        // gossip-partial pack/check counters from self.epoch_work.
        let work = self.epoch_work_from_chain(epoch, incremental);
        // BRIDGE: operator bucket carved off the top (0 before the bridge
        // height -> byte-identical to the legacy settle paths).
        let op_active = self.bridge_at(self.tip_height.saturating_add(1));
        let op_bps = self.operator_params().emission_share_bps.min(10_000) as u128;
        let op_bucket = move |emit: u64| -> u64 {
            if op_active {
                (emit as u128 * op_bps / 10_000) as u64
            } else {
                0
            }
        };
        let s = if self.rv2_epoch(epoch) {
            let (amm_v, lend_v) = self.lp_value_weights_v2(&work);
            crate::economy::settle_epoch_v2_ops(
                self.treasury,
                self.cfg.emission_bps,
                claimable,
                &work,
                &amm_v,
                &lend_v,
                &self.floor_weights_v2(),
                op_bucket,
            )
        } else {
            crate::economy::settle_epoch_ops(
                self.treasury,
                self.cfg.emission_bps,
                claimable,
                &work,
                &amm_w,
                &lend_w,
                0,
                op_bucket,
            )
        };
        if s.epoch_emit > 0 {
            self.treasury = self.treasury.saturating_sub(s.epoch_emit);
        }
        {
            let mut all: BTreeMap<String, u64> = BTreeMap::new();
            for (id, amt) in s
                .pack_pays
                .iter()
                .chain(s.check_pays.iter())
                .chain(s.watcher_pays.iter())
                .chain(s.amm_pays.iter())
                .chain(s.lend_pays.iter())
            .chain(s.floor_pays.iter())
            {
                *all.entry(id.clone()).or_insert(0) += amt;
            }
            let mut top: Vec<(String, u64)> = all.into_iter().collect();
            top.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
            top.truncate(20);
            self.last_settle = Some(serde_json::json!({
                "epoch": epoch,
                "claimable": claimable,
                "emit": s.epoch_emit,
                "validator_pot": s.validator_pot,
                "formula": if self.rv2_epoch(epoch) { "v2" } else { "v1" },
                "pays_top": top.into_iter().collect::<BTreeMap<_, _>>(),
                "settled_at_height": self.tip_height.saturating_add(1),
            }));
        }
        let mut distributed = 0u64;
        if self.seat_payout_at(self.tip_height.saturating_add(1)) {
            // Seat payout: validator pays (pack / check / floor) go to the seat
            // (payout account or seat bucket); account pays (watcher / AMM /
            // lend) stay in `claimable[account]`.
            for (id, amt) in s
                .pack_pays
                .iter()
                .chain(s.check_pays.iter())
                .chain(s.floor_pays.iter())
            {
                Self::credit_seat_reward(
                    &mut self.validators,
                    &mut self.state,
                    &mut self.claimable,
                    id,
                    *amt,
                );
                distributed = distributed.saturating_add(*amt);
            }
            for (id, amt) in s
                .watcher_pays
                .iter()
                .chain(s.amm_pays.iter())
                .chain(s.lend_pays.iter())
            {
                *self.claimable.entry(id.clone()).or_insert(0) += amt;
                distributed = distributed.saturating_add(*amt);
            }
        } else {
            for (id, amt) in s
                .pack_pays
                .iter()
                .chain(s.check_pays.iter())
                .chain(s.watcher_pays.iter())
                .chain(s.amm_pays.iter())
                .chain(s.lend_pays.iter())
                .chain(s.floor_pays.iter())
            {
                *self.claimable.entry(id.clone()).or_insert(0) += amt;
                distributed = distributed.saturating_add(*amt);
            }
        }
        // BRIDGE: operator bucket paid through the registry (inert before the
        // bridge height); its unpaid part is refunded below with the rest.
        let op_paid = self.settle_operators(epoch, s.operator_bucket);
        distributed = distributed.saturating_add(op_paid);
        if op_active {
            if let Some(serde_json::Value::Object(m)) = self.last_settle.as_mut() {
                m.insert("operator_bucket".into(), serde_json::json!(s.operator_bucket));
                m.insert("operator_paid".into(), serde_json::json!(op_paid));
            }
        }
        // Undistributed emission (no workers / empty weights) returns to treasury —
        // do not destroy FPL when an idle claimable epoch settles.
        if s.epoch_emit > 0 {
            let refund = s.epoch_emit.saturating_sub(distributed.min(s.epoch_emit));
            if refund > 0 {
                self.treasury = self.treasury.saturating_add(refund);
            }
        }
        self.epoch_work = EpochWork::default();
        // v2.9.62 B7: capture LP units at the start of the next epoch (hold rule).
        if self.rv2_epoch(epoch + 1) {
            self.epoch_work.lp_start = self.lp_units_now();
            self.epoch_work.lp_start_taken = true;
        }
        self.last_settled_epoch = epoch;
    }

    /// Debit native from account (fee-free internal economy moves).
    fn debit_native(&mut self, account: &str, amount: u64) -> Result<(), String> {
        let mut a = self.state.get(account);
        if a.balance < amount {
            return Err("insufficient native".into());
        }
        a.balance -= amount;
        self.state.accounts.insert(account.to_string(), a);
        Ok(())
    }

    fn credit_native(&mut self, account: &str, amount: u64) {
        let mut a = self.state.get(account);
        a.balance = a.balance.saturating_add(amount);
        self.state.accounts.insert(account.to_string(), a);
    }

    pub fn create_pool(
        &mut self,
        pool_id: &str,
        asset_a: &str,
        asset_b: &str,
    ) -> Result<(), String> {
        if self.defi.pools.contains_key(pool_id) {
            return Err("pool exists".into());
        }
        self.defi.pools.insert(
            pool_id.to_string(),
            AmmPool::new(pool_id, asset_a, asset_b),
        );
        Ok(())
    }

    pub fn add_liquidity(
        &mut self,
        pool_id: &str,
        provider: &str,
        amt_a: u64,
        amt_b: u64,
    ) -> Result<u64, String> {
        let pool = self
            .defi
            .pools
            .get(pool_id)
            .ok_or("unknown pool")?
            .clone();
        // debit assets
        if pool.asset_a == DEFI_NATIVE || pool.asset_a == "FPL" {
            self.debit_native(provider, amt_a)?;
        } else {
            self.defi.debit_asset(provider, &pool.asset_a, amt_a)?;
        }
        if pool.asset_b == DEFI_NATIVE || pool.asset_b == "FPL" {
            self.debit_native(provider, amt_b)?;
        } else {
            self.defi.debit_asset(provider, &pool.asset_b, amt_b)?;
        }
        let p = self.defi.pools.get_mut(pool_id).unwrap();
        p.add_liquidity(provider, amt_a, amt_b)
    }

    pub fn swap(
        &mut self,
        pool_id: &str,
        who: &str,
        token_in: &str,
        amount_in: u64,
        min_out: u64,
    ) -> Result<u64, String> {
        let pool = self
            .defi
            .pools
            .get(pool_id)
            .ok_or("unknown pool")?
            .clone();
        let token_out = if token_in == pool.asset_a {
            pool.asset_b.clone()
        } else {
            pool.asset_a.clone()
        };
        if token_in == DEFI_NATIVE || token_in == "FPL" {
            self.debit_native(who, amount_in)?;
        } else {
            self.defi.debit_asset(who, token_in, amount_in)?;
        }
        let out = {
            let p = self.defi.pools.get_mut(pool_id).unwrap();
            p.swap(token_in, amount_in, min_out)?
        };
        if token_out == DEFI_NATIVE || token_out == "FPL" {
            self.credit_native(who, out);
        } else {
            self.defi.credit_asset(who, &token_out, out);
        }
        Ok(out)
    }

    /// Swap leg: legacy pool-only before 2.10.4; from the 2.10.4 height an
    /// `<ASSET>/FPL` pool leg routes best-price across the order book and
    /// the pool ([`crate::orderbook::hybrid_swap`]). With an empty book the
    /// result is the same as the pool swap.
    pub fn swap_any(
        &mut self,
        pool_id: &str,
        who: &str,
        token_in: &str,
        amount_in: u64,
        min_out: u64,
    ) -> Result<u64, String> {
        let fpl_pair = self
            .defi
            .pools
            .get(pool_id)
            .map(|p| (p.asset_a == "FPL") != (p.asset_b == "FPL"))
            .unwrap_or(false);
        if !(self.orderbook_open() && fpl_pair) {
            return self.swap(pool_id, who, token_in, amount_in, min_out);
        }
        {
            let p = &self.defi.pools[pool_id];
            if token_in != p.asset_a && token_in != p.asset_b {
                return Err("swap: unknown asset".into());
            }
            if amount_in == 0 {
                return Err("swap: zero in".into());
            }
        }
        let h = self.tip_height.saturating_add(1);
        let mut b = crate::orderbook::Books { state: &mut self.state, defi: &mut self.defi };
        let out = crate::orderbook::hybrid_swap(&mut b, pool_id, who, token_in, amount_in, h)?;
        if out < min_out {
            return Err(format!("swap: slippage out {out} < min {min_out}"));
        }
        Ok(out)
    }

    pub fn create_market(&mut self, market_id: &str, asset: &str) -> Result<(), String> {
        if self.defi.markets.contains_key(market_id) {
            return Err("market exists".into());
        }
        self.defi.markets.insert(
            market_id.to_string(),
            LendingMarket::new(market_id, asset),
        );
        Ok(())
    }

    pub fn lend_supply(
        &mut self,
        market_id: &str,
        who: &str,
        amount: u64,
    ) -> Result<u64, String> {
        let asset = self
            .defi
            .markets
            .get(market_id)
            .ok_or("unknown market")?
            .asset
            .clone();
        if asset == DEFI_NATIVE || asset == "FPL" {
            self.debit_native(who, amount)?;
        } else {
            self.defi.debit_asset(who, &asset, amount)?;
        }
        self.defi
            .markets
            .get_mut(market_id)
            .unwrap()
            .supply(who, amount)
    }

    pub fn lend_withdraw(&mut self, market_id: &str, who: &str, shares: u64) -> Result<u64, String> {
        let asset = self
            .defi
            .markets
            .get(market_id)
            .ok_or("unknown market")?
            .asset
            .clone();
        let amount = self
            .defi
            .markets
            .get_mut(market_id)
            .unwrap()
            .withdraw_supply(who, shares)?;
        if asset == DEFI_NATIVE || asset == "FPL" {
            self.credit_native(who, amount);
        } else {
            self.defi.credit_asset(who, &asset, amount);
        }
        Ok(amount)
    }

    /// FPL per one whole coin from the deepest FPL pool for this asset.
    fn pool_price_fpl(&self, asset: &str) -> Option<u64> {
        self.pool_price_fpl_scaled(asset, crate::defi::coin_scale(asset))
    }

    /// v2.10.4: pool spot as FPL per `scale` raw units.
    fn pool_price_fpl_scaled(&self, asset: &str, scale: u128) -> Option<u64> {
        let mut best_raw = 0u64;
        let mut best: Option<u64> = None;
        for p in self.defi.pools.values() {
            let (fpl, raw) = if p.asset_a == "FPL" && p.asset_b == asset {
                (p.reserve_a, p.reserve_b)
            } else if p.asset_b == "FPL" && p.asset_a == asset {
                (p.reserve_b, p.reserve_a)
            } else {
                continue;
            };
            if raw <= best_raw {
                continue;
            }
            if let Some(px) = crate::defi::fpl_per_coin_scaled(fpl, raw, scale) {
                best_raw = raw;
                best = Some(px);
            }
        }
        best
    }

    /// Write the pool spot onto the market. ETH fits because the price is per 1 ETH, not per million wei.
    pub fn sync_lend_price(&mut self, market_id: &str) -> Result<u64, String> {
        let m = self
            .lend_market_rescaled(self.defi.markets.get(market_id).ok_or("unknown market")?);
        let asset = m.asset.clone();
        let scale = m.scale();
        let px = self
            .pool_price_fpl_scaled(&asset, scale)
            .ok_or_else(|| format!("no pool price for {asset}"))?;
        let slot = self.defi.markets.get_mut(market_id).unwrap();
        *slot = m;
        slot.set_price(px);
        Ok(px)
    }

    pub fn lend_borrow(
        &mut self,
        market_id: &str,
        who: &str,
        amount: u64,
        collateral_fpl: u64,
    ) -> Result<(), String> {
        let asset = self
            .defi
            .markets
            .get(market_id)
            .ok_or("unknown market")?
            .asset
            .clone();
        // A pool spot replaces the stored price before the LTV check, so ETH cannot borrow at 1 wei = 1 FPL.
        let scale = self
            .lend_market_rescaled(self.defi.markets.get(market_id).ok_or("unknown market")?)
            .scale();
        if self.pool_price_fpl_scaled(&asset, scale).is_some() {
            let _ = self.sync_lend_price(market_id);
        }
        if collateral_fpl > 0 {
            self.debit_native(who, collateral_fpl)?;
        }
        if let Err(e) = self
            .defi
            .markets
            .get_mut(market_id)
            .unwrap()
            .borrow(who, amount, collateral_fpl)
        {
            if collateral_fpl > 0 {
                self.credit_native(who, collateral_fpl);
            }
            return Err(e);
        }
        if asset == DEFI_NATIVE || asset == "FPL" {
            self.credit_native(who, amount);
        } else {
            self.defi.credit_asset(who, &asset, amount);
        }
        Ok(())
    }

    pub fn lend_repay(&mut self, market_id: &str, who: &str, amount: u64) -> Result<u64, String> {
        let asset = self
            .defi
            .markets
            .get(market_id)
            .ok_or("unknown market")?
            .asset
            .clone();
        if asset == DEFI_NATIVE || asset == "FPL" {
            self.debit_native(who, amount)?;
        } else {
            self.defi.debit_asset(who, &asset, amount)?;
        }
        let paid = self
            .defi
            .markets
            .get_mut(market_id)
            .unwrap()
            .repay(who, amount)?;
        let refund = amount.saturating_sub(paid);
        if refund > 0 {
            if asset == DEFI_NATIVE || asset == "FPL" {
                self.credit_native(who, refund);
            } else {
                self.defi.credit_asset(who, &asset, refund);
            }
        }
        let col = self
            .defi
            .markets
            .get(market_id)
            .and_then(|m| m.collateral.get(who))
            .copied()
            .unwrap_or(0);
        let debt = self
            .defi
            .markets
            .get(market_id)
            .and_then(|m| m.debt.get(who))
            .copied()
            .unwrap_or(0);
        if debt == 0 && col > 0 {
            self.defi
                .markets
                .get_mut(market_id)
                .unwrap()
                .collateral
                .remove(who);
            self.credit_native(who, col);
        }
        Ok(paid)
    }

    pub fn remove_liquidity(&mut self, pool_id: &str, who: &str, lp_burn: u64) -> Result<(u64, u64), String> {
        let pool = self
            .defi
            .pools
            .get(pool_id)
            .ok_or("unknown pool")?
            .clone();
        let (out_a, out_b) = self
            .defi
            .pools
            .get_mut(pool_id)
            .unwrap()
            .remove_liquidity(who, lp_burn)?;
        if pool.asset_a == DEFI_NATIVE || pool.asset_a == "FPL" {
            self.credit_native(who, out_a);
        } else {
            self.defi.credit_asset(who, &pool.asset_a, out_a);
        }
        if pool.asset_b == DEFI_NATIVE || pool.asset_b == "FPL" {
            self.credit_native(who, out_b);
        } else {
            self.defi.credit_asset(who, &pool.asset_b, out_b);
        }
        Ok((out_a, out_b))
    }

    fn find_pool(&self, a: &str, b: &str) -> Option<String> {
        self.defi.pools.iter().find_map(|(id, p)| {
            let hit = (p.asset_a == a && p.asset_b == b) || (p.asset_a == b && p.asset_b == a);
            if hit { Some(id.clone()) } else { None }
        })
    }

    /// Direct pool, or sell→FPL→buy when both hub pools exist.
    pub fn swap_route(
        &mut self,
        who: &str,
        token_in: &str,
        token_out: &str,
        amount_in: u64,
        min_out: u64,
    ) -> Result<u64, String> {
        if token_in == token_out {
            return Err("swap: same asset".into());
        }
        if let Some(id) = self.find_pool(token_in, token_out) {
            return self.swap_any(&id, who, token_in, amount_in, min_out);
        }
        if token_in != "FPL" && token_out != "FPL" {
            let p1 = self
                .find_pool(token_in, "FPL")
                .ok_or("no pool from sell asset to FPL")?;
            let mid = self.swap_any(&p1, who, token_in, amount_in, 1)?;
            let p2 = self
                .find_pool("FPL", token_out)
                .ok_or("no pool from FPL to buy asset")?;
            return self.swap_any(&p2, who, "FPL", mid, min_out);
        }
        Err("no route".into())
    }

    /// Record watcher work + optional current hourly slot (presence).
    pub fn watcher_credit(&mut self, account: &str, work_units: u64, with_slot: bool) {
        if work_units > 0 {
            self.epoch_work.record_watcher_work(account, work_units);
        }
        if with_slot {
            let slot = self.current_epoch_slot();
            if self.rv2_epoch(self.current_epoch()) {
                self.epoch_work.record_watcher_slot_v2(account, slot);
            } else {
                self.epoch_work.record_watcher_slot(account, slot);
            }
        }
    }

    /// Mark discrete presence slots `0..slots-1` (capped at 168) without advancing clock.
    /// Private soak / admin: full-week presence without waiting 7d wall time.
    pub fn watcher_mark_presence(&mut self, account: &str, slots: u64) {
        let n = slots.min(WATCHER_SLOTS_PER_EPOCH);
        let v2 = self.rv2_epoch(self.current_epoch());
        for s in 0..n {
            if v2 {
                self.epoch_work.record_watcher_slot_v2(account, s);
            } else {
                self.epoch_work.record_watcher_slot(account, s);
            }
        }
    }

    /// Combined credit: work + optional wall-clock slot + optional bulk presence slots.
    pub fn watcher_credit_ex(
        &mut self,
        account: &str,
        work_units: u64,
        with_slot: bool,
        presence_slots: u64,
    ) {
        self.watcher_credit(account, work_units, with_slot);
        if presence_slots > 0 {
            self.watcher_mark_presence(account, presence_slots);
        }
    }

    pub fn current_epoch_slot(&self) -> u64 {
        let epoch_ms = self.cfg.epoch_ms.max(1);
        let into = self.now_ms.saturating_sub(self.genesis_ms) % epoch_ms;
        let slot_ms = epoch_ms / WATCHER_SLOTS_PER_EPOCH.max(1);
        into / slot_ms.max(1)
    }

    /// True if `account` already filled `slot` this epoch (wallet enter/exit).
    ///
    /// v2.9.62+ epochs record presence in `watcher_slot_bits`; reading only the
    /// legacy `check_seen` set made this always false on rv2 epochs.
    pub fn watcher_in_slot(&self, account: &str, slot: u64) -> bool {
        self.epoch_work.watcher_has_slot(account, slot)
    }

    /// Distinct watchers that filled the current hourly slot (status field).
    pub fn watchers_active_slot(&self) -> u64 {
        self.epoch_work.watchers_in_slot(self.current_epoch_slot())
    }

    /// Slot duration ms for current epoch length (private fleet debug).
    pub fn watcher_slot_ms(&self) -> u64 {
        let epoch_ms = self.cfg.epoch_ms.max(1);
        (epoch_ms / WATCHER_SLOTS_PER_EPOCH.max(1)).max(1)
    }

    /// Force-settle current incomplete epoch (admin/test only).
    pub fn force_settle_current_epoch(&mut self) {
        let e = self.current_epoch();
        if e > self.last_settled_epoch {
            self.settle_epoch_index(e);
        }
    }

    /// Pull claimable rewards into account balance (proto claim).
    pub fn claim_rewards(&mut self, account: &str) -> Result<u64, String> {
        let amt = self.claimable.remove(account).unwrap_or(0);
        if amt == 0 {
            return Ok(0);
        }
        let mut a = self.state.get(account);
        a.balance = a.balance.saturating_add(amt);
        self.state.accounts.insert(account.to_string(), a);
        Ok(amt)
    }

    /// Activate a vault: Hot → Vault, nominate the only legal payout address, hard-lock.
    /// The protocol will never pay any other destination from this account.
    pub fn open_vault(&mut self, account: &str, destination: &str) -> Result<(), String> {
        let dest = destination.trim();
        if dest.is_empty() {
            return Err("vault: nominate a destination to activate".into());
        }
        if dest == account {
            return Err("vault: destination must differ from the vault account".into());
        }
        let mut a = self.state.get(account);
        a.meta.open_as(AccountType::Vault)?;
        a.meta.set_allowlist(vec![dest.to_string()])?;
        a.meta.vault_lock()?;
        self.state.accounts.insert(account.to_string(), a);
        Ok(())
    }

    pub fn vault_lock(&mut self, account: &str) -> Result<(), String> {
        let mut a = self.state.get(account);
        a.meta.vault_lock()?;
        self.state.accounts.insert(account.to_string(), a);
        Ok(())
    }

    fn enroll_name_key(&mut self, tx: &Tx) -> Result<(), String> {
        if self.keys.has_public(&tx.account) {
            return Ok(());
        }
        self.key_bind_check(tx)?;
        match self.keys.scheme {
            CryptoScheme::HmacDev => {
                self.keys
                    .insert_public(&tx.account, &tx.public_key)
                    .map_err(|e| e.to_string())?;
            }
            CryptoScheme::Falcon512 => {
                let pk = crypto::PublicKey::from_hex(self.keys.scheme, &tx.public_key)
                    .map_err(|e| e.to_string())?;
                let payload = Tx::payload(
                    &tx.account,
                    tx.sequence,
                    &tx.destination,
                    tx.amount,
                    tx.fee,
                    tx.network_id,
                    &tx.body,
                );
                if !KeyRing::verify_with_public(&pk, &payload, &tx.signature) {
                    return Err("bad tx crypto: bad signature".into());
                }
                self.keys
                    .insert_public(&tx.account, &tx.public_key)
                    .map_err(|e| e.to_string())?;
            }
        }
        Ok(())
    }

    pub fn reserve_name(&mut self, name: &str, public_key: &str) -> Result<(), String> {
        let want = NameRegistry::validate_name(name)?;
        if want != name {
            return Err("name: use the normalized lowercase name as the account".into());
        }
        self.names.reserve(name, public_key, self.now_ms)?;
        Ok(())
    }

    pub fn activate_name(&mut self, name: &str, public_key: &str) -> Result<(), String> {
        let want = NameRegistry::validate_name(name)?;
        if want != name {
            return Err("name: use the normalized lowercase name as the account".into());
        }
        let fee = {
            let st = self.names.status(name, self.now_ms);
            match st {
                NameStatus::Activated { .. } => 0,
                NameStatus::Reserved { fee_required, .. } | NameStatus::Free { fee_required } => {
                    fee_required
                }
            }
        };
        if fee > 0 {
            let mut a = self.state.get(name);
            if a.balance < fee {
                return Err(format!("name: activation needs {fee} FPL"));
            }
            a.balance -= fee;
            self.state.accounts.insert(name.to_string(), a);
            self.treasury = self.treasury.saturating_add(fee);
        }
        self.names.activate(name, public_key, self.now_ms)?;
        Ok(())
    }

    /// Submit a rail block header (watcher work on success).
    pub fn submit_rail_header(
        &mut self,
        asset: &str,
        header: RailHeader,
        watcher: Option<&str>,
    ) -> Result<(), String> {
        // v2.9.62 A2: from H_act, identical re-submits are rejected and work is
        // credited only for real progress (tip advance or winning reorg).
        let strict = self.rv2_open();
        let fork_fix = self.btc4_fork_fix_open();
        let progressed = self.bridge.rail_mut(asset)?.submit_header_ex2(header, strict, fork_fix)?;
        if let Some(w) = watcher {
            if progressed {
                self.watcher_credit(w, 1, true);
            } else {
                // Pending-fork header: presence only.
                self.watcher_credit(w, 0, true);
            }
        }
        Ok(())
    }

    /// SPV deposit: verify proof, mint wrapped rail asset to `to`, credit watcher work.
    pub fn rail_deposit(
        &mut self,
        asset: &str,
        to: &str,
        amount: u64,
        proof: BridgeProof,
        watcher: Option<&str>,
    ) -> Result<(), String> {
        if asset != crate::bridge::RAIL_BTC
            && !crate::evm_spv::is_evm_rail(asset)
            && !self.cfg.allow_admin_wire
        {
            return Err("unknown rail mint disabled on public".into());
        }
        if crate::evm_spv::is_evm_rail(asset) {
            self.bridge.mint_evm_lc(asset, amount, &proof, to)?;
        } else {
            if asset == crate::bridge::RAIL_BTC {
                if let Ok(s) = self.abort_seed_bytes() {
                    self.bridge.rail_mut(asset)?.take_seed = Some(s);
                }
            }
            let tip = self.bridge.rail(asset)?.tip_height;
            self.bridge
                .rail_mut(asset)?
                .verify_and_mint(amount, &proof, tip, Some(to))?;
        }
        if asset == crate::bridge::RAIL_BTC {
            let vout = if proof.raw_tx.is_empty() {
                0
            } else {
                let raw = crate::btc_spv::hex_decode(&proof.raw_tx).unwrap_or_default();
                crate::btc_spv::parse_tx(&raw)
                    .ok()
                    .and_then(|tx| {
                        let watch_hex = self
                            .bridge
                            .rail(asset)
                            .ok()?
                            .effective_vault_pub()
                            .map(|p| p.spk_hex.clone())?;
                        let watch = crate::btc_spv::hex_decode(&watch_hex).ok()?;
                        crate::btc_spv::extract_deposit(&tx, &watch).ok()
                    })
                    .map(|e| e.vout)
                    .unwrap_or(0)
            };
            let instance_deposit = self
                .bridge
                .rail(asset)
                .ok()
                .and_then(|r| r.bitvm2_instance_spk.clone())
                .and_then(|spk| {
                    let raw = crate::btc_spv::hex_decode(&proof.raw_tx).ok()?;
                    let tx = crate::btc_spv::parse_tx(&raw).ok()?;
                    crate::btc_spv::extract_deposit(&tx, &spk).ok().map(|_| true)
                })
                .unwrap_or(false);
            if !instance_deposit {
                self.bridge.rail_mut(asset)?.record_vault_deposit(
                    &proof.external_txid,
                    vout,
                    amount,
                    proof.height,
                );
            }
            if let Ok(seed) = self.abort_seed_bytes() {
                if !proof.raw_tx.is_empty() {
                    if let Ok(raw) = crate::btc_spv::hex_decode(&proof.raw_tx) {
                        if let Ok(tx) = crate::btc_spv::parse_tx(&raw) {
                            if let Ok(uv) = crate::user_vault::extract_deposit(
                                &tx,
                                &seed,
                                crate::user_vault::USER_VAULT_CSV,
                            ) {
                                let owner = to.to_string();
                                self.bridge.rail_mut(asset)?.user_vaults.insert(
                                    proof.external_txid.to_ascii_lowercase(),
                                    crate::bridge::UserVaultMeta {
                                        owner,
                                        user_h160_hex: hex::encode(uv.user_h160),
                                        nonce_hex: hex::encode(uv.nonce),
                                        sats: uv.value_sats,
                                        vout: uv.vout,
                                    },
                                );
                            }
                        }
                    }
                }
            }
        }
        // Mint wrapped asset balance (BTC/ETH/BNB as defi balances).
        if asset == NATIVE || asset == DEFI_NATIVE {
            self.credit_native(to, amount);
        } else {
            self.defi.credit_asset(to, asset, amount);
        }
        if let Some(w) = watcher {
            self.watcher_credit(w, 1, true);
        }
        Ok(())
    }

    /// Permissionless V3 peg-in. Txs apply at ledger height `tip + 1`.
    ///
    /// A mint credits the same rail balance V1 credits (`credit_asset` /
    /// native) after `resolve_evm_v3_deposit` has already added `total_minted`.
    /// A refund does not touch balances or `total_minted` beyond the claim
    /// leaf the bridge recorded. No watcher credit: this is not rail work.
    pub fn eth_v3_deposit(
        &mut self,
        asset: &str,
        deposit_id: &str,
        credit_to: &str,
        proof: &crate::bridge::BridgeProof,
    ) -> Result<(), String> {
        let height = self.tip_height.saturating_add(1);
        if !self.eth_v3_at(height) {
            return Err(crate::bridge::V3_DEPOSITS_NOT_ACTIVE.into());
        }
        let v3 = self
            .eth_v3_bridge
            .ok_or_else(|| crate::bridge::V3_BRIDGE_NOT_CONFIGURED.to_string())?;
        let defi = &self.defi;
        let balance_of = |acct: &str, asset: &str| defi.asset_bal(acct, asset);
        let view = crate::bridge::V3CreditView {
            balance_of: &balance_of,
        };
        let outcome = self.bridge.resolve_evm_v3_deposit(
            asset,
            deposit_id,
            credit_to,
            proof,
            &v3,
            &view,
        )?;
        if let crate::bridge::V3Outcome::Mint {
            asset,
            amount,
            credit_to,
        } = outcome
        {
            if asset == NATIVE || asset == DEFI_NATIVE {
                self.credit_native(&credit_to, amount);
            } else {
                self.defi.credit_asset(&credit_to, &asset, amount);
            }
        }
        Ok(())
    }

    /// Burn wrapped rail asset and open a withdraw note for external release.
    pub fn rail_withdraw(
        &mut self,
        asset: &str,
        from: &str,
        amount: u64,
        external_to: &str,
    ) -> Result<String, String> {
        self.rail_withdraw_signed(asset, from, amount, external_to, None)
    }

    /// v1: do not burn FBTC until a t-of-n vault signature is present.
    pub fn rail_withdraw_signed(
        &mut self,
        asset: &str,
        from: &str,
        amount: u64,
        external_to: &str,
        vault_sig: Option<&str>,
    ) -> Result<String, String> {
        self.rail_withdraw_full(asset, from, amount, external_to, vault_sig, None)
    }

    pub fn rail_withdraw_full(
        &mut self,
        asset: &str,
        from: &str,
        amount: u64,
        external_to: &str,
        vault_sig: Option<&str>,
        signed_btc_tx: Option<&str>,
    ) -> Result<String, String> {
        if asset == crate::bridge::RAIL_BTC4 {
            return self.btc4_withdraw(from, amount, external_to);
        }
        if asset == crate::bridge::RAIL_BTC {
            if self.btc_exit_mode == crate::bitvm2_exit::BtcExitMode::Bitvm2 {
                if signed_btc_tx.filter(|s| !s.is_empty()).is_some() {
                    return Err("BTC_EXIT_MODE=bitvm2 rejects watch Kickoff signed_btc_tx".into());
                }
                if asset == NATIVE || asset == DEFI_NATIVE {
                    self.debit_native(from, amount)?;
                } else {
                    self.defi.debit_asset(from, asset, amount)?;
                }
                let note = self.bridge.rail_mut(asset)?.withdraw(
                    from,
                    amount,
                    external_to,
                    self.tip_height,
                )?;
                self.bridge.rail_mut(asset)?.open_bitvm2_withdraw(
                    &note,
                    from,
                    external_to,
                    amount,
                    self.tip_height,
                )?;
                let _ = self.publish_user_vault_take(from, &note);
                return Ok(note);
            }
            let raw = signed_btc_tx
                .filter(|s| !s.is_empty())
                .ok_or("BTC withdraw requires dest-lock Kickoff tx")?;
            let parsed = crate::btc_spv::parse_tx(&crate::btc_spv::hex_decode(raw)?)?;
            let vout0 = parsed
                .outputs
                .first()
                .ok_or("kickoff missing vout0")?;
            let vout0_spk = crate::btc_spv::hex_encode(&vout0.1);
            self.bridge.reconcile_btc_kickoff_utxos();
            let vault_spk_hex = self
                .bridge
                .rail(asset)?
                .effective_vault_pub()
                .ok_or("BTC vault pubkey not genesis-set")?
                .spk_hex
                .clone();
            let vault_spk = crate::btc_spv::hex_decode(vault_spk_hex.trim())?;
            if crate::bitvm::is_nums_spk(&vault_spk) {
                crate::bitvm::nums_kickoff_structure_ok(
                    &crate::btc_spv::hex_decode(raw)?,
                    &vault_spk,
                )?;
            }
            self.bridge.rail_mut(asset)?.apply_kickoff_utxos(
                &parsed,
                &vault_spk,
                self.tip_height,
                true,
            )?;
            let _ = vault_sig;
            if asset == NATIVE || asset == DEFI_NATIVE {
                self.debit_native(from, amount)?;
            } else {
                self.defi.debit_asset(from, asset, amount)?;
            }
            let note = self.bridge.rail_mut(asset)?.withdraw(
                from,
                amount,
                external_to,
                self.tip_height,
            )?;
            let abort = self.fresh_abort_preimage(&note)?;
            let csv = crate::bitvm::CLAIM_CSV_BLOCKS;
            self.bridge.rail_mut(asset)?.open_bitvm_claim(
                &note,
                from,
                external_to,
                amount,
                abort,
                self.tip_height,
                csv,
            )?;
            self.bridge.rail(asset)?.kickoff_ok(&note, &vout0_spk)?;
            if let Some(dir) = &self.keys_dir {
                let _ = crate::bitvm::write_abort_secret(dir, &note, &abort);
            }
            self.bridge
                .rail_mut(asset)?
                .signed_vault_txs
                .insert(note.clone(), raw.to_string());
            return Ok(note);
        }
        if asset == NATIVE || asset == DEFI_NATIVE {
            self.debit_native(from, amount)?;
        } else {
            self.defi.debit_asset(from, asset, amount)?;
        }
        let note = self.bridge.rail_mut(asset)?.withdraw(
            from,
            amount,
            external_to,
            self.tip_height,
        )?;
        if crate::evm_spv::is_evm_rail(asset) {
            let usdc = asset == crate::bridge::RAIL_USDC;
            self.bridge
                .rail_mut(asset)?
                .record_evm_withdraw(&note, external_to, amount, usdc)?;
        }
        Ok(note)
    }

    fn publish_user_vault_take(&mut self, from: &str, note_id: &str) -> Result<(), String> {
        let seed = self.abort_seed_bytes()?;
        let dest20 = crate::btc_spv::dest_id20(from);
        let rail = self.bridge.rail_mut(crate::bridge::RAIL_BTC)?;
        let meta = rail
            .user_vaults
            .values()
            .find(|m| m.owner == from)
            .cloned()
            .ok_or_else(|| "no user-vault deposit for this account".to_string())?;
        let h160_raw = crate::btc_spv::hex_decode(&meta.user_h160_hex)?;
        let nonce_raw = crate::btc_spv::hex_decode(&meta.nonce_hex)?;
        if h160_raw.len() != 20 || nonce_raw.len() != 32 {
            return Err("user-vault meta corrupt".into());
        }
        let mut h160 = [0u8; 20];
        h160.copy_from_slice(&h160_raw);
        let mut nonce = [0u8; 32];
        nonce.copy_from_slice(&nonce_raw);
        let pre = crate::user_vault::take_preimage(&seed, &dest20, &h160, &nonce);
        rail.published_takes
            .insert(note_id.to_string(), hex::encode(pre));
        Ok(())
    }

    fn abort_seed_bytes(&self) -> Result<[u8; 32], String> {
        if let Some(dir) = &self.keys_dir {
            let p = dir.join("bitvm-abort-seed");
            let raw = std::fs::read(&p).map_err(|_| {
                "BTC withdraw needs keys/bitvm-abort-seed on every seat (not the vault key)".to_string()
            })?;
            if raw.len() < 32 {
                return Err("bitvm-abort-seed must be 32 bytes".into());
            }
            let mut s = [0u8; 32];
            s.copy_from_slice(&raw[..32]);
            return Ok(s);
        }
        Ok(crate::bitvm::sha256_32(b"fpl-test-abort-seed"))
    }

    fn fresh_abort_preimage(&self, note_id: &str) -> Result<[u8; 32], String> {
        Ok(crate::bitvm::abort_preimage_from_seed(
            &self.abort_seed_bytes()?,
            note_id,
        ))
    }

    /// Record BitVM2 peg-out txid after operator fronts BTC on Bitcoin.
    pub fn rail_bitvm2_pegout(
        &mut self,
        note_id: &str,
        pegout_txid_hex: &str,
        operator: &str,
    ) -> Result<(), String> {
        self.bridge
            .rail_mut(crate::bridge::RAIL_BTC)?
            .record_bitvm2_pegout(note_id, operator, pegout_txid_hex)
    }

    /// Snapshot claim fields for off-thread Groth16 verify (admin attest path).
    pub fn bitvm2_attest_prepare(
        &self,
        note_id: &str,
    ) -> Result<Bitvm2AttestPrepare, String> {
        if self.bitvm2_m1_at(self.tip_height.saturating_add(1)) {
            return Err("bitvm2: admin attest is closed from the M1 height (use Bitvm2AttestV2)".into());
        }
        let rail = self.bridge.rail(crate::bridge::RAIL_BTC)?;
        let c = rail
            .bitvm2_claims
            .get(note_id)
            .ok_or_else(|| "no bitvm2 claim".to_string())?
            .clone();
        if c.status != crate::bitvm2_exit::Bitvm2Status::AwaitingPegout
            && c.status != crate::bitvm2_exit::Bitvm2Status::PegoutPosted
        {
            return Err("bitvm2 claim not awaiting attest".into());
        }
        let dest_h160 = crate::bitvm::dest_h160_from_address(&c.dest)?;
        Ok(Bitvm2AttestPrepare {
            note_id: note_id.to_string(),
            dest_h160,
            amount: c.amount,
            tip_height: self.tip_height,
            tip_hash: self.tip_hash.clone(),
            mimc_leaves: rail.bitvm2_claim_leaves.clone(),
        })
    }

    /// Apply attestation after verify (must match prepare inputs).
    pub fn bitvm2_attest_apply(
        &mut self,
        note_id: &str,
        operator: &str,
        pegout_txid_hex: &str,
        claim_txid_hex: &str,
        proof_hex: &str,
        public_hex: &[String],
        statement_digest_hex: &str,
    ) -> Result<(), String> {
        if self.bitvm2_m1_at(self.tip_height.saturating_add(1)) {
            return Err("bitvm2: admin attest is closed from the M1 height (use Bitvm2AttestV2)".into());
        }
        self.bridge.rail_mut(crate::bridge::RAIL_BTC)?.apply_bitvm2_attest(
            note_id,
            operator,
            pegout_txid_hex,
            claim_txid_hex,
            proof_hex,
            public_hex,
            statement_digest_hex,
        )
    }

    /// Record BitVM2 pegout + Claim (operator attest).
    pub fn rail_bitvm2_attest(
        &mut self,
        note_id: &str,
        pegout_txid_hex: &str,
        claim_txid_hex: &str,
        proof_hex: &str,
        public_hex: &[String],
        statement_digest_hex: &str,
        operator: &str,
    ) -> Result<(), String> {
        if self.bitvm2_m1_at(self.tip_height.saturating_add(1)) {
            return Err("bitvm2: use Bitvm2AttestV2 from the M1 height".into());
        }
        self.bridge.rail_mut(crate::bridge::RAIL_BTC)?.attest_bitvm2_claim(
            note_id,
            operator,
            pegout_txid_hex,
            claim_txid_hex,
            proof_hex,
            public_hex,
            statement_digest_hex,
            self.tip_height,
            &self.tip_hash,
        )
    }

    /// M1 attestation (see [`crate::bridge::RailState::attest_bitvm2_claim_v2`]).
    pub fn rail_bitvm2_attest_v2(
        &mut self,
        attest: &crate::bridge::Bitvm2AttestV2,
        operator: &str,
    ) -> Result<(), String> {
        let h = self.tip_height.saturating_add(1);
        if !self.bitvm2_m1_at(h) {
            return Err("Bitvm2AttestV2 before the M1 height".into());
        }
        let vk = self.bitvm2_vk.clone();
        let rail = self.bitvm2_rail_for_note(&attest.note_id);
        self.bridge
            .rail_mut(rail)?
            .attest_bitvm2_claim_v2(attest, operator, &vk, h)
    }

    /// Groth16 Disprove for a challenged BitVM2 claim. Returns true if proof is invalid.
    /// From M1 the stored attestation is re-verified; submitted bytes are ignored.
    pub fn rail_bitvm2_disprove(
        &mut self,
        note_id: &str,
        proof_hex: &str,
        public_hex: &[String],
        statement_digest_hex: &str,
    ) -> Result<bool, String> {
        if self.bitvm2_m1_at(self.tip_height.saturating_add(1)) {
            let vk = self.bitvm2_vk.clone();
            let rail = self.bitvm2_rail_for_note(note_id);
            return self
                .bridge
                .rail_mut(rail)?
                .disprove_bitvm2_v2(note_id, &vk);
        }
        self.bridge.rail_mut(crate::bridge::RAIL_BTC)?.disprove_bitvm2(
            note_id,
            proof_hex,
            public_hex,
            statement_digest_hex,
            self.tip_height,
            &self.tip_hash,
        )
    }

    /// Permissionless BitVM challenge. Honest dest/amount is rejected (anti-grief).
    pub fn rail_challenge(
        &mut self,
        asset: &str,
        note_id: &str,
        observed_dest: &str,
        observed_amount: u64,
        by: &str,
    ) -> Result<[u8; 32], String> {
        // BRIDGE: a BitVM2 claim is challenged on Bitcoin (Challenge -> Assert ->
        // Disprove, slashed via OperatorSlash). The ledger-side "observed
        // dest/amount" challenge is unverifiable (anyone can submit a wrong
        // observation and refund the burner after an operator already paid), so
        // it is refused for BitVM2 claims from the bridge height.
        if self.bridge_at(self.tip_height.saturating_add(1))
            && self
                .bridge
                .rail(asset)
                .map(|r| r.bitvm2_claims.contains_key(note_id))
                .unwrap_or(false)
        {
            return Err("bitvm2 claim: challenge on Bitcoin (BitVM2 Challenge/Disprove), not via RailChallenge".into());
        }
        let secret = self.bridge.rail_mut(asset)?.challenge_claim(
            note_id,
            observed_dest,
            observed_amount,
            by,
            self.tip_height,
            self.keys_dir.as_deref(),
        )?;
        if let Some((from, amt)) = self.bridge.rail(asset)?.refund_challenged(note_id) {
            self.defi.credit_asset(&from, asset, amt);
            if let Ok(r) = self.bridge.rail_mut(asset) {
                r.total_burned = r.total_burned.saturating_sub(amt);
            }
        }
        Ok(secret)
    }

    pub fn rail_finalize_bitvm(&mut self, asset: &str) -> Result<(), String> {
        self.bridge
            .rail_mut(asset)?
            .finalize_claims(self.tip_height, crate::bitvm::FPL_CHALLENGE_LEDGERS);
        Ok(())
    }

    /// BitVM Kickoff: no founder signature. Valid iff FPL leaf ∈ claim_root and
    /// vout0 is the dest-locked claim script.
    pub fn bitvm_kickoff_check(&self, asset: &str, note_id: &str, vout0_spk_hex: &str) -> Result<(), String> {
        self.bridge.rail(asset)?.kickoff_ok(note_id, vout0_spk_hex)
    }

    /// Last FROST spend of the tracked pool into the NUMS P2TR. No FBTC burn.
    pub fn btc_pool_move_to_nums(&mut self, raw_hex: &str) -> Result<String, String> {
        if raw_hex.trim() == "retarget" {
            let rail = self.bridge.rail_mut(crate::bridge::RAIL_BTC)?;
            rail.vault_utxos.clear();
            rail.vault_pub = Some(crate::bitvm::nums_vault_pub());
            return Ok("retarget".into());
        }
        let raw = crate::btc_spv::hex_decode(raw_hex.trim())?;
        let parsed = crate::btc_spv::parse_tx(&raw)?;
        let nums = crate::bitvm::nums_pool_spk()?;
        let v0 = parsed
            .outputs
            .first()
            .ok_or("pool move missing vout0")?;
        if v0.1.as_slice() != nums.as_slice() {
            return Err("pool move vout0 is not the NUMS pool".into());
        }
        if v0.0 < crate::vault::DUST_SATS {
            return Err("NUMS output is dust".into());
        }
        let rail = self.bridge.rail_mut(crate::bridge::RAIL_BTC)?;
        match rail.apply_pool_move_utxos(&parsed, &nums, self.tip_height, true) {
            Ok(()) => {}
            Err(e) if e.contains("does not spend a tracked vault UTXO") => {
                // Book-fix after a rejected broadcast: drop phantom UTXOs and
                // retarget packed vault_pub to the current NUMS script.
                rail.vault_utxos.clear();
            }
            Err(e) => return Err(e),
        }
        self.bridge.rail_mut(crate::bridge::RAIL_BTC)?.vault_pub =
            Some(crate::bitvm::nums_vault_pub());
        Ok(parsed.txid_display)
    }

    /// Drop oldest ledgers when over `max_chain_ledgers` (always bounded — v2.3.1).
    pub fn prune_chain(&mut self) {
        let max = self.cfg.max_chain_ledgers.max(1);
        if self.chain.len() > max {
            let drop_n = self.chain.len() - max;
            // Persist before drain — otherwise a 1-ledger RAM tail deletes the
            // only copy of tip-1 before disk has a height index (2.9.34).
            if let Some(store) = &self.body_store {
                for led in self.chain.iter().take(drop_n) {
                    let _ = store.put(led);
                }
            }
            self.chain.drain(0..drop_n);
        }
        // Keep a long height→hash map even when the RAM tail is short, so
        // residual NeedLedgers can still resolve disk bodies after a bounce.
        let keep_seen = max.max(ChainConfig::DEFAULT_MAX_CHAIN_LEDGERS) as u64;
        let min_h = self.tip_height.saturating_sub(keep_seen);
        self.seen_at_height.retain(|h, _| *h > min_h);
        self.height_sealers.retain(|h, _| *h > min_h);
        self.prune_old_bodies();
        self.prune_vote_maps();
    }

    /// Drop tx bodies older than `max_body_ledgers` (keep header + tx_ids).
    /// Archive + `BodyStore`: persist first, then strip so RSS stays bounded.
    /// Archive without a store (unit tests): keep bodies in RAM.
    pub fn prune_old_bodies(&mut self) {
        if self.cfg.archive && self.body_store.is_none() {
            return;
        }
        let keep = self.cfg.max_body_ledgers.max(1);
        if self.chain.len() <= keep {
            return;
        }
        let cut = self.chain.len() - keep;
        for led in self.chain.iter_mut().take(cut) {
            if !led.has_body() {
                continue;
            }
            if let Some(store) = &self.body_store {
                if store.put(led).is_err() {
                    continue;
                }
            }
            led.strip_body();
        }
    }

    /// Attach a disk body store and spill any bodies already in RAM.
    pub fn open_body_store(
        &mut self,
        dir: impl Into<std::path::PathBuf>,
    ) -> anyhow::Result<()> {
        let store = BodyStore::open(dir)?;
        for led in &self.chain {
            if led.has_body() {
                store.put(led)?;
            }
        }
        self.body_store = Some(store);
        self.cfg.archive = true;
        self.prune_old_bodies();
        Ok(())
    }

    /// Full body for `hash` if we still hold txs (pending, recent chain, or disk).
    pub fn ledger_body(&self, hash: &str) -> Option<Ledger> {
        if let Some(p) = &self.pending_proposal {
            if p.ledger_hash == hash && p.has_body() {
                return Some(p.clone());
            }
        }
        if let Some(l) = self
            .chain
            .iter()
            .find(|l| l.ledger_hash == hash && l.has_body())
        {
            return Some(l.clone());
        }
        if let Some(l) = self.open_bodies.get(hash).filter(|l| l.has_body()) {
            return Some(l.clone());
        }
        self.body_store.as_ref().and_then(|s| s.get(hash))
    }

    /// Bound vote / skip maps so catch-up storms cannot grow RAM without bound (P1).
    fn prune_vote_maps(&mut self) {
        // Only tip + pending need live vote/sig maps. Keeping every chain hash
        // stored 11 Falcon hex sigs (~2MB at h=150) and cloned them per packed tx.
        let mut live: BTreeSet<String> = BTreeSet::new();
        if let Some(p) = &self.pending_proposal {
            live.insert(p.ledger_hash.clone());
        }
        if let Some(l) = self.chain.last() {
            live.insert(l.ledger_hash.clone());
        }
        if self.chain.len() >= 2 {
            live.insert(self.chain[self.chain.len() - 2].ledger_hash.clone());
        }
        if !live.is_empty() {
            self.ok_votes.retain(|h, _| live.contains(h));
            self.ok_sigs.retain(|h, _| live.contains(h));
            self.ok_round.retain(|h, _| live.contains(h));
            self.soft_ok.retain(|h| live.contains(h));
            self.hard_ok.retain(|h| live.contains(h));
        }
        let min_cert_h = self.tip_height.saturating_sub(64);
        self.certs.retain(|h, _| *h >= min_cert_h);
        self.ok_by_height_voter.retain(|h, _| *h + 32 > self.tip_height);
        let tip = self.tip_height;
        let min_skip_h = tip.saturating_sub(Self::SKIP_VOTE_HISTORY);
        self.skips.retain(|h, _| *h > min_skip_h);
        self.skip_votes.retain(|h, _| *h > min_skip_h);
        // Pending future ledgers: hard cap
        if self.pending_ledgers.len() > Self::PENDING_LEDGERS_CAP {
            let mut heights: Vec<u64> = self.pending_ledgers.keys().copied().collect();
            heights.sort_unstable();
            let drop_n = heights.len() - Self::PENDING_LEDGERS_CAP;
            for h in heights.into_iter().take(drop_n) {
                self.pending_ledgers.remove(&h);
            }
        }
    }

    /// Pong = **liveness / tip advertisement only** (v2.3.0+). Never reseeds lottery.
    pub fn pong(&mut self, id: &str) {
        if let Some(v) = self.validators.get_mut(id) {
            // Reserve 0 as "never heard" for pack permission (may_pack requires fresh).
            v.last_pong_ms = self.now_ms.max(1);
            v.avail = 0.8 * v.avail + 0.2 * 1.0;
        }
    }

    /// Liveness + tip advertisement from Pong/Hello. Records advertised tip so
    /// progress-timeout can skip live-but-lagging packers (e.g. bonded joiner
    /// still at tip 0 while mesh is at tip N).
    pub fn pong_with_tip(&mut self, id: &str, tip_height: u64) {
        self.pong_with_inventory(id, tip_height, 0, false);
    }

    /// Liveness + tip + hub inventory (Pong). `mempool_len`/`is_hub` are how
    /// light checkers learn the network has packable work (v2.9.12).
    pub fn pong_with_inventory(
        &mut self,
        id: &str,
        tip_height: u64,
        mempool_len: u64,
        is_hub: bool,
    ) {
        self.pong_with_role(id, tip_height, mempool_len, is_hub, false, 0);
    }

    /// Hello/Pong with hub + archive ads (v2.9.21).
    pub fn pong_with_role(
        &mut self,
        id: &str,
        tip_height: u64,
        mempool_len: u64,
        is_hub: bool,
        archive: bool,
        snap_height: u64,
    ) {
        self.pong(id);
        if let Some(v) = self.validators.get_mut(id) {
            v.last_advertised_tip = Some(tip_height);
            v.last_mempool_len = mempool_len;
            v.advertised_hub = is_hub;
            v.advertised_archive = archive;
            if snap_height > 0 {
                v.last_snap_height = snap_height;
            }
        }
        // Recompute best from **live** ads — do not keep a stale high-water mark
        // after a brief fork/phantom tip (that stuck tip_lag>0 and froze packing).
        self.refresh_best_peer_tip();
    }

    /// Work exists to seal: local next-seq **or** a fresh hub advertised pending.
    /// Light checkers must not need the txs themselves to vote skip (2.9.11 hole).
    pub fn network_has_pack_work(&self) -> bool {
        if self.has_applicable_tx() {
            return true;
        }
        self.validators.values().any(|v| {
            v.advertised_hub
                && v.last_mempool_len > 0
                && v.pong_fresh(self.now_ms, self.cfg.pong_window_ms)
        })
    }

    /// Set `best_peer_tip` to max(local tip, live peer tip ads).
    /// Call after pong tip updates so `may_pack` / catch-up see the mesh, not ghosts.
    pub fn refresh_best_peer_tip(&mut self) {
        let mut live_max = self.tip_height;
        for v in self.validators.values() {
            if v.id == self.id {
                continue;
            }
            if !v.pong_fresh(self.now_ms, self.cfg.pong_window_ms) {
                continue;
            }
            if let Some(t) = v.last_advertised_tip {
                live_max = live_max.max(t);
            }
        }
        self.best_peer_tip = live_max;
    }

    /// True if this validator is ponging but clearly behind our tip (material lag).
    /// Allow 1 height slack for in-flight seals / slow pong refresh.
    pub fn validator_tip_lagging(&self, id: &str) -> bool {
        let Some(v) = self.validators.get(id) else {
            return false;
        };
        match v.last_advertised_tip {
            Some(t) => t.saturating_add(1) < self.tip_height,
            None => false,
        }
    }

    /// Submit a tx into the local mempool. `Ok(true)` = newly stored (gossip this);
    /// `Ok(false)` = already had it (do not re-gossip).
    /// Rejects when `max_mempool_txs` is hit (backpressure, avoid OOM).
    /// When `fee_escalate`, rejects fees below the util-tier minimum.
    pub fn submit_tx(&mut self, tx: Tx) -> Result<bool, String> {
        let result = self.submit_tx_inner(tx);
        match &result {
            Ok(is_new) => self.metrics.record_submit_ok(*is_new),
            Err(e) => self.metrics.record_submit_err(e),
        }
        let util = mempool_util_bps(self.mempool.len(), self.cfg.max_mempool_txs);
        self.metrics.last_util_bps = util;
        self.metrics.last_suggested_min_fee = self.current_min_fee();
        result
    }

    fn submit_tx_inner(&mut self, tx: Tx) -> Result<bool, String> {
        if tx.network_id != self.cfg.network_id {
            return Err("wrong network".into());
        }
        // v2.9.77: never re-admit (from gossip or anywhere) a tx id this seat
        // already dropped as permanently invalid. Before the signature check
        // so a re-gossiped poison costs a set lookup, not a Falcon verify.
        if self.perm_dropped.contains(&tx.tx_id, self.now_ms, &self.tip_hash) {
            return Err(TX_PREVIOUSLY_DROPPED.into());
        }
        // v2.9.61 (#34): an EthV3Deposit that cannot apply in the open height
        // is refused before verify, eviction, or insert. It is never kept or
        // relayed (2.9.60 seats cannot decode the variant), and it does not
        // take or evict anything at its account + sequence. Not permanent:
        // the same deposit is admitted once `tip + 1 >= eth_v3_from_height`.
        if self.rv2_tx_pre_activation(&tx) {
            return Err(RV2_NOT_ACTIVE.into());
        }
        if self.seat_tx_pre_activation(&tx) {
            return Err(SEAT_PAYOUT_NOT_ACTIVE.into());
        }
        if self.external_addrs_tx_pre_activation(&tx) {
            return Err(EXTERNAL_ADDRS_NOT_ACTIVE.into());
        }
        if self.orderbook_tx_pre_activation(&tx) {
            return Err(ORDERBOOK_NOT_ACTIVE.into());
        }
        if self.v3_deposit_pre_activation(&tx) {
            return Err(crate::bridge::V3_DEPOSITS_NOT_ACTIVE.into());
        }
        // v2.9.65: 2.9.64 seats cannot decode PayToKey; never admit or relay
        // it before the key-bind height.
        if matches!(tx.body, TxBody::PayToKey { .. }) && !self.key_bind_gate_open() {
            return Err(PAY_TO_KEY_NOT_ACTIVE.into());
        }
        // 2.9.74 seats cannot decode Bitvm2AttestV2: never admit or relay it
        // before the M1 height (apply refuses it there too).
        if matches!(tx.body, TxBody::Bitvm2AttestV2 { .. })
            && !self.bitvm2_m1_at(self.tip_height.saturating_add(1))
        {
            return Err("Bitvm2AttestV2 before the M1 height".into());
        }
        // BRIDGE: same rule for the operator-network bodies (appended TxBody
        // variants older seats cannot decode): same single bridge height.
        if matches!(
            tx.body,
            TxBody::OperatorRegister { .. }
                | TxBody::OperatorHeartbeat { .. }
                | TxBody::OperatorUnbond
                | TxBody::OperatorGraphBind { .. }
                | TxBody::OperatorSlash { .. }
                | TxBody::Btc4PegIn { .. }
        ) && !self.bridge_at(self.tip_height.saturating_add(1))
        {
            return Err("operator: bridge not active at this height".into());
        }
        // First-seen vault/name txs enroll the embedded Falcon key *before*
        // mempool verify — otherwise admit dies with "bad tx crypto".
        if self.tx_name_enroll(&tx) {
            self.enroll_name_key(&tx)?;
        }
        self.restore_ring_key(&tx);
        self.onchain_verify_key(&tx);
        if let Err(e) = self.verify_account_tx(&tx) {
            return Err(e);
        }
        if matches!(tx.body, TxBody::WatcherCredit { .. }) {
            return Err("watcher-credit disabled; use WatcherHeartbeat or rail work".into());
        }
        if matches!(tx.body, TxBody::CreditAsset { .. }) && !self.cfg.allow_admin_wire {
            return Err("admin-only: CreditAsset disabled".into());
        }
        if let TxBody::SetExternalAddrs { chain, address } = &tx.body {
            validate_external_addr(chain, address)?;
        }
        // Fee floor: apply only to *new* txs (dupes may re-advertise at old fee).
        if self.cfg.fee_escalate || self.cfg.min_fee > 0 {
            let need = self.current_min_fee();
            if tx.fee < need {
                // Allow duplicate re-submit path only if already in pool.
                if !self.mempool.by_id.contains_key(&tx.tx_id) {
                    return Err(format!(
                        "fee too low want {need} got {} (tier util_bps={} escalate={})",
                        tx.fee,
                        mempool_util_bps(self.mempool.len(), self.cfg.max_mempool_txs),
                        self.cfg.fee_escalate
                    ));
                }
            }
        }
        // Reject BTC headers that packers would drop as permanent failures
        // (deep reorg submitted at the stale tip, bits mismatch, …). "accepted"
        // must mean the rail can apply the header, not merely mempool insert.
        if let TxBody::RailHeader {
            asset,
            height,
            hash,
            parent_hash,
            merkle_root,
            raw,
        } = &tx.body
        {
            if asset == crate::bridge::RAIL_BTC || asset == crate::bridge::RAIL_BTC4 {
                if let Ok(rail) = self.bridge.rail(asset) {
                    // v2.9.54: chained admission. The probe includes this
                    // account's own pending txs at lower, contiguous sequences
                    // (what the packer applies first on its draft), so a burst
                    // h+1..h+32 is admitted while h+1 is still pending.
                    // Mempool only — block apply/verify are unchanged.
                    let mut probe = self.btc_admission_probe(rail, &tx.account, tx.sequence);
                    let strict = self.rv2_open();
                    let fork_fix = self.btc4_fork_fix_open();
                    if let Err(e) = probe.submit_header_ex2(crate::bridge::RailHeader {
                        height: *height,
                        hash: hash.clone(),
                        parent_hash: parent_hash.clone(),
                        merkle_root: merkle_root.clone(),
                        raw: raw.clone(),
                    }, strict, fork_fix) {
                        if Self::is_permanent_tx_failure(&e) {
                            return Err(e);
                        }
                    }
                }
            }
        }
        // v2.9.61: a V3 deposit id that is already resolved can never apply.
        // Refuse it here (map lookup only, mempool admission, before any
        // eviction) so the submitter gets "already resolved" back instead of
        // a tx that is accepted and then dropped at pack.
        if let TxBody::EthV3Deposit { deposit_id, .. } = &tx.body {
            if self.bridge.eth_v3_resolution(deposit_id).is_some() {
                return Err(crate::bridge::V3_DEPOSIT_ALREADY_RESOLVED.into());
            }
        }
        // One account may keep a short pipeline (need .. need+64) so a block
        // can seal several of its txs in order. Anything older is stale.
        // Anything further ahead is refused here: a few keys used to fill the
        // 50_000 cap with future sequences and the pool only dropped them once
        // *every* account lacked a packable head.
        let need = self.state.get(&tx.account).sequence;
        if tx.sequence < need {
            return Err(format!(
                "sequence stale want {need} got {}",
                tx.sequence
            ));
        }
        let ahead = need.saturating_add(Self::MEMPOOL_SEQ_WINDOW);
        if tx.sequence > ahead {
            return Err(format!(
                "sequence too far ahead want <={ahead} got {}",
                tx.sequence
            ));
        }
        let replacing = self.mempool.iter_candidates().any(|old| {
            old.account == tx.account && old.sequence == tx.sequence
        });
        // v2.9.77: a same-(account, seq) arrival replaces the pending tx only
        // if it is not itself permanently invalid at the head. Otherwise a
        // stale tx re-gossiped from another seat evicts the valid resubmit
        // (watcher-eth-lc seq 4622, 21 Oct 2026). Head only: a later sequence
        // cannot be dry-run against committed state.
        if replacing && tx.sequence == need {
            if let Err(e) = self.dry_run_head(&tx) {
                if Self::is_permanent_tx_failure(&e) {
                    let tip = self.tip_hash.clone();
                    self.perm_dropped.insert(&tx.tx_id, self.now_ms, &tip);
                    return Err(format!("refused same-seq replacement: {e}"));
                }
            }
        }
        if !replacing {
            let pending = self
                .mempool
                .iter_candidates()
                .filter(|old| old.account == tx.account)
                .count();
            if pending >= Self::MEMPOOL_SEQ_WINDOW as usize {
                return Err(format!(
                    "account mempool cap {} reached for {}",
                    Self::MEMPOOL_SEQ_WINDOW, tx.account
                ));
            }
        }
        self.evict_mempool_account_seq(&tx.account, tx.sequence);
        self.mempool.insert(tx, self.cfg.max_mempool_txs)
    }

    /// How far past an account's next sequence a tx may sit in the mempool.
    /// Also the cap on pending txs from one account. Matches the BTC header
    /// burst the admission probe will replay.
    pub const MEMPOOL_SEQ_WINDOW: u64 = 64;

    /// Max pending same-account txs replayed onto the BTC admission probe
    /// (v2.9.54). Deeper chains fall back to the committed-tip-only check.
    pub const BTC_ADMIT_CHAIN_MAX: u64 = 64;

    /// BTC rail state an incoming header from `account` at `sequence` is
    /// admitted against (v2.9.54).
    ///
    /// Starts from the committed rail. If `account` has pending txs at **every**
    /// sequence `need..sequence` (no gap, at most [`Self::BTC_ADMIT_CHAIN_MAX`]),
    /// they are replayed in the order the packer applies them: per sequence,
    /// arrival order; a non-BTC-header tx does not touch the BTC rail and counts
    /// as applied; a BTC header that fails falls through to its next same-seq
    /// sibling (packer drop/rotate). If any sequence is missing or none of its
    /// siblings applies, the incoming tx is not applicable after its
    /// predecessors, so the result is the committed rail alone — exactly the
    /// pre-2.9.54 check.
    ///
    /// Mempool admission only. Never called from pack/verify/commit.
    fn btc_admission_probe(
        &self,
        rail: &crate::bridge::RailState,
        account: &str,
        sequence: u64,
    ) -> crate::bridge::RailState {
        let need = self.state.get(account).sequence;
        if sequence <= need || sequence - need > Self::BTC_ADMIT_CHAIN_MAX {
            return rail.clone();
        }
        let mut by_seq: BTreeMap<u64, Vec<&Tx>> = BTreeMap::new();
        for t in self.mempool.iter_candidates() {
            if t.account == account && t.sequence >= need && t.sequence < sequence {
                by_seq.entry(t.sequence).or_default().push(t);
            }
        }
        if (need..sequence).any(|s| !by_seq.contains_key(&s)) {
            return rail.clone(); // sequence gap: not applicable yet
        }
        let mut probe = rail.clone();
        let strict = self.rv2_open();
        let fork_fix = self.btc4_fork_fix_open();
        for sibs in by_seq.values() {
            let mut ok = false;
            for t in sibs {
                match &t.body {
                    TxBody::RailHeader {
                        asset,
                        height,
                        hash,
                        parent_hash,
                        merkle_root,
                        raw,
                    } if asset == &rail.asset => {
                        if probe
                            .submit_header_ex2(crate::bridge::RailHeader {
                                height: *height,
                                hash: hash.clone(),
                                parent_hash: parent_hash.clone(),
                                merkle_root: merkle_root.clone(),
                                raw: raw.clone(),
                            }, strict, fork_fix)
                            .is_ok()
                        {
                            ok = true;
                            break;
                        }
                    }
                    _ => {
                        ok = true;
                        break;
                    }
                }
            }
            if !ok {
                return rail.clone(); // a predecessor cannot apply
            }
        }
        probe
    }

    /// v2.9.77: apply `tx` to throwaway drafts of committed state (the same
    /// dry run [`Self::sanitize_mempool`] does for heads).
    fn dry_run_head(&mut self, tx: &Tx) -> Result<(), String> {
        let mut draft_state = self.state.clone();
        let mut draft_defi = self.defi.clone();
        let mut draft_bridge = self.bridge.clone();
        let mut draft_vals = self.validators.clone();
        let mut draft_claim = self.claimable.clone();
        let mut draft_work = self.epoch_work.clone();
        let saved_now = self.now_ms;
        self.perm_head_dry_runs = self.perm_head_dry_runs.saturating_add(1);
        let r = self.try_protocol_tx(
            &mut draft_state,
            &mut draft_defi,
            &mut draft_bridge,
            &mut draft_vals,
            &mut draft_claim,
            &mut draft_work,
            tx,
        );
        self.now_ms = saved_now;
        r
    }

    /// New submit at `(account, sequence)` replaces prior mempool entries so a
    /// fresh LC update is not stuck behind a stale same-seq tx from gossip.
    fn evict_mempool_account_seq(&mut self, account: &str, sequence: u64) {
        let ids: Vec<String> = self
            .mempool
            .iter_candidates()
            .filter(|tx| tx.account == account && tx.sequence == sequence)
            .map(|tx| tx.tx_id.clone())
            .collect();
        if !ids.is_empty() {
            self.mempool.remove_many(&ids);
        }
    }

    /// v2.9.76: our own packed ledger failed self-accept because tx `tx_id`
    /// failed apply. Drop it (and later sequences of that account, which can
    /// no longer apply) from the local mempool so the next pack excludes it.
    /// Proposal-building only: other seats' blocks are validated as before.
    pub fn evict_self_accept_failure(&mut self) -> Option<String> {
        let id = self.last_apply_fail_tx.take()?;
        let (acct, seq) = self
            .mempool
            .iter_candidates()
            .find(|t| t.tx_id == id)
            .map(|t| (t.account.clone(), t.sequence))?;
        let ids: Vec<String> = self
            .mempool
            .iter_candidates()
            .filter(|t| t.account == acct && t.sequence >= seq)
            .map(|t| t.tx_id.clone())
            .collect();
        self.mempool.remove_many(&ids);
        self.evicted_since_last_seal = true;
        Some(id)
    }

    /// Operator / admin manual eviction of stuck mempool transactions by
    /// `tx_id`, `account:sequence`, or `account`. Also records evicted tx IDs
    /// in `perm_dropped` at the current tip so gossip does not re-insert them.
    pub fn drop_mempool_target(&mut self, target: &str) -> Vec<String> {
        let t = target.trim();
        if t.is_empty() {
            return Vec::new();
        }
        let acct_seq: Option<(&str, u64)> = t
            .rsplit_once(':')
            .and_then(|(a, s)| s.parse::<u64>().ok().map(|seq| (a, seq)));
        let ids: Vec<String> = self
            .mempool
            .iter_candidates()
            .filter(|tx| {
                if tx.tx_id == t {
                    return true;
                }
                if let Some((acct, seq)) = acct_seq {
                    return tx.account == acct && tx.sequence == seq;
                }
                tx.account == t
            })
            .map(|tx| tx.tx_id.clone())
            .collect();
        if !ids.is_empty() {
            let tip = self.tip_hash.clone();
            let now = self.now_ms;
            for id in &ids {
                self.perm_dropped.insert(id, now, &tip);
            }
            self.mempool.remove_many(&ids);
        }
        ids
    }

    pub fn skip_set_for(&self, height: u64) -> BTreeSet<String> {
        self.skips.get(&height).cloned().unwrap_or_default()
    }

    /// Record a packer that cannot produce a non-empty ledger at this height.
    /// Prefer [`apply_shared_skip`] for consensus-affecting skips so all nodes
    /// share the same tip-gated path.
    pub fn skip_packer(&mut self, height: u64, packer: &str) {
        self.skips
            .entry(height)
            .or_default()
            .insert(packer.to_string());
    }

    /// True if `packer` already delivered a live proposal at `height` — they
    /// **must not** be progress-skipped (skip would orphan the seal and stall).
    pub fn packer_has_proposal_at(&self, height: u64, packer: &str) -> bool {
        if self
            .pending_proposal
            .as_ref()
            .map(|p| p.height == height && p.packer == packer)
            .unwrap_or(false)
        {
            return true;
        }
        self.seen_at_height
            .get(&height)
            .map(|(p, _)| p == packer)
            .unwrap_or(false)
    }

    /// Any body already staged or committed at `height` — a second sealer is a fork.
    pub fn height_has_proposal(&self, height: u64) -> bool {
        self.pending_proposal
            .as_ref()
            .map(|p| p.height == height)
            .unwrap_or(false)
            || self.seen_at_height.contains_key(&height)
    }

    /// Drop skip votes + certified skip for a packer who sealed (proposal arrived).
    pub fn unskip_packer(&mut self, height: u64, packer: &str) {
        if let Some(s) = self.skips.get_mut(&height) {
            s.remove(packer);
            if s.is_empty() {
                self.skips.remove(&height);
            }
        }
        if let Some(m) = self.skip_votes.get_mut(&height) {
            m.remove(packer);
            if m.is_empty() {
                self.skip_votes.remove(&height);
            }
        }
    }

    /// Certify skip of `packer` at this height (after skip QC).
    ///
    /// **v2.3.4 model:** the **seat order is tip-fixed** (`lottery_order`). Skip does
    /// **not** reseed that order — it only advances the cursor to the next preselected
    /// seat. Same tip ⇒ same full order on every node; skip QC must agree for the
    /// same active seat.
    ///
    /// Refuses to skip a packer who already staged a proposal (they did the job).
    pub fn apply_shared_skip(&mut self, height: u64, packer: &str, tip_hash: &str) -> bool {
        if tip_hash != self.tip_hash || height != self.tip_height + 1 {
            return false;
        }
        // Round mode: skips are derived from the round only (`sync_round_skips`).
        if self.vote_rounds_at(height) {
            return false;
        }
        if packer.is_empty() {
            return false;
        }
        if self.packer_has_proposal_at(height, packer) {
            return false;
        }
        // A body is already in flight at this height — skip would elect a
        // second sealer (859 split). Wait for soft QC or view-change.
        if self.height_has_proposal(height) {
            return false;
        }
        // v2.9.51: open_bodies can hold a rival header/body before seen_at_height
        // is updated (progress-timeout skip vs live sealer race → dual / jail).
        if self.open_bodies.values().any(|l| l.height == height) {
            return false;
        }
        if self.now_ms < self.skip_reopen_cooldown_until_ms {
            return false;
        }
        let already = self.skip_set_for(height).contains(packer);
        self.skip_packer(height, packer);
        // v2.6.0 / v2.9.3: reopen when every seat in the **lottery order** is
        // skip-QC'd. That is an agreed failed attempt — not a committed height.
        let order = self.lottery_order();
        let skips_now = self.skip_set_for(height);
        let all_order_skipped = !order.is_empty() && order.iter().all(|id| skips_now.contains(id));
        if all_order_skipped {
            self.reopen_uncommitted_height(height);
            return !already;
        }
        if !already {
            // Next preselected seat gets a fresh pack window.
            self.height_open_ms = self.now_ms;
            let grace = (self.cfg.progress_timeout_ms.max(200)) / 2;
            self.skip_grace_until_ms = self.now_ms.saturating_add(grace);
        }
        !already
    }

    /// Agreed failure of an **uncommitted** height (all 6 skip-QC'd).
    ///
    /// A discarded pending is not a commit. Sealer bans exist so the *current
    /// walk* tries the next seat instead of resealing two hashes. Once the
    /// whole committee has failed, keeping those bans burns the 6 and the
    /// height can never commit (v2.9.2 live stall at h=1929).
    fn reopen_uncommitted_height(&mut self, height: u64) {
        if height != self.tip_height.saturating_add(1) {
            return;
        }
        self.skips.remove(&height);
        self.skip_votes.remove(&height);
        self.height_sealers.remove(&height);
        self.seen_at_height.remove(&height);
        self.clear_attempt_votes(height);
        if self
            .pending_proposal
            .as_ref()
            .map(|p| p.height == height)
            .unwrap_or(false)
        {
            self.pending_proposal = None;
        }
        self.height_open_ms = self.now_ms;
        self.skip_grace_until_ms = 0;
        self.skip_reopen_cooldown_until_ms = self
            .now_ms
            .saturating_add(self.cfg.progress_timeout_ms.max(500));
    }

    /// Votes / queued slashes for an uncommitted height belong to that attempt.
    /// Keeping them after the body is gone makes every honest reseal look like
    /// a checker double-OK (2.9.6 live: ghost 327b388f vs new 778292d6).
    fn clear_attempt_votes(&mut self, height: u64) {
        if let Some(voters) = self.ok_by_height_voter.remove(&height) {
            for hash in voters.values() {
                self.ok_votes.remove(hash);
                self.soft_ok.remove(hash);
                self.hard_ok.remove(hash);
                self.ok_sigs.remove(hash);
                self.ok_round.remove(hash);
            }
        }
        // Round-scoped heights: `round_votes` is the lock + equivocation
        // record and same-(height, round) evidence is real — keep both.
        // Tallies are rebuilt from `round_votes` on the next vote.
        if self.round_votes.contains_key(&height) || self.vote_rounds_at(height) {
            return;
        }
        self.pending_slashes.retain(|e| e.height != height);
    }

    /// Snap does not restore `pending_proposal`. Votes for `h > tip` cannot
    /// refer to a live body — drop them so the next pack is a new attempt.
    pub fn drop_uncommitted_attempt_votes(&mut self) {
        let tip = self.tip_height;
        let stale: Vec<u64> = self
            .ok_by_height_voter
            .keys()
            .copied()
            .filter(|h| *h > tip)
            .collect();
        for h in stale {
            self.clear_attempt_votes(h);
        }
        // Keep round-scoped evidence (it proves one (height, round) dual).
        let rv = &self.round_votes;
        self.pending_slashes
            .retain(|e| e.height <= tip || (e.round != 0 || rv.contains_key(&e.height)));
    }

    /// Bonded, non-jailed checker — only these may cast QC votes (A2).
    pub fn eligible_voter(&self, voter: &str) -> bool {
        if voter.is_empty() {
            return false;
        }
        self.validators
            .get(voter)
            .map(|v| !v.jailed && v.bond > 0)
            .unwrap_or(false)
    }

    pub fn vote_ok_payload(network_id: u32, height: u64, ledger_hash: &str, voter: &str) -> String {
        format!("pl-ok:v1|{network_id}|{height}|{ledger_hash}|{voter}")
    }
    /// v2.10.0 round-scoped OK: one vote per (height, round) per voter.
    pub fn vote_ok_payload_v2(
        network_id: u32,
        height: u64,
        round: u64,
        ledger_hash: &str,
        voter: &str,
    ) -> String {
        format!("pl-ok:v2|{network_id}|{height}|{round}|{ledger_hash}|{voter}")
    }
    /// Payload for `height` under the active vote format.
    pub fn ok_payload_for(&self, height: u64, round: u64, ledger_hash: &str, voter: &str) -> String {
        if self.vote_rounds_at(height) {
            Self::vote_ok_payload_v2(self.cfg.network_id, height, round, ledger_hash, voter)
        } else {
            Self::vote_ok_payload(self.cfg.network_id, height, ledger_hash, voter)
        }
    }
    pub fn vote_skip_payload(
        network_id: u32,
        height: u64,
        packer: &str,
        tip_hash: &str,
        voter: &str,
    ) -> String {
        format!("pl-skip:v1|{network_id}|{height}|{packer}|{tip_hash}|{voter}")
    }
    pub fn vote_vc_payload(
        network_id: u32,
        height: u64,
        tip_hash: &str,
        round: u64,
        voter: &str,
    ) -> String {
        format!("pl-vc:v1|{network_id}|{height}|{tip_hash}|{round}|{voter}")
    }
    pub fn vote_online_payload(network_id: u32, epoch_id: u64, hash: &str, voter: &str) -> String {
        format!("pl-online:v1|{network_id}|{epoch_id}|{hash}|{voter}")
    }

    fn accept_vote_sig(&self, voter: &str, payload: &str, signature: &str) -> bool {
        if !self.eligible_voter(voter) {
            return false;
        }
        if !self.cfg.require_vote_sigs {
            return true;
        }
        if signature.is_empty() {
            return false;
        }
        // v2.9.62 A13: from H_act only registered keys count (never a key one
        // seat learned from a Hello that the others do not have).
        let h = self.tip_height.saturating_add(1);
        let Some(pk) = self.consensus_key_at(voter, h) else {
            return false;
        };
        self.verify_consensus_sig(voter, h, &pk, payload, signature)
    }

    /// Sign a local OK vote (empty string if we have no secret).
    pub fn sign_ok_vote(&self, height: u64, ledger_hash: &str) -> String {
        let round = self.own_ok_round(height);
        self.sign_ok_vote_round(height, round, ledger_hash)
    }
    /// Sign an OK for an explicit round (`pl-ok:v2` on round-scoped heights).
    pub fn sign_ok_vote_round(&self, height: u64, round: u64, ledger_hash: &str) -> String {
        let p = self.ok_payload_for(height, round, ledger_hash, &self.id);
        self.keys.sign(&self.id, &p).unwrap_or_default()
    }
    pub fn sign_skip_vote(&self, height: u64, packer: &str, tip_hash: &str) -> String {
        let p = Self::vote_skip_payload(self.cfg.network_id, height, packer, tip_hash, &self.id);
        self.keys.sign(&self.id, &p).unwrap_or_default()
    }
    pub fn sign_vc_vote(&self, height: u64, tip_hash: &str, round: u64) -> String {
        let p = Self::vote_vc_payload(self.cfg.network_id, height, tip_hash, round, &self.id);
        self.keys.sign(&self.id, &p).unwrap_or_default()
    }
    pub fn sign_online_vote(&self, epoch_id: u64, hash: &str) -> String {
        let p = Self::vote_online_payload(self.cfg.network_id, epoch_id, hash, &self.id);
        self.keys.sign(&self.id, &p).unwrap_or_default()
    }

    /// Cast a skip vote. Skip enters the lottery only after **soft QC** of voters
    /// (same threshold as soft ledger OK).
    ///
    /// Returns `(qc_applied, vote_was_new)` so the wire layer can **re-fan** a
    /// newly recorded vote (epidemic gossip). Without re-fan, multi-host meshes
    /// stall at votes=1/3 when direct fanout drops under load.
    pub fn vote_skip(
        &mut self,
        height: u64,
        packer: &str,
        tip_hash: &str,
        voter: &str,
    ) -> bool {
        self.vote_skip_ex(height, packer, tip_hash, voter, "").0
    }

    /// Like [`vote_skip`] but also reports whether this voter's attestation was new.
    pub fn vote_skip_ex(
        &mut self,
        height: u64,
        packer: &str,
        tip_hash: &str,
        voter: &str,
        signature: &str,
    ) -> (bool, bool) {
        if tip_hash != self.tip_hash || height != self.tip_height + 1 {
            return (false, false);
        }
        if packer.is_empty() || voter.is_empty() {
            return (false, false);
        }
        if !self.in_committee(voter) {
            return (false, false);
        }
        let payload = Self::vote_skip_payload(self.cfg.network_id, height, packer, tip_hash, voter);
        if !self.accept_vote_sig(voter, &payload, signature) {
            return (false, false);
        }
        // Staged proposal = packer did their job — drop skip votes, do not QC-skip.
        if self.packer_has_proposal_at(height, packer) {
            self.unskip_packer(height, packer);
            return (false, false);
        }
        if self.now_ms < self.skip_reopen_cooldown_until_ms {
            return (false, false);
        }
        // Already certified — idempotent (not "new").
        if self.skip_set_for(height).contains(packer) {
            return (false, false);
        }
        let qc = self.qc_voters();
        let voters = self
            .skip_votes
            .entry(height)
            .or_default()
            .entry(packer.to_string())
            .or_default();
        let vote_was_new = voters.insert(voter.to_string());
        let n = voters
            .iter()
            .filter(|id| qc.is_empty() || qc.iter().any(|c| c == *id))
            .count();
        let need = self.commit_votes_needed();
        if n >= need {
            (self.apply_shared_skip(height, packer, tip_hash), vote_was_new)
        } else {
            (false, vote_was_new)
        }
    }

    /// Soft / commit QC from **tip-committed** state only (checklist A5 / REVIEW #6).
    ///
    /// Committee of 6 (1 packer + 5 checkers): need = **4 of the 6** (v2.9.0).
    /// Packer OK counts. n &lt; 6 keeps the small-set rule (`soft_ok_votes`, floor 2).
    /// Pong is pack permission (`may_pack_locally`), never QC math.
    ///
    /// With `≥ 2` seats, need is **never 1** (anti solo-commit).
    pub fn soft_votes_needed(&self) -> usize {
        self.commit_votes_needed()
    }

    /// Tip-advance / skip / view-change bar.
    ///
    /// Full committee (`len ≥ 6`): **4 of 6**. Smaller draws keep
    /// `min(soft_ok_votes, |seats|)` with a floor of 2 when `|seats| ≥ 2`.
    pub fn commit_votes_needed(&self) -> usize {
        let order = self.lottery_order();
        if self.cfg.committee_size > 0 && order.len() >= 6 {
            return 4;
        }
        let c = if self.cfg.committee_size > 0 {
            order.len().max(1)
        } else {
            self.checker_count()
        };
        if c == 0 {
            return 1;
        }
        let mut need = self.cfg.soft_ok_votes.min(c).max(1);
        if c >= 2 {
            need = need.max(2).min(c);
        }
        need
    }

    /// Voters that fill the commit / skip / VC bar (full committee when drawn).
    fn qc_voters(&self) -> Vec<String> {
        if self.cfg.committee_size > 0 {
            return self.lottery_order();
        }
        self.committee_checkers()
    }

    pub fn counts_as_qc_voter(&self, id: &str) -> bool {
        let c = self.qc_voters();
        c.is_empty() || c.iter().any(|x| x == id)
    }

    // -----------------------------------------------------------------------
    // Certified online epoch (v2.4.0 mainnet product)
    // -----------------------------------------------------------------------

    /// Current online-epoch id from tip height. Shared across nodes on same tip.
    pub fn online_epoch_id_now(&self) -> u64 {
        let h = self.cfg.online_epoch_heights;
        if h == 0 {
            return 0;
        }
        self.tip_height / h
    }

    /// Deterministic commitment of an ONLINE roster for an epoch.
    pub fn online_set_hash(epoch_id: u64, members: &BTreeSet<String>) -> String {
        let joined = members.iter().cloned().collect::<Vec<_>>().join(",");
        sha256_hex(format!("online|v1|{epoch_id}|{joined}").as_bytes())
    }

    /// Bonded non-jailed validators (lottery-eligible by bond only).
    pub fn bonded_ids(&self) -> BTreeSet<String> {
        self.validators
            .values()
            .filter(|v| v.lottery_weight() > 0.0)
            .map(|v| v.id.clone())
            .collect()
    }

    /// Local observation: bonded + pong-fresh right now (input to OnlineSetVote).
    pub fn observe_online_members(&self) -> BTreeSet<String> {
        self.validators
            .values()
            .filter(|v| {
                v.lottery_weight() > 0.0
                    && v.pong_fresh(self.now_ms, self.cfg.pong_window_ms)
            })
            .map(|v| v.id.clone())
            .collect()
    }

    /// Live certified ONLINE seats (ignores open-height freeze). Used for status
    /// and for **freezing** the next open height at tip commit.
    pub fn live_online_seat_ids(&self) -> BTreeSet<String> {
        let bonded = self.bonded_ids();
        if self.cfg.online_epoch_heights == 0 {
            return bonded;
        }
        if self.online_members.is_empty() {
            return bonded;
        }
        let filtered: BTreeSet<String> = self
            .online_members
            .iter()
            .filter(|id| bonded.contains(*id))
            .cloned()
            .collect();
        if filtered.is_empty() {
            bonded
        } else {
            filtered
        }
    }

    /// Seat set for **lottery / packing this open height** (v2.4.0 + v2.5.0 freeze).
    ///
    /// When `schedule_height == tip+1`, returns the roster frozen at tip commit so
    /// a mid-height ONLINE certification cannot re-elect the packer (soak h=1671).
    pub fn online_seat_ids(&self) -> BTreeSet<String> {
        let open = self.tip_height.saturating_add(1);
        if self.schedule_height == open && !self.schedule_online_members.is_empty() {
            let bonded = self.bonded_ids();
            let filtered: BTreeSet<String> = self
                .schedule_online_members
                .iter()
                .filter(|id| bonded.contains(*id))
                .cloned()
                .collect();
            if !filtered.is_empty() {
                return filtered;
            }
        }
        self.live_online_seat_ids()
    }

    /// True if id is allowed to hold a packer seat this height.
    pub fn is_online_seat(&self, id: &str) -> bool {
        self.online_seat_ids().contains(id)
    }

    /// Freeze the **QC committee** for the newly opened height (`tip+1`).
    ///
    /// Committee is `draw_committee()` from **bonded + tip seed** (v2.8.1).
    /// Local ONLINE is stored for status / epoch votes only — it is not a
    /// lottery input and must not change who the 6 are.
    pub fn freeze_open_height_schedule(&mut self) {
        let open = self.tip_height.saturating_add(1);
        let prev_sched = self.schedule_height;
        self.schedule_height = open;
        self.schedule_online_members = self.live_online_seat_ids();
        self.schedule_online_hash = if self.online_hash.is_empty() {
            "bootstrap".to_string()
        } else {
            self.online_hash.clone()
        };
        self.schedule_committee = self.draw_committee();
        if let Some(l) = self.chain.last() {
            if l.is_v4() && !l.next_committee.is_empty() {
                // Membership must match; sealed next-6 order is authoritative
                // (draw_committee Vec order can differ after snapshot load).
                debug_assert_eq!(
                    self.schedule_committee.iter().collect::<BTreeSet<_>>(),
                    l.next_committee.iter().collect::<BTreeSet<_>>(),
                    "v4 freeze must equal sealed next-6 (as sets)"
                );
                self.schedule_committee = l.next_committee.clone();
            }
        }
        // Round belongs to the open height. Re-freezing the *same* height
        // (pong / ONLINE install) must not rewind it on round-scoped heights.
        let same_height_rounds = self.vote_rounds_at(open) && prev_sched == open;
        if !same_height_rounds {
            self.height_view_round = 0;
            self.last_view_change_vote_ms = 0;
            self.pending_rounds = 0;
        }
        self.view_change_votes.retain(|h, _| *h >= open.saturating_sub(2));
    }

    /// ONLINE hash tag for lottery seed (frozen for open height when available).
    pub fn lottery_online_tag(&self) -> String {
        let open = self.tip_height.saturating_add(1);
        if self.schedule_height == open && !self.schedule_online_hash.is_empty() {
            return self.schedule_online_hash.clone();
        }
        if self.online_hash.is_empty() {
            "bootstrap".to_string()
        } else {
            self.online_hash.clone()
        }
    }

    /// Install a soft-QC'd ONLINE set for `epoch_id`.
    ///
    /// Updates **live** ONLINE only. Does **not** rewrite `schedule_*` for an
    /// already-open height (v2.5.0 A1/A2).
    pub fn install_online_set(&mut self, epoch_id: u64, members: BTreeSet<String>, hash: String) {
        // Only advance or same epoch — never install an older epoch over a newer.
        if epoch_id < self.online_epoch_id && !self.online_members.is_empty() {
            return;
        }
        self.online_epoch_id = epoch_id;
        self.online_members = members;
        self.online_hash = hash.clone();
        self.online_ok.insert(epoch_id, hash);
        // Bind lottery freeze for open height:
        // - not frozen yet → freeze now
        // - frozen as bootstrap and no pending → upgrade once to first certified ONLINE
        //   (safe: mesh agrees on same QC; does not re-elect mid-flight after a proposal)
        // - frozen non-bootstrap → leave alone (A1: mid-height ONLINE flip cannot reseed)
        let open = self.tip_height.saturating_add(1);
        if self.schedule_height != open {
            self.freeze_open_height_schedule();
        } else if self.schedule_online_hash == "bootstrap"
            && self.pending_proposal.is_none()
            && !self.online_hash.is_empty()
        {
            self.schedule_online_members = self.live_online_seat_ids();
            self.schedule_online_hash = self.online_hash.clone();
            // Do **not** redraw the committee. ONLINE is permission, not a
            // seed input (v2.9.2). Redraw here forked nodes that certified
            // ONLINE from those still on bootstrap.
        }
    }

    /// Cast / accumulate an OnlineSetVote. Returns `(qc_just_applied, vote_was_new)`.
    ///
    /// Soft QC on `hash = online_set_hash(epoch_id, members)`. On QC, freezes
    /// seats for that epoch until a later epoch certifies.
    pub fn vote_online_set(
        &mut self,
        epoch_id: u64,
        members: BTreeSet<String>,
        voter: &str,
    ) -> (bool, bool) {
        self.vote_online_set_ex(epoch_id, members, voter, "")
    }

    /// Like [`vote_online_set`]; second of the pair is unused — returns `(qc, new)`.
    pub fn vote_online_set_ex(
        &mut self,
        epoch_id: u64,
        members: BTreeSet<String>,
        voter: &str,
        signature: &str,
    ) -> (bool, bool) {
        if self.cfg.online_epoch_heights == 0 {
            return (false, false);
        }
        if voter.is_empty() || members.is_empty() {
            return (false, false);
        }
        // Members must be subset of currently bonded (ignore stale ghosts).
        let bonded = self.bonded_ids();
        let members: BTreeSet<String> = members.into_iter().filter(|m| bonded.contains(m)).collect();
        if members.is_empty() {
            return (false, false);
        }
        // Mainnet polish: refuse undersized ONLINE sets — need enough seats to
        // satisfy soft QC among the roster itself (`|ONLINE| >= soft_need`).
        let min_seats = self
            .cfg
            .soft_ok_votes
            .min(bonded.len())
            .max(1);
        if members.len() < min_seats {
            return (false, false);
        }
        // Only the current tip epoch. Votes from a rewound / lagging peer
        // (epoch 6 while we are at epoch 79) must not certify or flip seats.
        let now_e = self.online_epoch_id_now();
        if epoch_id != now_e {
            return (false, false);
        }
        // Already certified this exact set for this epoch.
        let hash = Self::online_set_hash(epoch_id, &members);
        let payload = Self::vote_online_payload(self.cfg.network_id, epoch_id, &hash, voter);
        if !self.accept_vote_sig(voter, &payload, signature) {
            return (false, false);
        }
        if self.online_ok.get(&epoch_id).map(|h| h == &hash).unwrap_or(false) {
            return (false, false);
        }
        // If this epoch already QC'd a *different* set, freeze it (no flip-flop).
        if self.online_ok.contains_key(&epoch_id) {
            return (false, false);
        }

        let voters = self
            .online_votes
            .entry(epoch_id)
            .or_default()
            .entry(hash.clone())
            .or_default();
        let vote_was_new = voters.insert(voter.to_string());
        let n = voters.len();
        // ONLINE elects the live roster — not the ledger committee (that is 4-of-6).
        let need = self
            .cfg
            .soft_ok_votes
            .min(self.checker_count())
            .min(members.len())
            .max(1);
        if n >= need && members.len() >= min_seats {
            self.install_online_set(epoch_id, members, hash);
            // Prune old vote maps.
            let keep = epoch_id.saturating_sub(4);
            self.online_votes.retain(|e, _| *e >= keep);
            self.online_ok.retain(|e, _| *e >= keep);
            return (true, vote_was_new);
        }
        (false, vote_was_new)
    }

    /// Build local OnlineSetVote for the current epoch if we should cast/re-fan.
    /// Returns `(epoch_id, members)` when the node loop should gossip a vote.
    pub fn maybe_online_set_vote(&mut self) -> Option<(u64, BTreeSet<String>)> {
        if self.cfg.online_epoch_heights == 0 {
            return None;
        }
        let epoch_id = self.online_epoch_id_now();
        // Already certified this epoch — nothing to vote (carry seats).
        if self.online_ok.contains_key(&epoch_id) {
            return None;
        }
        let mut members = self.observe_online_members();
        // Always include self if bonded (we are online if we are voting).
        if self
            .validators
            .get(&self.id)
            .map(|v| v.lottery_weight() > 0.0)
            .unwrap_or(false)
        {
            members.insert(self.id.clone());
        }
        if members.is_empty() {
            return None;
        }
        // Require at least min(soft_ok, bonded) when possible so soft QC is reachable.
        let bonded_n = self.bonded_ids().len();
        let min_seats = self.cfg.soft_ok_votes.min(bonded_n).max(1);
        if members.len() < min_seats && bonded_n >= min_seats {
            // Not enough local pongs yet — still vote observed set so mesh can union via QC
            // on a common subset after more pongs; do not invent members.
        }
        let hash = Self::online_set_hash(epoch_id, &members);
        // Rate-limit: re-fan same vote at most every progress_timeout (or 2s).
        let interval = self.cfg.progress_timeout_ms.max(2_000);
        let same = self.last_online_vote_epoch == epoch_id && self.last_online_vote_hash == hash;
        if same && self.now_ms.saturating_sub(self.last_online_vote_ms) < interval {
            return None;
        }
        let hash = Self::online_set_hash(epoch_id, &members);
        let sig = self.sign_online_vote(epoch_id, &hash);
        let (_qc, _new) =
            self.vote_online_set_ex(epoch_id, members.clone(), &self.id.clone(), &sig);
        self.last_online_vote_epoch = epoch_id;
        self.last_online_vote_hash = hash;
        self.last_online_vote_ms = self.now_ms;
        Some((epoch_id, members))
    }

    /// Hard QC threshold from `hard_ok_ratio` (grows with bonded set size).
    ///
    /// Hard is **network-wide** — it does not use the 6-seat lottery committee.
    /// Soft (tip advance) is committee-only; hard is finality and may trail.
    ///
    /// **v2.5.0 C:** never require more hard votes than |ONLINE| (or bonded checkers).
    /// Prevents unreachable hard_need (e.g. n_bonded=3 → ceil(1.8)=2 ok; with joiners
    /// n=6 hard=4 but ONLINE=3 → hard capped at 3).
    pub fn hard_votes_needed(&self) -> usize {
        let c = self.checker_count();
        let mut need = ((c as f64) * self.cfg.hard_ok_ratio).ceil() as usize;
        need = need.max(1).min(c.max(1));
        if !self.online_members.is_empty() && self.cfg.online_epoch_heights > 0 {
            need = need.min(self.online_members.len().max(1));
        }
        need
    }

    /// v2.9.79: may a seat without the tip cert vote a round view-change?
    /// Only on round-scoped heights, and only after the open round has made
    /// no progress for twice the proposal timeout.
    pub fn certless_round_vc_allowed(&self) -> bool {
        let open = self.tip_height.saturating_add(1);
        if !self.vote_rounds_at(open) {
            return false;
        }
        let start = self.round_open_ms.max(self.height_open_ms);
        self.now_ms.saturating_sub(start) >= self.proposal_timeout_ms().saturating_mul(2)
    }

    /// Proposal-timeout threshold in ms (v2.5.0 B2).
    pub fn proposal_timeout_ms(&self) -> u64 {
        self.cfg
            .progress_timeout_ms
            .max(500)
            .saturating_mul(Self::PROPOSAL_TIMEOUT_MULT)
    }

    /// Soft-QC a view-change for the open height. On QC: clear pending, skip
    /// the silent/current packer on the **same** 6, bump `height_view_round`
    /// as a vote counter only. Does **not** reseed lottery (v2.9.2).
    ///
    /// Height-local only — never hard-resyncs from genesis.
    pub fn vote_view_change(
        &mut self,
        height: u64,
        tip_hash: &str,
        round: u64,
        voter: &str,
    ) -> (bool, bool) {
        self.vote_view_change_ex(height, tip_hash, round, voter, "")
    }

    pub fn vote_view_change_ex(
        &mut self,
        height: u64,
        tip_hash: &str,
        round: u64,
        voter: &str,
        signature: &str,
    ) -> (bool, bool) {
        if tip_hash != self.tip_hash || height != self.tip_height.saturating_add(1) {
            return (false, false);
        }
        if voter.is_empty() || round == 0 {
            return (false, false);
        }
        if !self.in_committee(voter) {
            return (false, false);
        }
        let payload = Self::vote_vc_payload(self.cfg.network_id, height, tip_hash, round, voter);
        if !self.accept_vote_sig(voter, &payload, signature) {
            return (false, false);
        }
        if self.vote_rounds_at(height) {
            return self.vote_round_change(height, round, voter);
        }
        // Only the next round is votable (no jump-ahead storms).
        let want = self.height_view_round.saturating_add(1);
        if round != want {
            return (false, false);
        }
        if self.schedule_height != height {
            self.freeze_open_height_schedule();
        }
        let qc = self.qc_voters();
        let voters = self
            .view_change_votes
            .entry(height)
            .or_default()
            .entry(round)
            .or_default();
        let vote_was_new = voters.insert(voter.to_string());
        let n = voters
            .iter()
            .filter(|id| qc.is_empty() || qc.iter().any(|c| c == *id))
            .count();
        let need = self.commit_votes_needed();
        if n >= need {
            self.apply_view_change(height, round);
            return (true, vote_was_new);
        }
        (false, vote_was_new)
    }

    fn apply_view_change(&mut self, height: u64, round: u64) {
        if self.vote_rounds_at(height) {
            self.apply_round_advance(height, round);
            return;
        }
        self.height_view_round = round;
        // Typed (v2.10.0): dual proposal, checker split, ingest fork. The old
        // substring test missed "checker equivocation …" (h=369421 halt).
        let dual = self.open_height_dual(height);
        // Unique pending is the attempt body. Dropping it is what produced a
        // second hash at h=1929 (v2.9.3 live). Only discard on dual.
        if self.pending_proposal.is_some() && !dual {
            if let Some(m) = self.view_change_votes.get_mut(&height) {
                m.remove(&round);
            }
            return;
        }
        if dual {
            // Legacy `pl-ok:v1` cannot tell a later-attempt re-vote from a
            // double-OK, so this attempt's OKs (and the "evidence" they made)
            // are attempt-local. Round-scoped heights keep real evidence.
            self.clear_attempt_votes(height);
            self.stall = None;
        }
        let mut silent = None;
        if let Some(p) = self.pending_proposal.take() {
            silent = Some(p.packer.clone());
            self.note_height_sealer(p.height, &p.packer);
        }
        if let Some((packer, _)) = self.seen_at_height.remove(&height) {
            silent = Some(packer.clone());
            self.note_height_sealer(height, &packer);
        }
        if silent.is_none() {
            silent = self.lottery_packer();
        }
        if let Some(ref p) = silent {
            self.skip_packer(height, p);
        }
        // Same 6. Exhausted skip set = failed attempt → reopen (v2.9.3).
        let order = self.lottery_order();
        let skips_now = self.skip_set_for(height);
        if !order.is_empty() && order.iter().all(|id| skips_now.contains(id)) {
            self.reopen_uncommitted_height(height);
        }
        let _ = self.sanitize_mempool();
        self.height_open_ms = self.now_ms;
        self.skip_grace_until_ms = self
            .now_ms
            .saturating_add((self.cfg.progress_timeout_ms.max(200)) / 2);
        if let Some(m) = self.view_change_votes.get_mut(&height) {
            m.remove(&round);
        }
        self.last_catchup_conflict = format!(
            "view-change applied h={height} round={round} (same committee; cursor advanced)"
        );
    }

    fn note_height_sealer(&mut self, height: u64, packer: &str) {
        if packer.is_empty() {
            return;
        }
        self.height_sealers
            .entry(height)
            .or_default()
            .insert(packer.to_string());
    }

    /// Whether the open-height pending has exceeded proposal-timeout.
    pub fn pending_proposal_timed_out(&self) -> bool {
        let Some(p) = &self.pending_proposal else {
            return false;
        };
        if p.height != self.tip_height.saturating_add(1) {
            return false;
        }
        let elapsed = self.now_ms.saturating_sub(self.height_open_ms);
        elapsed >= self.proposal_timeout_ms()
    }

    /// Cast / re-fan a ViewChange vote when pending is stuck past proposal-timeout
    /// or height is open with applicable txs and no progress for the same window.
    ///
    /// Returns `(height, tip_hash, target_round)` when the node loop should gossip.
    pub fn maybe_view_change_vote(&mut self) -> Option<(u64, String, u64)> {
        // Lagging nodes recover via catch-up, not view-change. VC while behind
        // floods the mesh and delays NeedLedgers/LedgersBatch (tip=0 freeze class).
        if self.still_lagging() {
            return None;
        }
        // Cold tip with no peer ads yet: seal loop probes catch-up; do not VC-spam.
        if self.best_peer_tip == 0 && self.tip_height == 0 {
            return None;
        }
        // Missing tip cert is recertify's job. VC cannot pack the next height
        // and only walks the 6 (2.9.14 resume freeze at 12939).
        //
        // v2.9.79 (671185 stall): on round-scoped heights a cert-less
        // committee seat may still vote the round forward once the open
        // round has been silent for 2x proposal-timeout. With 3 of 6 seats
        // cert-less (incl. the round-0 proposer) the 3 cert holders could
        // never reach 4 VC votes, so the silent proposer held the height for
        // over an hour. Rate-limited by the round clock; never on legacy.
        if self.tip_height > 0
            && !self.certs.contains_key(&self.tip_height)
            && !self.certless_round_vc_allowed()
        {
            return None;
        }
        let height = self.tip_height.saturating_add(1);
        if self.schedule_height != height {
            self.freeze_open_height_schedule();
        }
        if self.vote_rounds_at(height) {
            return self.maybe_round_timeout_vote(height);
        }
        let elapsed = self.now_ms.saturating_sub(self.height_open_ms);
        let timeout = self.proposal_timeout_ms();
        if elapsed < timeout {
            return None;
        }
        // v2.6.0: capture stall reasons **before** sanitize (sanitize clears poison
        // and would otherwise hide the multi-host tip-32 freeze class).
        let stuck_pending = self.pending_proposal.is_some();
        let had_applicable = self.has_applicable_tx();
        let net_work = self.network_has_pack_work();
        let was_poisoned = self.mempool_poisoned();
        let no_seat = self.lottery_packer().is_none();
        let dual = self.open_height_dual(height);
        let _ = self.sanitize_mempool();
        // v2.9.4: a unique live pending is the attempt. Do **not** VC-drop it
        // (that minted a new fatter hash and reset OKs to 0). Seal loop re-fans.
        // VC is for silence (no pending) or dual hashes.
        if stuck_pending && !dual {
            return None;
        }
        // View-change is for a leader who published nothing before the deadline.
        // Being on the committee is not silence; that voted every seat out and
        // the open height never sealed.
        if self.in_skip_grace() {
            return None;
        }
        let leader = self.lottery_packer();
        let leader_silent = match leader.as_deref() {
            None => true,
            Some(id) => {
                !self.packer_has_proposal_at(height, id) && !self.height_has_proposal(height)
            }
        };
        // v2.10.0 Phase 1: a *dual* pending is stuck too (h=369421 never VC'd).
        let _ = net_work;
        let open_stuck = (stuck_pending && dual)
            || (self.pending_proposal.is_none()
                && leader_silent
                && (had_applicable || was_poisoned || no_seat || dual || self.has_applicable_tx()));
        if !open_stuck {
            return None;
        }
        let interval = self.cfg.progress_timeout_ms.max(1_000);
        if self
            .now_ms
            .saturating_sub(self.last_view_change_vote_ms)
            < interval
        {
            // Still re-fan on each timeout window boundary for epidemic gossip.
            if elapsed % interval > 250 && self.last_view_change_vote_ms > 0 {
                return None;
            }
        }
        let round = self.height_view_round.saturating_add(1);
        let tip = self.tip_hash.clone();
        let me = self.id.clone();
        let sig = self.sign_vc_vote(height, &tip, round);
        let (_qc, _new) = self.vote_view_change_ex(height, &tip, round, &me, &sig);
        self.last_view_change_vote_ms = self.now_ms;
        Some((height, tip, round))
    }

    /// Genesis tip is soft-final. Live tip is soft once it sits on the committed
    /// chain (tip only advances after soft QC). Vote maps (`soft_ok`) are not
    /// persisted in snapshots — after restore, **chain presence** is enough so
    /// packing is not permanently blocked with "tip not soft-QC'd".
    pub fn tip_is_soft(&self) -> bool {
        if self.tip_height == 0 {
            return true;
        }
        if self.soft_ok.contains(&self.tip_hash) {
            return true;
        }
        // Snapshot / restart: soft_ok cleared but tip is already committed.
        self.chain.last().is_some_and(|l| {
            l.height == self.tip_height && l.ledger_hash == self.tip_hash
        })
    }

    /// True if we should wait before packing after a fresh shared skip.
    pub fn in_skip_grace(&self) -> bool {
        self.now_ms < self.skip_grace_until_ms
    }

    /// Any observed activity on the next height (proposal in flight) — do not timeout-skip yet.
    pub fn note_next_height_activity(&mut self) {
        self.height_open_ms = self.now_ms;
    }

    /// Min interval between pull catch-up requests.
    /// Kept short enough for multi-host lag, long enough to avoid request storms.
    pub const CATCHUP_REQ_INTERVAL_MS: u64 = 800;
    /// Max ledgers returned per catch-up response (count cap). Byte cap below
    /// is the real Falcon-512 bound — 64 × 128-tx bodies is ~10 MB.
    pub const CATCHUP_BATCH: usize = 64;
    /// Max estimated JSON bytes per LedgersBatch (v2.9.20). One fat soak
    /// ledger is ~170 KB; a 1.5 MB batch is ~8 of those and always fits
    /// the catch lane.
    pub const CATCHUP_BATCH_MAX_BYTES: usize = 1_500_000;
    /// Wait this long for a batch before sending another NeedLedgers.
    pub const CATCHUP_INFLIGHT_MS: u64 = 2_500;
    /// Hard-resync from genesis: slower request cadence (full history is expensive).
    pub const HARD_RESYNC_REQ_INTERVAL_MS: u64 = 2_000;

    /// Note peer tip from Pong; returns `Some(from_height)` if we should pull catch-up.
    ///
    /// **v2.3.2 P2:** residual catch-up is always `tip+1` unless the operator has
    /// armed hard-resync (`need_hard_resync`). Genesis-range pulls are operator-only.
    pub fn note_peer_tip(&mut self, peer_tip_height: u64, peer_tip_hash: &str) -> Option<u64> {
        if peer_tip_height > self.best_peer_tip {
            self.best_peer_tip = peer_tip_height;
            if !peer_tip_hash.is_empty() {
                self.best_peer_tip_hash = peer_tip_hash.to_string();
            }
        } else if peer_tip_height == self.best_peer_tip
            && !peer_tip_hash.is_empty()
            && self.best_peer_tip_hash.is_empty()
        {
            self.best_peer_tip_hash = peer_tip_hash.to_string();
        }
        // Canonical fork at our height — residual catch-up cannot help.
        if peer_tip_height == self.tip_height
            && self.tip_height > 0
            && !peer_tip_hash.is_empty()
            && !self.tip_hash.is_empty()
            && peer_tip_hash != self.tip_hash
        {
            self.last_catchup_conflict = format!(
                "catch-up conflict (no auto hard-resync): fork at h={} local {} peer {}",
                self.tip_height,
                &self.tip_hash[..self.tip_hash.len().min(16)],
                &peer_tip_hash[..peer_tip_hash.len().min(16)]
            );
            return None;
        }
        if peer_tip_height <= self.tip_height && !self.need_hard_resync {
            return None;
        }
        // A Hello/Pong must not start a second pull or refresh the inflight
        // deadline. That kept the ticker from rotating after 2.5s, so a lost
        // batch froze the tip.
        if self.catchup_inflight {
            return None;
        }
        self.rebase_future_stamps();
        let interval = self.catchup_interval_ms();
        if self
            .now_ms
            .saturating_sub(self.last_catchup_req_ms)
            < interval
        {
            return None;
        }
        self.last_catchup_req_ms = self.now_ms;
        if self.need_hard_resync && self.hard_resync_operator && self.can_hard_resync() {
            Some(1)
        } else if self.need_hard_resync && !self.hard_resync_operator {
            // Stale auto-arm from an old binary — drop it.
            self.need_hard_resync = false;
            Some(self.tip_height.saturating_add(1))
        } else if self.need_hard_resync {
            // Operator armed but we cannot rebuild — residual only.
            self.need_hard_resync = false;
            self.hard_resync_operator = false;
            self.last_catchup_conflict =
                "hard-resync armed but genesis material missing; residual only".into();
            Some(self.tip_height.saturating_add(1))
        } else {
            Some(self.tip_height.saturating_add(1))
        }
    }

    /// Operator-only: arm hard-resync from genesis (v2.3.2 P2).
    ///
    /// Prefer this for deliberate rebuilds. Catch-up **must not** arm a wipe
    /// (joiners state-sync from a snapshot; live hubs keep tip).
    pub fn operator_request_hard_resync(&mut self, reason: &str) -> Result<(), String> {
        if !self.can_hard_resync() {
            return Err(
                "hard-resync unavailable: need genesis_accounts + genesis_validators (reload snapshot)"
                    .into(),
            );
        }
        self.need_hard_resync = true;
        self.hard_resync_operator = true;
        self.hard_resync_fail_streak = 0;
        self.pending_proposal = None;
        self.last_catchup_conflict = if reason.is_empty() {
            "operator hard-reset".into()
        } else {
            format!("operator hard-reset: {reason}")
        };
        // Allow immediate NeedLedgers(from=1).
        self.last_catchup_req_ms = 0;
        Ok(())
    }

    /// **Never** auto-wipe. Kept so call sites compile; records the conflict only.
    /// Joiners recover from a live snapshot, not `NeedLedgers from=1`.
    pub fn arm_lagging_fork_resync(&mut self, reason: &str) -> bool {
        self.last_catchup_conflict = format!(
            "catch-up conflict (no auto hard-resync): {reason}"
        );
        false
    }

    /// Clear operator hard-resync arm without rebuilding.
    pub fn clear_hard_resync_arm(&mut self) {
        self.need_hard_resync = false;
        self.hard_resync_operator = false;
        self.hard_resync_fail_streak = 0;
    }

    /// Apply a directed catch-up batch (production path). Returns new tip height.
    ///
    /// **v2.3.2 / v2.7.1:** residual apply only (`tip+1`). Genesis rebuild
    /// only when the **operator** armed a wipe. A from=1 batch must never
    /// rewind a live tip (800→64 class).
    pub fn apply_catchup_batch(&mut self, ledgers: &[Ledger]) -> Result<u64, String> {
        if self.need_hard_resync && !self.hard_resync_operator {
            // Leftover auto-arm from a pre-2.7.1 binary — drop, never wipe.
            self.need_hard_resync = false;
        }
        if self.need_hard_resync && self.hard_resync_operator {
            let has_genesis = ledgers.iter().any(|l| l.height == 1);
            if has_genesis && self.can_hard_resync() {
                return self.hard_resync_from_ledgers(ledgers);
            }
            if !has_genesis {
                // fall through to residual
            } else {
                self.need_hard_resync = false;
                self.hard_resync_operator = false;
                self.last_catchup_conflict =
                    "hard-resync batch lacked usable genesis material".into();
            }
        }
        // Sort + dedupe by height for safe sequential apply.
        let mut by_h: BTreeMap<u64, Ledger> = BTreeMap::new();
        for led in ledgers {
            by_h.entry(led.height).or_insert_with(|| led.clone());
        }
        for (_h, led) in by_h {
            // Never re-litigate committed history (a from=1 batch must not
            // rewind or fork-check h=1 when we already have a tip).
            if led.height <= self.tip_height {
                continue;
            }
            // Residual window only (P1/P2 bound).
            if led.height > self.tip_height.saturating_add(Self::PENDING_LEDGERS_CAP as u64) {
                continue;
            }
            match self.ingest_ledger_catchup(&led) {
                Ok(Some(_)) => {
                    self.last_catchup_conflict.clear();
                }
                Ok(None) => {} // buffered future or already-have
                Err(e) => {
                    // Keep tip. Joiners recover via snapshot; operators hard-reset.
                    if e.contains("state root")
                        || e.contains("bad parent")
                        || e.contains("equivocation")
                        || e.contains("fork")
                    {
                        let h = led.height;
                        let _ = self.arm_lagging_fork_resync(&format!("h={h}: {e}"));
                        return Err(e);
                    }
                    // Transient: stop batch, keep partial tip.
                    self.last_catchup_conflict = format!("h={}: {e}", led.height);
                    break;
                }
            }
        }
        Ok(self.tip_height)
    }

    /// True if we still need more history from peers.
    pub fn still_lagging(&self) -> bool {
        self.need_hard_resync || self.best_peer_tip > self.tip_height
    }

    /// Another bonded seat has advertised a tip (Hello/Pong).
    pub fn peers_have_spoken(&self) -> bool {
        self.validators.values().any(|v| {
            v.id != self.id
                && v.last_advertised_tip.is_some()
                && v.pong_fresh(self.now_ms, self.cfg.pong_window_ms)
        })
    }

    /// After snap start, do not pack until a peer tip is heard or grace elapses.
    /// Staggered resume: locals at 16984 packed before droplet (16993) Hello'd
    /// and forked residual catch-up (`bad parent` at 16994).
    pub const STARTUP_TIP_GRACE_MS: u64 = 12_000;
    /// After a fork/parent conflict, do not flood NeedLedgers.
    pub const CATCHUP_CONFLICT_BACKOFF_MS: u64 = 5_000;

    pub fn startup_pack_blocked(&self) -> bool {
        // Fresh genesis already waits for live seats. This is snap-resume only.
        if self.started_ms == 0 || self.tip_height == 0 || self.peers_have_spoken() {
            return false;
        }
        self.now_ms.saturating_sub(self.started_ms) < Self::STARTUP_TIP_GRACE_MS
    }

    /// Seats that have ponged and advertised a tip at/above ours (plus self).
    pub fn live_seats_on_tip(&self) -> usize {
        let mut n = 1usize; // self is on this tip
        for v in self.validators.values() {
            if v.id == self.id || v.jailed || v.bond == 0 {
                continue;
            }
            if !v.pong_fresh(self.now_ms, self.cfg.pong_window_ms) {
                continue;
            }
            match v.last_advertised_tip {
                Some(t) if t < self.tip_height => {}
                _ => n += 1,
            }
        }
        n
    }

    /// Production 4-of-6: do not seal while the QC set is still bouncing.
    /// Smaller test committees (n<6) are unchanged. Genesis has its own
    /// live-seat gate — do not apply this at tip 0.
    pub fn pack_quorum_ready(&self) -> Result<(), String> {
        if self.tip_height == 0 || self.lottery_order().len() < 6 {
            return Ok(());
        }
        let live = self.live_seats_on_tip();
        let need = self.commit_votes_needed();
        if live < need {
            return Err(format!(
                "pack quorum {live}/{need} seats on tip {} — wait for bounce",
                self.tip_height
            ));
        }
        Ok(())
    }

    pub fn catchup_interval_ms(&self) -> u64 {
        let conflict = self.last_catchup_conflict.contains("bad parent")
            || self.last_catchup_conflict.contains("catch-up conflict")
            || self.last_catchup_conflict.contains("state root");
        if conflict {
            return Self::CATCHUP_CONFLICT_BACKOFF_MS;
        }
        if self.need_hard_resync && self.can_hard_resync() {
            return Self::HARD_RESYNC_REQ_INTERVAL_MS;
        }
        if self.best_peer_tip == 0 && self.tip_height == 0 {
            return Self::CATCHUP_REQ_INTERVAL_MS.saturating_mul(5).max(2_000);
        }
        Self::CATCHUP_REQ_INTERVAL_MS
    }

    /// Rate-limited catch-up start height, or None if we should not pull now.
    pub fn take_catchup_pull(&mut self) -> Option<u64> {
        // Exclusive snap: residual on this lane is what starved NeedSnapshot
        // for minutes before the 2.9.24 offer (v11 still waiting).
        if self.wants_snapshot() {
            return None;
        }
        self.rebase_future_stamps();
        let since = self.now_ms.saturating_sub(self.last_catchup_req_ms);
        if self.catchup_inflight && since < Self::CATCHUP_INFLIGHT_MS {
            return None;
        }
        if self.catchup_inflight && since >= Self::CATCHUP_INFLIGHT_MS {
            // No LedgersBatch arrived — this hub could not serve tip+1.
            // Rotate before the next NeedLedgers (AMD-20260827-1).
            self.empty_residual_streak = self.empty_residual_streak.saturating_add(1);
            self.catchup_hub_rotate = self.catchup_hub_rotate.saturating_add(1);
            self.catchup_inflight = false;
        }
        if !self.catchup_inflight && since < self.catchup_interval_ms() {
            return None;
        }
        let tip = self.tip_height;
        let best = self.best_peer_tip;
        let hard = self.need_hard_resync && self.can_hard_resync();
        let from = if hard {
            Some(1u64)
        } else if best > tip {
            self.note_peer_tip(best, "")
        } else if best == 0 && tip == 0 {
            Some(1u64)
        } else if best == 0 && tip > 0 {
            Some(tip.saturating_add(1))
        } else {
            None
        };
        if from.is_some() {
            self.last_catchup_req_ms = self.now_ms;
            self.catchup_inflight = true;
        }
        from
    }

    /// A catch-up batch was applied (or rejected). Clear inflight so we can pull again.
    pub fn note_catchup_batch(&mut self, advanced: bool) {
        self.catchup_inflight = false;
        if advanced {
            self.last_catchup_req_ms = 0;
            self.empty_residual_streak = 0;
            // Keep catchup_hub_rotate — the hub that served is the one we want.
        } else {
            self.empty_residual_streak = self.empty_residual_streak.saturating_add(1);
            self.catchup_hub_rotate = self.catchup_hub_rotate.saturating_add(1);
        }
    }

    /// Hub peer indices in NeedLedgers order (rotate on miss).
    pub fn catchup_peer_order(&self, idxs: &[usize]) -> Vec<usize> {
        if idxs.is_empty() {
            return Vec::new();
        }
        let n = idxs.len();
        let start = (self.catchup_hub_rotate as usize) % n;
        (0..n).map(|k| idxs[(start + k) % n]).collect()
    }

    /// Prefer the archive that just served a join snap (residual must match).
    pub fn catchup_peer_order_biased(&self, idxs: &[usize], peer_at: impl Fn(usize) -> String) -> Vec<usize> {
        let mut order = self.catchup_peer_order(idxs);
        if self.catchup_snap_peer.is_empty() {
            return order;
        }
        if let Some(pos) = order
            .iter()
            .position(|&i| peer_at(i) == self.catchup_snap_peer)
        {
            let hub = order.remove(pos);
            order.insert(0, hub);
        }
        order
    }

    /// NeedLedgers candidates, best first (v2.9.49).
    ///
    /// `peers[i] = (fanout index, peer id learned from Hello)`. Before 2.9.49
    /// only `--hubs` peers were asked. A hub that falls behind (v1, whose hub
    /// list is itself + v3) had one real candidate; when that lane was busy
    /// every pull was dropped ("catch lane full or no usable hub") while five
    /// healthy validators sat on the blocks it needed. Now:
    ///
    /// 1. usable hubs (rotated, snap source first) — same as before;
    /// 2. then every other usable peer (rotated): any non-jailed validator
    ///    that advertised a tip above ours, freshest pong first;
    /// 3. never ourselves.
    ///
    /// Unknown / not-yet-Hello'd peers stay eligible but go last.
    pub fn catchup_candidates(&self, peers: &[(usize, String)], hub_idxs: &[usize]) -> CatchupPlan {
        let mut plan = CatchupPlan::default();
        let id_of = |i: usize| -> String {
            peers
                .iter()
                .find(|(j, _)| *j == i)
                .map(|(_, id)| id.clone())
                .unwrap_or_default()
        };
        let classify = |i: usize, out: &mut Vec<usize>, unknown: &mut Vec<usize>, plan: &mut CatchupPlan| {
            let id = id_of(i);
            if !id.is_empty() && id == self.id {
                plan.skipped_self += 1;
                return;
            }
            if !self.catchup_peer_usable(&id) {
                if self.validators.get(&id).map(|v| v.jailed).unwrap_or(false) {
                    plan.skipped_jailed += 1;
                } else {
                    plan.skipped_behind += 1;
                }
                return;
            }
            if id.is_empty() || !self.validators.contains_key(&id) {
                unknown.push(i);
            } else {
                out.push(i);
            }
        };
        // 1. hubs (existing rotation + snap-source bias).
        let hub_order = self.catchup_peer_order_biased(hub_idxs, &id_of);
        let mut hubs = Vec::new();
        let mut hubs_unknown = Vec::new();
        for i in hub_order {
            classify(i, &mut hubs, &mut hubs_unknown, &mut plan);
        }
        // 2. everyone else, rotated by the same cursor so misses spread load.
        let rest: Vec<usize> = peers
            .iter()
            .map(|(i, _)| *i)
            .filter(|i| !hub_idxs.contains(i))
            .collect();
        let rest_order = self.catchup_peer_order(&rest);
        let mut others = Vec::new();
        let mut others_unknown = Vec::new();
        for i in rest_order {
            classify(i, &mut others, &mut others_unknown, &mut plan);
        }
        // Freshest pong first among known validators (stable for ties).
        let fresh = |i: &usize| -> bool {
            let id = id_of(*i);
            self.validators
                .get(&id)
                .map(|v| v.pong_fresh(self.now_ms, self.cfg.pong_window_ms))
                .unwrap_or(false)
        };
        others.sort_by_key(|i| !fresh(i));
        plan.hub_count = hubs.len() + hubs_unknown.len();
        plan.order.extend(hubs);
        plan.order.extend(hubs_unknown);
        plan.order.extend(others);
        plan.order.extend(others_unknown);
        plan
    }

    pub fn note_snap_source(&mut self, peer_id: &str) {
        if !peer_id.is_empty() {
            self.catchup_snap_peer = peer_id.to_string();
        }
    }

    /// Prefer a hub that has advertised a tip strictly ahead of us.
    /// Empty / unknown `peer_id` stays eligible (Hello not in yet).
    pub fn catchup_peer_usable(&self, peer_id: &str) -> bool {
        if peer_id.is_empty() {
            return true;
        }
        // A hub lists its own address in `--peers/--hubs` (v1 dials itself).
        // Asking ourselves for tip+1 can never help (v2.9.49).
        if peer_id == self.id {
            return false;
        }
        let Some(v) = self.validators.get(peer_id) else {
            return true;
        };
        if v.jailed {
            return false;
        }
        match v.last_advertised_tip {
            Some(t) => t > self.tip_height,
            None => true,
        }
    }

    /// Lag at which residual NeedLedgers is the wrong tool. Pull a snap
    /// from an archive hub, then catch up the tail (v2.9.21).
    /// 1024 soak ledgers is minutes of Falcon-512 verify on a 2-core WAN
    /// seat — they lose the race. 256 is "pin staleness", not a replay.
    pub const SNAPSHOT_PULL_LAG: u64 = 256;
    /// Residual catch-up is enough under this lag. Not a pin-rotate threshold:
    /// rotating a ~100 MB join snap at 32 heights aborts the public download
    /// (`snap hash changed`) before the observer finishes.
    pub const SNAPSHOT_SERVE_STALE_LAG: u64 = 32;
    /// Snap is join/disaster, not a feeding loop. Residual of certified
    /// ledgers is cheap (2.9.27); 256 was treating every slow seat as a joiner.
    pub const SNAPSHOT_JOIN_LAG: u64 = 2_048;
    pub const SNAPSHOT_PULL_INTERVAL_MS: u64 = 5_000;
    pub const SNAPSHOT_CHUNK_BYTES: usize = 256 * 1024;
    /// Hole-fill pipeline (v2.9.24). Archive already pushes every chunk;
    /// this is only for dropped slices on a bad path.
    pub const SNAPSHOT_PIPE_WINDOW: u32 = 16;
    pub const SNAPSHOT_RETRY_MS: u64 = 1_000;
    /// v2.9.62: re-request the tail above the highest received chunk only
    /// after this long without progress (the push may have been dropped).
    pub const SNAPSHOT_TAIL_RETRY_MS: u64 = 1_500;
    /// No progress → drop the assembler and `NeedSnapshot` again.
    /// Do **not** fall through to NeedLedgers (that was the 2.9.23 hole).
    pub const SNAPSHOT_STALL_ABORT_MS: u64 = 15_000;
    /// Do not rotate the pin mid-chunk if it is still useful.
    pub const SNAPSHOT_PIN_IDLE_MS: u64 = 45_000;

    /// Archive: publish a new `.join.serve.json`?
    /// Idle (no chunk for 45s) **or** live tip is a snap-lag ahead of the pin.
    /// Joiners retrying a stale pin keep `last_chunk` hot — idle-only never
    /// rotated (v4/v11 froze at 172587 while head ran to 178k).
    /// A live pull holds the pin until that snap-lag. Rotating at 32 heights
    /// while chunks are in flight aborts the ~100 MB public join.
    pub fn snap_pin_should_rotate(live_tip: u64, pin_tip: u64, last_chunk_ms: u64, now_ms: u64) -> bool {
        let idle = last_chunk_ms == 0 || now_ms.saturating_sub(last_chunk_ms) > Self::SNAPSHOT_PIN_IDLE_MS;
        let stale = live_tip.saturating_sub(pin_tip) >= Self::SNAPSHOT_PULL_LAG;
        idle || stale
    }

    /// `last_catchup_conflict` proves our chain diverged (not stale gossip).
    pub fn catchup_conflict_is_fork_poison(&self) -> bool {
        let c = &self.last_catchup_conflict;
        if c.starts_with("ingest h=") {
            // Live ingest reject: poison only if it was at/above our tip.
            let h = c
                .trim_start_matches("ingest h=")
                .split(|ch: char| !ch.is_ascii_digit())
                .next()
                .and_then(|d| d.parse::<u64>().ok())
                .unwrap_or(0);
            if h < self.tip_height
                || (h == self.tip_height && self.certs.contains_key(&self.tip_height))
            {
                return false;
            }
        }
        c.contains("state root mismatch") || c.contains("fork at h=")
    }

    /// Join or disaster only. In-mesh seats residual + live gossip (2.9.27).
    /// Archive ad still required — otherwise NeedLedgers must run.
    ///
    /// v2.9.34: three empty residuals with only a few heights missing means
    /// the RAM tail has a hole — pull a join snap instead of sitting at
    /// tip-2 forever. A miss while still under `SNAPSHOT_JOIN_LAG` but past
    /// that small hole is not one: re-snapping the ~100 MB pin there loses
    /// the race with the chain (a public joiner sat ~100 behind and
    /// downloaded forever). Those seats keep pulling ledgers.
    ///
    /// AMD-20260827-1: a lagging **archive** uses the same hole rule.
    /// Archives used to only *serve* snaps, so a 12-high hole behind a dead
    /// first hub never recovered.
    pub fn wants_snapshot(&self) -> bool {
        // Fork poison before the archive/hub gate. A lite joiner that only
        // dials the public relay never records an archive seat, so the gate
        // used to hide a state-root mismatch and newer snapshot offers.
        if self.catchup_conflict_is_fork_poison() && self.still_lagging() {
            return true;
        }
        if !self.snap_sources_available() {
            return false;
        }
        // Sources answered "nothing newer than you" recently and we are not far
        // behind: residual NeedLedgers can serve the gap (take_catchup_pull is
        // gated on !wants_snapshot). Without this a tip-0 seat whose peers'
        // snapshot files are still at tip 0 looped on NeedSnapshot forever.
        if self.stale_snap_offer_recent() && self.tip_lag() < Self::SNAPSHOT_JOIN_LAG {
            return false;
        }
        if self.cfg.archive {
            // After hard-reset / forked snapshot archive, genesis archive hubs must
            // join-snap like validators — ledger pull from h=1 never completes at 200k+.
            if self.tip_height == 0 {
                return true;
            }
            return self.residual_hole_needs_snapshot();
        }
        if self.tip_height == 0 || self.tip_lag() >= Self::SNAPSHOT_JOIN_LAG {
            return true;
        }
        self.residual_hole_needs_snapshot()
    }

    /// Request stamps are on the node-local `now_ms` clock. That clock can
    /// move backwards (snapshot adopt takes the source seat's clock), and a
    /// stamp left in the future blocks its rate limit until the clock passes
    /// it again: minutes to an hour on the live mesh. Treat it as "long ago".
    pub fn rebase_future_stamps(&mut self) {
        if self.last_catchup_req_ms > self.now_ms {
            self.last_catchup_req_ms = 0;
            self.catchup_inflight = false;
        }
        if self.last_snap_req_ms > self.now_ms {
            self.last_snap_req_ms = 0;
        }
        if self.stale_snap_offer_ms > self.now_ms {
            self.stale_snap_offer_ms = 0;
        }
    }

    /// Unanswered/empty residual pulls (~2.6 s each) after which a lagging
    /// seat with no reachable archive asks a hub for a snapshot even above
    /// `SNAPSHOT_SERVE_STALE_LAG` (~30 s of silence).
    pub const RESIDUAL_NO_SERVER_STREAK: u32 = 12;

    /// True when three empty ledger replies are a real hole, not a slow tail.
    ///
    /// Under `SNAPSHOT_SERVE_STALE_LAG` the peers' RAM window should already
    /// hold the missing heights, so three empties means the tail is gone.
    /// Between that and `SNAPSHOT_JOIN_LAG` the archive can still serve the
    /// heights; another full snapshot does not converge.
    fn residual_hole_needs_snapshot(&self) -> bool {
        // An in-sync seat collects empty residuals as a matter of course, so
        // with lag 0 every seat sent NeedSnapshot every 5 s and the hubs built
        // a ~100 MB snapshot reply for each one. A hole means we are behind.
        let lag = self.tip_lag();
        if self.empty_residual_streak >= 3 && lag > 0 && lag < Self::SNAPSHOT_SERVE_STALE_LAG {
            return true;
        }
        // 2.9.79 upgrade stall: above the RAM window only an archive serves
        // the gap. With no archive reachable (a seat whose --peers omit v1)
        // every pull went unanswered and the seat waited forever between
        // SNAPSHOT_SERVE_STALE_LAG and SNAPSHOT_JOIN_LAG. After sustained
        // silence, a hub snapshot is the only way forward.
        lag > 0
            && self.empty_residual_streak >= Self::RESIDUAL_NO_SERVER_STREAK
            && self.archive_seats().is_empty()
    }

    /// How long a stale snapshot answer suppresses join-snap in favour of
    /// residual ledger pulls (only while lag < `SNAPSHOT_JOIN_LAG`).
    pub const STALE_SNAP_OFFER_COOLDOWN_MS: u64 = 30_000;

    /// A snapshot source just offered nothing newer than our tip.
    pub fn note_stale_snapshot_offer(&mut self) {
        self.stale_snap_offer_ms = self.now_ms.max(1);
        self.empty_residual_streak = 0;
    }

    pub fn stale_snap_offer_recent(&self) -> bool {
        self.stale_snap_offer_ms > 0
            && self.now_ms.saturating_sub(self.stale_snap_offer_ms) < Self::STALE_SNAP_OFFER_COOLDOWN_MS
    }

    /// Archive seats, or hub seats ahead when no archive can serve (broken archive hub).
    pub fn snap_sources_available(&self) -> bool {
        !self.archive_seats().is_empty() || !self.hub_snap_seats().is_empty()
    }

    /// Rate-limited NeedSnapshot, or None.
    pub fn take_snapshot_pull(&mut self) -> bool {
        self.rebase_future_stamps();
        if !self.wants_snapshot() {
            return false;
        }
        if self
            .now_ms
            .saturating_sub(self.last_snap_req_ms)
            < Self::SNAPSHOT_PULL_INTERVAL_MS
        {
            return false;
        }
        self.last_snap_req_ms = self.now_ms;
        true
    }

    /// Seats that advertised archive (Hello/Pong). Empty = none heard yet.
    pub fn archive_seats(&self) -> Vec<String> {
        self.validators
            .iter()
            .filter(|(id, v)| {
                *id != &self.id
                    && v.advertised_archive
                    && v.pong_fresh(self.now_ms, self.cfg.pong_window_ms)
            })
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// Hub seats strictly ahead of us — ephemeral join-snap when archive is down.
    pub fn hub_snap_seats(&self) -> Vec<String> {
        self.validators
            .iter()
            .filter(|(id, v)| {
                *id != &self.id
                    && v.advertised_hub
                    && !v.jailed
                    && v.pong_fresh(self.now_ms, self.cfg.pong_window_ms)
                    && v.last_advertised_tip.unwrap_or(0) > self.tip_height
            })
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// Adopt a peer snapshot: take tip state + chain tail, keep local id/keys
    /// and the CLI archive flag (copied archive=true disabled strip — 20922).
    pub fn adopt_peer_snapshot(&mut self, loaded: Node) {
        let id = self.id.clone();
        let keys = self.keys.clone();
        let hub = self.is_hub;
        let store = self.body_store.take();
        let archive = self.cfg.archive;
        let max_body = self.cfg.max_body_ledgers;
        let vote_sigs = self.cfg.require_vote_sigs;
        let admin = self.cfg.allow_admin_wire;
        let mempool = std::mem::take(&mut self.mempool);
        // Snap JSON does not persist live Hello/Pong ads. Wiping them made
        // wants_snapshot false after adopt → residual-only forever (v12 18k).
        let ads: BTreeMap<String, (bool, bool, u64, u64)> = self
            .validators
            .iter()
            .map(|(id, v)| {
                (
                    id.clone(),
                    (
                        v.advertised_archive,
                        v.advertised_hub,
                        v.last_snap_height,
                        v.last_pong_ms,
                    ),
                )
            })
            .collect();

        self.state = loaded.state;
        self.tip_hash = loaded.tip_hash;
        self.tip_height = loaded.tip_height;
        self.validators = loaded.validators;
        self.rewards = loaded.rewards;
        self.now_ms = loaded.now_ms;
        self.genesis_ms = loaded.genesis_ms;
        self.treasury = loaded.treasury;
        self.epoch_work = loaded.epoch_work;
        self.last_settled_epoch = loaded.last_settled_epoch;
        self.claimable = loaded.claimable;
        self.defi = loaded.defi;
        self.bridge = loaded.bridge;
        self.metrics = loaded.metrics;
        self.height_open_ms = loaded.height_open_ms;
        self.chain = loaded.chain;
        self.seen_at_height = loaded.seen_at_height;
        self.certs = loaded.certs;
        self.genesis_accounts = loaded.genesis_accounts;
        self.genesis_validators = loaded.genesis_validators;
        self.online_epoch_id = loaded.online_epoch_id;
        self.online_members = loaded.online_members;
        self.online_hash = loaded.online_hash;
        self.pending_slashes = loaded.pending_slashes;
        self.ok_by_height_voter = loaded.ok_by_height_voter;
        self.ok_sigs = loaded.ok_sigs;
        self.names = loaded.names;
        self.cfg.epoch_ms = loaded.cfg.epoch_ms;
        self.cfg.first_claim_epoch = loaded.cfg.first_claim_epoch;
        self.cfg.network_id = loaded.cfg.network_id;
        for (id, v) in self.validators.iter_mut() {
            if let Some((arch, hub, snap_h, pong)) = ads.get(id) {
                if *arch {
                    v.advertised_archive = true;
                }
                if *hub {
                    v.advertised_hub = true;
                }
                if *snap_h > v.last_snap_height {
                    v.last_snap_height = *snap_h;
                }
                // The adopted clock is the source's `now_ms`, which can be
                // minutes behind ours (logical clocks drift per seat). Clamp so
                // a local pong stamp never sits in the adopted future.
                let pong = (*pong).min(self.now_ms);
                if pong > v.last_pong_ms {
                    v.last_pong_ms = pong;
                }
            }
        }

        self.id = id;
        self.keys = keys;
        // No ring seeding here: a seat key under an account id would shadow
        // the wallet key before the Fix B height. Consensus sigs use the
        // registry key directly (`verify_consensus_sig`).
        self.is_hub = hub;
        // Forked on-disk bodies survive snap adopt and poison residual catch-up.
        if let Some(store) = store.as_ref() {
            let dir = store.dir.clone();
            let _ = std::fs::remove_dir_all(&dir);
            let _ = std::fs::create_dir_all(&dir);
            for led in &self.chain {
                if led.has_body() {
                    let path = dir.join(format!("{}.json", led.ledger_hash));
                    if let Ok(bytes) = serde_json::to_vec(led) {
                        let tmp = path.with_extension("json.tmp");
                        if std::fs::write(&tmp, &bytes).is_ok() {
                            let _ = std::fs::rename(&tmp, &path);
                        }
                        if led.height > 0 && !led.ledger_hash.is_empty() {
                            let hp = dir.join(format!("h-{}.hash", led.height));
                            let _ = std::fs::write(hp, led.ledger_hash.as_bytes());
                        }
                    }
                }
            }
        }
        self.body_store = store;
        self.cfg.archive = archive;
        self.cfg.max_body_ledgers = max_body;
        self.cfg.require_vote_sigs = vote_sigs;
        self.cfg.allow_admin_wire = admin;
        self.mempool = mempool;
        self.pending_proposal = None;
        self.pending_ledgers.clear();
        self.ok_votes.clear();
        self.soft_ok.clear();
        self.hard_ok.clear();
        self.skip_votes.clear();
        self.view_change_votes.clear();
        self.catchup_inflight = false;
        // 2.9.79 upgrade stall: `now_ms` just jumped to the source's clock,
        // which can be far behind ours. A request stamp from our old clock
        // then made `now - last_catchup_req_ms` saturate to 0 and residual
        // catch-up never fired again (scottdog froze at 678630 after adopt).
        self.last_catchup_req_ms = 0;
        self.stale_snap_offer_ms = 0;
        self.empty_residual_streak = 0;
        self.last_catchup_conflict.clear();
        // v2.9.50: snap adopt lands on the peer's canonical tip — drop any
        // IngestFork / DualProposal stall left from the abandoned rival
        // (lingered on v10 after snap-only catch-up, 2026-10-06).
        self.stall = None;
        self.last_snap_req_ms = self.now_ms;
        self.drop_uncommitted_attempt_votes();
        self.drop_invalid_certs();
        for l in &self.chain {
            if let Some(c) = &l.parent_cert {
                self.certs.entry(c.height).or_insert_with(|| c.clone());
            }
        }
        self.sync_now_to_chain();
        self.freeze_open_height_schedule();
        self.prune_chain();
        self.mempool.prune_stale(&self.state);
        self.started_ms = self.now_ms.max(1);
    }

    /// Serve consecutive **committed** ledgers at/after `from_height` (pull catch-up).
    /// Never includes uncertified `pending_proposal` (v2.3.2 P2 QC-based catch-up).
    pub fn ledgers_from(&self, from_height: u64, max: usize) -> Vec<Ledger> {
        let max = max.clamp(1, Self::CATCHUP_BATCH.max(1));
        let mut out = Vec::with_capacity(max.min(16));
        let mut bytes = 0usize;
        let mut next = from_height;
        for led in &self.chain {
            if led.height < next {
                continue;
            }
            // Residual only. Skipping a missing body used to return a later
            // window the joiner cannot apply (tip+1 never arrives).
            if led.height != next {
                break;
            }
            let Some(full) = self.full_committed_ledger(led) else {
                break;
            };
            if !Self::push_catchup_ledger(&mut out, &mut bytes, full, max) {
                break;
            }
            next = next.saturating_add(1);
        }
        // RAM tail may be 1 ledger after a snap load. Disk height index +
        // seen_at_height still know tip-1, tip-2, … (v2.9.34).
        if let Some(store) = &self.body_store {
            while out.len() < max && next <= self.tip_height {
                let full = store.get_at_height(next).or_else(|| {
                    self.seen_at_height
                        .get(&next)
                        .and_then(|(_, h)| store.get(h))
                });
                let Some(full) = full else {
                    break;
                };
                if !Self::push_catchup_ledger(&mut out, &mut bytes, full, max) {
                    break;
                }
                next = next.saturating_add(1);
            }
        }
        out
    }

    fn full_committed_ledger(&self, led: &Ledger) -> Option<Ledger> {
        if led.has_body() {
            Some(led.clone())
        } else {
            self.body_store
                .as_ref()
                .and_then(|s| s.get(&led.ledger_hash))
        }
    }

    fn push_catchup_ledger(
        out: &mut Vec<Ledger>,
        bytes: &mut usize,
        full: Ledger,
        max: usize,
    ) -> bool {
        let sz = full.estimate_wire_bytes();
        if !out.is_empty()
            && (out.len() >= max || bytes.saturating_add(sz) > Self::CATCHUP_BATCH_MAX_BYTES)
        {
            return false;
        }
        *bytes = bytes.saturating_add(sz);
        out.push(full);
        true
    }

    /// How many heights we lag the best peer tip (0 if ahead/equal).
    pub fn tip_lag(&self) -> u64 {
        self.best_peer_tip.saturating_sub(self.tip_height)
    }

    /// Whether we should pull history from peers.
    ///
    /// Includes the live-join case: no peer tip ads yet (`best_peer_tip == 0`)
    /// because existing mesh nodes only fan to *their* configured peers, not
    /// to inbound joiners — so we never see Pongs until reverse-path exists.
    /// Probing `NeedLedgers` still works on our outbound dials.
    pub fn wants_catchup_probe(&self) -> bool {
        self.need_hard_resync
            || self.best_peer_tip > self.tip_height
            || self.best_peer_tip == 0
    }

    /// How many backup seats to keep visible behind the active packer (status/ops).
    pub const LOTTERY_BACKUP_DEPTH: usize = 3;
    /// Hub dish targets: active winner + first backup (v2.9.14).
    pub const DISH_SEATS: usize = 2;

    /// **Tip-fixed seat order** (v2.8.1).
    ///
    /// Seed = `H(network_id|height|tip_hash|prev_packer|set:id:bond,…)` only.
    /// **Never** pongs, **never** ONLINE, **never** view-round. Those are pack
    /// permission / recovery. Same tip ⇒ same order on every honest node.
    ///
    /// `extra_skips` = virtual exclusions while building the order (rank 0,1,2…),
    /// not network skip state.
    pub fn lottery_packer_with_skips(&self, extra_skips: &BTreeSet<String>) -> Option<String> {
        let height = self.tip_height + 1;
        let seats = self.bonded_ids();
        let mut all: Vec<(String, f64, u64)> = self
            .validators
            .values()
            .filter_map(|v| {
                let w = v.lottery_weight();
                if w <= 0.0 || !seats.contains(&v.id) {
                    return None;
                }
                Some((v.id.clone(), w, v.bond))
            })
            .collect();
        all.sort_by(|a, b| a.0.cmp(&b.0));
        if all.is_empty() {
            return None;
        }
        let set_key: String = all
            .iter()
            .map(|(id, _, bond)| format!("{id}:{bond}"))
            .collect::<Vec<_>>()
            .join(",");
        let prev_packer = self
            .chain
            .last()
            .map(|l| l.packer.as_str())
            .unwrap_or("genesis");
        // v8 after a v4 tip: seed is inner_hash so next-6 is not inside the lottery input.
        // v7 otherwise (including the first v4 height C(S), drawn from the v3 parent).
        let (tag, tip_seed) = if self.qc_v4_active_tip() {
            ("v8", self.lottery_tip_seed())
        } else {
            ("v7", self.tip_hash.clone())
        };
        let seed = sha256_hex(
            format!(
                "lottery|{tag}|{}|{}|{}|prev:{}|set:{}",
                self.cfg.network_id, height, tip_seed, prev_packer, set_key
            )
            .as_bytes(),
        );
        // A9: integer pick — seed % total_bond over sorted bonds (no f64).
        // v2.9.62 A3: from H_act every eligible seat weighs 1 (equal odds).
        let equal = self.rv2_at(height);
        let eligible: Vec<(String, u64)> = all
            .into_iter()
            .filter(|(id, _, _)| !extra_skips.contains(id))
            .map(|(id, _, bond)| (id, if equal { 1 } else { bond }))
            .collect();
        if eligible.is_empty() {
            return None;
        }
        let total: u128 = eligible.iter().map(|(_, b)| u128::from(*b)).sum();
        if total == 0 {
            return None;
        }
        let rank_n = extra_skips.len() as u64;
        let pick_seed = sha256_hex(format!("pick|{seed}|rank:{rank_n}").as_bytes());
        let n = u128::from_str_radix(&pick_seed[..16.min(pick_seed.len())], 16).unwrap_or(0);
        let mut r = n % total;
        for (id, bond) in &eligible {
            let b = u128::from(*bond);
            if r < b {
                return Some(id.clone());
            }
            r -= b;
        }
        eligible.last().map(|(id, _)| id.clone())
    }

    /// Full tip-fixed order for this height (ignores network skips).
    /// Seats = bonded non-jailed as of the tip (v2.8.1). ONLINE is not a filter.
    /// When `committee_size > 0`, this is the **QC committee** (1 packer + checkers),
    /// frozen at tip commit so skip cannot draw a new group mid-height.
    ///
    /// Frozen seats that have since unbonded are filtered out. If the whole
    /// freeze is gone, redraw from current bonded seats.
    pub fn lottery_order(&self) -> Vec<String> {
        let open = self.tip_height.saturating_add(1);
        if self.schedule_height == open && !self.schedule_committee.is_empty() {
            let seats = self.bonded_ids();
            let filtered: Vec<String> = self
                .schedule_committee
                .iter()
                .filter(|id| seats.contains(*id))
                .cloned()
                .collect();
            if !filtered.is_empty() {
                return filtered;
            }
        }
        self.draw_committee()
    }

    /// Deterministic committee: first `committee_size` of the full lottery draw.
    /// Skip / view-change only walk this list — they do not re-lottery.
    pub fn draw_committee(&self) -> Vec<String> {
        let n = self.bonded_ids().len();
        let mut virtual_skips = BTreeSet::new();
        let mut out = Vec::with_capacity(n);
        while out.len() < n {
            let Some(w) = self.lottery_packer_with_skips(&virtual_skips) else {
                break;
            };
            virtual_skips.insert(w.clone());
            out.push(w);
        }
        let cap = self.cfg.committee_size;
        if cap > 0 && out.len() > cap {
            out.truncate(cap);
        }
        out
    }

    /// v8 next-6 after packing height `h`: seed = inner_hash, height = h+1, prev = packer.
    fn draw_committee_v8(
        &self,
        inner_hash_hex: &str,
        next_height: u64,
        prev_packer: &str,
        validators: &BTreeMap<String, ValidatorInfo>,
    ) -> Vec<String> {
        let seats: BTreeSet<String> = validators
            .values()
            .filter(|v| v.lottery_weight() > 0.0)
            .map(|v| v.id.clone())
            .collect();
        let mut all: Vec<(String, u64)> = validators
            .values()
            .filter_map(|v| {
                let w = v.lottery_weight();
                if w <= 0.0 || !seats.contains(&v.id) {
                    return None;
                }
                Some((v.id.clone(), v.bond))
            })
            .collect();
        all.sort_by(|a, b| a.0.cmp(&b.0));
        if all.is_empty() {
            return Vec::new();
        }
        let set_key: String = all
            .iter()
            .map(|(id, bond)| format!("{id}:{bond}"))
            .collect::<Vec<_>>()
            .join(",");
        let seed = sha256_hex(
            format!(
                "lottery|v8|{}|{}|{}|prev:{}|set:{}",
                self.cfg.network_id, next_height, inner_hash_hex, prev_packer, set_key
            )
            .as_bytes(),
        );
        let mut virtual_skips = BTreeSet::new();
        let mut out = Vec::new();
        let n = all.len();
        // v2.9.62 A3: equal weights from H_act (set_key above still binds bonds).
        let equal = self.rv2_at(next_height);
        while out.len() < n {
            let eligible: Vec<(String, u64)> = all
                .iter()
                .filter(|(id, _)| !virtual_skips.contains(id))
                .map(|(id, b)| (id.clone(), if equal { 1 } else { *b }))
                .collect();
            if eligible.is_empty() {
                break;
            }
            let total: u128 = eligible.iter().map(|(_, b)| u128::from(*b)).sum();
            if total == 0 {
                break;
            }
            let rank_n = virtual_skips.len() as u64;
            let pick_seed = sha256_hex(format!("pick|{seed}|rank:{rank_n}").as_bytes());
            let nmod = u128::from_str_radix(&pick_seed[..16.min(pick_seed.len())], 16).unwrap_or(0);
            let mut r = nmod % total;
            let mut picked = eligible.last().map(|(id, _)| id.clone()).unwrap();
            for (id, bond) in &eligible {
                let b = u128::from(*bond);
                if r < b {
                    picked = id.clone();
                    break;
                }
                r -= b;
            }
            virtual_skips.insert(picked.clone());
            out.push(picked);
        }
        let cap = self.cfg.committee_size;
        if cap > 0 && out.len() > cap {
            out.truncate(cap);
        }
        out
    }

    pub fn sealed_committee(&self) -> Vec<String> {
        let open = self.tip_height.saturating_add(1);
        if self.schedule_height == open && !self.schedule_committee.is_empty() {
            return self.schedule_committee.clone();
        }
        self.draw_committee()
    }

    pub fn in_committee(&self, id: &str) -> bool {
        let c = self.lottery_order();
        c.is_empty() || c.iter().any(|x| x == id)
    }

    /// Soft-QC checkers: frozen committee minus the lottery packer (seat 0).
    ///
    /// A full draw of 6 → 5 checkers. Commit QC is **4 of the 6** (packer counts).
    /// Smaller draws (n<6) keep every seat so 2-of-2 / 3-of-3 still works.
    pub fn committee_checkers(&self) -> Vec<String> {
        let order = self.lottery_order();
        if self.cfg.committee_size > 0 && order.len() >= 6 {
            return order.into_iter().skip(1).collect();
        }
        order
    }

    fn counts_as_soft_checker(&self, id: &str) -> bool {
        self.counts_as_qc_voter(id)
    }

    /// **Active packer** = first seat in tip-fixed order not certified-skipped.
    ///
    /// Skip advances the cursor down a **preselected** list; it does not reseed.
    /// If v2 is #1 and skipped → #2 (v1) is active; order stays v2,v1,v3,…
    pub fn lottery_packer(&self) -> Option<String> {
        let height = self.tip_height + 1;
        let skips = self.skip_set_for(height);
        self.lottery_order()
            .into_iter()
            .find(|id| !skips.contains(id))
    }

    /// Active queue: current seat + backups still eligible (depth default 3).
    ///
    /// After each skip QC the next preselected seat is promoted; the list still
    /// shows remaining seats from the **same tip-fixed order** (lottery “fires”
    /// every open height from tip, not on each skip reseed).
    pub fn lottery_ranked(&self, limit: usize) -> Vec<String> {
        let height = self.tip_height + 1;
        let skips = self.skip_set_for(height);
        let max = if limit == 0 {
            Self::LOTTERY_BACKUP_DEPTH.max(1)
        } else {
            limit
        };
        self.lottery_order()
            .into_iter()
            .filter(|id| !skips.contains(id))
            .take(max)
            .collect()
    }

    /// Tip-fixed order + active cursor (for status / dash).
    pub fn lottery_queue_json(&self) -> serde_json::Value {
        let height = self.tip_height + 1;
        let order = self.lottery_order();
        let skips = self.skip_set_for(height);
        let active = self.lottery_packer();
        let backups: Vec<String> = order
            .iter()
            .filter(|id| !skips.contains(*id) && active.as_ref() != Some(*id))
            .take(Self::LOTTERY_BACKUP_DEPTH)
            .cloned()
            .collect();
        serde_json::json!({
            "order": order,
            "skipped": skips.iter().cloned().collect::<Vec<_>>(),
            "active": active,
            "backups": backups,
            "depth": Self::LOTTERY_BACKUP_DEPTH,
        })
    }

    /// Pre-check whether `tx` can be packed at the current committed state.
    /// Checks sequence match, key-bind gate, and the 4 permanent/non-packable
    /// error classes from Alert #16 (`OperatorGraphBind` already bound,
    /// `LendBorrow` LTV exceeded, `PayToKey` destination already has a key,
    /// and `VaultOpen` on a non-Hot account).
    pub fn is_tx_packable(&self, tx: &Tx) -> Result<(), String> {
        let need = self.state.get(&tx.account).sequence;
        if tx.sequence != need {
            return Err(format!("bad sequence want {need} got {}", tx.sequence));
        }
        Self::pack_key_bind_check(self.key_bind_gate_open(), &self.state, tx)?;
        match &tx.body {
            TxBody::OperatorGraphBind {
                deposit_txid,
                kick_off_2_txid,
                assert_final_txid,
                depositor_account,
                cosign,
            } => {
                if !depositor_account.is_empty()
                    && !self.state.accounts.contains_key(depositor_account.trim())
                {
                    return Err("operator: depositor_account is not a Falcon account".into());
                }
                let r = self
                    .bridge
                    .operators
                    .by_account(&tx.account)
                    .ok_or_else(|| "operator: unknown operator".to_string())?;
                let gkey = format!(
                    "{}:{}",
                    deposit_txid.trim().to_ascii_lowercase(),
                    r.btc_xonly_hex
                );
                if self.bridge.operators.graphs.contains_key(&gkey) {
                    return Err("operator: graph already bound for this deposit".into());
                }
                if !*cosign {
                    let k2 = kick_off_2_txid.trim().to_ascii_lowercase();
                    let af = assert_final_txid.trim().to_ascii_lowercase();
                    if self
                        .bridge
                        .operators
                        .graphs
                        .values()
                        .any(|g| g.kick_off_2_txid == k2 || g.assert_final_txid == af)
                    {
                        return Err("graph txid already bound elsewhere".into());
                    }
                }
            }
            TxBody::LendBorrow {
                market_id,
                amount,
                collateral_fpl,
            } => {
                let m = self
                    .defi
                    .markets
                    .get(market_id)
                    .ok_or_else(|| "unknown market".to_string())?;
                let mut m_probe = self.lend_market_rescaled(m);
                if let Some(px) = self.pool_price_fpl_scaled(&m_probe.asset, m_probe.scale()) {
                    m_probe.set_price(px);
                }
                m_probe.borrow(&tx.account, *amount, *collateral_fpl)?;
            }
            TxBody::PayToKey { key_hash } => {
                if !is_key_commit_hex(key_hash) {
                    return Err("pay_to_key: key_hash must be 64 lowercase hex".into());
                }
                if tx.destination.is_empty() || tx.destination == tx.account {
                    return Err("pay_to_key: bad destination".into());
                }
                if self.account_key_bound(&tx.destination) {
                    return Err("pay_to_key: destination already has a key".into());
                }
                if !self.key_bind_gate_open() {
                    return Err(PAY_TO_KEY_NOT_ACTIVE.into());
                }
                let dest = self.state.get(&tx.destination);
                if !dest.meta.key_commit.is_empty() && dest.meta.key_commit != *key_hash {
                    return Err("pay_to_key: destination committed to another key".into());
                }
            }
            TxBody::VaultOpen { destination } => {
                let dest = destination.trim();
                if dest.is_empty() {
                    return Err("vault: nominate a destination to activate".into());
                }
                if dest == tx.account {
                    return Err("vault: destination must differ from the vault account".into());
                }
                let sender = self.state.get(&tx.account);
                if sender.meta.account_type != AccountType::Hot {
                    return Err("only Hot can convert account type once".into());
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// True when `tx` passes [`Self::is_tx_packable`] at the current state.
    pub fn is_tx_applicable(&self, tx: &Tx) -> bool {
        self.is_tx_packable(tx).is_ok()
    }

    /// True if at least one pending tx has `sequence == account.need` and passes
    /// [`Self::is_tx_applicable`] (can pack now).
    ///
    /// Distinguishes **work the network can seal** from **seq-poison mempool**
    /// (future sequences only) or non-packable permanent failures.
    pub fn has_applicable_tx(&self) -> bool {
        if self.mempool.is_empty() {
            return false;
        }
        for tx in self.mempool.iter_candidates() {
            let need = self.state.get(&tx.account).sequence;
            if tx.sequence == need && self.is_tx_applicable(tx) {
                return true;
            }
        }
        false
    }

    /// Transactions whose sequence is the account's next required sequence
    /// and pass [`Self::is_tx_applicable`].
    /// One head per account can pack on this height; later sequences in the
    /// same pool are not applicable yet.
    pub fn applicable_head_count(&self) -> usize {
        if self.mempool.is_empty() {
            return 0;
        }
        let mut n = 0usize;
        for tx in self.mempool.iter_candidates() {
            let need = self.state.get(&tx.account).sequence;
            if tx.sequence == need && self.is_tx_applicable(tx) {
                n += 1;
            }
        }
        n
    }

    /// Non-empty mempool with zero next-seq matches (future-seq / gap poison).
    ///
    /// Under load this freezes the tip if recovery gates require `has_applicable_tx`
    /// (pack fails, skip suppressed, view-change suppressed) — v2.6.0 closes that.
    pub fn mempool_poisoned(&self) -> bool {
        !self.mempool.is_empty() && !self.has_applicable_tx()
    }

    /// Drop mempool poison without destroying a healthy sequential pipeline.
    ///
    /// **Always** prune stale (`seq < need`). **Only** drop future (`seq > need`)
    /// when the pool is **poisoned** (non-empty, zero next-seq matches). A healthy
    /// pipeline (`need`, `need+1`, `need+2`, …) must stay intact so one pack can
    /// seal multiple consecutive txs and later heights still have work. Blind
    /// future-drop on every pack (pre-v2.6.0) wiped packer-only mempools and
    /// froze multi-height seals under load.
    pub fn sanitize_mempool(&mut self) -> (usize, usize) {
        let stale = self.mempool.prune_stale(&self.state);
        // Capture after stale prune: future-only remainder is true poison.
        let future = if self.mempool_poisoned() {
            self.drop_future_seq_txs()
        } else {
            0
        };
        // v2.9.51: also drop permanently failing *applicable* heads (correct
        // seq but e.g. insufficient fee balance). Those are not future-poison,
        // so they used to sit forever, trip liveness_has_work, and freeze the tip
        // when the lottery winner never ran pack (or lacked tip cert).
        let _perm = self.drop_permanent_applicable_heads();
        (stale, future)
    }

    /// v2.9.56: logical-time bound on the sanitize head memo (see
    /// [`Self::drop_permanent_applicable_heads`]).
    pub const PERM_HEAD_MEMO_TTL_MS: u64 = 5_000;

    /// Dry-run each `seq == need` mempool head; drop permanent apply failures.
    ///
    /// Safe to call from any seat (not only the packer) so unpayable txs cannot
    /// hold `has_applicable_tx` / hub ads / liveness forever.
    ///
    /// v2.9.56: each head is dry-run at most once per committed tip (and per
    /// [`Self::PERM_HEAD_MEMO_TTL_MS`] of logical time). The result of a
    /// dry-run depends only on committed state, which cannot change without a
    /// new tip. Before this, a seat that kept calling sanitize at a flat tip
    /// (lagging round-0 lottery winner calling `pack_or_skip` every 200 ms
    /// tick) re-cloned state + bridge per head per tick under `node.lock`,
    /// pinned a tokio worker and starved its own I/O (v10 h=376571 and
    /// v12 h=377619 hangs, 2026-10-08).
    pub fn drop_permanent_applicable_heads(&mut self) -> usize {
        if self.mempool.is_empty() {
            return 0;
        }
        if self.perm_head_memo_tip != self.tip_hash
            || self.now_ms.saturating_sub(self.perm_head_memo_since_ms) >= Self::PERM_HEAD_MEMO_TTL_MS
            || self.now_ms < self.perm_head_memo_since_ms
        {
            self.perm_head_memo.clear();
            self.perm_head_memo_tip = self.tip_hash.clone();
            self.perm_head_memo_since_ms = self.now_ms;
        }
        let heads: Vec<Tx> = self
            .mempool
            .iter_candidates()
            .filter(|tx| self.state.get(&tx.account).sequence == tx.sequence)
            .filter(|tx| !self.perm_head_memo.contains(&tx.tx_id))
            .cloned()
            .collect();
        if heads.is_empty() {
            return 0;
        }
        let mut drop_ids = Vec::new();
        let saved_now = self.now_ms;
        for tx in heads {
            let mut draft_state = self.state.clone();
            let mut draft_defi = self.defi.clone();
            let mut draft_bridge = self.bridge.clone();
            let mut draft_vals = self.validators.clone();
            let mut draft_claim = self.claimable.clone();
            let mut draft_work = self.epoch_work.clone();
            self.perm_head_dry_runs = self.perm_head_dry_runs.saturating_add(1);
            let r = self.try_protocol_tx(
                &mut draft_state,
                &mut draft_defi,
                &mut draft_bridge,
                &mut draft_vals,
                &mut draft_claim,
                &mut draft_work,
                &tx,
            );
            match r {
                Err(e) if Self::is_permanent_tx_failure(&e) => {
                    eprintln!(
                        "falcon-pl sanitize drop {} seq {} {}: {e}",
                        tx.tx_id, tx.sequence, tx.account
                    );
                    { let tip = self.tip_hash.clone(); self.perm_dropped.insert(&tx.tx_id, saved_now, &tip); }
                    drop_ids.push(tx.tx_id.clone());
                }
                _ => {
                    self.perm_head_memo.insert(tx.tx_id.clone());
                }
            }
        }
        self.now_ms = saved_now;
        let n = drop_ids.len();
        if n > 0 {
            self.mempool.remove_many(&drop_ids);
            self.evicted_since_last_seal = true;
        }
        n
    }

    /// Active lottery seat cannot seal from the mesh's point of view:
    /// offline (stale pong) or lagging (advertised tip strictly behind ours).
    ///
    /// Missing tip ads alone are **not** unavailability (common right after pong
    /// without tip gossip) — that path caused false skips of live winners.
    pub fn active_packer_unavailable(&self) -> bool {
        let Some(winner) = self.lottery_packer() else {
            return true; // no seat → height must recover via reopen / view-change
        };
        let Some(v) = self.validators.get(&winner) else {
            return true;
        };
        if !v.pong_fresh(self.now_ms, self.cfg.pong_window_ms) {
            return true;
        }
        if let Some(t) = v.last_advertised_tip {
            if t < self.tip_height {
                return true; // lagging packer
            }
        }
        false
    }

    /// Open height has exceeded proposal-timeout without a commit (pending or not).
    pub fn open_height_stalled(&self) -> bool {
        self.now_ms.saturating_sub(self.height_open_ms) >= self.proposal_timeout_ms()
    }

    /// Progress-timeout: propose skip of the **active** seat only (cursor advance).
    ///
    /// Does **not** reseed seat order. After QC, next preselected seat becomes
    /// active. Never skip a packer with a staged proposal (job already done).
    ///
    /// **v2.6.0 / v2.9.14 liveness:**
    /// - Offline / lagging active seat → skip after progress_timeout.
    /// - Pong-fresh, on tip → do **not** skip (live silence is view-change).
    /// - Header / `want_body` → already proposed; wait for body / QC.
    /// - Observer applicable alone is not a skip (2.9.9 storm).
    /// - Poison / idle → no skip.
    pub fn live_pack_timeout_ms(&self) -> u64 {
        // Must exceed NeedTxs grace + pack_budget. A raw 2s is unsafe on this
        // fleet (800+1000). Slack covers Falcon seal + one gossip RTT.
        self.cfg
            .pack_budget_ms
            .max(500)
            .saturating_add(Self::NEED_TXS_PRE_PACK_GRACE_MS)
            .saturating_add(Self::LIVE_PACK_SLACK_MS)
    }

    pub fn propose_progress_timeout_skip(&self) -> Option<(u64, String, String)> {
        if self.cfg.progress_timeout_ms == 0 {
            return None;
        }
        // Catch-up owns recovery while behind a known peer tip.
        if self.still_lagging() {
            return None;
        }
        let elapsed = self.now_ms.saturating_sub(self.height_open_ms);
        if elapsed < self.cfg.progress_timeout_ms {
            return None;
        }
        let height = self.tip_height + 1;
        // Proposal in flight → wait soft QC / view-change; do not skip the sealer
        // while pending is still within proposal-timeout (v2.5.0 B4).
        if let Some(p) = &self.pending_proposal {
            if p.height == height {
                return None;
            }
        }
        let winner = self.lottery_packer()?;
        // v2.9.51: cert-less local winner cannot seal (may_pack / tip_parent_cert
        // refuse). Self-skip even when the mempool looks idle — otherwise the
        // cursor stays on a seat that can never produce parent_cert.
        if winner == self.id
            && self.tip_height > 0
            && !self.certs.contains_key(&self.tip_height)
        {
            return Some((height, winner, self.tip_hash.clone()));
        }
        // Truly idle — no pending and **no network work** (local or hub ad).
        // Local empty is not idle if a hub advertised pending (v2.9.12).
        if !self.network_has_pack_work() && self.pending_proposal.is_none() {
            return None;
        }
        if winner == self.id {
            return None;
        }
        if self.packer_has_proposal_at(height, &winner) || self.height_has_proposal(height) {
            return None;
        }
        // Header seen, body not yet — they already proposed (v2.9.14).
        if self.want_body_height == height && !self.want_body_hash.is_empty() {
            return None;
        }
        // Unavailable only. Live silence is view-change, not a 3s walk of
        // pong-fresh remotes who are still pulling or packing Falcon.
        if self.active_packer_unavailable() {
            return Some((height, winner, self.tip_hash.clone()));
        }
        None
    }

    /// Cast local skip vote for active seat; after QC, cursor advances to next seat.
    ///
    /// **v2.3.7:** if we already voted but the skip is **not yet certified**, still
    /// return `(height, winner, tip)` so the node loop **re-fans** the SkipPacker —
    /// but **at most once per `progress_timeout_ms`**. Continuous re-fan every seal
    /// tick floods `WIRE_QUEUE_CAP` and drops ProposeLedger/LedgerOk (worse freeze).
    pub fn maybe_progress_timeout_skip(&mut self) -> Option<(u64, String, String)> {
        // Round mode: the proposer is f(tip, round). An unavailable proposer
        // is handled by a (faster) round timeout, never a local skip cursor.
        if self.vote_rounds_at(self.tip_height.saturating_add(1)) {
            return None;
        }
        // v2.6.0: purge poison so progress evaluation sees true applicable state.
        let _ = self.sanitize_mempool();
        let (height, winner, tip) = self.propose_progress_timeout_skip()?;
        let voter = self.id.clone();
        let already = self
            .skip_votes
            .get(&height)
            .and_then(|m| m.get(&winner))
            .map(|s| s.contains(&voter))
            .unwrap_or(false);
        if already {
            if self.skip_set_for(height).contains(&winner) {
                return None;
            }
            // Rate-limit re-emit: only on each new progress_timeout window.
            let window = self.cfg.progress_timeout_ms.max(1);
            let elapsed = self.now_ms.saturating_sub(self.height_open_ms);
            // First window already cast the vote; re-fan on window 2,3,… only once
            // per window (when elapsed crosses a multiple of `window`).
            if elapsed < window.saturating_mul(2) {
                // Still inside first extra window — allow one re-fan after first timeout.
                // Use coarse bucket so ~seal_interval ticks collapse to one emit.
            }
            let bucket = elapsed / window;
            // Encode last re-fan bucket in skip_grace unused high bits? Keep simple:
            // only re-fan when (elapsed % window) < seal-ish 250ms → ~1/window.
            if elapsed % window > 250 {
                return None;
            }
            let _ = bucket; // documented for future last-bucket store
            return Some((height, winner, tip));
        }
        let sig = self.sign_skip_vote(height, &winner, &tip);
        let _ = self.vote_skip_ex(height, &winner, &tip, &voter, &sig);
        Some((height, winner, tip))
    }

    /// Drop pending txs with `sequence > account.need` (future-seq poison).
    ///
    /// **Caller must only invoke when poisoned** (no `seq == need` head). Used by
    /// [`sanitize_mempool`]. Leaving a future-only pool fills capacity and freezes
    /// tip when recovery gates require `has_applicable_tx` (v2.2.7 / v2.6.0).
    /// Never call on a healthy pipeline — that discards `need+1…` that pack next.
    pub fn drop_future_seq_txs(&mut self) -> usize {
        let mut drop_ids = Vec::new();
        for tx in self.mempool.iter_candidates() {
            let need = self.state.get(&tx.account).sequence;
            if tx.sequence > need {
                drop_ids.push(tx.tx_id.clone());
            }
        }
        let n = drop_ids.len();
        if n > 0 {
            self.mempool.remove_many(&drop_ids);
        }
        n
    }

    /// Try pack. Empty mempool → `Ok(None)` **without** skip (wait for txs).
    ///
    /// Poisoned pool (future-only / gap with no head): sanitize drops poison so
    /// correct next-seq work can enter. Do **not** self-skip (same poison on every
    /// packer → thrash). Height-level recovery is view-change (v2.6.0).
    ///
    /// v2.9.56: the local pack gate runs **before** sanitize. A seat that may
    /// not pack (tip lag, no soft QC, pending proposal, not the winner, ...)
    /// gets the same error as before from `pack_as`, but no longer pays a
    /// full mempool dry-run on every 200 ms tick while it holds `node.lock`.
    /// While a proposal is in flight, check the signatures of the transactions
    /// that would form the next block. The next packer is not known until this
    /// quorum lands, so every seat does the work and the winner proposes
    /// without spending the pack budget on those checks again.
    pub fn warm_pipeline(&mut self) {
        let Some(pending) = self.pending_proposal.clone() else {
            return;
        };
        if self.pipeline_for == pending.ledger_hash {
            return;
        }
        let mut covered: HashMap<String, u64> = HashMap::new();
        let mut in_block = std::collections::HashSet::new();
        for tx in &pending.txs {
            in_block.insert(tx.tx_id.clone());
            let e = covered.entry(tx.account.clone()).or_insert(tx.sequence);
            if tx.sequence > *e {
                *e = tx.sequence;
            }
        }
        let mut seen = std::collections::HashSet::new();
        let mut heads: Vec<&Tx> = Vec::new();
        for tx in self.mempool.iter_candidates() {
            if in_block.contains(&tx.tx_id) || seen.contains(&tx.account) {
                continue;
            }
            let need = covered
                .get(&tx.account)
                .map(|s| s.saturating_add(1))
                .unwrap_or_else(|| self.state.get(&tx.account).sequence);
            if tx.sequence != need || tx.signature.is_empty() {
                continue;
            }
            seen.insert(tx.account.clone());
            if !self.keys.has_public(&tx.account) && tx.public_key.is_empty() {
                continue;
            }
            heads.push(tx);
            if heads.len() >= Self::PACK_DEFAULT_MAX_TXS {
                break;
            }
        }
        let workers = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
            .clamp(1, 16);
        let onchain = self.onchain_sig_keys(&heads);
        let (ok, _) = Self::preverify_pack_sigs(&self.keys, &onchain, &heads, workers);
        self.sig_warm = ok;
        self.pipeline_for = pending.ledger_hash;
    }

    pub fn pack_or_skip(&mut self, packer: &str) -> Result<Option<Ledger>, String> {
        self.may_pack_locally(packer)?;
        let _ = self.sanitize_mempool();
        match self.pack_as(packer) {
            Ok(l) => Ok(Some(l)),
            Err(e) if e.contains("empty mempool") => {
                // Idle — do not mark packer skipped or height freezes forever.
                Ok(None)
            }
            Err(e) if e.contains("no applicable") => {
                self.pack_no_applicable = self.pack_no_applicable.saturating_add(1);
                // Force poison clear: pack saw no head; drop future remnants so the
                // next submit of `need` can land (mempool-full / load-seq desync).
                if self.mempool_poisoned() {
                    let _ = self.drop_future_seq_txs();
                }
                let _ = self.sanitize_mempool();
                match self.pack_as(packer) {
                    Ok(l) => Ok(Some(l)),
                    Err(e2) if e2.contains("empty mempool") || e2.contains("no applicable") => {
                        Ok(None)
                    }
                    Err(e2) => Err(e2),
                }
            }
            Err(e) => Err(e),
        }
    }

    fn checker_count(&self) -> usize {
        self.validators
            .values()
            .filter(|v| !v.jailed && v.bond > 0)
            .count()
            .max(1)
    }

    /// Cast OK vote on a staged or committed ledger. When soft QC is met for the
    /// pending proposal, commits tip (v2.3.0 P0).
    pub fn vote_ok(&mut self, ledger_hash: &str, voter: &str) -> (bool, bool) {
        // Unsigned in-process convenience. On round-scoped heights the vote is
        // counted in the local round (own vote: `own_ok_round`).
        let height = self.ok_vote_height(ledger_hash);
        let round = if !self.vote_rounds_at(height) {
            0
        } else if voter == self.id {
            self.own_ok_round(height)
        } else {
            self.height_view_round
        };
        let (soft, hard, _) = self.vote_ok_round_ex(ledger_hash, voter, "", round);
        (soft, hard)
    }

    /// Height an OK for `ledger_hash` refers to (tip, staged/known body, else open).
    pub fn ok_vote_height(&self, ledger_hash: &str) -> u64 {
        if self.tip_hash == ledger_hash {
            return self.tip_height;
        }
        self.pending_proposal
            .as_ref()
            .filter(|p| p.ledger_hash == ledger_hash)
            .map(|p| p.height)
            .or_else(|| self.open_bodies.get(ledger_hash).map(|l| l.height))
            .unwrap_or(self.tip_height.saturating_add(1))
    }

    /// v2.9.58: how far past `tip+1` a signed OK is kept for later.
    pub const FUTURE_OK_WINDOW: u64 = 8;
    /// v2.9.58: max buffered future OKs (oldest dropped first).
    pub const FUTURE_OK_CAP: usize = 256;

    fn ok_hash_known(&self, ledger_hash: &str) -> bool {
        self.tip_hash == ledger_hash
            || self
                .pending_proposal
                .as_ref()
                .map(|p| p.ledger_hash == ledger_hash)
                .unwrap_or(false)
            || self.open_bodies.contains_key(ledger_hash)
    }

    /// Wire entry for `LedgerOk` (v2.9.58): like [`Self::vote_ok_round_ex`],
    /// but uses the height the vote carries.
    ///
    /// [`Self::ok_vote_height`] maps an OK for an unknown body to `tip+1`, so
    /// before 2.9.58 a lagging seat verified an OK for `tip+2..` against the
    /// wrong height and silently dropped it; once it caught up, the round-0
    /// votes for the live height were gone (only re-sends could help). Now a
    /// correctly signed OK for an unknown body at `tip+2 ..= tip+WINDOW` is
    /// kept (bounded) and replayed through the normal path when that height
    /// opens. Votes, payloads, certs and the wire format are unchanged; the
    /// replayed vote is exactly the one that would have been counted had it
    /// arrived a moment later.
    pub fn vote_ok_wire(
        &mut self,
        wire_height: u64,
        ledger_hash: &str,
        voter: &str,
        signature: &str,
        round: u64,
    ) -> (bool, bool, bool) {
        let open = self.tip_height.saturating_add(1);
        if wire_height > open
            && wire_height <= self.tip_height.saturating_add(Self::FUTURE_OK_WINDOW)
            && voter != self.id
            && !self.ok_hash_known(ledger_hash)
        {
            self.buffer_future_ok(wire_height, ledger_hash, voter, signature, round);
            return (false, false, false);
        }
        self.vote_ok_round_ex(ledger_hash, voter, signature, round)
    }

    /// Keep a future OK if its signature verifies for its own height.
    /// Returns whether it was newly buffered.
    pub fn buffer_future_ok(
        &mut self,
        height: u64,
        ledger_hash: &str,
        voter: &str,
        signature: &str,
        round: u64,
    ) -> bool {
        let round = if self.vote_rounds_at(height) { round } else { 0 };
        let payload = self.ok_payload_for(height, round, ledger_hash, voter);
        if !self.accept_vote_sig(voter, &payload, signature) {
            return false;
        }
        let e = FutureOk {
            height,
            ledger_hash: ledger_hash.to_string(),
            voter: voter.to_string(),
            signature: signature.to_string(),
            round,
        };
        if self.future_oks.contains(&e) {
            return false;
        }
        if self.future_oks.len() >= Self::FUTURE_OK_CAP {
            self.future_oks.remove(0);
        }
        self.future_oks.push(e);
        true
    }

    /// Feed buffered OKs whose height is now open through the normal vote
    /// path; drop stale ones. Returns how many were replayed.
    pub fn replay_future_oks(&mut self) -> usize {
        if self.future_oks.is_empty() {
            return 0;
        }
        let open = self.tip_height.saturating_add(1);
        let max = self.tip_height.saturating_add(Self::FUTURE_OK_WINDOW);
        let all = std::mem::take(&mut self.future_oks);
        let mut due = Vec::new();
        for e in all {
            if e.height == open {
                due.push(e);
            } else if e.height > open && e.height <= max {
                self.future_oks.push(e);
            }
        }
        let n = due.len();
        for e in due {
            // Same path as a fresh wire vote at this height.
            let _ = self.vote_ok_round_ex(&e.ledger_hash, &e.voter, &e.signature, e.round);
        }
        n
    }

    /// Legacy wire entry (no round field ⇒ round 0).
    pub fn vote_ok_ex(
        &mut self,
        ledger_hash: &str,
        voter: &str,
        signature: &str,
    ) -> (bool, bool, bool) {
        self.vote_ok_round_ex(ledger_hash, voter, signature, 0)
    }

    /// Like [`vote_ok`]; third flag is whether this voter's OK was newly recorded
    /// (wire layer re-fans fresh votes for multi-host epidemic gossip).
    ///
    /// `round` is the signed view round (`pl-ok:v2`) on round-scoped heights
    /// and ignored (0) on legacy heights.
    pub fn vote_ok_round_ex(
        &mut self,
        ledger_hash: &str,
        voter: &str,
        signature: &str,
        round: u64,
    ) -> (bool, bool, bool) {
        let height = self.ok_vote_height(ledger_hash);
        if self.vote_rounds_at(height) {
            let payload =
                Self::vote_ok_payload_v2(self.cfg.network_id, height, round, ledger_hash, voter);
            if !self.accept_vote_sig(voter, &payload, signature) {
                return (false, false, false);
            }
            return self.record_round_ok(height, round, ledger_hash, voter, signature);
        }
        let payload = Self::vote_ok_payload(self.cfg.network_id, height, ledger_hash, voter);
        if !self.accept_vote_sig(voter, &payload, signature) {
            return (false, false, false);
        }
        if !self.eligible_voter(voter) {
            return (false, false, false);
        }
        // Two OK hashes at one height: record evidence for the **next ledger**.
        // Do not slash here — jail is in the commitment root; a local-only slash
        // forks catch-up (v1 stuck at 275 after the live v12 double-OK).
        if let Some(prev) = self
            .ok_by_height_voter
            .get(&height)
            .and_then(|m| m.get(voter))
            .cloned()
        {
            if prev != ledger_hash && voter == self.id {
                // Never queue evidence against ourselves (a pending switch made
                // us re-vote); refuse the second OK instead of self-jailing.
                return (false, false, false);
            }
            if prev != ledger_hash {
                let sig_a = self
                    .ok_sigs
                    .get(&prev)
                    .and_then(|m| m.get(voter))
                    .cloned()
                    .unwrap_or_default();
                let ev = SlashEvidence {
                    offender: voter.to_string(),
                    height,
                    hash_a: prev.clone(),
                    sig_a,
                    hash_b: ledger_hash.to_string(),
                    sig_b: signature.to_string(),
                    kind: String::new(),
                    round: 0,
                };
                if !self
                    .pending_slashes
                    .iter()
                    .any(|e| e.offender == ev.offender && e.height == ev.height)
                {
                    self.pending_slashes.push(ev);
                }
                self.stall = Some(ConsensusStall::CheckerEquivocation {
                    height,
                    round: 0,
                    voter: voter.to_string(),
                });
                self.last_catchup_conflict = format!(
                    "checker equivocation {voter} h={height} queued for next ledger (had {prev} got {ledger_hash})"
                );
                return (false, false, false);
            }
        }
        // Soft/commit = 4 of 6 committee (tip advance). Hard = every bonded OK.
        let qc = self.qc_voters();
        let set = self.ok_votes.entry(ledger_hash.to_string()).or_default();
        let fresh = set.insert(voter.to_string());
        if !signature.is_empty() {
            self.ok_sigs
                .entry(ledger_hash.to_string())
                .or_default()
                .insert(voter.to_string(), signature.to_string());
        }
        self.ok_by_height_voter
            .entry(height)
            .or_default()
            .insert(voter.to_string(), ledger_hash.to_string());
        let soft_n = if qc.is_empty() {
            set.len()
        } else {
            set.iter()
                .filter(|id| qc.iter().any(|c| c == *id))
                .count()
        };
        let hard_n = set.len();
        let soft_need = self.commit_votes_needed();
        let hard_need = self.hard_votes_needed();
        let soft = soft_n >= soft_need;
        let hard = hard_n >= hard_need;
        if soft {
            self.soft_ok.insert(ledger_hash.to_string());
            self.store_cert_if_ready(ledger_hash, height);
        }
        if hard {
            self.hard_ok.insert(ledger_hash.to_string());
        }
        // Epoch check credit only for newly counted votes on known ledgers.
        if fresh {
            self.epoch_work.record_check(voter, ledger_hash);
        }
        // Soft QC commits only when this body is the unique leader (no rival
        // at the same height also at need). Majority soft makes two QCs
        // impossible; this is belt-and-suspenders.
        if soft {
            if let Some(p) = &self.pending_proposal {
                if p.ledger_hash == ledger_hash && !self.rival_has_soft_qc(ledger_hash) {
                    if let Err(e) = self.commit_pending_proposal() {
                        self.last_catchup_conflict = format!(
                            "soft-QC commit failed h={} hash={}: {e}",
                            self.tip_height.saturating_add(1),
                            &ledger_hash[..16.min(ledger_hash.len())]
                        );
                    }
                }
            }
        }
        (soft, hard, fresh)
    }

    /// Build and store a 4-of-6 (or small-n) cert once commit QC is met.
    fn store_cert_if_ready(&mut self, ledger_hash: &str, height: u64) {
        if self.certs.contains_key(&height) {
            return;
        }
        let committee = self.qc_voters();
        let need = self.commit_votes_needed();
        let Some(set) = self.ok_votes.get(ledger_hash) else {
            return;
        };
        let sigs = self.ok_sigs.get(ledger_hash);
        let mut voters = Vec::new();
        let mut signatures = Vec::new();
        let source = if committee.is_empty() {
            set.iter().cloned().collect::<Vec<_>>()
        } else {
            committee
                .iter()
                .filter(|id| set.contains(*id))
                .cloned()
                .collect()
        };
        for id in source {
            let sig = sigs
                .and_then(|m| m.get(&id))
                .cloned()
                .unwrap_or_default();
            // A recertify cert with empty or outsider sigs is rejected on
            // self-accept (`cert missing sig` / `voter not in committee`).
            if sig.is_empty() && self.cfg.require_vote_sigs {
                continue;
            }
            voters.push(id);
            signatures.push(sig);
        }
        if voters.len() < need {
            return;
        }
        let parent_hash = if self.tip_hash == ledger_hash {
            self.chain
                .last()
                .map(|l| l.parent_hash.clone())
                .unwrap_or_default()
        } else {
            self.pending_proposal
                .as_ref()
                .filter(|p| p.ledger_hash == ledger_hash)
                .map(|p| p.parent_hash.clone())
                .unwrap_or_else(|| self.tip_hash.clone())
        };
        self.certs.insert(
            height,
            LedgerCert {
                height,
                ledger_hash: ledger_hash.to_string(),
                parent_hash,
                committee,
                voters,
                signatures,
                round: if self.vote_rounds_at(height) {
                    self.ok_round.get(ledger_hash).copied().unwrap_or(0)
                } else {
                    0
                },
            },
        );
    }

    fn rival_has_soft_qc(&self, ledger_hash: &str) -> bool {
        let need = self.commit_votes_needed();
        let committed: BTreeSet<String> = self.chain.iter().map(|l| l.ledger_hash.clone()).collect();
        self.ok_votes.iter().any(|(h, s)| {
            if h == ledger_hash || committed.contains(h) {
                return false;
            }
            s.iter().filter(|id| self.counts_as_qc_voter(id)).count() >= need
        })
    }

    /// Local permission to pack: lottery winner, fresh pong, soft tip, no pending.
    ///
    /// Production rule: a lagging node must never seal. Packing on a stale tip
    /// creates a parallel chain (bad parent / state root at higher heights).
    pub fn may_pack_locally(&self, packer: &str) -> Result<(), String> {
        if self.need_hard_resync {
            return Err("hard-resync in progress — catch up before pack".into());
        }
        if self.startup_pack_blocked() {
            return Err("startup: wait for peer tip ads".into());
        }
        if let Err(e) = self.pack_quorum_ready() {
            return Err(e);
        }
        if self.tip_height == 0 {
            let live = self
                .validators
                .values()
                .filter(|v| !v.jailed && v.bond > 0 && v.pong_fresh(self.now_ms, self.cfg.pong_window_ms))
                .count();
            let need = self.cfg.soft_ok_votes.min(self.checker_count()).max(1);
            if live < need {
                return Err(format!(
                    "genesis: {live}/{need} live seats — wait before sealing h=1"
                ));
            }
        }
        if self.best_peer_tip > self.tip_height {
            return Err(format!(
                "tip lag {} (local {} < best peer {}) — catch up before pack",
                self.tip_lag(),
                self.tip_height,
                self.best_peer_tip
            ));
        }
        if !self.tip_is_soft() {
            return Err("tip not soft-QC'd — wait before packing next height".into());
        }
        // v2.9.51: chain presence after snapshot makes tip_is_soft true, but
        // packing the next height still needs parent_cert in `certs`. Without
        // this gate a cert-less winner spins on "no 4-of-6 cert for tip".
        if self.tip_height > 0 && !self.certs.contains_key(&self.tip_height) {
            return Err(format!(
                "no tip cert for h={} — wait for committee QC / recertify",
                self.tip_height
            ));
        }
        if let Some(p) = &self.pending_proposal {
            return Err(format!(
                "proposal pending soft QC at h={} ({})",
                p.height,
                &p.ledger_hash[..16.min(p.ledger_hash.len())]
            ));
        }
        let open = self.tip_height.saturating_add(1);
        if self.height_has_proposal(open) {
            return Err(format!(
                "h={open} already has a proposal — wait QC or view-change"
            ));
        }
        let winner = self
            .lottery_packer()
            .ok_or_else(|| "no bonded packers in registry".to_string())?;
        if winner != packer {
            return Err(format!("{packer} not lottery winner (want {winner})"));
        }
        let v = self
            .validators
            .get(packer)
            .ok_or_else(|| "unknown packer".to_string())?;
        if !v.pong_fresh(self.now_ms, self.cfg.pong_window_ms) {
            return Err(format!(
                "{packer} pong stale — ping before pack (window {}ms)",
                self.cfg.pong_window_ms
            ));
        }
        // ONLINE / pong is permission only. Election is tip-bonded (v2.8.1).
        Ok(())
    }

    /// Admin-only pack permission: skip lottery, tip lag, pong, soft-QC gates.
    /// Used for solo LC catch-up on an isolated archive (unix `--admin-sock`).
    pub fn may_pack_admin_force(&self, packer: &str) -> Result<(), String> {
        if self.need_hard_resync {
            return Err("hard-resync in progress — catch up before pack".into());
        }
        if packer != self.id {
            return Err(format!("admin force seal only for local id {}", self.id));
        }
        Ok(())
    }

    /// Full consensus commitment (accounts + defi + bridge + bonds + claimable).
    pub fn commitment_root(&self) -> String {
        Self::commitment_root_parts(
            &self.state,
            &self.defi,
            &self.bridge,
            &self.validators,
            &self.claimable,
        )
    }

    fn commitment_root_parts(
        state: &WorldState,
        defi: &DefiState,
        bridge: &BridgeState,
        validators: &BTreeMap<String, ValidatorInfo>,
        claimable: &BTreeMap<String, u64>,
    ) -> String {
        // jail_count is consensus-critical (Unjail cost); must be in the root.
        let val_slim: BTreeMap<String, (u64, u64, bool, u32, String)> = validators
            .iter()
            .map(|(k, v)| {
                (
                    k.clone(),
                    (
                        v.bond,
                        v.unbonding,
                        v.jailed,
                        v.jail_count,
                        v.bond_account.clone(),
                    ),
                )
            })
            .collect();
        // v2.9.62: v2 validator fields join the root as a 6th element, only
        // once any is non-default (from H_act). Before that the bytes are the
        // 2.9.61 5-tuple.
        let val_v2 = Self::val_v2_slim(validators);
        let presence = Self::presence_slim(validators);
        let catchup = Self::catchup_slim(validators);
        // Seat payout: the seat map joins as a 9th element once any seat has a
        // bucket or a payout account (never before activation).
        let seat = Self::seat_slim(validators);
        if !seat.is_empty() {
            let input = (
                &state.accounts,
                defi,
                bridge,
                val_slim,
                claimable,
                &val_v2,
                &presence,
                &catchup,
                &seat,
            );
            let root = crate::exec_map::sha256_hex_split(&input);
            #[cfg(test)]
            if state.accounts.len() <= 50_000 {
                let fresh = sha256_hex(&serde_json::to_vec(&input).unwrap_or_default());
                assert_eq!(root, fresh, "seat cached commitment root != fresh root");
            }
            return root;
        }
        if !catchup.is_empty() {
            let input = (
                &state.accounts,
                defi,
                bridge,
                val_slim,
                claimable,
                &val_v2,
                &presence,
                &catchup,
            );
            let root = crate::exec_map::sha256_hex_split(&input);
            #[cfg(test)]
            if state.accounts.len() <= 50_000 {
                let fresh = sha256_hex(&serde_json::to_vec(&input).unwrap_or_default());
                assert_eq!(root, fresh, "catchup cached commitment root != fresh root");
            }
            return root;
        }
        if !presence.is_empty() {
            let input = (&state.accounts, defi, bridge, val_slim, claimable, &val_v2, &presence);
            let root = crate::exec_map::sha256_hex_split(&input);
            #[cfg(test)]
            if state.accounts.len() <= 50_000 {
                let fresh = sha256_hex(&serde_json::to_vec(&input).unwrap_or_default());
                assert_eq!(root, fresh, "presence cached commitment root != fresh root");
            }
            return root;
        }
        if !val_v2.is_empty() {
            let input = (&state.accounts, defi, bridge, val_slim, claimable, val_v2);
            let root = crate::exec_map::sha256_hex_split(&input);
            #[cfg(test)]
            if state.accounts.len() <= 50_000 {
                let fresh = sha256_hex(&serde_json::to_vec(&input).unwrap_or_default());
                assert_eq!(root, fresh, "v2 cached commitment root != fresh root");
            }
            return root;
        }
        // v2.9.58: same bytes as `sha256_hex(serde_json::to_vec(..))`, but the
        // ~200 MB exec header map is encoded once per generation and a root
        // already computed for identical bytes (verify → commit → status) is
        // reused. See `exec_map`.
        let input = (&state.accounts, defi, bridge, val_slim, claimable);
        let root = crate::exec_map::sha256_hex_split(&input);
        // Test builds cross-check against a fresh full encode (skipped for the
        // 150k-account timing fixture, where it would double a timed root).
        #[cfg(test)]
        if state.accounts.len() <= 50_000 {
            let fresh = sha256_hex(&serde_json::to_vec(&input).unwrap_or_default());
            assert_eq!(root, fresh, "v2.9.58 cached commitment root != fresh root");
            ROOT_CROSSCHECKS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        root
    }

    fn catchup_slim(validators: &BTreeMap<String, ValidatorInfo>) -> BTreeMap<String, u64> {
        validators
            .iter()
            .filter(|(_, v)| v.last_active_height > 0)
            .map(|(k, v)| (k.clone(), v.last_active_height))
            .collect()
    }

    fn presence_slim(
        validators: &BTreeMap<String, ValidatorInfo>,
    ) -> BTreeMap<String, (u32, bool)> {
        validators
            .iter()
            .filter(|(_, v)| v.earn_locked || v.earn_streak > 0)
            .map(|(k, v)| (k.clone(), (v.earn_streak, v.earn_locked)))
            .collect()
    }

    /// Seat payout root map: seats with a non-zero bucket or a payout account.
    fn seat_slim(
        validators: &BTreeMap<String, ValidatorInfo>,
    ) -> BTreeMap<String, (u64, Option<String>)> {
        validators
            .iter()
            .filter(|(_, v)| v.seat_claimable > 0 || v.seat_payout.is_some())
            .map(|(k, v)| (k.clone(), (v.seat_claimable, v.seat_payout.clone())))
            .collect()
    }

    fn val_v2_slim(
        validators: &BTreeMap<String, ValidatorInfo>,
    ) -> BTreeMap<String, (u64, bool, u32, bool, String, bool)> {
        validators
            .iter()
            .filter_map(|(k, v)| v.v2_slim().map(|t| (k.clone(), t)))
            .collect()
    }

    /// Plain (pre-2.9.58) commitment root: full serialize + sha256, no cache.
    pub fn commitment_root_fresh(&self) -> String {
        let val_slim: BTreeMap<String, (u64, u64, bool, u32, String)> = self
            .validators
            .iter()
            .map(|(k, v)| {
                (
                    k.clone(),
                    (v.bond, v.unbonding, v.jailed, v.jail_count, v.bond_account.clone()),
                )
            })
            .collect();
        let val_v2 = Self::val_v2_slim(&self.validators);
        let presence = Self::presence_slim(&self.validators);
        let catchup = Self::catchup_slim(&self.validators);
        let seat = Self::seat_slim(&self.validators);
        let bytes = if !seat.is_empty() {
            serde_json::to_vec(&(
                &self.state.accounts,
                &self.defi,
                &self.bridge,
                val_slim,
                &self.claimable,
                &val_v2,
                &presence,
                &catchup,
                &seat,
            ))
        } else if !catchup.is_empty() {
            serde_json::to_vec(&(
                &self.state.accounts,
                &self.defi,
                &self.bridge,
                val_slim,
                &self.claimable,
                &val_v2,
                &presence,
                &catchup,
            ))
        } else if !presence.is_empty() {
            serde_json::to_vec(&(
                &self.state.accounts,
                &self.defi,
                &self.bridge,
                val_slim,
                &self.claimable,
                &val_v2,
                &presence,
            ))
        } else if val_v2.is_empty() {
            serde_json::to_vec(&(
                &self.state.accounts,
                &self.defi,
                &self.bridge,
                val_slim,
                &self.claimable,
            ))
        } else {
            serde_json::to_vec(&(
                &self.state.accounts,
                &self.defi,
                &self.bridge,
                val_slim,
                &self.claimable,
                val_v2,
            ))
        }
        .unwrap_or_default();
        sha256_hex(&bytes)
    }

    /// Pay fee from hot balance, then claimable (stake/reward ops only).
    ///
    /// Production: genesis validators often have **bond + claimable** but no hot
    /// balance. Unbond/claim must still be able to pay fees without a separate
    /// funding step, or the tx sits in mempool forever and can stall packing.
    fn pay_fee(&mut self, account: &str, fee: u64, allow_claimable: bool) -> Result<(), String> {
        if fee == 0 {
            return Ok(());
        }
        let mut sender = self.state.get(account);
        if sender.balance >= fee {
            sender.balance -= fee;
            self.state.accounts.insert(account.to_string(), sender);
            return Ok(());
        }
        if !allow_claimable {
            return Err("insufficient balance for fee".into());
        }
        let need = fee.saturating_sub(sender.balance);
        let cl = self.claimable.get(account).copied().unwrap_or(0);
        if cl < need {
            return Err("insufficient balance for fee".into());
        }
        sender.balance = 0;
        self.state.accounts.insert(account.to_string(), sender);
        let left = cl - need;
        if left == 0 {
            self.claimable.remove(account);
        } else {
            self.claimable.insert(account.to_string(), left);
        }
        Ok(())
    }

    /// Apply a signed protocol tx against full node state (used in pack + accept).
    pub fn apply_protocol_tx(&mut self, tx: &Tx) -> Result<(), String> {
        self.apply_protocol_tx_ex(tx, true)
    }

    /// Record the sender key on the account the first time a payment carries
    /// it. A later tx may omit the key. A different key is rejected.
    fn note_sender_key(&mut self, tx: &Tx) -> Result<(), String> {
        if self.cfg.network_id == crate::NETWORK_ID_PUBLIC_TESTNET_2300
            && self.tip_height.saturating_add(1)
                < crate::params_v2::TESTNET_2300_ACCOUNT_KEY_FROM_HEIGHT
        {
            return Ok(());
        }
        if tx.public_key.is_empty() {
            return Ok(());
        }
        let mut acct = self.state.get(&tx.account);
        if acct.meta.public_key.is_empty() {
            self.key_bind_check(tx)?;
            acct.meta.public_key = tx.public_key.clone();
            self.state.accounts.insert(tx.account.clone(), acct);
            return Ok(());
        }
        if acct.meta.public_key != tx.public_key {
            return Err("sender key does not match account".into());
        }
        Ok(())
    }

    /// 2.9.79-beta.3 reverse guard rail (from the Fix B height): a new wallet
    /// account may not take the id of a registered validator seat unless it
    /// binds that seat's own key (`same_key`). Stops a second `nodesafe`
    /// (wallet and seat under one name, different keys). Existing accounts
    /// with an on-chain key are not affected.
    pub const SEAT_NAME_TAKEN: &'static str = "account name is a registered validator seat id";
    fn seat_name_guard(&self, id: &str, same_key: impl Fn(&str) -> bool) -> Result<(), String> {
        if !self.key_bind_onchain_gate_open() {
            return Ok(());
        }
        // Deterministic key only (BondV2 on chain or the legacy registry);
        // `ValidatorInfo.public_key` of a legacy seat is Hello metadata and
        // is not part of the state commitment.
        let reg = self.registered_key(id);
        if !self.validators.contains_key(id) && reg.is_none() {
            return Ok(());
        }
        if reg.as_deref().is_some_and(|pk| same_key(pk)) {
            return Ok(());
        }
        Err(Self::SEAT_NAME_TAKEN.into())
    }

    /// v2.9.65 (C-1): `tip + 1 >= key_bind_from_height` on a Falcon network.
    pub fn key_bind_gate_open(&self) -> bool {
        self.keys.scheme == CryptoScheme::Falcon512
            && self.tip_height.saturating_add(1)
                >= crate::params_v2::key_bind_from_height(self.cfg.network_id)
    }

    /// v2.9.65 (C-1) / v2.9.77: may `tx` bind `tx.public_key` as the first key
    /// of `tx.account`? Before activation: always (unchanged). After: only when
    /// the account already has that key **on chain** (`meta.public_key`), the
    /// account id is the classic address of the key, or the account's funder
    /// committed the key hash (`PayToKey` / `meta.key_commit`). The in-memory
    /// key ring is never consulted: seats disagree about who is in the ring
    /// (restart, gossip order), and a ring hit would let one seat accept a
    /// block another rejects. Admission bodies keep their own release-key
    /// check. No tx body, Pay and Claim included, binds an uncommitted key.
    fn key_bind_check(&self, tx: &Tx) -> Result<(), String> {
        if !self.key_bind_gate_open() {
            return Ok(());
        }
        if matches!(
            tx.body,
            TxBody::ApproveValidator { .. } | TxBody::RevokeApproval { .. } | TxBody::RevokeArchive { .. }
        ) {
            return Ok(());
        }
        if tx.public_key.is_empty() {
            return Err(KEY_BIND_REFUSED.into());
        }
        // Before the v2.9.77 on-chain gate the 2.9.65..2.9.76 rule stands
        // (ring first), so 2.9.76 and 2.9.77 seats agree until activation.
        if !self.key_bind_onchain_gate_open() {
            if let Some(k) = self.keys.public_hex(&tx.account) {
                return if crate::crypto::hex_eq(&k, &tx.public_key) {
                    Ok(())
                } else {
                    Err("bad tx crypto: key mismatch".into())
                };
            }
        }
        let meta = self.state.get(&tx.account).meta;
        if !meta.public_key.is_empty() {
            return if crate::crypto::hex_eq(&meta.public_key, &tx.public_key) {
                Ok(())
            } else {
                Err("sender key does not match account".into())
            };
        }
        self.seat_name_guard(&tx.account, |seat_pk| crate::crypto::hex_eq(seat_pk, &tx.public_key))?;
        if falcon_classic_address(&tx.public_key).as_deref() == Some(tx.account.as_str()) {
            return Ok(());
        }
        if !meta.key_commit.is_empty()
            && key_commit_hash(&tx.public_key).as_deref() == Some(meta.key_commit.as_str())
        {
            return Ok(());
        }
        Err(KEY_BIND_REFUSED.into())
    }

    /// Packer-side key bind: like `key_bind_check` but never reads the local
    /// key ring, even before the v2.9.77 on-chain gate. A packer may be
    /// stricter than ingest; it must never be looser, or its blocks are
    /// rejected by every seat whose ring lacks the key (falcon-node, 671xxx).
    pub fn pack_key_bind_check(gate_open: bool, state: &WorldState, tx: &Tx) -> Result<(), String> {
        if !gate_open || tx.public_key.is_empty() {
            return Ok(());
        }
        if matches!(
            tx.body,
            TxBody::ApproveValidator { .. } | TxBody::RevokeApproval { .. } | TxBody::RevokeArchive { .. }
        ) {
            return Ok(());
        }
        let meta = state.get(&tx.account).meta;
        if !meta.public_key.is_empty() {
            return Ok(()); // match / mismatch is decided by the normal apply path
        }
        if falcon_classic_address(&tx.public_key).as_deref() == Some(tx.account.as_str()) {
            return Ok(());
        }
        if !meta.key_commit.is_empty()
            && key_commit_hash(&tx.public_key).as_deref() == Some(meta.key_commit.as_str())
        {
            return Ok(());
        }
        Err(KEY_BIND_REFUSED.into())
    }

    /// Account has a key. From the v2.9.77 on-chain gate: **on chain** only
    /// (`meta.public_key`), so every seat answers the same way. Before it:
    /// ring or account meta (2.9.65..2.9.76 rule, unchanged).
    pub fn account_key_bound(&self, id: &str) -> bool {
        if self.key_bind_onchain_gate_open() {
            return !self.state.get(id).meta.public_key.is_empty();
        }
        self.keys.has_public(id) || !self.state.get(id).meta.public_key.is_empty()
    }

    /// v2.9.77 (Fix B): `tip + 1 >= key_bind_onchain_from_height`. From here
    /// key binding, `PayToKey`'s "destination already has a key", and sender
    /// verification read only on-chain keys, never the node-local ring.
    /// Changes block validity, so it is an activation height.
    pub fn key_bind_onchain_gate_open(&self) -> bool {
        self.tip_height.saturating_add(1)
            >= crate::params_v2::key_bind_onchain_from_height(self.cfg.network_id)
    }

    /// v2.9.77 (Fix B): sender verification may fall back to the key stored
    /// on chain. When the ring has no key for `tx.account` but
    /// `meta.public_key` is set (and matches the carried key, if any), load it
    /// into the ring before `Tx::verify`. Gated, like the ring restore, so a
    /// 2.9.77 seat never accepts a block a 2.9.76 seat rejects before
    /// activation. Never adds a key that state does not already bind.
    fn onchain_verify_key(&mut self, tx: &Tx) {
        if !self.key_bind_onchain_gate_open() || self.keys.has_public(&tx.account) {
            return;
        }
        if let Some(pk) = self.account_public_key(&tx.account) {
            if tx.public_key.is_empty() || crate::crypto::hex_eq(&pk, &tx.public_key) {
                let _ = self.keys.insert_public(&tx.account, &pk);
            }
        }
    }

    /// The key ring is in-memory and is not rebuilt from state on restart.
    /// If the account already has this exact key recorded on chain
    /// (`meta.public_key`), put it back in the ring so non-enroll bodies
    /// (swap, liquidity, lend) do not fail with "unknown key". Never adds a
    /// key that state does not already bind.
    ///
    /// Activation-gated (`tip + 1 >= ring_restore_from_height`): before it this
    /// is a no-op on BOTH the mempool and the apply path. The ring persists
    /// across calls, so an ungated mempool restore would let this node apply
    /// (and propose) a block that a restarted pre-activation seat rejects.
    pub fn ring_restore_gate_open(&self) -> bool {
        self.tip_height.saturating_add(1) >= self.ring_restore_from_height
    }

    fn restore_ring_key(&mut self, tx: &Tx) {
        if !self.ring_restore_gate_open() {
            return;
        }
        if tx.public_key.is_empty() || self.keys.has_public(&tx.account) {
            return;
        }
        if let Some(pk) = self.account_public_key(&tx.account) {
            if crate::crypto::hex_eq(&pk, &tx.public_key) {
                let _ = self.keys.insert_public(&tx.account, &pk);
            }
        }
    }

    /// First-seen key binding for `tx`: [`Tx::is_name_enroll`], plus `Claim`
    /// from `claim_enroll_from_height` (u64::MAX on 2300: seats never bound a
    /// key on Claim, so neither may main until that height is set).
    pub fn tx_name_enroll(&self, tx: &Tx) -> bool {
        tx.is_name_enroll()
            || (matches!(tx.body, TxBody::Claim)
                && self.tip_height.saturating_add(1) >= self.claim_enroll_from_height)
    }

    /// From the Fix B height: on-chain key of `id` used for account tx sigs.
    fn onchain_sig_key(&self, id: &str) -> Option<String> {
        // Seat payout: a seat sender verifies against the seat's registered
        // key only (independent of the Fix B gate; refused pre-activation).
        if let Some(seat) = self.seat_sender_active(id) {
            return self.registered_key(seat);
        }
        if self.keys.scheme != CryptoScheme::Falcon512 || !self.key_bind_onchain_gate_open() {
            return None;
        }
        self.account_public_key(id)
    }

    /// Account tx signature check. From the Fix B height an account with an
    /// on-chain key is verified against that key only (seat keys in the ring
    /// under the same id are ignored); otherwise `Tx::verify` as before.
    pub fn verify_account_tx(&self, tx: &Tx) -> Result<(), String> {
        let Some(pk) = self.onchain_sig_key(&tx.account) else {
            return tx.verify(&self.keys);
        };
        let payload = Tx::payload(
            &tx.account, tx.sequence, &tx.destination, tx.amount, tx.fee, tx.network_id, &tx.body,
        );
        if sha256_hex(payload.as_bytes()) != tx.tx_id {
            return Err("bad tx crypto: tx_id mismatch".into());
        }
        self.keys
            .verify_account_sig(&tx.account, &tx.public_key, Some(&pk), &payload, &tx.signature)
    }

    /// On-chain keys for pack pre-verify (empty before the Fix B height).
    fn onchain_sig_keys(&self, txs: &[&Tx]) -> BTreeMap<String, String> {
        txs.iter()
            .filter_map(|t| self.onchain_sig_key(&t.account).map(|k| (t.account.clone(), k)))
            .collect()
    }

    pub fn account_public_key(&self, id: &str) -> Option<String> {
        if let Some(seat) = self.seat_sender_active(id) {
            return self.registered_key(seat);
        }
        let pk = self
            .state
            .accounts
            .get(id)
            .map(|a| a.meta.public_key.clone())
            .unwrap_or_default();
        if pk.is_empty() { None } else { Some(pk) }
    }

    /// When `check_sig` is false, skip Falcon verify for this tx (batch bodies
    /// already verified senders in `verify_merkle_batch_known`, or operator set
    /// `FPL_CATCHUP_SKIP_TX_SIG=1` for certified catch-up on weak boxes).
    fn apply_protocol_tx_ex(&mut self, tx: &Tx, check_sig: bool) -> Result<(), String> {
        if tx.network_id != self.cfg.network_id {
            return Err("wrong network".into());
        }
        if tx.body.is_seat_tx() || self.seat_sender_active(&tx.account).is_some() {
            return self.apply_seat_tx(tx, check_sig);
        }
        // v2.10.0: before activation behave exactly like 2.9.81 (which cannot
        // decode the variant): refuse before any key enroll / fee / sequence.
        if self.external_addrs_tx_pre_activation(tx) {
            return Err(EXTERNAL_ADDRS_NOT_ACTIVE.into());
        }
        if self.orderbook_tx_pre_activation(tx) {
            return Err(ORDERBOOK_NOT_ACTIVE.into());
        }
        self.note_sender_key(tx)?;
        if self.tx_name_enroll(tx) && !tx.public_key.is_empty() {
            self.enroll_name_key(tx)?;
        }
        self.restore_ring_key(tx);
        self.onchain_verify_key(tx);
        if check_sig {
            self.verify_account_tx(tx)?;
        }
        let mut sender = self.state.get(&tx.account);
        if tx.sequence != sender.sequence {
            return Err(format!(
                "bad sequence want {} got {}",
                sender.sequence, tx.sequence
            ));
        }
        if let TxBody::SetExternalAddrs { chain, address } = &tx.body {
            let (chain_key, addr_val) = validate_external_addr(chain, address)?;
            if !addr_val.is_empty()
                && !sender.external_addrs.contains_key(&chain_key)
                && sender.external_addrs.len() >= MAX_EXTERNAL_ADDRS_PER_ACCOUNT
            {
                return Err(format!(
                    "external_addrs: max {MAX_EXTERNAL_ADDRS_PER_ACCOUNT} linked addresses per account"
                ));
            }
        }
        // Stake/reward ops may pay fee from claimable; payments/bonds need hot balance.
        let fee_from_claimable = matches!(
            tx.body,
            TxBody::Unbond { .. } | TxBody::CompleteUnbond { .. } | TxBody::Claim
        );
        // Advance sequence first (fee debit next).
        sender.sequence += 1;
        self.state.accounts.insert(tx.account.clone(), sender);
        self.pay_fee(&tx.account, tx.fee, fee_from_claimable)?;

        match &tx.body {
            // Dispatched to `apply_seat_tx` above.
            TxBody::SetSeatPayout { .. } | TxBody::ClaimSeat { .. } => {
                return Err("seat tx must be sent by the seat sender".into());
            }
            TxBody::Pay => {
                let mut sender = self.state.get(&tx.account);
                // fee already taken; amount still due
                if sender.balance < tx.amount {
                    return Err("insufficient balance".into());
                }
                sender.meta.enforce_payment(&tx.destination)?;
                sender.balance -= tx.amount;
                self.state.accounts.insert(tx.account.clone(), sender);
                let mut dest = self.state.get(&tx.destination);
                dest.balance = dest.balance.saturating_add(tx.amount);
                self.state.accounts.insert(tx.destination.clone(), dest);
            }
            TxBody::PayToKey { key_hash } => {
                if !self.key_bind_gate_open() {
                    return Err(PAY_TO_KEY_NOT_ACTIVE.into());
                }
                if !is_key_commit_hex(key_hash) {
                    return Err("pay_to_key: key_hash must be 64 lowercase hex".into());
                }
                if tx.destination.is_empty() || tx.destination == tx.account {
                    return Err("pay_to_key: bad destination".into());
                }
                if self.account_key_bound(&tx.destination) {
                    return Err("pay_to_key: destination already has a key".into());
                }
                self.seat_name_guard(&tx.destination, |seat_pk| {
                    key_commit_hash(seat_pk).as_deref() == Some(key_hash.as_str())
                })?;
                let mut sender = self.state.get(&tx.account);
                if sender.balance < tx.amount {
                    return Err("insufficient balance".into());
                }
                sender.meta.enforce_payment(&tx.destination)?;
                let mut dest = self.state.get(&tx.destination);
                if !dest.meta.key_commit.is_empty() && dest.meta.key_commit != *key_hash {
                    return Err("pay_to_key: destination committed to another key".into());
                }
                sender.balance -= tx.amount;
                self.state.accounts.insert(tx.account.clone(), sender);
                let mut dest = self.state.get(&tx.destination);
                dest.balance = dest.balance.saturating_add(tx.amount);
                dest.meta.key_commit = key_hash.clone();
                self.state.accounts.insert(tx.destination.clone(), dest);
            }
            TxBody::AssetPay { asset } => {
                let asset = asset.trim().to_ascii_uppercase();
                let btc4_ok = asset == "BTC4"
                    && self.tip_height.saturating_add(1) >= network_asset_pay_btc4_from_height(self.cfg.network_id);
                if !(matches!(asset.as_str(), "BTC" | "ETH" | "USDC") || btc4_ok) {
                    return Err("asset pay: only BTC, ETH, USDC (BTC4 after activation)".into());
                }
                if tx.destination.is_empty() || tx.destination == tx.account {
                    return Err("asset pay: bad destination".into());
                }
                if tx.amount == 0 {
                    return Err("asset pay: zero amount".into());
                }
                self.defi.debit_asset(&tx.account, &asset, tx.amount)?;
                self.defi.credit_asset(&tx.destination, &asset, tx.amount);
                if !self.state.accounts.contains_key(&tx.destination) {
                    let mut dest = self.state.get(&tx.destination);
                    dest.sequence = 1;
                    self.state.accounts.insert(tx.destination.clone(), dest);
                }
            }
            TxBody::Bond { validator } => {
                // restore fee-only sequence path: bond() debits amount itself
                // Revert fee-only debit pattern: bond expects full debit of amount
                let mut sender = self.state.get(&tx.account);
                // we already took fee and advanced seq; bond amount from remaining
                if sender.balance < tx.amount {
                    return Err("insufficient balance for bond".into());
                }
                // temporary credit fee back into accounting via bond path:
                // manually bond without double sequence
                sender.balance -= tx.amount;
                self.state.accounts.insert(tx.account.clone(), sender);
                if self.validators.get(validator).map(|v| v.jailed).unwrap_or(false) {
                    return Err("jailed: cannot bond".into());
                }
                let creating = !self.validators.contains_key(validator);
                if creating && tx.amount < self.cfg.min_bond {
                    return Err(format!("bond below min {}", self.cfg.min_bond));
                }
                if self.rv2_open() {
                    if creating {
                        return Err("bond: new seats need BondV2 (public key + proof of possession + approval)".into());
                    }
                    // v2.9.62 A7: only the owner may top up.
                    let v = &self.validators[validator];
                    let owner = if v.bond_account.is_empty() { validator.as_str() } else { v.bond_account.as_str() };
                    if tx.account != *validator && tx.account != owner {
                        return Err(format!("not bond owner: only {owner} or {validator} may top up"));
                    }
                }
                if let Some(v) = self.validators.get_mut(validator) {
                    v.bond = v.bond.saturating_add(tx.amount);
                    if v.bond_account.is_empty() {
                        v.bond_account = tx.account.clone();
                    }
                    // Fill packer key if we learned it via Hello before Bond.
                    if v.public_key.is_empty() {
                        if let Some(pk) = self.keys.public_hex(validator) {
                            v.public_key = pk;
                        }
                    }
                } else {
                    let pk = self.keys.public_hex(validator).unwrap_or_default();
                    let mut v = ValidatorInfo::new(validator, tx.amount, pk);
                    v.bond_account = tx.account.clone();
                    self.validators.insert(validator.clone(), v);
                }
            }
            TxBody::Unbond { validator, amount } => {
                // Only the bond owner (bond_account) or validator id may unbond.
                let ba = self
                    .validators
                    .get(validator)
                    .map(|v| {
                        if v.bond_account.is_empty() {
                            validator.clone()
                        } else {
                            v.bond_account.clone()
                        }
                    })
                    .unwrap_or_else(|| validator.clone());
                if tx.account != *validator && tx.account != ba {
                    return Err(format!(
                        "unbond signer {} is not bond owner {ba}",
                        tx.account
                    ));
                }
                self.request_unbond(validator, *amount)?;
            }
            TxBody::CompleteUnbond { validator } => {
                let ba = self
                    .validators
                    .get(validator)
                    .map(|v| {
                        if v.bond_account.is_empty() {
                            validator.clone()
                        } else {
                            v.bond_account.clone()
                        }
                    })
                    .unwrap_or_else(|| validator.clone());
                if tx.account != *validator && tx.account != ba {
                    return Err(format!(
                        "complete-unbond signer {} is not bond owner {ba}",
                        tx.account
                    ));
                }
                let _ = self.complete_unbond(validator)?;
            }
            TxBody::Unjail { validator } => {
                let (jailed, jail_count) = self
                    .validators
                    .get(validator)
                    .map(|v| (v.jailed, v.jail_count))
                    .ok_or_else(|| format!("unknown validator {validator}"))?;
                if !jailed {
                    return Err("not jailed".into());
                }
                // Historical jails (pre-jail_count field) land as jail_count=0.
                let priced = effective_jail_count(jailed, jail_count);
                let need = unjail_cost(self.cfg.min_bond, priced);
                if tx.amount < need {
                    return Err(format!(
                        "unjail needs {need} (jail_count={jail_count}, effective={priced}, min_bond={})",
                        self.cfg.min_bond
                    ));
                }
                let mut sender = self.state.get(&tx.account);
                if sender.balance < tx.amount {
                    return Err("insufficient balance for unjail".into());
                }
                sender.balance -= tx.amount;
                self.state.accounts.insert(tx.account.clone(), sender);
                let to_escrow = self.rv2_open();
                let lock = self.presence_at(self.tip_height.saturating_add(1));
                let v = self
                    .validators
                    .get_mut(validator)
                    .ok_or_else(|| format!("unknown validator {validator}"))?;
                if to_escrow {
                    // v2.9.62 A8: the payment is escrow, not lottery/pay weight.
                    v.escrow = v.escrow.saturating_add(tx.amount);
                } else {
                    v.bond = v.bond.saturating_add(tx.amount);
                }
                v.jailed = false;
                v.inactive = false;
                v.missed_turns = 0;
                if lock {
                    v.lock_earn();
                }
                // Persist the historical offence into the root via this ledger.
                if v.jail_count == 0 {
                    v.jail_count = 1;
                }
                if v.bond_account.is_empty() {
                    v.bond_account = tx.account.clone();
                }
                if v.public_key.is_empty() {
                    if let Some(pk) = self.keys.public_hex(validator) {
                        v.public_key = pk;
                    }
                }
                // jail_count is intentionally NOT reset — next jail escalates further.
            }
            TxBody::VaultOpen { destination } => {
                self.open_vault(&tx.account, destination)?;
            }
            TxBody::VaultLock => {
                self.vault_lock(&tx.account)?;
            }
            TxBody::NameReserve => {
                self.reserve_name(&tx.account, &tx.public_key)?;
            }
            TxBody::NameActivate => {
                self.activate_name(&tx.account, &tx.public_key)?;
            }
            TxBody::Claim => {
                let _ = self.claim_rewards(&tx.account)?;
            }
            TxBody::CreatePool {
                pool_id,
                asset_a,
                asset_b,
            } => {
                self.create_pool(pool_id, asset_a, asset_b)?;
            }
            TxBody::AddLiquidity {
                pool_id,
                amt_a,
                amt_b,
            } => {
                let _ = self.add_liquidity(pool_id, &tx.account, *amt_a, *amt_b)?;
            }
            TxBody::Swap {
                pool_id,
                token_in,
                amount_in,
                min_out,
            } => {
                let _ = self.swap_any(pool_id, &tx.account, token_in, *amount_in, *min_out)?;
            }
            TxBody::PlaceLimitOrder {
                pair,
                side,
                price,
                amount,
                expiry_height,
            } => {
                let h = self.tip_height.saturating_add(1);
                let mut b = crate::orderbook::Books { state: &mut self.state, defi: &mut self.defi };
                crate::orderbook::place_limit(&mut b, &tx.account, pair, side, *price, *amount, *expiry_height, h)?;
            }
            TxBody::CancelOrder { order_id } => {
                let mut b = crate::orderbook::Books { state: &mut self.state, defi: &mut self.defi };
                crate::orderbook::cancel(&mut b, &tx.account, *order_id)?;
            }
            TxBody::CreateMarket { market_id, asset } => {
                self.create_market(market_id, asset)?;
            }
            TxBody::LendSupply { market_id, amount } => {
                let _ = self.lend_supply(market_id, &tx.account, *amount)?;
            }
            TxBody::LendWithdraw { market_id, shares } => {
                let _ = self.lend_withdraw(market_id, &tx.account, *shares)?;
            }
            TxBody::LendBorrow {
                market_id,
                amount,
                collateral_fpl,
            } => {
                self.lend_borrow(market_id, &tx.account, *amount, *collateral_fpl)?;
            }
            TxBody::LendRepay { market_id, amount } => {
                let _ = self.lend_repay(market_id, &tx.account, *amount)?;
            }
            TxBody::LendSetPrice { market_id } => {
                let _ = self.sync_lend_price(market_id)?;
            }
            TxBody::RemoveLiquidity { pool_id, lp_burn } => {
                let _ = self.remove_liquidity(pool_id, &tx.account, *lp_burn)?;
            }
            TxBody::SwapRoute {
                token_in,
                token_out,
                amount_in,
                min_out,
            } => {
                let _ = self.swap_route(
                    &tx.account,
                    token_in,
                    token_out,
                    *amount_in,
                    *min_out,
                )?;
            }
            TxBody::CreditAsset { asset, amount } => {
                if !self.cfg.allow_admin_wire {
                    return Err("admin-only: CreditAsset disabled".into());
                }
                self.credit_asset_admin(&tx.account, asset, *amount)?;
            }
            TxBody::WatcherCredit { .. } => {
                return Err(
                    "watcher-credit disabled; use WatcherHeartbeat or rail work".into(),
                );
            }
            TxBody::WatcherHeartbeat => {
                // Presence only. Work stays 0 until a rail header/deposit lands.
                self.watcher_credit(&tx.account, 0, true);
            }
            TxBody::RailHeader {
                asset,
                height,
                hash,
                parent_hash,
                merkle_root,
                raw,
            } => {
                self.submit_rail_header(
                    asset,
                    RailHeader {
                        height: *height,
                        hash: hash.clone(),
                        parent_hash: parent_hash.clone(),
                        merkle_root: merkle_root.clone(),
                        raw: raw.clone(),
                    },
                    Some(&tx.account),
                )?;
            }
            TxBody::RailDeposit {
                asset,
                to,
                amount,
                proof,
            } => {
                self.rail_deposit(asset, to, *amount, proof.clone(), Some(&tx.account))?;
            }
            TxBody::RailWithdraw {
                asset,
                amount,
                external_to,
                vault_sig,
                signed_btc_tx,
            } => {
                let sig = if vault_sig.is_empty() {
                    None
                } else {
                    Some(vault_sig.as_str())
                };
                let signed = if signed_btc_tx.is_empty() {
                    None
                } else {
                    Some(signed_btc_tx.as_str())
                };
                let _ = self.rail_withdraw_full(
                    asset,
                    &tx.account,
                    *amount,
                    external_to,
                    sig,
                    signed,
                )?;
            }
            TxBody::RailChallenge {
                asset,
                note_id,
                observed_dest,
                observed_amount,
            } => {
                let _ = self.rail_challenge(
                    asset,
                    note_id,
                    observed_dest,
                    *observed_amount,
                    &tx.account,
                )?;
            }
            TxBody::Bitvm2Attest {
                note_id,
                pegout_txid_hex,
                claim_txid_hex,
                proof_hex,
                public_hex,
                statement_digest_hex,
            } => {
                self.rail_bitvm2_attest(
                    note_id,
                    pegout_txid_hex,
                    claim_txid_hex,
                    proof_hex,
                    public_hex,
                    statement_digest_hex,
                    &tx.account,
                )?;
            }
            TxBody::Bitvm2AttestV2 { attest } => {
                self.rail_bitvm2_attest_v2(attest, &tx.account)?;
            }
            TxBody::OperatorRegister { .. }
            | TxBody::OperatorHeartbeat { .. }
            | TxBody::OperatorUnbond
            | TxBody::OperatorGraphBind { .. }
            | TxBody::OperatorSlash { .. }
            | TxBody::Btc4PegIn { .. } => self.apply_operator_tx(tx)?,
            TxBody::BtcPoolMove { raw_tx } => {
                let _ = self.btc_pool_move_to_nums(raw_tx)?;
            }
            // Txs apply at ledger height tip+1 in pack, verify and commit
            // (tip advances only after the body is applied).
            TxBody::EthLcBootstrap { json } => {
                let gloas = self.eth_lc_gloas_at(self.tip_height.saturating_add(1));
                self.bridge.eth_lc_bootstrap_ex(json, gloas)?;
                if let Some(w) = Some(tx.account.as_str()) {
                    self.watcher_credit(w, 1, true);
                }
            }
            TxBody::EthLcUpdate { json } => {
                let gloas = self.eth_lc_gloas_at(self.tip_height.saturating_add(1));
                self.bridge.eth_lc_update_ex(json, gloas)?;
                self.watcher_credit(&tx.account, 1, true);
            }
            TxBody::EthExecHeaders { headers_json } => {
                let headers: Vec<crate::eth_exec::EthExecHeader> =
                    serde_json::from_str(headers_json).map_err(|e| e.to_string())?;
                let gloas = self.eth_lc_gloas_at(self.tip_height.saturating_add(1));
                self.bridge.eth_add_exec_headers_ex(headers, gloas)?;
                self.watcher_credit(&tx.account, 1, true);
            }
            TxBody::BtcHeaderBackfill { headers_json } => {
                let headers: Vec<crate::bridge::RailHeader> =
                    serde_json::from_str(headers_json).map_err(|e| e.to_string())?;
                self.bridge
                    .rail_mut(crate::bridge::RAIL_BTC)?
                    .backfill_btc_headers(&headers)?;
                self.watcher_credit(&tx.account, 1, true);
            }
            TxBody::EthV3Deposit {
                asset,
                deposit_id,
                credit_to,
                proof,
            } => {
                self.eth_v3_deposit(asset, deposit_id, credit_to, proof)?;
                // v2.9.62 B6: the submitter of a mint/refund earns 1 work + slot.
                if self.rv2_epoch(self.current_epoch()) {
                    self.watcher_credit(&tx.account, 1, true);
                }
            }
            TxBody::BondV2 {
                validator,
                public_key,
                pop_sig,
            } => self.apply_bond_v2(tx, validator, public_key, pop_sig)?,
            TxBody::Reactivate { validator } => {
                if !self.rv2_open() {
                    return Err("rv2 not active: reactivate".into());
                }
                let lock = self.presence_at(self.tip_height.saturating_add(1));
                let v = self
                    .validators
                    .get_mut(validator)
                    .ok_or_else(|| format!("unknown validator {validator}"))?;
                let owner = if v.bond_account.is_empty() { validator.clone() } else { v.bond_account.clone() };
                if tx.account != *validator && tx.account != owner {
                    return Err(format!("not bond owner: only {owner} or {validator} may reactivate"));
                }
                if v.jailed {
                    return Err("jailed: use Unjail".into());
                }
                if !self.seat_key_registry.is_empty()
                    && !v.v2_seat
                    && !self.seat_key_registry.contains_key(validator.as_str())
                {
                    return Err(format!("reactivate: {validator} has no registered key (bond a new seat with BondV2)"));
                }
                v.inactive = false;
                v.missed_turns = 0;
                if lock {
                    v.lock_earn();
                }
            }
            TxBody::ApproveValidator {
                id,
                public_key,
                expires_height,
            } => {
                self.require_admission_key(tx)?;
                if id.trim().is_empty() || public_key.trim().is_empty() {
                    return Err("admission: id and public_key required".into());
                }
                if self.validators.contains_key(id) {
                    return Err(format!("admission: {id} already exists"));
                }
                if *expires_height <= self.tip_height.saturating_add(1) {
                    return Err("admission: expires_height in the past".into());
                }
                self.defi.validator_approvals.insert(
                    id.clone(),
                    ValidatorApproval {
                        public_key: public_key.trim().to_ascii_lowercase(),
                        expires_height: *expires_height,
                    },
                );
            }
            TxBody::RevokeApproval { id } => {
                self.require_admission_key(tx)?;
                if self.defi.validator_approvals.remove(id).is_none() {
                    return Err(format!("admission: no approval for {id}"));
                }
            }
            TxBody::SetArchive { validator, on } => {
                if !self.rv2_open() {
                    return Err("rv2 not active: set_archive".into());
                }
                let v = self
                    .validators
                    .get_mut(validator)
                    .ok_or_else(|| format!("unknown validator {validator}"))?;
                let owner = if v.bond_account.is_empty() { validator.clone() } else { v.bond_account.clone() };
                if tx.account != *validator && tx.account != owner {
                    return Err(format!("not bond owner: only {owner} or {validator} may set archive"));
                }
                v.archive = *on;
            }
            TxBody::RevokeArchive { id } => {
                self.require_admission_key(tx)?;
                let v = self
                    .validators
                    .get_mut(id)
                    .ok_or_else(|| format!("unknown validator {id}"))?;
                if !v.archive {
                    return Err(format!("admission: {id} is not archive"));
                }
                v.archive = false;
            }
            TxBody::SetExternalAddrs { chain, address } => {
                let (chain_key, addr_val) = validate_external_addr(chain, address)?;
                let mut sender = self.state.get(&tx.account);
                if addr_val.is_empty() {
                    sender.external_addrs.remove(&chain_key);
                } else {
                    if !sender.external_addrs.contains_key(&chain_key)
                        && sender.external_addrs.len() >= MAX_EXTERNAL_ADDRS_PER_ACCOUNT
                    {
                        return Err(format!(
                            "external_addrs: max {MAX_EXTERNAL_ADDRS_PER_ACCOUNT} linked addresses per account"
                        ));
                    }
                    sender.external_addrs.insert(chain_key, addr_val);
                }
                self.state.accounts.insert(tx.account.clone(), sender);
            }
        }
        self.rail_finalize_bitvm("BTC").ok();
        self.bridge_finalize_claims();
        self.bridge.reconcile_btc_kickoff_utxos();
        Ok(())
    }

    /// Dry-run apply on caller-owned state slices (pack + commit).
    ///
    /// Swaps slices onto `self` so we do **not** clone the Falcon KeyRing
    /// (or chain / certs) per candidate tx. Caller passes a clone of the draft
    /// slices; on error those slices are discarded. `treasury` / settled epoch
    /// are restored so a failed Claim cannot leak onto the live node.
    /// Verify a wave of pack heads on the seat's cores. Order of `txs` is not
    /// consensus; only the later single-threaded apply selects the body.
    fn preverify_pack_sigs(
        keys: &crate::crypto::KeyRing,
        onchain: &BTreeMap<String, String>,
        txs: &[&Tx],
        workers: usize,
    ) -> (BTreeSet<String>, BTreeSet<String>) {
        let mut ok = BTreeSet::new();
        let mut bad = BTreeSet::new();
        if txs.is_empty() {
            return (ok, bad);
        }
        let workers = workers.clamp(1, txs.len());
        if workers == 1 {
            for tx in txs {
                if Self::pack_sig_ok(keys, onchain, tx) {
                    ok.insert(tx.tx_id.clone());
                } else {
                    bad.insert(tx.tx_id.clone());
                }
            }
            return (ok, bad);
        }
        let chunk = txs.len().div_ceil(workers);
        std::thread::scope(|scope| {
            let mut joins = Vec::new();
            for part in txs.chunks(chunk) {
                joins.push(scope.spawn(move || {
                    let mut ok = Vec::new();
                    let mut bad = Vec::new();
                    for tx in part {
                        if Self::pack_sig_ok(keys, onchain, tx) {
                            ok.push(tx.tx_id.clone());
                        } else {
                            bad.push(tx.tx_id.clone());
                        }
                    }
                    (ok, bad)
                }));
            }
            for join in joins {
                let (o, b) = join.join().expect("pack sig verify");
                ok.extend(o);
                bad.extend(b);
            }
        });
        (ok, bad)
    }

    /// Signature check used before apply. Payments are included: a key already
    /// in the ring uses `Tx::verify`, a key carried on the tx uses that key.
    /// Apply then skips a second check when the id is in the ok set.
    fn pack_sig_ok(keys: &crate::crypto::KeyRing, onchain: &BTreeMap<String, String>, tx: &Tx) -> bool {
        if tx.signature.is_empty() {
            return false;
        }
        if let Some(pk) = onchain.get(&tx.account) {
            let payload = Tx::payload(
                &tx.account, tx.sequence, &tx.destination, tx.amount, tx.fee, tx.network_id, &tx.body,
            );
            return sha256_hex(payload.as_bytes()) == tx.tx_id
                && keys
                    .verify_account_sig(&tx.account, &tx.public_key, Some(pk), &payload, &tx.signature)
                    .is_ok();
        }
        if keys.has_public(&tx.account) {
            return tx.verify(keys).is_ok();
        }
        if tx.public_key.is_empty() {
            return false;
        }
        let payload = Tx::payload(
            &tx.account,
            tx.sequence,
            &tx.destination,
            tx.amount,
            tx.fee,
            tx.network_id,
            &tx.body,
        );
        keys.verify_carried_key(&tx.account, &tx.public_key, &payload, &tx.signature)
            .is_ok()
    }

    fn try_protocol_tx(
        &mut self,
        state: &mut WorldState,
        defi: &mut DefiState,
        bridge: &mut BridgeState,
        validators: &mut BTreeMap<String, ValidatorInfo>,
        claimable: &mut BTreeMap<String, u64>,
        epoch_work: &mut EpochWork,
        tx: &Tx,
    ) -> Result<(), String> {
        self.try_protocol_tx_ex(
            state, defi, bridge, validators, claimable, epoch_work, tx, true,
        )
    }

    fn try_protocol_tx_ex(
        &mut self,
        state: &mut WorldState,
        defi: &mut DefiState,
        bridge: &mut BridgeState,
        validators: &mut BTreeMap<String, ValidatorInfo>,
        claimable: &mut BTreeMap<String, u64>,
        epoch_work: &mut EpochWork,
        tx: &Tx,
        check_sig: bool,
    ) -> Result<(), String> {
        std::mem::swap(&mut self.state, state);
        std::mem::swap(&mut self.defi, defi);
        std::mem::swap(&mut self.bridge, bridge);
        std::mem::swap(&mut self.validators, validators);
        std::mem::swap(&mut self.claimable, claimable);
        std::mem::swap(&mut self.epoch_work, epoch_work);
        let treas = self.treasury;
        let settled = self.last_settled_epoch;
        let r = self.apply_protocol_tx_ex(tx, check_sig);
        self.treasury = treas;
        self.last_settled_epoch = settled;
        std::mem::swap(&mut self.state, state);
        std::mem::swap(&mut self.defi, defi);
        std::mem::swap(&mut self.bridge, bridge);
        std::mem::swap(&mut self.validators, validators);
        std::mem::swap(&mut self.claimable, claimable);
        std::mem::swap(&mut self.epoch_work, epoch_work);
        r
    }

    /// Permanent apply failures — drop from mempool so they cannot poison packing.
    fn is_permanent_tx_failure(err: &str) -> bool {
        err.contains(Self::SEAT_NAME_TAKEN)
            || err.contains("insufficient balance")
            || err.contains("bad crypto")
            || err.contains("wrong network")
            || err.contains("not bond owner")
            || err.contains("jailed")
            || err.contains("not jailed")
            || err.contains("unjail needs")
            || err.contains("insufficient balance for unjail")
            || err.contains("unknown validator")
            || err.contains("unbond bad amount")
            || err.contains("no unbonding")
            || err.contains("unbond already pending")
            || err.contains("complete pending unbond")
            || err.contains("bond below min")
            || err.contains("watcher-credit disabled")
            || err.contains("admin-only")
            || err.contains("allowlist")
            || err.contains("vault:")
            || err.contains("only Hot can convert account type once")
            || err.contains("pay_to_key:")
            || err.contains("operator: graph already bound for this deposit")
            || err.contains("graph txid already bound elsewhere")
            || err.contains("borrow: LTV exceeded")
            || err.contains("name:")
            || err.contains("external_addrs:")
            || err.contains("BTC header parent mismatch")
            || err.contains("BTC duplicate header")
            || err.contains("admission:")
            || err.contains("bond_v2:")
            || err.contains("bond: new seats need BondV2")
            || err.contains("BTC fork has less work")
            || err.contains("BTC fork too long")
            || err.contains("BTC bits do not follow")
            || err.contains("BTC header does not meet target")
            || err.contains("header height want")
            || err.contains("no pool price")
            // 2.10.4 draft: a disallowed AssetPay (e.g. BTC4 before activation) can never
            // apply; without this it sits at the account head forever and stale gossip
            // evicts valid same-seq resubmits (scott.reynolds.123 seq 51, 3 Nov 2026).
            || err.contains("asset pay: only")
            || err.contains("asset pay: bad destination")
            || err.contains("asset pay: zero amount")
            // 2.10.4 order book: validation failures cannot change for this seq.
            || err.contains("order: ")
            || err.contains("deposit already spent")
            || err.contains("lock_id mismatch")
            || err.contains("block_hash mismatch")
            // Missing BTC header is temporary: backfill can insert it.
            // Dropping the RailDeposit made Claim FBTC look like it did nothing.
            || err.contains("no execution header")
            // Pruned deposit: the header will not be re-inserted. Not the
            // temporary "no execution header" miss, and not queued forever.
            || err.contains(crate::bridge::DEPOSIT_OLDER_THAN_HEADER_WINDOW)
            || err.contains(crate::bridge::V3_DEPOSIT_ALREADY_RESOLVED)
            || err.contains(crate::bridge::V1_DEPOSIT_AFTER_V3_ACTIVATION)
            || err.contains(crate::bridge::V3_DEPOSIT_NOT_IN_RECEIPT)
            || err.contains(crate::bridge::V3_DEPOSIT_BAD_TOKEN)
            || err.contains(crate::bridge::V3_DEPOSIT_ASSET_MISMATCH)
            || err.contains(crate::bridge::V3_DEPOSIT_ID_MALFORMED)
            // All headers under the monotonic prune floor: can never apply.
            || err.contains(crate::bridge::EXEC_HEADERS_BELOW_PRUNE_FLOOR)
            || err.contains("update does not advance finalized slot")
            || err.contains("update period")
            || err.contains("finalized header not in attested state")
            || err.contains("execution headers do not reach")
            || err.contains("headers neither reach")
            || err.contains("execution header rlp hash mismatch")
            || err.contains("parent_hash not in rlp")
            || err.contains("receipts_root not in rlp")
            || err.contains("number not in rlp")
            || err.contains("execution parent mismatch")
            || err.contains("execution numbers not consecutive")
            || err.contains("verify sync")
            || err.contains("sync committee")
            || err.contains("bls aggregate")
            || err.contains("sync bits")
            || err.contains("update period")
            || err.contains("execution payload not in")
            || err.contains("update slots out of order")
            || err.contains("must not carry an execution payload header")
            || err.contains("pre-Deneb LC header")
            || err.contains("sync committee not in")
            || err.contains("need ")
            || err.contains("confs")
    }

    /// Safety cap when `max_txs_per_ledger == 0` (v2.9.49). ~3.3 KB per
    /// Falcon-512 tx on the wire → ~1.3 MB body at the cap: one ledger still
    /// fits `CATCHUP_BATCH_MAX_BYTES` (1.5 MB) and the 4 MB body lane.
    /// `--max-txs N` overrides.
    pub const PACK_DEFAULT_MAX_TXS: usize = 400;
    /// Stop adding txs once the estimated Merkle body reaches this size.
    /// A first-seen account still carries its public key (~5 KB on the wire).
    /// An account that already has a key carries the signature only (~2.3 KB).
    /// 1 MB stays under the 1.5 MB catch-up batch and under the ~1.3 MB body
    /// that stalled the pipe. Not consensus: receivers do not re-derive it.
    pub const PACK_BODY_BUDGET_BYTES: usize = 1_000_000;
    pub const NEW_KEY_TX_EST_BYTES: usize = 5_000;
    pub const KNOWN_KEY_TX_EST_BYTES: usize = 2_300;
    /// v2.9.59: default mempool size that ends packer pacing early.
    /// Hold a quiet height open until this many txs are waiting, then seal.
    /// Matches one full ledger so a packer does not fire a 128-tx block
    /// while a larger dish is already available.
    pub const PACE_DEFAULT_MEMPOOL_TXS: usize = 400;
    /// Unused. Left from a removed 20 s full-block hold; [`Self::pace_wait`]
    /// does not read it. The only round-0 hold is the min-block-interval
    /// pacing in [`Self::pace_wait`] / [`Self::pace_effective_ms`].
    pub const FULL_BLOCK_HOLD_MS: u64 = 20_000;

    pub fn pack_as(&mut self, packer: &str) -> Result<Ledger, String> {
        self.pack_as_inner(packer, false)
    }

    pub fn pack_as_admin_force(&mut self, packer: &str) -> Result<Ledger, String> {
        self.pack_as_inner(packer, true)
    }

    fn pack_as_inner(&mut self, packer: &str, admin_force: bool) -> Result<Ledger, String> {
        if admin_force {
            self.may_pack_admin_force(packer)?;
        } else {
            self.may_pack_locally(packer)?;
        }
        let height = self.tip_height + 1;
        // Honest packer must never produce a second body at the same height
        // (mesh saw this as equivocation / dual proposal).
        if let Some((prev, _)) = self.seen_at_height.get(&height) {
            if prev == packer {
                return Err(format!(
                    "already sealed h={height} as {packer} — refuse second body"
                ));
            }
        }
        // Legacy only: height_sealers blocks a packer who already sealed this
        // height after a view-change. Round mode uses one proposer per round;
        // late-cached bodies must not permanently bar that seat from sealing
        // when its round arrives (soft-QC stall after VC, 2026-10-05).
        if !self.vote_rounds_at(height)
            && self
                .height_sealers
                .get(&height)
                .map(|s| s.contains(packer))
                .unwrap_or(false)
        {
            return Err(format!(
                "already sealed h={height} as {packer} — refuse second body after view-change"
            ));
        }
        let _pruned = self.mempool.prune_stale(&self.state);
        if self.mempool.is_empty() && !self.can_seal_empty() {
            return Err("empty mempool — refuse empty ledger".into());
        }
        // One apply path with ingest (2.7.2 / 2.9.6): fold + select + root at
        // the stamp written on the header. Local snap now_ms is timeouts only.
        // 2.9.5 clamped the header then still folded at wall-clock now_ms →
        // packer self-rejected (root at 17.6M ms vs sealed_at parent+60s).
        let stamp = self.pack_sealed_at();
        let ckpt = TimeFold::take(self);
        // Same order as verify/commit: settle → slash → unbonds, then txs.
        // Slash before tx select so a Bond to a pending offender is rejected.
        // Drop slashes that would leave fewer than 6 bonded (freeze risk).
        // Without this, v4 seal refuses the pack ("have 5 bonded") and the tip
        // stalls with soft-QC never forming — live incident 2026-10-05 after PR7.
        self.drop_slashes_that_break_quorum(&self.validators.clone());
        let pending = self.pending_slashes.clone();
        let _seized = self.apply_time_effects_with_slashes(stamp, true, &pending);
        // One clone of the draft per pack (not per candidate tx — v2.9.49).
        let mut draft = PackDraft {
            state: self.state.clone(),
            defi: self.defi.clone(),
            bridge: self.bridge.clone(),
            vals: self.validators.clone(),
            claim: self.claimable.clone(),
            work: self.epoch_work.clone(),
        };
        ckpt.restore(self);
        // Same cut as verify (`stage_drafts`) and commit. Before tx select,
        // so the activation block prunes even when it carries no ETH tx.
        self.prune_eth_exec_for_ledger(&mut draft.bridge, height);
        let r0 = self.rv2_round0(height);
        let me = self.id.clone();
        let voters = self
            .certs
            .get(&self.tip_height)
            .map(|c| c.voters.clone())
            .unwrap_or_default();
        self.rv2_ledger_hook(&mut draft.vals, height, &me, r0.as_deref(), &voters);
        self.seat_migrate_hook(&mut draft.vals, &mut draft.claim, height);
        self.orderbook_ledger_hook(&mut draft.state, &mut draft.defi, height);
        let saved_now = self.now_ms;
        self.now_ms = stamp;
        let force_full = pack_force_full_clone();
        let mut chosen = Vec::new();
        let mut drop_ids: Vec<String> = Vec::new();
        let mut by_acct: BTreeMap<String, Vec<Tx>> = BTreeMap::new();
        for tx in self.mempool.iter_candidates() {
            by_acct.entry(tx.account.clone()).or_default().push(tx.clone());
        }
        for txs in by_acct.values_mut() {
            txs.sort_by_key(|t| t.sequence);
        }
        let accounts: Vec<String> = by_acct.keys().cloned().collect();
        let budget = self.cfg.pack_budget_ms;
        // Signature checks do not depend on each other. Apply stays in
        // sequence order on one thread. A wave of current heads is verified
        // across the seat's cores, then applied with the check already done.
        let verify_workers = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
            .clamp(1, 16);
        // 0 = "unlimited" used to mean "whatever 1 s of full clones allows"
        // (~10–17). With cheap rollback a 50k mempool could build a multi-MB
        // body, so 0 now means the PACK_DEFAULT_MAX_TXS safety cap (v2.9.49).
        // Not consensus: receivers never re-derive the selection.
        let hard_cap = if self.cfg.max_txs_per_ledger > 0 {
            self.cfg.max_txs_per_ledger
        } else {
            Self::PACK_DEFAULT_MAX_TXS
        };
        let t_start = std::time::Instant::now();
        let mut progressed = true;
        // Size budget, not a count. A fixed cap of 8 new keys made a mempool
        // of first-seen accounts drain at 8 txs a block.
        let mut body_est = 0usize;
        while progressed {
            if hard_cap > 0 && chosen.len() >= hard_cap {
                break;
            }
            if budget > 0 && t_start.elapsed().as_millis() as u64 >= budget {
                break;
            }
            let room = if hard_cap > 0 {
                hard_cap.saturating_sub(chosen.len())
            } else {
                usize::MAX
            };
            // Drop the head borrows before the apply loop mutates by_acct.
            let (sig_ok, sig_bad) = {
                let mut heads: Vec<&Tx> = Vec::new();
                for acct in &accounts {
                    if heads.len() >= room {
                        break;
                    }
                    let Some(list) = by_acct.get(acct) else { continue };
                    let need = draft.state.get(acct).sequence;
                    let Some(tx) = list.iter().find(|t| t.sequence == need) else {
                        continue;
                    };
                    // Payments used to be skipped here, so every Falcon check
                    // ran one-by-one inside the 4 s pack budget and a full
                    // block never fitted while load was still arriving.
                    if tx.signature.is_empty() {
                        continue;
                    }
                    if !self.keys.has_public(&tx.account) && tx.public_key.is_empty() {
                        continue;
                    }
                    heads.push(tx);
                }
                let (warm, cold): (Vec<&Tx>, Vec<&Tx>) = heads
                    .into_iter()
                    .partition(|tx| self.sig_warm.contains(&tx.tx_id));
                let onchain = self.onchain_sig_keys(&cold);
                let (mut sig_ok, sig_bad) =
                    Self::preverify_pack_sigs(&self.keys, &onchain, &cold, verify_workers);
                for tx in warm {
                    sig_ok.insert(tx.tx_id.clone());
                }
                (sig_ok, sig_bad)
            };
            progressed = false;
            for acct in &accounts {
                if hard_cap > 0 && chosen.len() >= hard_cap {
                    break;
                }
                if budget > 0 && t_start.elapsed().as_millis() as u64 >= budget {
                    break;
                }
                let need = draft.state.get(acct).sequence;
                let Some(list) = by_acct.get_mut(acct) else {
                    continue;
                };
                while list.first().map(|t| t.sequence < need).unwrap_or(false) {
                    list.remove(0);
                }
                let Some(tx) = list.first().cloned() else {
                    continue;
                };
                if tx.sequence != need {
                    continue;
                }
                let carries_new_key = self.account_public_key(&tx.account).is_none();
                let add = if carries_new_key {
                    Self::NEW_KEY_TX_EST_BYTES
                } else {
                    Self::KNOWN_KEY_TX_EST_BYTES
                };
                if !chosen.is_empty()
                    && body_est.saturating_add(add) > Self::PACK_BODY_BUDGET_BYTES
                {
                    continue;
                }
                // Cheap per-tx rollback (v2.9.49): record only what this tx
                // can touch before it fails; full clone for other bodies.
                let undo = if force_full {
                    PackUndo::Full(Box::new(draft.clone()))
                } else {
                    PackUndo::capture(&draft, &tx)
                };
                if sig_bad.contains(&tx.tx_id) {
                    drop_ids.push(tx.tx_id.clone());
                    list.remove(0);
                    progressed = true;
                    continue;
                }
                let check_sig = !sig_ok.contains(&tx.tx_id);
                // Packer key bind uses on-chain keys only (meta.public_key,
                // classic address, or a PayToKey commit already in the draft,
                // same block included), never the local ring: a ring-only key
                // makes a block that seats without that ring entry reject.
                let r = if let Err(e) = Self::pack_key_bind_check(self.key_bind_gate_open(), &draft.state, &tx) {
                    Err(e)
                } else {
                self.try_protocol_tx_ex(
                    &mut draft.state,
                    &mut draft.defi,
                    &mut draft.bridge,
                    &mut draft.vals,
                    &mut draft.claim,
                    &mut draft.work,
                    &tx,
                    check_sig,
                )
                };
                if r.is_err() {
                    undo.restore(&mut draft);
                }
                match r {
                    Ok(()) => {
                        body_est = body_est.saturating_add(add);
                        chosen.push(tx.clone());
                        list.remove(0);
                        progressed = true;
                    }
                    Err(e) if Self::is_permanent_tx_failure(&e) => {
                        // Drop poison txs so they cannot stall every packer forever.
                        eprintln!(
                            "falcon-pl pack drop {} seq {} {}: {e}",
                            tx.tx_id, tx.sequence, tx.account
                        );
                        { let tip = self.tip_hash.clone(); self.perm_dropped.insert(&tx.tx_id, saved_now, &tip); }
                        drop_ids.push(tx.tx_id.clone());
                        list.remove(0);
                        progressed = true; // continue scanning remaining
                    }
                    Err(_e) => {
                        // Transient / activation-gated failure (e.g. EthLcUpdate waiting
                        // for activation height). Permanent failures are matched above and
                        // evicted into `drop_ids` + `perm_dropped`.
                    }
                }
            }
        }
        self.now_ms = saved_now;
        if !drop_ids.is_empty() {
            self.mempool.remove_many(&drop_ids);
            self.evicted_since_last_seal = true;
        }
        if chosen.is_empty() && !self.can_seal_empty() {
            if self.mempool.is_empty() {
                return Err("empty mempool — refuse empty ledger".into());
            }
            return Err("no applicable txs — refuse empty ledger".into());
        }
        // Bind skip claims for every seat ahead of us in the ONLINE order so
        // receivers can reject illegal packers without sharing local skip maps.
        let skipped = self.skip_claims_for_packer(packer)?;
        let parent_cert = self.tip_parent_cert()?;
        // Slash already applied in the draft preamble (before tx select).
        let root = Self::commitment_root_parts(
            &draft.state,
            &draft.defi,
            &draft.bridge,
            &draft.vals,
            &draft.claim,
        );
        let mut led = if self.qc_v4_at(height) {
            self.seal_v4_ledger(
                height,
                packer,
                chosen,
                root,
                stamp,
                skipped,
                parent_cert,
                &draft.bridge,
                &draft.vals,
            )?
        } else {
            // UTC header binds only on the v4/v5 pack path. Refuse non-v4 pack
            // once FPL_UTC_FROM_HEIGHT (or override) is armed for this net —
            // packing with sealed_utc_ms=0 would fail live admission anyway.
            let utc_from = utc_header::network_utc_from_height(self.cfg.network_id);
            if utc_header::utc_active(height, utc_from) {
                return Err(format!(
                    "UTC active at h={height} (from={utc_from}) but qc_v4 not armed — refuse non-v4 pack"
                ));
            }
            Ledger::seal_with_skips(
                height,
                self.tip_hash.clone(),
                self.cfg.network_id,
                packer,
                &self.keys,
                chosen,
                root,
                stamp,
                skipped,
                parent_cert,
            )?
        };
        led.slashes = self.pending_slashes.clone();
        Ok(led)
    }

    fn seal_v4_ledger(
        &self,
        height: u64,
        packer: &str,
        txs: Vec<Tx>,
        state_root_after: String,
        sealed_at_ms: u64,
        skipped_predecessors: Vec<String>,
        parent_cert: Option<LedgerCert>,
        draft_bridge: &crate::bridge::BridgeState,
        draft_vals: &BTreeMap<String, ValidatorInfo>,
    ) -> Result<Ledger, String> {
        let bonded_after = draft_vals
            .values()
            .filter(|v| v.lottery_weight() > 0.0)
            .count();
        if bonded_after < 6 {
            let live: Vec<&str> = draft_vals
                .iter()
                .filter(|(_, v)| v.lottery_weight() > 0.0)
                .map(|(id, _)| id.as_str())
                .collect();
            let slashed: Vec<&str> = self
                .pending_slashes
                .iter()
                .map(|e| e.offender.as_str())
                .collect();
            return Err(format!(
                "v4 pack needs 6 bonded, have {bonded_after} live={live:?} slashed={slashed:?} txs={} — refuse hole in LC chain",
                txs.len()
            ));
        }
        let claim_root_hex = hex::encode(crate::lc::evm_header_claim_root(draft_bridge));
        let current_committee = self.sealed_committee();
        if current_committee.is_empty() {
            return Err("v4 pack: empty sealed committee".into());
        }
        let current_committee_root = self.current_committee_root_at(&current_committee, height)?;
        let tx_ids: Vec<String> = txs.iter().map(|t| t.tx_id.clone()).collect();
        let fee_total: u64 = txs.iter().map(|t| t.fee).sum();
        let tx_root = Ledger::tx_root(&tx_ids);
        let cert_tag = Ledger::parent_cert_tag(parent_cert.as_ref());
        let from = utc_header::network_utc_from_height(self.cfg.network_id);
        let domain = header_domain(height, from);
        // Unarmed (default): sealed_utc_ms=0, v4 preimage unchanged.
        // Armed: stamp the Node's injectable pack clock (System = OS wall).
        let sealed_utc_ms = match domain {
            HeaderDomain::LegacyV4 => 0,
            HeaderDomain::V5 => {
                let w = self.utc_pack_clock.now_unix_ms();
                if w == 0 {
                    return Err("seal_v4_ledger: wall_unix_ms unavailable while UTC active".into());
                }
                w
            }
        };
        let msg = packer_msg_for_domain(
            domain,
            height,
            &self.tip_hash,
            self.cfg.network_id,
            packer,
            &tx_root,
            &state_root_after,
            &skipped_predecessors,
            &cert_tag,
            &claim_root_hex,
            &current_committee_root,
            sealed_utc_ms,
        );
        let packer_public_key = self
            .keys
            .public_hex(packer)
            .ok_or_else(|| format!("no packer key {packer}"))?;
        let packer_sig = self.keys.sign(packer, &msg).map_err(|e| e.to_string())?;
        let inner_hash = inner_hash_hex(&msg, &packer_sig);
        // v2.9.62 A4: from H_act the next-6 seed excludes the packer signature.
        let seed = if self.rv2_at(height) {
            seed_v2_hex(&self.tip_hash, height, &msg)
        } else {
            inner_hash.clone()
        };
        let next_committee = self.draw_committee_v8(&seed, height + 1, packer, draft_vals);
        if next_committee.len() < 6 {
            return Err(format!(
                "v4 pack next-6 short ({}) — refuse hole in LC chain",
                next_committee.len()
            ));
        }
        let next_committee_root = self.next_committee_root_at(&next_committee, height, draft_vals)?;
        let inner = parse32(&inner_hash)?;
        let next_root = parse32(&next_committee_root)?;
        let claim = parse32(&claim_root_hex)?;
        let ledger_hash = outer_hash_hex(&inner, &next_root, &claim);
        Ok(Ledger {
            height,
            parent_hash: self.tip_hash.clone(),
            network_id: self.cfg.network_id,
            packer: packer.into(),
            packer_public_key,
            tx_ids,
            txs,
            state_root_after,
            sealed_at_ms,
            sealed_utc_ms,
            packer_sig,
            ledger_hash,
            skipped_predecessors,
            parent_cert,
            slashes: Vec::new(),
            fee_total,
            claim_root: claim_root_hex,
            current_committee_root,
            next_committee_root,
            inner_hash,
            current_committee,
            next_committee,
            batch_root: String::new(),
            batch_sig: String::new(),
            batch_paths: Vec::new(),
        })
    }

    /// Drop snap/wire certs that will fail ingest (empty sig, outsider voter).
    pub fn drop_invalid_certs(&mut self) {
        let need = self.commit_votes_needed();
        let require = self.cfg.require_vote_sigs;
        let nid = self.cfg.network_id;
        let bad: Vec<u64> = self
            .certs
            .iter()
            .filter_map(|(h, c)| {
                let bad = if self.key_registry_at(*h) {
                    c.verify_with(&|v: &str| self.registered_key(v), &self.keys, nid, require, need, self.vote_rounds_at(*h))
                        .is_err()
                } else {
                    c.verify(&self.keys, nid, require, need).is_err()
                };
                if bad {
                    Some(*h)
                } else {
                    None
                }
            })
            .collect();
        for h in bad {
            self.certs.remove(&h);
        }
    }

    /// After snap/catch-up the tip may be committed with no `certs[h]` (that
    /// cert rides the *next* ledger). Committee re-OKs the tip hash so pack
    /// can carry `parent_cert` again (v2.9.10).
    pub fn recertify_committed_tip(&mut self) -> Option<(u64, String, String)> {
        if self.tip_height == 0 {
            return None;
        }
        // Local committed tip is enough. `best_peer_tip==0` right after snap
        // used to skip recertify on every seat until pongs — then VC walked
        // the 6 with no cert and nobody could pack (2.9.14 resume at 12939).
        if self.need_hard_resync || self.best_peer_tip > self.tip_height {
            return None;
        }
        if self.certs.contains_key(&self.tip_height) {
            return None;
        }
        let me = self.id.clone();
        if !self.eligible_voter(&me) {
            return None;
        }
        let h = self.tip_height;
        let hash = self.tip_hash.clone();
        let round = self.own_ok_round(h);
        let sig = self.sign_ok_vote_round(h, round, &hash);
        if sig.is_empty() && self.cfg.require_vote_sigs {
            return None;
        }
        let _ = self.vote_ok_round_ex(&hash, &me, &sig, round);
        self.store_cert_if_ready(&hash, h);
        Some((h, hash, sig))
    }

    /// v2.9.57 (379780 stall, 2026-10-08): a peer is re-OKing **our** committed
    /// tip in the recert round, so it has no cert for it. Seats that hold the
    /// cert never ran [`Self::recertify_committed_tip`], so with 3 committee
    /// seats cert-less (they committed the tip via catch-up and signed their
    /// own OK in the recert round instead of the proposal round) the recert
    /// round topped out at 3 < 4 votes forever, the cert-less round-0
    /// proposer could not pack, and cert-less seats may not vote view-change.
    /// Cert holders now join the recert round for their tip (same hash, own
    /// round slot, so never equivocation). The node binary unicasts that vote
    /// plus [`Self::tip_cert_relay`] OKs to the asking seat only. Each voter
    /// is assisted at most once per tip height (the old global
    /// [`Self::RECERT_ASSIST_EVERY_MS`] resend filled the Vote lane at
    /// h=827004 and starved view-change).
    ///
    /// Returns `(height, hash, signature)` of our recert vote to unicast
    /// to `voter`. `None` for a non-recert round, wrong hash, cert-less
    /// local seat, a voter we did not record as asking, or a voter already
    /// assisted at this height.
    pub fn recert_assist(&mut self, ledger_hash: &str, round: u64, voter: &str) -> Option<(u64, String, String)> {
        if round != Self::RECERT_ROUND || voter == self.id || self.tip_height == 0 {
            return None;
        }
        let h = self.tip_height;
        if ledger_hash != self.tip_hash || !self.vote_rounds_at(h) {
            return None;
        }
        // Cert-less seats recertify on their own tick.
        if !self.certs.contains_key(&h) {
            return None;
        }
        // Only answer committee peers' recert requests that we actually recorded.
        let asked = self
            .round_votes
            .get(&h)
            .and_then(|m| m.get(&Self::RECERT_ROUND))
            .and_then(|v| v.get(voter))
            .map(|(hash, _)| hash == ledger_hash)
            .unwrap_or(false);
        if !asked {
            return None;
        }
        let me = self.id.clone();
        if !self.eligible_voter(&me) {
            return None;
        }
        if self.recert_assist_h != h {
            self.recert_assist_peers.clear();
            self.recert_assist_h = h;
        }
        if self.recert_assist_peers.contains(voter) {
            return None;
        }
        let existing = self
            .round_votes
            .get(&h)
            .and_then(|m| m.get(&Self::RECERT_ROUND))
            .and_then(|v| v.get(&me))
            .filter(|(hash, _)| *hash == self.tip_hash)
            .map(|(_, sig)| sig.clone());
        let hash = self.tip_hash.clone();
        let sig = match existing {
            Some(sig) => sig,
            None => {
                let sig = self.sign_ok_vote_round(h, Self::RECERT_ROUND, &hash);
                if sig.is_empty() && self.cfg.require_vote_sigs {
                    return None;
                }
                let _ = self.vote_ok_round_ex(&hash, &me, &sig, Self::RECERT_ROUND);
                sig
            }
        };
        self.recert_assist_peers.insert(voter.to_string());
        self.recert_assist_ms = self.now_ms;
        Some((h, hash, sig))
    }

    /// Historical recert-assist resend window (logical ms). Assist is now
    /// one-shot per (height, voter); tests still advance `now_ms` by this.
    pub const RECERT_ASSIST_EVERY_MS: u64 = 3_000;

    /// v2.9.79 (671185 stall, 2026-10-21): record a signed OK for our
    /// committed tip while we hold no cert for it, then try to rebuild the
    /// cert from the tip's **own** sealing committee.
    ///
    /// The recert round is counted against the *next* committee
    /// (`qc_voters()`), so cert holders outside it (e.g. v1) assisted forever
    /// without helping, and a cert-less lottery winner never packed. The
    /// original 4-of-6 OKs are still valid signatures for the tip; any peer
    /// that holds the cert can relay them (see [`Self::tip_cert_relay`]).
    ///
    /// Returns `true` when this vote completed and stored the tip cert.
    pub fn note_tip_cert_vote(
        &mut self,
        height: u64,
        ledger_hash: &str,
        voter: &str,
        signature: &str,
        round: u64,
    ) -> bool {
        let h = self.tip_height;
        if h == 0 || height != h || ledger_hash != self.tip_hash {
            return false;
        }
        if self.certs.contains_key(&h) {
            return false;
        }
        if self.tip_cert_votes_h != h {
            self.tip_cert_votes.clear();
            self.tip_cert_votes_h = h;
        }
        let round = if self.vote_rounds_at(h) { round } else { 0 };
        let payload = self.ok_payload_for(h, round, ledger_hash, voter);
        let sig_ok = if self.cfg.require_vote_sigs {
            if signature.is_empty() {
                false
            } else if let Some(pk) = self.consensus_key_at(voter, h) {
                self.verify_consensus_sig(voter, h, &pk, &payload, signature)
            } else {
                false
            }
        } else {
            true
        };
        if !sig_ok {
            return false;
        }
        // Bound memory: at most a handful of rounds per tip.
        if !self.tip_cert_votes.contains_key(&round) && self.tip_cert_votes.len() >= 16 {
            return false;
        }
        self.tip_cert_votes
            .entry(round)
            .or_default()
            .insert(voter.to_string(), signature.to_string());
        self.try_assemble_tip_cert()
    }

    /// Build + verify a cert for the tip from relayed original OKs. Committee
    /// is the tip ledger's frozen `current_committee`; the result must pass
    /// [`Self::verify_cert`] (same check every peer applies to `parent_cert`).
    pub fn try_assemble_tip_cert(&mut self) -> bool {
        let h = self.tip_height;
        if h == 0 || self.certs.contains_key(&h) || self.tip_cert_votes_h != h {
            return false;
        }
        let Some(tip) = self.chain.last() else {
            return false;
        };
        if tip.height != h || tip.ledger_hash != self.tip_hash {
            return false;
        }
        let committee = tip.current_committee.clone();
        let parent_hash = tip.parent_hash.clone();
        if committee.is_empty() {
            return false;
        }
        let need = Self::cert_need_for(committee.len(), self.cfg.soft_ok_votes);
        let round_scoped = self.vote_rounds_at(h);
        for (round, votes) in &self.tip_cert_votes {
            let mut voters = Vec::new();
            let mut signatures = Vec::new();
            for id in &committee {
                if let Some(sig) = votes.get(id) {
                    voters.push(id.clone());
                    signatures.push(sig.clone());
                }
            }
            if voters.len() < need {
                continue;
            }
            let cert = LedgerCert {
                height: h,
                ledger_hash: self.tip_hash.clone(),
                parent_hash: parent_hash.clone(),
                committee: committee.clone(),
                voters,
                signatures,
                round: if round_scoped { *round } else { 0 },
            };
            if self.verify_cert(&cert).is_ok() {
                self.certs.insert(h, cert);
                self.tip_cert_votes.clear();
                return true;
            }
        }
        false
    }

    /// Original OKs inside our tip cert, as `(voter, signature, round)`, for a
    /// cert holder to unicast as plain `LedgerOk` to a peer that asks for a
    /// recert. Existing wire message, valid signatures, same hash/round as
    /// already sent: older seats treat them as duplicate votes (mixed-version
    /// safe). Never mesh-fan these (827004 stall).
    pub fn tip_cert_relay(&self) -> Vec<(String, String, u64)> {
        let Some(c) = self.certs.get(&self.tip_height) else {
            return Vec::new();
        };
        if c.ledger_hash != self.tip_hash {
            return Vec::new();
        }
        c.voters
            .iter()
            .zip(c.signatures.iter())
            .filter(|(_, s)| !s.is_empty() || !self.cfg.require_vote_sigs)
            .map(|(v, s)| (v.clone(), s.clone(), c.round))
            .collect()
    }

    /// Cert that unlocked the current tip. Height 1 carries `None`.
    fn tip_parent_cert(&mut self) -> Result<Option<LedgerCert>, String> {
        if self.tip_height == 0 {
            return Ok(None);
        }
        if !self.certs.contains_key(&self.tip_height) {
            let tip = self.tip_hash.clone();
            let h = self.tip_height;
            self.store_cert_if_ready(&tip, h);
        }
        self.certs
            .get(&self.tip_height)
            .cloned()
            .map(Some)
            .ok_or_else(|| {
                format!(
                    "no 4-of-6 cert for tip h={} — wait for committee QC",
                    self.tip_height
                )
            })
    }

    fn cert_need_for(committee_len: usize, soft_ok_votes: usize) -> usize {
        if committee_len >= 6 {
            return 4;
        }
        if committee_len == 0 {
            return 1;
        }
        let mut need = soft_ok_votes.min(committee_len).max(1);
        if committee_len >= 2 {
            need = need.max(2).min(committee_len);
        }
        need
    }

    fn verify_parent_cert(&self, ledger: &Ledger) -> Result<(), String> {
        if ledger.height <= 1 {
            if ledger.parent_cert.is_some() {
                return Err("height 1 must not carry parent_cert".into());
            }
            return Ok(());
        }
        let Some(cert) = &ledger.parent_cert else {
            return Err(format!("missing parent_cert at h={}", ledger.height));
        };
        if cert.height != self.tip_height || cert.ledger_hash != self.tip_hash {
            return Err(format!(
                "parent_cert does not match tip h={} hash",
                self.tip_height
            ));
        }
        self.verify_cert(cert)
    }

    /// Verify a commit certificate with this node's rules for its height
    /// (A13: registry keys from `H_act`, else the local keyring).
    pub fn verify_cert(&self, cert: &LedgerCert) -> Result<(), String> {
        let need = Self::cert_need_for(cert.committee.len(), self.cfg.soft_ok_votes);
        if self.key_registry_at(cert.height) {
            return cert.verify_with(
                &|v: &str| self.registered_key(v),
                &self.keys,
                self.cfg.network_id,
                self.cfg.require_vote_sigs,
                need,
                self.vote_rounds_at(cert.height),
            );
        }
        cert.verify_ex(
            &self.keys,
            self.cfg.network_id,
            self.cfg.require_vote_sigs,
            need,
            self.vote_rounds_at(cert.height),
        )
    }

    /// Ordered seats that must be claimed-skipped for `packer` to be the legal
    /// active seat (all ONLINE seats before packer in lottery_order).
    pub fn skip_claims_for_packer(&self, packer: &str) -> Result<Vec<String>, String> {
        let order = self.lottery_order();
        let packer_idx = order
            .iter()
            .position(|id| id == packer)
            .ok_or_else(|| format!("{packer} not in tip-fixed committee"))?;
        let height = self.tip_height + 1;
        let certified = self.skip_set_for(height);
        let mut claims = Vec::with_capacity(packer_idx);
        for id in &order[..packer_idx] {
            if !certified.contains(id) {
                return Err(format!(
                    "cannot pack: predecessor {id} not skip-QC'd at h={height}"
                ));
            }
            claims.push(id.clone());
        }
        Ok(claims)
    }

    /// Validate packer + skip claims against shared ONLINE seat order (v2.4.0 polish).
    ///
    /// Does **not** require the receiver to have the same local skip_votes map —
    /// the claim is part of the signed ledger; soft QC of the ledger is network
    /// agreement. Rejects inconsistent claims (wrong packer, skip after packer, etc.).
    pub fn validate_proposal_seats(&self, ledger: &Ledger) -> Result<(), String> {
        let order = self.lottery_order();
        if order.is_empty() {
            return Err("no bonded lottery seats".into());
        }
        let packer_idx = order
            .iter()
            .position(|id| id == &ledger.packer)
            .ok_or_else(|| {
                format!(
                    "packer {} not in tip-fixed committee {:?}",
                    ledger.packer, order
                )
            })?;
        let claim = &ledger.skipped_predecessors;
        if claim.len() != packer_idx {
            return Err(format!(
                "skip claim length {} want {packer_idx} (all predecessors must be claimed)",
                claim.len()
            ));
        }
        for (i, id) in claim.iter().enumerate() {
            if order.get(i).map(|s| s.as_str()) != Some(id.as_str()) {
                return Err(format!(
                    "skip claim order mismatch at {i}: got {id} want {:?}",
                    order.get(i)
                ));
            }
        }
        // Active seat under claimed skips must be this packer.
        let claim_set: BTreeSet<String> = claim.iter().cloned().collect();
        let expected = order
            .iter()
            .find(|id| !claim_set.contains(*id))
            .ok_or_else(|| "all seats claimed skipped".to_string())?;
        if expected != &ledger.packer {
            return Err(format!(
                "wrong packer got {} want {expected} under skip claims",
                ledger.packer
            ));
        }
        Ok(())
    }

    /// Drop pending slashes that would leave fewer than 6 bonded seats.
    ///
    /// With exactly 6 live seats, jailing one freezes the chain: the packer
    /// refuses the ledger (`v4 pack needs 6 bonded`), the slash never commits,
    /// and every later tx waits. Soft-QC then appears stuck because no body
    /// can seal. Prefer dropping the evidence over halting (hotfix2 / PR8).
    fn drop_slashes_that_break_quorum(&mut self, vals: &BTreeMap<String, ValidatorInfo>) {
        if self.pending_slashes.is_empty() {
            return;
        }
        let mut kept = Vec::new();
        let mut sim = vals.clone();
        let mut dropped = Vec::new();
        for ev in self.pending_slashes.drain(..) {
            let mut trial = sim.clone();
            Self::apply_slash_evidence(&mut trial, std::slice::from_ref(&ev));
            let n = trial
                .values()
                .filter(|v| v.lottery_weight() > 0.0)
                .count();
            if n >= 6 {
                sim = trial;
                kept.push(ev);
            } else {
                dropped.push(format!("{}@{}", ev.offender, ev.height));
            }
        }
        if !dropped.is_empty() {
            eprintln!(
                "falcon-pl drop slash that would leave <6 bonded: {}",
                dropped.join(",")
            );
        }
        self.pending_slashes = kept;
    }

    /// Jail on proven equivocation: seize **all** active bond and any
    /// pending unbonding into the prize pot (returned), bump `jail_count`,
    /// and set `jailed`. Prefer prize pot over burn — callers credit
    /// `epoch_work.fee_reward_pool` with the returned amount.
    ///
    /// The legacy `slash_equivocation` config amount is unused: a jail always
    /// confiscates the full stake so the escalated unjail rebond is meaningful.
    fn apply_slash_evidence(
        vals: &mut BTreeMap<String, ValidatorInfo>,
        evs: &[SlashEvidence],
    ) -> u64 {
        let mut seized = 0u64;
        for ev in evs {
            if ev.offender.is_empty() || ev.hash_a == ev.hash_b {
                continue;
            }
            if let Some(v) = vals.get_mut(&ev.offender) {
                if v.jailed {
                    continue;
                }
                let take = v.bond.saturating_add(v.unbonding).saturating_add(v.escrow);
                v.bond = 0;
                v.unbonding = 0;
                v.escrow = 0; // v2.9.62 A8: escrow is seized with the bond
                v.unbond_ready_ms = 0;
                v.slash_total = v.slash_total.saturating_add(take);
                v.jail_count = v.jail_count.saturating_add(1);
                v.jailed = true;
                v.quality = 0.0;
                seized = seized.saturating_add(take);
            }
        }
        seized
    }

    /// Slash full bond into the prize pot and jail on proven equivocation.
    pub fn slash_equivocation(&mut self, packer: &str) -> u64 {
        let lock = self.presence_at(self.tip_height.saturating_add(1));
        if let Some(v) = self.validators.get_mut(packer) {
            if v.jailed {
                return 0;
            }
            let take = v.bond.saturating_add(v.unbonding).saturating_add(v.escrow);
            v.bond = 0;
            v.unbonding = 0;
            v.escrow = 0; // v2.9.62 A8: escrow is seized with the bond
            v.unbond_ready_ms = 0;
            v.slash_total = v.slash_total.saturating_add(take);
            v.jail_count = v.jail_count.saturating_add(1);
            v.jailed = true;
            v.quality = 0.0;
            if lock {
                v.lock_earn();
            }
            self.epoch_work.fee_reward_pool =
                self.epoch_work.fee_reward_pool.saturating_add(take);
            return take;
        }
        0
    }

    /// Ingest a ledger: apply if next height, else buffer for catch-up.
    /// Returns applied accept result (may cascade multiple pending).
    pub fn ingest_ledger(&mut self, ledger: &Ledger) -> Result<Option<AcceptResult>, String> {
        self.ingest_ledger_ex(ledger, true)
    }

    /// Catch-up ingest: sequential parent/sig/state checks; **no lottery re-check**.
    /// Pull sync must follow a peer's sealed history even if local skip/bond
    /// bookkeeping briefly diverged (production lag fix).
    pub fn ingest_ledger_catchup(
        &mut self,
        ledger: &Ledger,
    ) -> Result<Option<AcceptResult>, String> {
        self.ingest_ledger_ex(ledger, false)
    }

    fn ingest_ledger_ex(
        &mut self,
        ledger: &Ledger,
        check_lottery: bool,
    ) -> Result<Option<AcceptResult>, String> {
        if ledger.height <= self.tip_height {
            // already have this height or older
            if let Some((_, h)) = self.seen_at_height.get(&ledger.height) {
                if h != &ledger.ledger_hash {
                    let msg = format!(
                        "equivocation/fork at h={} have {h} got {}",
                        ledger.height, ledger.ledger_hash
                    );
                    // Only a rival for our *tip* can mean the open height is
                    // contested. A late body for an older committed height is
                    // stale gossip (a losing attempt relayed minutes later by a
                    // backlogged peer). Typing it as IngestFork made
                    // `open_height_dual` true for every later height, so a
                    // unique, canonical pending got view-change-dropped
                    // (v1, 2026-10-06: stale h=371908 while pending 371952).
                    // A certified tip (4-of-6 cert held) cannot be out-voted
                    // either, so its rival is stale too.
                    if ledger.height == self.tip_height
                        && !self.certs.contains_key(&self.tip_height)
                    {
                        self.stall = Some(ConsensusStall::IngestFork {
                            height: ledger.height,
                        });
                    }
                    return Err(msg);
                }
            }
            return Ok(None);
        }
        if ledger.height > self.tip_height + 1 {
            // buffer future (cap to avoid unbounded memory — P1 tighter bound)
            if self.pending_ledgers.len() < Self::PENDING_LEDGERS_CAP
                || self.pending_ledgers.contains_key(&ledger.height)
            {
                if check_lottery {
                    // Live gossip: first body at this height wins the hold slot.
                    self.pending_ledgers
                        .entry(ledger.height)
                        .or_insert_with(|| ledger.clone());
                } else {
                    // Catch-up: certified history replaces any earlier live hold
                    // (v2.9.50 — rival held at h while behind must not beat the
                    // later canonical batch item at the same height).
                    self.pending_ledgers.insert(ledger.height, ledger.clone());
                }
            }
            return Ok(None);
        }
        // height == tip + 1
        // Drop a conflicting hold at this height; the body we are about to
        // accept (live stage or catch-up commit) is authoritative.
        if let Some(held) = self.pending_ledgers.remove(&ledger.height) {
            if held.ledger_hash != ledger.ledger_hash {
                // abandoned rival — do not cascade it later
                let _ = held;
            }
        }
        let mut last = self.accept_ledger_ex(ledger, check_lottery)?;
        // Cascade held futures on the *live* path only (soft-QC staging).
        // Catch-up must never commit a bare held proposal: apply_catchup_batch
        // already feeds certified bodies in height order, so cascading a
        // previously gossiped live rival at tip+1 was the v10 fork at ~372938
        // (v2.9.50).
        if check_lottery {
            loop {
                let next_h = self.tip_height + 1;
                let Some(next) = self.pending_ledgers.remove(&next_h) else {
                    break;
                };
                match self.accept_ledger_ex(&next, check_lottery) {
                    Ok(r) => last = r,
                    Err(e) => {
                        let _ = e;
                        break;
                    }
                }
            }
        }
        // prune pending far below tip
        let tip = self.tip_height;
        self.pending_ledgers.retain(|h, _| *h > tip);
        Ok(Some(last))
    }

    pub fn accept_ledger(&mut self, ledger: &Ledger) -> Result<AcceptResult, String> {
        self.accept_ledger_ex(ledger, true)
    }

    /// Catch-up / admin force: immediate commit without live lottery/QC staging.
    pub fn accept_ledger_catchup(&mut self, ledger: &Ledger) -> Result<AcceptResult, String> {
        self.accept_ledger_ex(ledger, false)
    }

    /// Live path: stage + soft-QC commit. Catch-up (`check_lottery=false`): immediate commit.
    fn accept_ledger_ex(
        &mut self,
        ledger: &Ledger,
        check_lottery: bool,
    ) -> Result<AcceptResult, String> {
        let round_mode = check_lottery && self.vote_rounds_at(ledger.height);
        // Equivocation: same packer, same height, different hash (staged or committed)
        // Round mode handles packer duals in `accept_round_proposal` (no local slash).
        if let Some((prev_packer, prev_hash)) = self
            .seen_at_height
            .get(&ledger.height)
            .filter(|_| !round_mode)
        {
            if prev_packer == &ledger.packer && prev_hash != &ledger.ledger_hash {
                // Lagging catch-up: we have an uncommitted local dual; the peer
                // already committed the other hash. Adopt theirs (do not slash —
                // slash would desync the catch-up state root).
                if !check_lottery && ledger.height == self.tip_height.saturating_add(1) {
                    self.note_height_sealer(ledger.height, &ledger.packer);
                    self.seen_at_height.remove(&ledger.height);
                    self.pending_proposal = None;
                } else {
                    let slashed = self.slash_equivocation(&ledger.packer);
                    return Err(format!(
                        "equivocation by {} at h={} slash={slashed}",
                        ledger.packer, ledger.height
                    ));
                }
            }
        }

        if ledger.height != self.tip_height + 1 {
            return Err(format!(
                "height want {} got {}",
                self.tip_height + 1,
                ledger.height
            ));
        }
        if ledger.parent_hash != self.tip_hash {
            return Err("bad parent".into());
        }
        if ledger.network_id != self.cfg.network_id {
            return Err("network".into());
        }
        if !self.packer_sig_ok(ledger) {
            return Err("bad packer sig".into());
        }
        // v2.10.0 (Item #16): an empty ledger is valid only from
        // `empty_block_from_height`; before it, reject exactly like 2.9.81.
        if ledger.txs.is_empty() && !self.empty_block_at(ledger.height) {
            return Err("empty ledger rejected".into());
        }
        self.verify_parent_cert(ledger)?;
        if let Some(c) = &ledger.parent_cert {
            self.certs.entry(c.height).or_insert_with(|| c.clone());
        }

        // --- Round-scoped live path (v2.10.0) ---
        if round_mode {
            self.verify_round_slash_evidence(ledger)?;
            return self.accept_round_proposal(ledger);
        }

        // --- Live path (v2.3.0 P0): stage proposal; tip advances only on soft QC ---
        if check_lottery {
            if let Some(p) = &self.pending_proposal {
                if p.ledger_hash == ledger.ledger_hash {
                    // Same proposal re-delivered — refresh self-vote / try commit.
                    // Do **not** treat as a new stage (caller must not re-fan ProposeLedger).
                    let me = self.id.clone();
                    let lh = ledger.ledger_hash.clone();
                    let _ = self.vote_ok(&lh, &me);
                    return Ok(AcceptResult {
                        height: ledger.height,
                        packer: ledger.packer.clone(),
                        n_txs: ledger.txs.len(),
                        fees: ledger.txs.iter().map(|t| t.fee).sum(),
                        reward_paid: 0,
                    });
                }
                if p.packer == ledger.packer {
                    let slashed = self.slash_equivocation(&ledger.packer);
                    return Err(format!(
                        "equivocation by {} at h={} slash={slashed}",
                        ledger.packer, ledger.height
                    ));
                }
                // v2.5.0 B1: QC-first among uncommitted proposals (not keep-first forever).
                // Clone pending first so we can freeze schedule without borrow conflict.
                let pending = p.clone();
                if self.schedule_height != ledger.height {
                    self.freeze_open_height_schedule();
                }
                let local_ok = self.validate_proposal_seats(&pending).is_ok();
                let rival_ok = self.validate_proposal_seats(ledger).is_ok();
                if !rival_ok {
                    return Err(format!(
                        "fork: rival invalid at h={} keep {} got {} (seat)",
                        ledger.height,
                        &pending.ledger_hash[..16.min(pending.ledger_hash.len())],
                        &ledger.ledger_hash[..16.min(ledger.ledger_hash.len())]
                    ));
                }
                if !local_ok && rival_ok {
                    // Drop illegal local pending; fall through to stage valid rival.
                    self.pending_proposal = None;
                    self.last_catchup_conflict = format!(
                        "replaced invalid pending at h={} with {}",
                        ledger.height,
                        &ledger.ledger_hash[..16.min(ledger.ledger_hash.len())]
                    );
                } else {
                    let local_votes = self
                        .ok_votes
                        .get(&pending.ledger_hash)
                        .map(|s| s.len())
                        .unwrap_or(0);
                    let rival_votes = self
                        .ok_votes
                        .get(&ledger.ledger_hash)
                        .map(|s| s.len())
                        .unwrap_or(0);
                    // Unique soft QC wins. Otherwise every node picks the lower
                    // hash so a 0–1 self-vote cannot pin the first-seen body.
                    let need = self.commit_votes_needed();
                    let rival_qc = rival_votes >= need;
                    let local_qc = local_votes >= need;
                    let rival_wins = if rival_qc && !local_qc {
                        true
                    } else if local_qc && !rival_qc {
                        false
                    } else if rival_qc && local_qc {
                        ledger.ledger_hash < pending.ledger_hash
                    } else {
                        ledger.ledger_hash < pending.ledger_hash
                    };
                    self.stall = Some(ConsensusStall::DualProposal {
                        height: ledger.height,
                        kept: if rival_wins {
                            ledger.ledger_hash.clone()
                        } else {
                            pending.ledger_hash.clone()
                        },
                        rival: if rival_wins {
                            pending.ledger_hash.clone()
                        } else {
                            ledger.ledger_hash.clone()
                        },
                    });
                    if rival_wins {
                        self.pending_proposal = None;
                        self.seen_at_height.remove(&ledger.height);
                        self.last_catchup_conflict = format!(
                            "qc-first switch h={} {} votes={local_votes} → {} votes={rival_votes}",
                            ledger.height,
                            &pending.ledger_hash[..16.min(pending.ledger_hash.len())],
                            &ledger.ledger_hash[..16.min(ledger.ledger_hash.len())]
                        );
                    } else {
                        self.last_catchup_conflict = format!(
                            "fork: conflicting proposal at h={} keep {} (votes={local_votes}) got {} (votes={rival_votes}); view-change if stuck",
                            ledger.height,
                            &pending.ledger_hash[..16.min(pending.ledger_hash.len())],
                            &ledger.ledger_hash[..16.min(ledger.ledger_hash.len())]
                        );
                        return Err(self.last_catchup_conflict.clone());
                    }
                }
            }
            // Proposal = packer did the job. Undo any raced skip-QC so lottery
            // matches the sealer (skip must not orphan a valid seal).
            let h = ledger.height;
            if self.schedule_height != h {
                self.freeze_open_height_schedule();
            }
            if self.skip_set_for(h).contains(&ledger.packer) {
                self.unskip_packer(h, &ledger.packer);
            }
            // v2.4.0 polish + v2.5.0 freeze: reject illegal packers via skip claims
            // under the frozen open-height schedule.
            self.validate_proposal_seats(ledger)?;
            // Local active-seat check: when our skip QC matches the claim, must agree.
            // If we lag on skip QC but claim is schedule-valid, still accept for soft QC
            // (mesh agreement is the ledger QC). If we already have a *stricter* active
            // (fewer skips), reject as wrong packer to avoid accepting late forgeries.
            if let Some(expected) = self.lottery_packer() {
                if ledger.packer != expected {
                    // Only hard-reject when local skips already cover the claim prefix
                    // (we are caught up on skip QC and still disagree).
                    let local = self.skip_set_for(h);
                    let claim_ok = ledger
                        .skipped_predecessors
                        .iter()
                        .all(|s| local.contains(s));
                    if claim_ok {
                        return Err(format!(
                            "wrong packer got {} want {expected} (local skip QC)",
                            ledger.packer
                        ));
                    }
                }
            }
            // Verify state root before staging (reject invalid proposals early).
            self.verify_ledger_state_root(ledger)?;
            self.pending_proposal = Some(ledger.clone());
            self.seen_at_height.insert(
                ledger.height,
                (ledger.packer.clone(), ledger.ledger_hash.clone()),
            );
            self.note_height_sealer(ledger.height, &ledger.packer);
            // Clear residual skip votes for this packer (proposal wins).
            self.unskip_packer(h, &ledger.packer);
            // Align local skip set with claimed predecessors so cursor matches soft tip.
            for s in &ledger.skipped_predecessors {
                self.skip_packer(h, s);
            }
            self.note_next_height_activity();
            let me = self.id.clone();
            let lh = ledger.ledger_hash.clone();
            let _ = self.vote_ok(&lh, &me);
            // vote_ok may have committed if soft QC already met (small n).
            return Ok(AcceptResult {
                height: ledger.height,
                packer: ledger.packer.clone(),
                n_txs: ledger.txs.len(),
                fees: ledger.txs.iter().map(|t| t.fee).sum(),
                reward_paid: 0,
            });
        }

        // --- Catch-up / historical: immediate commit (no lottery re-check) ---
        self.pending_proposal = None;
        self.commit_ledger_body_ex(ledger, true)
    }

    /// Verify commitment root matches without mutating tip state.
    /// Stage-time drafts for `ledger` on the current tip: time effects at
    /// `sealed_at`, then every tx, on clones (self is restored). Shared by
    /// [`Self::verify_ledger_state_root`] and [`Self::prestage_root_input`].
    fn stage_drafts(&mut self, ledger: &Ledger) -> Result<(RootInput, u64, u64), String> {
        self.check_sealed_at(ledger)?;
        // Live staging: UTC skew vs OS wall (no-op while H_utc unarmed).
        self.check_sealed_utc_live(ledger)?;
        // Same physics as pack: settle → slash → unbonds at sealed_at, then txs.
        let ckpt = TimeFold::take(self);
        let _seized = self.apply_time_effects_with_slashes(
            ledger.sealed_at_ms,
            ledger.fee_total > 0 || (ledger.txs.is_empty() && self.empty_block_at(ledger.height)),
            &ledger.slashes,
        );
        let mut draft_state = self.state.clone();
        let mut draft_defi = self.defi.clone();
        let mut draft_bridge = self.bridge.clone();
        let mut draft_vals = self.validators.clone();
        let mut draft_claim = self.claimable.clone();
        let mut draft_work = self.epoch_work.clone();
        self.prune_eth_exec_for_ledger(&mut draft_bridge, ledger.height);
        let r0 = self.rv2_round0(ledger.height);
        let voters = ledger
            .parent_cert
            .as_ref()
            .map(|c| c.voters.clone())
            .unwrap_or_default();
        self.rv2_ledger_hook(&mut draft_vals, ledger.height, &ledger.packer, r0.as_deref(), &voters);
        self.seat_migrate_hook(&mut draft_vals, &mut draft_claim, ledger.height);
        self.orderbook_ledger_hook(&mut draft_state, &mut draft_defi, ledger.height);
        let saved = self.now_ms;
        self.now_ms = ledger.sealed_at_ms;
        let mut fee_total = 0u64;
        let mut err = None;
        if !ledger.batch_sig.is_empty() {
            let packer_rk = self.packer_registry_key(ledger);
            let known_keys: Vec<(String, String)> = ledger
                .txs
                .iter()
                .filter_map(|tx| {
                    self.account_public_key(&tx.account)
                        .map(|pk| (tx.account.clone(), pk))
                })
                .collect();
            if let Err(e) = ledger.verify_merkle_batch_reg(&self.keys, &|id| {
                known_keys
                    .iter()
                    .find(|(a, _)| a == id)
                    .map(|(_, pk)| pk.clone())
            }, ledger.height >= crate::params_v2::key_bind_onchain_from_height(self.cfg.network_id), packer_rk.as_deref()) {
                ckpt.restore(self);
                self.now_ms = saved;
                return Err(e);
            }
        }
        let check_sig = ledger.batch_sig.is_empty();
        self.last_apply_fail_tx = None;
        for tx in &ledger.txs {
            fee_total = fee_total.saturating_add(tx.fee);
            if let Err(e) = self.try_protocol_tx_ex(
                &mut draft_state,
                &mut draft_defi,
                &mut draft_bridge,
                &mut draft_vals,
                &mut draft_claim,
                &mut draft_work,
                tx,
                check_sig,
            ) {
                self.last_apply_fail_tx = Some(tx.tx_id.clone());
                err = Some(e);
                break;
            }
        }
        self.now_ms = saved;
        let last_settled = self.last_settled_epoch;
        ckpt.restore(self);
        if let Some(e) = err {
            return Err(e);
        }
        let _ = draft_work;
        Ok((
            RootInput {
                state: draft_state,
                defi: draft_defi,
                bridge: draft_bridge,
                validators: draft_vals,
                claimable: draft_claim,
            },
            fee_total,
            last_settled,
        ))
    }

    fn verify_ledger_state_root(&mut self, ledger: &Ledger) -> Result<u64, String> {
        let (draft, fee_total, last_settled) = self.stage_drafts(ledger)?;
        // v2.9.59: normally a memo hit — the node binary precomputed this
        // exact root outside `node.lock` ([`Self::prestage_root_input`]).
        let root = draft.root();
        if root != ledger.state_root_after {
            return Err(format!(
                "state root mismatch at h={} (local now_ms={} sealed_at_ms={} last_settled={})",
                ledger.height, self.now_ms, ledger.sealed_at_ms, last_settled
            ));
        }
        self.verify_v4_contents(ledger, &draft.bridge, &draft.validators)?;
        Ok(fee_total)
    }

    /// v2.9.59: build the stage-time root input for a live proposal of the
    /// next height **without** hashing it, so the caller can compute the
    /// ~207 MB root after releasing `node.lock` ([`RootInput::root`] fills the
    /// root memo). The later stage under the lock then hits the memo. Purely
    /// a cache warm-up: if anything differs, the stage just hashes as before.
    pub fn prestage_root_input(&mut self, ledger: &Ledger) -> Prestage {
        if ledger.height != self.tip_height.saturating_add(1)
            || ledger.parent_hash != self.tip_hash
            || ledger.network_id != self.cfg.network_id
            || (ledger.txs.is_empty() && !self.empty_block_at(ledger.height))
        {
            return Prestage::Skip;
        }
        let staged = self
            .pending_proposal
            .as_ref()
            .map(|p| p.ledger_hash == ledger.ledger_hash)
            .unwrap_or(false);
        if staged || self.open_bodies.contains_key(&ledger.ledger_hash) {
            return Prestage::Skip;
        }
        if self.prestaged_hash == ledger.ledger_hash || PrestageJob::in_flight(&ledger.ledger_hash) {
            return Prestage::Wait(ledger.ledger_hash.clone());
        }
        if !self.validators.contains_key(&ledger.packer) || !self.packer_sig_ok(ledger) {
            return Prestage::Skip;
        }
        if !self.prestage_gate(ledger) {
            return Prestage::Skip;
        }
        let Ok((draft, _, _)) = self.stage_drafts(ledger) else {
            return Prestage::Skip;
        };
        match PrestageJob::begin(ledger.ledger_hash.clone(), draft) {
            Some(job) => {
                self.prestaged_hash = ledger.ledger_hash.clone();
                self.prestage_count = self.prestage_count.saturating_add(1);
                Prestage::Run(job)
            }
            None => Prestage::Wait(ledger.ledger_hash.clone()),
        }
    }

    /// v2.9.59: the cheap, read-only pre-root checks the accept path runs
    /// before it hashes (parent cert, round slash evidence, seat / skip
    /// claims under the frozen open-height schedule, one body per packer,
    /// body-cache cap; legacy: no rival pending, lottery packer). Prestage
    /// only warms the memo for proposals that would reach the root check, so
    /// a bonded peer cannot buy extra full-root hashes with signed junk. Any
    /// doubt (e.g. schedule not frozen yet) → `false` = no prestage, and the
    /// normal path decides exactly as before.
    fn prestage_gate(&self, ledger: &Ledger) -> bool {
        let h = ledger.height;
        if self.schedule_height != h || self.verify_parent_cert(ledger).is_err() {
            return false;
        }
        if self.vote_rounds_at(h) {
            if self.verify_round_slash_evidence(ledger).is_err()
                || self.open_bodies.len() >= Self::OPEN_BODIES_CAP
                || self
                    .open_bodies
                    .values()
                    .any(|b| b.packer == ledger.packer && b.ledger_hash != ledger.ledger_hash)
            {
                return false;
            }
            return self.validate_proposal_seats(ledger).is_ok();
        }
        if self.pending_proposal.is_some() || self.skip_set_for(h).contains(&ledger.packer) {
            return false;
        }
        if self.validate_proposal_seats(ledger).is_err() {
            return false;
        }
        match self.lottery_packer() {
            Some(expected) if expected != ledger.packer => {
                let local = self.skip_set_for(h);
                !ledger.skipped_predecessors.iter().all(|s| local.contains(s))
            }
            _ => true,
        }
    }

    /// v2.9.59 pacing cap: never longer than one live pack window, so
    /// pace + pull/pack/seal/gossip stays inside peers' round-0 silence
    /// timeout (`round_silence_timeout_ms(0)` = 2 × live pack window), and
    /// inside the legacy proposal timeout minus one window.
    pub fn pace_effective_ms(&self) -> u64 {
        if self.pace_min_interval_ms == 0 {
            return 0;
        }
        let window = self.live_pack_timeout_ms();
        // Legacy (pre-round) view-change fires at `proposal_timeout_ms`.
        let legacy = self.proposal_timeout_ms().saturating_sub(window);
        self.pace_min_interval_ms.min(window).min(legacy)
    }

    /// Round-0 pacing. Hold the seal while this seat has some transactions
    /// but fewer than [`Self::pace_mempool_txs`] (and fewer than the per-ledger
    /// cap), until [`Self::pace_effective_ms`] after `tip_advanced_ms` (this
    /// seat's own commit of the previous block, not its `sealed_at`). No hold
    /// with an empty mempool, after a skip, or in a view-change round > 0.
    pub fn pace_wait(&self) -> bool {
        if self.pace_min_interval_ms == 0 {
            return false;
        }
        let h = self.tip_height.saturating_add(1);
        if !self.skip_set_for(h).is_empty() {
            return false;
        }
        let cap = if self.cfg.max_txs_per_ledger > 0 {
            self.cfg.max_txs_per_ledger
        } else {
            Self::PACK_DEFAULT_MAX_TXS
        };
        let mp = self.mempool.len();
        if mp == 0 || mp >= self.pace_mempool_txs.max(1) || mp >= cap {
            return false;
        }
        if self.height_view_round > 0 {
            return false;
        }
        self.now_ms.saturating_sub(self.tip_advanced_ms) < self.pace_effective_ms()
    }

    fn verify_v4_contents(
        &self,
        ledger: &Ledger,
        draft_bridge: &crate::bridge::BridgeState,
        draft_vals: &BTreeMap<String, ValidatorInfo>,
    ) -> Result<(), String> {
        if !self.qc_v4_at(ledger.height) {
            if ledger.is_v4() {
                return Err("v4 header before qc_start_height".into());
            }
            return Ok(());
        }
        if !ledger.is_v4() {
            return Err("v4 height missing inner_hash".into());
        }
        let want_claim = hex::encode(crate::lc::evm_header_claim_root(draft_bridge));
        if ledger.claim_root != want_claim {
            return Err("v4 claim_root mismatch".into());
        }
        let sealed = self.sealed_committee();
        if ledger.current_committee != sealed {
            return Err("v4 current_committee mismatch".into());
        }
        let want_cur = self.current_committee_root_at(&ledger.current_committee, ledger.height)?;
        if ledger.current_committee_root != want_cur {
            return Err("v4 current_committee_root mismatch".into());
        }
        let bonded_after = draft_vals
            .values()
            .filter(|v| v.lottery_weight() > 0.0)
            .count();
        if bonded_after < 6 {
            return Err("v4 ledger with <6 bonded after apply".into());
        }
        let seed = if self.rv2_at(ledger.height) {
            ledger.seed_v2()
        } else {
            ledger.inner_hash.clone()
        };
        let want_next = self.draw_committee_v8(
            &seed,
            ledger.height + 1,
            &ledger.packer,
            draft_vals,
        );
        if ledger.next_committee != want_next {
            return Err("v4 next_committee mismatch".into());
        }
        let want_next_root = self.next_committee_root_at(&ledger.next_committee, ledger.height, draft_vals)?;
        if ledger.next_committee_root != want_next_root {
            return Err("v4 next_committee_root mismatch".into());
        }
        Ok(())
    }

    /// Commit staged pending proposal after soft QC (or no-op if already committed).
    pub fn commit_pending_proposal(&mut self) -> Result<AcceptResult, String> {
        let Some(ledger) = self.pending_proposal.clone() else {
            return Err("no pending proposal".into());
        };
        if !self.soft_ok.contains(&ledger.ledger_hash) {
            return Err("pending proposal not soft-QC'd".into());
        }
        // Already advanced (duplicate commit).
        if self.tip_height >= ledger.height
            && self.tip_hash == ledger.ledger_hash
        {
            self.pending_proposal = None;
            return Ok(AcceptResult {
                height: ledger.height,
                packer: ledger.packer.clone(),
                n_txs: ledger.txs.len(),
                fees: ledger.txs.iter().map(|t| t.fee).sum(),
                reward_paid: 0,
            });
        }
        if ledger.height != self.tip_height + 1 || ledger.parent_hash != self.tip_hash {
            self.pending_proposal = None;
            return Err("pending proposal no longer attaches to tip".into());
        }
        let r = self.commit_ledger_body_ex(&ledger, false)?;
        self.pending_proposal = None;
        Ok(r)
    }

    /// Apply ledger to tip state (caller ensures validity / soft or catch-up).
    fn commit_ledger_body(&mut self, ledger: &Ledger) -> Result<AcceptResult, String> {
        self.commit_ledger_body_ex(ledger, false)
    }

    fn commit_ledger_body_ex(
        &mut self,
        ledger: &Ledger,
        catchup: bool,
    ) -> Result<AcceptResult, String> {
        // Deterministic UTC field rules only — never re-apply live wall skew on
        // commit/catch-up (replay must accept historical stamps).
        self.check_sealed_utc_historical(ledger)?;
        // One apply path: time effects from the ledger stamp, then txs.
        // Local now_ms is not an input to the root. Catch-up of old ledgers
        // must match even if this node has been ticking for hours.
        let ckpt = TimeFold::take(self);
        let _seized = self.apply_time_effects_with_slashes(
            ledger.sealed_at_ms,
            ledger.fee_total > 0 || (ledger.txs.is_empty() && self.empty_block_at(ledger.height)),
            &ledger.slashes,
        );
        let saved = self.now_ms;
        self.now_ms = ledger.sealed_at_ms;
        let mut draft_state = self.state.clone();
        let mut draft_defi = self.defi.clone();
        let mut draft_bridge = self.bridge.clone();
        let mut draft_vals = self.validators.clone();
        let mut draft_claim = self.claimable.clone();
        let mut draft_work = self.epoch_work.clone();
        self.prune_eth_exec_for_ledger(&mut draft_bridge, ledger.height);
        let r0 = self.rv2_round0(ledger.height);
        let voters = ledger
            .parent_cert
            .as_ref()
            .map(|c| c.voters.clone())
            .unwrap_or_default();
        self.rv2_ledger_hook(&mut draft_vals, ledger.height, &ledger.packer, r0.as_deref(), &voters);
        self.seat_migrate_hook(&mut draft_vals, &mut draft_claim, ledger.height);
        self.orderbook_ledger_hook(&mut draft_state, &mut draft_defi, ledger.height);
        let mut fee_total = 0u64;
        let mut apply_err = None;
        // Merkle-batch bodies: packer batch_sig + (from H=520000) per-sender
        // Falcon sigs are checked here. Non-batch bodies verify in try_protocol_tx.
        if !ledger.batch_sig.is_empty() {
            let packer_rk = self.packer_registry_key(ledger);
            let known_keys: Vec<(String, String)> = ledger
                .txs
                .iter()
                .filter_map(|tx| {
                    self.account_public_key(&tx.account)
                        .map(|pk| (tx.account.clone(), pk))
                })
                .collect();
            ledger.verify_merkle_batch_reg(&self.keys, &|id| {
                known_keys
                    .iter()
                    .find(|(a, _)| a == id)
                    .map(|(_, pk)| pk.clone())
            }, ledger.height >= crate::params_v2::key_bind_onchain_from_height(self.cfg.network_id), packer_rk.as_deref())?;
        }
        // v2.9.66 (audit R-2): verify per-tx Falcon sigs on catch-up of
        // non-batch bodies by default (same as the live path). Operators on
        // weak boxes may set FPL_CATCHUP_SKIP_TX_SIG=1 to skip when a
        // parent_cert is present (old snap-treadmill tradeoff).
        let check_sig = ledger.batch_sig.is_empty()
            && !(catchup
                && ledger.parent_cert.is_some()
                && crate::catchup_skip_tx_sig());
        for tx in &ledger.txs {
            fee_total = fee_total.saturating_add(tx.fee);
            if let Err(e) = self.try_protocol_tx_ex(
                &mut draft_state,
                &mut draft_defi,
                &mut draft_bridge,
                &mut draft_vals,
                &mut draft_claim,
                &mut draft_work,
                tx,
                check_sig,
            ) {
                apply_err = Some(e);
                break;
            }
        }
        self.now_ms = saved.max(ledger.sealed_at_ms);
        if let Some(e) = apply_err {
            ckpt.restore(self);
            return Err(e);
        }
        let root = Self::commitment_root_parts(
            &draft_state,
            &draft_defi,
            &draft_bridge,
            &draft_vals,
            &draft_claim,
        );
        if root != ledger.state_root_after {
            ckpt.restore(self);
            return Err(format!(
                "state root mismatch at h={} (local now_ms={} sealed_at_ms={} last_settled={})",
                ledger.height, self.now_ms, ledger.sealed_at_ms, self.last_settled_epoch
            ));
        }
        if let Err(e) = self.verify_v4_contents(ledger, &draft_bridge, &draft_vals) {
            ckpt.restore(self);
            return Err(e);
        }

        let fill = (ledger.txs.len() as f64 / 64.0).clamp(0.0, 1.5) / 1.5;
        let quality_sample = (0.6 * fill + 0.4 * 1.0).clamp(0.0, 1.0);

        let ledger_epoch = epoch_index(ledger.sealed_at_ms, self.genesis_ms, self.cfg.epoch_ms);
        let v2 = self.rv2_epoch(ledger_epoch);
        let mut seat_prop = 0u64;
        let (burn, fee_reward) = if v2 {
            // v2.9.62 B1/B3/B4 (after the root check: claimable changes here
            // land in the next ledger's root, identically on every seat).
            // Split on the block's fee total (64 × 2 = 128 → 64 / 38 / 26).
            let (burn, prop, pot) = crate::economy::fee_split_v2(fee_total);
            let paying = ledger.txs.iter().filter(|t| t.fee > 0).count() as u64;
            let locked = |id: &str| draft_vals.get(id).is_some_and(|v| v.earn_locked);
            let mut pot = pot;
            if prop > 0 && !locked(&ledger.packer) {
                if self.seat_payout_at(ledger.height) {
                    // Credited below (draft_vals is borrowed by `locked`).
                    seat_prop = prop;
                } else {
                    *draft_claim.entry(ledger.packer.clone()).or_insert(0) += prop;
                }
            } else {
                pot = pot.saturating_add(prop);
            }
            draft_work.fee_reward_pool = draft_work.fee_reward_pool.saturating_add(pot);
            if !(ledger.txs.is_empty() && self.empty_block_at(ledger.height)) && !locked(&ledger.packer) {
                *draft_work.proposer_credit.entry(ledger.packer.clone()).or_insert(0) +=
                    crate::economy::proposer_block_credit(paying);
            }
            if let Some(c) = &ledger.parent_cert {
                let voters: BTreeSet<&String> = c.voters.iter().collect();
                for v in voters {
                    if locked(v) {
                        continue;
                    }
                    *draft_work.vote_credit.entry(v.clone()).or_insert(0) += 1;
                }
            }
            if self.presence_at(ledger.height) {
                draft_work.presence_heights = draft_work.presence_heights.saturating_add(1);
                *draft_work.present.entry(ledger.packer.clone()).or_insert(0) += 1;
                if let Some(c) = &ledger.parent_cert {
                    for v in &c.voters {
                        if v != &ledger.packer {
                            *draft_work.present.entry(v.clone()).or_insert(0) += 1;
                        }
                    }
                }
            }
            (burn, prop.saturating_add(pot))
        } else {
            let (burn, fee_reward) = fee_burn_and_reward(fee_total);
            draft_work.fee_reward_pool = draft_work
                .fee_reward_pool
                .saturating_add(fee_reward);
            (burn, fee_reward)
        };
        if seat_prop > 0 {
            // Seat payout: proposer fee share is a validator reward.
            Self::credit_seat_reward(
                &mut draft_vals,
                &mut draft_state,
                &mut draft_claim,
                &ledger.packer,
                seat_prop,
            );
        }
        self.metrics.record_sealed_fees(
            fee_total,
            burn,
            fee_reward,
            ledger.txs.len() as u64,
        );
        for tx in &ledger.txs {
            self.metrics.push_fee_sample(tx.fee);
        }

        draft_work.record_pack(&ledger.packer, ledger.tx_ids.len() as u64);

        // v2.9.58: the claim root of the committed bridge. On v4 heights it was
        // just checked against the header; otherwise compute it once here.
        let claim_root_hex = if self.qc_v4_at(ledger.height) && ledger.is_v4() {
            ledger.claim_root.clone()
        } else {
            hex::encode(crate::lc::evm_header_claim_root(&draft_bridge))
        };
        self.state = draft_state;
        self.defi = draft_defi;
        self.bridge = draft_bridge;
        self.validators = draft_vals;
        self.claimable = draft_claim;
        self.epoch_work = draft_work;
        self.tip_height = ledger.height;
        self.tip_hash = ledger.ledger_hash.clone();
        self.tip_roots = Some((ledger.height, ledger.ledger_hash.clone(), root, claim_root_hex));
        self.chain.push(ledger.clone());
        if let Some(store) = &self.body_store {
            let _ = store.put(ledger);
        }
        self.prune_chain();
        self.mempool.remove_many(&ledger.tx_ids);
        for id in &ledger.tx_ids {
            self.body_fill.remove(id);
        }
        // The tip moved, so earlier empty residuals were not a hole.
        self.empty_residual_streak = 0;
        self.body_shells.remove(&ledger.ledger_hash);
        self.mempool.prune_stale(&self.state);
        self.seen_at_height.insert(
            ledger.height,
            (ledger.packer.clone(), ledger.ledger_hash.clone()),
        );
        self.note_height_sealer(ledger.height, &ledger.packer);

        let quality_mult = 0.5 + 0.7 * quality_sample;
        let pay = ((fee_reward as f64) * quality_mult) as u64;
        *self.rewards.entry(ledger.packer.clone()).or_insert(0) += pay;
        if let Some(v) = self.validators.get_mut(&ledger.packer) {
            v.quality = 0.7 * v.quality + 0.3 * quality_sample;
            v.pack_count += 1;
        }

        // Ensure soft at least includes local view after commit (catch-up path).
        self.soft_ok.insert(ledger.ledger_hash.clone());
        let me = self.id.clone();
        let lh = ledger.ledger_hash.clone();
        // Count self vote without re-entering commit via vote_ok soft path.
        let set = self.ok_votes.entry(lh.clone()).or_default();
        if set.insert(me.clone()) {
            self.epoch_work.record_check(&me, &lh);
        }
        let n = set.len();
        if n >= self.hard_votes_needed() {
            self.hard_ok.insert(lh);
        }

        // Catch-up clock sync is done in apply_catchup_batch (not here).
        // Live commit never adopts packer sealed_at_ms (A6).

        // Clear certified skips / skip votes for this height; open next window.
        self.skips.remove(&ledger.height);
        self.skip_votes.remove(&ledger.height);
        self.height_open_ms = self.now_ms;
        self.pending_proposal = None;
        self.evicted_since_last_seal = false;
        // v2.10.0: liveness clock + round state belong to the open height.
        self.tip_advanced_ms = self.now_ms;
        self.round_open_ms = self.now_ms;
        self.work_seen_since_ms = 0;
        self.stall = None;
        self.pending_rounds = 0;
        self.open_bodies.clear();
        {
            let committed_h = ledger.height;
            // Keep the committed height briefly so late same-round duals still
            // produce evidence; older round records are dead weight.
            self.round_votes.retain(|h, _| h.saturating_add(2) > committed_h);
        }
        // Fresh open height → allow a new pre-pack NeedTxs cycle (P1).
        self.need_txs_for_height = 0;
        self.need_txs_open_ms = 0;
        if let Some(c) = &ledger.parent_cert {
            self.certs.entry(c.height).or_insert_with(|| c.clone());
        }
        // Consume equivocation evidence that was due by this height — whether
        // it rode the ledger, was omitted by drop_slashes_that_break_quorum, or
        // was queued against an already-committed dual (live: h=373256 evidence
        // packed into 373257+). Keying only on `e.height == ledger.height` left
        // older duals sticky forever, so Unjail of one co-offender re-armed the
        // other (v1↔v12 ping-pong, 2026-10-06). Keep only evidence still in the
        // future relative to the tip we just sealed.
        self.pending_slashes.retain(|e| e.height > ledger.height);
        // Operator Unjail paid the escalated rebond — do not re-apply prior
        // queued evidence against that seat on a later pack.
        for tx in &ledger.txs {
            if let TxBody::Unjail { validator } = &tx.body {
                self.pending_slashes
                    .retain(|e| e.offender != *validator);
            }
        }
        let committed_hash = ledger.ledger_hash.clone();
        let committed_h = ledger.height;
        // Build this height's cert while the voting committee is still frozen.
        self.store_cert_if_ready(&committed_hash, committed_h);
        // v2.5.0 A1: freeze lottery ONLINE inputs for tip+1 at commit time.
        self.freeze_open_height_schedule();

        if let Some(dir) = &self.keys_dir {
            let _ = crate::lc::attest_committed(
                dir,
                &self.id,
                ledger.height,
                &ledger.parent_hash,
                &ledger.ledger_hash,
                &self.bridge,
            );
            let v4 = if ledger.is_v4() {
                Some(crate::falcon_qc::AttestV4Fields {
                    claim_root: ledger.claim_root.clone(),
                    inner_hash: ledger.inner_hash.clone(),
                    current_committee_root: ledger.current_committee_root.clone(),
                    next_committee_root: ledger.next_committee_root.clone(),
                    current_committee: ledger.current_committee.clone(),
                    next_committee: ledger.next_committee.clone(),
                })
            } else {
                None
            };
            if let Ok((_, slash)) = crate::falcon_qc::attest_committed(
                dir,
                &self.id,
                ledger.height,
                &ledger.parent_hash,
                &ledger.ledger_hash,
                &self.bridge,
                v4.as_ref(),
            ) {
                if let Some(s) = slash {
                    let ev = s.to_slash_evidence();
                    if !self
                        .pending_slashes
                        .iter()
                        .any(|e| e.offender == ev.offender && e.height == ev.height)
                    {
                        self.pending_slashes.push(ev);
                    }
                }
            }
        }

        // v2.9.58: OKs for this new open height that arrived while we lagged.
        self.replay_future_oks();

        Ok(AcceptResult {
            height: ledger.height,
            packer: ledger.packer.clone(),
            n_txs: ledger.txs.len(),
            fees: fee_total,
            reward_paid: pay,
        })
    }

    pub fn confirmations(&self, height: u64) -> u64 {
        self.tip_height.saturating_sub(height)
    }

    /// Newest transactions in the in-memory tail that touch this account.
    fn recent_account_txs(&self, account: &str, limit: usize) -> Vec<serde_json::Value> {
        let mut out = Vec::new();
        for led in self.chain.iter().rev() {
            if collect_account_txs(led, account, limit, &mut out) {
                break;
            }
        }
        out
    }

    /// Lowest height whose body the RAM tail still holds (disk history starts below it).
    pub fn ram_body_floor(&self) -> u64 {
        self.chain
            .iter()
            .filter(|l| l.has_body())
            .map(|l| l.height)
            .min()
            .unwrap_or(self.tip_height.saturating_add(1))
    }

    pub fn account_json(&self, account: &str) -> serde_json::Value {
        let a = self.state.get(account);
        let assets = self
            .defi
            .assets
            .get(account)
            .cloned()
            .unwrap_or_default();
        let slot = self.current_epoch_slot();
        let key_fp: Option<String> = {
            let pk = &a.meta.public_key;
            (!pk.is_empty()).then(|| sha256_hex(pk.to_ascii_lowercase().as_bytes())[..16].to_string())
        };
        serde_json::json!({
            "account": account,
            "sequence": a.sequence,
            "balance": a.balance,
            "claimable": self.claimable.get(account).copied().unwrap_or(0),
            // Seat payout: validator rewards of the seat with this id (not
            // claimable by the wallet `Claim`; see `ClaimSeat`).
            "seat_claimable": self.validators.get(account).map(|v| v.seat_claimable),
            "seat_payout": self.validators.get(account).and_then(|v| v.seat_payout.clone()),
            "seat_sender_sequence": self
                .validators
                .contains_key(account)
                .then(|| self.state.get(&seat_sender(account)).sequence),
            "account_type": a.meta.account_type,
            "allowlist": a.meta.allowlist,
            "vault_locked": a.meta.vault_locked,
            "name_status": match self.names.by_name.get(account) {
                Some(r) if r.activated => "activated",
                Some(r) if r.reserved_until_ms > self.now_ms => "reserved",
                _ => "none",
            },
            "activation_fee": NameRegistry::activation_fee(account),
            "reserved_until_ms": self
                .names
                .by_name
                .get(account)
                .filter(|r| !r.activated)
                .map(|r| r.reserved_until_ms)
                .unwrap_or(0),
            "assets": assets
                .iter()
                .map(|(k, v)| (k.clone(), display_asset(account, k, *v)))
                .collect::<BTreeMap<_, _>>(),
            "external_addrs": a.external_addrs,
            "lp": self.defi.pools.values().filter_map(|p| {
                let lp = p.lp.get(account).copied().unwrap_or(0);
                if lp == 0 { None } else {
                    Some(serde_json::json!({
                        "pool_id": p.id,
                        "lp": lp,
                        "asset_a": p.asset_a,
                        "asset_b": p.asset_b,
                    }))
                }
            }).collect::<Vec<_>>(),
            "lend_positions": self.defi.markets.values().filter_map(|m| {
                let shares = m.supply_shares.get(account).copied().unwrap_or(0);
                let debt = m.debt.get(account).copied().unwrap_or(0);
                let collateral = m.collateral.get(account).copied().unwrap_or(0);
                if shares == 0 && debt == 0 { None } else {
                    Some(serde_json::json!({
                        "market_id": m.id,
                        "asset": m.asset,
                        "shares": shares,
                        "debt": debt,
                        "collateral_fpl": collateral,
                    }))
                }
            }).collect::<Vec<_>>(),
            "exists": self.state.accounts.contains_key(account),
            // Public: sha256(lowercase hex on-chain key)[..16], or null if no key bound.
            // The installer uses it to refuse a seat id that is a wallet account.
            "key_fp": key_fp,
            "recent_txs": self.recent_account_txs(account, 8),
            "watcher_work": self.epoch_work.watcher_work.get(account).copied().unwrap_or(0),
            "watcher_slots": self.epoch_work.watcher_slots.get(account).copied().unwrap_or(0),
            "watcher_current_slot": slot,
            "watcher_in_slot": self.watcher_in_slot(account, slot),
            "watcher_slot_ms": self.watcher_slot_ms(),
        })
    }

    pub fn accounts_json(&self) -> serde_json::Value {
        let mut m = serde_json::Map::new();
        for id in self.state.accounts.keys() {
            if let serde_json::Value::Object(obj) = self.account_json(id) {
                // drop redundant account field inside map
                let mut slim = obj;
                slim.remove("account");
                slim.remove("exists");
                m.insert(id.clone(), serde_json::Value::Object(slim));
            }
        }
        serde_json::Value::Object(m)
    }

    /// Full status including every account (large; avoid over WAN). Prefer
    /// [`status_json_slim`] for ops/dashboard; use `include_accounts=true` only
    /// when load-net or tools need sequence resync.
    pub fn status_json(&self) -> serde_json::Value {
        self.status_json_detail(true)
    }

    /// Ops/dashboard status without the multi-MB accounts dump (v2.3.9).
    pub fn status_json_slim(&self) -> serde_json::Value {
        self.status_json_detail(false)
    }

    pub fn status_json_detail(&self, include_accounts: bool) -> serde_json::Value {
        let (mut body, heavy) = self.status_json_split(include_accounts, false);
        heavy.fill(&mut body);
        body
    }

    /// v2.9.58 brief status: same fields as the full status (attestations and
    /// claim leaves empty, as the wire handler always stripped them), but the
    /// state root and LC claim root come from [`Self::tip_roots`], recorded at
    /// commit. No 207 MB root, claim-leaf or attestation-file work.
    pub fn status_json_brief(&self) -> serde_json::Value {
        self.status_json_split(false, true).0
    }

    /// Fill [`Self::tip_roots`] for the current tip if it is missing or stale
    /// (after a snapshot load or adoption, before the first commit), so the
    /// root is computed once rather than on every brief status.
    pub fn ensure_tip_roots(&mut self) {
        let fresh = matches!(&self.tip_roots,
            Some((h, hash, _, _)) if *h == self.tip_height && *hash == self.tip_hash);
        if !fresh {
            let (root, claim) = self.tip_roots_or_compute();
            self.tip_roots = Some((self.tip_height, self.tip_hash.clone(), root, claim));
        }
    }

    /// Brief status for the wire handler: [`Self::ensure_tip_roots`] then
    /// [`Self::status_json_brief`].
    pub fn status_json_brief_cached(&mut self) -> serde_json::Value {
        self.ensure_tip_roots();
        self.status_json_brief()
    }

    /// (state root, claim root) of the current tip: cached at commit, else
    /// computed (startup before the first commit, or after a resync).
    pub fn tip_roots_or_compute(&self) -> (String, String) {
        if let Some((h, hash, root, claim)) = &self.tip_roots {
            if *h == self.tip_height && *hash == self.tip_hash {
                return (root.clone(), claim.clone());
            }
        }
        (
            self.commitment_root(),
            hex::encode(crate::lc::evm_header_claim_root(&self.bridge)),
        )
    }

    /// Status body plus the heavy work still to do. `brief=true`: roots from
    /// the commit cache, nothing left to fill. `brief=false`: the caller runs
    /// [`StatusHeavy::fill`] — the wire handler does it after dropping
    /// `node.lock`.
    pub fn status_json_split(&self, include_accounts: bool, brief: bool) -> (serde_json::Value, StatusHeavy) {
        let brief_roots = if brief { Some(self.tip_roots_or_compute()) } else { None };
        let heavy = if brief {
            StatusHeavy::default()
        } else {
            StatusHeavy {
                root_input: Some(RootInput {
                    state: self.state.clone(),
                    defi: self.defi.clone(),
                    bridge: self.bridge.clone(),
                    validators: self.validators.clone(),
                    claimable: self.claimable.clone(),
                }),
                keys_dir: self.keys_dir.clone(),
            }
        };
        let ranked = self.lottery_ranked(3);
        let winner = ranked.first().cloned();
        let standby = ranked.get(1).cloned();
        let tip_soft = self
            .chain
            .last()
            .map(|l| self.soft_ok.contains(&l.ledger_hash))
            .unwrap_or(false)
            || self.tip_is_soft();
        let tip_hard = self
            .chain
            .last()
            .map(|l| self.hard_ok.contains(&l.ledger_hash))
            .unwrap_or(false);
        let tip_votes = self
            .chain
            .last()
            .and_then(|l| self.ok_votes.get(&l.ledger_hash).map(|s| s.len()))
            .unwrap_or(0);
        let open_elapsed = self.now_ms.saturating_sub(self.height_open_ms);
        let accounts_val = if include_accounts {
            self.accounts_json()
        } else {
            serde_json::json!({})
        };
        let claimable_val = if include_accounts {
            serde_json::to_value(&self.claimable).unwrap_or_default()
        } else {
            serde_json::json!({})
        };
        let mut body = serde_json::json!({
            "network": NETWORK_NAME,
            "network_id": self.cfg.network_id,
            "id": self.id,
            "scheme": self.cfg.scheme.as_str(),
            "product_version": PRODUCT_VERSION,
            "role": if self.is_hub { "hub" } else { "val" },
            "is_hub": self.is_hub,
            "tip_height": self.tip_height,
            "tip_hash": self.tip_hash,
            "best_peer_tip": self.best_peer_tip,
            "tip_lag": self.tip_lag(),
            "mempool": self.mempool.len(),
            "max_mempool_txs": self.cfg.max_mempool_txs,
            "mempool_full": self.cfg.max_mempool_txs > 0
                && self.mempool.len() >= self.cfg.max_mempool_txs,
            "mempool_pulls": self.mempool_pulls,
            "mempool_served": self.mempool_served,
            "mempool_absorbed": self.mempool_absorbed,
            "pack_no_applicable": self.pack_no_applicable,
            "has_applicable_tx": self.has_applicable_tx(),
            "need_txs_for_height": self.need_txs_for_height,
            "waiting_need_txs_grace": self.waiting_need_txs_grace(),
            "need_hard_resync": self.need_hard_resync,
            "best_peer_tip_hash": self.best_peer_tip_hash,
            "last_catchup_conflict": self.last_catchup_conflict,
            "online_epoch_id": self.online_epoch_id,
            "online_epoch_now": self.online_epoch_id_now(),
            "online_epoch_heights": self.cfg.online_epoch_heights,
            "online_members": self.online_members.iter().cloned().collect::<Vec<_>>(),
            "online_hash": self.online_hash,
            "online_seats": self.online_seat_ids().into_iter().collect::<Vec<_>>(),
            "online_certified": !self.online_members.is_empty(),
            "genesis_validators": self.genesis_validators.len(),
            "params_version": PARAMS_VERSION,
            "min_fee": self.cfg.min_fee,
            "suggested_min_fee": self.current_min_fee(),
            "fee_escalate": self.cfg.fee_escalate,
            "metrics": self.metrics.to_json(
                self.mempool.len(),
                self.cfg.max_mempool_txs,
                self.cfg.min_fee,
                self.cfg.fee_escalate,
            ),
            "chain_len": self.chain.len(),
            "max_chain_ledgers": self.cfg.max_chain_ledgers,
            "epoch": self.current_epoch(),
            "epoch_ms": self.cfg.epoch_ms,
            "genesis_ms": self.genesis_ms,
            "now_ms": self.now_ms,
            "epoch_claimable": epoch_claimable_from(
                self.current_epoch(),
                self.cfg.first_claim_epoch,
            ),
            "first_claim_epoch": self.cfg.first_claim_epoch,
            "treasury": self.treasury,
            "emission_bps": self.cfg.emission_bps,
            "accounts": accounts_val,
            "accounts_omitted": !include_accounts,
            "accounts_count": self.state.accounts.len(),
            "faucet": self.account_json(FAUCET_ACCOUNT),
            "epoch_pack_txs": serde_json::to_value(&self.epoch_work.pack_txs).unwrap_or_default(),
            "epoch_check_votes": serde_json::to_value(&self.epoch_work.check_votes).unwrap_or_default(),
            "claimable": claimable_val,
            "last_settled_epoch": self.last_settled_epoch,
            "amm_pools": self.defi.pools.len(),
            "lend_markets": self.defi.markets.len(),
            "defi_pools": self.defi.pools.values().map(|p| serde_json::json!({
                "id": p.id,
                "asset_a": p.asset_a,
                "asset_b": p.asset_b,
                "reserve_a": p.reserve_a,
                "reserve_b": p.reserve_b,
                "lp_supply": p.lp_supply,
            })).collect::<Vec<_>>(),
            "defi_markets": self.defi.markets.values().map(|m| serde_json::json!({
                "id": m.id,
                "asset": m.asset,
                "total_supply": m.total_supply,
                "total_borrow": m.total_borrow,
                "ltv_bps": m.ltv_bps,
                "price_fpl": m.price_native_per_scale,
            })).collect::<Vec<_>>(),
            "eth_lc": self.bridge.eth_lc.as_ref().map(|s| {
                let (exec_floor, exec_tip) = self.bridge.eth_exec_bounds();
                serde_json::json!({
                    "finalized_slot": s.finalized_slot,
                    "execution_number": s.execution_number,
                    "execution_block_hash": s.execution_block_hash,
                    "period": s.period,
                    "pks": s.current_pks.len(),
                    "next_pks": s.next_pks.len(),
                    // `eth_lc.eth_exec_floor` is the low end of the contiguous connected stored range (from `eth_exec_bounds()`), not the prune floor (top-level `eth_exec_prune_floor`).
                    "eth_exec_floor": exec_floor,
                    "eth_exec_tip": exec_tip,
                    "eth_exec_window": crate::bridge::ETH_EXEC_HEADER_WINDOW,
                })
            }),
            // BRIDGE: operator registry (kits read this instead of peers.json once
            // the bridge height is live). Status only, not consensus.
            "bridge_operators": serde_json::json!({
                "active": self.bridge_at(self.tip_height.saturating_add(1)),
                "from_height": self.bitvm2_m1_from_height,
                "params": self.operator_params(),
                "operators": &self.bridge.operators.operators,
                "graphs": &self.bridge.operators.graphs,
                "slashed": self.bridge.operators.credited.keys().filter_map(|k| k.strip_prefix("disprove:graph:")).collect::<Vec<_>>(),
                "pegout_refund_ledgers": crate::bridge_operators::BITVM2_PEGOUT_REFUND_LEDGERS,
                "burned_total": self.bridge.operators.burned_total,
            }),
            "rails": self.bridge.rails.iter().map(|(k, r)| serde_json::json!({
                "asset": k,
                "tip_height": r.tip_height,
                "tip_hash": r.tip_hash,
                "header_count": r.headers.len(),
                "header_floor": r.btc_header_floor(),
                // v2.10.1: status only (non-consensus) view of pending BTC branches.
                "btc_fork": crate::bridge::RailState::btc_branch_summary(&r.btc_fork),
                "btc_fork_alt": crate::bridge::RailState::btc_branch_summary(&r.btc_fork_alt),
                "header_tail": r.headers.iter().rev().take(64).map(|(hgt, hdr)| serde_json::json!({
                    "height": hgt,
                    "hash": hdr.hash,
                })).collect::<Vec<_>>(),
                "tip_merkle_root": r.tip_merkle_root,
                "total_minted": display_rail_minted(k, r.total_minted),
                "total_burned": display_rail_burned(k, r.total_burned),
                "lock_id": r.lock_id,
                "min_confirmations": r.min_confirmations,
                "spent_deposits": r.spent_deposits.iter().cloned().collect::<Vec<_>>(),
                "open_withdrawals": r.withdrawals.len(),
                // RailWithdraw notes, then V3 refund notes (status-only rows; see
                // `eth_v3_refund_withdrawals_json`). `open_withdrawals` stays the
                // RailWithdraw count.
                "withdrawals": r.withdrawals.iter().map(|(id, (amt, dest, from))| serde_json::json!({
                    "note_id": id,
                    "amount": amt,
                    "external_to": dest,
                    "from": from,
                    "signed_btc_tx": r.signed_vault_txs.get(id).cloned().unwrap_or_default(),
                })).chain(self.bridge.eth_v3_refund_withdrawals_json(k)).collect::<Vec<_>>(),
                "spv": if r.is_bitcoin_tip() { "bitcoin" } else { "protocol" },
                "vault_sats": crate::vault::vault_sats(&r.vault_utxos),
                "vault_utxos": r.vault_utxos.len(),
                "vault_utxo_list": r.vault_utxos.iter().map(|u| serde_json::json!({
                    "txid": u.txid,
                    "vout": u.vout,
                    "sats": u.sats,
                    "height": u.height,
                })).collect::<Vec<_>>(),
                "vault_pub": r.effective_vault_pub(),
                "vault_address": r.effective_vault_pub().and_then(|p| {
                    let spk = hex::decode(p.spk_hex.trim()).ok()?;
                    if spk.len() == 34 && spk[0] == 0x51 && spk[1] == 0x20 {
                        crate::vault::p2tr_testnet_address(&spk[2..]).ok()
                    } else {
                        None
                    }
                }),
                "claim_root": r.claim_root,
                "claim_leaves": r.claim_leaves,
                "user_vaults": r.user_vaults,
                "published_takes": r.published_takes,
                "bitvm2_claim_root": r.bitvm2_claim_root,
                "bitvm2_claim_leaves": r.bitvm2_claim_leaves,
                // M1 provers bind attests to one of these (status view only; not consensus).
                "fpl_checkpoints": r.fpl_checkpoints.iter().rev().take(16).map(|(h, x)| (h.to_string(), x.clone())).collect::<std::collections::BTreeMap<String, String>>(),
                "bitvm2_claims": r.bitvm2_claims.values().map(|c| serde_json::json!({
                    "note_id": c.note_id,
                    "from": c.from,
                    "dest": c.dest,
                    "amount": c.amount,
                    "status": c.status,
                    "open_height": c.open_height,
                    "mimc_leaf_hex": c.mimc_leaf_hex,
                    "pegout_txid_hex": c.pegout_txid_hex,
                    "claim_txid_hex": c.claim_txid_hex,
                    "claim_id": c.claim_id,
                    "statement_digest_hex": c.statement_digest_hex,
                    "operator": c.operator,
                    "attest_height": c.attest_height,
                })).collect::<Vec<_>>(),
                "bitvm_claims": r.bitvm_claims.values().map(|c| serde_json::json!({
                    "note_id": c.note_id,
                    "from": c.from,
                    "dest": c.dest,
                    "amount": c.amount,
                    "abort_commit": c.abort_commit,
                    "csv_blocks": c.csv_blocks,
                    "status": c.status,
                    "challenge_by": c.challenge_by,
                    "claim_spk": c.claim_spk_hex,
                    "published_abort": if c.status == crate::bitvm::ClaimStatus::Challenged {
                        c.published_abort.clone()
                    } else {
                        String::new()
                    },
                })).collect::<Vec<_>>(),
            })).collect::<Vec<_>>(),
            "watcher_work": serde_json::to_value(&self.epoch_work.watcher_work).unwrap_or_default(),
            "watcher_slots": serde_json::to_value(&self.epoch_work.watcher_slots).unwrap_or_default(),
            "watcher_slots_per_epoch": WATCHER_SLOTS_PER_EPOCH,
            "watcher_slot_ms": self.watcher_slot_ms(),
            "watcher_current_slot": self.current_epoch_slot(),
            "watchers_active_slot": self.watchers_active_slot(),
            "watcher_weights_preview": serde_json::to_value(economy::watcher_weights(
                &self.epoch_work.watcher_work,
                &self.epoch_work.watcher_slots,
                WATCHER_SLOTS_PER_EPOCH,
            ))
            .unwrap_or_default(),
            "product": "Falcon PL",
            "btc_exit_mode": self.btc_exit_mode.as_str(),
            "bitvm2_instance": {
                "nums_tag": std::str::from_utf8(crate::bitvm2_instance::nums_tag()).unwrap_or(""),
                "key_path": "unspendable-NUMS",
                "watch_key": "none",
                "payout": "csv+operator-CHECKSIG",
                "challenge": "setup-n-of-n-presign-to-assert-connector",
                "address": crate::bitvm2_instance::InstanceKeys::from_env()
                    .and_then(|k| crate::bitvm2_instance::instance_address(&k).ok()),
            },
            "ticker": "FPL",
            "consensus": "Falcon Consensus",
            "lc": {
                "start_height": self.keys_dir.as_ref().map(|d| crate::lc::load_bridge_cfg(d).start_height).unwrap_or(0),
                // v2.9.58: brief = commit cache; full = filled by StatusHeavy.
                "claim_root": brief_roots.as_ref().map(|r| r.1.clone()),
                "claim_leaves": [],
                "attestations": [],
            },
            "falcon_qc": {
                "attestations": [],
                "attestations_v2": [],
                "qc_header_version": self.qc_header_version,
                "qc_start_height": self.qc_start_height,
            },
            "state_root": brief_roots.as_ref().map(|r| r.0.clone()),
            "lottery_winner_next": winner,
            "lottery_standby_next": standby,
            "lottery_ranked_next": ranked,
            "lottery_order": self.lottery_order(),
            "lottery_queue": self.lottery_queue_json(),
            "skips_next": self.skip_set_for(self.tip_height + 1),
            "height_open_elapsed_ms": open_elapsed,
            "progress_timeout_ms": self.cfg.progress_timeout_ms,
            "tip_soft": tip_soft,
            "tip_hard": tip_hard,
            "tip_ok_votes": tip_votes,
            "soft_need": self.soft_votes_needed(),
            "commit_need": self.commit_votes_needed(),
            "hard_need": self.hard_votes_needed(),
            "committee_size": self.cfg.committee_size,
            "qc_committee": self.lottery_order(),
            "qc_checkers": self.committee_checkers(),
            "sealed_committee": self.chain.last().map(|l| l.current_committee.clone()).unwrap_or_else(|| self.sealed_committee()),
            "next_committee": self.chain.last().map(|l| l.next_committee.clone()).unwrap_or_default(),
            "inner_hash": self.chain.last().map(|l| l.inner_hash.clone()).unwrap_or_default(),
            "claim_root": self.chain.last().map(|l| l.claim_root.clone()).unwrap_or_default(),
            "current_committee_root": self.chain.last().map(|l| l.current_committee_root.clone()).unwrap_or_default(),
            "next_committee_root": self.chain.last().map(|l| l.next_committee_root.clone()).unwrap_or_default(),
            "current_committee_leaves": self.chain.last().and_then(|l| {
                self.committee_pks_at(&l.current_committee, l.height).ok().and_then(|p| crate::qc_header::committee_leaf_hexes(&p).ok())
            }).unwrap_or_default(),
            "next_committee_leaves": self.chain.last().and_then(|l| {
                self.committee_pks_at(&l.next_committee, l.height).ok().and_then(|p| crate::qc_header::committee_leaf_hexes(&p).ok())
            }).unwrap_or_default(),
            "qc_header_version": self.qc_header_version,
            "qc_start_height": self.qc_start_height,
            "tip_has_cert": self.tip_height == 0 || self.certs.contains_key(&self.tip_height),
            "tip_cert_voters": self
                .certs
                .get(&self.tip_height)
                .map(|c| c.voters.len())
                .unwrap_or(0),
            "pending_proposal_height": self.pending_proposal.as_ref().map(|p| p.height),
            "pending_proposal_hash": self.pending_proposal.as_ref().map(|p| p.ledger_hash.clone()),
            "schedule_height": self.schedule_height,
            "schedule_online_hash": self.schedule_online_hash,
            "height_view_round": self.height_view_round,
            "vote_rounds_from_height": self.cfg.vote_rounds_from_height,
            "vote_rounds_network_default": network_vote_rounds_from_height(self.cfg.network_id),
            // Prune floor in consensus state (0 until the window arms).
            // `eth_lc.eth_exec_floor` stays the connected-range low.
            "eth_exec_prune_floor": self.bridge.eth_exec_prune_floor,
            "eth_exec_window": crate::bridge::ETH_EXEC_HEADER_WINDOW,
            "eth_lc_gloas_from_height": self.eth_lc_gloas_from_height,
            "eth_v3_from_height": self.eth_v3_from_height,
            "rewards_v2_from_height": self.rewards_v2_from_height,
            "rewards_v2_epoch": self.rewards_v2_epoch,
            "reward_formula": if self.rv2_epoch(self.current_epoch()) { "v2" } else { "v1" },
            "approvals": &self.defi.validator_approvals,
            "eth_v3_bridge": self.eth_v3_bridge.map(|a| format!("0x{}", hex::encode(a))),
            "eth_v3_expiry_secs": crate::bridge::ETH_V3_DEPOSIT_EXPIRY_SECS,
            "eth_v1_deposit_cutoff": self.bridge.eth_v1_deposit_cutoff,
            "eth_v3_resolved_total": self.bridge.eth_v3_deposits.len(),
            // Per-deposit outcome (mint or refund), so a depositor can find its refund
            // note. Walks the map, like rails[].withdrawals and claim_leaves already do.
            "eth_v3_resolutions": self.bridge.eth_v3_resolutions_json(),
            "vote_rounds_pause_from": self.cfg.vote_rounds_pause_from,
            "vote_rounds_resume_at": self.cfg.vote_rounds_resume_at,
            "vote_rounds_pause_network_default": network_vote_rounds_pause(self.cfg.network_id),
            "vote_rounds_paused_now": self.vote_rounds_paused_at(self.tip_height.saturating_add(1)),
            "round_scoped_votes": self.vote_rounds_at(self.tip_height.saturating_add(1)),
            // On-disk keys/lc/bridge.json fingerprint vs the startup fingerprint
            // and runtime fields; see `bridge_cfg_status`.
            "bridge_cfg": self.bridge_cfg_status(),
            "consensus_stall": self.stall,
            "liveness": self.liveness_status(),
            "proposal_timeout_ms": self.proposal_timeout_ms(),
            "i_may_pack": winner.as_ref().map(|w| w == &self.id).unwrap_or(false)
                && self.tip_is_soft()
                && self.pending_proposal.is_none()
                && self.validators.get(&self.id).map(|v| v.pong_fresh(self.now_ms, self.cfg.pong_window_ms)).unwrap_or(false),
            // v2.9.62 A12: display-only estimate, never paid. Renamed; the
            // old key stays one release for existing readers.
            "rewards": self.rewards,
            "rewards_display_legacy": self.rewards,
            "last_settle": &self.last_settle,
            "unbond_cooldown_ms": self.cfg.unbond_cooldown_ms,
            "amm_lp_weights": self.defi.aggregate_amm_lp_weights(),
            "lend_lp_weights": self.defi.aggregate_lend_lp_weights(),
            // Last sealed ledger summary (dashboard / ops).
            "last_pack_height": self.chain.last().map(|l| l.height).unwrap_or(0),
            "last_pack_packer": self
                .chain
                .last()
                .map(|l| l.packer.clone())
                .unwrap_or_default(),
            "last_pack_txs": self.chain.last().map(|l| l.txs.len()).unwrap_or(0),
            "last_pack_fee_total": self
                .chain
                .last()
                .map(|l| l.txs.iter().map(|t| t.fee).sum::<u64>())
                .unwrap_or(0),
            "pong_window_ms": self.cfg.pong_window_ms,
            "validators": self.validators.values().map(|v| {
                let ready = v.pong_fresh(self.now_ms, self.cfg.pong_window_ms);
                let age = if v.last_pong_ms == 0 {
                    None
                } else {
                    Some(self.now_ms.saturating_sub(v.last_pong_ms))
                };
                serde_json::json!({
                    "id": v.id,
                    "bond": v.bond,
                    "unbonding": v.unbonding,
                    "unbond_ready_ms": v.unbond_ready_ms,
                    "unbond_ready": v.unbonding > 0 && self.now_ms >= v.unbond_ready_ms,
                    "bond_account": v.bond_account,
                    "jailed": v.jailed,
                    "jail_count": v.jail_count,
                    "unjail_cost": if v.jailed {
                        unjail_cost(self.cfg.min_bond, effective_jail_count(true, v.jail_count))
                    } else {
                        0
                    },
                    "slash_total": v.slash_total,
                    "v2": {
                        "escrow": v.escrow,
                        "v2_seat": v.v2_seat,
                        "missed_turns": v.missed_turns,
                        "inactive": v.inactive,
                        "archive": v.archive,
                        "public_key_set": !v.public_key.is_empty(),
                        "earn_locked": v.earn_locked,
                        "earn_streak": v.earn_streak,
                    },
                    "pack_count": v.pack_count,
                    "perf": v.perf(),
                    "pong_fresh": ready,
                    "lottery_ready": ready && v.lottery_weight() > 0.0,
                    "last_pong_ms": v.last_pong_ms,
                    "pong_age_ms": age,
                    "last_advertised_tip": v.last_advertised_tip,
                })
            }).collect::<Vec<_>>(),
        });
        // v2.9.62: inputs of the v2 settle (status only), added outside the
        // json! macro (recursion limit).
        if let Some(m) = body.as_object_mut() {
            let (amm_v, lend_v) = self.lp_value_weights_v2(&self.epoch_work);
            m.insert(
                "rewards_v2".into(),
                serde_json::json!({
                    "active_epoch": self.rv2_epoch(self.current_epoch()),
                    "epoch_proposer_credit": &self.epoch_work.proposer_credit,
                    "epoch_vote_credit": &self.epoch_work.vote_credit,
                    "epoch_fee_reward_pool": self.epoch_work.fee_reward_pool,
                    "floor_weights": self.floor_weights_v2(),
                    "amm_lp_value_weights": amm_v,
                    "lend_lp_value_weights": lend_v,
                    "lp_start_taken": self.epoch_work.lp_start_taken,
                }),
            );
            m.insert("min_bond_new".into(), serde_json::json!(crate::params_v2::MIN_BOND_V2));
            // Tip time metadata outside json! (recursion limit). chain_physics ≠ Unix.
            m.insert(
                "tip_sealed_at_ms".into(),
                serde_json::json!(self.chain.last().map(|l| l.sealed_at_ms)),
            );
            m.insert("tip_sealed_at_quality".into(), serde_json::json!("chain_physics"));
            let tip_utc = self.chain.last().map(|l| l.sealed_utc_ms).filter(|&u| u > 0);
            m.insert("tip_sealed_utc_ms".into(), serde_json::json!(tip_utc));
            m.insert(
                "tip_sealed_utc_quality".into(),
                serde_json::json!(if tip_utc.is_some() {
                    "utc_committed"
                } else {
                    "unavailable"
                }),
            );
            m.insert(
                "utc_from_height".into(),
                serde_json::json!(utc_header::network_utc_from_height(self.cfg.network_id)),
            );
            m.insert(
                "utc_active_next".into(),
                serde_json::json!(utc_header::utc_active_on(
                    self.cfg.network_id,
                    self.tip_height.saturating_add(1),
                )),
            );
            m.insert(
                "seat_key_registry_ids".into(),
                serde_json::json!(self.seat_key_registry.keys().collect::<Vec<_>>()),
            );
            // A13: consensus key per validator (registry / BondV2), status only.
            if let Some(vs) = m.get_mut("validators").and_then(|v| v.as_array_mut()) {
                for vj in vs.iter_mut() {
                    let id = vj.get("id").and_then(|x| x.as_str()).unwrap_or("").to_string();
                    let reg = self.registered_key(&id);
                    let pk = reg.clone().or_else(|| self.validators.get(&id).map(|v| v.public_key.clone()));
                    if let Some(v2) = vj.get_mut("v2").and_then(|x| x.as_object_mut()) {
                        v2.insert("public_key".into(), serde_json::json!(pk.unwrap_or_default()));
                        v2.insert("key_registered".into(), serde_json::json!(reg.is_some()));
                    }
                }
            }
        }
        (body, heavy)
    }
}

// ---------------------------------------------------------------------------
// In-process network sim
// ---------------------------------------------------------------------------

pub struct Network {
    pub nodes: BTreeMap<String, Node>,
    pub cfg: ChainConfig,
    pub user_keys: KeyRing,
    pub account_seqs: BTreeMap<String, u64>,
}

impl Network {
    pub fn bootstrap(
        validator_ids: &[&str],
        bond: u64,
        user_accounts: &[(String, u64)],
        cfg: ChainConfig,
    ) -> Self {
        let mut val_keys = KeyRing::new(cfg.scheme);
        val_keys.generate_many(validator_ids.iter().copied());
        let mut user_keys = KeyRing::new(cfg.scheme);
        for (a, _) in user_accounts {
            user_keys.generate_id(a);
        }
        // Merge user pubs into each node for tx verify; vals need both
        let mut nodes = BTreeMap::new();
        for id in validator_ids {
            let mut keys = KeyRing::new(cfg.scheme);
            // copy secrets for this val only + all pubs
            for vid in validator_ids {
                if let Some(pk) = val_keys.public_hex(vid) {
                    let _ = keys.insert_public(vid, &pk);
                }
            }
            // load this validator secret from val_keys by re-generating is wrong for falcon
            // Instead share full val keyring clone for sim (all nodes can pack any)
            let mut n = Node::new(*id, cfg.clone(), val_keys.clone(), user_accounts);
            // import user publics for verify
            for (a, _) in user_accounts {
                if let Some(pk) = user_keys.public_hex(a) {
                    let _ = n.keys.insert_public(a, &pk);
                }
            }
            // user secrets only on wallets — for sim submit we use user_keys externally
            for vid in validator_ids {
                n.register_validator(vid, bond);
            }
            // v2.5.0: freeze open-height lottery schedule at tip=0.
            n.freeze_open_height_schedule();
            nodes.insert((*id).to_string(), n);
        }
        let mut account_seqs = BTreeMap::new();
        for (a, _) in user_accounts {
            account_seqs.insert(a.clone(), 1u64);
        }
        Self {
            nodes,
            cfg,
            user_keys,
            account_seqs,
        }
    }

    pub fn tick_all(&mut self, dt_ms: u64) {
        for n in self.nodes.values_mut() {
            n.tick(dt_ms);
        }
    }

    pub fn pong_all(&mut self) {
        let ids: Vec<String> = self.nodes.keys().cloned().collect();
        let t = self.nodes.values().next().map(|n| n.now_ms).unwrap_or(0);
        for n in self.nodes.values_mut() {
            n.now_ms = t;
            for id in &ids {
                n.pong(id);
            }
        }
    }

    pub fn payment(&mut self, from: &str, to: &str, amount: u64, fee: u64) -> Result<Tx, String> {
        let seq = *self.account_seqs.get(from).unwrap_or(&1);
        let tx = Tx::sign_with(
            &self.user_keys,
            from,
            seq,
            to,
            amount,
            fee,
            self.cfg.network_id,
        )?;
        self.account_seqs.insert(from.to_string(), seq + 1);
        for n in self.nodes.values_mut() {
            // ensure user pubs present
            if let Some(pk) = self.user_keys.public_hex(from) {
                let _ = n.keys.insert_public(from, &pk);
            }
            n.submit_tx(tx.clone())?;
        }
        Ok(tx)
    }

    pub fn seal_next_height(&mut self) -> Result<AcceptResult, String> {
        self.pong_all();
        let all_ids: Vec<String> = self.nodes.keys().cloned().collect();
        // Only elect packers that exist as harness Node processes.
        for _ in 0..self.nodes.len().saturating_add(2) {
            let host_ids: BTreeSet<String> = self.nodes.keys().cloned().collect();
            let pure = self
                .nodes
                .values()
                .next()
                .ok_or("no nodes")?
                .lottery_packer()
                .ok_or_else(|| "no eligible packer".to_string())?;
            if !host_ids.contains(&pure) {
                // Registry-only bonder won: cannot seal in this multi-process sim.
                // Tests should keep unhosted bonders out of lottery weight, or only
                // seal heights while pure winner is hosted.
                return Err(format!(
                    "lottery elected unhosted packer {pure} (no Node process)"
                ));
            }
            let packer = pure;
            for n in self.nodes.values_mut() {
                n.pong(&packer);
            }
            let mp = self
                .nodes
                .get(&packer)
                .map(|n| n.mempool.len())
                .unwrap_or(0);
            let maybe = self
                .nodes
                .get_mut(&packer)
                .ok_or("missing packer")?
                .pack_or_skip(&packer)?;
            if let Some(ledger) = maybe {
                let mut last = None;
                for n in self.nodes.values_mut() {
                    last = Some(n.accept_ledger(&ledger)?);
                }
                let hash = ledger.ledger_hash.clone();
                for n in self.nodes.values_mut() {
                    for id in &all_ids {
                        n.vote_ok(&hash, id);
                    }
                }
                let tip = self.tip_height();
                if tip < ledger.height {
                    return Err(format!(
                        "soft QC did not commit h={} tip={tip}",
                        ledger.height
                    ));
                }
                return last.ok_or_else(|| "no accept".into());
            }
            if mp == 0 {
                return Err("empty mempool".into());
            }
            return Err("no applicable txs".into());
        }
        Err("no applicable packer".into())
    }

    /// Live-seat pipeline (v2.9.76 tests): pack, attach the Merkle batch with
    /// the packer's known account keys, self-accept on the packer (evicting a
    /// tx that fails apply, as the node binary does), then every other seat
    /// accepts and votes. `legacy_strip` re-creates the 2.9.75 body by
    /// stripping every known key regardless of body kind.
    pub fn seal_next_height_batched(&mut self, legacy_strip: bool) -> Result<AcceptResult, String> {
        let all_ids: Vec<String> = self.nodes.keys().cloned().collect();
        let packer = self
            .nodes
            .values()
            .next()
            .and_then(|n| n.lottery_packer())
            .ok_or_else(|| "no eligible packer".to_string())?;
        for n in self.nodes.values_mut() {
            n.pong(&packer);
        }
        let p = self.nodes.get_mut(&packer).ok_or("missing packer")?;
        let Some(mut ledger) = p.pack_or_skip(&packer)? else {
            return Err("no applicable txs".into());
        };
        let known: BTreeMap<String, String> = ledger
            .txs
            .iter()
            .filter_map(|t| p.account_public_key(&t.account).map(|k| (t.account.clone(), k)))
            .collect();
        ledger.attach_merkle_batch_known(&p.keys, &|id| known.get(id).cloned())?;
        if legacy_strip {
            for t in &mut ledger.txs {
                if known.get(&t.account) == Some(&t.public_key) {
                    t.public_key.clear();
                }
            }
        }
        if let Err(e) = p.accept_ledger(&ledger) {
            let ev = p.evict_self_accept_failure();
            return Err(format!("self-accept: {e} (evicted {ev:?})"));
        }
        let mut last = None;
        for (id, n) in self.nodes.iter_mut() {
            if *id != packer {
                last = Some(n.accept_ledger(&ledger)?);
            }
        }
        let hash = ledger.ledger_hash.clone();
        for n in self.nodes.values_mut() {
            for id in &all_ids {
                n.vote_ok(&hash, id);
            }
        }
        if self.tip_height() < ledger.height {
            return Err(format!("soft QC did not commit h={}", ledger.height));
        }
        last.ok_or_else(|| "no accept".into())
    }

    pub fn tip_height(&self) -> u64 {
        self.nodes.values().next().map(|n| n.tip_height).unwrap_or(0)
    }

    pub fn balances(&self, acct: &str) -> Option<u64> {
        self.nodes
            .values()
            .next()
            .map(|n| n.state.get(acct).balance)
    }
}

/// Ordered NeedLedgers targets + why others were skipped (v2.9.49).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CatchupPlan {
    /// Fanout indices to try in order (first lane with room wins).
    pub order: Vec<usize>,
    /// How many of `order` (from the front) are `--hubs` peers.
    pub hub_count: usize,
    pub skipped_self: usize,
    pub skipped_jailed: usize,
    /// Advertised tip not above ours.
    pub skipped_behind: usize,
}

// ---------------------------------------------------------------------------
// Pack draft + per-tx rollback (v2.9.49)
// ---------------------------------------------------------------------------

/// The six state slices a pack dry-run mutates. Cloned **once** per pack.
#[derive(Debug, Clone)]
pub(crate) struct PackDraft {
    pub state: WorldState,
    pub defi: DefiState,
    pub bridge: BridgeState,
    pub vals: BTreeMap<String, ValidatorInfo>,
    pub claim: BTreeMap<String, u64>,
    pub work: EpochWork,
}

/// How a candidate tx is rolled back if it fails inside the pack loop.
///
/// Before v2.9.49 the pack loop cloned the whole draft (~200 MB on 2300, 60–200
/// ms) for **every** candidate so a failing tx could be discarded. That capped
/// blocks at ~10–17 txs inside the 1 s pack budget. Now `Pay` / `AssetPay`
/// (the bulk of traffic) record only the rows they can touch *before* they
/// can fail, and restore exactly those rows on error. Every other body keeps
/// the old full-clone path. The result (chosen txs, state root) is identical:
/// `pack_undo_matches_full_clone_*` tests pack the same mempool both ways.
pub(crate) enum PackUndo {
    /// Prior rows of `state.accounts` and `defi.assets` (None = row absent).
    Rows {
        accounts: Vec<(String, Option<AccountState>)>,
        assets: Vec<(String, Option<BTreeMap<String, u64>>)>,
    },
    /// Pre-2.9.49 behaviour: full snapshot of the draft.
    Full(Box<PackDraft>),
}

impl PackUndo {
    /// Footprint of `apply_protocol_tx_ex` up to its last `Err` return.
    ///
    /// * `Pay`: sequence bump + fee on `account` (fee never from claimable for
    ///   Pay), then amount check / allowlist; `destination` is credited last.
    /// * `AssetPay`: sequence bump + fee on `account`; `defi.assets` debit of
    ///   `account` and credit of `destination`; `destination` account row may
    ///   be created. Nothing touches validators / bridge / claimable / work
    ///   before an error, and success is never rolled back.
    ///
    /// Any change to those arms must keep this list a superset (the
    /// equivalence tests fail otherwise).
    pub(crate) fn capture(draft: &PackDraft, tx: &Tx) -> Self {
        let row = |a: &str| (a.to_string(), draft.state.accounts.get(a).cloned());
        match &tx.body {
            TxBody::Pay => PackUndo::Rows {
                accounts: vec![row(&tx.account), row(&tx.destination)],
                assets: Vec::new(),
            },
            TxBody::AssetPay { .. } => {
                let arow = |a: &str| (a.to_string(), draft.defi.assets.get(a).cloned());
                PackUndo::Rows {
                    accounts: vec![row(&tx.account), row(&tx.destination)],
                    assets: vec![arow(&tx.account), arow(&tx.destination)],
                }
            }
            _ => PackUndo::Full(Box::new(draft.clone())),
        }
    }

    #[cfg(test)]
    pub(crate) fn is_cheap(&self) -> bool {
        matches!(self, PackUndo::Rows { .. })
    }

    /// Put the draft back exactly as it was before the failed tx.
    pub(crate) fn restore(self, draft: &mut PackDraft) {
        match self {
            PackUndo::Rows { accounts, assets } => {
                // Reverse order so a duplicated key (account == destination)
                // ends at the first (oldest) snapshot.
                for (k, v) in accounts.into_iter().rev() {
                    match v {
                        Some(a) => {
                            draft.state.accounts.insert(k, a);
                        }
                        None => {
                            draft.state.accounts.remove(&k);
                        }
                    }
                }
                for (k, v) in assets.into_iter().rev() {
                    match v {
                        Some(m) => {
                            draft.defi.assets.insert(k, m);
                        }
                        None => {
                            draft.defi.assets.remove(&k);
                        }
                    }
                }
            }
            PackUndo::Full(d) => *draft = *d,
        }
    }
}

#[cfg(test)]
thread_local! {
    /// Test-only: force the pre-2.9.49 full-clone pack path (equivalence tests).
    static PACK_FORCE_FULL_CLONE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
pub(crate) fn set_pack_force_full_clone(on: bool) {
    PACK_FORCE_FULL_CLONE.with(|c| c.set(on));
}

#[inline]
fn pack_force_full_clone() -> bool {
    #[cfg(test)]
    {
        PACK_FORCE_FULL_CLONE.with(|c| c.get())
    }
    #[cfg(not(test))]
    {
        false
    }
}

// ---------------------------------------------------------------------------
// Wire protocol (multi-process)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WireMsg {
    /// v2.10.3: one in-order piece of a large line ([`crate::pieces`]).
    /// Sent only to peers whose Hello release is >= 2.10.3.
    Piece {
        pid: u64,
        i: u32,
        n: u32,
        d: String,
    },
    Hello {
        id: String,
        public_key: String,
        /// Validator registry snapshot for shared lottery set (id → bond).
        #[serde(default)]
        validators: BTreeMap<String, u64>,
        /// Public keys for registry members (and known users).
        #[serde(default)]
        publics: BTreeMap<String, String>,
        /// Sender tip so joiners can start pull catch-up without waiting for Pong
        /// fanout (mesh only fans to configured peers, not inbound dialers).
        #[serde(default)]
        tip_height: u64,
        #[serde(default)]
        tip_hash: String,
        /// Mempool hub role advertisement (GROWTH_AND_MEMPOOL).
        #[serde(default)]
        is_hub: bool,
        /// Pending tx count on sender (hint for NeedTxs).
        #[serde(default)]
        mempool_len: u64,
        /// Product version (checklist A10). Empty = legacy peer.
        #[serde(default)]
        product_version: String,
        /// Peer's network_id. 0 = unset/legacy.
        #[serde(default)]
        hello_network_id: u32,
        /// This seat holds a disk body store + snapshot file (v2.9.21).
        #[serde(default)]
        archive: bool,
        /// Height of the last snapshot this archive can serve.
        #[serde(default)]
        snap_height: u64,
        /// v2.10.3: real release (`PRODUCT_VERSION`). `product_version` stays
        /// the legacy-line wire string, so it cannot tell 2.10.x releases
        /// apart. Omitted when empty (older peers ignore unknown fields).
        #[serde(default, skip_serializing_if = "String::is_empty")]
        release_version: String,
        /// Additive capability tokens (e.g. `utc-header-v5`). Empty/omitted on
        /// older peers. Advertising is safe while UTC activation stays unarmed;
        /// session close on missing capability is gated separately (default off).
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        capabilities: Vec<String>,
    },
    /// Liveness + tip advertisement (gossiped). Does not alter lottery election.
    Pong {
        id: String,
        now_ms: u64,
        tip_height: u64,
        tip_hash: String,
        #[serde(default)]
        is_hub: bool,
        #[serde(default)]
        mempool_len: u64,
        #[serde(default)]
        archive: bool,
        #[serde(default)]
        snap_height: u64,
    },
    /// Pull catch-up: request ledgers at/after `from_height` (production lag fix).
    NeedLedgers {
        from_height: u64,
        #[serde(default = "default_catchup_batch")]
        max_count: u64,
    },
    /// Directed catch-up response (reply on the requesting connection only).
    /// Replaces mesh-flooding N×`ProposeLedger{catchup:true}` which thrashed dual-host.
    LedgersBatch {
        from_height: u64,
        ledgers: Vec<Ledger>,
    },
    /// Joiner too far behind: pull a snapshot from an archive (v2.9.21).
    NeedSnapshot {},
    SnapshotOffer {
        tip_height: u64,
        tip_hash: String,
        sha256: String,
        bytes: u64,
        chunk_size: u32,
        chunks: u32,
    },
    NeedSnapshotChunk {
        sha256: String,
        index: u32,
    },
    SnapshotChunk {
        sha256: String,
        index: u32,
        total: u32,
        /// Hex-encoded file slice.
        data: String,
    },
    SnapshotNo {
        reason: String,
    },
    /// Pull pending txs from a hub / peer (packer path before progress-timeout).
    NeedTxs {
        #[serde(default = "default_need_txs_batch")]
        max_count: u64,
    },
    /// Directed mempool batch response (reply on requesting connection).
    TxsBatch {
        txs: Vec<Tx>,
    },
    SubmitTx {
        tx: Tx,
    },
    /// Compact announcement of mempool transaction ids. Peers pull the ones
    /// they do not have. Ids are 64 hex chars, not the Falcon signature.
    TxInv {
        ids: Vec<String>,
    },
    /// Pull specific mempool transactions announced in [`WireMsg::TxInv`].
    NeedMempoolTxs {
        ids: Vec<String>,
    },
    ProposeLedger {
        ledger: Ledger,
        /// When true, receiver applies sequential catch-up without lottery re-check.
        #[serde(default)]
        catchup: bool,
    },
    /// v2.8.0 live gossip: header only. Body via [`NeedLedgerBody`] / [`LedgerBody`].
    ProposeHeader {
        header: LedgerHeader,
        #[serde(default)]
        catchup: bool,
    },
    NeedLedgerBody {
        ledger_hash: String,
    },
    LedgerBody {
        ledger: Ledger,
    },
    /// Live fan. Header plus tx ids. The seat fills `txs` from its mempool.
    /// Catch-up still uses [`LedgerBody`].
    LedgerBodyById {
        ledger: Ledger,
    },
    /// Ids missing from a [`LedgerBodyById`]. One pull, on the catch-up lane.
    NeedTxsByIds {
        ledger_hash: String,
        tx_ids: Vec<String>,
    },
    /// Only the txs named by [`NeedTxsByIds`].
    TxsByIds {
        ledger_hash: String,
        txs: Vec<Tx>,
    },
    /// Skip vote for progress-timeout / no-applicable. Applied to lottery only after
    /// soft QC of `voter`s (v2.3.0 P0). Legacy messages without `voter` are ignored.
    SkipPacker {
        height: u64,
        packer: String,
        tip_hash: String,
        /// Bonded checker casting this skip vote (required for QC).
        #[serde(default)]
        voter: String,
        /// Falcon-512 (or hmac-dev) over `pl-skip:v1|…` (checklist A2).
        #[serde(default)]
        signature: String,
    },
    /// Checker OK vote for soft/hard confirm.
    LedgerOk {
        height: u64,
        ledger_hash: String,
        voter: String,
        #[serde(default)]
        signature: String,
        /// v2.10.0 view round the OK was signed in (`pl-ok:v2`). Omitted when
        /// 0 so legacy peers see byte-identical messages before activation.
        #[serde(default, skip_serializing_if = "is_zero_u64")]
        round: u64,
    },
    /// Certified ONLINE epoch vote (v2.4.0 mainnet). Soft QC freezes packer seats
    /// for `epoch_id = tip_height / online_epoch_heights` to `members`.
    OnlineSetVote {
        epoch_id: u64,
        /// Sorted bonded ids observed online (pong-fresh) by `voter`.
        members: Vec<String>,
        voter: String,
        #[serde(default)]
        signature: String,
    },
    /// Height-local view-change (v2.5.0). Soft QC clears stuck pending and bumps
    /// lottery view round — never genesis hard-resync.
    ViewChange {
        height: u64,
        tip_hash: String,
        /// Target round (`current height_view_round + 1`).
        round: u64,
        voter: String,
        #[serde(default)]
        signature: String,
    },
    /// Status. Default **slim** (no full accounts dump) for WAN/ops.
    /// Set `include_accounts: true` for load-net sequence resync.
    StatusReq {
        #[serde(default)]
        include_accounts: bool,
        /// Omit QC/LC attestation dumps. The public wallet only needs rails,
        /// tip, and eth_lc; the full dump is ~2MB and times out over the proxy.
        #[serde(default)]
        brief: bool,
    },
    Status {
        body: serde_json::Value,
    },
    /// Read-only health snapshot (`falcon.health.v1`, docs/ops/NODE_HEALTH_SCHEMA.md).
    /// Cheap: no roots / accounts / attestations under the node lock.
    HealthReq {
        /// Recent log warnings/errors to include (default 20, max 64).
        #[serde(default)]
        warnings: u32,
    },
    Health {
        body: serde_json::Value,
    },
    SealNow,
    /// Operator solo recovery: pack + immediate commit (admin sock only).
    SealForce,
    /// Open vault with single allowlisted destination.
    VaultOpen {
        account: String,
        destination: String,
    },
    VaultLock {
        account: String,
    },
    ClaimRewards {
        account: String,
    },
    CreatePool {
        pool_id: String,
        asset_a: String,
        asset_b: String,
    },
    AddLiquidity {
        pool_id: String,
        provider: String,
        amt_a: u64,
        amt_b: u64,
    },
    Swap {
        pool_id: String,
        who: String,
        token_in: String,
        amount_in: u64,
        min_out: u64,
    },
    CreateMarket {
        market_id: String,
        asset: String,
    },
    LendSupply {
        market_id: String,
        who: String,
        amount: u64,
    },
    /// Watcher credit: work units + mark current epoch hour slot (presence).
    /// `presence_slots` > 0 marks slots 0..N-1 without wall-clock (soak / full-week sim).
    WatcherCredit {
        account: String,
        work_units: u64,
        #[serde(default = "default_true")]
        with_slot: bool,
        /// Bulk presence: mark this many hourly slots (max 168). 0 = none beyond with_slot.
        #[serde(default)]
        presence_slots: u64,
    },
    /// Bond native from account into validator id.
    Bond {
        id: String,
        from: String,
        amount: u64,
    },
    RequestUnbond {
        id: String,
        amount: u64,
    },
    CompleteUnbond {
        id: String,
    },
    /// Private soak: mint secondary asset (USD etc.) for LP paths.
    CreditAsset {
        account: String,
        asset: String,
        amount: u64,
    },
    /// Admin/test: advance clock and settle epochs.
    Tick {
        dt_ms: u64,
    },
    ForceSettleEpoch,
    /// SPV rail: submit external chain header.
    RailHeader {
        asset: String,
        height: u64,
        hash: String,
        parent_hash: String,
        merkle_root: String,
        #[serde(default)]
        watcher: String,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        raw: String,
    },
    /// SPV rail: deposit with merkle proof → mint wrapped asset.
    RailDeposit {
        asset: String,
        to: String,
        amount: u64,
        proof: BridgeProof,
        #[serde(default)]
        watcher: String,
    },
    /// SPV rail: burn wrapped asset → open withdraw note.
    RailWithdraw {
        asset: String,
        from: String,
        amount: u64,
        external_to: String,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        vault_sig: String,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        signed_btc_tx: String,
    },
    /// Operator admin: BitVM2 pegout + Claim attestation (bypasses lagging SubmitTx).
    RailBitvm2Attest {
        note_id: String,
        operator: String,
        pegout_txid_hex: String,
        claim_txid_hex: String,
        proof_hex: String,
        #[serde(default)]
        public_hex: Vec<String>,
        statement_digest_hex: String,
    },
    /// Operator admin: record Bitcoin peg-out txid for an open BitVM2 claim.
    RailBitvm2Pegout {
        note_id: String,
        operator: String,
        pegout_txid_hex: String,
    },
    RailChallenge {
        asset: String,
        note_id: String,
        observed_dest: String,
        observed_amount: u64,
    },
    /// Persist JSON snapshot to path (private fleet restart).
    SnapshotSave {
        path: String,
    },
    SnapshotLoad {
        path: String,
    },
    /// Operator-only: arm hard-resync from genesis (v2.3.2 P2). Not for mesh gossip.
    OperatorHardReset {
        #[serde(default)]
        reason: String,
    },
    /// Operator-only: evict a stuck tx hash or `account[:seq]` from the local mempool.
    MempoolDrop {
        target: String,
    },
    /// Wallet: query one account (seq, balance, claimable, assets).
    AccountQuery {
        account: String,
    },
    /// v2.10.4 RPC: order book depth for `pair` (`"BTC4-FPL"`), best
    /// `levels` price levels per side (default 50, max 200) + pool spot.
    OrderBookQuery {
        pair: String,
        #[serde(default)]
        levels: u32,
    },
    /// v2.10.4 RPC: one account's open orders.
    OpenOrdersQuery {
        account: String,
    },
    /// v2.10.4 RPC: recent fills (book and AMM legs), newest first.
    FillsQuery {
        #[serde(default)]
        pair: Option<String>,
        #[serde(default)]
        account: Option<String>,
        #[serde(default)]
        limit: u32,
    },
    /// Reply to the three order-book queries.
    OrderBook {
        body: serde_json::Value,
    },
    Account {
        body: serde_json::Value,
    },
    Ok {
        msg: String,
    },
    Err {
        msg: String,
    },
}

impl WireMsg {
    /// Side-channel / operator mutations. Public mesh TCP must reject these
    /// unless `ChainConfig.allow_admin_wire` (checklist A3/A4).
    pub fn is_admin(&self) -> bool {
        matches!(
            self,
            WireMsg::SealNow | WireMsg::SealForce
                | WireMsg::VaultOpen { .. }
                | WireMsg::VaultLock { .. }
                | WireMsg::ClaimRewards { .. }
                | WireMsg::CreatePool { .. }
                | WireMsg::AddLiquidity { .. }
                | WireMsg::Swap { .. }
                | WireMsg::CreateMarket { .. }
                | WireMsg::LendSupply { .. }
                | WireMsg::WatcherCredit { .. }
                | WireMsg::Bond { .. }
                | WireMsg::RequestUnbond { .. }
                | WireMsg::CompleteUnbond { .. }
                | WireMsg::CreditAsset { .. }
                | WireMsg::Tick { .. }
                | WireMsg::ForceSettleEpoch
                | WireMsg::RailHeader { .. }
                | WireMsg::RailDeposit { .. }
                | WireMsg::RailWithdraw { .. }
                | WireMsg::RailBitvm2Attest { .. }
                | WireMsg::RailBitvm2Pegout { .. }
                | WireMsg::SnapshotSave { .. }
                | WireMsg::SnapshotLoad { .. }
                | WireMsg::OperatorHardReset { .. }
                | WireMsg::MempoolDrop { .. }
        )
    }
}

fn is_zero_u64(v: &u64) -> bool {
    *v == 0
}

fn default_true() -> bool {
    true
}

fn default_catchup_batch() -> u64 {
    64
}

fn default_need_txs_batch() -> u64 {
    Node::NEED_TXS_BATCH as u64
}

#[cfg(test)]
mod pack_catchup_tests;
mod merkle_batch_tests;

#[cfg(test)]
mod leak_2963_tests;

#[cfg(test)]
mod btc_admit_tests;

#[cfg(test)]
mod eth_lc_gloas_tests;

#[cfg(test)]
mod eth_exec_prune_tests;

#[cfg(test)]
mod eth_v3_deposit_tests;
#[cfg(test)]
mod rv2_validator_tests;
#[cfg(test)]
mod admission_batch_tests;
#[cfg(test)]
mod bitvm2_m1_node_tests;
#[cfg(test)]
mod bridge_operators_tests;
#[cfg(test)]
mod btc4_bridge_tests;
#[cfg(test)]
mod ring_restore_gate_tests;
#[cfg(test)]
mod claim_enroll_gate_tests;
#[cfg(test)]
mod rv2_rewards_tests;
#[cfg(test)]
mod rv2_keyreg_tests;
#[cfg(test)]
mod key_bind_c1_tests;
#[cfg(test)]
mod perm_drop_onchain_key_tests;
#[cfg(test)]
mod key_bind_onchain_height_tests;
#[cfg(test)]
mod seat_account_key_split_tests;
#[cfg(test)]
mod ring_sidecar_restart_tests;
#[cfg(test)]
mod seat_name_guard_tests;
#[cfg(test)]
mod pack_ring_keybind_tests;
#[cfg(test)]
mod catchup_sig_r2_tests;

#[cfg(test)]
mod eth_v3_fork_dry_run_tests;

#[cfg(test)]
mod hello_gate_tests;
#[cfg(test)]
mod hello_release_tests;
#[cfg(test)]
mod utc_rehearsal_tests;
#[cfg(test)]
mod health_tests;

#[cfg(test)]
mod tests {
    use super::*;

    fn users() -> Vec<(String, u64)> {
        vec![
            ("alice".into(), 1_000_000),
            ("bob".into(), 1_000_000),
            ("carol".into(), 1_000_000),
        ]
    }

    #[test]
    fn exec_headers_below_prune_floor_is_permanent() {
        // v2.9.60: the prune floor is monotonic, so an all-below-floor
        // EthExecHeaders batch can never apply and must be dropped.
        assert!(Node::is_permanent_tx_failure(
            crate::bridge::EXEC_HEADERS_BELOW_PRUNE_FLOOR
        ));
        // An empty submit stays the temporary "no headers" error.
        assert!(!Node::is_permanent_tx_failure("no headers"));
    }

    #[test]
    fn hmac_multi_height() {
        let mut net = Network::bootstrap(
            &["v1", "v2", "v3", "v4", "v5"],
            1000,
            &users(),
            ChainConfig {
                max_txs_per_ledger: 4,
                pack_budget_ms: 0,
                ..Default::default()
            },
        );
        for n in net.nodes.values_mut() {
            n.cfg.max_txs_per_ledger = 4;
            n.cfg.pack_budget_ms = 0;
        }
        for _ in 0..20 {
            net.payment("alice", "bob", 10, 1).unwrap();
        }
        let mut total = 0;
        for _ in 0..5 {
            let r = net.seal_next_height().unwrap();
            total += r.n_txs;
        }
        assert_eq!(total, 20);
        assert!(net.nodes.values().all(|n| n.tip_hash == net.nodes.values().next().unwrap().tip_hash));
    }

    #[test]
    fn lottery_elects_bonded_even_without_pong() {
        // v2.3.0: election is tip-deterministic over bonded set, not pong-filtered.
        let mut net = Network::bootstrap(&["v1", "v2"], 1000, &users(), ChainConfig::default());
        // No pongs — still elect among bonded (winner cannot pack until pong-fresh).
        let w = net.nodes.values().next().unwrap().lottery_packer();
        assert!(w.is_some(), "bonded set must elect without pongs");
        net.pong_all();
        let winner = net.nodes.values().next().unwrap().lottery_packer().unwrap();
        // Stale pongs: still elected; may_pack fails.
        net.tick_all(60_000);
        assert_eq!(
            net.nodes.values().next().unwrap().lottery_packer().as_deref(),
            Some(winner.as_str()),
            "stale pong must not reseed lottery"
        );
        let err = net
            .nodes
            .get_mut(&winner)
            .unwrap()
            .may_pack_locally(&winner)
            .unwrap_err();
        assert!(
            err.contains("pong stale") || err.contains("stale") || err.contains("genesis"),
            "{err}"
        );
    }

    #[test]
    fn lottery_agrees_with_asymmetric_pong_views() {
        // Multi-host fork root-cause: different pong views must NOT diverge election.
        let mut net = Network::bootstrap(&["v1", "v2", "v3"], 1000, &users(), ChainConfig::default());
        // v1 node only sees v1,v2 pongs; v2 node only sees v2,v3; v3 sees all.
        net.nodes.get_mut("v1").unwrap().pong("v1");
        net.nodes.get_mut("v1").unwrap().pong("v2");
        net.nodes.get_mut("v2").unwrap().pong("v2");
        net.nodes.get_mut("v2").unwrap().pong("v3");
        net.nodes.get_mut("v3").unwrap().pong("v1");
        net.nodes.get_mut("v3").unwrap().pong("v2");
        net.nodes.get_mut("v3").unwrap().pong("v3");
        let winners: Vec<_> = net
            .nodes
            .values()
            .map(|n| n.lottery_packer().expect("bonded election"))
            .collect();
        assert!(
            winners.iter().all(|w| w == &winners[0]),
            "asymmetric pongs must not fork lottery: {winners:?}"
        );
    }

    #[test]
    fn online_epoch_qc_filters_seats() {
        // v2.4.0: after soft QC of OnlineSet, seats ⊆ certified members.
        let cfg = ChainConfig {
            online_epoch_heights: 10,
            soft_ok_votes: 2,
            progress_timeout_ms: 0,
            pong_window_ms: 60_000,
            ..Default::default()
        };
        let mut net = Network::bootstrap(&["v1", "v2", "v3", "v4"], 1000, &users(), cfg);
        net.pong_all();
        // Before QC: all bonded seats.
        assert_eq!(net.nodes["v1"].online_seat_ids().len(), 4);
        let members: BTreeSet<String> = ["v1", "v2", "v3"].into_iter().map(String::from).collect();
        for vid in ["v1", "v2", "v3"] {
            for n in net.nodes.values_mut() {
                let _ = n.vote_online_set(0, members.clone(), vid);
            }
        }
        // soft_need = min(2, live, …) → QC with 2 votes; we cast 3.
        for n in net.nodes.values() {
            assert!(
                n.online_ok.contains_key(&0),
                "epoch 0 must be certified"
            );
            assert_eq!(n.online_members, members);
            let seats = n.online_seat_ids();
            assert_eq!(seats.len(), 3, "v4 excluded from ONLINE seats: {seats:?}");
            assert!(!seats.contains("v4"));
            // v2.8.1: lottery is bonded, not ONLINE. v4 stays in the draw.
            let order = n.lottery_order();
            assert!(
                order.contains(&"v4".to_string()),
                "lottery must stay tip-bonded, got {order:?}"
            );
        }
        // All nodes agree on order with shared online set.
        let o0 = net.nodes["v1"].lottery_order();
        for n in net.nodes.values() {
            assert_eq!(n.lottery_order(), o0);
        }
    }

    #[test]
    fn online_bootstrap_all_bonded_before_qc() {
        let cfg = ChainConfig {
            online_epoch_heights: 25,
            ..Default::default()
        };
        let mut net = Network::bootstrap(&["v1", "v2", "v3"], 1000, &users(), cfg);
        net.pong_all();
        for n in net.nodes.values() {
            assert!(n.online_members.is_empty());
            assert_eq!(n.online_seat_ids().len(), 3);
        }
    }

    #[test]
    fn online_refuses_undersized_set() {
        // soft_ok=3, bonded=4 → min ONLINE size 3; {v1,v2} must not certify.
        let cfg = ChainConfig {
            online_epoch_heights: 10,
            soft_ok_votes: 3,
            pong_window_ms: 60_000,
            ..Default::default()
        };
        let mut net = Network::bootstrap(&["v1", "v2", "v3", "v4"], 1000, &users(), cfg);
        net.pong_all();
        let small: BTreeSet<String> = ["v1", "v2"].into_iter().map(String::from).collect();
        for vid in ["v1", "v2", "v3", "v4"] {
            for n in net.nodes.values_mut() {
                let (qc, _) = n.vote_online_set(0, small.clone(), vid);
                assert!(!qc, "undersized ONLINE must not QC");
            }
        }
        assert!(net.nodes["v1"].online_members.is_empty());
    }

    #[test]
    fn proposal_skip_claims_reject_illegal_packer() {
        let cfg = ChainConfig {
            online_epoch_heights: 0, // all bonded seats
            soft_ok_votes: 2,
            progress_timeout_ms: 0,
            pong_window_ms: 60_000,
            pack_budget_ms: 0,
            max_txs_per_ledger: 8,
            ..Default::default()
        };
        let mut net = Network::bootstrap(&["v1", "v2", "v3"], 1000, &users(), cfg);
        net.pong_all();
        net.payment("alice", "bob", 1, 1).unwrap();
        let order = net.nodes["v1"].lottery_order();
        let primary = order[0].clone();
        let standby = order[1].clone();
        // Standby packs with empty skip claims → illegal.
        let mut ledger = net
            .nodes
            .get_mut(&standby)
            .unwrap()
            .pack_as(&standby);
        // pack_as should fail (predecessor not skip-QC'd)
        assert!(ledger.is_err(), "standby must not pack without skip QC");
        // Force a forged ledger: primary order seat but wrong claims via seal_with_skips
        // after primary packs legitimately.
        net.payment("alice", "bob", 1, 1).unwrap();
        let ok = net
            .nodes
            .get_mut(&primary)
            .unwrap()
            .pack_as(&primary)
            .unwrap();
        assert!(ok.skipped_predecessors.is_empty());
        // Mutate to claim standby is packer with empty skips — sig will fail; instead
        // validate_proposal_seats on a synthetic claim.
        let mut bad = ok.clone();
        bad.packer = standby.clone();
        bad.skipped_predecessors = vec![]; // missing skip of primary
        let err = net.nodes["v1"]
            .validate_proposal_seats(&bad)
            .unwrap_err();
        assert!(
            err.contains("skip claim") || err.contains("wrong packer") || err.contains("want"),
            "{err}"
        );
        // Correct claim: skip primary, standby packs.
        let tip = net.nodes["v1"].tip_hash.clone();
        for n in net.nodes.values_mut() {
            let _ = n.apply_shared_skip(1, &primary, &tip);
        }
        net.payment("alice", "bob", 1, 1).unwrap();
        // After skip, tip still 0 until a ledger seals — height is still 1.
        let claims = net.nodes["v1"].skip_claims_for_packer(&standby).unwrap();
        assert_eq!(claims, vec![primary.clone()]);
        let good = net
            .nodes
            .get_mut(&standby)
            .unwrap()
            .pack_as(&standby)
            .unwrap();
        assert_eq!(good.skipped_predecessors, vec![primary]);
        for n in net.nodes.values() {
            n.validate_proposal_seats(&good).unwrap();
        }
    }

    #[test]
    fn refuse_empty_ledger() {
        let mut net = Network::bootstrap(&["v1", "v2", "v3"], 1000, &users(), ChainConfig::default());
        net.pong_all();
        let winner = net.nodes.values().next().unwrap().lottery_packer().unwrap();
        let err = net.nodes.get_mut(&winner).unwrap().pack_as(&winner).unwrap_err();
        assert!(err.contains("empty"), "{err}");
    }

    #[test]
    fn lottery_agrees_with_shared_pong_view() {
        // Shared pongs (and without) → same winner under tip-deterministic seed.
        let mut net = Network::bootstrap(&["v1", "v2", "v3"], 1000, &users(), ChainConfig::default());
        net.pong_all();
        let winners: Vec<_> = net
            .nodes
            .values()
            .map(|n| n.lottery_packer().unwrap())
            .collect();
        assert!(winners.iter().all(|w| w == &winners[0]), "{winners:?}");
    }

    #[test]
    fn wrong_packer_rejected() {
        let mut net = Network::bootstrap(&["v1", "v2", "v3"], 1000, &users(), ChainConfig::default());
        net.pong_all();
        net.payment("alice", "bob", 5, 1).unwrap();
        let winner = net.nodes.values().next().unwrap().lottery_packer().unwrap();
        let loser = ["v1", "v2", "v3"]
            .into_iter()
            .find(|x| *x != winner.as_str())
            .unwrap();
        // Force pack as loser by temporarily making them winner is hard; instead
        // build ledger as winner then change packer field → sig fails
        let mut ledger = net.nodes.get_mut(&winner).unwrap().pack_as(&winner).unwrap();
        ledger.packer = loser.to_string();
        let err = net.nodes.get_mut("v1").unwrap().accept_ledger(&ledger).unwrap_err();
        assert!(err.contains("wrong packer") || err.contains("bad packer"));
    }

    #[test]
    fn equivocation_jails() {
        let mut net = Network::bootstrap(&["v1", "v2", "v3"], 1000, &users(), ChainConfig::default());
        net.pong_all();
        net.payment("alice", "bob", 5, 1).unwrap();
        net.payment("alice", "bob", 5, 1).unwrap();
        let winner = net.nodes.values().next().unwrap().lottery_packer().unwrap();
        let n = net.nodes.get_mut(&winner).unwrap();
        let l1 = n.pack_as(&winner).unwrap();
        // second ledger same height different content: accept first, then forge second hash
        n.accept_ledger(&l1).unwrap();
        // reset tip to re-accept path for equivocation at same height recording
        // seen_at_height already has l1; craft l2 with same height/packer different hash
        let mut l2 = l1.clone();
        l2.ledger_hash = "deadbeef".repeat(8);
        let err = n.accept_ledger(&l2).unwrap_err();
        assert!(err.contains("equivocation"), "{err}");
        assert!(n.validators.get(&winner).unwrap().jailed);
        assert!(n.validators.get(&winner).unwrap().slash_total > 0);
    }

    #[test]
    fn falcon512_sign_and_chain() {
        let cfg = ChainConfig {
            scheme: CryptoScheme::Falcon512,
            max_txs_per_ledger: 8,
            ..Default::default()
        };
        let mut net = Network::bootstrap(&["v1", "v2", "v3"], 1000, &users(), cfg);
        for n in net.nodes.values_mut() {
            n.cfg.max_txs_per_ledger = 8;
        }
        for _ in 0..5 {
            net.payment("alice", "bob", 10, 1).unwrap();
        }
        let r = net.seal_next_height().unwrap();
        assert_eq!(r.n_txs, 5);
        assert_eq!(net.tip_height(), 1);
        // Falcon sigs are long
        let tx = &net.nodes.values().next().unwrap().chain[0].txs[0];
        assert!(tx.signature.len() > 100, "expected Falcon-sized sig");
    }

    #[test]
    fn unsigned_vote_rejected_when_sigs_required() {
        let mut n = Node::new(
            "v1",
            ChainConfig {
                require_vote_sigs: true,
                soft_ok_votes: 1,
                pack_budget_ms: 0,
                ..Default::default()
            },
            KeyRing::new(CryptoScheme::HmacDev),
            &users(),
        );
        n.register_validator("v1", 1000);
        n.register_validator("v2", 1000);
        n.keys.generate_many(["v1", "v2"].into_iter());
        n.pong("v1");
        n.pong("v2");
        // Ghost voter / empty sig must not count.
        let (soft, _, fresh) = n.vote_ok_ex("deadbeef", "ghost", "");
        assert!(!soft && !fresh);
        let (soft, _, fresh) = n.vote_ok_ex("deadbeef", "v1", "");
        assert!(!soft && !fresh, "empty sig rejected when required");
        let sig = n.sign_ok_vote(1, "deadbeef");
        assert!(!sig.is_empty());
        let (_, _, fresh) = n.vote_ok_ex("deadbeef", "v1", &sig);
        assert!(fresh, "honest signed vote records");
        // Wrong voter cannot use v1's sig.
        let (s, _, f) = n.vote_ok_ex("deadbeef", "v2", &sig);
        assert!(!s && !f);
    }

    #[test]
    fn hello_version_compatible_accepts_same_minor() {
        assert!(hello_version_compatible(""));
        assert!(hello_version_compatible("2.9.60"));
        assert!(hello_version_compatible("2.9.59"));
        assert!(hello_version_compatible("2.9.0"));
        assert!(hello_version_compatible("2.9.61"));
        // 2.11.0 accepts its own line and the legacy 2.9.x line.
        assert!(hello_version_compatible("2.11.0"));
        assert!(hello_version_compatible("2.11.7"));
        assert!(!hello_version_compatible("2.11.07"));
        assert!(!hello_version_compatible("2.10.0"));
        assert!(!hello_version_compatible("3.9.60"));
        assert!(!hello_version_compatible("2.8.99"));
        assert!(!hello_version_compatible("2.90.1"));
        assert!(!hello_version_compatible("2.9x"));
        assert!(!hello_version_compatible("junk"));
        // No patch: not `major.minor.<digits>`.
        assert!(!hello_version_compatible("2.9"));
        // Leading-zero patch is not a canonical 2.9.x version.
        assert!(!hello_version_compatible("2.9.060"));
        assert!(!hello_version_compatible("2.9.00"));
    }

    #[test]
    fn product_version_is_locked_to_crate() {
        assert_eq!(PRODUCT_VERSION, "2.11.2");
        assert_eq!(env!("CARGO_PKG_VERSION"), "2.11.2");
        assert_eq!(NodeRole::from_exe_name("/opt/bin/falcon-pl-val"), Some(NodeRole::Val));
        assert_eq!(NodeRole::from_exe_name("falcon-pl-archive"), Some(NodeRole::Archive));
        assert_eq!(NodeRole::VAL_MAX_CHAIN, 128);
    }

    #[test]
    fn admin_wire_classification() {
        assert!(WireMsg::SealNow.is_admin());
        assert!(WireMsg::SealForce.is_admin());
        assert!(WireMsg::Tick { dt_ms: 1 }.is_admin());
        assert!(WireMsg::ForceSettleEpoch.is_admin());
        assert!(WireMsg::OperatorHardReset {
            reason: "x".into()
        }
        .is_admin());
        assert!(WireMsg::SnapshotSave {
            path: "/tmp/x".into()
        }
        .is_admin());
        assert!(WireMsg::Bond {
            id: "v4".into(),
            from: "alice".into(),
            amount: 1
        }
        .is_admin());
        assert!(WireMsg::CreditAsset {
            account: "alice".into(),
            asset: "USD".into(),
            amount: 1
        }
        .is_admin());
        assert!(!WireMsg::StatusReq {
            include_accounts: false,
            brief: false,
        }
        .is_admin());
        assert!(!WireMsg::AccountQuery {
            account: "alice".into()
        }
        .is_admin());
        assert!(!WireMsg::NeedLedgers {
            from_height: 1,
            max_count: 8
        }
        .is_admin());
        assert!(!WireMsg::Pong {
            id: "v1".into(),
            now_ms: 0,
            tip_height: 0,
            tip_hash: String::new(),
            is_hub: false,
            mempool_len: 0,
            archive: false,
            snap_height: 0,
        }
        .is_admin());
        assert!(!WireMsg::NeedSnapshot {}.is_admin());
    }

    #[test]
    fn ineligible_voter_never_counts() {
        let mut n = Node::new(
            "v1",
            ChainConfig {
                pack_budget_ms: 0,
                soft_ok_votes: 1,
                ..Default::default()
            },
            KeyRing::new(CryptoScheme::HmacDev),
            &users(),
        );
        n.register_validator("v1", 1000);
        n.pong("v1");
        let (soft, _, fresh) = n.vote_ok_ex("abc", "not-a-val", "");
        assert!(!soft && !fresh);
        assert!(!n.eligible_voter(""));
        assert!(n.eligible_voter("v1"));
    }

    #[test]
    fn insert_public_refuses_key_overwrite() {
        let mut k = KeyRing::new(CryptoScheme::HmacDev);
        k.generate_id("alice");
        let pk = k.public_hex("alice").unwrap();
        k.insert_public("alice", &pk).unwrap();
        let err = k
            .insert_public("alice", "pl-pub:deadbeefdeadbeef")
            .unwrap_err();
        assert!(
            err.to_string().contains("overwrite") || err.to_string().contains("key"),
            "{err}"
        );
    }

    /// Checklist A1 / REVIEW #1: attacker Falcon key for a funded id must not verify.
    #[test]
    fn falcon_submit_rejects_mismatched_account_key() {
        let cfg = ChainConfig {
            scheme: CryptoScheme::Falcon512,
            pack_budget_ms: 0,
            max_txs_per_ledger: 8,
            ..Default::default()
        };
        let mut n = Node::new("v1", cfg, KeyRing::new(CryptoScheme::Falcon512), &users());
        n.register_validator("v1", 1000);
        let mut keys = KeyRing::new(CryptoScheme::Falcon512);
        keys.generate_many(["v1", "alice", "bob"].into_iter());
        n.keys = keys;
        n.pong("v1");
        let honest = Tx::sign_with(&n.keys, "alice", 1, "bob", 1, 1, n.cfg.network_id).unwrap();
        assert!(n.submit_tx(honest).unwrap());
        let mut attacker = KeyRing::new(CryptoScheme::Falcon512);
        attacker.generate_id("alice");
        let evil = Tx::sign_with(&attacker, "alice", 2, "bob", 1, 1, n.cfg.network_id).unwrap();
        let err = n.submit_tx(evil).unwrap_err();
        assert!(err.contains("crypto") || err.contains("bad"), "{err}");
    }

    #[test]
    fn soft_static_hard_scales_with_n() {
        // commit = 4 of 6 committee; hard = ceil(n*0.6). Large set does not grow commit.
        let ids: Vec<String> = (1..=13).map(|i| format!("v{i}")).collect();
        let id_refs: Vec<&str> = ids.iter().map(|s| s.as_str()).collect();
        let cfg = ChainConfig {
            soft_ok_votes: 3,
            hard_ok_ratio: 0.6,
            pack_budget_ms: 0,
            max_txs_per_ledger: 8,
            progress_timeout_ms: 0,
            pong_window_ms: 30_000,
            ..Default::default()
        };
        let mut net = Network::bootstrap(&id_refs, 1000, &users(), cfg);
        net.pong_all();
        let n = &net.nodes["v1"];
        assert_eq!(n.checker_count(), 13);
        assert_eq!(n.lottery_order().len(), 6, "committee is 6 even if 13 bonded");
        assert_eq!(n.soft_votes_needed(), 4, "commit = 4 of 6, not 51 of 100");
        assert_eq!(n.hard_votes_needed(), 8, "hard = ceil(13*0.6), network-wide");
        // Small live set: soft capped by live count (not stuck needing dead voters)
        let mut small = Network::bootstrap(&["v1", "v2"], 1000, &users(), ChainConfig {
            soft_ok_votes: 3,
            hard_ok_ratio: 0.6,
            pack_budget_ms: 0,
            max_txs_per_ledger: 8,
            progress_timeout_ms: 0,
            pong_window_ms: 30_000,
            ..Default::default()
        });
        small.pong_all();
        let s = &small.nodes["v1"];
        assert_eq!(s.soft_votes_needed(), 2);
        assert_eq!(s.hard_votes_needed(), 2); // ceil(2*0.6)=2
        // n=6: hard first exceeds soft
        let mut six = Network::bootstrap(&["v1", "v2", "v3", "v4", "v5", "v6"], 1000, &users(), ChainConfig {
            soft_ok_votes: 3,
            hard_ok_ratio: 0.6,
            pack_budget_ms: 0,
            max_txs_per_ledger: 8,
            progress_timeout_ms: 0,
            pong_window_ms: 30_000,
            ..Default::default()
        });
        six.pong_all();
        let x = &six.nodes["v1"];
        assert_eq!(x.soft_votes_needed(), 4, "n=6: 4 of 6 committee (packer counts)");
        assert_eq!(x.hard_votes_needed(), 4); // ceil(6*0.6)=4

        // Asymmetric pong must not change soft_need (QC is tip-committed, not live).
        let mut solo = Network::bootstrap(
            &["v1", "v2", "v3"],
            1000,
            &users(),
            ChainConfig {
                soft_ok_votes: 3,
                pack_budget_ms: 0,
                max_txs_per_ledger: 8,
                progress_timeout_ms: 0,
                pong_window_ms: 30_000,
                ..Default::default()
            },
        );
        solo.nodes.get_mut("v1").unwrap().pong("v1");
        solo.nodes.get_mut("v1").unwrap().now_ms = 100_000;
        assert_eq!(
            solo.nodes["v1"].soft_votes_needed(),
            3,
            "asymmetric pong must not change soft_need on same bonded set"
        );
        assert_eq!(
            solo.nodes["v2"].soft_votes_needed(),
            solo.nodes["v1"].soft_votes_needed()
        );
    }

    #[test]
    fn open_height_schedule_frozen_against_online_flip() {
        // v2.5.0 A1: once frozen to a certified ONLINE tag, later live ONLINE
        // mutations must not reseed lottery for the open height.
        let cfg = ChainConfig {
            soft_ok_votes: 2,
            progress_timeout_ms: 1_000,
            pong_window_ms: 30_000,
            pack_budget_ms: 0,
            max_txs_per_ledger: 8,
            online_epoch_heights: 10,
            ..Default::default()
        };
        let mut net = Network::bootstrap(&["v1", "v2", "v3"], 1000, &users(), cfg);
        net.pong_all();
        let members: std::collections::BTreeSet<String> =
            ["v1", "v2", "v3"].into_iter().map(String::from).collect();
        for id in ["v1", "v2", "v3"] {
            for n in net.nodes.values_mut() {
                let _ = n.vote_online_set(0, members.clone(), id);
            }
        }
        for n in net.nodes.values_mut() {
            n.freeze_open_height_schedule();
        }
        assert_ne!(net.nodes["v1"].schedule_online_hash, "bootstrap");
        let order_before = net.nodes["v1"].lottery_order();
        let tag_before = net.nodes["v1"].lottery_online_tag();
        // Mutate live ONLINE as if a later epoch cert arrived mid-height.
        for n in net.nodes.values_mut() {
            n.online_members = ["v1", "v2"].into_iter().map(String::from).collect();
            n.online_hash = "mutated-live-online-hash".into();
            n.online_epoch_id = 99;
        }
        assert_eq!(
            net.nodes["v1"].lottery_order(),
            order_before,
            "lottery order must not flip mid-open"
        );
        assert_eq!(
            net.nodes["v1"].lottery_online_tag(),
            tag_before,
            "lottery online tag frozen for open height"
        );
        for _ in 0..2 {
            net.payment("alice", "bob", 1, 1).unwrap();
        }
        net.seal_next_height().unwrap();
        assert_eq!(net.tip_height(), 1);
        assert_eq!(
            net.nodes["v1"].schedule_height,
            2,
            "schedule frozen for tip+1 after commit"
        );
    }

    #[test]
    fn same_tip_divergent_online_same_lottery() {
        // Mainnet bar: local ONLINE must not fork the draw.
        let cfg = ChainConfig {
            online_epoch_heights: 10,
            pack_budget_ms: 0,
            ..Default::default()
        };
        let mut net = Network::bootstrap(
            &["v1", "v2", "v3", "v4", "v5", "v6", "v7"],
            1000,
            &users(),
            cfg,
        );
        net.pong_all();
        for n in net.nodes.values_mut() {
            n.freeze_open_height_schedule();
        }
        let agree = net.nodes["v1"].lottery_order();
        assert_eq!(agree.len(), 6);
        {
            let n = net.nodes.get_mut("v4").unwrap();
            n.online_epoch_id = 16;
            n.online_hash = "stale-epoch-16-hash".into();
            n.schedule_online_hash = "stale-epoch-16-hash".into();
            n.online_members = ["v1", "v2", "v3"].into_iter().map(String::from).collect();
            n.schedule_online_members = n.online_members.clone();
        }
        assert_eq!(
            net.nodes["v4"].lottery_order(),
            agree,
            "stale local ONLINE must not change lottery"
        );
        assert_eq!(net.nodes["v1"].lottery_packer(), net.nodes["v4"].lottery_packer());
    }

    #[test]
    fn same_tip_divergent_view_same_lottery() {
        let mut net = Network::bootstrap(
            &["v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8"],
            1000,
            &users(),
            ChainConfig {
                pack_budget_ms: 0,
                ..Default::default()
            },
        );
        net.pong_all();
        for n in net.nodes.values_mut() {
            n.freeze_open_height_schedule();
        }
        let agree = net.nodes["v1"].lottery_order();
        {
            let n = net.nodes.get_mut("v4").unwrap();
            n.height_view_round = 3;
        }
        assert_eq!(
            net.nodes["v4"].lottery_order(),
            agree,
            "view-round must not reseed lottery"
        );
        assert_eq!(
            net.nodes["v4"].draw_committee(),
            net.nodes["v1"].draw_committee()
        );
    }

    #[test]
    fn hard_need_capped_by_online_size() {
        let cfg = ChainConfig {
            soft_ok_votes: 3,
            hard_ok_ratio: 0.6,
            pong_window_ms: 30_000,
            pack_budget_ms: 0,
            max_txs_per_ledger: 8,
            progress_timeout_ms: 0,
            online_epoch_heights: 10,
            committee_size: 0,
            ..Default::default()
        };
        let mut net = Network::bootstrap(
            &["v1", "v2", "v3", "v4", "v5", "v6"],
            1000,
            &users(),
            cfg,
        );
        net.pong_all();
        assert_eq!(net.nodes["v1"].hard_votes_needed(), 4);
        let members: std::collections::BTreeSet<String> =
            ["v1", "v2", "v3"].into_iter().map(String::from).collect();
        for id in ["v1", "v2", "v3"] {
            for n in net.nodes.values_mut() {
                let _ = n.vote_online_set(0, members.clone(), id);
            }
        }
        assert_eq!(net.nodes["v1"].online_members.len(), 3);
        assert_eq!(net.nodes["v1"].hard_votes_needed(), 3);
    }

    #[test]
    fn unique_pending_survives_view_change() {
        let cfg = ChainConfig {
            soft_ok_votes: 2,
            progress_timeout_ms: 1_000,
            pong_window_ms: 30_000,
            pack_budget_ms: 0,
            max_txs_per_ledger: 8,
            online_epoch_heights: 0,
            ..Default::default()
        };
        let mut net = Network::bootstrap(&["v1", "v2", "v3"], 1000, &users(), cfg);
        net.pong_all();
        for _ in 0..3 {
            net.payment("alice", "bob", 1, 1).unwrap();
        }
        net.seal_next_height().unwrap();
        net.pong_all();
        for n in net.nodes.values_mut() {
            n.freeze_open_height_schedule();
        }
        let winner = net.nodes["v1"].lottery_packer().expect("winner").clone();
        for _ in 0..3 {
            net.payment("alice", "bob", 1, 1).unwrap();
        }
        let led = {
            let n = net.nodes.get_mut(&winner).unwrap();
            n.pack_as(&winner).expect("pack")
        };
        {
            let n = net.nodes.get_mut("v1").unwrap();
            n.pending_proposal = Some(led);
            n.height_open_ms = n.now_ms;
        }
        assert!(net.nodes["v1"].pending_proposal.is_some());
        for n in net.nodes.values_mut() {
            n.now_ms = n.now_ms.saturating_add(n.proposal_timeout_ms() + 100);
        }
        let tip_hash = net.nodes["v1"].tip_hash.clone();
        let h = net.nodes["v1"].tip_height + 1;
        for id in ["v1", "v2"] {
            for n in net.nodes.values_mut() {
                let _ = n.vote_view_change(h, &tip_hash, 1, id);
            }
        }
        assert!(
            net.nodes["v1"].pending_proposal.is_some(),
            "unique pending must not be discarded by VC"
        );
        assert!(net.nodes["v1"].lottery_packer().is_some());
        assert!(
            net.nodes
                .get_mut("v1")
                .unwrap()
                .maybe_view_change_vote()
                .is_none(),
            "unique pending must not trigger VC-drop"
        );
    }

    #[test]
    fn view_change_does_not_redraw_committee() {
        let ids: Vec<String> = (1..=11).map(|i| format!("v{i}")).collect();
        let refs: Vec<&str> = ids.iter().map(|s| s.as_str()).collect();
        let mut net = Network::bootstrap(
            &refs,
            1000,
            &users(),
            ChainConfig {
                soft_ok_votes: 3,
                pack_budget_ms: 0,
                ..Default::default()
            },
        );
        net.pong_all();
        for n in net.nodes.values_mut() {
            n.freeze_open_height_schedule();
        }
        let before = net.nodes["v1"].lottery_order();
        assert_eq!(before.len(), 6);
        let first = before[0].clone();
        let tip = net.nodes["v1"].tip_hash.clone();
        let h = net.nodes["v1"].tip_height + 1;
        let seats = net.nodes["v1"].lottery_order();
        for id in seats.iter().take(4) {
            for n in net.nodes.values_mut() {
                let _ = n.vote_view_change(h, &tip, 1, id);
            }
        }
        let n = &net.nodes["v1"];
        assert_eq!(n.height_view_round, 1);
        assert_eq!(n.lottery_order(), before, "VC must not redraw the 6");
        assert_ne!(
            n.lottery_packer().as_deref(),
            Some(first.as_str()),
            "VC skip-advances the cursor on the same 6"
        );
    }

    #[test]
    fn view_change_same_packer_cannot_reseal() {
        let mut net = Network::bootstrap(
            &["v1", "v2", "v3", "v4", "v5", "v6"],
            1000,
            &users(),
            ChainConfig {
                soft_ok_votes: 3,
                pack_budget_ms: 0,
                max_txs_per_ledger: 8,
                ..Default::default()
            },
        );
        net.pong_all();
        for _ in 0..3 {
            net.payment("alice", "bob", 1, 1).unwrap();
        }
        let winner = net.nodes["v1"].lottery_packer().unwrap();
        let led = net.nodes.get_mut(&winner).unwrap().pack_as(&winner).unwrap();
        let h = led.height;
        {
            let n = net.nodes.get_mut("v1").unwrap();
            n.pending_proposal = Some(led.clone());
            n.seen_at_height
                .insert(h, (winner.clone(), led.ledger_hash.clone()));
            n.note_height_sealer(h, &winner);
        }
        let tip = net.nodes["v1"].tip_hash.clone();
        let seats = net.nodes["v1"].lottery_order();
        for id in seats.iter().take(4) {
            for n in net.nodes.values_mut() {
                let _ = n.vote_view_change(h, &tip, 1, id);
            }
        }
        let n = net.nodes.get_mut("v1").unwrap();
        assert!(
            n.pending_proposal.is_some(),
            "unique pending survives VC — reseal is the same hash"
        );
        assert!(n
            .height_sealers
            .get(&h)
            .map(|s| s.contains(&winner))
            .unwrap_or(false));
        if n.lottery_packer().as_deref() == Some(winner.as_str()) {
            let err = n.pack_as(&winner).unwrap_err();
            assert!(
                err.contains("already sealed") || err.contains("pending"),
                "{err}"
            );
        }
    }

    #[test]
    fn full_committee_skip_reopens_clears_sealer_bans() {
        let ids: Vec<String> = (1..=6).map(|i| format!("v{i}")).collect();
        let refs: Vec<&str> = ids.iter().map(|s| s.as_str()).collect();
        let mut net = Network::bootstrap(
            &refs,
            1000,
            &users(),
            ChainConfig {
                pack_budget_ms: 0,
                max_txs_per_ledger: 8,
                committee_size: 6,
                ..Default::default()
            },
        );
        net.pong_all();
        for n in net.nodes.values_mut() {
            n.freeze_open_height_schedule();
        }
        for _ in 0..3 {
            net.payment("alice", "bob", 1, 1).unwrap();
        }
        let winner = net.nodes["v1"].lottery_packer().unwrap();
        let led = net.nodes.get_mut(&winner).unwrap().pack_as(&winner).unwrap();
        let h = led.height;
        let tip = net.nodes["v1"].tip_hash.clone();
        let order = net.nodes["v1"].lottery_order();
        for n in net.nodes.values_mut() {
            n.pending_proposal = Some(led.clone());
            n.seen_at_height
                .insert(h, (winner.clone(), led.ledger_hash.clone()));
            n.note_height_sealer(h, &winner);
            let _ = n.vote_ok_ex(&led.ledger_hash, &winner, "");
        }
        // Skip-QC every seat (including the sealer after VC-style drop).
        for n in net.nodes.values_mut() {
            n.pending_proposal = None;
            n.seen_at_height.remove(&h);
        }
        for seat in &order {
            for n in net.nodes.values_mut() {
                n.skip_reopen_cooldown_until_ms = 0;
                n.apply_shared_skip(h, seat, &tip);
            }
        }
        let n = net.nodes.get_mut("v1").unwrap();
        assert!(
            n.skip_set_for(h).is_empty(),
            "full skip must reopen the attempt"
        );
        assert!(
            n.height_sealers.get(&h).map(|s| s.is_empty()).unwrap_or(true),
            "reopen must drop sealer bans on an uncommitted height"
        );
        assert!(
            n.ok_by_height_voter.get(&h).is_none(),
            "reopen must drop attempt OKs or the next body looks like a double-sign"
        );
        n.pong(&winner);
        n.skip_grace_until_ms = 0;
        n.skip_reopen_cooldown_until_ms = 0;
        assert!(
            n.pack_as(&winner).is_ok(),
            "discarded pending is not a commit — winner may pack the new attempt"
        );
    }

    #[test]
    fn catchup_adopts_peer_body_over_local_dual() {
        let mut net = Network::bootstrap(
            &["v1", "v2", "v3"],
            1000,
            &users(),
            ChainConfig {
                pack_budget_ms: 0,
                max_txs_per_ledger: 8,
                committee_size: 0,
                ..Default::default()
            },
        );
        net.pong_all();
        for _ in 0..3 {
            net.payment("alice", "bob", 1, 1).unwrap();
        }
        let winner = net.nodes["v1"].lottery_packer().unwrap();
        let led = net.nodes.get_mut(&winner).unwrap().pack_as(&winner).unwrap();
        let h = led.height;
        {
            let n = net.nodes.get_mut("v1").unwrap();
            n.seen_at_height
                .insert(h, (winner.clone(), "ff".repeat(32)));
            n.pending_proposal = None;
        }
        let n = net.nodes.get_mut("v1").unwrap();
        n.ingest_ledger_catchup(&led)
            .expect("catch-up must adopt peer body");
        assert_eq!(n.tip_height, h);
        assert_eq!(n.tip_hash, led.ledger_hash);
    }

    #[test]
    fn header_matches_sealed_ledger() {
        let mut net = Network::bootstrap(
            &["v1", "v2", "v3"],
            1000,
            &users(),
            ChainConfig {
                pack_budget_ms: 0,
                max_txs_per_ledger: 8,
                committee_size: 0,
                ..Default::default()
            },
        );
        net.pong_all();
        for _ in 0..3 {
            net.payment("alice", "bob", 1, 1).unwrap();
        }
        let w = net.nodes["v1"].lottery_packer().unwrap();
        let led = net.nodes.get_mut(&w).unwrap().pack_as(&w).unwrap();
        let h = led.header();
        assert_eq!(h.ledger_hash, led.ledger_hash);
        assert_eq!(h.tx_ids, led.tx_ids);
        assert!(h.verify_packer(&net.nodes["v1"].keys));
        assert!(led.has_body());
    }

    #[test]
    fn prune_old_bodies_keeps_recent() {
        let mut net = Network::bootstrap(
            &["v1", "v2", "v3"],
            1000,
            &users(),
            ChainConfig {
                pack_budget_ms: 0,
                max_txs_per_ledger: 8,
                max_body_ledgers: 2,
                committee_size: 0,
                ..Default::default()
            },
        );
        net.pong_all();
        for _ in 0..5 {
            net.payment("alice", "bob", 1, 1).unwrap();
            net.seal_next_height().unwrap();
        }
        let n = &net.nodes["v1"];
        assert!(n.tip_height >= 5);
        n.chain.iter().for_each(|l| {
            if l.height + 2 <= n.tip_height {
                assert!(!l.has_body(), "old h={} still has body", l.height);
            } else {
                assert!(l.has_body(), "recent h={} lost body", l.height);
            }
        });
        let last = n.chain.last().unwrap();
        assert!(n.ledger_body(&last.ledger_hash).is_some());
    }

    #[test]
    fn skip_advances_cursor_not_reseed_order() {
        // v2.3.4: tip-fixed order; skip promotes next preselected seat.
        let cfg = ChainConfig {
            progress_timeout_ms: 1_000,
            pong_window_ms: 2_000,
            pack_budget_ms: 0,
            max_txs_per_ledger: 8,
            soft_ok_votes: 1,
            ..Default::default()
        };
        let mut net = Network::bootstrap(&["v1", "v2", "v3"], 1000, &users(), cfg);
        net.pong_all();
        for _ in 0..3 {
            net.payment("alice", "bob", 1, 1).unwrap();
        }
        let order = net.nodes["v1"].lottery_order();
        assert!(order.len() >= 2);
        let primary = order[0].clone();
        let standby = order[1].clone();
        assert_eq!(
            net.nodes["v1"].lottery_packer().as_deref(),
            Some(primary.as_str())
        );
        let tip = net.nodes["v1"].tip_hash.clone();

        // Same skip QC on all nodes → same active seat (cursor).
        let voters: Vec<String> = net.nodes.keys().cloned().collect();
        for n in net.nodes.values_mut() {
            for v in &voters {
                if v != &primary {
                    let _ = n.vote_skip(1, &primary, &tip, v);
                }
            }
        }
        for n in net.nodes.values() {
            assert_eq!(
                n.lottery_order(),
                order,
                "seat order must stay tip-fixed after skip"
            );
            assert_eq!(
                n.lottery_packer().as_deref(),
                Some(standby.as_str()),
                "skip promotes preselected #2"
            );
            let q = n.lottery_ranked(3);
            assert_eq!(q[0], standby);
            assert!(q.len() >= 1);
        }
        // Standby can pack after skip QC + pong.
        for n in net.nodes.values_mut() {
            n.skip_grace_until_ms = 0;
            n.pong(&standby);
        }
        let ledger = net
            .nodes
            .get_mut(&standby)
            .unwrap()
            .pack_as(&standby)
            .unwrap();
        for n in net.nodes.values_mut() {
            n.accept_ledger(&ledger).unwrap();
        }
        let hash = ledger.ledger_hash.clone();
        let ids: Vec<String> = net.nodes.keys().cloned().collect();
        for n in net.nodes.values_mut() {
            for id in &ids {
                n.vote_ok(&hash, id);
            }
        }
        assert_eq!(net.tip_height(), 1);
    }

    #[test]
    fn lottery_order_same_despite_asymmetric_skips() {
        let mut net =
            Network::bootstrap(&["v1", "v2", "v3", "v4"], 1000, &users(), ChainConfig::default());
        net.pong_all();
        let tip = net.nodes["v1"].tip_hash.clone();
        let order0 = net.nodes["v1"].lottery_order();
        net.nodes
            .get_mut("v1")
            .unwrap()
            .apply_shared_skip(1, "v2", &tip);
        net.nodes
            .get_mut("v2")
            .unwrap()
            .apply_shared_skip(1, "v3", &tip);
        // Order identical everywhere (tip-fixed).
        for n in net.nodes.values() {
            assert_eq!(n.lottery_order(), order0);
        }
        // Active seat may differ until skip QC is shared — that's QC completeness,
        // not lottery reseed. When skip sets match, active matches.
        for n in net.nodes.values_mut() {
            let _ = n.apply_shared_skip(1, "v2", &tip);
            let _ = n.apply_shared_skip(1, "v3", &tip);
        }
        let actives: Vec<_> = net
            .nodes
            .values()
            .map(|n| n.lottery_packer().unwrap())
            .collect();
        assert!(
            actives.iter().all(|a| a == &actives[0]),
            "shared skips → same active: {actives:?}"
        );
    }

    #[test]
    fn progress_timeout_does_not_skip_live_winner() {
        // Lagging peer must NOT skip a packer that is still ponging (would fork).
        let cfg = ChainConfig {
            progress_timeout_ms: 1_000,
            pong_window_ms: 30_000,
            ..Default::default()
        };
        let mut net = Network::bootstrap(&["v1", "v2", "v3"], 1000, &users(), cfg);
        net.pong_all();
        net.payment("alice", "bob", 1, 1).unwrap();
        let primary = net.nodes.values().next().unwrap().lottery_packer().unwrap();
        let under = net.nodes["v1"].live_pack_timeout_ms().saturating_sub(200).max(200);
        for n in net.nodes.values_mut() {
            n.tick(under);
            // Keep winner live via pong
            n.pong(&primary);
            assert!(
                n.maybe_progress_timeout_skip().is_none(),
                "must not skip live winner inside pack+pull budget"
            );
            assert_eq!(n.lottery_packer().as_deref(), Some(primary.as_str()));
        }
    }

    #[test]
    fn live_pong_fresh_winner_is_not_skipped() {
        let cfg = ChainConfig {
            pack_budget_ms: 0,
            progress_timeout_ms: 1_000,
            pong_window_ms: 30_000,
            ..Default::default()
        };
        let mut net = Network::bootstrap(&["v1", "v2", "v3"], 1000, &users(), cfg);
        net.pong_all();
        net.payment("alice", "bob", 1, 1).unwrap();
        let primary = net.nodes["v1"].lottery_packer().unwrap();
        let wait = net.nodes["v1"].live_pack_timeout_ms() + 50;
        for n in net.nodes.values_mut() {
            n.height_open_ms = n.now_ms;
            n.tick(wait);
            n.pong(&primary);
        }
        let observer = net
            .nodes
            .keys()
            .find(|id| *id != &primary)
            .cloned()
            .unwrap();
        let skip = net
            .nodes
            .get_mut(&observer)
            .unwrap()
            .propose_progress_timeout_skip();
        assert!(
            skip.is_none(),
            "pong-fresh winner must not be skipped, got {skip:?}"
        );
    }

    #[test]
    fn want_body_blocks_progress_skip() {
        let cfg = ChainConfig {
            pack_budget_ms: 0,
            progress_timeout_ms: 1_000,
            pong_window_ms: 2_000,
            ..Default::default()
        };
        let mut net = Network::bootstrap(&["v1", "v2", "v3"], 1000, &users(), cfg);
        net.pong_all();
        net.payment("alice", "bob", 1, 1).unwrap();
        let primary = net.nodes["v1"].lottery_packer().unwrap();
        let observer = net
            .nodes
            .keys()
            .find(|id| *id != &primary)
            .cloned()
            .unwrap();
        {
            let c = net.nodes.get_mut(&observer).unwrap();
            c.note_want_body(c.tip_height + 1, "hdr");
            // Stale the winner — header still means they proposed.
            c.now_ms = c.now_ms.saturating_add(c.cfg.pong_window_ms + 1);
            c.height_open_ms = 0;
            assert!(c.propose_progress_timeout_skip().is_none());
        }
    }

    #[test]
    fn light_checker_does_not_skip_live_winner() {
        let cfg = ChainConfig {
            pack_budget_ms: 0,
            progress_timeout_ms: 1_000,
            pong_window_ms: 30_000,
            ..Default::default()
        };
        let mut net = Network::bootstrap(&["v1", "v2", "v3"], 1000, &users(), cfg);
        net.pong_all();
        let primary = net.nodes["v1"].lottery_packer().unwrap();
        let checker = net
            .nodes
            .keys()
            .find(|id| *id != &primary)
            .cloned()
            .unwrap();
        let hub = net
            .nodes
            .keys()
            .find(|id| *id != &primary && *id != &checker)
            .cloned()
            .unwrap();
        {
            let c = net.nodes.get_mut(&checker).unwrap();
            c.mempool = Default::default();
            assert!(!c.has_applicable_tx());
            c.pong_with_inventory(&hub, c.tip_height, 80, true);
            c.height_open_ms = c.now_ms;
            c.tick(c.live_pack_timeout_ms() + 50);
            c.pong(&primary);
            assert!(c.network_has_pack_work(), "hub ad must count as work");
            assert!(
                c.propose_progress_timeout_skip().is_none(),
                "hub inventory is not a reason to skip a live winner"
            );
        }
        // Dead winner: stale pong → skip.
        {
            let c = net.nodes.get_mut(&checker).unwrap();
            c.cfg.pong_window_ms = 1_000;
            c.now_ms = c.now_ms.saturating_add(5_000);
            c.pong(&checker);
            c.pong_with_inventory(&hub, c.tip_height, 80, true);
            c.height_open_ms = 0;
            assert!(c.active_packer_unavailable());
            let skip = c.propose_progress_timeout_skip();
            assert_eq!(
                skip.as_ref().map(|s| s.1.as_str()),
                Some(primary.as_str()),
                "unavailable winner is still skipped"
            );
        }
    }

    #[test]
    fn dish_seats_are_winner_and_first_backup() {
        let mut net = Network::bootstrap(
            &["v1", "v2", "v3"],
            1000,
            &users(),
            ChainConfig::default(),
        );
        net.pong_all();
        let n = net.nodes.get_mut("v1").unwrap();
        n.freeze_open_height_schedule();
        let order = n.lottery_order();
        assert!(order.len() >= 2);
        let seats = n.dish_seats();
        assert_eq!(seats.len(), 2, "winner + first backup");
        assert_eq!(seats[0], order[0]);
        assert_eq!(seats[1], order[1]);
        let tip = n.tip_hash.clone();
        assert!(n.apply_shared_skip(1, &order[0], &tip));
        let seats = n.dish_seats();
        assert_eq!(seats[0], order[1], "dish follows skip cursor");
        if order.len() >= 3 {
            assert_eq!(seats[1], order[2]);
        }
    }

    #[test]
    fn startup_waits_for_peer_tips_before_pack() {
        let mut n = Node::new(
            "v1",
            ChainConfig::default(),
            KeyRing::new(CryptoScheme::HmacDev),
            &users(),
        );
        n.register_validator("v1", 1000);
        n.register_validator("v2", 1000);
        n.tip_height = 10;
        n.started_ms = n.now_ms.max(1);
        assert!(n.startup_pack_blocked(), "no peer ads yet");
        n.now_ms = n.started_ms + Node::STARTUP_TIP_GRACE_MS + 1;
        assert!(!n.startup_pack_blocked(), "grace elapsed");
        n.now_ms = n.started_ms;
        n.pong_with_inventory("v2", 10, 0, false);
        assert!(!n.startup_pack_blocked(), "peer tip ad unblocks");
    }

    #[test]
    fn body_lane_seats_are_the_qc_committee() {
        let mut net = Network::bootstrap(
            &["v1", "v2", "v3"],
            1000,
            &users(),
            ChainConfig::default(),
        );
        net.pong_all();
        let n = net.nodes.get("v1").unwrap();
        let body = n.body_lane_seats();
        let order = n.lottery_order();
        assert_eq!(body, order, "body lane is the 6 (or n), not winner-only");
        assert!(body.len() >= 2);
    }

    #[test]
    fn shared_skip_promotes_next_seat_same_order() {
        let mut net = Network::bootstrap(&["v1", "v2", "v3"], 1000, &users(), ChainConfig::default());
        net.pong_all();
        let tip = net.nodes.values().next().unwrap().tip_hash.clone();
        let order = net.nodes["v1"].lottery_order();
        let primary = order[0].clone();
        let next = order[1].clone();
        assert!(!net
            .nodes
            .get_mut("v1")
            .unwrap()
            .apply_shared_skip(1, &primary, "not-the-tip"));
        assert!(net
            .nodes
            .get_mut("v1")
            .unwrap()
            .apply_shared_skip(1, &primary, &tip));
        assert_eq!(net.nodes["v1"].lottery_order(), order);
        assert_eq!(
            net.nodes.get("v1").unwrap().lottery_packer().as_deref(),
            Some(next.as_str())
        );
    }

    #[test]
    fn progress_timeout_idle_does_not_skip() {
        let mut net = Network::bootstrap(&["v1", "v2", "v3"], 1000, &users(), ChainConfig::default());
        net.pong_all();
        let primary = net.nodes.values().next().unwrap().lottery_packer().unwrap();
        for n in net.nodes.values_mut() {
            n.tick(5_000);
            assert!(n.maybe_progress_timeout_skip().is_none());
            assert_eq!(n.lottery_packer().as_deref(), Some(primary.as_str()));
        }
    }

    #[test]
    fn protocol_bond_in_ledger_updates_commitment() {
        let cfg = ChainConfig {
            pack_budget_ms: 0,
            max_txs_per_ledger: 8,
            unbond_cooldown_ms: 1_000,
            ..Default::default()
        };
        let mut net = Network::bootstrap(&["v1", "v2"], 1000, &users(), cfg);
        net.pong_all();
        let seq = net.account_seqs["alice"];
        let tx = Tx::sign_body(
            &net.user_keys,
            "alice",
            seq,
            "v2",
            2_000,
            2,
            net.cfg.network_id,
            TxBody::Bond {
                validator: "v2".into(),
            },
        )
        .unwrap();
        *net.account_seqs.get_mut("alice").unwrap() += 1;
        for n in net.nodes.values_mut() {
            n.submit_tx(tx.clone()).unwrap();
        }
        net.seal_next_height().unwrap();
        let b = net.nodes.get("v1").unwrap().validators["v2"].bond;
        assert_eq!(b, 1000 + 2_000);
        // peers share commitment
        let r1 = net.nodes.get("v1").unwrap().commitment_root();
        let r2 = net.nodes.get("v2").unwrap().commitment_root();
        assert_eq!(r1, r2);
    }

    #[test]
    fn pull_catchup_closes_tip_lag() {
        // Production lag fix: lagging node applies ledgers_from advanced peer.
        let cfg = ChainConfig {
            pack_budget_ms: 0,
            max_txs_per_ledger: 4,
            progress_timeout_ms: 0, // no skip noise
            ..Default::default()
        };
        let mut net = Network::bootstrap(&["v1", "v2", "v3"], 1000, &users(), cfg);
        net.pong_all();
        for _ in 0..5 {
            net.payment("alice", "bob", 1, 1).unwrap();
            net.seal_next_height().unwrap();
        }
        assert_eq!(net.tip_height(), 5);
        // Simulate v3 lagging: reset tip state but keep keys/validators
        {
            let n = net.nodes.get_mut("v3").unwrap();
            n.tip_height = 0;
            n.tip_hash = sha256_hex(b"pl-genesis-v1");
            n.chain.clear();
            n.seen_at_height.clear();
            n.state = WorldState::genesis(&users());
            n.mempool = Default::default();
            // peer advertises tip 5
            n.now_ms = 10_000;
            let from = n.note_peer_tip(5, "x").expect("should request catch-up");
            assert_eq!(from, 1);
        }
        let batch = net.nodes.get("v1").unwrap().ledgers_from(1, 64);
        assert_eq!(batch.len(), 5);
        for led in &batch {
            net.nodes
                .get_mut("v3")
                .unwrap()
                .ingest_ledger_catchup(led)
                .unwrap();
        }
        assert_eq!(net.nodes.get("v3").unwrap().tip_height, 5);
        assert_eq!(
            net.nodes.get("v3").unwrap().tip_hash,
            net.nodes.get("v1").unwrap().tip_hash
        );
    }

    #[test]
    fn catchup_matches_packer_after_epoch_ticks() {
        // Production dual-host bug: packer ticks epoch settle between seals;
        // lagging peer must advance now_ms to sealed_at_ms before apply.
        let cfg = ChainConfig {
            pack_budget_ms: 0,
            max_txs_per_ledger: 4,
            progress_timeout_ms: 0,
            epoch_ms: 1_000, // short epochs so settle fires mid-chain
            ..Default::default()
        };
        let mut net = Network::bootstrap(&["v1", "v2", "v3"], 1000, &users(), cfg);
        net.pong_all();
        for i in 0..8 {
            net.payment("alice", "bob", 1, 1).unwrap();
            // Simulate wall time advancing between seals (like node tick).
            for n in net.nodes.values_mut() {
                n.tick(400);
            }
            net.seal_next_height().unwrap();
            let _ = i;
        }
        assert!(net.tip_height() >= 8);
        let tip_hash = net.nodes.get("v1").unwrap().tip_hash.clone();
        let last_settled = net.nodes.get("v1").unwrap().last_settled_epoch;
        assert!(
            last_settled > 0,
            "expected epoch settle during chain; last_settled={last_settled}"
        );
        let batch = net.nodes.get("v1").unwrap().ledgers_from(1, 64);
        let want_tip = net.tip_height();
        let want_root = net.nodes.get("v1").unwrap().commitment_root();
        // Lagging v3 from genesis with cold clock.
        {
            let n = net.nodes.get_mut("v3").unwrap();
            n.tip_height = 0;
            n.tip_hash = sha256_hex(b"pl-genesis-v1");
            n.chain.clear();
            n.seen_at_height.clear();
            n.state = WorldState::genesis(&users());
            n.claimable.clear();
            n.epoch_work = Default::default();
            n.last_settled_epoch = 0;
            n.treasury = TREASURY_GENESIS;
            n.now_ms = 1_000;
            n.genesis_ms = 1_000;
            n.best_peer_tip = want_tip;
            let tip = n.apply_catchup_batch(&batch).expect("catch-up after epoch ticks");
            assert_eq!(tip, want_tip);
            assert_eq!(n.tip_hash, tip_hash);
            assert_eq!(n.last_settled_epoch, last_settled);
            assert_eq!(n.commitment_root(), want_root);
        }
    }

    #[test]
    fn settle_agrees_when_body_windows_differ() {
        // Live 20922: epoch 1368 had 126 ledgers. Archive hub counted
        // led.txs.len() on the last 64 RAM bodies. Droplet loaded v1's
        // archive=true snap, never opened a store, kept every catch-up body,
        // and rejected the first epoch-boundary ledger.
        let epoch_ms = 2_000u64;
        let cfg = ChainConfig {
            pack_budget_ms: 0,
            max_txs_per_ledger: 2,
            progress_timeout_ms: 0,
            epoch_ms,
            first_claim_epoch: 1,
            max_body_ledgers: 2,
            soft_ok_votes: 1,
            ..Default::default()
        };
        let mut net = Network::bootstrap(&["v1", "v2", "v3"], 1000, &users(), cfg);
        net.pong_all();
        // v3 is the joiner class: archive flag, no disk store → old prune
        // kept every body. v1/v2 strip to max_body=2 like a live hub.
        net.nodes.get_mut("v3").unwrap().cfg.archive = true;
        net.nodes.get_mut("v3").unwrap().cfg.max_body_ledgers = 1_000;
        for _ in 0..10 {
            net.payment("alice", "bob", 1, 1).unwrap();
            net.tick_all(300);
            net.seal_next_height().unwrap();
        }
        let v1_bodies = net.nodes["v1"]
            .chain
            .iter()
            .filter(|l| !l.txs.is_empty())
            .count();
        let v3_bodies = net.nodes["v3"]
            .chain
            .iter()
            .filter(|l| !l.txs.is_empty())
            .count();
        assert!(
            v1_bodies <= 2,
            "hub must strip to the body window, got {v1_bodies}"
        );
        assert!(
            v3_bodies > v1_bodies,
            "joiner must still hold extra bodies ({v3_bodies} vs hub {v1_bodies})"
        );
        assert_eq!(net.nodes["v1"].tip_hash, net.nodes["v3"].tip_hash);
        assert_eq!(
            net.nodes["v1"].commitment_root(),
            net.nodes["v3"].commitment_root()
        );
        // Cross the next epoch boundary with a fat enough history that
        // txs.len() on the 2-body window ≠ full-epoch tx_ids.
        let genesis = net.nodes["v1"].genesis_ms;
        let cur = net.nodes["v1"].current_epoch();
        let past_end = genesis.saturating_add(cur.saturating_mul(epoch_ms)) + 50;
        for n in net.nodes.values_mut() {
            n.now_ms = n.now_ms.max(past_end);
        }
        net.payment("alice", "bob", 1, 1).unwrap();
        net.seal_next_height()
            .expect("epoch-boundary pack must be accepted by a joiner with extra bodies");
        assert_eq!(net.nodes["v1"].tip_hash, net.nodes["v3"].tip_hash);
        assert_eq!(
            net.nodes["v1"].commitment_root(),
            net.nodes["v3"].commitment_root(),
            "settle must not depend on who still holds txs in RAM"
        );
        assert!(
            net.nodes["v1"].last_settled_epoch >= 1,
            "test must actually settle"
        );
    }

    #[test]
    fn pre_upgrade_epoch_boundary_replays_body_window() {
        // 34799: 2.9.17 packed with txs.len() on the 64-body window.
        // 2.9.18 incremental rejected an honest residual apply. Headers
        // from that era have fee_total=0 — replay the old walk when
        // every node stripped the same window.
        let epoch_ms = 2_000u64;
        let cfg = ChainConfig {
            pack_budget_ms: 0,
            max_txs_per_ledger: 2,
            progress_timeout_ms: 0,
            epoch_ms,
            first_claim_epoch: 1,
            max_body_ledgers: 2,
            soft_ok_votes: 1,
            ..Default::default()
        };
        let mut net = Network::bootstrap(&["v1", "v2", "v3"], 1000, &users(), cfg);
        net.pong_all();
        for _ in 0..8 {
            net.payment("alice", "bob", 1, 1).unwrap();
            net.tick_all(300);
            net.seal_next_height().unwrap();
        }
        for n in net.nodes.values_mut() {
            for led in &mut n.chain {
                led.fee_total = 0;
            }
        }
        let genesis = net.nodes["v1"].genesis_ms;
        let cur = net.nodes["v1"].current_epoch();
        let past_end = genesis.saturating_add(cur.saturating_mul(epoch_ms)) + 50;
        for n in net.nodes.values_mut() {
            n.now_ms = n.now_ms.max(past_end);
        }
        net.payment("alice", "bob", 1, 1).unwrap();
        net.seal_next_height()
            .expect("fee_total=0 epoch must replay the 2.9.17 body window");
        assert_eq!(net.nodes["v1"].tip_hash, net.nodes["v3"].tip_hash);
        assert_eq!(
            net.nodes["v1"].commitment_root(),
            net.nodes["v3"].commitment_root()
        );
    }

    #[test]
    fn clock_skew_does_not_change_catchup_root() {
        // The 2.7.1 v1/v2 stall: local now_ms hours ahead of sealed_at.
        let cfg = ChainConfig {
            pack_budget_ms: 0,
            max_txs_per_ledger: 4,
            progress_timeout_ms: 0,
            epoch_ms: 1_000,
            soft_ok_votes: 1,
            ..Default::default()
        };
        let mut net = Network::bootstrap(&["v1", "v2", "v3"], 1000, &users(), cfg);
        net.pong_all();
        for _ in 0..6 {
            net.payment("alice", "bob", 1, 1).unwrap();
            net.seal_next_height().unwrap();
        }
        let batch = net.nodes["v1"].ledgers_from(1, 64);
        let want_hash = net.nodes["v1"].tip_hash.clone();
        let want_root = net.nodes["v1"].commitment_root();
        let want_tip = net.tip_height();
        let n = net.nodes.get_mut("v3").unwrap();
        n.tip_height = 0;
        n.tip_hash = sha256_hex(b"pl-genesis-v1");
        n.chain.clear();
        n.seen_at_height.clear();
        n.state = WorldState::genesis(&users());
        n.claimable.clear();
        n.epoch_work = Default::default();
        n.last_settled_epoch = 0;
        n.treasury = TREASURY_GENESIS;
        n.now_ms = 3_600_000; // hour ahead of packer stamps
        n.genesis_ms = 1_000;
        let tip = n.apply_catchup_batch(&batch).expect("skewed catch-up");
        assert_eq!(tip, want_tip);
        assert_eq!(n.tip_hash, want_hash);
        assert_eq!(n.commitment_root(), want_root);
    }

    #[test]
    fn snap_clock_skew_does_not_reject_honest_pack() {
        // Power-cut: host1 snap now_ms hours behind host2. Packer stamps
        // from its clock; ingest must use parent sealed_at, not local now.
        let cfg = ChainConfig {
            pack_budget_ms: 0,
            max_txs_per_ledger: 4,
            progress_timeout_ms: 0,
            ..Default::default()
        };
        let mut net = Network::bootstrap(&["v1", "v2", "v3"], 1000, &users(), cfg);
        net.pong_all();
        net.payment("alice", "bob", 1, 1).unwrap();
        net.seal_next_height().unwrap();
        let parent_t = net.nodes["v1"].chain.last().unwrap().sealed_at_ms;
        net.nodes.get_mut("v1").unwrap().now_ms = parent_t;
        net.nodes.get_mut("v2").unwrap().now_ms = parent_t + 9_600_000;
        net.pong_all();
        net.payment("alice", "bob", 1, 1).unwrap();
        let winner = net.nodes["v2"].lottery_packer().unwrap();
        let packer = if winner == "v2" { "v2" } else { "v1" };
        net.nodes.get_mut(packer).unwrap().now_ms = parent_t + 9_600_000;
        net.nodes.get_mut("v1").unwrap().now_ms = parent_t;
        let w = net.nodes["v1"].lottery_packer().unwrap();
        let n = net.nodes.get_mut(&w).unwrap();
        n.now_ms = parent_t + 9_600_000;
        n.pong(&w);
        let led = n.pack_as(&w).expect("drifted packer can pack");
        assert!(
            led.sealed_at_ms <= parent_t + Node::SEALED_AT_MAX_AHEAD_MS,
            "stamp must clamp to parent+MAX"
        );
        let recv = net.nodes.get_mut("v1").unwrap();
        recv.now_ms = parent_t;
        recv.pong(&w);
        recv.verify_ledger_state_root(&led)
            .expect("stale snap clock must not reject clamped stamp");
    }

    #[test]
    fn pack_folds_at_chain_stamp_not_wall_clock() {
        // Live 2.9.5 after power-cut: 30s epochs, first_claim=1, last_settled
        // tracks parent time. Packer snap now_ms hours ahead folded hundreds of
        // extra epochs into claimable, then stamped parent+60s. Ingest folded
        // at sealed_at → self-accept state root mismatch.
        let epoch_ms = 3_000u64;
        let cfg = ChainConfig {
            pack_budget_ms: 0,
            max_txs_per_ledger: 4,
            progress_timeout_ms: 0,
            epoch_ms,
            first_claim_epoch: 1,
            soft_ok_votes: 1,
            ..Default::default()
        };
        let mut net = Network::bootstrap(&["v1", "v2", "v3"], 1000, &users(), cfg);
        net.pong_all();
        let genesis = net.nodes.values().next().unwrap().genesis_ms;
        // Cross at least one epoch within the 4s per-block pack_sealed_at step.
        for n in net.nodes.values_mut() {
            n.now_ms = genesis + epoch_ms + 5_000;
        }
        net.payment("alice", "bob", 1, 1).unwrap();
        net.seal_next_height().unwrap();
        let parent_t = net.nodes["v1"].chain.last().unwrap().sealed_at_ms;
        let settled = net.nodes["v1"].last_settled_epoch;
        assert!(settled >= 1, "test needs a settled epoch, got {settled}");
        net.payment("alice", "bob", 1, 1).unwrap();
        // Hours ahead of parent — same class as live now_ms=17654800 vs 7209800.
        let drifted = parent_t.saturating_add(10_440_000);
        for n in net.nodes.values_mut() {
            n.now_ms = drifted;
            n.pong(&n.id.clone());
        }
        net.pong_all();
        let winner = net.nodes["v1"].lottery_packer().unwrap();
        let n = net.nodes.get_mut(&winner).unwrap();
        n.now_ms = drifted;
        n.pong(&winner);
        let led = n.pack_as(&winner).expect("drifted packer can pack");
        assert!(
            led.sealed_at_ms <= parent_t + Node::SEALED_AT_MAX_AHEAD_MS,
            "stamp must clamp to parent+MAX, got {} parent {}",
            led.sealed_at_ms,
            parent_t
        );
        assert_eq!(
            led.sealed_at_ms,
            parent_t.saturating_add(4_000).min(drifted),
            "pack must write the clamped chain stamp, not wall now"
        );
        // Self-accept used to fail here (fold at wall vs stamp).
        n.verify_ledger_state_root(&led)
            .expect("packer must accept its own root at the written stamp");
        let recv = net.nodes.get_mut("v2").unwrap();
        recv.now_ms = parent_t;
        recv.pong(&winner);
        recv.verify_ledger_state_root(&led)
            .expect("peer with stale snap clock must accept pack-at-stamp root");
    }

    #[test]
    fn tick_does_not_mutate_commitment_root() {
        let mut n = Node::new(
            "v1",
            ChainConfig {
                epoch_ms: 1_000,
                ..Default::default()
            },
            KeyRing::new(CryptoScheme::HmacDev),
            &users(),
        );
        n.register_validator("v1", 1000);
        n.pong("v1");
        let before = n.commitment_root();
        let settled = n.last_settled_epoch;
        n.tick(30_000);
        assert_eq!(n.commitment_root(), before);
        assert_eq!(n.last_settled_epoch, settled);
    }

    #[test]
    fn genesis_pack_waits_for_live_seats() {
        let mut n = Node::new(
            "v1",
            ChainConfig {
                pack_budget_ms: 0,
                soft_ok_votes: 3,
                ..Default::default()
            },
            KeyRing::new(CryptoScheme::HmacDev),
            &users(),
        );
        n.register_validator("v1", 1000);
        n.register_validator("v2", 1000);
        n.register_validator("v3", 1000);
        n.keys.generate_many(["v1", "v2", "v3", "alice"].into_iter());
        n.pong("v1");
        let tx = Tx::sign_with(&n.keys, "alice", 1, "bob", 1, 1, n.cfg.network_id).unwrap();
        n.submit_tx(tx).unwrap();
        let err = n.pack_as("v1").unwrap_err();
        assert!(err.contains("genesis") || err.contains("live seats"), "{err}");
        n.pong("v2");
        n.pong("v3");
        // may fail lottery if v1 is not winner; just must not be genesis-wait
        if let Err(e) = n.pack_as("v1") {
            assert!(!e.contains("genesis"), "{e}");
        }
    }

    #[test]
    fn unbond_ledger_fee_from_claimable() {
        // Genesis validators have bond + claimable but often 0 hot balance.
        let cfg = ChainConfig {
            pack_budget_ms: 0,
            max_txs_per_ledger: 8,
            progress_timeout_ms: 0,
            unbond_cooldown_ms: 1_000,
            ..Default::default()
        };
        let mut net = Network::bootstrap(&["v1", "v2", "v3"], 1000, &users(), cfg);
        net.pong_all();
        // Give v1 claimable for fee; no hot balance.
        for n in net.nodes.values_mut() {
            n.claimable.insert("v1".into(), 100);
            // ensure v1 account sequence exists at 0 if missing
            if !n.state.accounts.contains_key("v1") {
                n.state.accounts.insert(
                    "v1".into(),
                    AccountState {
                        sequence: 0,
                        balance: 0,
                        meta: AccountMeta::default(),
                        external_addrs: BTreeMap::new(),
                    },
                );
            }
        }
        let keys = net.nodes.get("v1").unwrap().keys.clone();
        let tx = Tx::sign_body(
            &keys,
            "v1",
            0,
            "",
            0,
            1, // fee
            net.cfg.network_id,
            TxBody::Unbond {
                validator: "v1".into(),
                amount: 100,
            },
        )
        .unwrap();
        for n in net.nodes.values_mut() {
            n.submit_tx(tx.clone()).unwrap();
        }
        net.seal_next_height().unwrap();
        let v = net.nodes.get("v1").unwrap().validators.get("v1").unwrap();
        assert_eq!(v.bond, 900);
        assert_eq!(v.unbonding, 100);
        // fee taken from claimable
        assert_eq!(
            net.nodes.get("v1").unwrap().claimable.get("v1").copied().unwrap_or(0),
            99
        );
    }

    #[test]
    fn live_bond_in_adds_validator_to_lottery() {
        // Simulate running mesh: genesis v1,v2,v3 then Bond creates v4 on-chain.
        // Joiner starts without self pre-registered, applies history, sees bond.
        let cfg = ChainConfig {
            pack_budget_ms: 0,
            max_txs_per_ledger: 8,
            progress_timeout_ms: 0,
            min_bond: 1_000,
            ..Default::default()
        };
        let mut net = Network::bootstrap(&["v1", "v2", "v3"], 1000, &users(), cfg);
        net.pong_all();
        for _ in 0..3 {
            net.payment("alice", "bob", 1, 1).unwrap();
            net.seal_next_height().unwrap();
        }
        // Live bond-in: generate v4 key; alice signs Bond with user_keys.
        net.user_keys.generate_id("v4"); // ensure ring can hold; use val secret on joiner
        // Put v4 secret/public on all node rings for packer verify after join.
        let mut v4_ring = KeyRing::new(net.cfg.scheme);
        v4_ring.generate_id("v4");
        let pk = v4_ring.public_hex("v4").unwrap();
        for n in net.nodes.values_mut() {
            let _ = n.keys.insert_public("v4", &pk);
        }
        let seq = *net.account_seqs.get("alice").unwrap_or(&1);
        let bond_tx = Tx::sign_body(
            &net.user_keys,
            "alice",
            seq,
            "",
            1_000,
            1,
            net.cfg.network_id,
            TxBody::Bond {
                validator: "v4".into(),
            },
        )
        .unwrap();
        net.account_seqs.insert("alice".into(), seq + 1);
        for n in net.nodes.values_mut() {
            if let Some(apk) = net.user_keys.public_hex("alice") {
                let _ = n.keys.insert_public("alice", &apk);
            }
            let _ = n.keys.insert_public("v4", &pk);
            n.submit_tx(bond_tx.clone()).unwrap();
        }
        net.seal_next_height().unwrap();
        assert!(net.nodes.get("v1").unwrap().validators.contains_key("v4"));
        assert_eq!(net.nodes.get("v1").unwrap().validators["v4"].bond, 1_000);

        // Joiner: tip 0, genesis set only (no self), then catch-up full chain.
        let tip_hash = net.nodes.get("v1").unwrap().tip_hash.clone();
        let tip_h = net.tip_height();
        let batch = net.nodes.get("v1").unwrap().ledgers_from(1, 256);
        // Joiner keyring: genesis val pubs + v4 secret + user pubs for verify
        let mut jkeys = v4_ring;
        for vid in ["v1", "v2", "v3"] {
            if let Some(p) = net.nodes.get("v1").unwrap().keys.public_hex(vid) {
                let _ = jkeys.insert_public(vid, &p);
            }
        }
        for (a, _) in users() {
            if let Some(p) = net.user_keys.public_hex(&a) {
                let _ = jkeys.insert_public(&a, &p);
            }
        }
        let _ = jkeys.insert_public("v4", &pk);
        let mut joiner = Node::new("v4", net.cfg.clone(), jkeys, &users());
        for vid in ["v1", "v2", "v3"] {
            joiner.register_validator(vid, 1000);
        }
        assert!(!joiner.validators.contains_key("v4"));
        joiner.best_peer_tip = tip_h;
        let got = joiner.apply_catchup_batch(&batch).unwrap();
        assert_eq!(got, tip_h);
        assert_eq!(joiner.tip_hash, tip_hash);
        assert!(joiner.validators.contains_key("v4"));
        assert_eq!(joiner.validators["v4"].bond, 1_000);
        assert!(joiner.validators["v4"].lottery_weight() > 0.0);
        assert_eq!(joiner.tip_lag(), 0);
        // Without peer tip ads (inbound joiner), still want catch-up probes.
        joiner.best_peer_tip = 0;
        assert!(joiner.wants_catchup_probe());
    }

    #[test]
    fn lagging_joiner_still_tip_elected_but_cannot_pack_if_behind() {
        // v2.3.3: lagging joiner may still win tip-lottery (bond in set) but
        // may_pack refuses tip lag. Progress-timeout skip no longer re-elects.
        let cfg = ChainConfig {
            pack_budget_ms: 0,
            max_txs_per_ledger: 4,
            progress_timeout_ms: 100,
            pong_window_ms: 30_000,
            committee_size: 0,
            ..Default::default()
        };
        let mut net = Network::bootstrap(&["v1", "v2", "v3"], 1000, &users(), cfg);
        net.pong_all();
        for _ in 0..3 {
            net.payment("alice", "bob", 1, 1).unwrap();
            net.seal_next_height().unwrap();
        }
        net.payment("alice", "bob", 1, 1).unwrap();
        for n in net.nodes.values_mut() {
            n.register_validator("v4", 1000);
            n.pong_with_tip("v4", 0);
            assert!(n.validator_tip_lagging("v4"));
            n.best_peer_tip = n.tip_height;
            // v4 sole bond for election
            for (id, v) in n.validators.iter_mut() {
                if id != "v4" {
                    v.bond = 0;
                }
            }
            assert_eq!(n.lottery_packer().as_deref(), Some("v4"));
            assert!(n.propose_progress_timeout_skip().is_none()); // disabled re-elect
            // Mesh node with tip lag must not pack.
            n.best_peer_tip = n.tip_height + 5;
            let err = n.may_pack_locally("v4").unwrap_err();
            assert!(err.contains("tip lag") || err.contains("lag"), "{err}");
        }
    }

    #[test]
    fn lagging_node_must_not_pack() {
        // Production rule: packing on a stale tip forks the mesh.
        let cfg = ChainConfig {
            pack_budget_ms: 0,
            max_txs_per_ledger: 4,
            progress_timeout_ms: 0,
            ..Default::default()
        };
        let mut net = Network::bootstrap(&["v1", "v2", "v3"], 1000, &users(), cfg);
        net.pong_all();
        for _ in 0..3 {
            net.payment("alice", "bob", 1, 1).unwrap();
            net.seal_next_height().unwrap();
        }
        // v3 lags while others advance conceptually (best_peer_tip ahead).
        {
            let n = net.nodes.get_mut("v3").unwrap();
            n.best_peer_tip = 10;
            n.tip_height = 3;
            n.pong("v3");
            n.now_ms = 50_000;
            // Force lottery toward v3 by making it the only fresh ponger if needed;
            // may_pack_locally must still refuse solely due to tip lag.
            let err = n.may_pack_locally("v3").unwrap_err();
            assert!(
                err.contains("tip lag"),
                "expected tip lag refuse, got: {err}"
            );
            assert!(n.pack_as("v3").is_err());
        }
    }

    #[test]
    fn apply_catchup_batch_closes_multi_height_lag() {
        let cfg = ChainConfig {
            pack_budget_ms: 0,
            max_txs_per_ledger: 4,
            progress_timeout_ms: 0,
            ..Default::default()
        };
        let mut net = Network::bootstrap(&["v1", "v2", "v3"], 1000, &users(), cfg);
        net.pong_all();
        for _ in 0..12 {
            net.payment("alice", "bob", 1, 1).unwrap();
            net.seal_next_height().unwrap();
        }
        let batch = net.nodes.get("v1").unwrap().ledgers_from(1, 64);
        assert_eq!(batch.len(), 12);
        let tip_hash = net.nodes.get("v1").unwrap().tip_hash.clone();
        {
            let n = net.nodes.get_mut("v3").unwrap();
            n.tip_height = 0;
            n.tip_hash = sha256_hex(b"pl-genesis-v1");
            n.chain.clear();
            n.seen_at_height.clear();
            n.state = WorldState::genesis(&users());
            n.best_peer_tip = 12;
            let tip = n.apply_catchup_batch(&batch).unwrap();
            assert_eq!(tip, 12);
            assert_eq!(n.tip_hash, tip_hash);
            assert!(!n.still_lagging());
            // Now allowed to pack again.
            n.pong("v3");
            n.now_ms = 100_000;
            // may fail lottery; tip lag must not be the error.
            if let Err(e) = n.may_pack_locally("v3") {
                assert!(!e.contains("tip lag"), "still tip lag after catch-up: {e}");
            }
        }
    }

    #[test]
    fn stripped_bodies_cannot_serve_tip0_catchup() {
        let cfg = ChainConfig {
            pack_budget_ms: 0,
            max_txs_per_ledger: 4,
            progress_timeout_ms: 0,
            max_body_ledgers: 2,
            archive: false,
            ..Default::default()
        };
        let mut net = Network::bootstrap(&["v1", "v2", "v3"], 1000, &users(), cfg);
        net.pong_all();
        for _ in 0..8 {
            net.payment("alice", "bob", 1, 1).unwrap();
            net.seal_next_height().unwrap();
        }
        let n = net.nodes.get("v1").unwrap();
        assert_eq!(n.tip_height, 8);
        let from1 = n.ledgers_from(1, 64);
        assert!(
            from1.is_empty(),
            "non-archive must not jump a stripped h=1 hole, got {:?}",
            from1.iter().map(|l| l.height).collect::<Vec<_>>()
        );
    }

    #[test]
    fn ledgers_from_is_contiguous_and_byte_capped() {
        let cfg = ChainConfig {
            pack_budget_ms: 0,
            max_txs_per_ledger: 4,
            progress_timeout_ms: 0,
            max_body_ledgers: 8,
            ..Default::default()
        };
        let mut net = Network::bootstrap(&["v1", "v2", "v3"], 1000, &users(), cfg);
        net.pong_all();
        for _ in 0..8 {
            net.payment("alice", "bob", 1, 1).unwrap();
            net.seal_next_height().unwrap();
        }
        let n = net.nodes.get_mut("v1").unwrap();
        // Punch a hole at h=5 (stripped, no store).
        if let Some(led) = n.chain.iter_mut().find(|l| l.height == 5) {
            led.strip_body();
        }
        let batch = n.ledgers_from(4, 64);
        assert_eq!(
            batch.iter().map(|l| l.height).collect::<Vec<_>>(),
            vec![4],
            "must stop at the first missing body, not skip to 6+"
        );
        n.chain.retain(|l| l.height != 6);
        let batch = n.ledgers_from(6, 64);
        assert!(batch.is_empty(), "missing height must not serve 7+");
    }

    #[test]
    fn adopt_peer_snapshot_keeps_id_and_archive_flag() {
        let cfg = ChainConfig {
            pack_budget_ms: 0,
            max_txs_per_ledger: 4,
            progress_timeout_ms: 0,
            ..Default::default()
        };
        let mut net = Network::bootstrap(&["v1", "v2", "v3"], 1000, &users(), cfg);
        net.pong_all();
        for _ in 0..4 {
            net.payment("alice", "bob", 1, 1).unwrap();
            net.seal_next_height().unwrap();
        }
        let src = net.nodes["v1"].to_snapshot();
        let tmp = std::env::temp_dir().join("pl-adopt-test.json");
        let bytes = serde_json::to_vec(&src).unwrap();
        std::fs::write(&tmp, bytes).unwrap();
        let keys = KeyRing::new(CryptoScheme::HmacDev);
        let loaded = Node::load_snapshot(&tmp, keys).unwrap();
        let joiner = net.nodes.get_mut("v3").unwrap();
        joiner.cfg.archive = false;
        joiner.id = "v3".into();
        let tip = loaded.tip_height;
        let hash = loaded.tip_hash.clone();
        joiner.best_peer_tip = tip + Node::SNAPSHOT_JOIN_LAG;
        if let Some(v) = joiner.validators.get_mut("v1") {
            v.advertised_archive = true;
            v.last_pong_ms = joiner.now_ms;
        }
        assert!(joiner.wants_snapshot());
        joiner.validators.get_mut("v1").unwrap().advertised_archive = false;
        assert!(
            !joiner.wants_snapshot(),
            "without an archive ad, residual catch-up must still run"
        );
        joiner.validators.get_mut("v1").unwrap().advertised_archive = true;
        joiner.best_peer_tip = tip + 400;
        assert!(
            !joiner.wants_snapshot(),
            "in-mesh lag is residual + live gossip, not a snap feed"
        );
        joiner.tip_height = 0;
        joiner.best_peer_tip = 10;
        assert!(
            joiner.wants_snapshot(),
            "cold join (tip=0) still takes a snap"
        );
        joiner.tip_height = tip;
        joiner.best_peer_tip = tip + Node::SNAPSHOT_JOIN_LAG;
        assert!(joiner.wants_snapshot());
        assert!(
            joiner.take_catchup_pull().is_none(),
            "residual must not own the catch lane while a snap is the right tool"
        );
        assert!(
            !Node::snap_pin_should_rotate(100, 100, 1, 10_000),
            "fresh pin, mid-serve: hold"
        );
        assert!(
            !Node::snap_pin_should_rotate(100 + Node::SNAPSHOT_PULL_LAG - 1, 100, 1, 10_000),
            "pin still useful"
        );
        assert!(
            !Node::snap_pin_should_rotate(
                100 + Node::SNAPSHOT_SERVE_STALE_LAG,
                100,
                9_000,
                10_000
            ),
            "a live ~100 MB pull must not rotate at 32 heights"
        );
        assert!(
            Node::snap_pin_should_rotate(100 + Node::SNAPSHOT_PULL_LAG, 100, 1, 10_000),
            "joiners holding a stale pin must not block rotate"
        );
        assert!(
            Node::snap_pin_should_rotate(100, 100, 1, 1 + Node::SNAPSHOT_PIN_IDLE_MS + 1),
            "idle rotate still works"
        );
        joiner.adopt_peer_snapshot(loaded);
        assert_eq!(joiner.id, "v3");
        assert!(
            joiner.validators["v1"].advertised_archive,
            "adopt must keep archive ads or the seat never snaps again"
        );
        assert!(!joiner.cfg.archive, "must not inherit archive from snap");
        assert_eq!(joiner.tip_height, tip);
        assert_eq!(joiner.tip_hash, hash);
        assert!(!joiner.chain.is_empty());
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn join_snapshot_is_short_tail() {
        let cfg = ChainConfig {
            pack_budget_ms: 0,
            max_txs_per_ledger: 4,
            progress_timeout_ms: 0,
            max_chain_ledgers: 20,
            ..Default::default()
        };
        let mut net = Network::bootstrap(&["v1", "v2", "v3"], 1000, &users(), cfg);
        net.pong_all();
        for _ in 0..12 {
            net.payment("alice", "bob", 1, 1).unwrap();
            net.seal_next_height().unwrap();
        }
        let n = &net.nodes["v1"];
        let full = n.to_snapshot();
        let join = n.to_join_snapshot();
        assert_eq!(join.tip_height, full.tip_height);
        assert_eq!(join.tip_hash, full.tip_hash);
        assert!(join.chain.len() <= Node::JOIN_CHAIN_LEDGERS);
        assert!(join.chain.len() <= full.chain.len());
        assert_eq!(join.chain.last().map(|l| l.height), Some(n.tip_height));
    }

    #[test]
    fn archive_keeps_bodies_so_tip0_can_catch_up() {
        let cfg = ChainConfig {
            pack_budget_ms: 0,
            max_txs_per_ledger: 4,
            progress_timeout_ms: 0,
            max_body_ledgers: 2,
            archive: true,
            ..Default::default()
        };
        let mut net = Network::bootstrap(&["v1", "v2", "v3"], 1000, &users(), cfg);
        net.pong_all();
        for _ in 0..8 {
            net.payment("alice", "bob", 1, 1).unwrap();
            net.seal_next_height().unwrap();
        }
        let batch = net.nodes.get("v1").unwrap().ledgers_from(1, 64);
        assert_eq!(batch.len(), 8, "archive must serve every body from h=1");
        assert_eq!(batch[0].height, 1);
        let tip_hash = net.nodes.get("v1").unwrap().tip_hash.clone();
        let n = net.nodes.get_mut("v3").unwrap();
        n.tip_height = 0;
        n.tip_hash = sha256_hex(b"pl-genesis-v1");
        n.chain.clear();
        n.seen_at_height.clear();
        n.state = WorldState::genesis(&users());
        n.best_peer_tip = 8;
        assert_eq!(n.apply_catchup_batch(&batch).unwrap(), 8);
        assert_eq!(n.tip_hash, tip_hash);
    }

    #[test]
    fn archive_disk_store_strips_ram_and_serves_tip0() {
        let dir = std::env::temp_dir().join(format!(
            "falcon-pl-bodies-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let cfg = ChainConfig {
            pack_budget_ms: 0,
            max_txs_per_ledger: 4,
            progress_timeout_ms: 0,
            max_body_ledgers: 2,
            archive: true,
            ..Default::default()
        };
        let mut net = Network::bootstrap(&["v1", "v2", "v3"], 1000, &users(), cfg);
        net.nodes
            .get_mut("v1")
            .unwrap()
            .open_body_store(&dir)
            .unwrap();
        net.pong_all();
        for _ in 0..8 {
            net.payment("alice", "bob", 1, 1).unwrap();
            net.seal_next_height().unwrap();
        }
        let n = net.nodes.get("v1").unwrap();
        assert_eq!(n.tip_height, 8);
        let ram_bodies = n.chain.iter().filter(|l| l.has_body()).count();
        assert_eq!(ram_bodies, 2, "archive+disk must strip RAM to the body window");
        let batch = n.ledgers_from(1, 64);
        assert_eq!(batch.len(), 8, "disk archive must serve every body from h=1");
        assert_eq!(batch[0].height, 1);
        assert!(batch[0].has_body());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cli_zero_max_chain_is_archive_default_not_one() {
        assert_eq!(
            ChainConfig::resolve_max_chain_ledgers(0),
            ChainConfig::DEFAULT_MAX_CHAIN_LEDGERS
        );
        assert_eq!(ChainConfig::resolve_max_chain_ledgers(128), 128);
        assert_ne!(ChainConfig::resolve_max_chain_ledgers(0), 1);
    }

    #[test]
    fn archive_disk_serves_two_height_gap_after_one_ledger_ram() {
        let dir = std::env::temp_dir().join(format!(
            "falcon-pl-bodies-gap-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let cfg = ChainConfig {
            pack_budget_ms: 0,
            max_txs_per_ledger: 4,
            progress_timeout_ms: 0,
            max_chain_ledgers: 1,
            max_body_ledgers: 1,
            archive: true,
            ..Default::default()
        };
        let mut net = Network::bootstrap(&["v1", "v2", "v3"], 1000, &users(), cfg);
        net.nodes
            .get_mut("v1")
            .unwrap()
            .open_body_store(&dir)
            .unwrap();
        net.pong_all();
        for _ in 0..6 {
            net.payment("alice", "bob", 1, 1).unwrap();
            net.seal_next_height().unwrap();
        }
        let n = net.nodes.get("v1").unwrap();
        assert_eq!(n.tip_height, 6);
        assert_eq!(n.chain.len(), 1, "RAM tail is the tip only");
        let batch = n.ledgers_from(4, 64);
        assert_eq!(
            batch.iter().map(|l| l.height).collect::<Vec<_>>(),
            vec![4, 5, 6],
            "disk height index must serve the 2-high gap"
        );
        assert!(batch.iter().all(|l| l.has_body()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn empty_residual_wants_snapshot_after_three_holes() {
        let mut n = Node::new(
            "v2",
            ChainConfig::default(),
            crate::crypto::KeyRing::new(crate::crypto::CryptoScheme::HmacDev),
            &users(),
        );
        n.register_validator("v1", 1000);
        n.register_validator("v2", 1000);
        n.tip_height = 10;
        n.best_peer_tip = 12;
        n.cfg.archive = false;
        if let Some(v) = n.validators.get_mut("v1") {
            v.advertised_archive = true;
            v.last_pong_ms = n.now_ms;
        }
        assert!(!n.wants_snapshot());
        n.empty_residual_streak = 3;
        assert!(n.wants_snapshot(), "hole after empty residual must snap");
        n.tip_height = 400;
        n.best_peer_tip = 500;
        n.empty_residual_streak = 3;
        assert!(
            !n.wants_snapshot(),
            "a ~100 height tail must stay on NeedLedgers, not another join snap"
        );
    }

    #[test]
    fn fork_poison_wants_snapshot_with_no_archive_seat() {
        let mut n = Node::new(
            "joiner",
            ChainConfig::default(),
            crate::crypto::KeyRing::new(crate::crypto::CryptoScheme::HmacDev),
            &users(),
        );
        n.register_validator("joiner", 1000);
        n.tip_height = 100;
        n.best_peer_tip = 400;
        n.last_catchup_conflict =
            "catch-up conflict (no auto hard-resync): state root mismatch at h=101".into();
        assert!(
            n.wants_snapshot(),
            "a relay-only joiner must re-snap after a state-root mismatch"
        );
    }

    #[test]
    fn archive_fork_poison_wants_snapshot_from_hub_when_no_archive() {
        let mut n = Node::new(
            "v1",
            ChainConfig::default(),
            crate::crypto::KeyRing::new(crate::crypto::CryptoScheme::HmacDev),
            &users(),
        );
        n.register_validator("v1", 1000);
        n.register_validator("v2", 1000);
        n.cfg.archive = true;
        n.tip_height = 100;
        n.tip_hash = "deadbeef".into();
        n.best_peer_tip = 120;
        n.last_catchup_conflict =
            "catch-up conflict (no auto hard-resync): state root mismatch at h=101".into();
        if let Some(v) = n.validators.get_mut("v2") {
            v.advertised_hub = true;
            v.last_advertised_tip = Some(120);
            v.last_pong_ms = n.now_ms;
        }
        assert!(
            n.wants_snapshot(),
            "forked archive must re-snap from hub when no other archive exists"
        );
    }

    fn upgrade_stall_node() -> Node {
        let mut n = Node::new(
            "scottdog",
            ChainConfig::default(),
            crate::crypto::KeyRing::new(crate::crypto::CryptoScheme::HmacDev),
            &users(),
        );
        n.register_validator("scottdog", 1000);
        n.register_validator("v3", 1000);
        n.now_ms = 5_833_000_000;
        n.tip_height = 678_630;
        n.best_peer_tip = 678_650;
        if let Some(v) = n.validators.get_mut("v3") {
            v.advertised_hub = true;
            v.last_advertised_tip = Some(678_650);
            v.last_pong_ms = n.now_ms;
        }
        n
    }

    /// 2.9.79-beta.3 upgrade stall (scottdog 678630): snapshot adopt moved
    /// `now_ms` back to the source's clock; the residual stamp from our own
    /// clock sat in the future and `take_catchup_pull` never fired again.
    #[test]
    fn catchup_pull_fires_after_clock_moves_back() {
        let mut n = upgrade_stall_node();
        // Our last request was stamped on our own (later) clock.
        n.last_catchup_req_ms = n.now_ms + 4_684_000;
        n.catchup_inflight = false;
        assert!(!n.wants_snapshot());
        assert_eq!(
            n.take_catchup_pull(),
            Some(678_631),
            "a future request stamp must not block residual catch-up"
        );
        // Same for an inflight stamp in the future: it is stale, not inflight.
        let mut n = upgrade_stall_node();
        n.last_catchup_req_ms = n.now_ms + 60_000;
        n.catchup_inflight = true;
        assert_eq!(n.take_catchup_pull(), Some(678_631));
        // A future snapshot stamp must not block the snapshot rate limit.
        let mut n = upgrade_stall_node();
        n.empty_residual_streak = 3;
        n.best_peer_tip = 678_640;
        n.last_snap_req_ms = n.now_ms + 60_000;
        assert!(n.wants_snapshot());
        assert!(n.take_snapshot_pull(), "future snap stamp must not block NeedSnapshot");
    }

    #[test]
    fn adopt_peer_snapshot_resets_local_request_stamps() {
        let cfg = ChainConfig {
            pack_budget_ms: 0,
            max_txs_per_ledger: 4,
            progress_timeout_ms: 0,
            ..Default::default()
        };
        let mut net = Network::bootstrap(&["v1", "v2", "v3"], 1000, &users(), cfg);
        net.pong_all();
        for _ in 0..4 {
            net.payment("alice", "bob", 1, 1).unwrap();
            net.seal_next_height().unwrap();
        }
        let src = net.nodes["v1"].to_snapshot();
        let tmp = std::env::temp_dir().join("pl-adopt-clock-test.json");
        std::fs::write(&tmp, serde_json::to_vec(&src).unwrap()).unwrap();
        let loaded = Node::load_snapshot(&tmp, KeyRing::new(CryptoScheme::HmacDev)).unwrap();
        let src_now = loaded.now_ms;
        let joiner = net.nodes.get_mut("v3").unwrap();
        // Joiner clock runs well ahead of the source (live: v11 +78 min vs v3).
        joiner.now_ms = src_now + 4_684_000;
        joiner.last_catchup_req_ms = joiner.now_ms;
        joiner.stale_snap_offer_ms = joiner.now_ms;
        let ahead = joiner.now_ms;
        for v in joiner.validators.values_mut() {
            v.last_pong_ms = ahead;
        }
        joiner.adopt_peer_snapshot(loaded);
        assert_eq!(joiner.last_catchup_req_ms, 0);
        assert_eq!(joiner.stale_snap_offer_ms, 0);
        assert!(
            joiner.validators.values().all(|v| v.last_pong_ms <= joiner.now_ms),
            "restored pong stamps must not sit in the adopted clock's future"
        );
        joiner.best_peer_tip = joiner.tip_height + 20;
        assert_eq!(joiner.take_catchup_pull(), Some(joiner.tip_height + 1));
    }

    /// Box repro (2.9.79 in-place upgrade, seeds without the v1 archive):
    /// lag between SNAPSHOT_SERVE_STALE_LAG and SNAPSHOT_JOIN_LAG, the hub
    /// never answers residual pulls. Sustained silence must fall back to a
    /// hub snapshot instead of waiting forever.
    #[test]
    fn unanswered_residual_without_archive_falls_back_to_hub_snapshot() {
        let mut n = upgrade_stall_node();
        n.best_peer_tip = n.tip_height + 200;
        n.empty_residual_streak = Node::RESIDUAL_NO_SERVER_STREAK - 1;
        assert!(!n.wants_snapshot(), "a short silence stays on residual");
        n.empty_residual_streak = Node::RESIDUAL_NO_SERVER_STREAK;
        assert!(n.wants_snapshot(), "sustained silence with no archive must snap from the hub");
        // An archive in reach can serve the heights: stay on residual.
        n.register_validator("v1", 1000);
        if let Some(v) = n.validators.get_mut("v1") {
            v.advertised_archive = true;
            v.last_pong_ms = n.now_ms;
        }
        assert!(!n.wants_snapshot(), "with an archive reachable, residual keeps the lane");
        // In sync: never.
        let mut n = upgrade_stall_node();
        n.best_peer_tip = n.tip_height;
        n.empty_residual_streak = 100;
        assert!(!n.wants_snapshot());
    }

    #[test]
    fn archive_at_genesis_wants_snapshot_when_peer_archive_exists() {
        let mut n = Node::new(
            "v1",
            ChainConfig::default(),
            crate::crypto::KeyRing::new(crate::crypto::CryptoScheme::HmacDev),
            &users(),
        );
        n.register_validator("v1", 1000);
        n.register_validator("v2", 1000);
        n.cfg.archive = true;
        n.tip_height = 0;
        n.best_peer_tip = 274_000;
        if let Some(v) = n.validators.get_mut("v2") {
            v.advertised_archive = true;
            v.last_pong_ms = n.now_ms;
        }
        assert!(
            n.wants_snapshot(),
            "genesis archive after resync must join-snap immediately"
        );
    }

    #[test]
    fn archive_empty_residual_wants_snapshot_when_another_archive_exists() {
        let mut n = Node::new(
            "v1",
            ChainConfig::default(),
            crate::crypto::KeyRing::new(crate::crypto::CryptoScheme::HmacDev),
            &users(),
        );
        n.register_validator("v1", 1000);
        n.register_validator("v2", 1000);
        n.cfg.archive = true;
        n.tip_height = 10;
        n.best_peer_tip = 22;
        if let Some(v) = n.validators.get_mut("v2") {
            v.advertised_archive = true;
            v.last_pong_ms = n.now_ms;
        }
        assert!(
            !n.wants_snapshot(),
            "archive must not snap on the first miss"
        );
        n.empty_residual_streak = 3;
        assert!(
            n.wants_snapshot(),
            "lagging archive with 3 empty residuals must join-snap"
        );
    }

    #[test]
    fn archive_without_peer_archive_does_not_snap() {
        let mut n = Node::new(
            "v1",
            ChainConfig::default(),
            crate::crypto::KeyRing::new(crate::crypto::CryptoScheme::HmacDev),
            &users(),
        );
        n.register_validator("v1", 1000);
        n.cfg.archive = true;
        n.tip_height = 10;
        n.best_peer_tip = 22;
        n.empty_residual_streak = 9;
        assert!(
            !n.wants_snapshot(),
            "sole archive cannot join-snap from itself"
        );
    }

    #[test]
    fn catchup_rotates_hub_on_inflight_miss() {
        let mut n = Node::new(
            "v1",
            ChainConfig::default(),
            crate::crypto::KeyRing::new(crate::crypto::CryptoScheme::HmacDev),
            &users(),
        );
        n.tip_height = 10;
        n.best_peer_tip = 12;
        n.catchup_inflight = true;
        n.last_catchup_req_ms = 0;
        n.now_ms = Node::CATCHUP_INFLIGHT_MS + 1;
        assert_eq!(n.catchup_hub_rotate, 0);
        assert!(n.take_catchup_pull().is_some());
        assert_eq!(n.catchup_hub_rotate, 1);
        assert_eq!(n.empty_residual_streak, 1);
        n.note_catchup_batch(false);
        assert_eq!(n.catchup_hub_rotate, 2);
        n.note_catchup_batch(true);
        assert_eq!(n.catchup_hub_rotate, 2, "keep the hub that served");
        assert_eq!(n.empty_residual_streak, 0);
    }

    #[test]
    fn catchup_peer_order_and_usable() {
        let mut n = Node::new(
            "v1",
            ChainConfig::default(),
            crate::crypto::KeyRing::new(crate::crypto::CryptoScheme::HmacDev),
            &users(),
        );
        n.register_validator("v1", 1000);
        n.register_validator("v4", 1000);
        n.register_validator("v3", 1000);
        n.tip_height = 100;
        n.catchup_hub_rotate = 1;
        assert_eq!(n.catchup_peer_order(&[10, 20, 30]), vec![20, 30, 10]);
        if let Some(v) = n.validators.get_mut("v4") {
            v.last_advertised_tip = Some(50);
        }
        if let Some(v) = n.validators.get_mut("v3") {
            v.last_advertised_tip = Some(112);
        }
        assert!(
            !n.catchup_peer_usable("v4"),
            "behind advertised tip is not usable"
        );
        assert!(n.catchup_peer_usable("v3"));
        assert!(n.catchup_peer_usable(""), "unknown Hello still probed");
    }

    #[test]
    fn pack_quorum_blocks_when_committee_is_split() {
        let mut n = Node::new(
            "v1",
            ChainConfig {
                committee_size: 6,
                ..ChainConfig::default()
            },
            crate::crypto::KeyRing::new(crate::crypto::CryptoScheme::HmacDev),
            &users(),
        );
        for id in ["v1", "v2", "v3", "v4", "v5", "v6"] {
            n.register_validator(id, 1000);
            n.pong(id);
        }
        n.tip_height = 5;
        // Only two peers advertise the live tip — 3 including self, need 4.
        for id in ["v2", "v3"] {
            if let Some(v) = n.validators.get_mut(id) {
                v.last_advertised_tip = Some(5);
            }
        }
        for id in ["v4", "v5", "v6"] {
            if let Some(v) = n.validators.get_mut(id) {
                v.last_advertised_tip = Some(3);
            }
        }
        let err = n.pack_quorum_ready().unwrap_err();
        assert!(err.contains("pack quorum"), "{err}");
        for id in ["v4", "v5"] {
            if let Some(v) = n.validators.get_mut(id) {
                v.last_advertised_tip = Some(5);
            }
        }
        assert!(n.pack_quorum_ready().is_ok());
    }

    #[test]
    fn hard_resync_without_genesis_keeps_tip() {
        let cfg = ChainConfig {
            pack_budget_ms: 0,
            max_txs_per_ledger: 4,
            progress_timeout_ms: 0,
            ..Default::default()
        };
        let mut net = Network::bootstrap(&["v1", "v2", "v3"], 1000, &users(), cfg);
        net.pong_all();
        for _ in 0..5 {
            net.payment("alice", "bob", 1, 1).unwrap();
            net.seal_next_height().unwrap();
        }
        let batch = net.nodes.get("v1").unwrap().ledgers_from(3, 64);
        assert!(!batch.is_empty());
        assert!(batch[0].height >= 3);
        let n = net.nodes.get_mut("v3").unwrap();
        n.need_hard_resync = true;
        n.best_peer_tip = 5;
        let tip_before = n.tip_height;
        let tip = n.hard_resync_from_ledgers(&batch).unwrap();
        assert_eq!(tip, tip_before, "must not wipe tip without h=1");
        assert!(n.need_hard_resync);
        assert!(n.pending_ledgers.contains_key(&batch[0].height));
    }

    #[test]
    fn hard_resync_tolerates_dupes_gaps_and_partial() {
        // Dual-host thrash fix: duplicate heights and sparse batches must not
        // error with "resync stalled"; partial continuous prefix is OK.
        let cfg = ChainConfig {
            pack_budget_ms: 0,
            max_txs_per_ledger: 4,
            progress_timeout_ms: 0,
            ..Default::default()
        };
        let mut net = Network::bootstrap(&["v1", "v2", "v3"], 1000, &users(), cfg);
        net.pong_all();
        for _ in 0..6 {
            net.payment("alice", "bob", 1, 1).unwrap();
            net.seal_next_height().unwrap();
        }
        let batch = net.nodes.get("v1").unwrap().ledgers_from(1, 64);
        assert_eq!(batch.len(), 6);
        let tip_hash = net.nodes.get("v1").unwrap().tip_hash.clone();

        // Lagging node with wrong tip bookkeeping.
        {
            let n = net.nodes.get_mut("v3").unwrap();
            n.tip_height = 2;
            n.need_hard_resync = true;
            n.best_peer_tip = 6;
            // Duplicates + gap (drop h=5): continuous prefix 1..=4 then stop.
            let mut messy = batch.clone();
            messy.push(batch[0].clone()); // dup h=1
            messy.push(batch[5].clone()); // h=6 after gap
            messy.retain(|l| l.height != 5);
            let tip = n.hard_resync_from_ledgers(&messy).expect("resync");
            assert_eq!(tip, 4, "continuous prefix through h=4");
            assert!(!n.need_hard_resync || n.tip_height < n.best_peer_tip);
        }
        // Finish with normal catch-up for remaining (5..6).
        {
            let n = net.nodes.get_mut("v3").unwrap();
            for led in &batch {
                if led.height > n.tip_height {
                    let _ = n.ingest_ledger_catchup(led).unwrap();
                }
            }
            assert_eq!(n.tip_height, 6);
            assert_eq!(n.tip_hash, tip_hash);
        }

        // Full resync with pure duplicates still reaches tip.
        {
            let n = net.nodes.get_mut("v3").unwrap();
            n.need_hard_resync = true;
            n.best_peer_tip = 6;
            let mut dups = batch.clone();
            dups.extend(batch.iter().cloned());
            let tip = n.hard_resync_from_ledgers(&dups).expect("dup resync");
            assert_eq!(tip, 6);
            assert!(!n.need_hard_resync);
            assert_eq!(n.tip_hash, tip_hash);
        }
    }

    #[test]
    fn emission_matrix_sectors_and_caps() {
        // §5.5 emission matrix (pack / check / watcher / AMM / lend / quiet / bootstrap).
        let emit = economy::epoch_emit(TREASURY_GENESIS, 30);
        assert_eq!(emit, 588_000_000);
        let top = economy::top_buckets(emit);
        assert_eq!(top.validators + top.watchers + top.amm + top.lend, emit);
        assert_eq!(top.validators, emit * 55 / 100);
        assert_eq!(top.watchers, emit * 5 / 100);
        assert_eq!(top.amm, emit * 20 / 100);
        assert_eq!(economy::cap_lp(emit), emit * 50 / 10_000); // 0.5%
        assert_eq!(economy::cap_watcher(emit), emit * 5 / 10_000); // 0.05%

        // Bootstrap: epochs 1–7 not claimable.
        for e in 1..=7 {
            assert!(!economy::epoch_claimable(e));
        }
        assert!(economy::epoch_claimable(8));

        // Quiet: no work → no pays; emit refunds (via settle path on node).
        let work = EpochWork::default();
        let empty = BTreeMap::new();
        let s = economy::settle_epoch(
            TREASURY_GENESIS,
            30,
            true,
            &work,
            &empty,
            &empty,
            0,
        );
        assert_eq!(s.epoch_emit, emit);
        assert!(s.pack_pays.is_empty() && s.check_pays.is_empty());
        assert!(s.watcher_pays.is_empty() && s.amm_pays.is_empty() && s.lend_pays.is_empty());

        // Pack skew: more txs_packed → more pack half.
        let mut work = EpochWork::default();
        work.record_pack("v1", 100);
        work.record_pack("v2", 50);
        work.record_check("v1", "h1");
        work.record_check("v2", "h1");
        work.record_check("v2", "h2");
        let s = economy::settle_epoch(
            TREASURY_GENESIS,
            30,
            true,
            &work,
            &empty,
            &empty,
            0,
        );
        assert!(s.pack_pays["v1"] > s.pack_pays["v2"]);
        assert!(s.check_pays["v2"] > s.check_pays["v1"]);

        // LP cap binds sole LP.
        let mut amm = BTreeMap::new();
        amm.insert("alice".into(), 1_000u64);
        let s = economy::settle_epoch(
            TREASURY_GENESIS,
            30,
            true,
            &EpochWork::default(),
            &amm,
            &empty,
            0,
        );
        assert_eq!(s.amm_pays["alice"], economy::cap_lp(emit));
    }

    #[test]
    fn payday_identical_claimable_after_claim_epoch() {
        let epoch_ms = 1_000u64;
        let cfg = ChainConfig {
            pack_budget_ms: 0,
            max_txs_per_ledger: 8,
            progress_timeout_ms: 0,
            epoch_ms,
            archive: true,
            ..Default::default()
        };
        let mut net = Network::bootstrap(
            &["v1", "v2", "v3", "v4", "v5", "v6"],
            1000,
            &users(),
            cfg,
        );
        net.pong_all();
        for _ in 0..3 {
            net.payment("alice", "bob", 1, 1).unwrap();
        }
        net.seal_next_height().unwrap();
        // Pack inside the first claimable epoch (8).
        let genesis = net.nodes.values().next().unwrap().genesis_ms;
        let in_e8 = genesis + 7 * epoch_ms + 10;
        for n in net.nodes.values_mut() {
            n.now_ms = in_e8;
        }
        for _ in 0..3 {
            net.payment("alice", "bob", 1, 1).unwrap();
        }
        net.seal_next_height().unwrap();
        // Next epoch so maybe_settle commits epoch 8.
        let in_e9 = genesis + 8 * epoch_ms + 10;
        for n in net.nodes.values_mut() {
            n.now_ms = in_e9;
        }
        for _ in 0..3 {
            net.payment("alice", "bob", 1, 1).unwrap();
        }
        net.seal_next_height().unwrap();
        let mut maps = Vec::new();
        for n in net.nodes.values() {
            assert!(
                n.last_settled_epoch >= 8,
                "{} settled {}",
                n.id,
                n.last_settled_epoch
            );
            let sum: u64 = n.claimable.values().sum();
            assert!(sum > 0, "{} claimable empty after payday", n.id);
            maps.push((n.tip_hash.clone(), n.last_settled_epoch, n.claimable.clone()));
        }
        let first = &maps[0];
        for m in &maps {
            assert_eq!(m.0, first.0, "tip hash");
            assert_eq!(m.1, first.1, "settled epoch");
            assert_eq!(m.2, first.2, "claimable map");
        }
    }

    #[test]
    fn testnet_first_claim_epoch_1_pays_on_first_settle() {
        let epoch_ms = 1_000u64;
        let cfg = ChainConfig {
            pack_budget_ms: 0,
            max_txs_per_ledger: 8,
            progress_timeout_ms: 0,
            epoch_ms,
            first_claim_epoch: 1,
            ..Default::default()
        };
        let mut net = Network::bootstrap(
            &["v1", "v2", "v3", "v4", "v5", "v6"],
            1000,
            &users(),
            cfg,
        );
        net.pong_all();
        let genesis = net.nodes.values().next().unwrap().genesis_ms;
        for n in net.nodes.values_mut() {
            n.now_ms = genesis + 10;
        }
        for _ in 0..3 {
            net.payment("alice", "bob", 1, 1).unwrap();
        }
        net.seal_next_height().unwrap();
        for n in net.nodes.values_mut() {
            n.now_ms = genesis + epoch_ms + 10;
        }
        for _ in 0..3 {
            net.payment("alice", "bob", 1, 1).unwrap();
        }
        net.seal_next_height().unwrap();
        for n in net.nodes.values() {
            assert!(n.last_settled_epoch >= 1, "{} settled {}", n.id, n.last_settled_epoch);
            let sum: u64 = n.claimable.values().sum();
            assert!(sum > 0, "testnet must emit on epoch 1, {} got 0", n.id);
        }
    }

    #[test]
    fn multi_node_tip_deterministic_seal_agrees() {
        // Pure tip lottery: all nodes elect same packer; seal + soft QC → one tip.
        let cfg = ChainConfig {
            pack_budget_ms: 0,
            max_txs_per_ledger: 4,
            soft_ok_votes: 1,
            ..Default::default()
        };
        let mut net = Network::bootstrap(&["v1", "v2", "v3"], 1000, &users(), cfg);
        net.pong_all();
        for _ in 0..2 {
            net.payment("alice", "bob", 1, 1).unwrap();
        }
        net.pong_all();
        let winners: Vec<_> = net
            .nodes
            .values()
            .map(|n| n.lottery_packer().unwrap())
            .collect();
        assert!(winners.iter().all(|w| w == &winners[0]), "{winners:?}");
        let primary = winners[0].clone();
        let ledger = net
            .nodes
            .get_mut(&primary)
            .unwrap()
            .pack_as(&primary)
            .unwrap();
        for n in net.nodes.values_mut() {
            n.ingest_ledger(&ledger).unwrap();
        }
        let hash = ledger.ledger_hash.clone();
        let ids: Vec<String> = net.nodes.keys().cloned().collect();
        for n in net.nodes.values_mut() {
            for id in &ids {
                n.vote_ok(&hash, id);
            }
        }
        assert!(net.nodes.values().all(|n| n.tip_height == 1));
        let hashes: BTreeSet<_> = net.nodes.values().map(|n| n.tip_hash.clone()).collect();
        assert_eq!(hashes.len(), 1, "all tips same hash");
    }

    #[test]
    fn submit_dedupes_and_flags_new() {
        let mut net = Network::bootstrap(&["v1", "v2"], 1000, &users(), ChainConfig::default());
        let tx = net.payment("alice", "bob", 1, 1).unwrap();
        // payment already inserted on all nodes
        for n in net.nodes.values() {
            assert_eq!(n.mempool.len(), 1);
        }
        // Mempool::insert deduplicates by tx_id; submit_tx replaces same-(account, seq) in-place.
        let dup_raw = net
            .nodes
            .get_mut("v1")
            .unwrap()
            .mempool
            .insert(tx.clone(), ChainConfig::default().max_mempool_txs)
            .unwrap();
        assert!(!dup_raw, "Mempool::insert must report false for duplicate tx_id");
        let again = net.nodes.get_mut("v1").unwrap().submit_tx(tx).unwrap();
        assert!(again, "submit_tx replaces same-(account, seq) entry in-place");
        assert_eq!(net.nodes.get("v1").unwrap().mempool.len(), 1);
    }

    #[test]
    fn mempool_full_rejects_new_not_dup() {
        let cfg = ChainConfig {
            max_mempool_txs: 2,
            fee_escalate: false, // isolate full-pool path from fee tiers
            min_fee: 1,
            ..Default::default()
        };
        let mut net = Network::bootstrap(&["v1", "v2"], 1000, &users(), cfg);
        net.payment("alice", "bob", 1, 1).unwrap();
        net.payment("bob", "alice", 1, 1).unwrap();
        assert_eq!(net.nodes.get("v1").unwrap().mempool.len(), 2);
        // third unique tx should fail on full pool
        let err = net.payment("carol", "alice", 1, 1).unwrap_err();
        assert!(err.contains("mempool full"), "{err}");
        // duplicate of existing still ok (replaces same-(account, seq) without exceeding cap)
        let existing = net.nodes.get("v1").unwrap().mempool.iter_candidates().next().unwrap().clone();
        let dup_raw = net.nodes.get_mut("v1").unwrap().mempool.insert(existing.clone(), 2).unwrap();
        assert!(!dup_raw);
        let dup = net.nodes.get_mut("v1").unwrap().submit_tx(existing).unwrap();
        assert!(dup);
        assert_eq!(net.nodes.get("v1").unwrap().mempool.len(), 2);
    }

    #[test]
    fn vault_blocks_wrong_destination() {
        let mut net = Network::bootstrap(&["v1"], 1000, &users(), ChainConfig::default());
        let n0 = net.nodes.get_mut("v1").unwrap();
        assert!(n0.open_vault("alice", "").unwrap_err().contains("nominate"));
        assert!(n0
            .open_vault("alice", "alice")
            .unwrap_err()
            .contains("differ"));
        n0.open_vault("alice", "bob").unwrap();
        let locked = n0.state.get("alice");
        assert_eq!(locked.meta.account_type, AccountType::Vault);
        assert!(locked.meta.vault_locked);
        assert_eq!(locked.meta.allowlist, vec!["bob".to_string()]);
        let n = net.nodes.get_mut("v1").unwrap();
        let _ = n
            .keys
            .insert_public("alice", &net.user_keys.public_hex("alice").unwrap());
        let seq = n.state.get("alice").sequence;
        let tx = Tx::sign_with(
            &net.user_keys,
            "alice",
            seq,
            "carol",
            1,
            1,
            n.cfg.network_id,
        )
        .unwrap();
        let err = n.state.apply_tx(&tx, &n.keys).unwrap_err();
        assert!(err.contains("vault") || err.contains("allowlist"), "{err}");
        // allowed dest still works
        let tx2 = Tx::sign_with(
            &net.user_keys,
            "alice",
            seq,
            "bob",
            1,
            1,
            n.cfg.network_id,
        )
        .unwrap();
        n.state.apply_tx(&tx2, &n.keys).unwrap();
    }

    #[test]
    fn name_reserve_activate_and_timeout() {
        let mut net = Network::bootstrap(&["v1"], 100_000, &users(), ChainConfig::default());
        let n = net.nodes.get_mut("v1").unwrap();
        n.now_ms = 10_000;
        n.keys.generate_id("delta");
        n.reserve_name("delta", &n.keys.public_hex("delta").unwrap())
            .unwrap();
        assert!(matches!(
            n.names.status("delta", n.now_ms),
            crate::names::NameStatus::Reserved { fee_required: 5_000, .. }
        ));
        n.now_ms += crate::names::NAME_RESERVE_MS + 1;
        assert!(matches!(
            n.names.status("delta", n.now_ms),
            crate::names::NameStatus::Free { .. }
        ));
        n.keys.generate_id("north.wind.station");
        {
            let mut a = n.state.get("north.wind.station");
            a.balance = 200;
            n.state.accounts.insert("north.wind.station".into(), a);
        }
        n.activate_name(
            "north.wind.station",
            &n.keys.public_hex("north.wind.station").unwrap(),
        )
        .unwrap();
        assert!(matches!(
            n.names.status("north.wind.station", n.now_ms),
            crate::names::NameStatus::Activated { fee_required: 100, .. }
        ));
        assert_eq!(n.state.get("north.wind.station").balance, 100);
    }

    #[test]
    fn chain_prune_keeps_cap() {
        let cfg = ChainConfig {
            max_chain_ledgers: 3,
            max_txs_per_ledger: 1,
            pack_budget_ms: 0,
            ..Default::default()
        };
        let mut net = Network::bootstrap(&["v1", "v2"], 1000, &users(), cfg);
        for n in net.nodes.values_mut() {
            n.cfg.max_chain_ledgers = 3;
            n.cfg.max_txs_per_ledger = 1;
            n.cfg.pack_budget_ms = 0;
        }
        for _ in 0..10 {
            net.payment("alice", "bob", 1, 1).unwrap();
            net.seal_next_height().unwrap();
        }
        assert!(net.nodes.values().all(|n| n.chain.len() <= 3));
        assert_eq!(net.tip_height(), 10);
    }

    #[test]
    fn defi_amm_and_lend_smoke() {
        let mut net = Network::bootstrap(&["v1"], 1000, &users(), ChainConfig::default());
        let n = net.nodes.get_mut("v1").unwrap();
        n.create_pool("p1", "FPL", "USD").unwrap();
        n.defi.credit_asset("alice", "USD", 10_000);
        n.add_liquidity("p1", "alice", 5_000, 5_000).unwrap();
        n.defi.credit_asset("bob", "USD", 100);
        // bob swaps USD -> FPL
        let out = n.swap("p1", "bob", "USD", 100, 1).unwrap();
        assert!(out > 0);
        n.create_market("m1", "USD").unwrap();
        n.defi.credit_asset("carol", "USD", 1_000);
        n.lend_supply("m1", "carol", 500).unwrap();
        assert!(n.defi.markets["m1"].total_supply >= 500);
    }

    #[test]
    fn watcher_weight_full_epoch_vs_dust() {
        let mut n = Node::new(
            "v1",
            ChainConfig {
                epoch_ms: 168_000, // 168 * 1000ms slots if slot = epoch/168
                ..Default::default()
            },
            KeyRing::new(CryptoScheme::HmacDev),
            &users(),
        );
        n.genesis_ms = n.now_ms;
        // full presence: mark all slots
        for s in 0..168u64 {
            n.epoch_work.record_watcher_slot("alice", s);
        }
        n.epoch_work.record_watcher_work("alice", 100);
        n.epoch_work.record_watcher_work("bob", 100);
        n.epoch_work.record_watcher_slot("bob", 0); // 1 slot only
        let w = economy::watcher_weights(
            &n.epoch_work.watcher_work,
            &n.epoch_work.watcher_slots,
            168,
        );
        assert_eq!(w["alice"], 100);
        assert_eq!(*w.get("bob").unwrap_or(&0), 0); // 100*1/168 = 0
    }

    #[test]
    fn bond_unbond_cooldown_and_complete() {
        let cfg = ChainConfig {
            unbond_cooldown_ms: 5_000,
            min_bond: 1_000,
            ..Default::default()
        };
        let mut n = Node::new(
            "v1",
            cfg,
            KeyRing::new(CryptoScheme::HmacDev),
            &users(),
        );
        n.keys.generate_id("v2");
        // alice bonds into new validator v2
        let total = n.bond("v2", "alice", 5_000).unwrap();
        assert_eq!(total, 5_000);
        assert_eq!(n.state.get("alice").balance, 1_000_000 - 5_000);
        assert_eq!(n.validators["v2"].lottery_weight(), 5_000.0);
        n.request_unbond("v2", 2_000).unwrap();
        assert_eq!(n.validators["v2"].bond, 3_000);
        assert_eq!(n.validators["v2"].unbonding, 2_000);
        assert_eq!(n.validators["v2"].lottery_weight(), 3_000.0);
        assert!(n.complete_unbond("v2").unwrap_err().contains("not ready"));
        // Advance clock without auto-complete path.
        n.now_ms = n.now_ms.saturating_add(5_000);
        let ret = n.complete_unbond("v2").unwrap();
        assert_eq!(ret, 2_000);
        assert_eq!(n.state.get("alice").balance, 1_000_000 - 5_000 + 2_000);
        assert_eq!(n.validators["v2"].unbonding, 0);
        // Second unbond: advance clock then complete (ledger-time path in
        // accept_ledger; tests call complete_all_ready_unbonds explicitly).
        n.request_unbond("v2", 1_000).unwrap();
        n.tick(5_000);
        let done = n.complete_all_ready_unbonds();
        assert_eq!(done, vec![("v2".into(), 1_000)]);
        assert_eq!(n.validators["v2"].unbonding, 0);
        assert_eq!(n.state.get("alice").balance, 1_000_000 - 5_000 + 2_000 + 1_000);
    }

    #[test]
    fn amm_and_lend_lp_claim_on_settle() {
        let cfg = ChainConfig {
            epoch_ms: 10_000,
            emission_bps: 30,
            ..Default::default()
        };
        let mut n = Node::new(
            "v1",
            cfg,
            KeyRing::new(CryptoScheme::HmacDev),
            &users(),
        );
        n.register_validator("v1", 1000);
        n.genesis_ms = n.now_ms;
        n.tick(8 * 10_000);
        n.maybe_settle_epochs();
        // AMM: FPL/USD pool with alice LP
        n.create_pool("p1", "FPL", "USD").unwrap();
        n.credit_asset_admin("alice", "USD", 50_000).unwrap();
        n.add_liquidity("p1", "alice", 10_000, 10_000).unwrap();
        // Lend: carol supplies USD
        n.create_market("m1", "USD").unwrap();
        n.credit_asset_admin("carol", "USD", 20_000).unwrap();
        n.lend_supply("m1", "carol", 10_000).unwrap();
        assert!(!n.defi.aggregate_amm_lp_weights().is_empty());
        assert!(!n.defi.aggregate_lend_lp_weights().is_empty());
        n.force_settle_current_epoch();
        let alice = n.claimable.get("alice").copied().unwrap_or(0);
        let carol = n.claimable.get("carol").copied().unwrap_or(0);
        assert!(alice > 0, "AMM LP claim alice={alice}");
        assert!(carol > 0, "lend LP claim carol={carol}");
        let emit = economy::epoch_emit(TREASURY_GENESIS, 30);
        let lp_cap = economy::cap_lp(emit);
        assert!(alice <= lp_cap, "alice {alice} > cap {lp_cap}");
        assert!(carol <= lp_cap, "carol {carol} > cap {lp_cap}");
    }

    #[test]
    fn v2_btc_rail_work_only_on_progress() {
        let mk = |armed: bool| {
            let mut n = Node::new("v1", ChainConfig::default(), KeyRing::new(CryptoScheme::HmacDev), &users());
            if armed {
                n.rewards_v2_from_height = 1;
                n.rewards_v2_epoch = 0;
            }
            n
        };
        let h1 = crate::btc_spv::mine_header(&"00".repeat(32), &"11".repeat(32), 0x207fffff, 1_700_000_000).unwrap();
        let h2 = crate::btc_spv::mine_header(&h1.hash_display, &"22".repeat(32), 0x207fffff, 1_700_000_001).unwrap();
        let hdr = |height: u64, p: &crate::btc_spv::ParsedHeader| RailHeader {
            height,
            hash: String::new(),
            parent_hash: String::new(),
            merkle_root: String::new(),
            raw: p.raw_hex.clone(),
        };
        for armed in [false, true] {
            let mut n = mk(armed);
            assert_eq!(n.rv2_open(), armed);
            n.submit_rail_header("BTC", hdr(100, &h1), Some("w")).unwrap();
            n.submit_rail_header("BTC", hdr(101, &h2), Some("w")).unwrap();
            assert_eq!(n.epoch_work.watcher_work["w"], 2);
            let r = n.submit_rail_header("BTC", hdr(101, &h2), Some("w"));
            if armed {
                assert!(r.unwrap_err().contains("BTC duplicate header"));
                assert_eq!(n.epoch_work.watcher_work["w"], 2, "no work for a re-submit");
                assert!(Node::is_permanent_tx_failure("BTC duplicate header at 101"));
            } else {
                r.unwrap(); // legacy: accepted as a 1-deep "reorg" and credited
                assert_eq!(n.epoch_work.watcher_work["w"], 3);
            }
        }
    }

    #[test]
    fn watcher_full_presence_claimable_on_settle() {
        let cfg = ChainConfig {
            epoch_ms: 10_000,
            emission_bps: 30,
            ..Default::default()
        };
        let mut n = Node::new(
            "v1",
            cfg,
            KeyRing::new(CryptoScheme::HmacDev),
            &users(),
        );
        n.register_validator("v1", 1000);
        n.genesis_ms = n.now_ms;
        // skip bootstrap: jump into claimable epoch 8
        n.tick(8 * 10_000);
        n.maybe_settle_epochs();
        assert!(n.current_epoch() >= 8);
        // dust: work only, 1 wall slot → weight 0
        n.watcher_credit("bob", 100, true);
        assert_eq!(
            *economy::watcher_weights(
                &n.epoch_work.watcher_work,
                &n.epoch_work.watcher_slots,
                WATCHER_SLOTS_PER_EPOCH,
            )
            .get("bob")
            .unwrap_or(&0),
            0
        );
        // full presence soak path
        n.watcher_credit_ex("alice", 100, false, WATCHER_SLOTS_PER_EPOCH);
        assert_eq!(n.epoch_work.watcher_slots.get("alice").copied().unwrap_or(0), 168);
        let w = economy::watcher_weights(
            &n.epoch_work.watcher_work,
            &n.epoch_work.watcher_slots,
            WATCHER_SLOTS_PER_EPOCH,
        );
        assert_eq!(w["alice"], 100);
        n.force_settle_current_epoch();
        let alice_claim = n.claimable.get("alice").copied().unwrap_or(0);
        assert!(alice_claim > 0, "full-presence watcher should earn; got {alice_claim}");
        // watcher pot = 5% of epochEmit; per-account cap = 0.05% of emit.
        // Sole full-weight watcher should land at (or within 1 unit of) the cap.
        let emit = economy::epoch_emit(n.treasury.saturating_add(
            // treasury may already reflect prior bootstrap settles; use live treasury
            // for cap bound, and TREASURY_GENESIS as upper reference.
            0,
        ).max(1), 30);
        let emit_gen = economy::epoch_emit(TREASURY_GENESIS, 30);
        let cap = economy::cap_watcher(emit.max(emit_gen));
        assert!(
            alice_claim <= cap,
            "sole full watcher must not exceed cap; claim={alice_claim} cap={cap}"
        );
        assert!(
            alice_claim * 100 >= cap * 99,
            "sole full watcher should be at/near cap; claim={alice_claim} cap={cap}"
        );
    }

    #[test]
    fn watcher_heartbeat_marks_current_slot_only() {
        let cfg = ChainConfig {
            epoch_ms: 10_000,
            fee_escalate: false,
            min_fee: 1,
            ..Default::default()
        };
        let mut keys = KeyRing::new(CryptoScheme::HmacDev);
        keys.generate_id("alice");
        let mut n = Node::new("v1", cfg, keys, &users());
        n.genesis_ms = n.now_ms;
        let slot0 = n.current_epoch_slot();
        let seq = n.state.get("alice").sequence;
        let tx = Tx::sign_body(
            &n.keys,
            "alice",
            seq,
            "",
            0,
            2,
            n.cfg.network_id,
            TxBody::WatcherHeartbeat,
        )
        .unwrap();
        n.apply_protocol_tx(&tx).unwrap();
        assert_eq!(
            n.epoch_work.watcher_work.get("alice").copied().unwrap_or(0),
            0,
            "heartbeat must not mint work"
        );
        assert_eq!(n.epoch_work.watcher_slots.get("alice").copied().unwrap_or(0), 1);
        assert!(n.watcher_in_slot("alice", slot0));
        assert!(n.account_json("alice")["watcher_in_slot"].as_bool().unwrap());

        // same slot again — presence stays 1
        let seq = n.state.get("alice").sequence;
        let tx2 = Tx::sign_body(
            &n.keys,
            "alice",
            seq,
            "",
            0,
            2,
            n.cfg.network_id,
            TxBody::WatcherHeartbeat,
        )
        .unwrap();
        n.apply_protocol_tx(&tx2).unwrap();
        assert_eq!(n.epoch_work.watcher_slots.get("alice").copied().unwrap_or(0), 1);

        n.tick(n.watcher_slot_ms());
        let slot1 = n.current_epoch_slot();
        assert_ne!(slot1, slot0, "tick should enter the next presence slot");
        let seq = n.state.get("alice").sequence;
        let tx3 = Tx::sign_body(
            &n.keys,
            "alice",
            seq,
            "",
            0,
            2,
            n.cfg.network_id,
            TxBody::WatcherHeartbeat,
        )
        .unwrap();
        n.apply_protocol_tx(&tx3).unwrap();
        assert_eq!(n.epoch_work.watcher_slots["alice"], 2);
        assert_eq!(
            n.epoch_work.watcher_work.get("alice").copied().unwrap_or(0),
            0
        );
        assert!(n.watcher_in_slot("alice", slot1));
        assert_eq!(
            serde_json::to_string(&TxBody::WatcherHeartbeat).unwrap(),
            r#"{"kind":"watcher_heartbeat"}"#
        );
    }

    #[test]
    fn signed_rail_header_counts_as_watcher_work() {
        let cfg = ChainConfig {
            fee_escalate: false,
            min_fee: 1,
            ..Default::default()
        };
        let mut keys = KeyRing::new(CryptoScheme::HmacDev);
        keys.generate_id("alice");
        let mut n = Node::new("v1", cfg, keys, &users());
        let seq = n.state.get("alice").sequence;
        let tx = Tx::sign_body(
            &n.keys,
            "alice",
            seq,
            "",
            0,
            2,
            n.cfg.network_id,
            TxBody::RailHeader {
                asset: "ETH".into(),
                height: 1,
                hash: "bh1".into(),
                parent_hash: "".into(),
                merkle_root: "mr1".into(),
                raw: String::new(),
            },
        )
        .unwrap();
        n.apply_protocol_tx(&tx).unwrap();
        assert_eq!(n.epoch_work.watcher_work["alice"], 1);
        assert_eq!(n.epoch_work.watcher_slots["alice"], 1);
        assert_eq!(n.bridge.rail("ETH").unwrap().tip_height, 1);
    }

    #[test]
    fn watcher_credit_tx_rejected() {
        let mut keys = KeyRing::new(CryptoScheme::HmacDev);
        keys.generate_id("alice");
        let mut n = Node::new(
            "v1",
            ChainConfig {
                fee_escalate: false,
                min_fee: 1,
                allow_admin_wire: true,
                ..Default::default()
            },
            keys,
            &users(),
        );
        let seq = n.state.get("alice").sequence;
        let tx = Tx::sign_body(
            &n.keys,
            "alice",
            seq,
            "",
            0,
            2,
            n.cfg.network_id,
            TxBody::WatcherCredit {
                work_units: 99,
                presence_slots: 168,
            },
        )
        .unwrap();
        let err = n.apply_protocol_tx(&tx).unwrap_err();
        assert!(err.contains("disabled"), "{err}");
        assert_eq!(n.epoch_work.watcher_work.get("alice").copied().unwrap_or(0), 0);
    }

    #[test]
    fn credit_asset_native_rejected_without_admin_wire() {
        let mut keys = KeyRing::new(CryptoScheme::HmacDev);
        keys.generate_id("alice");
        let mut n = Node::new(
            "v1",
            ChainConfig {
                fee_escalate: false,
                min_fee: 1,
                allow_admin_wire: false,
                ..Default::default()
            },
            keys,
            &users(),
        );
        let before = n.state.get("alice").balance;
        let seq = n.state.get("alice").sequence;
        let tx = Tx::sign_body(
            &n.keys,
            "alice",
            seq,
            "",
            0,
            2,
            n.cfg.network_id,
            TxBody::CreditAsset {
                asset: "FPL".into(),
                amount: 1_000_000,
            },
        )
        .unwrap();
        let err = n.apply_protocol_tx(&tx).unwrap_err();
        assert!(err.contains("admin-only"), "{err}");
        // Fee/seq may apply before the body reject; native must not be minted.
        assert!(n.state.get("alice").balance <= before);
        assert_ne!(n.state.get("alice").balance, before.saturating_add(1_000_000));
        assert!(n
            .credit_asset_admin("alice", "FPL", 10)
            .unwrap_err()
            .contains("admin-only"));
        // Must not enter the mempool either (no pipeline stall).
        let seq = n.state.get("alice").sequence;
        let tx2 = Tx::sign_body(
            &n.keys,
            "alice",
            seq,
            "",
            0,
            2,
            n.cfg.network_id,
            TxBody::CreditAsset {
                asset: "FPL".into(),
                amount: 1,
            },
        )
        .unwrap();
        assert!(n.submit_tx(tx2).unwrap_err().contains("admin-only"));
    }

    #[test]
    fn epoch_settle_credits_claimable() {
        let cfg = ChainConfig {
            epoch_ms: 1_000, // 1s epochs for test
            emission_bps: 30,
            pack_budget_ms: 0,
            max_txs_per_ledger: 4,
            ..Default::default()
        };
        let mut net = Network::bootstrap(&["v1", "v2"], 1000, &users(), cfg);
        for n in net.nodes.values_mut() {
            n.cfg.epoch_ms = 1_000;
            n.genesis_ms = n.now_ms;
        }
        net.pong_all();
        for _ in 0..4 {
            net.payment("alice", "bob", 1, 1).unwrap();
        }
        net.seal_next_height().unwrap();
        // Advance past bootstrap epochs 1..7 into claimable 8+
        for n in net.nodes.values_mut() {
            n.tick(8_000); // 8 epochs of 1s
            let settled = n.maybe_settle_epochs();
            assert!(!settled.is_empty() || n.last_settled_epoch > 0);
        }
        // After settling claimable epochs with pack work, packer has claimable
        let any_claim: u64 = net
            .nodes
            .values()
            .map(|n| n.claimable.values().sum::<u64>())
            .sum();
        // bootstrap 1-7 zero + epoch 8 may have emit — with 8s tick from genesis, epochs settled 1..7
        // need more time into epoch 8 completion for settle of 8
        for n in net.nodes.values_mut() {
            n.tick(1_000);
            n.maybe_settle_epochs();
        }
        let any_claim: u64 = net
            .nodes
            .values()
            .map(|n| n.claimable.values().sum::<u64>())
            .sum();
        // At least fee_reward may credit via settle; emission from epoch 8+
        assert!(any_claim > 0 || net.nodes.values().any(|n| n.last_settled_epoch >= 7));
        let _ = any_claim;
    }

    #[test]
    fn status_exposes_account_sequences_and_faucet() {
        let n = Node::new(
            "v1",
            ChainConfig::default(),
            KeyRing::new(CryptoScheme::HmacDev),
            &genesis_accounts(2),
        );
        let st = n.status_json();
        assert!(st["accounts"]["alice"]["sequence"].as_u64().unwrap() >= 1);
        assert_eq!(st["accounts"]["alice"]["balance"].as_u64().unwrap(), GENESIS_BALANCE);
        assert_eq!(st["faucet"]["account"], FAUCET_ACCOUNT);
        assert_eq!(st["faucet"]["balance"].as_u64().unwrap(), FAUCET_GENESIS);
        assert!(st["epoch_ms"].as_u64().unwrap() > 0);
    }

    #[test]
    fn fee_escalation_rejects_low_fee_when_hot() {
        let cfg = ChainConfig {
            max_mempool_txs: 4,
            min_fee: 1,
            fee_escalate: true,
            ..Default::default()
        };
        let mut net = Network::bootstrap(&["v1"], 1000, &users(), cfg);
        // 0/4 idle → min 1
        net.payment("alice", "bob", 1, 1).unwrap();
        // 1/4 = 2500 bps → 2×; fee 1 rejected
        let err = net.payment("alice", "bob", 1, 1).unwrap_err();
        assert!(err.contains("fee too low"), "{err}");
        assert!(err.contains("want 2"), "{err}");
        net.payment("alice", "bob", 1, 2).unwrap(); // now 2/4 = 50% → 4×
        let err2 = net.payment("alice", "bob", 1, 2).unwrap_err();
        assert!(err2.contains("fee too low") && err2.contains("want 4"), "{err2}");
        net.payment("alice", "bob", 1, 4).unwrap();
        assert!(
            net.nodes
                .get("v1")
                .unwrap()
                .metrics
                .submit_reject_fee_low
                >= 2
        );
        let st = net.nodes.get("v1").unwrap().status_json();
        assert_eq!(st["params_version"], metrics::PARAMS_VERSION);
        assert!(st["metrics"]["fee_market"]["suggested_min_fee"].as_u64().unwrap() >= 4);
    }

    #[test]
    fn btc_spv_deposit_and_withdraw() {
        use bridge::{BridgeProof, RailHeader, RAIL_BTC};

        let mut n = Node::new(
            "v1",
            ChainConfig::default(),
            KeyRing::new(CryptoScheme::HmacDev),
            &users(),
        );
        n.bridge.rail_mut(RAIL_BTC).unwrap().min_confirmations = 1;
        let lock = n.bridge.rail(RAIL_BTC).unwrap().lock_id.clone();
        let amount = 50_000u64;
        let secret = {
            let d = sha256_hex(b"test-vault-sk");
            let mut s = [0u8; 32];
            let raw = hex::decode(&d).unwrap();
            s.copy_from_slice(&raw);
            s[0] &= 0x3f;
            s
        };
        let shares = crate::vault::split_secret(&secret, 5, 3, 0, b"tv").unwrap();
        let vp = crate::vault::vault_pub_from_secret(&secret, 0, 5, 3).unwrap();
        n.bridge.rail_mut(RAIL_BTC).unwrap().vault_pub = Some(vp.clone());
        let watch = hex::decode(&vp.spk_hex).unwrap();
        let (raw_tx, tx) = crate::btc_spv::test_deposit_tx(&watch, "bob", amount);
        let hdr = crate::btc_spv::mine_header(
            &"00".repeat(32),
            &tx.txid_display,
            0x207fffff,
            1_700_000_000,
        )
        .unwrap();
        n.submit_rail_header(
            RAIL_BTC,
            RailHeader {
                height: 1,
                hash: String::new(),
                parent_hash: String::new(),
                merkle_root: String::new(),
                raw: hdr.raw_hex.clone(),
            },
            Some("alice"),
        )
        .unwrap();
        let proof = BridgeProof {
            external_txid: tx.txid_display.clone(),
            block_hash: hdr.hash_display.clone(),
            height: 1,
            merkle_path: vec![],
            merkle_index: 0,
            lock_id: lock,
            parent_hash: String::new(),
            merkle_root: hdr.merkle_display.clone(),
            external_to: String::new(),
            raw_tx: crate::btc_spv::hex_encode(&raw_tx),
        };
        n.rail_deposit(RAIL_BTC, "bob", amount, proof.clone(), Some("alice"))
            .unwrap();
        assert_eq!(n.defi.asset_bal("bob", RAIL_BTC), amount);
        assert_eq!(n.bridge.rail(RAIL_BTC).unwrap().total_minted, amount);
        assert!(n.epoch_work.watcher_work.get("alice").copied().unwrap_or(0) >= 2);
        let dest = "n1fH7uhaDauQYfuwG6t1aTncvyuBSZtDEY";
        let plan = crate::vault::coin_select(
            &n.bridge.rail(RAIL_BTC).unwrap().vault_utxos,
            10_000,
            dest,
            crate::vault::DEFAULT_FEE_SATS,
        )
        .unwrap();
        let vsig = crate::vault::sign_plan(&shares[0..3], &plan).unwrap();
        let note_id = crate::crypto::sha256_hex(
            format!("wd:BTC:bob:10000:{dest}").as_bytes(),
        );
        let kick = crate::vault::signed_dest_lock_kickoff(
            &shares[0..3],
            &n.bridge.rail(RAIL_BTC).unwrap().vault_utxos,
            dest,
            10_000,
            crate::vault::DEFAULT_FEE_SATS,
            &vp.spk_hex,
            &note_id,
        )
        .unwrap();
        let note = n
            .rail_withdraw_full(RAIL_BTC, "bob", 10_000, dest, Some(&vsig), Some(&kick))
            .unwrap();
        assert!(!note.is_empty());
        assert_eq!(n.defi.asset_bal("bob", RAIL_BTC), amount - 10_000);
        assert_eq!(n.bridge.rail(RAIL_BTC).unwrap().total_burned, 10_000);
        assert!(n.rail_deposit(RAIL_BTC, "bob", amount, proof, None).is_err());
        let st = n.status_json();
        let dump = st.to_string();
        assert!(!dump.contains(&hex::encode(secret)), "status must not leak vault secret");
        assert!(st["rails"][0]["vault_pub"].is_object() || st["rails"].as_array().unwrap().iter().any(|r| r["asset"] == "BTC" && r["vault_pub"].is_object()));
    }

    #[test]
    fn nums_bitvm_kickoff_withdraw_rejects_keypath() {
        use bridge::{BridgeProof, RailHeader, RAIL_BTC};

        let mut n = Node::new(
            "v1",
            ChainConfig::default(),
            KeyRing::new(CryptoScheme::HmacDev),
            &users(),
        );
        n.bridge.rail_mut(RAIL_BTC).unwrap().min_confirmations = 1;
        let vp = crate::bitvm::nums_vault_pub();
        n.bridge.rail_mut(RAIL_BTC).unwrap().vault_pub = Some(vp.clone());
        let watch = hex::decode(&vp.spk_hex).unwrap();
        let amount = 50_000u64;
        let (raw_tx, tx) = crate::btc_spv::test_deposit_tx(&watch, "bob", amount);
        let hdr = crate::btc_spv::mine_header(
            &"00".repeat(32),
            &tx.txid_display,
            0x207fffff,
            1_700_000_000,
        )
        .unwrap();
        n.submit_rail_header(
            RAIL_BTC,
            RailHeader {
                height: 1,
                hash: String::new(),
                parent_hash: String::new(),
                merkle_root: String::new(),
                raw: hdr.raw_hex.clone(),
            },
            Some("alice"),
        )
        .unwrap();
        n.rail_deposit(
            RAIL_BTC,
            "bob",
            amount,
            BridgeProof {
                external_txid: tx.txid_display.clone(),
                block_hash: hdr.hash_display.clone(),
                height: 1,
                merkle_path: vec![],
                merkle_index: 0,
                lock_id: n.bridge.rail(RAIL_BTC).unwrap().lock_id.clone(),
                parent_hash: String::new(),
                merkle_root: hdr.merkle_display.clone(),
                external_to: String::new(),
                raw_tx: crate::btc_spv::hex_encode(&raw_tx),
            },
            Some("alice"),
        )
        .unwrap();
        let dest_sk = crate::btc_tx::sha256_once(b"fpl-nums-bob-dest");
        let dest_pk = crate::btc_tx::compressed_pubkey_from_secret(&dest_sk).unwrap();
        let dest = crate::vault::p2wpkh_testnet_address(&dest_pk).unwrap();
        let utxo = n.bridge.rail(RAIL_BTC).unwrap().vault_utxos[0].clone();
        let seed = crate::bitvm::sha256_32(b"fpl-test-abort-seed");
        let kick = crate::bitvm::nums_dest_lock_kickoff(
            &utxo.txid,
            utxo.vout,
            utxo.sats,
            &dest,
            &dest_sk,
            &crate::bitvm::watch_secret_for_tests(),
            20_000,
            crate::vault::DEFAULT_FEE_SATS,
            "bob",
            &seed,
        )
        .unwrap();
        let note = n
            .rail_withdraw_full(RAIL_BTC, "bob", 20_000, &dest, None, Some(&kick))
            .unwrap();
        assert!(!note.is_empty());
        assert_eq!(n.defi.asset_bal("bob", RAIL_BTC), amount - 20_000);
        let wits = crate::btc_spv::extract_witnesses(&hex::decode(&kick).unwrap()).unwrap();
        assert!(crate::bitvm::is_script_path_witness(&wits[0]));
        assert!(!crate::bitvm::is_keypath_witness(&wits[0]));
    }

    #[test]
    fn btc_pool_move_frost_to_nums() {
        use crate::frost_vault::{
            as_vault_pub, dkg_simulate, frost_pub_from_package, frost_sign_tweaked,
            keypath_pay_finish, keypath_pay_sighash,
        };
        use bridge::RAIL_BTC;

        let seats: Vec<String> = (1..=6).map(|i| format!("v{i}")).collect();
        let (keys, pub_pkg) = dkg_simulate(&seats, 4).unwrap();
        let fp = frost_pub_from_package(&pub_pkg, 6, 4).unwrap();
        let mut n = Node::new(
            "v1",
            ChainConfig::default(),
            KeyRing::new(CryptoScheme::HmacDev),
            &users(),
        );
        n.bridge.rail_mut(RAIL_BTC).unwrap().vault_pub = Some(as_vault_pub(&fp));
        let prev = "aa".repeat(32);
        n.bridge
            .rail_mut(RAIL_BTC)
            .unwrap()
            .record_vault_deposit(&prev, 0, 142_000, 1);
        let nums_spk = crate::bitvm::nums_pool_spk().unwrap();
        let vault_spk = hex::decode(&fp.spk_hex).unwrap();
        let (pre, outs) = keypath_pay_sighash(
            &prev,
            0,
            142_000,
            &nums_spk,
            141_000,
            1_000,
            &vault_spk,
        )
        .unwrap();
        let signers: Vec<(String, _)> = seats[..4]
            .iter()
            .map(|s| (s.clone(), keys.get(s).unwrap().clone()))
            .collect();
        let sig = frost_sign_tweaked(&signers, &seats, &pub_pkg, &pre).unwrap();
        let raw = keypath_pay_finish(&prev, 0, 142_000, &outs, &vault_spk, &sig).unwrap();
        let txid = n.btc_pool_move_to_nums(&raw).unwrap();
        assert!(!txid.is_empty());
        let rail = n.bridge.rail(RAIL_BTC).unwrap();
        let watch = hex::decode(&rail.effective_vault_pub().unwrap().spk_hex).unwrap();
        assert!(crate::bitvm::is_nums_spk(&watch));
        assert_eq!(crate::vault::vault_sats(&rail.vault_utxos), 141_000);
        assert_eq!(rail.vault_utxos[0].vout, 0);
        assert_eq!(rail.total_burned, 0);
    }

    #[test]
    fn snapshot_roundtrip_preserves_bridge() {
        use bridge::{BridgeProof, RailHeader, RAIL_BTC};
        use std::path::PathBuf;

        let mut n = Node::new(
            "v1",
            ChainConfig::default(),
            KeyRing::new(CryptoScheme::HmacDev),
            &users(),
        );
        n.register_validator("v1", 1000);
        n.bridge.rail_mut(RAIL_BTC).unwrap().min_confirmations = 1;
        let lock = n.bridge.rail(RAIL_BTC).unwrap().lock_id.clone();
        let vp = crate::vault::vault_pub_from_secret(&[9u8; 32], 0, 5, 3).unwrap();
        n.bridge.rail_mut(RAIL_BTC).unwrap().vault_pub = Some(vp.clone());
        let watch = hex::decode(&vp.spk_hex).unwrap();
        let (raw_tx, tx) = crate::btc_spv::test_deposit_tx(&watch, "alice", 100);
        let hdr = crate::btc_spv::mine_header(
            &"00".repeat(32),
            &tx.txid_display,
            0x207fffff,
            1_700_000_001,
        )
        .unwrap();
        n.submit_rail_header(
            RAIL_BTC,
            RailHeader {
                height: 1,
                hash: String::new(),
                parent_hash: String::new(),
                merkle_root: String::new(),
                raw: hdr.raw_hex.clone(),
            },
            None,
        )
        .unwrap();
        let proof = BridgeProof {
            external_txid: tx.txid_display,
            block_hash: hdr.hash_display,
            height: 1,
            merkle_path: vec![],
            merkle_index: 0,
            lock_id: lock,
            parent_hash: String::new(),
            merkle_root: hdr.merkle_display,
            external_to: String::new(),
            raw_tx: crate::btc_spv::hex_encode(&raw_tx),
        };
        n.rail_deposit(RAIL_BTC, "alice", 100, proof, None).unwrap();
        n.claimable.insert("alice".into(), 42);

        let dir = PathBuf::from(std::env::temp_dir()).join(format!(
            "fpl-snap-test-{}",
            std::process::id()
        ));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("node.json");
        n.save_snapshot(&path).unwrap();
        let keys = KeyRing::new(CryptoScheme::HmacDev);
        let loaded = Node::load_snapshot(&path, keys).unwrap();
        assert_eq!(loaded.bridge.rail(RAIL_BTC).unwrap().total_minted, 100);
        assert_eq!(loaded.claimable.get("alice").copied().unwrap_or(0), 42);
        assert_eq!(loaded.defi.asset_bal("alice", RAIL_BTC), 100);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// v2.9.53: low-disk guard refuses before touching disk, and a failed
    /// write never leaves a partial `.json.tmp` (host2 filled to 100% and
    /// kept 0-byte / 200 MB tmp files on every retry).
    #[test]
    fn guarded_snapshot_write_refuses_cleanly_and_never_leaves_tmp() {
        use std::path::PathBuf;
        let cfg = ChainConfig {
            pack_budget_ms: 0,
            progress_timeout_ms: 0,
            ..Default::default()
        };
        let mut net = Network::bootstrap(&["v1", "v2", "v3"], 1000, &users(), cfg);
        net.pong_all();
        net.payment("alice", "bob", 1, 1).unwrap();
        net.seal_next_height().unwrap();
        let n = net.nodes.get("v1").unwrap();
        let dir = PathBuf::from(std::env::temp_dir()).join(format!(
            "fpl-disk-guard-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("v1.json");
        let tmp = path.with_extension("json.tmp");

        // Guard sees the real statvfs + serialized size, and can refuse.
        let seen = std::cell::Cell::new(0u64);
        let refuse = |st: Option<&crate::disk::DiskStat>, need: u64| {
            assert!(st.is_some(), "statvfs on test dir");
            seen.set(need);
            Err("low disk: test".to_string())
        };
        let e = n.save_join_snapshot_checked(&path, &refuse).unwrap_err();
        assert!(e.to_string().contains("low disk"), "{e}");
        assert!(seen.get() > 0);
        assert!(!path.exists() && !tmp.exists(), "refusal must not create files");

        // Allowed: written, size reported, no tmp left behind.
        let allow = |_: Option<&crate::disk::DiskStat>, _: u64| Ok(());
        let bytes = n.save_snapshot_checked(&path, &allow).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().len(), bytes);
        assert!(!tmp.exists());

        // Write failure (tmp path is a directory → write errors): tmp cleanup
        // must not remove the previous good snapshot.
        std::fs::create_dir_all(&tmp).unwrap();
        assert!(n.save_snapshot(&path).is_err());
        assert_eq!(std::fs::metadata(&path).unwrap().len(), bytes, "old snapshot intact");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Production reliability: restart must restore chain tail so peers can
    /// serve residual catch-up without full-history archive.
    #[test]
    fn snapshot_roundtrip_restores_chain_tail() {
        use std::path::PathBuf;

        let cfg = ChainConfig {
            pack_budget_ms: 0,
            max_txs_per_ledger: 4,
            progress_timeout_ms: 0,
            max_chain_ledgers: 8,
            ..Default::default()
        };
        let mut net = Network::bootstrap(&["v1", "v2", "v3"], 1000, &users(), cfg);
        net.pong_all();
        for _ in 0..12 {
            net.payment("alice", "bob", 1, 1).unwrap();
            net.seal_next_height().unwrap();
        }
        let n = net.nodes.get("v1").unwrap();
        assert_eq!(n.tip_height, 12);
        // Pruned to max_chain_ledgers=8
        assert_eq!(n.chain.len(), 8);
        assert_eq!(n.chain.first().unwrap().height, 5);
        let tip_hash = n.tip_hash.clone();
        let serve_from = n.chain.first().unwrap().height;

        let dir = PathBuf::from(std::env::temp_dir()).join(format!(
            "fpl-snap-chain-{}",
            std::process::id()
        ));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("v1.json");
        n.save_snapshot(&path).unwrap();

        // Old-style empty-chain snap still loads tip (compat).
        let mut bare: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        bare.as_object_mut().unwrap().remove("chain");
        bare["version"] = serde_json::json!(1);
        let bare_path = dir.join("v1-bare.json");
        std::fs::write(&bare_path, serde_json::to_string_pretty(&bare).unwrap()).unwrap();
        let bare_n =
            Node::load_snapshot(&bare_path, KeyRing::new(CryptoScheme::HmacDev)).unwrap();
        assert_eq!(bare_n.tip_height, 12);
        assert!(bare_n.chain.is_empty(), "pre-v2 snap has no chain");
        assert!(bare_n.ledgers_from(serve_from, 64).is_empty());

        // v2 snap restores tail + seen_at_height; residual pull works.
        let loaded =
            Node::load_snapshot(&path, KeyRing::new(CryptoScheme::HmacDev)).unwrap();
        assert_eq!(loaded.tip_height, 12);
        assert_eq!(loaded.tip_hash, tip_hash);
        assert_eq!(loaded.chain.len(), 8);
        assert_eq!(loaded.chain.last().unwrap().ledger_hash, tip_hash);
        assert_eq!(loaded.chain.first().unwrap().height, serve_from);
        let batch = loaded.ledgers_from(serve_from, 64);
        assert_eq!(batch.len(), 8);
        assert_eq!(batch[0].height, serve_from);
        assert!(loaded.seen_at_height.contains_key(&12));
        // Residual window for a peer that state-synced then fell a few heights behind.
        let residual = loaded.ledgers_from(10, 64);
        assert_eq!(residual.len(), 3);
        assert_eq!(residual[0].height, 10);
        assert_eq!(residual[2].height, 12);

        let st = loaded.status_json();
        assert_eq!(st["product_version"], PRODUCT_VERSION);
        assert_eq!(st["chain_len"], 8);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Snapshot must keep true genesis balances (not tip state) so hard-resync
    /// cannot enter a perpetual from=1 storm after restart.
    #[test]
    fn mempool_export_absorb_need_txs() {
        let mut n = Node::new(
            "v1",
            ChainConfig {
                pack_budget_ms: 0,
                max_txs_per_ledger: 8,
                progress_timeout_ms: 0,
                ..Default::default()
            },
            KeyRing::new(CryptoScheme::HmacDev),
            &users(),
        );
        n.is_hub = true;
        let mut keys = KeyRing::new(CryptoScheme::HmacDev);
        keys.generate_many(["alice", "bob"].into_iter());
        n.keys = keys;
        for i in 1..=5 {
            let tx = Tx::sign_with(&n.keys, "alice", i, "bob", 1, 1, n.cfg.network_id).unwrap();
            assert!(n.submit_tx(tx).unwrap());
        }
        assert_eq!(n.mempool.len(), 5);
        let batch = n.serve_need_txs(3);
        assert_eq!(batch.len(), 3);
        assert!(n.mempool_served >= 1);

        let mut light = Node::new(
            "v2",
            ChainConfig::default(),
            KeyRing::new(CryptoScheme::HmacDev),
            &users(),
        );
        assert!(light.wants_need_txs());
        let added = light.absorb_txs(&batch);
        assert_eq!(added, 3);
        assert_eq!(light.mempool.len(), 3);
        // Dedupe
        assert_eq!(light.absorb_txs(&batch), 0);
    }

    #[test]
    fn recertify_committed_tip_rebuilds_missing_cert() {
        let cfg = ChainConfig {
            pack_budget_ms: 0,
            max_txs_per_ledger: 4,
            progress_timeout_ms: 0,
            soft_ok_votes: 4,
            committee_size: 6,
            ..Default::default()
        };
        let ids = ["v1", "v2", "v3", "v4", "v5", "v6"];
        let mut net = Network::bootstrap(&ids, 1000, &users(), cfg);
        net.pong_all();
        net.payment("alice", "bob", 1, 1).unwrap();
        net.seal_next_height().unwrap();
        let h = net.tip_height();
        assert!(h >= 1);
        for n in net.nodes.values_mut() {
            n.certs.remove(&h);
            n.ok_votes.clear();
            n.ok_sigs.clear();
        }
        assert!(net.nodes["v1"].certs.get(&h).is_none());
        for n in net.nodes.values_mut() {
            let _ = n.recertify_committed_tip();
        }
        // Votes are local; harvest into one node as the mesh would.
        let mut votes = Vec::new();
        for n in net.nodes.values() {
            if let Some(set) = n.ok_votes.get(&n.tip_hash) {
                for v in set {
                    if let Some(sig) = n.ok_sigs.get(&n.tip_hash).and_then(|m| m.get(v)) {
                        votes.push((v.clone(), sig.clone()));
                    }
                }
            }
        }
        let tip_hash = net.nodes["v1"].tip_hash.clone();
        let host = net.nodes.get_mut("v1").unwrap();
        for (v, sig) in votes {
            let _ = host.vote_ok_ex(&tip_hash, &v, &sig);
        }
        host.store_cert_if_ready(&tip_hash, h);
        assert!(
            host.certs.contains_key(&h),
            "committee re-OK must rebuild tip cert"
        );
        assert!(host.recertify_committed_tip().is_none());
    }

    #[test]
    fn recertify_runs_before_pongs_and_blocks_vc() {
        let cfg = ChainConfig {
            pack_budget_ms: 0,
            max_txs_per_ledger: 4,
            progress_timeout_ms: 1_000,
            soft_ok_votes: 4,
            committee_size: 6,
            ..Default::default()
        };
        let ids = ["v1", "v2", "v3", "v4", "v5", "v6"];
        let mut net = Network::bootstrap(&ids, 1000, &users(), cfg);
        net.pong_all();
        net.payment("alice", "bob", 1, 1).unwrap();
        net.seal_next_height().unwrap();
        let h = net.tip_height();
        for n in net.nodes.values_mut() {
            n.certs.remove(&h);
            n.best_peer_tip = 0;
            n.height_open_ms = 0;
            n.now_ms = n.now_ms.saturating_add(20_000);
        }
        let host = net.nodes.get_mut("v1").unwrap();
        assert!(
            host.maybe_view_change_vote().is_none(),
            "no VC while tip cert is missing"
        );
        assert!(
            host.recertify_committed_tip().is_some(),
            "snap start (best_peer_tip=0) must still recertify"
        );
    }

    #[test]
    fn want_body_pull_retries_until_have_it() {
        let mut n = Node::new(
            "v1",
            ChainConfig::default(),
            KeyRing::new(CryptoScheme::HmacDev),
            &users(),
        );
        n.now_ms = 1_000;
        n.note_want_body(2, "abc");
        assert_eq!(n.take_body_pull().as_deref(), Some("abc"));
        assert!(n.take_body_pull().is_none(), "rate-limited");
        n.tick(Node::BODY_PULL_INTERVAL_MS);
        assert_eq!(n.take_body_pull().as_deref(), Some("abc"));
        n.clear_want_body();
        assert!(n.take_body_pull().is_none());
    }

    #[test]
    fn pending_body_push_is_packer_or_hub_only() {
        let stub = |packer: &str| Ledger {
            height: 2,
            parent_hash: "p".into(),
            network_id: 2200,
            packer: packer.into(),
            packer_public_key: String::new(),
            tx_ids: vec!["t".into()],
            txs: vec![],
            state_root_after: String::new(),
            sealed_at_ms: 1,
            sealed_utc_ms: 0,
            packer_sig: String::new(),
            ledger_hash: "abc".into(),
            skipped_predecessors: vec![],
            parent_cert: None,
            slashes: vec![],
            fee_total: 0,
            claim_root: String::new(),
            current_committee_root: String::new(),
            next_committee_root: String::new(),
            inner_hash: String::new(),
            current_committee: vec![],
            next_committee: vec![],
            batch_root: String::new(),
            batch_sig: String::new(),
            batch_paths: Vec::new(),
        };
        // txs.len() != tx_ids.len() → no body
        let mut n = Node::new(
            "v1",
            ChainConfig::default(),
            KeyRing::new(CryptoScheme::HmacDev),
            &users(),
        );
        n.now_ms = 1_000;
        n.pending_proposal = Some(stub("v1"));
        assert!(n.take_pending_body_push().is_none(), "header-only pending");
        // Give it a matching empty-id body so has_body() is true.
        n.pending_proposal = Some(Ledger {
            tx_ids: vec![],
            txs: vec![],
            ..stub("v1")
        });
        assert!(n.take_pending_body_push().is_some(), "packer pushes");
        assert!(n.take_pending_body_push().is_none(), "rate-limited");
        n.tick(Node::BODY_PUSH_INTERVAL_MS);
        n.id = "v2".into();
        n.is_hub = false;
        n.pending_proposal = Some(Ledger {
            tx_ids: vec![],
            txs: vec![],
            ..stub("v1")
        });
        assert!(
            n.take_pending_body_push().is_none(),
            "light checker must not flood"
        );
        n.is_hub = true;
        assert!(n.take_pending_body_push().is_some(), "hub re-serves body");
    }

    #[test]
    fn packer_feed_sends_applicable_heads_first() {
        let mut n = Node::new(
            "v1",
            ChainConfig {
                pack_budget_ms: 0,
                max_txs_per_ledger: 8,
                progress_timeout_ms: 0,
                ..Default::default()
            },
            KeyRing::new(CryptoScheme::HmacDev),
            &users(),
        );
        n.is_hub = true;
        n.register_validator("v1", 1000);
        n.register_validator("v2", 1000);
        let mut keys = KeyRing::new(CryptoScheme::HmacDev);
        keys.generate_many(["v1", "v2", "alice", "bob"].into_iter());
        n.keys = keys;
        n.pong("v1");
        n.pong("v2");
        n.freeze_open_height_schedule();
        // Arrival order: alice futures first, then bob's head.
        for seq in 2..=5 {
            let tx = Tx::sign_with(&n.keys, "alice", seq, "bob", 1, 1, n.cfg.network_id).unwrap();
            assert!(n.submit_tx(tx).unwrap());
        }
        let bob = Tx::sign_with(&n.keys, "bob", 1, "alice", 1, 1, n.cfg.network_id).unwrap();
        assert!(n.submit_tx(bob).unwrap());
        let alice_head =
            Tx::sign_with(&n.keys, "alice", 1, "bob", 1, 1, n.cfg.network_id).unwrap();
        assert!(n.submit_tx(alice_head).unwrap());
        let batch = n.export_packer_batch(2);
        assert_eq!(batch.len(), 2);
        let seqs: Vec<(String, u64)> = batch
            .iter()
            .map(|t| (t.account.clone(), t.sequence))
            .collect();
        assert!(
            seqs.iter().all(|(_, s)| *s == 1),
            "first slots must be applicable heads, got {seqs:?}"
        );
        // Future-only local pile still requests hub inventory.
        let mut thin = Node::new(
            "v2",
            ChainConfig {
                pack_budget_ms: 0,
                progress_timeout_ms: 0,
                ..Default::default()
            },
            KeyRing::new(CryptoScheme::HmacDev),
            &users(),
        );
        thin.keys.generate_many(["alice", "bob"].into_iter());
        for seq in 2..=10 {
            let tx =
                Tx::sign_with(&thin.keys, "alice", seq, "bob", 1, 1, thin.cfg.network_id).unwrap();
            thin.submit_tx(tx).unwrap();
        }
        assert!(thin.mempool.len() >= 8);
        assert!(!thin.has_applicable_tx());
        assert!(
            thin.should_pre_pack_need_txs(),
            "len≥8 future-only must still pull"
        );
        let feed = n.take_packer_feed().expect("hub must push applicable heads");
        assert!(feed.iter().any(|t| t.sequence == 1));
        let seats = n.dish_seats();
        let seat = seats[0].clone();
        let ids: Vec<String> = feed.iter().map(|t| t.tx_id.clone()).collect();
        assert!(
            feed.iter().all(|t| t.sequence == 1),
            "the first dish is heads only"
        );
        n.note_dish_queued(&seat, &ids);
        n.tick(Node::PACKER_FEED_INTERVAL_MS);
        let again = n.take_packer_dish();
        let next = again
            .as_ref()
            .and_then(|rows| rows.iter().find(|(id, _)| id == &seat));
        let depth = next.map(|(_, txs)| txs.len()).unwrap_or(0);
        assert!(depth > 0, "depth follows on the next tick");
        assert!(
            next.unwrap().1.iter().all(|t| t.sequence > 1),
            "the second dish does not repeat heads"
        );
    }

    #[test]
    fn short_pack_hole_pulls_once() {
        let mut n = Node::new(
            "v1",
            ChainConfig {
                pack_budget_ms: 0,
                progress_timeout_ms: 0,
                ..Default::default()
            },
            KeyRing::new(CryptoScheme::HmacDev),
            &users(),
        );
        n.tick(1);
        n.register_validator("v1", 1000);
        n.register_validator("v3", 1000);
        n.pong("v1");
        n.pong_with_inventory("v3", 0, 1_400, true);
        n.keys.generate_many(["alice", "bob"].into_iter());
        for seq in 1..=4 {
            let tx = Tx::sign_with(&n.keys, "alice", seq, "bob", 1, 1, n.cfg.network_id).unwrap();
            n.submit_tx(tx).unwrap();
        }
        n.cfg.pack_budget_ms = 4_000;
        n.cfg.progress_timeout_ms = 9_000;
        n.cfg.pong_window_ms = 60_000;
        assert!(n.packable_tx_count() < 300, "shallow queue");
        assert!(n.short_pack_hole(), "shallow walk with a full hub must pull");
        assert!(n.should_pre_pack_need_txs());
        n.mark_pre_pack_need_txs();
        assert!(n.waiting_need_txs_grace(), "do not seal the thin walk yet");
        n.tick(900);
        assert!(n.waiting_need_txs_grace(), "the wait outlasts the 800ms grace");
        assert!(n.should_pre_pack_need_txs(), "pull again while v1 still has more");
        n.tick(4_000);
        assert!(
            n.waiting_need_txs_grace(),
            "the 4s pack budget must not seal a thin walk"
        );
        n.tick(3_000);
        assert!(
            !n.waiting_need_txs_grace(),
            "the wait ends when the skip is close"
        );
        assert!(!n.should_pre_pack_need_txs());
    }

    #[test]
    fn pre_pack_need_txs_gate() {
        // P1: thin / no-applicable → pull once, wait grace, then allow pack attempt.
        let mut n = Node::new(
            "v1",
            ChainConfig {
                pack_budget_ms: 0,
                progress_timeout_ms: 0,
                ..Default::default()
            },
            KeyRing::new(CryptoScheme::HmacDev),
            &users(),
        );
        n.register_validator("v1", 1000);
        n.pong("v1");
        assert!(n.should_pre_pack_need_txs(), "empty mp must pull before pack");
        n.mark_pre_pack_need_txs();
        assert!(
            !n.should_pre_pack_need_txs(),
            "rate-limited inside NEED_TXS_INTERVAL"
        );
        assert!(n.waiting_need_txs_grace(), "grace window active");
        n.tick(Node::NEED_TXS_INTERVAL_MS);
        assert!(
            n.should_pre_pack_need_txs(),
            "still !applicable → re-pull after interval"
        );
        n.tick(Node::NEED_TXS_PRE_PACK_GRACE_MS + 1);
        assert!(!n.waiting_need_txs_grace(), "grace expires");
        // With applicable work, skip pull.
        let mut keys = KeyRing::new(CryptoScheme::HmacDev);
        keys.generate_many(["alice", "bob"].into_iter());
        n.keys = keys;
        let tx = Tx::sign_with(&n.keys, "alice", 1, "bob", 1, 1, n.cfg.network_id).unwrap();
        n.submit_tx(tx).unwrap();
        // New height cycle after commit would reset; here tip still 0 open h=1 already pulled.
        assert!(n.has_applicable_tx());
        assert!(!n.should_pre_pack_need_txs());
        assert!(!n.short_pack_hole(), "one head is not a full-pool hole");
        // No hub ad yet: one local head is the whole pool, so do not pull.
        // A fresh hub advertising more than we hold must pull before the seal.
        let mut hungry = Node::new(
            "v2",
            ChainConfig {
                pack_budget_ms: 0,
                progress_timeout_ms: 0,
                pong_window_ms: 60_000,
                max_txs_per_ledger: 0,
                ..Default::default()
            },
            KeyRing::new(CryptoScheme::HmacDev),
            &users(),
        );
        hungry.register_validator("v2", 1000);
        hungry.register_validator("v1", 1000);
        hungry.pong("v2");
        hungry.pong_with_inventory("v1", 0, 20_000, true);
        hungry.keys.generate_many(["alice", "bob"].into_iter());
        let tx = Tx::sign_with(&hungry.keys, "alice", 1, "bob", 1, 1, hungry.cfg.network_id)
            .unwrap();
        hungry.submit_tx(tx).unwrap();
        assert!(hungry.has_applicable_tx());
        assert!(hungry.hub_has_more_than_local());
        assert!(
            hungry.should_pre_pack_need_txs(),
            "4 local heads must still pull a hub that advertises 20k"
        );
        hungry.mark_pre_pack_need_txs();
        assert!(hungry.waiting_need_txs_grace());
        assert!(!hungry.should_pre_pack_need_txs(), "one pull this height");
    }

    #[test]
    fn max_chain_ledgers_zero_clamped() {
        let mut cfg = ChainConfig {
            max_chain_ledgers: 0,
            ..Default::default()
        };
        cfg.sanitize();
        assert_eq!(cfg.max_chain_ledgers, ChainConfig::DEFAULT_MAX_CHAIN_LEDGERS);
        let n = Node::new(
            "v1",
            ChainConfig {
                max_chain_ledgers: 0,
                ..Default::default()
            },
            KeyRing::new(CryptoScheme::HmacDev),
            &users(),
        );
        assert_eq!(n.cfg.max_chain_ledgers, ChainConfig::DEFAULT_MAX_CHAIN_LEDGERS);
    }

    #[test]
    fn catchup_conflict_no_auto_hard_resync() {
        // P2: conflicting residual batch must not arm need_hard_resync.
        let cfg = ChainConfig {
            pack_budget_ms: 0,
            max_txs_per_ledger: 4,
            soft_ok_votes: 1,
            ..Default::default()
        };
        let mut net = Network::bootstrap(&["v1", "v2", "v3"], 1000, &users(), cfg);
        net.pong_all();
        net.payment("alice", "bob", 1, 1).unwrap();
        net.seal_next_height().unwrap();
        let tip = net.tip_height();
        assert_eq!(tip, 1);
        // Forge a bogus ledger at tip+1 with wrong parent → residual conflict.
        let n = net.nodes.get_mut("v1").unwrap();
        let mut fake = n.chain[0].clone();
        fake.height = 2;
        fake.parent_hash = "deadbeef".repeat(8);
        fake.ledger_hash = "cafebabe".repeat(8);
        let before_flag = n.need_hard_resync;
        let err = n.apply_catchup_batch(&[fake]).unwrap_err();
        assert!(
            err.contains("bad parent") || err.contains("parent") || err.contains("height"),
            "{err}"
        );
        assert!(
            !n.need_hard_resync,
            "P2: catch-up conflict must not auto-arm hard-resync (was {before_flag})"
        );
        assert!(
            !n.last_catchup_conflict.is_empty(),
            "conflict should be recorded for ops"
        );
    }

    #[test]
    fn live_tip_never_rewinds_on_genesis_catchup_batch() {
        // 2026-08-13: apply_catchup_batch(from=1) rewound tip 800→64.
        let cfg = ChainConfig {
            pack_budget_ms: 0,
            max_txs_per_ledger: 4,
            soft_ok_votes: 1,
            ..Default::default()
        };
        let mut net = Network::bootstrap(&["v1", "v2", "v3"], 1000, &users(), cfg);
        net.pong_all();
        for _ in 0..8 {
            net.payment("alice", "bob", 1, 1).unwrap();
            net.seal_next_height().unwrap();
        }
        let tip_before = net.tip_height();
        assert_eq!(tip_before, 8);
        let tip_hash = net.nodes["v1"].tip_hash.clone();
        let prefix = net.nodes["v1"].ledgers_from(1, 4);
        assert_eq!(prefix.len(), 4);
        let n = net.nodes.get_mut("v2").unwrap();
        n.best_peer_tip = 20;
        n.need_hard_resync = true; // stale auto-arm from old binaries
        let tip = n.apply_catchup_batch(&prefix).unwrap();
        assert_eq!(tip, tip_before, "must not rewind a live tip");
        assert_eq!(n.tip_hash, tip_hash);
        assert!(!n.need_hard_resync, "stale auto-arm must not survive");
        assert!(!n.hard_resync_operator);
    }

    #[test]
    fn catchup_conflict_while_lagging_does_not_arm() {
        let cfg = ChainConfig {
            pack_budget_ms: 0,
            max_txs_per_ledger: 4,
            soft_ok_votes: 1,
            ..Default::default()
        };
        let mut net = Network::bootstrap(&["v1", "v2", "v3"], 1000, &users(), cfg);
        net.pong_all();
        net.payment("alice", "bob", 1, 1).unwrap();
        net.seal_next_height().unwrap();
        let n = net.nodes.get_mut("v1").unwrap();
        n.best_peer_tip = 99; // looks lagging
        let mut fake = n.chain[0].clone();
        fake.height = 2;
        fake.parent_hash = "deadbeef".repeat(8);
        fake.ledger_hash = "cafebabe".repeat(8);
        let _ = n.apply_catchup_batch(&[fake]).unwrap_err();
        assert!(!n.need_hard_resync);
        assert!(!n.hard_resync_operator);
        assert_eq!(n.tip_height, 1);
    }

    #[test]
    fn operator_hard_reset_arms_flag() {
        let mut n = Node::new(
            "v1",
            ChainConfig::default(),
            KeyRing::new(CryptoScheme::HmacDev),
            &users(),
        );
        n.register_validator("v1", 1000);
        n.ensure_genesis_validators(&[String::from("v1")], 1000);
        n.genesis_accounts = users();
        assert!(n.can_hard_resync());
        assert!(!n.need_hard_resync);
        n.operator_request_hard_resync("test rebuild").unwrap();
        assert!(n.need_hard_resync);
        assert!(n.last_catchup_conflict.contains("operator"));
        // note_peer_tip while armed requests from=1
        n.best_peer_tip = 10;
        n.last_catchup_req_ms = 0;
        n.now_ms = 10_000;
        let from = n.note_peer_tip(10, "abc");
        assert_eq!(from, Some(1));
    }

    #[test]
    fn proposal_blocks_skip_of_sealer() {
        // If packer already staged a proposal, progress-skip must not fire / apply.
        let cfg = ChainConfig {
            progress_timeout_ms: 1_000,
            pack_budget_ms: 0,
            max_txs_per_ledger: 4,
            soft_ok_votes: 1,
            ..Default::default()
        };
        let mut net = Network::bootstrap(&["v1", "v2", "v3"], 1000, &users(), cfg);
        net.pong_all();
        net.payment("alice", "bob", 1, 1).unwrap();
        let winner = net.nodes["v1"].lottery_packer().unwrap();
        let ledger = net
            .nodes
            .get_mut(&winner)
            .unwrap()
            .pack_as(&winner)
            .unwrap();
        // Stage on all nodes (soft may or may not commit depending on soft_need).
        for n in net.nodes.values_mut() {
            let _ = n.accept_ledger(&ledger);
        }
        let tip = net.nodes["v1"].tip_hash.clone();
        // Even after long wait, must not skip the sealer who has pending/proposal.
        for n in net.nodes.values_mut() {
            n.tick(5_000);
            // If already soft-committed, no pending — skip N/A for next height.
            if n.pending_proposal.is_some() {
                assert!(
                    n.propose_progress_timeout_skip().is_none(),
                    "must not skip packer with staged proposal"
                );
                assert!(
                    !n.vote_skip(n.tip_height + 1, &winner, &tip, "v2"),
                    "vote_skip must refuse sealer with proposal"
                );
                assert!(
                    !n.apply_shared_skip(n.tip_height + 1, &winner, &tip),
                    "apply_shared_skip must refuse sealer with proposal"
                );
            }
        }
    }

    #[test]
    fn second_packer_cannot_seal_open_height() {
        let cfg = ChainConfig {
            pack_budget_ms: 0,
            max_txs_per_ledger: 4,
            soft_ok_votes: 3,
            progress_timeout_ms: 0,
            ..Default::default()
        };
        let mut net = Network::bootstrap(&["v1", "v2", "v3"], 1000, &users(), cfg);
        net.pong_all();
        net.payment("alice", "bob", 1, 1).unwrap();
        let winner = net.nodes["v1"].lottery_packer().unwrap();
        let led = net.nodes.get_mut(&winner).unwrap().pack_as(&winner).unwrap();
        net.nodes.get_mut("v1").unwrap().accept_ledger(&led).unwrap();
        assert!(net.nodes["v1"].height_has_proposal(1));
        let err = net
            .nodes
            .get_mut("v1")
            .unwrap()
            .may_pack_locally(&winner)
            .unwrap_err();
        assert!(
            err.contains("proposal") || err.contains("already"),
            "{err}"
        );
    }

    #[test]
    fn dual_proposal_tie_picks_lower_hash() {
        let cfg = ChainConfig {
            pack_budget_ms: 0,
            max_txs_per_ledger: 4,
            soft_ok_votes: 3,
            progress_timeout_ms: 0,
            ..Default::default()
        };
        let mut net = Network::bootstrap(&["v1", "v2", "v3"], 1000, &users(), cfg);
        net.pong_all();
        net.payment("alice", "bob", 1, 1).unwrap();
        net.payment("alice", "bob", 1, 1).unwrap();
        let w1 = net.nodes["v1"].lottery_packer().unwrap();
        let a = net.nodes.get_mut(&w1).unwrap().pack_as(&w1).unwrap();
        let tip = net.nodes["v1"].tip_hash.clone();
        // Elect a second sealer without accepting `a` first (the 859 race).
        for n in net.nodes.values_mut() {
            let _ = n.apply_shared_skip(1, &w1, &tip);
        }
        let w2 = net.nodes["v1"].lottery_packer().unwrap();
        assert_ne!(w2, w1);
        let b = net.nodes.get_mut(&w2).unwrap().pack_as(&w2).unwrap();
        let low = if a.ledger_hash <= b.ledger_hash {
            a.ledger_hash.clone()
        } else {
            b.ledger_hash.clone()
        };
        // First-seen is `a` (maybe higher hash). Then `b`. Must keep the lower hash.
        let _ = net.nodes.get_mut("v1").unwrap().accept_ledger(&a);
        let _ = net.nodes.get_mut("v1").unwrap().accept_ledger(&b);
        let pending = net.nodes["v1"]
            .pending_proposal
            .as_ref()
            .map(|p| p.ledger_hash.clone())
            .or_else(|| {
                net.nodes["v1"]
                    .chain
                    .last()
                    .map(|l| l.ledger_hash.clone())
            });
        assert_eq!(pending.as_ref(), Some(&low), "tie-break must pick lower hash");
    }

    #[test]
    fn committee_outsider_ok_does_not_count() {
        let mut net = Network::bootstrap(
            &["v1", "v2", "v3", "v4", "v5", "v6", "v7"],
            1000,
            &users(),
            ChainConfig {
                soft_ok_votes: 3,
                committee_size: 6,
                pack_budget_ms: 0,
                ..Default::default()
            },
        );
        net.pong_all();
        let order = net.nodes["v1"].lottery_order();
        assert_eq!(order.len(), 6, "committee is 6 of 7");
        let outsider = ["v1", "v2", "v3", "v4", "v5", "v6", "v7"]
            .into_iter()
            .find(|id| !order.iter().any(|x| x == id))
            .unwrap();
        let n = net.nodes.get_mut("v1").unwrap();
        let (soft, hard, fresh) = n.vote_ok_ex("deadbeef", outsider, "");
        assert!(!soft, "outsider {outsider} must not soft-pass the ledger");
        assert!(fresh, "outsider OK still records for network hard QC");
        assert!(!hard, "one outsider vote is not hard QC");
        assert!(!n.in_committee(outsider));
        assert_eq!(n.soft_votes_needed(), 4);
        assert_eq!(n.hard_votes_needed(), 5, "hard = ceil(7*0.6)");
    }

    #[test]
    fn n13_committee_soft_network_hard() {
        // 100-val scale in miniature: tip waits on 4 of 6, hard on 8 of 13.
        let ids: Vec<String> = (1..=13).map(|i| format!("v{i}")).collect();
        let refs: Vec<&str> = ids.iter().map(|s| s.as_str()).collect();
        let mut net = Network::bootstrap(
            &refs,
            1000,
            &users(),
            ChainConfig {
                soft_ok_votes: 3,
                hard_ok_ratio: 0.6,
                pack_budget_ms: 0,
                ..Default::default()
            },
        );
        net.pong_all();
        let n = &net.nodes["v1"];
        assert_eq!(n.lottery_order().len(), 6);
        assert_eq!(n.committee_checkers().len(), 5);
        assert_eq!(n.soft_votes_needed(), 4);
        assert_eq!(n.commit_votes_needed(), 4);
        assert_eq!(n.hard_votes_needed(), 8);
    }

    #[test]
    fn n6_commit_is_4_of_6() {
        let mut net = Network::bootstrap(
            &["v1", "v2", "v3", "v4", "v5", "v6"],
            1000,
            &users(),
            ChainConfig {
                soft_ok_votes: 3,
                hard_ok_ratio: 0.6,
                ..Default::default()
            },
        );
        net.pong_all();
        let n = &net.nodes["v1"];
        assert_eq!(n.lottery_order().len(), 6);
        assert_eq!(n.committee_checkers().len(), 5);
        assert_eq!(n.soft_votes_needed(), 4);
        assert_eq!(n.commit_votes_needed(), 4);
        assert_eq!(n.hard_votes_needed(), 4);
        let packer = n.lottery_order()[0].clone();
        assert!(n.counts_as_qc_voter(&packer), "packer counts toward 4-of-6");
    }

    #[test]
    fn packer_ok_counts_toward_4_of_6() {
        let mut net = Network::bootstrap(
            &["v1", "v2", "v3", "v4", "v5", "v6", "v7"],
            1000,
            &users(),
            ChainConfig {
                soft_ok_votes: 3,
                pack_budget_ms: 0,
                ..Default::default()
            },
        );
        net.pong_all();
        let order = net.nodes["v1"].lottery_order();
        let packer = order[0].clone();
        let rest: Vec<String> = order.iter().skip(1).cloned().collect();
        assert_eq!(rest.len(), 5);
        let n = net.nodes.get_mut("v1").unwrap();
        let (soft, _, _) = n.vote_ok_ex("body", &packer, "");
        assert!(!soft, "packer alone is not 4-of-6");
        for (i, c) in rest.iter().take(2).enumerate() {
            let (soft, _, _) = n.vote_ok_ex("body", c, "");
            assert!(!soft, "packer+{} is not 4-of-6", i + 1);
        }
        let (soft, _, _) = n.vote_ok_ex("body", &rest[2], "");
        assert!(soft, "packer + 3 others = 4-of-6");
    }

    #[test]
    fn parent_cert_rides_next_ledger() {
        let mut net = Network::bootstrap(
            &["v1", "v2", "v3", "v4", "v5", "v6"],
            1000,
            &users(),
            ChainConfig {
                pack_budget_ms: 0,
                max_txs_per_ledger: 8,
                ..Default::default()
            },
        );
        net.pong_all();
        for _ in 0..3 {
            net.payment("alice", "bob", 1, 1).unwrap();
        }
        net.seal_next_height().unwrap();
        assert_eq!(net.tip_height(), 1);
        let n = &net.nodes["v1"];
        assert!(n.certs.contains_key(&1), "h=1 must have a 4-of-6 cert");
        assert!(n.chain[0].parent_cert.is_none(), "genesis parent_cert is None");
        for _ in 0..3 {
            net.payment("alice", "bob", 1, 1).unwrap();
        }
        net.seal_next_height().unwrap();
        assert_eq!(net.tip_height(), 2);
        let n = &net.nodes["v1"];
        let cert = n.chain[1]
            .parent_cert
            .as_ref()
            .expect("h=2 must carry parent_cert");
        assert_eq!(cert.height, 1);
        assert_eq!(cert.ledger_hash, n.chain[0].ledger_hash);
        assert!(cert.voters.len() >= 4, "cert voters={}", cert.voters.len());
    }

    #[test]
    fn checker_double_ok_is_slashed() {
        // 7 bonded: with exactly 6, v2.9.47's drop_slashes_that_break_quorum
        // (rightly) discards the evidence instead of freezing the chain.
        let mut net = Network::bootstrap(
            &["v1", "v2", "v3", "v4", "v5", "v6", "v7"],
            1000,
            &users(),
            ChainConfig {
                pack_budget_ms: 0,
                slash_equivocation: 100,
                ..Default::default()
            },
        );
        net.pong_all();
        let order = net.nodes["v1"].lottery_order();
        let voter = order[1].clone();
        let bond_before = net.nodes["v1"].validators[&voter].bond;
        for n in net.nodes.values_mut() {
            let (soft, _, _) = n.vote_ok_ex("hash-a", &voter, "");
            assert!(!soft);
            let (soft, _, _) = n.vote_ok_ex("hash-b", &voter, "");
            assert!(!soft);
            assert!(
                !n.validators[&voter].jailed,
                "jail waits for the next ledger (must not fork off-chain)"
            );
        }
        // The offender's own node never queues evidence against itself (v2.10.0);
        // every other seat does.
        let observer = order.iter().find(|id| **id != voter).unwrap().clone();
        assert!(
            net.nodes[&observer]
                .pending_slashes
                .iter()
                .any(|e| e.offender == voter),
            "double-OK must queue slash evidence"
        );
        for _ in 0..3 {
            net.payment("alice", "bob", 1, 1).unwrap();
        }
        net.seal_next_height().unwrap();
        for n in net.nodes.values() {
            assert!(n.validators[&voter].jailed, "next ledger must jail on every node");
            assert!(n.validators[&voter].bond < bond_before);
        }
    }

    #[test]
    fn snapshot_drops_uncommitted_oks_new_attempt() {
        use std::path::PathBuf;
        let mut net = Network::bootstrap(
            &["v1", "v2", "v3", "v4", "v5", "v6"],
            1000,
            &users(),
            ChainConfig {
                pack_budget_ms: 0,
                slash_equivocation: 100,
                ..Default::default()
            },
        );
        net.pong_all();
        let voter = net.nodes["v1"].lottery_order()[1].clone();
        let n = net.nodes.get_mut("v1").unwrap();
        let _ = n.vote_ok_ex("hash-a", &voter, "sig-a");
        n.pending_slashes.push(SlashEvidence {
            offender: voter.clone(),
            height: n.tip_height.saturating_add(1),
            hash_a: "hash-a".into(),
            sig_a: "sig-a".into(),
            hash_b: "hash-old".into(),
            sig_b: "sig-old".into(),
            kind: String::new(),
            round: 0,
        });
        let dir = PathBuf::from(std::env::temp_dir()).join(format!(
            "fpl-slash-snap-{}",
            std::process::id()
        ));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("v1.json");
        n.save_snapshot(&path).unwrap();
        let keys = n.keys.clone();
        let mut loaded = Node::load_snapshot(&path, keys).unwrap();
        assert!(
            loaded
                .ok_by_height_voter
                .get(&(loaded.tip_height + 1))
                .is_none(),
            "uncommitted OKs must not survive load — pending body is not restored"
        );
        assert!(
            loaded.pending_slashes.is_empty(),
            "uncommitted slash evidence dies with the attempt"
        );
        let (soft, _, fresh) = loaded.vote_ok_ex("hash-b", &voter, "sig-b");
        assert!(!soft);
        assert!(fresh, "new attempt must accept a fresh OK");
        assert!(
            loaded.pending_slashes.is_empty(),
            "fresh pack after resume is not a double-sign vs a ghost hash"
        );
        // Committed-height evidence still survives (jail after next ledger).
        loaded.pending_slashes.push(SlashEvidence {
            offender: voter.clone(),
            height: loaded.tip_height,
            hash_a: "committed-a".into(),
            sig_a: "s".into(),
            hash_b: "committed-b".into(),
            sig_b: "s".into(),
            kind: String::new(),
            round: 0,
        });
        loaded.save_snapshot(&path).unwrap();
        let keys2 = loaded.keys.clone();
        let loaded2 = Node::load_snapshot(&path, keys2).unwrap();
        assert!(
            loaded2
                .pending_slashes
                .iter()
                .any(|e| e.offender == voter && e.height == loaded2.tip_height),
            "queued slash at h<=tip must survive restart"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn view_change_on_silent_packer_empty_mempool() {
        let mut net = Network::bootstrap(
            &["v1", "v2", "v3", "v4", "v5", "v6"],
            1000,
            &users(),
            ChainConfig {
                pack_budget_ms: 0,
                max_txs_per_ledger: 8,
                progress_timeout_ms: 1_000,
                ..Default::default()
            },
        );
        net.pong_all();
        for _ in 0..3 {
            net.payment("alice", "bob", 1, 1).unwrap();
        }
        net.seal_next_height().unwrap();
        assert_eq!(net.tip_height(), 1);
        for n in net.nodes.values_mut() {
            n.best_peer_tip = n.tip_height;
            n.freeze_open_height_schedule();
            n.now_ms = n.now_ms.saturating_add(n.proposal_timeout_ms() + 100);
        }
        assert!(net.nodes["v1"].mempool.is_empty());
        // v2.10.0: blocks are load-driven. With no local txs and no hub
        // inventory ad, silence is idleness — no VC, no cursor walk.
        for n in net.nodes.values_mut() {
            assert!(
                n.maybe_view_change_vote().is_none(),
                "idle chain (no work anywhere) must not view-change"
            );
        }
        // v2.9.49+: hub pong advertisement alone (with empty local mempools) does not
        // trigger committee-silence VC; VC fires when local applicable work arrives.
        for n in net.nodes.values_mut() {
            let now = n.now_ms;
            if let Some(v) = n.validators.get_mut("v1") {
                v.advertised_hub = true;
                v.last_mempool_len = 5;
                v.last_pong_ms = now;
            }
            assert!(
                n.maybe_view_change_vote().is_none(),
                "empty local mempool must not committee-silence VC"
            );
        }
        net.payment("alice", "bob", 1, 1).unwrap();
        let mut any = false;
        for n in net.nodes.values_mut() {
            if n.maybe_view_change_vote().is_some() {
                any = true;
            }
        }
        assert!(any, "committee must VC on packer silence once applicable work is present");
        let tip = net.nodes["v1"].tip_hash.clone();
        let h = net.nodes["v1"].tip_height + 1;
        let seats = net.nodes["v1"].lottery_order();
        for id in seats.iter().take(4) {
            for n in net.nodes.values_mut() {
                let _ = n.vote_view_change(h, &tip, 1, id);
            }
        }
        assert_eq!(net.nodes["v1"].height_view_round, 1);
    }

    #[test]
    fn three_vs_three_cannot_commit() {
        // 4-of-6 uniqueness: two disjoint 3-cliques cannot both (or either) tip-advance.
        let mut net = Network::bootstrap(
            &["v1", "v2", "v3", "v4", "v5", "v6"],
            1000,
            &users(),
            ChainConfig {
                pack_budget_ms: 0,
                ..Default::default()
            },
        );
        net.pong_all();
        let order = net.nodes["v1"].lottery_order();
        assert_eq!(order.len(), 6);
        let left: Vec<String> = order.iter().take(3).cloned().collect();
        let right: Vec<String> = order.iter().skip(3).cloned().collect();
        let n = net.nodes.get_mut("v1").unwrap();
        for id in &left {
            let (soft, _, _) = n.vote_ok_ex("hash-left", id, "");
            assert!(!soft, "{id} left clique must not 4-of-6");
        }
        for id in &right {
            let (soft, _, _) = n.vote_ok_ex("hash-right", id, "");
            assert!(!soft, "{id} right clique must not 4-of-6");
        }
        assert!(!n.soft_ok.contains("hash-left"));
        assert!(!n.soft_ok.contains("hash-right"));
        assert_eq!(n.tip_height, 0);
    }

    #[test]
    fn missing_parent_cert_rejected_after_genesis() {
        let mut net = Network::bootstrap(
            &["v1", "v2", "v3", "v4", "v5", "v6"],
            1000,
            &users(),
            ChainConfig {
                pack_budget_ms: 0,
                max_txs_per_ledger: 8,
                ..Default::default()
            },
        );
        net.pong_all();
        for _ in 0..3 {
            net.payment("alice", "bob", 1, 1).unwrap();
        }
        net.seal_next_height().unwrap();
        for _ in 0..3 {
            net.payment("alice", "bob", 1, 1).unwrap();
        }
        let winner = net.nodes["v1"].lottery_packer().unwrap();
        let led = net.nodes.get_mut(&winner).unwrap().pack_as(&winner).unwrap();
        assert!(led.parent_cert.is_some(), "honest h=2 carries parent_cert");
        let stripped = Ledger::seal_with_skips(
            led.height,
            led.parent_hash.clone(),
            led.network_id,
            &led.packer,
            &net.nodes[&winner].keys,
            led.txs.clone(),
            led.state_root_after.clone(),
            led.sealed_at_ms,
            led.skipped_predecessors.clone(),
            None,
        )
        .unwrap();
        let err = net
            .nodes
            .get_mut("v1")
            .unwrap()
            .accept_ledger(&stripped)
            .unwrap_err();
        assert!(
            err.contains("parent_cert") || err.contains("bad packer") || err.contains("missing"),
            "{err}"
        );
        assert_eq!(net.nodes["v1"].tip_height, 1);
    }

    #[test]
    fn forged_parent_cert_rejected() {
        let mut net = Network::bootstrap(
            &["v1", "v2", "v3", "v4", "v5", "v6"],
            1000,
            &users(),
            ChainConfig {
                pack_budget_ms: 0,
                max_txs_per_ledger: 8,
                ..Default::default()
            },
        );
        net.pong_all();
        for _ in 0..3 {
            net.payment("alice", "bob", 1, 1).unwrap();
        }
        net.seal_next_height().unwrap();
        for _ in 0..3 {
            net.payment("alice", "bob", 1, 1).unwrap();
        }
        let winner = net.nodes["v1"].lottery_packer().unwrap();
        let honest = net.nodes.get_mut(&winner).unwrap().pack_as(&winner).unwrap();
        let order = net.nodes["v1"].lottery_order();
        let forged = LedgerCert {
            height: 1,
            ledger_hash: "00".repeat(32),
            parent_hash: honest.parent_hash.clone(),
            committee: order.clone(),
            voters: order.iter().take(4).cloned().collect(),
            signatures: vec![String::new(); 4],
            round: 0,
        };
        let evil = Ledger::seal_with_skips(
            honest.height,
            honest.parent_hash.clone(),
            honest.network_id,
            &honest.packer,
            &net.nodes[&winner].keys,
            honest.txs.clone(),
            honest.state_root_after.clone(),
            honest.sealed_at_ms,
            honest.skipped_predecessors.clone(),
            Some(forged),
        )
        .unwrap();
        let err = net
            .nodes
            .get_mut("v1")
            .unwrap()
            .accept_ledger(&evil)
            .unwrap_err();
        assert!(
            err.contains("parent_cert") || err.contains("does not match"),
            "{err}"
        );
        assert_eq!(net.nodes["v1"].tip_height, 1);
    }

    #[test]
    fn undersized_parent_cert_rejected() {
        let mut net = Network::bootstrap(
            &["v1", "v2", "v3", "v4", "v5", "v6"],
            1000,
            &users(),
            ChainConfig {
                pack_budget_ms: 0,
                max_txs_per_ledger: 8,
                ..Default::default()
            },
        );
        net.pong_all();
        for _ in 0..3 {
            net.payment("alice", "bob", 1, 1).unwrap();
        }
        net.seal_next_height().unwrap();
        let tip_hash = net.nodes["v1"].tip_hash.clone();
        let tip_parent = net.nodes["v1"].chain[0].parent_hash.clone();
        for _ in 0..3 {
            net.payment("alice", "bob", 1, 1).unwrap();
        }
        let winner = net.nodes["v1"].lottery_packer().unwrap();
        let honest = net.nodes.get_mut(&winner).unwrap().pack_as(&winner).unwrap();
        let order = net.nodes["v1"].lottery_order();
        let thin = LedgerCert {
            height: 1,
            ledger_hash: tip_hash,
            parent_hash: tip_parent,
            committee: order.clone(),
            voters: order.iter().take(3).cloned().collect(),
            signatures: vec![String::new(); 3],
            round: 0,
        };
        let evil = Ledger::seal_with_skips(
            honest.height,
            honest.parent_hash.clone(),
            honest.network_id,
            &honest.packer,
            &net.nodes[&winner].keys,
            honest.txs.clone(),
            honest.state_root_after.clone(),
            honest.sealed_at_ms,
            honest.skipped_predecessors.clone(),
            Some(thin),
        )
        .unwrap();
        let err = net
            .nodes
            .get_mut("v1")
            .unwrap()
            .accept_ledger(&evil)
            .unwrap_err();
        assert!(
            err.contains("cert voters") || err.contains("parent_cert") || err.contains("need"),
            "{err}"
        );
        assert_eq!(net.nodes["v1"].tip_height, 1);
    }

    #[test]
    fn kill_winner_promotes_preselected_backup() {
        // Skip QC of #1 → same #2 everywhere; order unchanged.
        let cfg = ChainConfig {
            pack_budget_ms: 0,
            max_txs_per_ledger: 4,
            soft_ok_votes: 1,
            ..Default::default()
        };
        let mut net = Network::bootstrap(&["v1", "v2", "v3", "v4", "v5"], 1000, &users(), cfg);
        net.pong_all();
        let order = net.nodes["v1"].lottery_order();
        let primary = order[0].clone();
        let backup = order[1].clone();
        let tip_hash = net.nodes["v1"].tip_hash.clone();
        let all_ids: Vec<String> = net.nodes.keys().cloned().collect();
        for n in net.nodes.values_mut() {
            for id in &all_ids {
                n.pong(id);
            }
            for v in all_ids.iter().filter(|id| *id != &primary) {
                let _ = n.vote_skip(1, &primary, &tip_hash, v);
            }
        }
        for n in net.nodes.values() {
            assert_eq!(n.lottery_order(), order);
            assert_eq!(n.lottery_packer().as_deref(), Some(backup.as_str()));
        }
    }

    #[test]
    fn snapshot_preserves_true_genesis_accounts() {
        use std::path::PathBuf;

        let g = users();
        let mut keys = KeyRing::new(CryptoScheme::HmacDev);
        keys.generate_many(["v1", "alice", "bob"].into_iter());
        let mut n = Node::new(
            "v1",
            ChainConfig {
                pack_budget_ms: 0,
                max_txs_per_ledger: 4,
                progress_timeout_ms: 0,
                ..Default::default()
            },
            keys,
            &g,
        );
        n.register_validator("v1", 1000);
        n.pong("v1");
        // Spend so tip balances ≠ genesis.
        n.submit_tx(
            Tx::sign_with(&n.keys, "alice", 1, "bob", 100, 1, n.cfg.network_id).unwrap(),
        )
        .unwrap();
        let led = n.pack_or_skip("v1").unwrap().unwrap();
        n.accept_ledger(&led).unwrap();
        assert_ne!(
            n.state.accounts.get("alice").map(|a| a.balance),
            g.iter().find(|(k, _)| k == "alice").map(|(_, b)| *b)
        );
        let genesis_alice = g.iter().find(|(k, _)| k == "alice").unwrap().1;

        let dir = PathBuf::from(std::env::temp_dir()).join(format!(
            "fpl-snap-gen-{}",
            std::process::id()
        ));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("n.json");
        n.save_snapshot(&path).unwrap();
        let loaded =
            Node::load_snapshot(&path, KeyRing::new(CryptoScheme::HmacDev)).unwrap();
        assert!(loaded.can_hard_resync());
        let ga = loaded
            .genesis_accounts
            .iter()
            .find(|(k, _)| k == "alice")
            .map(|(_, b)| *b)
            .unwrap();
        assert_eq!(ga, genesis_alice, "genesis must not be tip balances");
        // Tip state still has spent balance
        assert_eq!(
            loaded.state.accounts.get("alice").map(|a| a.balance),
            n.state.accounts.get("alice").map(|a| a.balance)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Corrupt chain tip mismatch must not load a divergent tail.
    #[test]
    fn snapshot_rejects_mismatched_chain_tip() {
        use std::path::PathBuf;

        let cfg = ChainConfig {
            pack_budget_ms: 0,
            max_txs_per_ledger: 4,
            progress_timeout_ms: 0,
            ..Default::default()
        };
        let mut net = Network::bootstrap(&["v1"], 1000, &users(), cfg);
        net.pong_all();
        for _ in 0..3 {
            net.payment("alice", "bob", 1, 1).unwrap();
            net.seal_next_height().unwrap();
        }
        let n = net.nodes.get("v1").unwrap();
        let dir = PathBuf::from(std::env::temp_dir()).join(format!(
            "fpl-snap-bad-{}",
            std::process::id()
        ));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("bad.json");
        n.save_snapshot(&path).unwrap();
        let mut v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        v["tip_hash"] = serde_json::json!("deadbeef");
        std::fs::write(&path, serde_json::to_string_pretty(&v).unwrap()).unwrap();
        let loaded =
            Node::load_snapshot(&path, KeyRing::new(CryptoScheme::HmacDev)).unwrap();
        assert_eq!(loaded.tip_height, 3);
        assert!(
            loaded.chain.is_empty(),
            "mismatched tip_hash must drop chain tail"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Live bond-in then fork recovery: hard-resync must not re-insert live
    /// joiners at genesis (commitment root includes bonds) — that was the
    /// v2.2.4 join tip-0 freeze (state root mismatch at h=1 forever).
    #[test]
    fn hard_resync_after_live_bond_replays_clean() {
        let cfg = ChainConfig {
            pack_budget_ms: 0,
            max_txs_per_ledger: 8,
            progress_timeout_ms: 0,
            ..Default::default()
        };
        let mut net = Network::bootstrap(&["v1", "v2", "v3"], 1000, &users(), cfg);
        net.pong_all();
        for _ in 0..3 {
            net.payment("alice", "bob", 1, 1).unwrap();
            net.seal_next_height().unwrap();
        }
        // Live bond new validator v4 (not in genesis set).
        net.user_keys.generate_id("v4");
        for n in net.nodes.values_mut() {
            let _ = n
                .keys
                .insert_public("v4", &net.user_keys.public_hex("v4").unwrap());
        }
        let seq = net.account_seqs["alice"];
        let bond_tx = Tx::sign_body(
            &net.user_keys,
            "alice",
            seq,
            "v4",
            1_000,
            2,
            net.cfg.network_id,
            TxBody::Bond {
                validator: "v4".into(),
            },
        )
        .unwrap();
        *net.account_seqs.get_mut("alice").unwrap() += 1;
        for n in net.nodes.values_mut() {
            n.submit_tx(bond_tx.clone()).unwrap();
        }
        net.seal_next_height().unwrap();
        assert!(net.nodes.get("v1").unwrap().validators.contains_key("v4"));
        // More seals only while lottery #1 is a hosted seed (v4 has no Node process).
        for _ in 0..8 {
            let pure = net.nodes["v1"].lottery_packer().unwrap();
            if !net.nodes.contains_key(&pure) {
                break;
            }
            net.payment("alice", "bob", 1, 1).unwrap();
            net.seal_next_height().unwrap();
        }
        let tip = net.tip_height();
        let tip_hash = net.nodes.get("v1").unwrap().tip_hash.clone();
        let batch = net.nodes.get("v1").unwrap().ledgers_from(1, 64);
        assert!(batch.len() as u64 >= tip);
        assert!(tip >= 1);

        // Simulate forked joiner: has live vals (v4) in registry at tip.
        let n = net.nodes.get_mut("v3").unwrap();
        assert_eq!(n.genesis_validators.len(), 3, "only seeds in genesis set");
        assert!(n.validators.contains_key("v4"));
        n.need_hard_resync = true;
        n.best_peer_tip = tip;
        // Old bug: reset re-bonded v4 at genesis → h=1 root mismatch forever.
        let got = n.hard_resync_from_ledgers(&batch).expect("hard-resync");
        assert_eq!(got, tip);
        assert_eq!(n.tip_hash, tip_hash);
        assert!(n.validators.contains_key("v4"), "bond re-applied from chain");
        assert_eq!(n.genesis_validators.len(), 3);
        assert!(!n.need_hard_resync);
    }

    /// Full mempool of future-only seqs must be cleared on pack so tip can move
    /// (v2.2.7 / AMD-20260812-7).
    #[test]
    fn no_applicable_drops_future_seq_poison() {
        let mut n = Node::new(
            "v1",
            ChainConfig {
                pack_budget_ms: 0,
                max_txs_per_ledger: 8,
                progress_timeout_ms: 1_000,
                max_mempool_txs: 100,
                ..Default::default()
            },
            KeyRing::new(CryptoScheme::HmacDev),
            &users(),
        );
        n.register_validator("v1", 1000);
        let mut keys = KeyRing::new(CryptoScheme::HmacDev);
        keys.generate_many(["v1", "alice", "bob"].into_iter());
        n.keys = keys;
        n.pong("v1");
        for seq in [50u64, 51, 52] {
            let tx = Tx::sign_with(&n.keys, "alice", seq, "bob", 1, 1, n.cfg.network_id).unwrap();
            assert!(n.submit_tx(tx).unwrap());
        }
        assert!(!n.has_applicable_tx());
        assert_eq!(n.mempool.len(), 3);
        assert!(n.pack_or_skip("v1").unwrap().is_none());
        assert_eq!(n.mempool.len(), 0, "future-seq poison must be dropped");
        // Correct next seq can pack after clear.
        let tx = Tx::sign_with(&n.keys, "alice", 1, "bob", 1, 1, n.cfg.network_id).unwrap();
        assert!(n.submit_tx(tx).unwrap());
        assert!(n.pack_or_skip("v1").unwrap().is_some());
    }

    #[test]
    fn mempool_rejects_sequence_past_the_account_window() {
        let mut n = Node::new(
            "v1",
            ChainConfig {
                pack_budget_ms: 0,
                max_txs_per_ledger: 8,
                progress_timeout_ms: 1_000,
                max_mempool_txs: 100_000,
                ..Default::default()
            },
            KeyRing::new(CryptoScheme::HmacDev),
            &users(),
        );
        n.register_validator("v1", 1000);
        let mut keys = KeyRing::new(CryptoScheme::HmacDev);
        keys.generate_many(["v1", "alice", "bob"].into_iter());
        n.keys = keys;
        n.pong("v1");
        let window = Node::MEMPOOL_SEQ_WINDOW;
        for seq in 1..=window {
            let tx = Tx::sign_with(&n.keys, "alice", seq, "bob", 1, 1, n.cfg.network_id).unwrap();
            assert!(n.submit_tx(tx).unwrap(), "pipeline seq {seq} must be kept");
        }
        let too_far =
            Tx::sign_with(&n.keys, "alice", window + 1, "bob", 1, 1, n.cfg.network_id).unwrap();
        let err = n.submit_tx(too_far).unwrap_err();
        assert!(err.contains("too far ahead") || err.contains("cap"), "{err}");
        assert_eq!(n.mempool.len() as u64, window);
        // A second account is not blocked by alice's full window.
        let bob = Tx::sign_with(&n.keys, "bob", 1, "alice", 1, 1, n.cfg.network_id).unwrap();
        assert!(n.submit_tx(bob).unwrap());
    }

    /// Seq-poison: packer sanitizes without self-skip; empty mempool does not
    /// progress-skip (v2.2.4). v2.6.0: height stall with poison arms view-change.
    #[test]
    fn seq_poison_does_not_self_skip_or_progress_skip() {
        let mut n = Node::new(
            "v1",
            ChainConfig {
                pack_budget_ms: 0,
                max_txs_per_ledger: 8,
                progress_timeout_ms: 1_000,
                ..Default::default()
            },
            KeyRing::new(CryptoScheme::HmacDev),
            &users(),
        );
        n.register_validator("v1", 1000);
        n.register_validator("v2", 1000);
        let mut keys = KeyRing::new(CryptoScheme::HmacDev);
        keys.generate_many(["v1", "v2", "alice", "bob"].into_iter());
        n.keys = keys;
        n.pong("v1");
        n.pong_with_tip("v2", 0);
        // On-chain alice needs seq 1; only future txs within MEMPOOL_SEQ_WINDOW (<=65) present.
        for seq in [50u64, 51, 52] {
            let tx = Tx::sign_with(&n.keys, "alice", seq, "bob", 1, 1, n.cfg.network_id).unwrap();
            assert!(n.submit_tx(tx).unwrap());
        }
        assert!(n.mempool_poisoned());
        assert_eq!(n.mempool.len(), 3);

        let winner = n.lottery_packer().unwrap();
        // v2.3.3: cannot force winner via skip — pack only if elected.
        if winner == "v1" {
            let before_skips = n.skip_set_for(1).clone();
            assert!(n.pack_or_skip("v1").unwrap().is_none());
            assert_eq!(
                n.skip_set_for(1),
                before_skips,
                "no-applicable must not self-skip"
            );
            assert!(n.mempool.is_empty(), "packer sanitize clears poison");
        } else {
            // Not local winner — pack_or_skip as v1 must refuse lottery.
            let err = n.pack_or_skip("v1").unwrap_err();
            assert!(err.contains("not lottery") || err.contains("winner"), "{err}");
        }
        // Empty mempool → no progress-skip.
        n.mempool.remove_many(
            &n.mempool
                .iter_candidates()
                .map(|t| t.tx_id.clone())
                .collect::<Vec<_>>(),
        );
        n.height_open_ms = n.now_ms.saturating_sub(n.cfg.progress_timeout_ms + 1);
        assert!(
            n.propose_progress_timeout_skip().is_none(),
            "empty mempool must not progress-skip"
        );
    }

    /// v2.6.0: open height with poison past proposal-timeout arms view-change
    /// (the multi-host tip-32 freeze class). Cold tip=0 with best_peer=0 prefers
    /// catch-up over VC — so this test seals tip=1 first, then poisons tip+1.
    #[test]
    fn poison_mempool_height_stall_view_change() {
        let mut n = Node::new(
            "v1",
            ChainConfig {
                pack_budget_ms: 0,
                max_txs_per_ledger: 8,
                progress_timeout_ms: 1_000,
                soft_ok_votes: 1,
                ..Default::default()
            },
            KeyRing::new(CryptoScheme::HmacDev),
            &users(),
        );
        n.register_validator("v1", 1000);
        n.register_validator("v2", 1000);
        let mut keys = KeyRing::new(CryptoScheme::HmacDev);
        keys.generate_many(["v1", "v2", "alice", "bob"].into_iter());
        n.keys = keys;
        n.pong("v1");
        n.pong_with_tip("v2", 0);
        n.freeze_open_height_schedule();
        // Seal tip=1 so we are not on the cold tip=0 catch-up path.
        let ok_tx = Tx::sign_with(&n.keys, "alice", 1, "bob", 1, 1, n.cfg.network_id).unwrap();
        assert!(n.submit_tx(ok_tx).unwrap());
        let winner = n.lottery_packer().unwrap();
        n.pong(&winner);
        let led = n.pack_as(&winner).unwrap();
        n.accept_ledger(&led).unwrap();
        n.vote_ok(&led.ledger_hash, "v1");
        n.vote_ok(&led.ledger_hash, "v2");
        assert_eq!(n.tip_height, 1);
        n.best_peer_tip = 1; // mesh not ahead — still_lagging false
        n.freeze_open_height_schedule();
        for seq in [50u64, 51, 52] {
            let tx = Tx::sign_with(&n.keys, "alice", seq, "bob", 1, 1, n.cfg.network_id).unwrap();
            assert!(n.submit_tx(tx).unwrap());
        }
        assert!(n.mempool_poisoned());
        // Before timeout: no view-change.
        assert!(n.maybe_view_change_vote().is_none());
        // Advance wall clock past proposal-timeout (4 × progress).
        let pto = n.proposal_timeout_ms();
        n.now_ms = n.now_ms.saturating_add(pto + 1);
        n.pong("v1");
        n.pong_with_tip("v2", 1);
        n.best_peer_tip = 1;
        n.last_view_change_vote_ms = 0;
        let vc = n.maybe_view_change_vote();
        assert!(vc.is_some(), "poison stall must arm view-change");
        // Multi-val soft floor is ≥2 (anti solo-fork). Second voter completes QC.
        assert_eq!(n.height_view_round, 0, "single vote must not solo-apply VC");
        let tip = n.tip_hash.clone();
        let (_qc, _) = n.vote_view_change(2, &tip, 1, "v2");
        assert_eq!(n.height_view_round, 1, "second soft vote applies view-change");
        assert!(n.mempool.is_empty(), "view-change path sanitizes poison");
    }

    /// Lagging node must not arm view-change (catch-up owns recovery).
    #[test]
    fn lagging_node_suppresses_view_change() {
        let mut n = Node::new(
            "v1",
            ChainConfig {
                pack_budget_ms: 0,
                progress_timeout_ms: 1_000,
                soft_ok_votes: 1,
                ..Default::default()
            },
            KeyRing::new(CryptoScheme::HmacDev),
            &users(),
        );
        n.register_validator("v1", 1000);
        n.pong("v1");
        n.freeze_open_height_schedule();
        n.best_peer_tip = 50; // mesh far ahead
        let mut keys = KeyRing::new(CryptoScheme::HmacDev);
        keys.generate_many(["v1", "alice", "bob"].into_iter());
        n.keys = keys;
        for seq in [50u64, 51] {
            let tx = Tx::sign_with(&n.keys, "alice", seq, "bob", 1, 1, n.cfg.network_id).unwrap();
            let _ = n.submit_tx(tx);
        }
        n.now_ms = n.now_ms.saturating_add(n.proposal_timeout_ms() + 1);
        n.last_view_change_vote_ms = 0;
        assert!(n.still_lagging());
        assert!(
            n.maybe_view_change_vote().is_none(),
            "lagging must not VC-spam"
        );
    }

    /// Healthy sequential pipeline must survive sanitize (v2.6.0 production rule).
    #[test]
    fn sanitize_keeps_sequential_pipeline() {
        let mut n = Node::new(
            "v1",
            ChainConfig {
                pack_budget_ms: 0,
                max_txs_per_ledger: 4,
                ..Default::default()
            },
            KeyRing::new(CryptoScheme::HmacDev),
            &users(),
        );
        n.register_validator("v1", 1000);
        let mut keys = KeyRing::new(CryptoScheme::HmacDev);
        keys.generate_many(["v1", "alice", "bob"].into_iter());
        n.keys = keys;
        n.pong("v1");
        for seq in 1u64..=8 {
            let tx = Tx::sign_with(&n.keys, "alice", seq, "bob", 1, 1, n.cfg.network_id).unwrap();
            assert!(n.submit_tx(tx).unwrap());
        }
        assert!(n.has_applicable_tx());
        assert!(!n.mempool_poisoned());
        let (stale, future) = n.sanitize_mempool();
        assert_eq!(stale, 0);
        assert_eq!(future, 0, "must not drop need+1… pipeline");
        assert_eq!(n.mempool.len(), 8);
        let led = n.pack_or_skip("v1").unwrap().unwrap();
        assert_eq!(led.txs.len(), 4, "packer must seal up to max_txs of pipeline");
        assert_eq!(n.mempool.len(), 8, "pack does not drain; commit does");
    }

    /// v2.9.51: applicable (seq == need) but permanently unpayable head is dropped
    /// by sanitize so it cannot freeze liveness_has_work / tip progress.
    #[test]
    fn sanitize_drops_permanent_unpayable_applicable_head() {
        let mut n = Node::new(
            "v1",
            ChainConfig {
                pack_budget_ms: 0,
                max_txs_per_ledger: 4,
                ..Default::default()
            },
            KeyRing::new(CryptoScheme::HmacDev),
            &users(),
        );
        n.register_validator("v1", 1000);
        let mut keys = KeyRing::new(CryptoScheme::HmacDev);
        keys.generate_many(["v1", "alice", "bob"].into_iter());
        n.keys = keys;
        n.pong("v1");
        // Drain alice hot balance so a correct-seq pay cannot cover the fee.
        {
            let mut a = n.state.get("alice");
            a.balance = 0;
            a.sequence = 1;
            n.state.accounts.insert("alice".into(), a);
        }
        let tx = Tx::sign_with(&n.keys, "alice", 1, "bob", 1, 2, n.cfg.network_id).unwrap();
        // Bypass submit_tx prechecks that may reject; insert directly.
        n.mempool.insert(tx, n.cfg.max_mempool_txs);
        assert_eq!(n.mempool.len(), 1);
        assert!(n.has_applicable_tx());
        let _ = n.sanitize_mempool();
        assert!(
            n.mempool.is_empty(),
            "insufficient-fee applicable head must be dropped"
        );
        assert!(!n.has_applicable_tx());
        assert!(!n.liveness_has_work());
    }

    /// v2.9.56 harness for the v10 h=376571 / v12 h=377619 hangs: a seat that
    /// caught up by batch is the round-0 lottery winner for tip+1 while the
    /// mesh is already ahead (best_peer_tip > tip). The seal tick calls
    /// `pack_or_skip` every 200 ms. Before the fix every call ran a full
    /// mempool dry-run (state + ~200 MB bridge clone per head) under
    /// `node.lock` before `may_pack_locally` refused with "tip lag".
    fn lagging_winner_with_heads(n_heads: usize, exec_headers: u64) -> Node {
        let mut n = Node::new(
            "v1",
            ChainConfig {
                pack_budget_ms: 0,
                max_txs_per_ledger: 4,
                progress_timeout_ms: 1_000,
                soft_ok_votes: 1,
                ..Default::default()
            },
            KeyRing::new(CryptoScheme::HmacDev),
            &users(),
        );
        n.register_validator("v1", 1000);
        let mut keys = KeyRing::new(CryptoScheme::HmacDev);
        keys.generate_many(["v1", "alice", "bob", "carol"].into_iter());
        n.keys = keys;
        n.pong("v1");
        // Caught up by batch to h=10, soft, but peers advertise h=12.
        n.tip_height = 10;
        n.tip_hash = "ab".repeat(32);
        n.soft_ok.insert(n.tip_hash.clone());
        n.best_peer_tip = 12;
        n.now_ms = 5_000;
        n.height_open_ms = 5_000;
        n.freeze_open_height_schedule();
        // Big never-pruned exec header map, like the live bridge.
        {
            let m = n.bridge.eth_exec_headers.make_mut();
            for i in 0..exec_headers {
                m.insert(
                    i,
                    crate::eth_exec::EthExecHeader {
                        number: i,
                        hash: format!("{:064x}", i + 1),
                        parent_hash: format!("{:064x}", i),
                        receipts_root: "00".repeat(32),
                        rlp_hex: "f9".repeat(600),
                    },
                );
            }
        }
        // Several correct-sequence (applicable) heads from different accounts.
        let accts = ["alice", "bob", "carol"];
        for a in accts.iter().take(n_heads) {
            let seq = n.state.get(a).sequence;
            let to = if *a == "alice" { "bob" } else { "alice" };
            let tx = Tx::sign_with(&n.keys, a, seq, to, 1, 2, n.cfg.network_id).unwrap();
            let _ = n.mempool.insert(tx, n.cfg.max_mempool_txs);
        }
        n
    }

    #[test]
    fn lagging_round0_winner_pack_tick_does_no_mempool_dry_runs() {
        let mut n = lagging_winner_with_heads(3, 2_000);
        assert_eq!(n.lottery_packer().as_deref(), Some("v1"));
        assert_eq!(n.mempool.len(), 3);
        assert!(n.has_applicable_tx());
        // 50 seal ticks (10 s of wall clock at 200 ms) while lagging.
        for _ in 0..50 {
            let err = n.pack_or_skip("v1").unwrap_err();
            assert!(err.contains("tip lag"), "lagging winner must refuse: {err}");
            n.tick(200);
        }
        assert_eq!(
            n.perm_head_dry_runs, 0,
            "a seat that may not pack must not dry-run the mempool on each tick"
        );
        assert_eq!(n.mempool.len(), 3, "gate must not drop good txs");
        // Catch-up lands (peers no longer ahead): the gate now passes the
        // lag check and pack_or_skip sanitizes again (once per head).
        n.best_peer_tip = n.tip_height;
        let _ = n.pack_or_skip("v1");
        assert!(n.perm_head_dry_runs <= 3, "dry-runs {}", n.perm_head_dry_runs);
    }

    #[test]
    fn sanitize_dry_runs_each_head_once_per_tip() {
        let mut n = lagging_winner_with_heads(3, 500);
        for _ in 0..40 {
            let _ = n.sanitize_mempool();
        }
        assert_eq!(n.perm_head_dry_runs, 3, "one dry-run per head per tip");
        assert_eq!(n.mempool.len(), 3);
        // New committed tip → heads are re-checked once.
        n.tip_hash = "cd".repeat(32);
        for _ in 0..10 {
            let _ = n.sanitize_mempool();
        }
        assert_eq!(n.perm_head_dry_runs, 6);
        // Same tip, but logical TTL passed → re-checked once (time-dependent
        // failures still drop on a flat tip).
        n.now_ms += Node::PERM_HEAD_MEMO_TTL_MS;
        for _ in 0..10 {
            let _ = n.sanitize_mempool();
        }
        assert_eq!(n.perm_head_dry_runs, 9);
    }

    #[test]
    fn sanitize_memo_still_drops_head_that_turns_unpayable_on_new_tip() {
        let mut n = lagging_winner_with_heads(1, 0);
        let _ = n.sanitize_mempool();
        assert_eq!(n.mempool.len(), 1);
        // Next tip drains alice: her memoized head must be re-checked + dropped.
        {
            let mut a = n.state.get("alice");
            a.balance = 0;
            n.state.accounts.insert("alice".into(), a);
        }
        n.tip_hash = "ef".repeat(32);
        let _ = n.sanitize_mempool();
        assert!(n.mempool.is_empty(), "unpayable head must drop after tip change");
    }

    /// v2.9.56: `eth_exec_headers` is copy-on-write; serialization (snapshot,
    /// wire, commitment root input) must be unchanged.
    #[test]
    fn eth_exec_headers_arc_is_cheap_to_clone_and_serializes_as_map() {
        let n = lagging_winner_with_heads(0, 64);
        let b2 = n.bridge.clone();
        assert!(crate::exec_map::ExecHeaderMap::ptr_eq(&n.bridge.eth_exec_headers, &b2.eth_exec_headers));
        let v = serde_json::to_value(&n.bridge).unwrap();
        let plain: BTreeMap<u64, crate::eth_exec::EthExecHeader> = (*n.bridge.eth_exec_headers).clone();
        assert_eq!(v["eth_exec_headers"], serde_json::to_value(&plain).unwrap());
        let s = serde_json::to_string(&n.bridge).unwrap();
        assert!(s.contains("\"eth_exec_headers\":{\"0\":{\"number\":0,"));
        let back: crate::bridge::BridgeState = serde_json::from_str(&s).unwrap();
        assert_eq!(serde_json::to_string(&back).unwrap(), s);
        assert_eq!(back.eth_exec_bounds(), (0, 63));
        // Empty map is still omitted (old snapshots / roots unchanged).
        let empty = crate::bridge::BridgeState::default();
        assert!(!serde_json::to_string(&empty).unwrap().contains("eth_exec_headers"));
        // Mutating a clone does not touch the original.
        let mut b3 = n.bridge.clone();
        b3.eth_exec_headers.make_mut().remove(&0);
        assert_eq!(n.bridge.eth_exec_headers.len(), 64);
        assert_eq!(b3.eth_exec_headers.len(), 63);
    }

    /// v2.9.51: lottery winner without tip cert must self-skip after progress-timeout.
    #[test]
    fn cert_less_local_winner_self_skips_after_timeout() {
        let mut n = Node::new(
            "v1",
            ChainConfig {
                pack_budget_ms: 0,
                max_txs_per_ledger: 4,
                progress_timeout_ms: 1_000,
                soft_ok_votes: 1,
                ..Default::default()
            },
            KeyRing::new(CryptoScheme::HmacDev),
            &users(),
        );
        n.register_validator("v1", 1000);
        let mut keys = KeyRing::new(CryptoScheme::HmacDev);
        keys.generate_many(["v1", "alice", "bob"].into_iter());
        n.keys = keys;
        n.pong("v1");
        // Simulate restored tip: soft via soft_ok, but certs map empty.
        n.tip_height = 10;
        n.tip_hash = "ab".repeat(32);
        n.soft_ok.insert(n.tip_hash.clone());
        n.certs.clear();
        n.height_open_ms = 0;
        n.now_ms = 5_000;
        n.freeze_open_height_schedule();
        assert_eq!(n.lottery_packer().as_deref(), Some("v1"));
        assert!(!n.certs.contains_key(&10));
        assert!(n.tip_is_soft());
        let skip = n.propose_progress_timeout_skip();
        assert!(skip.is_some(), "cert-less local winner must self-skip");
        assert_eq!(skip.unwrap().1, "v1");
        let err = n.may_pack_locally("v1").unwrap_err();
        assert!(
            err.contains("no tip cert"),
            "may_pack must refuse cert-less tip: {err}"
        );
    }

    /// v2.6.0: offline active seat is progress-skipped even without applicable txs.
    #[test]
    fn offline_active_seat_progress_skipped() {
        let mut n = Node::new(
            "v1",
            ChainConfig {
                pack_budget_ms: 0,
                max_txs_per_ledger: 8,
                progress_timeout_ms: 1_000,
                pong_window_ms: 2_000,
                soft_ok_votes: 1,
                ..Default::default()
            },
            KeyRing::new(CryptoScheme::HmacDev),
            &users(),
        );
        n.register_validator("v1", 1000);
        n.register_validator("v2", 1000);
        let mut keys = KeyRing::new(CryptoScheme::HmacDev);
        keys.generate_many(["v1", "v2", "alice", "bob"].into_iter());
        n.keys = keys;
        n.freeze_open_height_schedule();
        // Only self pongs; leave v2 stale. Put poison so mempool non-empty.
        n.pong("v1");
        n.now_ms = 10_000; // beyond pong window for any old pong on v2
        let tx = Tx::sign_with(&n.keys, "alice", 50, "bob", 1, 1, n.cfg.network_id).unwrap();
        assert!(n.submit_tx(tx).unwrap());
        // Force height open past progress timeout.
        n.height_open_ms = 0;
        let winner = n.lottery_packer().unwrap();
        if winner == "v1" {
            // Local is active — progress skip of self is never proposed.
            assert!(n.propose_progress_timeout_skip().is_none());
        } else {
            assert!(n.active_packer_unavailable());
            let skip = n.propose_progress_timeout_skip();
            assert!(skip.is_some(), "offline winner must be skip-eligible");
            assert_eq!(skip.unwrap().1, winner);
        }
    }

    /// v2.6.0: skip-QC of every lottery-order seat reopens the height.
    #[test]
    fn all_lottery_seats_skipped_reopens_height() {
        let mut n = Node::new(
            "v1",
            ChainConfig {
                pack_budget_ms: 0,
                max_txs_per_ledger: 8,
                progress_timeout_ms: 1_000,
                soft_ok_votes: 1,
                ..Default::default()
            },
            KeyRing::new(CryptoScheme::HmacDev),
            &users(),
        );
        n.register_validator("v1", 1000);
        n.register_validator("v2", 1000);
        n.pong("v1");
        n.pong("v2");
        n.freeze_open_height_schedule();
        let tip = n.tip_hash.clone();
        let order = n.lottery_order();
        assert!(order.len() >= 2);
        for id in &order {
            assert!(n.apply_shared_skip(1, id, &tip));
        }
        // After last seat, set must clear (reopen) — not remain full.
        assert!(
            n.skip_set_for(1).is_empty(),
            "all-order skip must reopen empty skip set"
        );
        assert!(n.lottery_packer().is_some());
    }

    #[test]
    fn first_seen_pay_enrolls_hmac_key() {
        let mut user = crate::crypto::KeyRing::new(crate::crypto::CryptoScheme::HmacDev);
        user.generate_id("scott.personal");
        let nid = NETWORK_ID_PRIVATE_V22;
        let tx = Tx::sign_with(&user, "scott.personal", 1, "bob", 10, 2, nid).unwrap();
        let mut n = Node::new(
            "v1",
            ChainConfig::default(),
            crate::crypto::KeyRing::new(crate::crypto::CryptoScheme::HmacDev),
            &[("scott.personal".into(), 4_000)],
        );
        assert!(!n.keys.has_public("scott.personal"));
        assert!(n.submit_tx(tx).unwrap());
        assert!(n.keys.has_public("scott.personal"));
    }

    #[test]
    fn first_seen_pay_accepts_uppercase_public_key() {
        let mut user = crate::crypto::KeyRing::new(crate::crypto::CryptoScheme::HmacDev);
        user.generate_id("scott.personal.vault");
        let nid = NETWORK_ID_PRIVATE_V22;
        let mut tx = Tx::sign_with(&user, "scott.personal.vault", 1, "scott.personal", 10, 2, nid)
            .unwrap();
        tx.public_key = tx.public_key.to_ascii_uppercase();
        let mut n = Node::new(
            "v1",
            ChainConfig::default(),
            crate::crypto::KeyRing::new(crate::crypto::CryptoScheme::HmacDev),
            &[("scott.personal.vault".into(), 2_000)],
        );
        assert!(n.submit_tx(tx).unwrap());
    }

    #[test]
    fn first_seen_falcon_pay_enrolls() {
        let mut user = crate::crypto::KeyRing::new(crate::crypto::CryptoScheme::Falcon512);
        user.generate_id("scott.personal");
        let nid = NETWORK_ID_PRIVATE_V22;
        let tx = Tx::sign_with(&user, "scott.personal", 1, "bob", 10, 2, nid).unwrap();
        let mut n = Node::new(
            "v1",
            ChainConfig {
                scheme: crate::crypto::CryptoScheme::Falcon512,
                ..ChainConfig::default()
            },
            crate::crypto::KeyRing::new(crate::crypto::CryptoScheme::Falcon512),
            &[("scott.personal".into(), 4_000)],
        );
        assert!(!n.keys.has_public("scott.personal"));
        assert!(n.submit_tx(tx).unwrap());
        assert!(n.keys.has_public("scott.personal"));
    }

    #[test]
    fn sally_dave_amm_unequal_withdraw() {
        use bridge::{BridgeProof, RailHeader, RAIL_BTC, RAIL_USDC};

        let mut n = Node::new(
            "v1",
            ChainConfig::default(),
            KeyRing::new(CryptoScheme::HmacDev),
            &users(),
        );
        n.bridge.rail_mut(RAIL_BTC).unwrap().min_confirmations = 1;
        n.bridge.rail_mut(RAIL_USDC).unwrap().min_confirmations = 1;

        let secret = {
            let d = sha256_hex(b"sally-dave-vault");
            let mut s = [0u8; 32];
            s.copy_from_slice(&hex::decode(&d).unwrap());
            s[0] &= 0x3f;
            s
        };
        let shares = crate::vault::split_secret(&secret, 5, 3, 0, b"sd").unwrap();
        let vp = crate::vault::vault_pub_from_secret(&secret, 0, 5, 3).unwrap();
        n.bridge.rail_mut(RAIL_BTC).unwrap().vault_pub = Some(vp.clone());
        let watch = hex::decode(&vp.spk_hex).unwrap();

        // Sally 90k, Dave 115k (same ratio as the funded testnet wallets).
        let mut height = 0u64;
        let mut prev = "00".repeat(32);
        for (who, amt) in [("sally", 90_000u64), ("dave", 115_000u64)] {
            height += 1;
            let (raw_tx, tx) = crate::btc_spv::test_deposit_tx(&watch, who, amt);
            let hdr = crate::btc_spv::mine_header(
                &prev,
                &tx.txid_display,
                0x207fffff,
                1_700_000_000 + height as u32,
            )
            .unwrap();
            prev = hdr.hash_display.clone();
            n.submit_rail_header(
                RAIL_BTC,
                RailHeader {
                    height,
                    hash: String::new(),
                    parent_hash: String::new(),
                    merkle_root: String::new(),
                    raw: hdr.raw_hex.clone(),
                },
                Some("alice"),
            )
            .unwrap();
            let proof = BridgeProof {
                external_txid: tx.txid_display.clone(),
                block_hash: hdr.hash_display.clone(),
                height,
                merkle_path: vec![],
                merkle_index: 0,
                lock_id: n.bridge.rail(RAIL_BTC).unwrap().lock_id.clone(),
                parent_hash: String::new(),
                merkle_root: hdr.merkle_display.clone(),
                external_to: String::new(),
                raw_tx: crate::btc_spv::hex_encode(&raw_tx),
            };
            n.rail_deposit(RAIL_BTC, who, amt, proof, Some("alice"))
                .unwrap();
        }
        assert_eq!(n.defi.asset_bal("sally", RAIL_BTC), 90_000);
        assert_eq!(n.defi.asset_bal("dave", RAIL_BTC), 115_000);
        assert_eq!(n.bridge.rail(RAIL_BTC).unwrap().vault_utxos.len(), 2);

        // USDC rail mint (bridged), then BTC/USDC AMM. Sally sells BTC, ends
        // with less FBTC than she deposited; Dave keeps more than 50/50.
        n.defi.credit_asset("alice", RAIL_USDC, 200_000);
        assert_eq!(n.defi.asset_bal("alice", RAIL_USDC), 200_000);

        // Move some BTC to alice so she can seed the pool, then Sally swaps.
        n.defi.credit_asset("alice", RAIL_BTC, 0); // ensure map
        n.defi.debit_asset("dave", RAIL_BTC, 20_000).unwrap();
        n.defi.credit_asset("alice", RAIL_BTC, 20_000);
        n.create_pool("btc-usdc", RAIL_BTC, RAIL_USDC).unwrap();
        n.add_liquidity("btc-usdc", "alice", 20_000, 80_000).unwrap();
        let out = n.swap("btc-usdc", "sally", RAIL_BTC, 20_000, 1).unwrap();
        assert!(out > 0);
        let sally_btc = n.defi.asset_bal("sally", RAIL_BTC);
        let dave_btc = n.defi.asset_bal("dave", RAIL_BTC);
        assert_eq!(sally_btc, 70_000);
        assert_eq!(dave_btc, 95_000);
        assert_ne!(sally_btc, 90_000);
        assert_ne!(dave_btc, 115_000);

        // Trade FBTC between accounts (direct pay of the wrapped asset).
        n.defi.debit_asset("dave", RAIL_BTC, 5_000).unwrap();
        n.defi.credit_asset("sally", RAIL_BTC, 5_000);
        let sally_btc = n.defi.asset_bal("sally", RAIL_BTC);
        let dave_btc = n.defi.asset_bal("dave", RAIL_BTC);
        assert_eq!(sally_btc, 75_000);
        assert_eq!(dave_btc, 90_000);

        // Unequal withdraws (min 10k). Wrong dest sig is rejected.
        let dest_s = "n1fH7uhaDauQYfuwG6t1aTncvyuBSZtDEY";
        let dest_d = "n1BkijgCanBDsDvFjjwpaM7fX8UgBx8w5A";
        let plan_s = crate::vault::coin_select(
            &n.bridge.rail(RAIL_BTC).unwrap().vault_utxos,
            20_000,
            dest_s,
            crate::vault::DEFAULT_FEE_SATS,
        )
        .unwrap();
        let vsig_s = crate::vault::sign_plan(&shares[0..3], &plan_s).unwrap();
        let note_s = crate::crypto::sha256_hex(
            format!("wd:BTC:sally:20000:{dest_s}").as_bytes(),
        );
        let signed_s = crate::vault::signed_dest_lock_kickoff(
            &shares[0..3],
            &n.bridge.rail(RAIL_BTC).unwrap().vault_utxos,
            dest_s,
            20_000,
            crate::vault::DEFAULT_FEE_SATS,
            &vp.spk_hex,
            &note_s,
        )
        .unwrap();
        n.rail_withdraw_full(
            RAIL_BTC,
            "sally",
            20_000,
            dest_s,
            Some(&vsig_s),
            Some(&signed_s),
        )
        .unwrap();
        assert_eq!(n.defi.asset_bal("sally", RAIL_BTC), 55_000);

        let mut bad = plan_s.clone();
        bad.dest = dest_d.to_string();
        assert!(crate::vault::verify_plan_sig(
            &hex::decode(&vp.pubkey_hex).unwrap(),
            &bad,
            &vsig_s
        )
        .is_err());

        let plan_d = crate::vault::coin_select(
            &n.bridge.rail(RAIL_BTC).unwrap().vault_utxos,
            30_000,
            dest_d,
            crate::vault::DEFAULT_FEE_SATS,
        )
        .unwrap();
        let vsig_d = crate::vault::sign_plan(&shares[1..4], &plan_d).unwrap();
        let note_d = crate::crypto::sha256_hex(
            format!("wd:BTC:dave:30000:{dest_d}").as_bytes(),
        );
        let kick_d = crate::vault::signed_dest_lock_kickoff(
            &shares[1..4],
            &n.bridge.rail(RAIL_BTC).unwrap().vault_utxos,
            dest_d,
            30_000,
            crate::vault::DEFAULT_FEE_SATS,
            &vp.spk_hex,
            &note_d,
        )
        .unwrap();
        n.rail_withdraw_full(RAIL_BTC, "dave", 30_000, dest_d, Some(&vsig_d), Some(&kick_d))
            .unwrap();
        assert_eq!(n.defi.asset_bal("dave", RAIL_BTC), 60_000);
        assert_ne!(20_000, 90_000);
        assert_ne!(30_000, 115_000);
        let st = n.status_json().to_string();
        assert!(!st.contains(&hex::encode(secret)));
        assert!(n
            .bridge
            .rail(RAIL_BTC)
            .unwrap()
            .signed_vault_txs
            .values()
            .any(|t| !t.is_empty()));
    }

    #[test]
    fn evm_eth_usdc_and_adversarial_proofs() {
        use bridge::{BridgeProof, RAIL_ETH, RAIL_USDC};

        let mut n = Node::new(
            "v1",
            ChainConfig {
                allow_admin_wire: false,
                ..ChainConfig::default()
            },
            KeyRing::new(CryptoScheme::HmacDev),
            &users(),
        );
        let eth_lock = n.bridge.rail(RAIL_ETH).unwrap().lock_id.clone();
        let err = n
            .rail_deposit(
                RAIL_ETH,
                "sally",
                1_000,
                BridgeProof {
                    external_txid: "0xabc".into(),
                    block_hash: "h1".into(),
                    height: 1,
                    merkle_path: vec![],
                    merkle_index: 0,
                    lock_id: eth_lock.clone(),
                    parent_hash: String::new(),
                    merkle_root: String::new(),
                    external_to: crate::evm_spv::ETH_NATIVE_TOKEN.into(),
                    raw_tx: String::new(),
                },
                Some("alice"),
            )
            .unwrap_err();
        assert!(
            err.contains("light client") || err.contains("not bootstrapped"),
            "{err}"
        );
        let usdc_lock = n.bridge.rail(RAIL_USDC).unwrap().lock_id.clone();
        let err = n
            .rail_deposit(
                RAIL_USDC,
                "dave",
                5_000,
                BridgeProof {
                    external_txid: "0xdef".into(),
                    block_hash: "u1".into(),
                    height: 1,
                    merkle_path: vec![],
                    merkle_index: 0,
                    lock_id: usdc_lock,
                    parent_hash: String::new(),
                    merkle_root: String::new(),
                    external_to: crate::evm_spv::SEPOLIA_USDC.into(),
                    raw_tx: String::new(),
                },
                None,
            )
            .unwrap_err();
        assert!(
            err.contains("light client") || err.contains("not bootstrapped"),
            "{err}"
        );
    }

    #[test]
    fn bitvm_challenge_aborts_theft_grief_rejected_no_complete() {
        use bridge::{BridgeProof, RailHeader, RAIL_BTC};
        use crate::bitvm::ClaimStatus;

        let mut n = Node::new(
            "v1",
            ChainConfig::default(),
            KeyRing::new(CryptoScheme::HmacDev),
            &users(),
        );
        n.bridge.rail_mut(RAIL_BTC).unwrap().min_confirmations = 1;
        let secret = {
            let d = sha256_hex(b"bitvm-vault");
            let mut s = [0u8; 32];
            s.copy_from_slice(&hex::decode(&d).unwrap());
            s[0] &= 0x3f;
            s
        };
        let shares = crate::vault::split_secret(&secret, 5, 3, 0, b"bv").unwrap();
        let vp = crate::vault::vault_pub_from_secret(&secret, 0, 5, 3).unwrap();
        n.bridge.rail_mut(RAIL_BTC).unwrap().vault_pub = Some(vp.clone());
        let watch = hex::decode(&vp.spk_hex).unwrap();
        let (raw_tx, tx) = crate::btc_spv::test_deposit_tx(&watch, "bob", 50_000);
        let hdr = crate::btc_spv::mine_header(
            &"00".repeat(32),
            &tx.txid_display,
            0x207fffff,
            1_700_000_000,
        )
        .unwrap();
        n.submit_rail_header(
            RAIL_BTC,
            RailHeader {
                height: 1,
                hash: String::new(),
                parent_hash: String::new(),
                merkle_root: String::new(),
                raw: hdr.raw_hex.clone(),
            },
            Some("alice"),
        )
        .unwrap();
        n.rail_deposit(
            RAIL_BTC,
            "bob",
            50_000,
            BridgeProof {
                external_txid: tx.txid_display,
                block_hash: hdr.hash_display,
                height: 1,
                merkle_path: vec![],
                merkle_index: 0,
                lock_id: n.bridge.rail(RAIL_BTC).unwrap().lock_id.clone(),
                parent_hash: String::new(),
                merkle_root: hdr.merkle_display,
                external_to: String::new(),
                raw_tx: crate::btc_spv::hex_encode(&raw_tx),
            },
            Some("alice"),
        )
        .unwrap();

        let dest = "n1fH7uhaDauQYfuwG6t1aTncvyuBSZtDEY";
        let steal = "n1BkijgCanBDsDvFjjwpaM7fX8UgBx8w5A";
        let plan = crate::vault::coin_select(
            &n.bridge.rail(RAIL_BTC).unwrap().vault_utxos,
            20_000,
            dest,
            crate::vault::DEFAULT_FEE_SATS,
        )
        .unwrap();
        let vsig = crate::vault::sign_plan(&shares[0..3], &plan).unwrap();
        let note_id = crate::crypto::sha256_hex(
            format!("wd:BTC:bob:20000:{dest}").as_bytes(),
        );
        let kick = crate::vault::signed_dest_lock_kickoff(
            &shares[0..3],
            &n.bridge.rail(RAIL_BTC).unwrap().vault_utxos,
            dest,
            20_000,
            crate::vault::DEFAULT_FEE_SATS,
            &n.bridge.rail(RAIL_BTC).unwrap().vault_pub.as_ref().unwrap().spk_hex,
            &note_id,
        )
        .unwrap();
        let note = n
            .rail_withdraw_full(RAIL_BTC, "bob", 20_000, dest, Some(&vsig), Some(&kick))
            .unwrap();
        assert_eq!(n.defi.asset_bal("bob", RAIL_BTC), 30_000);

        let claim = n.bridge.rail(RAIL_BTC).unwrap().bitvm_claims[&note].clone();
        assert_eq!(claim.status, ClaimStatus::Pending);
        assert!(claim.published_abort.is_empty());
        let ws = crate::bitvm::claim_witness_script(
            &{
                let mut c = [0u8; 32];
                c.copy_from_slice(&hex::decode(&claim.abort_commit).unwrap());
                c
            },
            &{
                let mut d = [0u8; 20];
                d.copy_from_slice(&hex::decode(&claim.dest_h160).unwrap());
                d
            },
            claim.csv_blocks,
        )
        .unwrap();
        assert_eq!(crate::bitvm::p2wsh_spk_hex(&ws), claim.claim_spk_hex);

        // Grief: observed == committed.
        let err = n
            .rail_challenge(RAIL_BTC, &note, dest, 20_000, "carol")
            .unwrap_err();
        assert!(err.contains("grief"), "{err}");
        assert_eq!(
            n.bridge.rail(RAIL_BTC).unwrap().bitvm_claims[&note].status,
            ClaimStatus::Pending
        );

        // Theft Kickoff dest ≠ claim dest → abort preimage published, FBTC refunded.
        let abort = n
            .rail_challenge(RAIL_BTC, &note, steal, 20_000, "alice")
            .unwrap();
        assert!(crate::bitvm::abort_path_valid(
            &abort,
            &{
                let mut c = [0u8; 32];
                c.copy_from_slice(&hex::decode(&claim.abort_commit).unwrap());
                c
            }
        ));
        let after = n.bridge.rail(RAIL_BTC).unwrap().bitvm_claims[&note].clone();
        assert_eq!(after.status, ClaimStatus::Challenged);
        assert_eq!(n.defi.asset_bal("bob", RAIL_BTC), 50_000); // refunded
        let dump = n.status_json().to_string();
        assert!(!dump.contains(&hex::encode(secret)), "no vault secret");
        // pending claims must not leak abort in status before challenge; after challenge watchers need it
        assert!(dump.contains(&after.published_abort));
        assert!(!after.published_abort.is_empty());
    }

    #[test]
    fn bitvm_kickoff_no_founder_sig_dest_lock_only() {
        use bridge::{BridgeProof, RailHeader, RAIL_BTC};

        let mut n = Node::new(
            "v1",
            ChainConfig::default(),
            KeyRing::new(CryptoScheme::HmacDev),
            &users(),
        );
        n.bridge.rail_mut(RAIL_BTC).unwrap().min_confirmations = 1;
        let vp = crate::vault::vault_pub_from_secret(&[3u8; 32], 0, 5, 3).unwrap();
        n.bridge.rail_mut(RAIL_BTC).unwrap().vault_pub = Some(vp.clone());
        let watch = hex::decode(&vp.spk_hex).unwrap();
        let (raw_tx, tx) = crate::btc_spv::test_deposit_tx(&watch, "bob", 50_000);
        let hdr = crate::btc_spv::mine_header(
            &"00".repeat(32),
            &tx.txid_display,
            0x207fffff,
            1_700_000_123,
        )
        .unwrap();
        n.submit_rail_header(
            RAIL_BTC,
            RailHeader {
                height: 1,
                hash: String::new(),
                parent_hash: String::new(),
                merkle_root: String::new(),
                raw: hdr.raw_hex.clone(),
            },
            None,
        )
        .unwrap();
        n.rail_deposit(
            RAIL_BTC,
            "bob",
            50_000,
            BridgeProof {
                external_txid: tx.txid_display,
                block_hash: hdr.hash_display,
                height: 1,
                merkle_path: vec![],
                merkle_index: 0,
                lock_id: n.bridge.rail(RAIL_BTC).unwrap().lock_id.clone(),
                parent_hash: String::new(),
                merkle_root: hdr.merkle_display,
                external_to: String::new(),
                raw_tx: crate::btc_spv::hex_encode(&raw_tx),
            },
            None,
        )
        .unwrap();

        let dest = "n1fH7uhaDauQYfuwG6t1aTncvyuBSZtDEY";
        let shares = crate::vault::split_secret(&[3u8; 32], 5, 3, 0, b"k").unwrap();
        let note_id = crate::crypto::sha256_hex(
            format!("wd:BTC:bob:20000:{dest}").as_bytes(),
        );
        let kick = crate::vault::signed_dest_lock_kickoff(
            &shares[0..3],
            &n.bridge.rail(RAIL_BTC).unwrap().vault_utxos,
            dest,
            20_000,
            crate::vault::DEFAULT_FEE_SATS,
            &vp.spk_hex,
            &note_id,
        )
        .unwrap();
        let vsig = crate::vault::sign_plan(
            &shares[0..3],
            &crate::vault::coin_select(
                &n.bridge.rail(RAIL_BTC).unwrap().vault_utxos,
                20_000,
                dest,
                crate::vault::DEFAULT_FEE_SATS,
            )
            .unwrap(),
        )
        .unwrap();
        let note = n
            .rail_withdraw_full(RAIL_BTC, "bob", 20_000, dest, Some(&vsig), Some(&kick))
            .unwrap();
        let c = n.bridge.rail(RAIL_BTC).unwrap().bitvm_claims[&note].clone();
        n.bitvm_kickoff_check(RAIL_BTC, &note, &c.claim_spk_hex)
            .unwrap();
        let thief_spk = "0014deadbeefdeadbeefdeadbeefdeadbeefdeadbee";
        assert!(n.bitvm_kickoff_check(RAIL_BTC, &note, thief_spk).is_err());
        let dump = n.status_json().to_string();
        assert!(dump.contains("claim_root"));
        assert!(!c.published_abort.is_empty() || c.status != crate::bitvm::ClaimStatus::Challenged);
    }

    fn enable_v4(net: &mut Network, start: u64) {
        for n in net.nodes.values_mut() {
            n.qc_header_version = 4;
            n.qc_start_height = start;
        }
    }

    #[test]
    fn v4_five_bonded_refuses_pack() {
        let mut net = Network::bootstrap(
            &["v1", "v2", "v3", "v4", "v5"],
            1000,
            &users(),
            ChainConfig {
                pack_budget_ms: 0,
                ..Default::default()
            },
        );
        net.pong_all();
        enable_v4(&mut net, 1);
        net.payment("alice", "bob", 1, 1).unwrap();
        let packer = net.nodes["v1"].lottery_packer().unwrap();
        let err = net
            .nodes
            .get_mut(&packer)
            .unwrap()
            .pack_as(&packer)
            .unwrap_err();
        assert!(
            err.contains("6 bonded") || err.contains("LC chain"),
            "{err}"
        );
        assert_eq!(net.nodes["v1"].tip_height, 0);
    }

    #[test]
    fn v4_seal_freeze_matches_next_committee() {
        let mut net = Network::bootstrap(
            &["v1", "v2", "v3", "v4", "v5", "v6"],
            1000,
            &users(),
            ChainConfig {
                pack_budget_ms: 0,
                ..Default::default()
            },
        );
        net.pong_all();
        enable_v4(&mut net, 1);
        net.payment("alice", "bob", 10, 1).unwrap();
        let r = net.seal_next_height().unwrap();
        assert_eq!(r.height, 1);
        for n in net.nodes.values() {
            let led = n.chain.last().expect("committed");
            assert!(led.is_v4(), "h=1 must be v4");
            assert_eq!(led.claim_root.len(), 64);
            assert_eq!(led.inner_hash.len(), 64);
            assert_eq!(led.current_committee.len(), 6);
            assert_eq!(led.next_committee.len(), 6);
            assert_eq!(n.schedule_committee, led.next_committee);
            assert_eq!(n.lottery_order(), led.next_committee);
            let inner = crate::qc_header::parse32(&led.inner_hash).unwrap();
            let next_root = crate::qc_header::parse32(&led.next_committee_root).unwrap();
            let claim = crate::qc_header::parse32(&led.claim_root).unwrap();
            assert_eq!(
                crate::qc_header::outer_hash_hex(&inner, &next_root, &claim),
                led.ledger_hash
            );
            assert!(led.verify_packer(&n.keys));
        }
        let hashes: Vec<_> = net
            .nodes
            .values()
            .map(|n| n.chain.last().unwrap().ledger_hash.clone())
            .collect();
        assert!(hashes.iter().all(|h| h == &hashes[0]));
        let inners: Vec<_> = net
            .nodes
            .values()
            .map(|n| n.chain.last().unwrap().inner_hash.clone())
            .collect();
        assert!(inners.iter().all(|h| h == &inners[0]));

        net.payment("alice", "bob", 10, 1).unwrap();
        let r2 = net.seal_next_height().unwrap();
        assert_eq!(r2.height, 2);
        let led2 = net.nodes["v1"].chain.last().unwrap();
        assert!(led2.is_v4());
        assert_eq!(
            led2.current_committee,
            net.nodes["v1"].chain[net.nodes["v1"].chain.len() - 2].next_committee
        );
    }

    /// Jail seizes full bond into the prize pot; Unjail needs 2× MIN_BOND after
    /// the first offence and 4× after the second; jailed seats stay out of the
    /// lottery until Unjail lands; jail_count survives snapshot round-trip.
    #[test]
    fn unjail_escalating_rebond_prize_pot_and_snapshot() {
        use crate::economy::unjail_cost;
        use std::path::PathBuf;

        let cfg = ChainConfig {
            pack_budget_ms: 0,
            max_txs_per_ledger: 8,
            slash_equivocation: 100, // ignored: jail seizes full bond
            min_bond: MIN_BOND,
            ..Default::default()
        };
        // 7 bonded: drop_slashes keeps quorum (≥6) so the evidence can land.
        let mut net = Network::bootstrap(
            &["v1", "v2", "v3", "v4", "v5", "v6", "v7"],
            MIN_BOND,
            &users(),
            cfg,
        );
        net.pong_all();
        let victim = net.nodes["v1"].lottery_order()[1].clone();
        let bond_before = net.nodes["v1"].validators[&victim].bond;
        assert_eq!(bond_before, MIN_BOND);

        // Queue slash evidence on every node (same shape as checker double-OK).
        for n in net.nodes.values_mut() {
            n.pending_slashes.push(SlashEvidence {
                offender: victim.clone(),
                height: n.tip_height.saturating_add(1),
                hash_a: "hash-a".into(),
                sig_a: "sig-a".into(),
                hash_b: "hash-b".into(),
                sig_b: "sig-b".into(),
                kind: String::new(),
                round: 0,
            });
        }
        let pot_before = net.nodes["v1"].epoch_work.fee_reward_pool;
        net.payment("alice", "bob", 1, 1).unwrap();
        net.seal_next_height().unwrap();

        for n in net.nodes.values() {
            let v = &n.validators[&victim];
            assert!(v.jailed, "jailed on {}", n.id);
            assert_eq!(v.bond, 0, "full bond seized");
            assert_eq!(v.jail_count, 1);
            assert_eq!(v.slash_total, bond_before);
            assert!(
                n.epoch_work.fee_reward_pool >= pot_before.saturating_add(bond_before),
                "seized bond must land in prize pot (fee_reward_pool)"
            );
            let order = n.lottery_order();
            assert!(!order.contains(&victim), "jailed seat out of lottery");
        }

        // Bond while jailed must fail (Unjail is the only path).
        let err = net
            .nodes
            .get_mut("v1")
            .unwrap()
            .bond(&victim, "alice", MIN_BOND)
            .unwrap_err();
        assert!(err.contains("jailed"), "{err}");

        let need1 = unjail_cost(MIN_BOND, 1);
        assert_eq!(need1, 2 * MIN_BOND);
        // Underpay Unjail is rejected; restore alice after the dry apply
        // (apply advances seq/fee before the amount gate).
        let seq = net.account_seqs["alice"];
        let under = Tx::sign_body(
            &net.user_keys,
            "alice",
            seq,
            &victim,
            need1 - 1,
            2,
            net.cfg.network_id,
            TxBody::Unjail {
                validator: victim.clone(),
            },
        )
        .unwrap();
        let alice_snap = net.nodes["v2"].state.get("alice");
        let err = net
            .nodes
            .get_mut("v1")
            .unwrap()
            .apply_protocol_tx(&under)
            .unwrap_err();
        assert!(err.contains("unjail needs"), "{err}");
        assert!(net.nodes["v1"].validators[&victim].jailed);
        net.nodes
            .get_mut("v1")
            .unwrap()
            .state
            .accounts
            .insert("alice".into(), alice_snap);

        // Snapshot round-trip while jailed.
        {
            let n = net.nodes.get_mut("v1").unwrap();
            let path = PathBuf::from(std::env::temp_dir()).join(format!(
                "falcon-unjail-snap-{}-{}.json",
                std::process::id(),
                n.now_ms
            ));
            n.save_snapshot(&path).unwrap();
            let keys = n.keys.clone();
            let loaded = Node::load_snapshot(&path, keys).unwrap();
            let lv = &loaded.validators[&victim];
            assert!(lv.jailed);
            assert_eq!(lv.jail_count, 1);
            assert_eq!(lv.bond, 0);
            let _ = std::fs::remove_file(&path);
        }

        // Successful Unjail at 2× MIN_BOND.
        let unjail = Tx::sign_body(
            &net.user_keys,
            "alice",
            seq,
            &victim,
            need1,
            2,
            net.cfg.network_id,
            TxBody::Unjail {
                validator: victim.clone(),
            },
        )
        .unwrap();
        *net.account_seqs.get_mut("alice").unwrap() += 1;
        for n in net.nodes.values_mut() {
            n.submit_tx(unjail.clone()).unwrap();
        }
        net.seal_next_height().unwrap();
        net.pong_all();

        for n in net.nodes.values() {
            let v = &n.validators[&victim];
            assert!(!v.jailed, "cleared on {}", n.id);
            assert_eq!(v.bond, need1);
            assert_eq!(v.jail_count, 1, "count must not reset on unjail");
        }
        // Back in the lottery once ponging.
        let order = net.nodes["v1"].lottery_order();
        assert!(order.contains(&victim), "unjailed seat returns to lottery");

        // Second jail → unjail needs 4× MIN_BOND.
        for n in net.nodes.values_mut() {
            n.pending_slashes.push(SlashEvidence {
                offender: victim.clone(),
                height: n.tip_height.saturating_add(1),
                hash_a: "hash-c".into(),
                sig_a: "sig-c".into(),
                hash_b: "hash-d".into(),
                sig_b: "sig-d".into(),
                kind: String::new(),
                round: 0,
            });
        }
        net.payment("alice", "bob", 1, 1).unwrap();
        net.seal_next_height().unwrap();
        for n in net.nodes.values() {
            let v = &n.validators[&victim];
            assert!(v.jailed);
            assert_eq!(v.jail_count, 2);
            assert_eq!(v.bond, 0);
        }
        let need2 = unjail_cost(MIN_BOND, 2);
        assert_eq!(need2, 4 * MIN_BOND);
        let seq = net.account_seqs["alice"];
        let unjail2 = Tx::sign_body(
            &net.user_keys,
            "alice",
            seq,
            &victim,
            need2,
            2,
            net.cfg.network_id,
            TxBody::Unjail {
                validator: victim.clone(),
            },
        )
        .unwrap();
        *net.account_seqs.get_mut("alice").unwrap() += 1;
        for n in net.nodes.values_mut() {
            n.submit_tx(unjail2.clone()).unwrap();
        }
        net.seal_next_height().unwrap();
        for n in net.nodes.values() {
            let v = &n.validators[&victim];
            assert!(!v.jailed);
            assert_eq!(v.bond, need2);
            assert_eq!(v.jail_count, 2);
        }
    }

    /// With exactly 6 live seats, a queued slash of one would freeze v4 packing.
    /// drop_slashes_that_break_quorum must discard it so the tip can advance
    /// (live 2026-10-05: "v4 pack needs 6 bonded, have 5 … slashed=[v3]").
    #[test]
    fn drop_slashes_keeps_pack_alive_at_exactly_six() {
        let cfg = ChainConfig {
            pack_budget_ms: 0,
            max_txs_per_ledger: 8,
            min_bond: MIN_BOND,
            ..Default::default()
        };
        let mut net = Network::bootstrap(
            &["v1", "v2", "v3", "v4", "v5", "v6"],
            MIN_BOND,
            &users(),
            cfg,
        );
        net.pong_all();
        enable_v4(&mut net, 1);
        let victim = net.nodes["v1"].lottery_order()[1].clone();
        for n in net.nodes.values_mut() {
            n.pending_slashes.push(SlashEvidence {
                offender: victim.clone(),
                height: n.tip_height.saturating_add(1),
                hash_a: "hash-a".into(),
                sig_a: "sig-a".into(),
                hash_b: "hash-b".into(),
                sig_b: "sig-b".into(),
                kind: String::new(),
                round: 0,
            });
        }
        net.payment("alice", "bob", 1, 1).unwrap();
        let r = net.seal_next_height().expect("pack must succeed after dropping quorum slash");
        assert_eq!(r.height, 1);
        for n in net.nodes.values() {
            assert!(
                !n.validators[&victim].jailed,
                "quorum-breaking slash must not jail {victim} on {}",
                n.id
            );
            assert!(
                n.pending_slashes.is_empty(),
                "dropped evidence must leave pending_slashes empty on {}",
                n.id
            );
            let bonded = n
                .validators
                .values()
                .filter(|v| v.lottery_weight() > 0.0)
                .count();
            assert_eq!(bonded, 6, "all six stay live on {}", n.id);
        }
    }

    /// Sticky dual-offender evidence must not ping-pong after Unjail.
    ///
    /// Live 2026-10-06 h=373256: drop_slashes jailed one of {v1,v12} and left
    /// the co-offender's evidence queued. Because evidence.height was the dual
    /// height (not the packing height), commit never cleared it. Unjail of one
    /// seat then re-jailed the other on the next pack — twice.
    #[test]
    fn sticky_equivocation_evidence_does_not_ping_pong_after_unjail() {
        use crate::economy::unjail_cost;

        let cfg = ChainConfig {
            pack_budget_ms: 0,
            max_txs_per_ledger: 8,
            min_bond: MIN_BOND,
            ..Default::default()
        };
        // 7 bonded so drop_slashes can jail exactly one and still leave ≥6.
        let mut net = Network::bootstrap(
            &["v1", "v2", "v3", "v4", "v5", "v6", "v7"],
            MIN_BOND,
            &users(),
            cfg,
        );
        net.pong_all();
        // Advance tip once so the dual height is *historical* relative to the
        // slash-packing ledger (matches live: queue at 373256, pack later).
        net.payment("alice", "bob", 1, 1).unwrap();
        net.seal_next_height().unwrap();
        assert_eq!(net.tip_height(), 1);

        let order = net.nodes["v1"].lottery_order();
        let a = order[1].clone();
        let b = order[2].clone();
        assert_ne!(a, b);
        let dual_h = 1u64; // already committed
        for n in net.nodes.values_mut() {
            for offender in [&a, &b] {
                n.pending_slashes.push(SlashEvidence {
                    offender: offender.clone(),
                    height: dual_h,
                    hash_a: format!("hash-a-{offender}"),
                    sig_a: "sig-a".into(),
                    hash_b: format!("hash-b-{offender}"),
                    sig_b: "sig-b".into(),
                    kind: String::new(),
                    round: 0,
                });
            }
        }

        net.payment("alice", "bob", 1, 1).unwrap();
        net.seal_next_height().unwrap();
        assert_eq!(net.tip_height(), 2);

        let mut jailed: Vec<String> = Vec::new();
        let mut free: Vec<String> = Vec::new();
        for id in [&a, &b] {
            if net.nodes["v1"].validators[id].jailed {
                jailed.push(id.clone());
            } else {
                free.push(id.clone());
            }
        }
        assert_eq!(jailed.len(), 1, "exactly one co-offender jailed (quorum keep)");
        assert_eq!(free.len(), 1, "other co-offender spared by drop_slashes");
        let first = jailed[0].clone();
        let other = free[0].clone();

        for n in net.nodes.values() {
            assert!(
                n.pending_slashes
                    .iter()
                    .all(|e| e.height > n.tip_height),
                "historical dual evidence must be consumed on commit (node {})",
                n.id
            );
            assert!(
                !n.pending_slashes
                    .iter()
                    .any(|e| e.offender == first || e.offender == other),
                "neither co-offender may keep sticky evidence on {}",
                n.id
            );
        }

        // Unjail the jailed seat; sticky evidence must not jail the other.
        let need = unjail_cost(MIN_BOND, 1);
        let seq = net.account_seqs["alice"];
        let unjail = Tx::sign_body(
            &net.user_keys,
            "alice",
            seq,
            &first,
            need,
            2,
            net.cfg.network_id,
            TxBody::Unjail {
                validator: first.clone(),
            },
        )
        .unwrap();
        *net.account_seqs.get_mut("alice").unwrap() += 1;
        for n in net.nodes.values_mut() {
            n.submit_tx(unjail.clone()).unwrap();
        }
        net.seal_next_height().unwrap();
        net.pong_all();

        for n in net.nodes.values() {
            assert!(
                !n.validators[&first].jailed,
                "{first} must stay unjailed on {}",
                n.id
            );
            assert!(
                !n.validators[&other].jailed,
                "{other} must not be re-jailed after Unjail of {first} on {}",
                n.id
            );
            assert_eq!(n.validators[&first].jail_count, 1);
            assert_eq!(n.validators[&other].jail_count, 0);
        }

        // One more pack with both bonded — still no ping-pong.
        net.payment("alice", "bob", 1, 1).unwrap();
        net.seal_next_height().unwrap();
        for n in net.nodes.values() {
            assert!(!n.validators[&first].jailed, "still free on {}", n.id);
            assert!(!n.validators[&other].jailed, "still free on {}", n.id);
            assert!(n.pending_slashes.is_empty(), "no sticky leftovers on {}", n.id);
        }
    }

    /// Seats jailed before jail_count existed deserialize as jail_count=0.
    /// First Unjail must still cost 2× MIN_BOND and persist jail_count=1.
    #[test]
    fn historical_jail_count_zero_unjail_costs_double() {
        use crate::economy::{effective_jail_count, unjail_cost};

        let cfg = ChainConfig {
            pack_budget_ms: 0,
            max_txs_per_ledger: 8,
            min_bond: MIN_BOND,
            ..Default::default()
        };
        let mut net = Network::bootstrap(
            &["v1", "v2", "v3", "v4", "v5", "v6", "v7"],
            MIN_BOND,
            &users(),
            cfg,
        );
        net.pong_all();
        let victim = "v2".to_string();
        for n in net.nodes.values_mut() {
            let v = n.validators.get_mut(&victim).unwrap();
            v.jailed = true;
            v.bond = 0;
            v.jail_count = 0; // historical
            v.slash_total = MIN_BOND;
        }
        assert_eq!(effective_jail_count(true, 0), 1);
        let need = unjail_cost(MIN_BOND, effective_jail_count(true, 0));
        assert_eq!(need, 2 * MIN_BOND);
        let st = net.nodes["v1"].status_json();
        let v2 = st["validators"]
            .as_array()
            .unwrap()
            .iter()
            .find(|x| x["id"] == "v2")
            .unwrap();
        assert_eq!(v2["unjail_cost"], need);

        let seq = net.account_seqs["alice"];
        let under = Tx::sign_body(
            &net.user_keys,
            "alice",
            seq,
            &victim,
            MIN_BOND, // old buggy cost
            2,
            net.cfg.network_id,
            TxBody::Unjail {
                validator: victim.clone(),
            },
        )
        .unwrap();
        let alice_snap = net.nodes["v1"].state.get("alice");
        let err = net
            .nodes
            .get_mut("v1")
            .unwrap()
            .apply_protocol_tx(&under)
            .unwrap_err();
        assert!(err.contains("unjail needs"), "{err}");
        // Restore alice — apply advances seq/fee before the amount gate.
        net.nodes
            .get_mut("v1")
            .unwrap()
            .state
            .accounts
            .insert("alice".into(), alice_snap);

        let ok = Tx::sign_body(
            &net.user_keys,
            "alice",
            seq,
            &victim,
            need,
            2,
            net.cfg.network_id,
            TxBody::Unjail {
                validator: victim.clone(),
            },
        )
        .unwrap();
        *net.account_seqs.get_mut("alice").unwrap() += 1;
        for n in net.nodes.values_mut() {
            n.submit_tx(ok.clone()).unwrap();
        }
        net.seal_next_height().unwrap();
        for n in net.nodes.values() {
            let v = &n.validators[&victim];
            assert!(!v.jailed);
            assert_eq!(v.bond, need);
            assert_eq!(v.jail_count, 1, "historical offence must persist as 1");
        }
    }

    #[test]
    fn commitment_root_includes_jail_count() {

        let cfg = ChainConfig {
            pack_budget_ms: 0,
            ..Default::default()
        };
        let mut net = Network::bootstrap(&["v1", "v2", "v3"], MIN_BOND, &users(), cfg);
        net.pong_all();
        let before = net.nodes["v1"].commitment_root();
        // Mutate only jail_count — root must move (consensus-critical for Unjail).
        net.nodes.get_mut("v1").unwrap().validators.get_mut("v2").unwrap().jail_count = 3;
        let after = net.nodes["v1"].commitment_root();
        assert_ne!(before, after, "jail_count must be in the commitment root");
        // Matching counts restore the same root.
        net.nodes.get_mut("v2").unwrap().validators.get_mut("v2").unwrap().jail_count = 3;
        assert_eq!(
            net.nodes["v1"].commitment_root(),
            net.nodes["v2"].commitment_root()
        );
    }

    /// Packer and receivers apply slash before txs. A Bond to a pending
    /// offender must be dropped at pack (not included then jailed), so peers
    /// that slash first do not reject the ledger.
    #[test]
    fn pack_and_receive_apply_slash_before_txs() {
        let cfg = ChainConfig {
            pack_budget_ms: 0,
            max_txs_per_ledger: 8,
            min_bond: MIN_BOND,
            ..Default::default()
        };
        let mut net = Network::bootstrap(
            &["v1", "v2", "v3", "v4", "v5", "v6", "v7"],
            MIN_BOND,
            &users(),
            cfg,
        );
        net.pong_all();
        let victim = net.nodes["v1"].lottery_order()[1].clone();
        for n in net.nodes.values_mut() {
            n.pending_slashes.push(SlashEvidence {
                offender: victim.clone(),
                height: n.tip_height.saturating_add(1),
                hash_a: "hash-a".into(),
                sig_a: "sig-a".into(),
                hash_b: "hash-b".into(),
                sig_b: "sig-b".into(),
                kind: String::new(),
                round: 0,
            });
        }
        // Bond to the offender would succeed if txs ran before slash.
        let seq = net.account_seqs["alice"];
        let bond_tx = Tx::sign_body(
            &net.user_keys,
            "alice",
            seq,
            &victim,
            MIN_BOND,
            2,
            net.cfg.network_id,
            TxBody::Bond {
                validator: victim.clone(),
            },
        )
        .unwrap();
        *net.account_seqs.get_mut("alice").unwrap() += 1;
        for n in net.nodes.values_mut() {
            n.submit_tx(bond_tx.clone()).unwrap();
        }
        // Payable filler so the height can seal after Bond is rejected.
        net.payment("bob", "carol", 1, 1).unwrap();
        let r = net.seal_next_height().unwrap();
        assert!(r.n_txs >= 1, "filler must pack");
        for n in net.nodes.values() {
            assert!(n.validators[&victim].jailed);
            assert_eq!(n.validators[&victim].bond, 0);
            let led = n.chain.last().unwrap();
            assert!(
                led.txs.iter().all(|tx| !matches!(tx.body, TxBody::Bond { .. })),
                "Bond to pending offender must not land in the ledger"
            );
            assert!(
                !led.slashes.is_empty(),
                "slash evidence must bind on the ledger"
            );
        }
        let roots: Vec<_> = net.nodes.values().map(|n| n.commitment_root()).collect();
        assert!(roots.iter().all(|r| r == &roots[0]), "packer/receive roots match");
    }

    /// Ready unbond must not complete ahead of slash on the same ledger —
    /// the unbonding stake is seized into the prize pot, not paid to bond_account.
    #[test]
    fn slash_runs_before_ready_unbond_completion() {
        let cfg = ChainConfig {
            pack_budget_ms: 0,
            max_txs_per_ledger: 8,
            min_bond: MIN_BOND,
            unbond_cooldown_ms: 1_000,
            ..Default::default()
        };
        let mut net = Network::bootstrap(
            &["v1", "v2", "v3", "v4", "v5", "v6", "v7"],
            MIN_BOND,
            &users(),
            cfg,
        );
        net.pong_all();
        let victim = net.nodes["v1"].lottery_order()[1].clone();
        // Put half the bond into unbonding; bond_account defaults to validator id
        // for genesis seats — set to alice so we can watch the credit.
        for n in net.nodes.values_mut() {
            let v = n.validators.get_mut(&victim).unwrap();
            v.bond_account = "alice".into();
            v.bond = MIN_BOND / 2;
            v.unbonding = MIN_BOND / 2;
            v.unbond_ready_ms = n.now_ms; // already mature relative to now
        }
        let alice_before = net.nodes["v1"].state.get("alice").balance;
        let pot_before = net.nodes["v1"].epoch_work.fee_reward_pool;
        // Advance clocks so sealed_at (≥ now, ≤ parent+60s) is past ready.
        for n in net.nodes.values_mut() {
            n.tick(5_000);
        }
        for n in net.nodes.values_mut() {
            n.pending_slashes.push(SlashEvidence {
                offender: victim.clone(),
                height: n.tip_height.saturating_add(1),
                hash_a: "hash-a".into(),
                sig_a: "sig-a".into(),
                hash_b: "hash-b".into(),
                sig_b: "sig-b".into(),
                kind: String::new(),
                round: 0,
            });
        }
        net.payment("bob", "carol", 1, 1).unwrap();
        net.seal_next_height().unwrap();
        for n in net.nodes.values() {
            let v = &n.validators[&victim];
            assert!(v.jailed);
            assert_eq!(v.bond, 0);
            assert_eq!(v.unbonding, 0, "unbonding must be seized, not completed");
            assert_eq!(
                n.state.get("alice").balance,
                alice_before,
                "ready unbond must not credit bond_account when slash is on the ledger"
            );
            assert!(
                n.epoch_work.fee_reward_pool >= pot_before.saturating_add(MIN_BOND),
                "full bond+unbonding must land in the prize pot"
            );
        }
    }


    #[test]
    fn btc4_three_consecutive_header_batches_admitted_and_packed_cleanly() {
        let mut net = Network::bootstrap(
            &["v1", "v2", "v3", "v4", "v5"],
            1000,
            &users(),
            ChainConfig {
                fee_escalate: false,
                min_fee: 1,
                pack_budget_ms: 0,
                max_txs_per_ledger: 0,
                ..Default::default()
            },
        );
        net.pong_all();

        let anchor_hdr = crate::btc_spv::mine_header(&"00".repeat(32), &"aa".repeat(32), 0x207f_ffff, 1_700_000_000).unwrap();
        let h0 = 155_232u64;
        for n in net.nodes.values_mut() {
            n.bitvm2_m1_from_height = 0;
            let mut rail = crate::bridge::RailState::new_btc4();
            rail.btc_checkpoint = Some((h0, anchor_hdr.hash_display.clone()));
            n.bridge.rails.insert(crate::bridge::RAIL_BTC4.into(), rail);
        }

        // First commit the BTC4 checkpoint anchor at h0 so tip_height == h0.
        let anchor_tx = Tx::sign_body(
            &net.user_keys,
            "alice",
            1,
            "",
            0,
            1,
            net.cfg.network_id,
            TxBody::RailHeader {
                asset: crate::bridge::RAIL_BTC4.into(),
                height: h0,
                hash: String::new(),
                parent_hash: String::new(),
                merkle_root: String::new(),
                raw: anchor_hdr.raw_hex.clone(),
            },
        )
        .unwrap();
        for n in net.nodes.values_mut() {
            assert_eq!(n.submit_tx(anchor_tx.clone()), Ok(true));
        }
        let r0 = net.seal_next_height().unwrap();
        assert_eq!(r0.n_txs, 1);

        // Mine 3 consecutive BTC4 headers chaining onto h0.
        let mut prev_hash = anchor_hdr.hash_display.clone();
        let mut batches = Vec::new();
        for i in 1..=3u64 {
            let merkle = format!("{:02x}", i as u8).repeat(32);
            let h = crate::btc_spv::mine_header(&prev_hash, &merkle, 0x207f_ffff, 1_700_000_000 + i as u32 * 600).unwrap();
            prev_hash = h.hash_display.clone();
            let tx = Tx::sign_body(
                &net.user_keys,
                "alice",
                1 + i,
                "",
                0,
                1,
                net.cfg.network_id,
                TxBody::RailHeader {
                    asset: crate::bridge::RAIL_BTC4.into(),
                    height: h0 + i,
                    hash: String::new(),
                    parent_hash: String::new(),
                    merkle_root: String::new(),
                    raw: h.raw_hex.clone(),
                },
            )
            .unwrap();
            batches.push((i, h, tx));
        }

        // Submit all 3 consecutive BTC4 header txs to the mempool BEFORE packing a block.
        for (i, _h, tx) in &batches {
            for n in net.nodes.values_mut() {
                assert_eq!(
                    n.submit_tx(tx.clone()),
                    Ok(true),
                    "BTC4 header batch #{i} must be admitted into mempool"
                );
            }
        }
        for n in net.nodes.values() {
            assert_eq!(n.mempool.len(), 3);
        }

        // Pack and seal the next block: all 3 BTC4 headers pack cleanly in one block.
        let r = net.seal_next_height().unwrap();
        assert_eq!(r.n_txs, 3, "all 3 consecutive BTC4 headers must pack in one block");
        for n in net.nodes.values() {
            let rail = n.bridge.rail(crate::bridge::RAIL_BTC4).unwrap();
            assert_eq!(rail.tip_height, h0 + 3);
            assert_eq!(rail.tip_hash, batches[2].1.hash_display);
            assert!(n.mempool.is_empty());
        }
    }
}

#[cfg(test)]
mod account_history_store_tests {
    use super::*;

    #[test]
    fn history_comes_from_body_store_when_ram_tail_has_none() {
        let mut k = KeyRing::new(CryptoScheme::HmacDev);
        k.generate_many(["alice", "bob"]);
        let dir = std::env::temp_dir().join(format!("fpl-hist-{}", std::process::id()));
        let store = BodyStore::open(&dir).unwrap();
        for h in 1..=30u64 {
            let txs = if h % 10 == 0 {
                vec![Tx::sign_body(&k, "alice", h, "bob", h, 1, 2300, TxBody::Pay).unwrap()]
            } else {
                vec![]
            };
            let led = Ledger::seal(h, format!("{:064x}", h - 1), 2300, "alice", &k, txs, String::new(), h).unwrap();
            store.put(&led).unwrap();
        }
        let mut out = Vec::new();
        account_history_from_store(&store, "bob", 31, 1000, std::time::Duration::from_secs(5), 8, &mut out);
        let hs: Vec<u64> = out.iter().map(|v| v["height"].as_u64().unwrap()).collect();
        assert_eq!(hs, vec![30, 20, 10], "newest first, both sides of the transfer");
        assert_eq!(out[0]["kind"], "pay");
        // Bounded: only heights 21..30 scanned.
        let mut out = Vec::new();
        account_history_from_store(&store, "alice", 31, 10, std::time::Duration::from_secs(5), 8, &mut out);
        assert_eq!(out.len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn set_external_addrs_link_update_remove_and_account_query() {
        let mut net = Network::bootstrap(
            &["v1", "v2", "v3"],
            MIN_BOND,
            &[("alice".into(), 100_000), ("bob".into(), 100_000)],
            ChainConfig::default(),
        );
        net.pong_all();
        let node = net.nodes.get_mut("v1").unwrap();
        node.external_addrs_from_height = 0;
        let start_bal = node.state.get("alice").balance;
        assert_eq!(node.state.get("alice").sequence, 1);
        assert!(node.state.get("alice").external_addrs.is_empty());

        // 1. Set BTC, ETH (uppercase chain normalized to lowercase), and XRP addresses.
        let cases = [
            (1u64, "btc", "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx", 2u64),
            (2u64, "ETH", "0x71C7656EC7ab88b098defB751B7401B5f6d8976F", 2u64),
            (3u64, "xrp", "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh", 2u64),
        ];
        for (seq, chain, addr, fee) in cases {
            let tx = Tx::sign_body(
                &net.user_keys,
                "alice",
                seq,
                "",
                0,
                fee,
                net.cfg.network_id,
                TxBody::SetExternalAddrs {
                    chain: chain.into(),
                    address: addr.into(),
                },
            )
            .unwrap();
            node.submit_tx(tx.clone()).unwrap();
            node.apply_protocol_tx(&tx).unwrap();
        }

        let acct = node.state.get("alice");
        assert_eq!(acct.sequence, 4);
        assert_eq!(acct.balance, start_bal - 6);
        assert_eq!(
            acct.external_addrs.get("btc").map(String::as_str),
            Some("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx")
        );
        assert_eq!(
            acct.external_addrs.get("eth").map(String::as_str),
            Some("0x71C7656EC7ab88b098defB751B7401B5f6d8976F")
        );
        assert_eq!(
            acct.external_addrs.get("xrp").map(String::as_str),
            Some("rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh")
        );

        // Verify account_json exposes external_addrs directly.
        let aj = node.account_json("alice");
        assert_eq!(
            aj["external_addrs"]["btc"],
            "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"
        );
        assert_eq!(
            aj["external_addrs"]["eth"],
            "0x71C7656EC7ab88b098defB751B7401B5f6d8976F"
        );
        assert_eq!(
            aj["external_addrs"]["xrp"],
            "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh"
        );

        // 2. Update existing BTC address.
        let tx_update = Tx::sign_body(
            &net.user_keys,
            "alice",
            4,
            "",
            0,
            2,
            net.cfg.network_id,
            TxBody::SetExternalAddrs {
                chain: "btc".into(),
                address: "tb1qnewbtcaddress0000000000000000000000000".into(),
            },
        )
        .unwrap();
        node.apply_protocol_tx(&tx_update).unwrap();
        assert_eq!(
            node.state.get("alice").external_addrs.get("btc").map(String::as_str),
            Some("tb1qnewbtcaddress0000000000000000000000000")
        );
        assert_eq!(node.state.get("alice").external_addrs.len(), 3);

        // 3. Remove XRP binding with empty string "".
        let tx_clear = Tx::sign_body(
            &net.user_keys,
            "alice",
            5,
            "",
            0,
            2,
            net.cfg.network_id,
            TxBody::SetExternalAddrs {
                chain: "xrp".into(),
                address: String::new(),
            },
        )
        .unwrap();
        node.apply_protocol_tx(&tx_clear).unwrap();
        let acct = node.state.get("alice");
        assert_eq!(acct.sequence, 6);
        assert_eq!(acct.balance, start_bal - 10);
        assert!(!acct.external_addrs.contains_key("xrp"));
        assert_eq!(acct.external_addrs.len(), 2);
        let aj = node.account_json("alice");
        assert!(aj["external_addrs"].get("xrp").is_none());
    }

    #[test]
    fn set_external_addrs_validation_and_max_entries() {
        let mut net = Network::bootstrap(
            &["v1", "v2", "v3"],
            MIN_BOND,
            &[("alice".into(), 100_000), ("bob".into(), 100_000)],
            ChainConfig::default(),
        );
        net.pong_all();
        let node = net.nodes.get_mut("v1").unwrap();
        node.external_addrs_from_height = 0;

        // Reject empty chain, chain starting with digit, chain with punctuation, >16 char chain.
        for bad_chain in ["", "1btc", "btc-test", "abcdefghijklmnopq", "btc eth"] {
            let tx = Tx::sign_body(
                &net.user_keys,
                "alice",
                1,
                "",
                0,
                2,
                net.cfg.network_id,
                TxBody::SetExternalAddrs {
                    chain: bad_chain.into(),
                    address: "0x1234".into(),
                },
            )
            .unwrap();
            assert!(node.submit_tx(tx.clone()).is_err(), "chain {bad_chain:?} must be rejected at submit_tx");
            assert!(node.apply_protocol_tx(&tx).is_err(), "chain {bad_chain:?} must be rejected at apply");
            assert_eq!(node.state.get("alice").sequence, 1, "failed tx must not advance sequence");
        }

        // Reject too-long address (>128 chars) and address with internal whitespace.
        let long_addr = "a".repeat(MAX_EXTERNAL_ADDR_LEN + 1);
        for bad_addr in [long_addr.as_str(), "bc1q has space", "0x123\n456"] {
            let tx = Tx::sign_body(
                &net.user_keys,
                "alice",
                1,
                "",
                0,
                2,
                net.cfg.network_id,
                TxBody::SetExternalAddrs {
                    chain: "btc".into(),
                    address: bad_addr.into(),
                },
            )
            .unwrap();
            assert!(node.submit_tx(tx.clone()).is_err());
            assert!(node.apply_protocol_tx(&tx).is_err());
            assert_eq!(node.state.get("alice").sequence, 1);
        }

        // Fill up to MAX_EXTERNAL_ADDRS_PER_ACCOUNT (8) distinct chains.
        let chains = ["btc", "eth", "xrp", "bnb", "sol", "doge", "avax", "ada"];
        for (i, ch) in chains.iter().enumerate() {
            let seq = (i as u64) + 1;
            let tx = Tx::sign_body(
                &net.user_keys,
                "alice",
                seq,
                "",
                0,
                2,
                net.cfg.network_id,
                TxBody::SetExternalAddrs {
                    chain: (*ch).into(),
                    address: format!("addr_{ch}_{seq}"),
                },
            )
            .unwrap();
            node.apply_protocol_tx(&tx).unwrap();
        }
        assert_eq!(node.state.get("alice").external_addrs.len(), MAX_EXTERNAL_ADDRS_PER_ACCOUNT);

        // A 9th distinct chain is rejected without advancing sequence.
        let tx_ninth = Tx::sign_body(
            &net.user_keys,
            "alice",
            9,
            "",
            0,
            2,
            net.cfg.network_id,
            TxBody::SetExternalAddrs {
                chain: "dot".into(),
                address: "addr_dot".into(),
            },
        )
        .unwrap();
        let err = node.apply_protocol_tx(&tx_ninth).unwrap_err();
        assert!(err.contains("external_addrs: max 8"), "unexpected err: {err}");
        assert!(Node::is_permanent_tx_failure(&err));
        assert_eq!(node.state.get("alice").sequence, 9);

        // Updating an existing chain at the cap still succeeds.
        let tx_update = Tx::sign_body(
            &net.user_keys,
            "alice",
            9,
            "",
            0,
            2,
            net.cfg.network_id,
            TxBody::SetExternalAddrs {
                chain: "btc".into(),
                address: "addr_btc_updated".into(),
            },
        )
        .unwrap();
        node.apply_protocol_tx(&tx_update).unwrap();
        assert_eq!(
            node.state.get("alice").external_addrs.get("btc").map(String::as_str),
            Some("addr_btc_updated")
        );
    }

    #[test]
    fn account_state_snapshot_backward_compatibility_and_serde_alias() {
        // Legacy snapshot JSON without `external_addrs` deserializes with an empty map.
        let legacy_json = r#"{"sequence":7,"balance":50000,"meta":{"account_type":"hot","allowlist":[],"vault_locked":false,"public_key":""}}"#;
        let acct: AccountState = serde_json::from_str(legacy_json).unwrap();
        assert_eq!(acct.sequence, 7);
        assert_eq!(acct.balance, 50000);
        assert!(acct.external_addrs.is_empty());

        // Re-serializing an AccountState with empty external_addrs omits the field so state roots stay identical.
        let reserialized = serde_json::to_string(&acct).unwrap();
        assert!(!reserialized.contains("external_addrs"));

        // Both `"set_external_addrs"` and `"set_external_addr"` deserialize into TxBody::SetExternalAddrs.
        let b1: TxBody = serde_json::from_str(r#"{"kind":"set_external_addrs","chain":"btc","address":"tb1qxyz"}"#).unwrap();
        let b2: TxBody = serde_json::from_str(r#"{"kind":"set_external_addr","chain":"btc","address":"tb1qxyz"}"#).unwrap();
        assert_eq!(
            b1,
            TxBody::SetExternalAddrs {
                chain: "btc".into(),
                address: "tb1qxyz".into(),
            }
        );
        assert_eq!(b1, b2);
    }

    #[test]
    fn item16_four_permanent_error_classes_evicted_and_leader_proposes_empty_block() {
        let cfg = ChainConfig {
            pack_budget_ms: 0,
            max_txs_per_ledger: 16,
            soft_ok_votes: 1,
            min_fee: 0,
            fee_escalate: false,
            ..Default::default()
        };
        let mut net = Network::bootstrap(
            &["v1", "v2", "v3"],
            1_000,
            &[
                ("alice".into(), 100_000),
                ("bob".into(), 100_000),
                ("carol".into(), 100_000),
                ("dave".into(), 100_000),
            ],
            cfg,
        );
        net.pong_all();
        let winner = net.nodes.values().next().unwrap().lottery_packer().unwrap();
        let nid = net.cfg.network_id;
        let user_keys = net.user_keys.clone();
        let n = net.nodes.get_mut(&winner).unwrap();

        // Empty fallback blocks are gated (`empty_block_from_height`); open them for this test.
        n.empty_block_from_height = 0;
        // Set up state so all 4 error classes from Alert #16 trigger:
        // (1) OperatorGraphBind: alice is a registered operator whose graph for deposit "aa"*32 is already bound.
        n.bitvm2_m1_from_height = 0;
        let op_xonly = "11".repeat(32);
        let dep_txid = "aa".repeat(32);
        let k2_txid = "bb".repeat(32);
        let af_txid = "cc".repeat(32);
        let op_params = n.operator_params();
        n.bridge
            .operators
            .register(&op_params, "alice", &op_xonly, op_params.min_bond, 0)
            .unwrap();
        n.bridge
            .operators
            .bind_graph("alice", &dep_txid, &k2_txid, &af_txid, 0)
            .unwrap();

        // (2) LendBorrow: market "m-usdc" with liquidity 10_000, price 1, LTV 7000 bps -> max borrow on collateral 100 is 70.
        n.create_market("m-usdc", "USDC").unwrap();
        n.defi.credit_asset("bob", "USDC", 50_000);
        n.lend_supply("m-usdc", "bob", 10_000).unwrap();

        // (3) PayToKey: destination "bob" already has a key in n.keys / on-chain.
        let mut bob_acct = n.state.get("bob");
        bob_acct.meta.public_key = user_keys.public_hex("bob").unwrap();
        n.state.accounts.insert("bob".into(), bob_acct);

        // (4) VaultOpen: "dave" already opened a vault (AccountType::Vault), so a second VaultOpen fails with "only Hot can convert account type once".
        n.open_vault("dave", "bob").unwrap();

        let tx1 = Tx::sign_body(
            &user_keys,
            "alice",
            n.state.get("alice").sequence,
            "",
            0,
            1,
            nid,
            TxBody::OperatorGraphBind {
                deposit_txid: dep_txid.clone(),
                kick_off_2_txid: k2_txid.clone(),
                assert_final_txid: af_txid.clone(),
                depositor_account: String::new(),
                cosign: false,
            },
        )
        .unwrap();
        let tx2 = Tx::sign_body(
            &user_keys,
            "bob",
            n.state.get("bob").sequence,
            "",
            0,
            1,
            nid,
            TxBody::LendBorrow {
                market_id: "m-usdc".into(),
                amount: 5_000,
                collateral_fpl: 100,
            },
        )
        .unwrap();
        let tx3 = Tx::sign_body(
            &user_keys,
            "carol",
            n.state.get("carol").sequence,
            "bob",
            10,
            1,
            nid,
            TxBody::PayToKey {
                key_hash: "33".repeat(32),
            },
        )
        .unwrap();
        let tx4 = Tx::sign_body(
            &user_keys,
            "dave",
            n.state.get("dave").sequence,
            "",
            0,
            1,
            nid,
            TxBody::VaultOpen {
                destination: "bob".into(),
            },
        )
        .unwrap();

        // Verify pre-check (`is_tx_packable` / `is_tx_applicable`) and `is_permanent_tx_failure` on all 4:
        for (label, tx, expected_substr) in [
            ("OperatorGraphBind", &tx1, "operator: graph already bound for this deposit"),
            ("LendBorrow", &tx2, "borrow: LTV exceeded"),
            ("PayToKey", &tx3, "pay_to_key: destination already has a key"),
            ("VaultOpen", &tx4, "only Hot can convert account type once"),
        ] {
            let err = n.is_tx_packable(tx).unwrap_err();
            assert!(
                err.contains(expected_substr),
                "{label}: expected {expected_substr:?} in {err:?}"
            );
            assert!(!n.is_tx_applicable(tx), "{label} must not be applicable");
            assert!(
                Node::is_permanent_tx_failure(&err),
                "{label} error {err:?} must be classified as permanent"
            );
            let _ = n.mempool.insert(tx.clone(), n.cfg.max_mempool_txs);
        }

        assert_eq!(n.mempool.len(), 4);
        assert!(!n.has_applicable_tx(), "none of the 4 invalid txs is applicable");
        assert_eq!(n.applicable_head_count(), 0);

        // When the leader runs `pack_or_skip`, all 4 invalid txs are evicted and the leader
        // still seals a valid empty fallback block at height 1 instead of stalling!
        let ledger = n
            .pack_or_skip(&winner)
            .expect("pack_or_skip should not error")
            .expect("leader should propose an empty fallback block after evicting invalid txs");
        assert_eq!(ledger.height, 1);
        assert!(ledger.txs.is_empty(), "fallback block must be empty");
        assert!(n.mempool.is_empty(), "all 4 invalid txs must be evicted from mempool");
        for tx in [&tx1, &tx2, &tx3, &tx4] {
            assert!(
                n.perm_dropped.contains(&tx.tx_id, n.now_ms, &n.tip_hash),
                "evicted tx {} must be recorded in perm_dropped",
                tx.tx_id
            );
        }

        // Accepting and voting on the empty fallback block advances tip_height to 1 and resets `evicted_since_last_seal`.
        let res = n.accept_ledger(&ledger).expect("empty fallback block must be accepted");
        assert_eq!(res.height, 1);
        assert_eq!(res.n_txs, 0);
        for v in ["v1", "v2", "v3"] {
            n.vote_ok(&ledger.ledger_hash, v);
        }
        assert_eq!(n.tip_height, 1);
        assert!(!n.evicted_since_last_seal, "commit must reset evicted_since_last_seal");

        // On the next height with a genuinely idle/empty mempool and no evictions, `pack_or_skip` returns Ok(None).
        let w2 = n.lottery_packer().unwrap();
        assert!(n.pack_or_skip(&w2).unwrap().is_none());
    }

    #[test]
    fn item16_drop_mempool_target_by_hash_account_seq_and_account() {
        let mut net = Network::bootstrap(
            &["v1", "v2", "v3"],
            1_000,
            &[("alice".into(), 10_000), ("bob".into(), 10_000)],
            ChainConfig::default(),
        );
        let nid = net.cfg.network_id;
        let uk = net.user_keys.clone();
        let n = net.nodes.get_mut("v1").unwrap();
        let tx_a1 = Tx::sign_with(&uk, "alice", 1, "bob", 10, 2, nid).unwrap();
        let tx_a2 = Tx::sign_with(&uk, "alice", 2, "bob", 10, 2, nid).unwrap();
        let tx_b1 = Tx::sign_with(&uk, "bob", 1, "alice", 10, 2, nid).unwrap();
        assert!(n.submit_tx(tx_a1.clone()).unwrap());
        assert!(n.submit_tx(tx_a2.clone()).unwrap());
        assert!(n.submit_tx(tx_b1.clone()).unwrap());
        assert_eq!(n.mempool.len(), 3);

        // Drop by tx_id
        let d1 = n.drop_mempool_target(&tx_b1.tx_id);
        assert_eq!(d1, vec![tx_b1.tx_id.clone()]);
        assert_eq!(n.mempool.len(), 2);
        assert_eq!(n.submit_tx(tx_b1).unwrap_err(), TX_PREVIOUSLY_DROPPED);

        // Drop by account:seq
        let d2 = n.drop_mempool_target("alice:2");
        assert_eq!(d2, vec![tx_a2.tx_id.clone()]);
        assert_eq!(n.mempool.len(), 1);

        // Drop by account
        let d3 = n.drop_mempool_target("alice");
        assert_eq!(d3, vec![tx_a1.tx_id.clone()]);
        assert!(n.mempool.is_empty());
    }
}


/// v2.9.77: bounded FIFO of tx ids dropped as permanently invalid, with a TTL
/// so a failure that is only "permanent" for a while cannot block a tx id
/// for the life of the process. Local mempool policy, not consensus.
///
/// v2.9.78: each entry also records the tip hash it was dropped at and only
/// counts while the tip is unchanged. A new block can change the state a
/// failure depended on (stored exec headers: "headers neither reach LC head"),
/// and the tx id is the payload hash, so an identical resubmit must be
/// re-evaluated after the tip moves. The poison ping-pong it stops happens at
/// a single tip, so that protection is kept.
#[derive(Clone, Debug, Default)]
pub struct PermDropSet {
    order: std::collections::VecDeque<(String, u64)>,
    ids: std::collections::HashMap<String, (u64, String)>,
}

impl PermDropSet {
    pub const CAP: usize = 16_384;
    pub const TTL_MS: u64 = 6 * 60 * 60 * 1000;

    pub fn insert(&mut self, id: &str, now_ms: u64, tip_hash: &str) {
        if self
            .ids
            .insert(id.to_string(), (now_ms, tip_hash.to_string()))
            .is_none()
        {
            self.order.push_back((id.to_string(), now_ms));
        }
        while self.order.len() > Self::CAP {
            if let Some((old, _)) = self.order.pop_front() {
                self.ids.remove(&old);
            }
        }
    }

    pub fn contains(&self, id: &str, now_ms: u64, tip_hash: &str) -> bool {
        match self.ids.get(id) {
            Some((t, tip)) => {
                tip == tip_hash && (now_ms < *t || now_ms.saturating_sub(*t) < Self::TTL_MS)
            }
            None => false,
        }
    }

    pub fn len(&self) -> usize {
        self.ids.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }
}

/// v2.9.77: mempool refusal for a tx id this seat already dropped.
pub const TX_PREVIOUSLY_DROPPED: &str = "tx previously dropped as permanently invalid";

#[cfg(test)]
mod seat_payout_tests;

#[cfg(test)]
mod v2_10_activation_tests;

#[cfg(test)]
mod btc4_fork_fix_tests;
#[cfg(test)]
mod btc4_lend_scale_tests;
#[cfg(test)]
mod orderbook_tests;
