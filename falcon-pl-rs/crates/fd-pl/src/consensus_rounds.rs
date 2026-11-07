// Copyright (c) 2025-2026 BEARTEC. All rights reserved. See LICENSE.
//! # Round-scoped votes, deterministic per-round proposer, liveness (v2.10.0)
//!
//! **Incident (2026-09-28, testnet 2300, h=369421):** a timeout let two seats
//! seal the same height (v12 → `58b308…`, v10 → `00349f…`). Votes split 3-3 at
//! 4-of-6. Every node then picked `00349f` (lower hash) but refused the
//! `58b308` voters' later OKs as "checker equivocation" because `pl-ok:v1`
//! binds only `(height, hash)`. The stall check matched on log text
//! ("equivocation/fork") so view-change never ran. Halted ~6.5 days.
//!
//! **Design** (active from `ChainConfig::vote_rounds_from_height`):
//!
//! 1. **Votes are scoped to (height, round).** `pl-ok:v2|net|h|round|hash|voter`.
//!    A vote in a later round for another body is *not* equivocation. Two OKs
//!    for different hashes in **one** (height, round) are — that evidence is
//!    kept (never dropped on view-change/reopen) and rides the next ledger.
//!    Receivers verify the two signatures before applying the slash.
//! 2. **Commit needs 4-of-6 in one round.** The cert carries the round.
//! 3. **Lock rule (safety across rounds).** After OK'ing `A` in round `r`, a
//!    seat may OK a different body in a later round only when its view of
//!    round `r` proves `A` can never reach quorum (≥ n−q+1 other voters, e.g.
//!    3 of 6). In a 3-3 split both sides are provably dead → everyone is free.
//!    Otherwise it re-votes `A`.
//! 4. **One proposer per (height, round):** `order[round % n]` over the
//!    tip-frozen committee. The local skip cursor is *derived* from the round
//!    (no SkipPacker QC, no "silent packer" guess that differed per node — the
//!    old way two seats both thought they were the winner). Only that seat's
//!    body is staged; a late body from an earlier round's seat is cached
//!    (validated) but not staged or voted unless it already leads the vote.
//! 5. **Round timeout** advances the round by 4-of-6 ViewChange QC. Timers are
//!    **work-gated** (blocks are load-driven: an idle tip never times out and
//!    never walks the cursor) and back off per round. A proven split advances
//!    immediately. A node that sees a QC for a higher round jumps to it (a
//!    restarted seat re-syncs its round from peers' re-gossip).
//! 6. **Re-vote, don't re-mint.** On a new round each seat re-votes its target
//!    body (lock if alive, else the body with most votes, tie → current
//!    proposer's, then lower hash). The 3-3 split converges in round 1 on one
//!    body with 6 votes. A body that survives `MAX_PENDING_ROUNDS` advances is
//!    dropped and the round's proposer seals fresh.
//! 7. **Typed stall + watchdog.** [`ConsensusStall`] replaces substring
//!    matching. [`Node::liveness_tick`] alerts when work exists (pending body
//!    or applicable txs / hub inventory) but the tip is flat for
//!    `liveness_alert_ms`. A quiet chain (no txs) never alerts.
//! 8. **Restart safety.** Open-height `round_votes` persist in snapshots and a
//!    small own-vote journal, so a restarted seat keeps its lock and never
//!    signs a second hash in a round it already voted in. Re-gossiped old
//!    votes stay in their own round and cannot block a newer round.

use std::collections::{BTreeMap, BTreeSet};

use crate::{AcceptResult, ConsensusStall, Ledger, LivenessStatus, Node};

impl Node {
    /// Round used for re-certifying an already committed tip (cert rebuild
    /// after snapshot). Nothing else is ever voted in it, so it cannot clash
    /// with a live round's vote.
    pub const RECERT_ROUND: u64 = u64::MAX;
    /// A ViewChange more than this many rounds ahead is ignored (bounded state).
    pub const MAX_ROUND_JUMP: u64 = 64;
    /// Round advances a pending body may survive before it is dropped (unless
    /// this seat is locked on it and the lock is still alive).
    pub const MAX_PENDING_ROUNDS: u32 = 3;
    /// Validated bodies cached per open height.
    pub const OPEN_BODIES_CAP: usize = 8;
    /// Rounds of vote history retained per open height.
    pub const ROUND_HISTORY: usize = 32;

    /// Round-scoped votes (v2.10.0) are active at `height`: at/after
    /// `vote_rounds_from_height` and outside the pause window (v2.9.48).
    pub fn vote_rounds_at(&self, height: u64) -> bool {
        let a = self.cfg.vote_rounds_from_height;
        a > 0 && height >= a && !self.vote_rounds_paused_at(height)
    }

    /// `height` lies in the Phase 2 pause window
    /// `[vote_rounds_pause_from, vote_rounds_resume_at)` — certs and votes
    /// there use the legacy `pl-ok:v1` payload (e.g. 2300: the legacy-signed
    /// history after the 2026-10-05 pause, up to the re-enable height).
    pub fn vote_rounds_paused_at(&self, height: u64) -> bool {
        let (f, r) = (self.cfg.vote_rounds_pause_from, self.cfg.vote_rounds_resume_at);
        f > 0 && r > f && height >= f && height < r
    }

    /// Round this seat signs its own OK in for `height`.
    pub fn own_ok_round(&self, height: u64) -> u64 {
        if !self.vote_rounds_at(height) {
            0
        } else if height <= self.tip_height {
            Self::RECERT_ROUND
        } else {
            self.height_view_round
        }
    }

    /// Typed dual / split detection for the open height (legacy path too).
    pub fn open_height_dual(&self, height: u64) -> bool {
        let typed = match &self.stall {
            Some(ConsensusStall::IngestFork { .. }) => true,
            Some(s) => s.height() == height,
            None => false,
        };
        // Checker OKs at this height already span two hashes: the second body
        // can never reach 4-of-6 while the first OKs pin the voters (legacy).
        let split_oks = self
            .ok_by_height_voter
            .get(&height)
            .map(|m| m.values().collect::<BTreeSet<_>>().len() > 1)
            .unwrap_or(false);
        typed || split_oks
    }

    // ------------------------------------------------------------------
    // Vote recording / tally
    // ------------------------------------------------------------------

    fn committee_n(&self) -> usize {
        let q = self.qc_voters();
        if q.is_empty() {
            self.checker_count()
        } else {
            q.len()
        }
    }

    fn equivocators_at(&self, height: u64) -> BTreeSet<String> {
        self.pending_slashes
            .iter()
            .filter(|e| e.height == height && e.kind.is_empty())
            .map(|e| e.offender.clone())
            .collect()
    }

    /// Record a round-scoped OK. Returns `(soft, hard, fresh)`.
    pub(crate) fn record_round_ok(
        &mut self,
        height: u64,
        round: u64,
        ledger_hash: &str,
        voter: &str,
        signature: &str,
    ) -> (bool, bool, bool) {
        if !self.eligible_voter(voter) || ledger_hash.is_empty() {
            return (false, false, false);
        }
        if round == Self::RECERT_ROUND {
            if height > self.tip_height {
                return (false, false, false);
            }
        } else if height > self.tip_height
            && round > self.height_view_round.saturating_add(Self::MAX_ROUND_JUMP)
        {
            return (false, false, false);
        }
        if voter == self.id && self.may_cast_own_ok(height, round, ledger_hash).is_err() {
            return (false, false, false);
        }
        let prev = self
            .round_votes
            .get(&height)
            .and_then(|m| m.get(&round))
            .and_then(|v| v.get(voter))
            .cloned();
        if let Some((prev_hash, prev_sig)) = prev {
            if prev_hash != ledger_hash {
                // Same (height, round), two hashes: real, slashable equivocation.
                let ev = crate::SlashEvidence {
                    offender: voter.to_string(),
                    height,
                    hash_a: prev_hash.clone(),
                    sig_a: prev_sig,
                    hash_b: ledger_hash.to_string(),
                    sig_b: signature.to_string(),
                    kind: String::new(),
                    round,
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
                    round,
                    voter: voter.to_string(),
                });
                self.last_catchup_conflict = format!(
                    "checker equivocation {voter} h={height} round={round} queued (had {prev_hash} got {ledger_hash})"
                );
                return (false, false, false);
            }
            let (s, h) = self.retally_round(height, round, ledger_hash);
            return (s, h, false);
        }
        {
            let rounds = self.round_votes.entry(height).or_default();
            rounds
                .entry(round)
                .or_default()
                .insert(voter.to_string(), (ledger_hash.to_string(), signature.to_string()));
            while rounds.len() > Self::ROUND_HISTORY {
                // Drop the oldest live round (never the recert slot).
                let Some(oldest) = rounds.keys().copied().find(|r| *r != Self::RECERT_ROUND) else {
                    break;
                };
                if oldest == round {
                    break;
                }
                rounds.remove(&oldest);
            }
        }
        self.ok_by_height_voter
            .entry(height)
            .or_default()
            .insert(voter.to_string(), ledger_hash.to_string());
        if voter == self.id {
            self.write_vote_journal();
        }
        self.epoch_work.record_check(voter, ledger_hash);
        let (s, h) = self.retally_round(height, round, ledger_hash);
        (s, h, true)
    }

    /// Recount `ledger_hash` in `round`; adopt that round's voter set into
    /// `ok_votes` when it is the best evidence for the hash. Commits on QC.
    pub(crate) fn retally_round(&mut self, height: u64, round: u64, ledger_hash: &str) -> (bool, bool) {
        let mut voters = BTreeSet::new();
        let mut sigs = std::collections::HashMap::new();
        if let Some(v) = self.round_votes.get(&height).and_then(|m| m.get(&round)) {
            for (id, (h, sig)) in v {
                if h == ledger_hash {
                    voters.insert(id.clone());
                    if !sig.is_empty() {
                        sigs.insert(id.clone(), sig.clone());
                    }
                }
            }
        }
        let qc = self.qc_voters();
        let count = |set: &BTreeSet<String>| {
            if qc.is_empty() {
                set.len()
            } else {
                set.iter().filter(|id| qc.iter().any(|c| c == *id)).count()
            }
        };
        let need = self.commit_votes_needed();
        let new_n = count(&voters);
        let cur_round = self.ok_round.get(ledger_hash).copied();
        let cur_n = self.ok_votes.get(ledger_hash).map(&count).unwrap_or(0);
        let adopt = cur_round.is_none()
            || cur_round == Some(round)
            || (cur_n < need && new_n >= cur_n);
        if adopt && !voters.is_empty() {
            self.ok_votes.insert(ledger_hash.to_string(), voters);
            self.ok_sigs.insert(ledger_hash.to_string(), sigs);
            self.ok_round.insert(ledger_hash.to_string(), round);
        }
        let (soft_n, hard_n) = match self.ok_votes.get(ledger_hash) {
            Some(set) => (count(set), set.len()),
            None => (0, 0),
        };
        let soft = soft_n >= need;
        let hard = hard_n >= self.hard_votes_needed();
        if soft {
            self.soft_ok.insert(ledger_hash.to_string());
            self.store_cert_if_ready(ledger_hash, height);
        }
        if hard {
            self.hard_ok.insert(ledger_hash.to_string());
        }
        if soft && height == self.tip_height.saturating_add(1) {
            // A same-round QC wins over local preference: commit that body.
            let pending_is = self
                .pending_proposal
                .as_ref()
                .map(|p| p.ledger_hash == ledger_hash)
                .unwrap_or(false);
            if !pending_is {
                if let Some(b) = self.open_bodies.get(ledger_hash).cloned() {
                    self.seen_at_height
                        .insert(height, (b.packer.clone(), b.ledger_hash.clone()));
                    self.pending_proposal = Some(b);
                }
            }
            let pending_is = self
                .pending_proposal
                .as_ref()
                .map(|p| p.ledger_hash == ledger_hash)
                .unwrap_or(false);
            if pending_is && !self.rival_has_soft_qc(ledger_hash) {
                if let Err(e) = self.commit_pending_proposal() {
                    self.last_catchup_conflict = format!(
                        "soft-QC commit failed h={height} hash={}: {e}",
                        &ledger_hash[..16.min(ledger_hash.len())]
                    );
                }
            }
        }
        (soft, hard)
    }

    /// `hash` can no longer reach commit quorum in `round` (enough distinct,
    /// non-equivocating committee voters chose something else).
    pub fn round_hash_dead(&self, height: u64, round: u64, hash: &str) -> bool {
        let n = self.committee_n();
        let need = self.commit_votes_needed();
        let eq = self.equivocators_at(height);
        let other = self
            .round_votes
            .get(&height)
            .and_then(|m| m.get(&round))
            .map(|v| {
                v.iter()
                    .filter(|(id, (h, _))| {
                        h != hash && self.counts_as_qc_voter(id) && !eq.contains(*id)
                    })
                    .count()
            })
            .unwrap_or(0);
        n.saturating_sub(other) < need
    }

    /// No hash at all can reach quorum in `round` (split vote, e.g. 3-3 at 4-of-6).
    pub fn round_split_dead(&self, height: u64, round: u64) -> bool {
        let n = self.committee_n();
        let need = self.commit_votes_needed();
        let eq = self.equivocators_at(height);
        let Some(v) = self.round_votes.get(&height).and_then(|m| m.get(&round)) else {
            return false;
        };
        let mut per: BTreeMap<&str, usize> = BTreeMap::new();
        let mut seen = 0usize;
        for (id, (h, _)) in v {
            if self.counts_as_qc_voter(id) && !eq.contains(id) {
                seen += 1;
                *per.entry(h.as_str()).or_default() += 1;
            }
        }
        let maxv = per.values().copied().max().unwrap_or(0);
        seen > 0 && maxv + n.saturating_sub(seen) < need
    }

    /// This seat's most recent OK at `height` outside `except_round`.
    pub fn my_lock(&self, height: u64, except_round: Option<u64>) -> Option<(u64, String)> {
        let m = self.round_votes.get(&height)?;
        m.iter()
            .rev()
            .filter(|(r, _)| **r != Self::RECERT_ROUND && Some(**r) != except_round)
            .find_map(|(r, v)| v.get(&self.id).map(|(h, _)| (*r, h.clone())))
    }

    /// Whether this seat may sign an OK for `hash` in (`height`, `round`).
    pub fn may_cast_own_ok(&self, height: u64, round: u64, hash: &str) -> Result<(), String> {
        if !self.vote_rounds_at(height) {
            // Legacy `pl-ok:v1`: one hash per height, or we hand out evidence.
            if let Some(prev) = self.ok_by_height_voter.get(&height).and_then(|m| m.get(&self.id)) {
                if prev != hash {
                    return Err(format!("already OK'd {prev} at h={height} (v1 votes)"));
                }
            }
            return Ok(());
        }
        if round == Self::RECERT_ROUND {
            return if height <= self.tip_height {
                Ok(())
            } else {
                Err("recert round is for committed heights only".into())
            };
        }
        if height <= self.tip_height {
            return Err(format!("h={height} already committed"));
        }
        if let Some((h, _)) = self
            .round_votes
            .get(&height)
            .and_then(|m| m.get(&round))
            .and_then(|v| v.get(&self.id))
        {
            return if h == hash {
                Ok(())
            } else {
                Err(format!("already OK'd {h} in h={height} round={round}"))
            };
        }
        if let Some((rl, lock)) = self.my_lock(height, Some(round)) {
            if lock != hash && !self.round_hash_dead(height, rl, &lock) {
                let pending_is_this = self
                    .pending_proposal
                    .as_ref()
                    .map(|p| p.ledger_hash == hash)
                    .unwrap_or(false);
                // The locked body has already been dropped. Keeping the lock
                // then refuses every later proposal and the height never seals.
                let lock_gone = !self.open_bodies.contains_key(&lock);
                if !(lock_gone && pending_is_this && round > rl) {
                    return Err(format!(
                        "locked on {lock} from round {rl} (still able to reach quorum)"
                    ));
                }
            }
        }
        Ok(())
    }

    /// Sign this seat's OK for `hash` if allowed. Returns `(round, signature)`.
    /// Only the staged attempt body (or the committed tip) is ever signed.
    pub fn own_ok_vote(&mut self, height: u64, hash: &str) -> Option<(u64, String)> {
        if height > self.tip_height {
            let staged = self
                .pending_proposal
                .as_ref()
                .map(|p| p.height == height && p.ledger_hash == hash)
                .unwrap_or(false);
            if !staged {
                return None;
            }
        } else if height == self.tip_height && hash != self.tip_hash {
            return None;
        }
        let round = self.own_ok_round(height);
        self.may_cast_own_ok(height, round, hash).ok()?;
        let sig = self.sign_ok_vote_round(height, round, hash);
        if sig.is_empty() && self.cfg.require_vote_sigs {
            return None;
        }
        Some((round, sig))
    }

    // ------------------------------------------------------------------
    // Proposer / rounds
    // ------------------------------------------------------------------

    /// The single legal proposer for (`height`, `round`): `order[round % n]`.
    pub fn round_proposer(&self, round: u64) -> Option<String> {
        let order = self.lottery_order();
        if order.is_empty() {
            return None;
        }
        let k = (round % order.len() as u64) as usize;
        order.get(k).cloned()
    }

    /// Derive the skip cursor from the round so `lottery_packer()`,
    /// `skip_claims_for_packer` and `validate_proposal_seats` all agree with
    /// `round_proposer`. Identical on every seat that is in the same round.
    pub(crate) fn sync_round_skips(&mut self, height: u64) {
        if height != self.tip_height.saturating_add(1) {
            return;
        }
        let order = self.lottery_order();
        if order.is_empty() {
            return;
        }
        let k = (self.height_view_round % order.len() as u64) as usize;
        let set: BTreeSet<String> = order[..k].iter().cloned().collect();
        if set.is_empty() {
            self.skips.remove(&height);
        } else {
            self.skips.insert(height, set);
        }
        self.skip_votes.remove(&height);
    }

    /// Record a signed ViewChange vote on a round-scoped height.
    pub(crate) fn vote_round_change(&mut self, height: u64, round: u64, voter: &str) -> (bool, bool) {
        let cur = self.height_view_round;
        if round <= cur || round > cur.saturating_add(Self::MAX_ROUND_JUMP) {
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
        let fresh = voters.insert(voter.to_string());
        let n = voters
            .iter()
            .filter(|id| qc.is_empty() || qc.iter().any(|c| c == *id))
            .count();
        if n >= self.commit_votes_needed() {
            self.apply_round_advance(height, round);
            return (true, fresh);
        }
        (false, fresh)
    }

    /// Enter `round` at `height` after a ViewChange QC.
    pub(crate) fn apply_round_advance(&mut self, height: u64, round: u64) {
        if height != self.tip_height.saturating_add(1) || round <= self.height_view_round {
            return;
        }
        let prev = self.height_view_round;
        self.height_view_round = round;
        if let Some(m) = self.view_change_votes.get_mut(&height) {
            m.retain(|r, _| *r > round);
        }
        self.stall = None;
        let n = self.lottery_order().len().max(1) as u64;
        let wrapped = round / n != prev / n;
        let lock_alive = |me: &Node, hash: &str| {
            me.my_lock(height, None)
                .map(|(rl, l)| l == hash && !me.round_hash_dead(height, rl, &l))
                .unwrap_or(false)
        };
        if let Some(p) = self.pending_proposal.clone().filter(|p| p.height == height) {
            self.pending_rounds = self.pending_rounds.saturating_add(1);
            let keep = self.pending_rounds < Self::MAX_PENDING_ROUNDS || lock_alive(self, &p.ledger_hash);
            if !keep {
                // Free the dropped packer so it can seal again when its round
                // comes back (height_sealers would otherwise refuse forever
                // until a full committee wrap).
                if let Some(set) = self.height_sealers.get_mut(&height) {
                    set.remove(&p.packer);
                }
                self.pending_proposal = None;
                self.seen_at_height.remove(&height);
                self.open_bodies.remove(&p.ledger_hash);
                self.pending_rounds = 0;
            }
        }
        // Every round advance: clear sealers not tied to the kept pending.
        // Round mode's one-proposer-per-round guard is sufficient; retaining
        // late-body sealers blocked soft-QC after view-change on live 2300.
        {
            let keep_packer = self
                .pending_proposal
                .as_ref()
                .filter(|p| p.height == height)
                .map(|p| p.packer.clone());
            if let Some(set) = self.height_sealers.get_mut(&height) {
                if let Some(ref kp) = keep_packer {
                    set.retain(|id| id == kp);
                } else {
                    set.clear();
                }
            }
        }
        if wrapped {
            // New rotation: every seat may seal once more. Keep only bodies we
            // are still bound to (staged / live lock).
            self.height_sealers.remove(&height);
            let pending_hash = self.pending_proposal.as_ref().map(|p| p.ledger_hash.clone());
            let lock = self
                .my_lock(height, None)
                .filter(|(rl, l)| !self.round_hash_dead(height, *rl, l))
                .map(|(_, l)| l);
            self.open_bodies
                .retain(|k, _| Some(k) == pending_hash.as_ref() || Some(k) == lock.as_ref());
            if self.pending_proposal.is_none() {
                self.seen_at_height.remove(&height);
            }
        }
        self.sync_round_skips(height);
        self.maybe_switch_target(height);
        self.height_open_ms = self.now_ms;
        self.round_open_ms = self.now_ms;
        self.skip_grace_until_ms = 0;
        let _ = self.sanitize_mempool();
        self.last_catchup_conflict = format!(
            "round {prev}→{round} at h={height} proposer={:?} target={:?}",
            self.round_proposer(round),
            self.pending_proposal
                .as_ref()
                .map(|p| p.ledger_hash.chars().take(16).collect::<String>())
        );
        // Re-vote the target body in the new round (wire layer re-signs + fans).
        if let Some(hash) = self.pending_proposal.as_ref().map(|p| p.ledger_hash.clone()) {
            let me = self.id.clone();
            let _ = self.vote_ok(&hash, &me);
        }
        // Count votes for this round that arrived before we entered it.
        let hashes: BTreeSet<String> = self
            .round_votes
            .get(&height)
            .and_then(|m| m.get(&round))
            .map(|v| v.values().map(|(h, _)| h.clone()).collect())
            .unwrap_or_default();
        for h in hashes {
            if self.tip_height >= height {
                break;
            }
            let _ = self.retally_round(height, round, &h);
        }
    }

    /// Best vote count `hash` reached in any round at `height`.
    fn best_round_count(&self, height: u64, hash: &str) -> usize {
        let Some(m) = self.round_votes.get(&height) else {
            return 0;
        };
        m.iter()
            .filter(|(r, _)| **r != Self::RECERT_ROUND)
            .map(|(_, v)| {
                v.iter()
                    .filter(|(id, (h, _))| h == hash && self.counts_as_qc_voter(id))
                    .count()
            })
            .max()
            .unwrap_or(0)
    }

    /// Body this seat should vote for in the current round.
    pub fn select_round_target(&self, height: u64) -> Option<String> {
        if let Some((rl, lock)) = self.my_lock(height, None) {
            if !self.round_hash_dead(height, rl, &lock) {
                return self.open_bodies.contains_key(&lock).then_some(lock);
            }
        }
        let proposer = self.round_proposer(self.height_view_round);
        let order = self.lottery_order();
        let n = order.len().max(1);
        let cur_slot = (self.height_view_round % n as u64) as usize;
        self.open_bodies
            .values()
            .filter(|b| b.height == height)
            .map(|b| {
                let votes = self.best_round_count(height, &b.ledger_hash);
                let is_prop = proposer.as_deref() == Some(b.packer.as_str())
                    && b.skipped_predecessors.len() == cur_slot;
                (votes, is_prop, std::cmp::Reverse(b.ledger_hash.clone()))
            })
            .max()
            .map(|(_, _, std::cmp::Reverse(h))| h)
            // A body nobody voted for and that is not this round's proposal is
            // a late body: do not stage it over the current proposer's.
            .filter(|h| {
                let b = &self.open_bodies[h];
                self.best_round_count(height, h) > 0
                    || (proposer.as_deref() == Some(b.packer.as_str())
                        && b.skipped_predecessors.len() == cur_slot)
            })
    }

    /// Stage the round target as `pending_proposal` if it differs.
    pub fn maybe_switch_target(&mut self, height: u64) {
        let Some(t) = self.select_round_target(height) else {
            return;
        };
        if self.pending_proposal.as_ref().map(|p| p.ledger_hash == t).unwrap_or(false) {
            return;
        }
        if let Some(b) = self.open_bodies.get(&t).cloned() {
            self.seen_at_height
                .insert(height, (b.packer.clone(), b.ledger_hash.clone()));
            self.pending_proposal = Some(b);
            self.pending_rounds = 0;
        }
    }

    /// Round timeout with a body in hand: proposal-timeout, backed off per round.
    pub fn round_timeout_ms(&self, round: u64) -> u64 {
        let base = self.proposal_timeout_ms();
        base.saturating_add(base.saturating_mul(round.min(4)) / 2)
    }

    /// Round timeout when the round's proposer has produced nothing.
    pub fn round_silence_timeout_ms(&self, round: u64) -> u64 {
        let base = if self.active_packer_unavailable() {
            self.cfg.progress_timeout_ms.max(1_000)
        } else {
            self.live_pack_timeout_ms().saturating_mul(2)
        };
        base.saturating_add(base.saturating_mul(round.min(4)) / 2)
    }

    pub(crate) fn note_work_state(&mut self) {
        if self.liveness_has_work() {
            if self.work_seen_since_ms == 0 {
                self.work_seen_since_ms = self.now_ms.max(1);
            }
        } else {
            self.work_seen_since_ms = 0;
        }
    }

    /// Round-mode ViewChange trigger. Returns `(height, tip, target_round)`.
    pub(crate) fn maybe_round_timeout_vote(&mut self, height: u64) -> Option<(u64, String, u64)> {
        self.note_work_state();
        self.sync_round_skips(height);
        let pending_here = self
            .pending_proposal
            .as_ref()
            .map(|p| p.height == height)
            .unwrap_or(false);
        let work = pending_here
            || self.network_has_pack_work()
            || self.mempool_poisoned()
            || !self.open_bodies.is_empty();
        if !work {
            // Load-driven chain: no txs ⇒ no round clock, no cursor walk.
            return None;
        }
        let r = self.height_view_round;
        let split = self.round_split_dead(height, r);
        if split && self.stall.is_none() {
            self.stall = Some(ConsensusStall::SplitVote { height, round: r });
        }
        let start = self.round_open_ms.max(self.work_seen_since_ms);
        let elapsed = self.now_ms.saturating_sub(start);
        let timeout = if pending_here || !self.open_bodies.is_empty() {
            self.round_timeout_ms(r)
        } else {
            self.round_silence_timeout_ms(r)
        };
        if !split && elapsed < timeout {
            return None;
        }
        let target = r.saturating_add(1);
        let me = self.id.clone();
        // Only committee seats vote rounds; others follow the QC.
        if !self.in_committee(&me) {
            return None;
        }
        let already = self
            .view_change_votes
            .get(&height)
            .and_then(|m| m.get(&target))
            .map(|s| s.contains(&me))
            .unwrap_or(false);
        let interval = self.cfg.progress_timeout_ms.max(1_000);
        if already && self.now_ms.saturating_sub(self.last_view_change_vote_ms) < interval {
            return None;
        }
        let _ = self.sanitize_mempool();
        let tip = self.tip_hash.clone();
        let sig = self.sign_vc_vote(height, &tip, target);
        self.last_view_change_vote_ms = self.now_ms;
        let _ = self.vote_view_change_ex(height, &tip, target, &me, &sig);
        Some((height, tip, target))
    }

    // ------------------------------------------------------------------
    // Proposals
    // ------------------------------------------------------------------

    /// Live staging on a round-scoped height (header/parent/sig/cert already
    /// checked by `accept_ledger_ex`).
    pub(crate) fn accept_round_proposal(&mut self, ledger: &Ledger) -> Result<AcceptResult, String> {
        let h = ledger.height;
        if self.schedule_height != h {
            self.freeze_open_height_schedule();
        }
        self.sync_round_skips(h);
        let result = AcceptResult {
            height: h,
            packer: ledger.packer.clone(),
            n_txs: ledger.txs.len(),
            fees: ledger.txs.iter().map(|t| t.fee).sum(),
            reward_paid: 0,
        };
        let me = self.id.clone();
        let hash = ledger.ledger_hash.clone();
        let staged = self
            .pending_proposal
            .as_ref()
            .map(|p| p.ledger_hash == hash)
            .unwrap_or(false);
        if staged {
            let _ = self.vote_ok(&hash, &me);
            return Ok(result);
        }
        if !self.open_bodies.contains_key(&hash) {
            self.validate_proposal_seats(ledger)?;
            if let Some(other) = self
                .open_bodies
                .values()
                .find(|b| b.packer == ledger.packer && b.ledger_hash != hash)
            {
                let kept = other.ledger_hash.clone();
                self.stall = Some(ConsensusStall::DualProposal {
                    height: h,
                    kept: kept.clone(),
                    rival: hash.clone(),
                });
                return Err(format!(
                    "packer {} sealed a second body at h={h} in one rotation (kept {})",
                    ledger.packer,
                    &kept[..16.min(kept.len())]
                ));
            }
            if self.open_bodies.len() >= Self::OPEN_BODIES_CAP {
                return Err(format!("open-height body cache full at h={h}"));
            }
            self.verify_ledger_state_root(ledger)?;
            self.open_bodies.insert(hash.clone(), ledger.clone());
            // Do NOT note_height_sealer for late/cached bodies — that permanently
            // barred the packer from sealing when its round arrived (Phase 2
            // soft-QC stall after view-change).
        }
        let order_n = self.lottery_order().len().max(1) as u64;
        let cur_slot = self.height_view_round % order_n;
        let is_round_proposer = ledger.skipped_predecessors.len() as u64 == cur_slot
            && self.round_proposer(self.height_view_round).as_deref() == Some(ledger.packer.as_str());
        if is_round_proposer {
            self.note_next_height_activity();
        }
        match self.pending_proposal.as_ref().filter(|p| p.height == h).cloned() {
            None => {
                if is_round_proposer {
                    self.seen_at_height
                        .insert(h, (ledger.packer.clone(), hash.clone()));
                    self.note_height_sealer(h, &ledger.packer);
                    self.pending_proposal = Some(ledger.clone());
                    self.pending_rounds = 0;
                } else {
                    // Late (earlier round) or early body: cached, staged only
                    // if it already leads the vote.
                    self.maybe_switch_target(h);
                }
            }
            Some(p) => {
                self.stall = Some(ConsensusStall::DualProposal {
                    height: h,
                    kept: p.ledger_hash.clone(),
                    rival: hash.clone(),
                });
                self.maybe_switch_target(h);
            }
        }
        if self
            .pending_proposal
            .as_ref()
            .map(|p| p.ledger_hash == hash)
            .unwrap_or(false)
        {
            let _ = self.vote_ok(&hash, &me);
        }
        // Votes may have landed before the body: recount every round.
        let rounds: Vec<u64> = self
            .round_votes
            .get(&h)
            .map(|m| {
                m.iter()
                    .filter(|(_, v)| v.values().any(|(x, _)| *x == hash))
                    .map(|(r, _)| *r)
                    .collect()
            })
            .unwrap_or_default();
        for r in rounds {
            if self.tip_height >= h {
                break;
            }
            let _ = self.retally_round(h, r, &hash);
        }
        Ok(result)
    }

    /// Round-scoped slash evidence must prove two OKs in **one** (height, round).
    /// Rejects a ledger whose evidence would jail an honest later-round re-voter.
    pub(crate) fn verify_round_slash_evidence(&self, ledger: &Ledger) -> Result<(), String> {
        for ev in &ledger.slashes {
            self.verify_round_evidence_item(ev)?;
        }
        Ok(())
    }

    /// One evidence item. Legacy heights / non-OK kinds pass through unchanged.
    pub fn verify_round_evidence_item(&self, ev: &crate::SlashEvidence) -> Result<(), String> {
        if !ev.kind.is_empty() || !self.vote_rounds_at(ev.height) {
            return Ok(());
        }
        if ev.hash_a == ev.hash_b || ev.offender.is_empty() {
            return Err(format!("bad slash evidence for {} at h={}", ev.offender, ev.height));
        }
        if !self.cfg.require_vote_sigs {
            return Ok(());
        }
        // Key valid at the evidence height (registry from H_act, ring before),
        // the same rule `accept_vote_sig` used when the OKs were counted.
        let pk = self
            .consensus_key_at(&ev.offender, ev.height)
            .ok_or_else(|| format!("slash evidence: unknown key {}", ev.offender))?;
        for (hash, sig) in [(&ev.hash_a, &ev.sig_a), (&ev.hash_b, &ev.sig_b)] {
            let payload =
                Self::vote_ok_payload_v2(self.cfg.network_id, ev.height, ev.round, hash, &ev.offender);
            if sig.is_empty() || !self.verify_consensus_sig(&ev.offender, ev.height, &pk, &payload, sig) {
                return Err(format!(
                    "slash evidence for {} h={} round={} does not verify",
                    ev.offender, ev.height, ev.round
                ));
            }
        }
        Ok(())
    }

    // ------------------------------------------------------------------
    // Liveness watchdog
    // ------------------------------------------------------------------

    /// Work the chain should be sealing: a staged body or applicable txs
    /// (local or a fresh hub inventory ad). Idle mempool ⇒ no work.
    pub fn liveness_has_work(&self) -> bool {
        let open = self.tip_height.saturating_add(1);
        self.pending_proposal
            .as_ref()
            .map(|p| p.height == open)
            .unwrap_or(false)
            || self.network_has_pack_work()
    }

    pub fn liveness_status(&self) -> LivenessStatus {
        let has_work = self.liveness_has_work();
        let since = self.work_seen_since_ms.max(self.tip_advanced_ms);
        let stalled_for_ms = if has_work && self.work_seen_since_ms > 0 {
            self.now_ms.saturating_sub(since)
        } else {
            0
        };
        let thr = self.cfg.liveness_alert_ms;
        LivenessStatus {
            tip_height: self.tip_height,
            has_work,
            stalled: thr > 0 && stalled_for_ms >= thr,
            stalled_for_ms,
            alert_after_ms: thr,
            pending: self.pending_proposal.as_ref().map(|p| p.ledger_hash.clone()),
            mempool_len: self.mempool.len(),
            view_round: self.height_view_round,
            stall: self.stall.clone(),
        }
    }

    /// Call once per seal tick. Returns an alert line (rate-limited to once
    /// per `liveness_alert_ms`) when work exists and the tip is flat.
    pub fn liveness_tick(&mut self) -> Option<String> {
        self.note_work_state();
        let st = self.liveness_status();
        if !st.stalled {
            return None;
        }
        let thr = self.cfg.liveness_alert_ms.max(1);
        if self.liveness_alert_last_ms != 0
            && self.now_ms.saturating_sub(self.liveness_alert_last_ms) < thr
        {
            return None;
        }
        self.liveness_alert_last_ms = self.now_ms;
        Some(format!(
            "LIVENESS ALERT: tip h={} flat for {}s with work pending (pending={:?} mempool={} round={} stall={:?} last={})",
            st.tip_height,
            st.stalled_for_ms / 1000,
            st.pending.as_ref().map(|h| h.chars().take(16).collect::<String>()),
            st.mempool_len,
            st.view_round,
            st.stall,
            self.last_catchup_conflict
        ))
    }

    #[cfg(test)]
    pub(crate) fn pong_all_validators_for_test(&mut self) {
        let ids: Vec<String> = self.validators.keys().cloned().collect();
        for id in ids {
            self.pong(&id);
        }
    }

    // ------------------------------------------------------------------
    // Own-vote journal (restart safety)
    // ------------------------------------------------------------------

    /// Persist open-height round votes (incl. this seat's own) atomically.
    pub fn write_vote_journal(&self) {
        let Some(path) = &self.vote_journal else {
            return;
        };
        let open: BTreeMap<u64, &BTreeMap<u64, BTreeMap<String, (String, String)>>> = self
            .round_votes
            .iter()
            .filter(|(h, _)| **h > self.tip_height)
            .map(|(h, m)| (*h, m))
            .collect();
        let Ok(bytes) = serde_json::to_vec(&open) else {
            return;
        };
        let tmp = path.with_extension("tmp");
        if std::fs::write(&tmp, bytes).is_ok() {
            let _ = std::fs::rename(&tmp, path);
        }
    }

    /// Merge the journal into `round_votes` (heights above tip only).
    pub fn load_vote_journal(&mut self) -> usize {
        let Some(path) = self.vote_journal.clone() else {
            return 0;
        };
        let Ok(bytes) = std::fs::read(&path) else {
            return 0;
        };
        let Ok(m) = serde_json::from_slice::<
            BTreeMap<u64, BTreeMap<u64, BTreeMap<String, (String, String)>>>,
        >(&bytes) else {
            return 0;
        };
        let mut n = 0;
        for (h, rounds) in m {
            if h <= self.tip_height {
                continue;
            }
            let dst = self.round_votes.entry(h).or_default();
            for (r, votes) in rounds {
                let d = dst.entry(r).or_default();
                for (voter, v) in votes {
                    if !d.contains_key(&voter) {
                        d.insert(voter, v);
                        n += 1;
                    }
                }
            }
        }
        n
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{CryptoScheme, KeyRing};
    use crate::{ChainConfig, Network, SlashEvidence};

    const SIX: [&str; 6] = ["v1", "v2", "v3", "v4", "v5", "v6"];

    fn users() -> Vec<(String, u64)> {
        vec![
            ("alice".into(), 1_000_000),
            ("bob".into(), 1_000_000),
            ("carol".into(), 1_000_000),
        ]
    }

    fn cfg(rounds_from: u64) -> ChainConfig {
        ChainConfig {
            pack_budget_ms: 0,
            max_txs_per_ledger: 8,
            progress_timeout_ms: 1_000,
            vote_rounds_from_height: rounds_from,
            ..Default::default()
        }
    }

    /// 6 validators, quorum 4, one committed height (tip=1, cert stored),
    /// three fresh txs in every mempool, schedule frozen for h=2.
    fn six_after_one(rounds_from: u64) -> Network {
        let mut net = Network::bootstrap(&SIX, 1000, &users(), cfg(rounds_from));
        net.pong_all();
        for _ in 0..3 {
            net.payment("alice", "bob", 1, 1).unwrap();
        }
        net.seal_next_height().expect("h=1 commits");
        assert_eq!(net.tip_height(), 1);
        for _ in 0..3 {
            net.payment("alice", "bob", 1, 1).unwrap();
        }
        net.pong_all();
        for n in net.nodes.values_mut() {
            n.best_peer_tip = n.tip_height;
            n.freeze_open_height_schedule();
            n.sync_round_skips(2);
        }
        net
    }

    /// Seal a body for (h=2, `round`) on `packer`'s node without staging it.
    fn pack_in_round(net: &mut Network, packer: &str, round: u64) -> Ledger {
        let n = net.nodes.get_mut(packer).unwrap();
        let saved = n.height_view_round;
        n.height_view_round = round;
        n.sync_round_skips(2);
        let led = n.pack_as(packer).expect("pack");
        n.height_view_round = saved;
        n.sync_round_skips(2);
        led
    }

    fn deliver_vc(net: &mut Network, h: u64, round: u64, voters: &[String]) {
        let tip = net.nodes["v1"].tip_hash.clone();
        for v in voters {
            for n in net.nodes.values_mut() {
                let _ = n.vote_view_change(h, &tip, round, v);
            }
        }
    }

    /// Deliver recert votes from `from` to every other seat; return the
    /// assist votes the receivers want to fan (voter, hash, sig).
    fn deliver_recert(
        net: &mut Network,
        from: &[(String, String, String)],
        assist: bool,
    ) -> Vec<(String, String, String)> {
        let mut out = Vec::new();
        for (voter, hash, sig) in from {
            for (id, n) in net.nodes.iter_mut() {
                if id == voter {
                    continue;
                }
                let _ = n.vote_ok_round_ex(hash, voter, sig, Node::RECERT_ROUND);
                if assist {
                    if let Some((_, h2, s2)) = n.recert_assist(hash, Node::RECERT_ROUND, voter) {
                        out.push((id.clone(), h2, s2));
                    }
                }
            }
        }
        out
    }

    /// Live 379780 shape (2026-10-08): the round-0 body reached a cert on 4
    /// seats; the other 2 committed it via catch-up having seen only 3
    /// round-0 OKs, and re-OK'd it in the recert round. Cert holders never
    /// recertify, so recert stayed below 4 forever and a cert-less round-0
    /// proposer for h+1 could not pack ("no tip cert"); cert-less seats do not
    /// vote view-change, so the holders' VC stayed below 4 too.
    #[test]
    fn recert_split_is_healed_by_cert_holder_assist() {
        let mut net = six_after_one(1);
        let h = 2;
        let order = net.nodes["v1"].lottery_order();
        let a = pack_in_round(&mut net, &order[0], 0);
        let holders: Vec<String> = order[0..4].to_vec();
        let certless: Vec<String> = order[4..6].to_vec();
        for id in &holders {
            let n = net.nodes.get_mut(id).unwrap();
            n.open_bodies.insert(a.ledger_hash.clone(), a.clone());
            n.seen_at_height.insert(h, (a.packer.clone(), a.ledger_hash.clone()));
            n.pending_proposal = Some(a.clone());
            for v in &holders {
                let _ = n.vote_ok_round_ex(&a.ledger_hash, v, "", 0);
            }
            assert_eq!(n.tip_height, h, "{id} commits on round-0 QC");
            assert!(n.certs.contains_key(&h), "{id} holds the cert");
        }
        for id in &certless {
            let n = net.nodes.get_mut(id).unwrap();
            n.ingest_ledger_catchup(&a).expect("catch-up commit");
            assert_eq!(n.tip_height, h);
            for v in &holders[0..3] {
                let _ = n.vote_ok_round_ex(&a.ledger_hash, v, "", 0);
            }
            n.best_peer_tip = h;
            assert!(!n.certs.contains_key(&h), "{id}: only 3 round-0 OKs");
            assert_eq!(n.own_ok_round(h), Node::RECERT_ROUND);
        }
        for n in net.nodes.values_mut() {
            n.best_peer_tip = h;
        }
        // Pre-fix behaviour: cert-less seats recertify among themselves only.
        for _ in 0..5 {
            let mut req = Vec::new();
            for id in &certless {
                if let Some((_, hash, sig)) = net.nodes.get_mut(id).unwrap().recertify_committed_tip() {
                    req.push((id.clone(), hash, sig));
                }
            }
            assert_eq!(req.len(), 2);
            let _ = deliver_recert(&mut net, &req, false);
        }
        for id in &certless {
            let n = net.nodes.get_mut(id).unwrap();
            assert!(!n.certs.contains_key(&h), "{id}: 2 recert votes < 4 (stall)");
            assert!(n.maybe_view_change_vote().is_none(), "cert-less seat must not VC");
            assert!(n.may_pack_locally(id).is_err());
        }
        // v2.9.57: holders answer the recert request with their own recert OK.
        let mut req = Vec::new();
        for id in &certless {
            if let Some((_, hash, sig)) = net.nodes.get_mut(id).unwrap().recertify_committed_tip() {
                req.push((id.clone(), hash, sig));
            }
        }
        let assists = deliver_recert(&mut net, &req, true);
        let assisting: BTreeSet<String> = assists.iter().map(|(v, _, _)| v.clone()).collect();
        assert_eq!(assisting, holders.iter().cloned().collect::<BTreeSet<_>>(), "each holder assists once");
        assert_eq!(
            assists.len(),
            holders.len() * certless.len(),
            "one assist per holder per asking voter"
        );
        let again = deliver_recert(&mut net, &req, true);
        assert!(again.is_empty(), "same voters at this height are not assisted again");
        let _ = deliver_recert(&mut net, &assists, true);
        for id in &certless {
            let n = &net.nodes[id];
            let c = n.certs.get(&h).unwrap_or_else(|| panic!("{id} must recertify"));
            assert!(c.voters.len() >= 4, "{id} recert cert has {} voters", c.voters.len());
            let e = n.may_pack_locally(id).err().unwrap_or_default();
            assert!(!e.contains("no tip cert"), "{id}: {e}");
        }
        for n in net.nodes.values() {
            assert!(n.pending_slashes.is_empty(), "recert assist is not equivocation");
            assert_eq!(n.tip_hash, a.ledger_hash);
        }
    }

    #[test]
    fn recert_assist_only_from_cert_holders_for_recert_tip_votes() {
        let mut net = six_after_one(1);
        let order = net.nodes["v1"].lottery_order();
        let (p, q, r) = (order[0].clone(), order[1].clone(), order[2].clone());
        let tip = net.nodes[&p].tip_hash.clone();
        let hgt = net.nodes[&p].tip_height;
        // Not a recert vote → no assist.
        assert!(net.nodes.get_mut(&p).unwrap().recert_assist(&tip, 0, &q).is_none());
        // Recert vote for our tip that we never recorded → no assist.
        assert!(net.nodes.get_mut(&p).unwrap().recert_assist(&tip, Node::RECERT_ROUND, &q).is_none());
        let n = net.nodes.get_mut(&p).unwrap();
        let _ = n.vote_ok_round_ex(&tip, &q, "", Node::RECERT_ROUND);
        assert!(n.certs.contains_key(&hgt));
        assert!(n.recert_assist(&tip, Node::RECERT_ROUND, &q).is_some());
        // One assist per peer per height: same voter stays None even after the
        // old 3s window.
        assert!(n.recert_assist(&tip, Node::RECERT_ROUND, &q).is_none());
        n.now_ms += Node::RECERT_ASSIST_EVERY_MS;
        assert!(n.recert_assist(&tip, Node::RECERT_ROUND, &q).is_none());
        // A different voter at this height still gets one assist.
        let _ = n.vote_ok_round_ex(&tip, &r, "", Node::RECERT_ROUND);
        assert!(n.recert_assist(&tip, Node::RECERT_ROUND, &r).is_some());
        assert!(n.recert_assist(&tip, Node::RECERT_ROUND, &r).is_none());
        n.now_ms += Node::RECERT_ASSIST_EVERY_MS;
        assert!(n.recert_assist(&tip, Node::RECERT_ROUND, &r).is_none());
        // Cert-less seat never assists (it recertifies itself).
        n.certs.remove(&hgt);
        n.now_ms += Node::RECERT_ASSIST_EVERY_MS;
        assert!(n.recert_assist(&tip, Node::RECERT_ROUND, &q).is_none());
        assert!(n.pending_slashes.is_empty());
    }

    /// Live h=369421 shape: two bodies, votes split 3-3 at 4-of-6, everyone
    /// re-votes in the next round. Before v2.10.0 this halted the chain.
    #[test]
    fn split_3_3_at_quorum_4_recovers_next_round() {
        let mut net = six_after_one(1);
        let h = 2;
        let order = net.nodes["v1"].lottery_order();
        assert_eq!(order.len(), 6);
        assert_eq!(net.nodes["v1"].commit_votes_needed(), 4);
        // Round-0 proposer body A and round-1 proposer body B (the timeout race).
        let a = pack_in_round(&mut net, &order[0], 0);
        let b = pack_in_round(&mut net, &order[1], 1);
        assert_ne!(a.ledger_hash, b.ledger_hash);
        let grp_a: Vec<String> = vec![order[0].clone(), order[2].clone(), order[4].clone()];
        let grp_b: Vec<String> = vec![order[1].clone(), order[3].clone(), order[5].clone()];
        // Every node holds both bodies; each side staged "its" body and the
        // round-0 votes split 3-3 (both sides OK'd in the same round).
        for (id, n) in net.nodes.iter_mut() {
            n.open_bodies.insert(a.ledger_hash.clone(), a.clone());
            n.open_bodies.insert(b.ledger_hash.clone(), b.clone());
            let mine = if grp_a.contains(id) { a.clone() } else { b.clone() };
            n.seen_at_height.insert(h, (mine.packer.clone(), mine.ledger_hash.clone()));
            n.pending_proposal = Some(mine);
        }
        for n in net.nodes.values_mut() {
            for v in &grp_a {
                n.vote_ok_round_ex(&a.ledger_hash, v, "", 0);
            }
            for v in &grp_b {
                n.vote_ok_round_ex(&b.ledger_hash, v, "", 0);
            }
        }
        for n in net.nodes.values() {
            assert_eq!(n.tip_height, 1, "3-3 cannot commit");
            assert!(n.round_split_dead(h, 0), "split must be provable");
            assert!(n.pending_slashes.is_empty(), "a split is not equivocation");
        }
        // Proven split ⇒ immediate round timeout on every seat (no 6.5 days).
        let mut vc_voters = Vec::new();
        for (id, n) in net.nodes.iter_mut() {
            let v = n.maybe_view_change_vote();
            assert_eq!(v.as_ref().map(|x| x.2), Some(1), "{id} must vote round 1");
            assert!(matches!(n.stall, Some(ConsensusStall::SplitVote { round: 0, .. })));
            vc_voters.push(id.clone());
        }
        deliver_vc(&mut net, h, 1, &vc_voters);
        for n in net.nodes.values() {
            assert_eq!(n.height_view_round, 1);
            assert_eq!(n.round_proposer(1).as_deref(), Some(order[1].as_str()));
            assert_eq!(
                n.pending_proposal.as_ref().map(|p| p.ledger_hash.clone()),
                Some(b.ledger_hash.clone()),
                "every seat converges on one target body"
            );
        }
        // Gossip the round-1 re-votes (A voters now vote B: dead lock ⇒ free).
        for v in SIX {
            for n in net.nodes.values_mut() {
                n.vote_ok_round_ex(&b.ledger_hash, v, "", 1);
            }
        }
        for (id, n) in &net.nodes {
            assert_eq!(n.tip_height, 2, "{id} must commit h=2");
            assert_eq!(n.tip_hash, b.ledger_hash);
            assert!(n.pending_slashes.is_empty(), "round re-vote is not equivocation");
            assert!(n.validators.values().all(|v| !v.jailed));
            let cert = n.certs.get(&2).expect("cert");
            assert_eq!(cert.round, 1, "cert names the round it was signed in");
        }
        // A voters really did vote A (r0) then B (r1).
        let rv = &net.nodes["v1"].round_votes[&h];
        assert_eq!(rv[&0][&grp_a[1]].0, a.ledger_hash);
        assert_eq!(rv[&1][&grp_a[1]].0, b.ledger_hash);
        // And the chain keeps going.
        for _ in 0..2 {
            net.payment("alice", "bob", 1, 1).unwrap();
        }
        net.seal_next_height().expect("h=3 commits after recovery");
    }

    /// Two OKs for different hashes in ONE (height, round) are still caught,
    /// kept, and jail the offender on every node via the next ledger.
    /// A different-round re-vote by another seat is not.
    #[test]
    fn same_round_double_ok_is_slashed_cross_round_revote_is_not() {
        // 7 bonded so drop_slashes keeps the evidence (leaves ≥6 live).
        const SEVEN: [&str; 7] = ["v1", "v2", "v3", "v4", "v5", "v6", "v7"];
        let mut net = Network::bootstrap(&SEVEN, 1000, &users(), cfg(1));
        for n in net.nodes.values_mut() {
            n.cfg.committee_size = 6;
        }
        net.pong_all();
        for _ in 0..3 {
            net.payment("alice", "bob", 1, 1).unwrap();
        }
        net.seal_next_height().expect("h=1");
        for _ in 0..3 {
            net.payment("alice", "bob", 1, 1).unwrap();
        }
        let order = net.nodes["v1"].lottery_order();
        let cheat = order[2].clone();
        let honest = order[3].clone();
        for (id, n) in net.nodes.iter_mut() {
            if *id == cheat || *id == honest {
                continue;
            }
            n.vote_ok_round_ex("hash-a", &cheat, "", 5);
            n.vote_ok_round_ex("hash-b", &cheat, "", 5);
            n.vote_ok_round_ex("hash-a", &honest, "", 6);
            n.vote_ok_round_ex("hash-b", &honest, "", 7);
            assert!(n.pending_slashes.iter().any(|e| e.offender == cheat && e.round == 5));
            assert!(!n.pending_slashes.iter().any(|e| e.offender == honest));
            // Evidence survives a round advance / reopen (not attempt-local any more).
            n.clear_attempt_votes(2);
            assert!(n.pending_slashes.iter().any(|e| e.offender == cheat));
        }
        net.seal_next_height().expect("h=2 commits with evidence");
        for n in net.nodes.values() {
            assert!(n.validators[&cheat].jailed, "same-round double OK jails");
            assert!(!n.validators[&honest].jailed, "cross-round re-vote does not");
        }
    }

    /// Receivers verify evidence signatures: an honest cross-round re-voter
    /// cannot be framed by relabelling the rounds.
    #[test]
    fn evidence_must_be_signed_in_one_round() {
        let mut n = Node::new(
            "v1",
            ChainConfig {
                require_vote_sigs: true,
                vote_rounds_from_height: 1,
                pack_budget_ms: 0,
                ..Default::default()
            },
            KeyRing::new(CryptoScheme::HmacDev),
            &users(),
        );
        for v in SIX {
            n.register_validator(v, 1000);
        }
        n.keys.generate_many(SIX.into_iter());
        let sign = |n: &Node, r: u64, hash: &str| {
            let p = Node::vote_ok_payload_v2(n.cfg.network_id, 2, r, hash, "v2");
            n.keys.sign("v2", &p).unwrap()
        };
        let framed = SlashEvidence {
            offender: "v2".into(),
            height: 2,
            hash_a: "aa".into(),
            sig_a: sign(&n, 0, "aa"),
            hash_b: "bb".into(),
            sig_b: sign(&n, 1, "bb"),
            kind: String::new(),
            round: 0,
        };
        assert!(n.verify_round_evidence_item(&framed).is_err(), "cross-round is not evidence");
        let real = SlashEvidence {
            sig_a: sign(&n, 3, "aa"),
            sig_b: sign(&n, 3, "bb"),
            round: 3,
            ..framed.clone()
        };
        assert!(n.verify_round_evidence_item(&real).is_ok());
        // Signed wire path: round-scoped OK uses pl-ok:v2 and a v1 sig is refused.
        n.pong("v2");
        let v1_sig = n.keys.sign("v2", &Node::vote_ok_payload(n.cfg.network_id, 1, "cc", "v2")).unwrap();
        assert!(!n.vote_ok_round_ex("cc", "v2", &v1_sig, 0).2, "v1 sig rejected on v2 height");
        let v2_sig = n
            .keys
            .sign("v2", &Node::vote_ok_payload_v2(n.cfg.network_id, 1, 0, "cc", "v2"))
            .unwrap();
        assert!(n.vote_ok_round_ex("cc", "v2", &v2_sig, 0).2);
    }

    /// Root cause: one proposer per (height, round). A late body from the
    /// previous round's seat is cached but neither staged nor voted.
    #[test]
    fn late_body_from_earlier_round_is_not_staged() {
        let mut net = six_after_one(1);
        let h = 2;
        let order = net.nodes["v1"].lottery_order();
        let a = pack_in_round(&mut net, &order[0], 0);
        let b = pack_in_round(&mut net, &order[1], 1);
        let x = order[3].clone();
        let n = net.nodes.get_mut(&x).unwrap();
        n.apply_round_advance(h, 1);
        assert_eq!(n.lottery_packer().as_deref(), Some(order[1].as_str()));
        assert_eq!(n.round_proposer(1).as_deref(), Some(order[1].as_str()));
        n.accept_ledger(&a).expect("late body is valid, just not this round's");
        assert!(n.pending_proposal.is_none(), "late body must not be staged");
        assert!(n.open_bodies.contains_key(&a.ledger_hash));
        assert!(n.own_ok_vote(h, &a.ledger_hash).is_none(), "no vote for a late body");
        n.accept_ledger(&b).expect("round-1 proposer body");
        assert_eq!(n.pending_proposal.as_ref().map(|p| p.ledger_hash.clone()), Some(b.ledger_hash.clone()));
        assert_eq!(n.round_votes[&h][&1][&x].0, b.ledger_hash, "own vote is round-scoped");
        // Local skip QC / progress-skip can no longer move the cursor.
        let tip = n.tip_hash.clone();
        assert!(!n.apply_shared_skip(h, &order[1], &tip));
        assert!(n.maybe_progress_timeout_skip().is_none());
        // Only order[1] may seal at round 1.
        assert!(n.may_pack_locally(&order[0]).is_err());
    }

    /// Late-cached body must not permanently ban that packer via height_sealers.
    /// Round mode must not refuse pack with "already sealed … after view-change"
    /// (Phase 2 soft-QC stall after VC, 2026-10-05).
    #[test]
    fn round_advance_frees_late_body_packer_to_reseal() {
        let mut net = six_after_one(1);
        let h = 2;
        let order = net.nodes["v1"].lottery_order();
        let late = pack_in_round(&mut net, &order[0], 0);
        let n = net.nodes.get_mut(&order[2]).unwrap();
        n.apply_round_advance(h, 1);
        n.accept_ledger(&late).expect("late body cached");
        assert!(n.pending_proposal.is_none());
        assert!(
            !n.height_sealers
                .get(&h)
                .map(|s| s.contains(&order[0]))
                .unwrap_or(false),
            "late body must not mark height_sealers"
        );
        // Stale sealer mark must not block round-mode pack.
        let packer = order[0].clone();
        net.payment("alice", "bob", 1, 1).unwrap();
        let n = net.nodes.get_mut(&packer).unwrap();
        n.height_sealers.entry(h).or_default().insert(packer.clone());
        n.seen_at_height.remove(&h);
        n.height_view_round = 0;
        n.sync_round_skips(h);
        n.pong(&packer);
        assert!(n.vote_rounds_at(h));
        match n.pack_as(&packer) {
            Ok(_) => {}
            Err(e) => assert!(
                !e.contains("already sealed"),
                "round mode must not refuse on height_sealers: {e}"
            ),
        }
    }

    /// Soft QC in a later round commits the kept pending body (re-vote path).
    #[test]
    fn soft_qc_commits_pending_after_round_advance() {
        let mut net = six_after_one(1);
        let h = 2;
        let order = net.nodes["v1"].lottery_order();
        let body = pack_in_round(&mut net, &order[0], 0);
        // Every seat stages and votes in round 0.
        for id in &order {
            let n = net.nodes.get_mut(id).unwrap();
            n.accept_ledger(&body).expect("stage");
        }
        // Not enough same-round votes yet if each only self-voted — fan all OKs.
        for voter in &order {
            for id in &order {
                let n = net.nodes.get_mut(id).unwrap();
                let _ = n.vote_ok(&body.ledger_hash, voter);
            }
        }
        // If tip already advanced, we are done.
        if net.nodes["v1"].tip_height >= h {
            return;
        }
        // Advance to round 1 and re-vote the kept pending → soft QC must commit.
        for id in &order {
            let n = net.nodes.get_mut(id).unwrap();
            if n.tip_height < h {
                n.apply_round_advance(h, 1);
            }
        }
        for voter in &order {
            for id in &order {
                let n = net.nodes.get_mut(id).unwrap();
                if n.tip_height < h {
                    let _ = n.vote_ok(&body.ledger_hash, voter);
                }
            }
        }
        let tips: Vec<_> = order.iter().map(|id| net.nodes[id].tip_height).collect();
        assert!(
            tips.iter().any(|t| *t >= h),
            "soft QC after round advance must commit; tips={tips:?}"
        );
    }

    /// Load-driven chain: no txs ⇒ no round timeouts, no alerts. Work on a
    /// flat tip ⇒ round timeout, then a liveness alert after N minutes.
    #[test]
    fn idle_chain_never_times_out_or_alerts() {
        let mut net = Network::bootstrap(&SIX, 1000, &users(), cfg(1));
        net.pong_all();
        net.payment("alice", "bob", 1, 1).unwrap();
        net.seal_next_height().unwrap();
        let n = net.nodes.get_mut("v2").unwrap();
        n.best_peer_tip = n.tip_height;
        assert!(n.mempool.is_empty());
        n.now_ms += 3_600_000;
        n.pong_all_validators_for_test();
        assert!(n.maybe_view_change_vote().is_none(), "idle: no round clock");
        assert!(n.liveness_tick().is_none(), "idle: height flat is fine");
        assert!(!n.liveness_status().stalled);
        // A tx lands after an hour idle: the round clock starts now, not at the
        // last block (otherwise every first tx after idle forced a view-change).
        let tx = net.payment("alice", "bob", 1, 1).unwrap();
        let n = net.nodes.get_mut("v2").unwrap();
        let _ = tx;
        assert!(n.network_has_pack_work());
        assert!(n.liveness_tick().is_none());
        assert!(n.maybe_view_change_vote().is_none(), "proposer gets its window");
        n.now_ms += n.round_silence_timeout_ms(0) + 1;
        n.pong_all_validators_for_test();
        assert_eq!(n.maybe_view_change_vote().map(|v| v.2), Some(1), "silent proposer ⇒ round 1");
        n.now_ms += n.cfg.liveness_alert_ms;
        n.pong_all_validators_for_test();
        let alert = n.liveness_tick().expect("work + flat tip ⇒ alert");
        assert!(alert.contains("LIVENESS ALERT"), "{alert}");
        assert!(n.liveness_tick().is_none(), "rate-limited");
    }

    /// Restart (snapshot or journal) keeps the seat's own round vote, so it
    /// never signs a second hash in one (height, round).
    #[test]
    fn restart_keeps_own_round_vote() {
        let mut net = six_after_one(1);
        let n = net.nodes.get_mut("v3").unwrap();
        n.vote_ok_round_ex("hash-a", "v3", "", 0);
        assert!(n.may_cast_own_ok(2, 0, "hash-b").is_err());
        let dir = std::env::temp_dir().join(format!("fdpl-rounds-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let snap = dir.join("v3.json");
        n.save_snapshot(&snap).unwrap();
        let mut loaded = Node::load_snapshot(&snap, n.keys.clone()).unwrap();
        loaded.id = "v3".into();
        loaded.cfg.vote_rounds_from_height = 1;
        assert!(loaded.may_cast_own_ok(2, 0, "hash-b").is_err(), "snapshot keeps the lock");
        assert!(loaded.may_cast_own_ok(2, 0, "hash-a").is_ok());
        // Journal path (written synchronously on every own vote).
        let j = dir.join("v3.json.own-votes.json");
        n.vote_journal = Some(j.clone());
        n.vote_ok_round_ex("hash-a", "v3", "", 1);
        let mut fresh = Node::load_snapshot(&snap, n.keys.clone()).unwrap();
        fresh.id = "v3".into();
        fresh.cfg.vote_rounds_from_height = 1;
        fresh.round_votes.clear();
        fresh.vote_journal = Some(j);
        assert!(fresh.load_vote_journal() >= 2);
        assert!(fresh.may_cast_own_ok(2, 1, "hash-b").is_err(), "journal keeps the lock");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A restarted / lagging seat jumps to the network's round on a QC, and
    /// re-gossiped stale-round votes cannot block the newer round.
    #[test]
    fn round_jump_and_stale_votes_cannot_block() {
        let mut net = six_after_one(1);
        let h = 2;
        let order = net.nodes["v1"].lottery_order();
        let b = pack_in_round(&mut net, &order[2], 2);
        let x = order[4].clone();
        let tip = net.nodes[&x].tip_hash.clone();
        let n = net.nodes.get_mut(&x).unwrap();
        // Far-future round is ignored (bounded state).
        let (qc, fresh) = n.vote_view_change(h, &tip, 2 + Node::MAX_ROUND_JUMP + 5, &order[0]);
        assert!(!qc && !fresh);
        for v in order.iter().take(4) {
            let _ = n.vote_view_change(h, &tip, 2, v);
        }
        assert_eq!(n.height_view_round, 2, "QC for a higher round ⇒ jump");
        assert_eq!(n.lottery_packer().as_deref(), Some(order[2].as_str()));
        n.accept_ledger(&b).expect("round-2 body");
        // Old round-0 votes re-gossiped after a restart (the 2026-09 rolling
        // restart re-stall): recorded in their own round only.
        for v in [&order[0], &order[1], &order[3]] {
            n.vote_ok_round_ex("stale-hash", v, "", 0);
        }
        assert_eq!(n.tip_height, 1);
        assert!(n.pending_slashes.is_empty());
        for v in [&order[0], &order[1], &order[3]] {
            n.vote_ok_round_ex(&b.ledger_hash, v, "", 2);
        }
        assert_eq!(n.tip_height, 2, "4 round-2 votes commit despite stale round-0 votes");
        assert!(n.pending_slashes.is_empty());
    }

    /// Lock rule: a seat whose round-r body can still reach quorum does not
    /// vote a different body later (crash-fault safety across rounds).
    #[test]
    fn live_lock_blocks_switch_dead_lock_frees() {
        let mut net = six_after_one(1);
        let order = net.nodes["v1"].lottery_order();
        let me = order[0].clone();
        let n = net.nodes.get_mut(&me).unwrap();
        n.vote_ok_round_ex("A", &me, "", 0);
        n.vote_ok_round_ex("A", &order[1], "", 0);
        n.vote_ok_round_ex("B", &order[2], "", 0);
        // A: 2 votes, 1 against, 3 unseen ⇒ A may still reach 4 ⇒ locked.
        assert!(n.may_cast_own_ok(2, 1, "B").is_err());
        assert!(n.may_cast_own_ok(2, 1, "A").is_ok(), "re-voting the lock is fine");
        n.vote_ok_round_ex("B", &order[3], "", 0);
        n.vote_ok_round_ex("B", &order[4], "", 0);
        // 3 against ⇒ A can reach at most 3 < 4 ⇒ dead ⇒ free.
        assert!(n.may_cast_own_ok(2, 1, "B").is_ok());
        assert!(n.may_cast_own_ok(2, 0, "B").is_err(), "never two hashes in one round");
    }

    /// Pre-activation (legacy pl-ok:v1) still un-sticks: the typed stall fires
    /// view-change for a checker split (the old substring check never did).
    #[test]
    fn legacy_checker_split_now_triggers_view_change() {
        let mut net = six_after_one(0);
        let h = 2;
        let order = net.nodes["v1"].lottery_order();
        let a = net.nodes.get_mut(&order[0]).unwrap().pack_as(&order[0]).unwrap();
        let low = a.ledger_hash.clone();
        for n in net.nodes.values_mut() {
            n.accept_ledger(&a).unwrap();
        }
        // v1-style split: three seats also OK'd another hash at this height.
        for n in net.nodes.values_mut() {
            for v in [&order[3], &order[4], &order[5]] {
                n.vote_ok_ex("rival-hash", v, "");
            }
            for v in [&order[3], &order[4], &order[5]] {
                let _ = n.vote_ok_ex(&low, v, "");
            }
            assert_eq!(n.tip_height, 1, "legacy split pins the pending");
            assert!(n.open_height_dual(h));
        }
        let mut voters = Vec::new();
        for (id, n) in net.nodes.iter_mut() {
            n.now_ms += n.proposal_timeout_ms() + 100;
            if n.maybe_view_change_vote().is_some() {
                voters.push(id.clone());
            }
        }
        assert!(voters.len() >= 4, "typed split must drive VC (got {voters:?})");
        deliver_vc(&mut net, h, 1, &voters);
        for n in net.nodes.values() {
            assert!(n.pending_proposal.is_none(), "dual attempt discarded");
            assert!(n.ok_by_height_voter.get(&h).is_none(), "attempt OKs cleared");
        }
        net.seal_next_height().expect("legacy chain recovers");
    }

    /// Production bug (v10 @ 369439 shape): after a QC-first pending switch the
    /// seal loop used to re-fan an OK for the new hash at the *same* height.
    /// Peers recorded that as checker equivocation, and the node even queued
    /// evidence against itself. Own node must refuse the second OK and never
    /// put itself in `pending_slashes`.
    #[test]
    fn own_node_never_queues_self_slash_on_pending_switch() {
        let mut net = six_after_one(0); // legacy pl-ok:v1 path (Phase 1 / pre-H)
        let h = 2u64;
        let order = net.nodes["v1"].lottery_order();
        let me = order[1].clone();
        let peer = order[2].clone();
        // Own node: first OK for A, then try to OK B after a pending switch.
        {
            let n = net.nodes.get_mut(&me).unwrap();
            let (s, _, _) = n.vote_ok_ex("hash-a", &me, "sig-a");
            assert!(!s);
            assert!(n.pending_slashes.is_empty());
            let (s, _, recorded) = n.vote_ok_ex("hash-b", &me, "sig-b");
            assert!(!s && !recorded, "second own OK must be refused");
            assert!(
                n.pending_slashes.iter().all(|e| e.offender != me),
                "must never queue evidence against self: {:?}",
                n.pending_slashes
            );
            // Own lock stays on A.
            assert_eq!(
                n.ok_by_height_voter.get(&h).and_then(|m| m.get(&me)).map(|s| s.as_str()),
                Some("hash-a")
            );
        }
        // A peer observing the same two hashes *does* queue evidence (real
        // equivocation from their point of view if both were gossiped).
        {
            let n = net.nodes.get_mut(&peer).unwrap();
            n.vote_ok_ex("hash-a", &me, "sig-a");
            n.vote_ok_ex("hash-b", &me, "sig-b");
            assert!(
                n.pending_slashes.iter().any(|e| e.offender == me && e.height == h),
                "peer must still slash a real double OK"
            );
        }
    }

    /// Round-scoped twin of the self-incrimination guard: even when rounds are
    /// on, casting a second hash in the *same* (height, round) as self is
    /// refused with no self-slash; a peer still records evidence.
    #[test]
    fn round_mode_own_node_never_self_slashes_same_round() {
        let mut net = six_after_one(1);
        let h = 2u64;
        let order = net.nodes["v1"].lottery_order();
        let me = order[0].clone();
        let peer = order[1].clone();
        {
            let n = net.nodes.get_mut(&me).unwrap();
            n.vote_ok_round_ex("hash-a", &me, "sig-a", 0);
            assert!(n.may_cast_own_ok(h, 0, "hash-b").is_err());
            let before = n.pending_slashes.len();
            // Direct ingest of a conflicting own vote must not enqueue self-slash.
            n.vote_ok_round_ex("hash-b", &me, "sig-b", 0);
            assert_eq!(n.pending_slashes.len(), before);
            assert!(n.pending_slashes.iter().all(|e| e.offender != me));
        }
        {
            let n = net.nodes.get_mut(&peer).unwrap();
            n.vote_ok_round_ex("hash-a", &me, "sig-a", 0);
            n.vote_ok_round_ex("hash-b", &me, "sig-b", 0);
            assert!(
                n.pending_slashes
                    .iter()
                    .any(|e| e.offender == me && e.round == 0 && e.height == h),
                "peer still catches same-round double OK"
            );
        }
    }

    /// Lottery / committee overlap: with 7 bonded and one of the live 6 jailed
    /// mid-height (via slash evidence on the next ledger), the next committee
    /// must still be size 6 and draw from the remaining live bonded set (the
    /// v12-jail / v13-join shape on testnet 2300).
    #[test]
    fn jail_rotates_committee_to_next_bonded_seat() {
        const SEVEN: [&str; 7] = ["v1", "v2", "v3", "v4", "v5", "v6", "v7"];
        let mut net = Network::bootstrap(&SEVEN, 1000, &users(), cfg(1));
        // Cap the QC committee at 6 so a spare bonded seat sits outside.
        for n in net.nodes.values_mut() {
            n.cfg.committee_size = 6;
        }
        net.pong_all();
        for _ in 0..3 {
            net.payment("alice", "bob", 1, 1).unwrap();
        }
        net.seal_next_height().expect("h=1");
        let order_h1 = net.nodes["v1"].lottery_order();
        assert_eq!(order_h1.len(), 6, "committee capped at 6");
        let spare = SEVEN
            .iter()
            .map(|s| s.to_string())
            .find(|id| !order_h1.contains(id))
            .expect("one bonded seat outside the committee");
        // Jail one live committee seat via pending slash on every node.
        let victim = order_h1[0].clone();
        assert_ne!(victim, spare);
        for n in net.nodes.values_mut() {
            n.pending_slashes.push(SlashEvidence {
                offender: victim.clone(),
                height: 1,
                hash_a: "aa".into(),
                sig_a: String::new(),
                hash_b: "bb".into(),
                sig_b: String::new(),
                kind: String::new(),
                round: 0,
            });
        }
        for _ in 0..3 {
            net.payment("alice", "bob", 1, 1).unwrap();
        }
        net.seal_next_height().expect("h=2 jails victim");
        for n in net.nodes.values() {
            assert!(n.validators[&victim].jailed, "{victim} jailed on {}", n.id);
            let order = n.lottery_order();
            assert_eq!(order.len(), 6, "committee size must stay 6 after jail");
            assert!(!order.contains(&victim), "jailed seat leaves committee");
            let bonded_live = n
                .validators
                .values()
                .filter(|v| !v.jailed && v.bond > 0)
                .count();
            assert!(
                bonded_live >= 6,
                "need ≥6 live bonded after rotation, got {bonded_live}"
            );
            // Spare must be drawable now that victim is out.
            assert!(
                order.contains(&spare) || bonded_live > 6,
                "rotated committee should include spare {spare}, got {order:?}"
            );
        }
        // Chain keeps sealing with the rotated committee.
        for _ in 0..2 {
            net.payment("alice", "bob", 1, 1).unwrap();
        }
        net.seal_next_height().expect("h=3 after committee rotation");
        assert_eq!(net.tip_height(), 3);
    }

    #[test]
    fn vote_rounds_baked_for_2300_and_precedence() {
        use crate::{resolve_vote_rounds_from_height as r, TESTNET_2300_VOTE_ROUNDS_FROM_HEIGHT as H};
        assert_eq!(H, 369_998);
        // Missing env/flag/bridge.json on 2300 → baked constant (the risk we bake against).
        let x = r(2300, None, 0, 0);
        assert_eq!((x.height, x.source, x.mismatch), (H, "network-constant", false));
        // Live drop-in style (env = H) agrees.
        let x = r(2300, Some(H), 0, 0);
        assert_eq!((x.height, x.source, x.mismatch), (H, "env", false));
        // bridge.json value used when env/CLI unset.
        let x = r(2300, None, 0, H);
        assert_eq!((x.height, x.source, x.mismatch), (H, "bridge.json", false));
        // Explicit env 0 on 2300 is a mismatch (node refuses unless overridden).
        let x = r(2300, Some(0), 0, 0);
        assert_eq!((x.height, x.source, x.mismatch), (0, "env", true));
        // Wrong CLI height is a mismatch.
        assert!(r(2300, None, 370_000, 0).mismatch);
        // Other networks: no baked default, nothing is a mismatch.
        let x = r(2299, None, 0, 0);
        assert_eq!((x.height, x.source, x.mismatch), (0, "off", false));
        let x = r(2299, None, 1, 0);
        assert_eq!((x.height, x.source, x.mismatch), (1, "cli", false));
        assert_eq!(crate::network_vote_rounds_from_height(2200), 0);
    }

    #[test]
    fn bridge_cfg_fingerprint_digest_is_format_independent() {
        let base = std::env::temp_dir().join(format!("fdpl-bcfg-{}", std::process::id()));
        let a = base.join("a");
        let b = base.join("b");
        for d in [&a, &b] {
            std::fs::create_dir_all(d.join("lc")).unwrap();
        }
        std::fs::write(
            a.join("lc/bridge.json"),
            r#"{"start_height":116957,"network_id":2300,"key_root":"0xAB","qc_header_version":4,"qc_start_height":353091}"#,
        )
        .unwrap();
        std::fs::write(
            b.join("lc/bridge.json"),
            "{\n  \"qc_start_height\": 353091,\n  \"qc_header_version\": 4,\n  \"network_id\": 2300,\n  \"key_root\": \"ab\",\n  \"start_height\": 116957\n}\n",
        )
        .unwrap();
        let fa = crate::lc::bridge_cfg_fingerprint(&a);
        let fb = crate::lc::bridge_cfg_fingerprint(&b);
        assert_eq!(fa["present"], true);
        assert_eq!(fa["qc_header_version"], 4);
        assert_eq!(fa["qc_start_height"], 353091);
        assert_ne!(fa["sha256"], fb["sha256"], "raw bytes differ");
        assert_eq!(fa["qc_cfg_digest"], fb["qc_cfg_digest"], "same effective cfg");
        // Stale v13-style file (pre-v4) → different digest.
        let c = base.join("c");
        std::fs::create_dir_all(c.join("lc")).unwrap();
        std::fs::write(c.join("lc/bridge.json"), r#"{"start_height":116957,"network_id":2300,"key_root":"ab"}"#).unwrap();
        let fc = crate::lc::bridge_cfg_fingerprint(&c);
        assert_eq!(fc["qc_header_version"], 3);
        assert_ne!(fa["qc_cfg_digest"], fc["qc_cfg_digest"]);
        // Missing file.
        let fd = crate::lc::bridge_cfg_fingerprint(&base.join("missing"));
        assert_eq!(fd["present"], false);
        let _ = std::fs::remove_dir_all(&base);
    }

    fn lone_node(id: &str) -> crate::Node {
        let mut n = crate::Node::new(id, cfg(0), KeyRing::new(CryptoScheme::HmacDev), &users());
        n.register_validator("v1", 1000);
        n.register_validator(id, 1000);
        n
    }

    /// Harness restart-while-pending flake: a seat restarted at tip 0 whose
    /// archive's snapshot file is still at tip 0 gets a stale offer, and used
    /// to loop on NeedSnapshot forever (take_catchup_pull is gated on
    /// !wants_snapshot). A stale answer must hand over to residual NeedLedgers.
    #[test]
    fn tip0_stale_snapshot_offer_falls_back_to_residual_pull() {
        let mut n = lone_node("v3");
        n.cfg.archive = false;
        n.now_ms = 1_000_000;
        if let Some(v) = n.validators.get_mut("v1") {
            v.advertised_archive = true;
            v.last_pong_ms = n.now_ms;
        }
        n.tip_height = 0;
        n.best_peer_tip = 4;
        assert!(n.wants_snapshot(), "tip 0 with an archive → join-snap first");
        assert_eq!(n.take_catchup_pull(), None, "residual gated while snapping");

        n.note_stale_snapshot_offer();
        assert!(!n.wants_snapshot(), "stale offer → stop snapping");
        assert_eq!(n.take_catchup_pull(), Some(1), "residual NeedLedgers from h=1");

        // Cooldown expires → snapshot preferred again.
        n.now_ms += crate::Node::STALE_SNAP_OFFER_COOLDOWN_MS + 1;
        if let Some(v) = n.validators.get_mut("v1") {
            v.last_pong_ms = n.now_ms;
        }
        assert!(n.wants_snapshot());

        // Far behind: a stale offer never blocks join-snap.
        n.note_stale_snapshot_offer();
        n.best_peer_tip = crate::Node::SNAPSHOT_JOIN_LAG + 10;
        assert!(n.wants_snapshot(), "far behind still join-snaps");
    }

    /// Status drift must be measured against the startup fingerprint, not just
    /// the two QC fields (Copilot review on #6).
    #[test]
    fn bridge_cfg_drift_tracks_startup_fingerprint() {
        let dir = std::env::temp_dir().join(format!("fdpl-drift-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("lc")).unwrap();
        let write = |body: &str| std::fs::write(dir.join("lc/bridge.json"), body).unwrap();
        write(r#"{"start_height":116957,"network_id":2300,"key_root":"ab","qc_header_version":4,"qc_start_height":353091}"#);
        let mut n = lone_node("v3");
        n.cfg.network_id = 2300;
        n.cfg.vote_rounds_from_height = 369_998;
        n.keys_dir = Some(dir.clone());
        n.apply_qc_bridge_cfg();
        let st = n.bridge_cfg_status().unwrap();
        assert_eq!(st["drift"], false, "{st}");
        assert_eq!(st["startup_sha256"], st["sha256"]);

        // Only vote_rounds_from_height edited after start (QC fields unchanged).
        write(r#"{"start_height":116957,"network_id":2300,"key_root":"ab","qc_header_version":4,"qc_start_height":353091,"vote_rounds_from_height":370000}"#);
        let st = n.bridge_cfg_status().unwrap();
        assert_eq!(st["drift"], true, "{st}");
        let r: Vec<String> = serde_json::from_value(st["drift_reasons"].clone()).unwrap();
        assert!(r.contains(&"file_changed_since_start".to_string()), "{r:?}");
        assert!(r.contains(&"qc_cfg_digest_changed_since_start".to_string()), "{r:?}");
        assert!(r.contains(&"vote_rounds_differs_from_running".to_string()), "{r:?}");

        // Whitespace-only change: raw sha drifts (restart to re-apply), digest not.
        write("{ \"start_height\": 116957, \"network_id\": 2300, \"key_root\": \"ab\", \"qc_header_version\": 4, \"qc_start_height\": 353091 }");
        let st = n.bridge_cfg_status().unwrap();
        let r: Vec<String> = serde_json::from_value(st["drift_reasons"].clone()).unwrap();
        assert_eq!(r, vec!["file_changed_since_start".to_string()]);

        // Wrong network id in the file, applied at start: flagged even with no change since.
        write(r#"{"start_height":116957,"network_id":2200,"key_root":"ab","qc_header_version":4,"qc_start_height":353091}"#);
        n.apply_qc_bridge_cfg();
        let st = n.bridge_cfg_status().unwrap();
        let r: Vec<String> = serde_json::from_value(st["drift_reasons"].clone()).unwrap();
        assert_eq!(r, vec!["network_id_differs_from_node".to_string()]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---------------------------------------------------------------------
    // v2.9.48 Phase 2 pause window (2026-10-06 `cert bad sig` stall)
    // ---------------------------------------------------------------------

    /// Baked 2300 window, parsing, precedence and the startup gate for the
    /// exact fleet configurations we run or will run.
    #[test]
    fn vote_rounds_pause_baked_for_2300_precedence_and_startup_gate() {
        use crate::{
            check_vote_rounds_startup as gate, parse_vote_rounds_pause as parse,
            resolve_vote_rounds_from_height as rvr, resolve_vote_rounds_pause as rp,
            TESTNET_2300_VOTE_ROUNDS_PAUSE_FROM as PF, TESTNET_2300_VOTE_ROUNDS_RESUME_AT as RA,
        };
        assert_eq!(PF, 371_037, "first legacy-signed cert height on 2300");
        assert!(RA > PF && RA > 371_540, "resume must sit above the 2026-10-06 tip");
        assert_eq!(crate::network_vote_rounds_pause(2300), (PF, RA));
        assert_eq!(crate::network_vote_rounds_pause(2200), (0, 0));

        assert_eq!(parse("371037..380000"), Ok((371_037, 380_000)));
        assert_eq!(parse(" 371037 .. 385000 "), Ok((371_037, 385_000)));
        for off in ["off", "OFF", "none", "0", ""] {
            assert_eq!(parse(off), Ok((0, 0)), "{off:?}");
        }
        for bad in ["380000..371037", "5..5", "0..10", "10", "a..b", "10..x"] {
            assert!(parse(bad).is_err(), "{bad:?} must be rejected");
        }

        // Precedence: env (even off) > cli (even off) > bridge.json > constant.
        let r = rp(2300, None, None, (0, 0));
        assert_eq!((r.from, r.resume_at, r.source, r.mismatch), (PF, RA, "network-constant", false));
        let r = rp(2300, None, None, (PF, 390_000));
        assert_eq!((r.resume_at, r.source, r.mismatch), (390_000, "bridge.json", true));
        let r = rp(2300, None, Some((PF, 385_000)), (PF, 390_000));
        assert_eq!((r.resume_at, r.source), (385_000, "cli"));
        let r = rp(2300, None, Some((0, 0)), (PF, 390_000));
        assert_eq!((r.from, r.source, r.mismatch), (0, "cli", true), "explicit cli off wins");
        let r = rp(2300, Some((0, 0)), Some((PF, 385_000)), (0, 0));
        assert_eq!((r.from, r.resume_at, r.source, r.mismatch), (0, 0, "env", true));
        let r = rp(2200, None, None, (0, 0));
        assert_eq!((r.from, r.source, r.mismatch), (0, "off", false));

        // Startup gate, fleet shapes:
        // (a) target state: vote-rounds.conf (env 369998), no pause env.
        let a = rvr(2300, Some(369_998), 0, 0);
        assert_eq!(gate(2300, &a, &rp(2300, None, None, (0, 0)), false), Ok(vec![]));
        // (b) binary installed while zzz-legacy-unjam.conf is still present:
        //     starts (override) and stays legacy — the window is inert.
        let b = rvr(2300, Some(999_999_999), 0, 0);
        assert!(gate(2300, &b, &rp(2300, None, None, (0, 0)), false).is_err());
        assert_eq!(gate(2300, &b, &rp(2300, None, None, (0, 0)), true).map(|w| w.len()), Ok(1));
        // (c) bumping the resume height by env needs the override.
        let bump = rp(2300, Some((PF, 385_000)), None, (0, 0));
        let e = gate(2300, &a, &bump, false).unwrap_err();
        assert!(e.contains("vote_rounds_pause=[371037, 385000)") && e.contains("refusing"), "{e}");
        assert_eq!(gate(2300, &a, &bump, true).map(|w| w.len()), Ok(1));
        // (d) malformed window is refused even with the override.
        let mut badw = rp(2300, None, None, (0, 0));
        badw.resume_at = badw.from;
        assert!(gate(2300, &a, &badw, true).is_err());
    }

    #[test]
    fn vote_rounds_at_respects_pause_window() {
        let mut n = lone_node("v1");
        n.cfg.network_id = 2300;
        n.cfg.vote_rounds_from_height = 369_998;
        let (pf, ra) = crate::network_vote_rounds_pause(2300);
        n.cfg.vote_rounds_pause_from = pf;
        n.cfg.vote_rounds_resume_at = ra;
        assert!(!n.vote_rounds_at(369_997));
        assert!(n.vote_rounds_at(369_998));
        assert!(n.vote_rounds_at(371_036), "last round-scoped cert before the pause");
        assert!(!n.vote_rounds_at(371_037), "first legacy-signed cert");
        assert!(!n.vote_rounds_at(371_477), "the 2026-10-06 stall tip cert");
        assert!(!n.vote_rounds_at(ra - 1));
        assert!(n.vote_rounds_at(ra), "round-scoped again at resume");
        assert!(n.vote_rounds_paused_at(371_037) && !n.vote_rounds_paused_at(ra));
        assert_eq!(n.own_ok_round(371_600), 0, "legacy round inside the window");
        // Legacy-unjam override: window inert, everything legacy.
        n.cfg.vote_rounds_from_height = 999_999_999;
        assert!(!n.vote_rounds_at(369_998) && !n.vote_rounds_at(ra));
        // Status exposes the window.
        n.cfg.vote_rounds_from_height = 369_998;
        let st = n.status_json();
        assert_eq!(st["vote_rounds_pause_from"], pf);
        assert_eq!(st["vote_rounds_resume_at"], ra);
        assert_eq!(st["vote_rounds_pause_network_default"], serde_json::json!([pf, ra]));
    }

    fn signed_cfg() -> ChainConfig {
        ChainConfig {
            require_vote_sigs: true,
            ..cfg(1)
        }
    }

    /// Seal one height with **signed** OK votes (every voter signs in its own
    /// node's round for that height), so certs carry real `pl-ok:v1`/`v2` sigs.
    fn seal_signed(net: &mut Network) -> Result<Ledger, String> {
        net.payment("alice", "bob", 1, 1).map_err(|e| format!("{e:?}"))?;
        net.pong_all();
        let packer = net.nodes.values().next().unwrap().lottery_packer().ok_or("no packer")?;
        for n in net.nodes.values_mut() {
            n.pong(&packer);
        }
        let led = net
            .nodes
            .get_mut(&packer)
            .unwrap()
            .pack_or_skip(&packer)?
            .ok_or("packer produced no ledger")?;
        for n in net.nodes.values_mut() {
            n.accept_ledger(&led)?;
        }
        let ids: Vec<String> = net.nodes.keys().cloned().collect();
        let sigs: Vec<(String, String, u64)> = ids
            .iter()
            .map(|v| {
                let n = &net.nodes[v];
                let r = n.own_ok_round(led.height);
                (v.clone(), n.sign_ok_vote_round(led.height, r, &led.ledger_hash), r)
            })
            .collect();
        for n in net.nodes.values_mut() {
            for (v, sig, r) in &sigs {
                n.vote_ok_round_ex(&led.ledger_hash, v, sig, *r);
            }
        }
        let tip = net.tip_height();
        if tip < led.height {
            return Err(format!("soft QC did not commit h={} tip={tip}", led.height));
        }
        Ok(led)
    }

    fn set_window(net: &mut Network, from: u64, resume: u64) {
        for n in net.nodes.values_mut() {
            n.cfg.vote_rounds_pause_from = from;
            n.cfg.vote_rounds_resume_at = resume;
        }
    }

    /// Which payload every signature in `cert` verifies under.
    fn cert_kind(n: &Node, cert: &crate::LedgerCert) -> &'static str {
        let need = cert.voters.len();
        let legacy = cert.verify_ex(&n.keys, n.cfg.network_id, true, need, false).is_ok();
        let round = cert.verify_ex(&n.keys, n.cfg.network_id, true, need, true).is_ok();
        match (legacy, round) {
            (true, false) => "legacy",
            (false, true) => "round",
            (true, true) => "both",
            _ => "neither",
        }
    }

    /// Phase 2 live from h=1, paused (legacy-signed certs) from cert height
    /// `PF`, then re-enabled. Mirrors 2300: round certs ≤371036, legacy certs
    /// from 371037, tip cert legacy.
    const PF: u64 = 4;

    fn paused_chain() -> Network {
        let mut net = Network::bootstrap(&SIX, 1000, &users(), signed_cfg());
        for _ in 1..PF {
            seal_signed(&mut net).expect("round-scoped heights");
        }
        // The 2026-10-05 pause: from here certs are signed with pl-ok:v1. (Open
        // ended while it lasts; ledger PF still carries round cert PF-1.)
        set_window(&mut net, PF, u64::MAX);
        for _ in PF..=6 {
            seal_signed(&mut net).expect("legacy heights during the pause");
        }
        assert_eq!(net.tip_height(), 6);
        let n = &net.nodes["v1"];
        for h in 1..PF {
            assert_eq!(cert_kind(n, &n.certs[&h]), "round", "h={h}");
        }
        for h in PF..=6 {
            assert_eq!(cert_kind(n, &n.certs[&h]), "legacy", "h={h}");
            assert_eq!(n.certs[&h].round, 0);
        }
        net
    }

    /// The 2026-10-06 08:56 stall: re-enabling Phase 2 with only the activation
    /// height makes the legacy tip cert unverifiable (`cert bad sig`) so no
    /// packer can extend the tip. With the window it extends, stays legacy up
    /// to `resume_at`, and is round-scoped again from there.
    #[test]
    fn legacy_tip_cert_after_pause_needs_window_then_resumes_round_scoped() {
        // Without the window (activation only): stuck exactly like live.
        let mut stuck = paused_chain();
        set_window(&mut stuck, 0, 0);
        let tip_cert = stuck.nodes["v1"].certs[&6].clone();
        let n = &stuck.nodes["v1"];
        let e = tip_cert
            .verify_ex(&n.keys, n.cfg.network_id, true, 4, n.vote_rounds_at(6))
            .unwrap_err();
        assert!(e.starts_with("cert bad sig for "), "{e}");
        let e = seal_signed(&mut stuck).unwrap_err();
        assert!(e.contains("cert bad sig"), "re-enable without window must fail: {e}");
        assert_eq!(stuck.tip_height(), 6);

        // With the window [PF, 9): extends on legacy, resumes round-scoped at 9.
        let resume = 9;
        let mut net = paused_chain();
        set_window(&mut net, PF, resume);
        for n in net.nodes.values() {
            assert!(!n.vote_rounds_at(7), "tip+1 inside the window is legacy");
        }
        for _ in 7..=11 {
            seal_signed(&mut net).expect("window lets the chain move and resume");
        }
        assert_eq!(net.tip_height(), 11);
        for n in net.nodes.values() {
            for h in 1..PF {
                assert_eq!(cert_kind(n, &n.certs[&h]), "round", "{} h={h}", n.id);
            }
            for h in PF..resume {
                assert_eq!(cert_kind(n, &n.certs[&h]), "legacy", "{} h={h}", n.id);
            }
            for h in resume..=10 {
                assert_eq!(cert_kind(n, &n.certs[&h]), "round", "{} h={h}", n.id);
            }
            assert!(n.vote_rounds_at(12));
            assert!(n.validators.values().all(|v| !v.jailed), "no false jails at either edge");
            assert!(n.pending_slashes.is_empty());
        }
    }

    /// A fresh seat replaying history across both window edges (round →
    /// legacy at PF, legacy → round at resume) verifies every parent cert.
    /// Without the window, or in pure legacy mode, it stops at an edge.
    #[test]
    fn catch_up_across_pause_window_verifies_every_parent_cert() {
        let resume = 9;
        let mut net = paused_chain();
        set_window(&mut net, PF, resume);
        for _ in 7..=11 {
            seal_signed(&mut net).unwrap();
        }
        let src = &net.nodes["v1"];
        let ledgers: Vec<Ledger> = src.chain.iter().cloned().collect();
        assert_eq!(ledgers.last().map(|l| l.height), Some(11));

        let fresh = |from: u64, pf: u64, ra: u64| {
            let mut c = signed_cfg();
            c.vote_rounds_from_height = from;
            c.vote_rounds_pause_from = pf;
            c.vote_rounds_resume_at = ra;
            let mut o = Node::new("obs", c, src.keys.clone(), &users());
            for v in SIX {
                o.register_validator(v, 1000);
            }
            o.freeze_open_height_schedule();
            o
        };
        let replay = |o: &mut Node| -> Result<(), (u64, String)> {
            for l in &ledgers {
                o.ingest_ledger_catchup(l).map_err(|e| (l.height, e))?;
            }
            Ok(())
        };

        let mut ok = fresh(1, PF, resume);
        replay(&mut ok).expect("catch-up across the window");
        assert_eq!(ok.tip_height, 11);
        assert_eq!(ok.tip_hash, src.tip_hash);

        // Activation only: ledger PF+1 carries legacy cert PF.
        let (h, e) = replay(&mut fresh(1, 0, 0)).unwrap_err();
        assert_eq!(h, PF + 1, "{e}");
        assert!(e.contains("cert bad sig"), "{e}");
        // Legacy everywhere (the zzz-legacy-unjam view): ledger 2 carries round cert 1.
        let (h, e) = replay(&mut fresh(0, 0, 0)).unwrap_err();
        assert_eq!(h, 2, "{e}");
        assert!(e.contains("cert bad sig") || e.contains("legacy height"), "{e}");
        // Window without the resume edge: ledger resume+1 carries round cert resume.
        let (h, e) = replay(&mut fresh(1, PF, u64::MAX)).unwrap_err();
        assert_eq!(h, resume + 1, "{e}");
        assert!(e.contains("cert"), "{e}");
    }

    /// bridge.json without a window keeps the pre-v2.9.48 digest; a window
    /// changes it and is drift-checked against the running window.
    #[test]
    fn bridge_cfg_pause_window_digest_and_drift() {
        let base = crate::lc::LcBridgeCfg {
            start_height: 116_957,
            network_id: 2300,
            key_root: "ab".into(),
            qc_header_version: 4,
            qc_start_height: 353_091,
            vote_rounds_from_height: 0,
            vote_rounds_pause_from: 0,
            vote_rounds_resume_at: 0,
        };
        // Pinned pre-v2.9.48 canonical string.
        use sha2::{Digest, Sha256};
        let legacy = hex::encode(Sha256::digest(
            b"falcon-pl-qc-cfg:v1|nid=2300|start=116957|qcv=4|qcs=353091|vr=0|root=ab",
        ));
        assert_eq!(crate::lc::qc_cfg_digest(&base), legacy);
        let with = crate::lc::LcBridgeCfg {
            vote_rounds_pause_from: 371_037,
            vote_rounds_resume_at: 380_000,
            ..base.clone()
        };
        assert_ne!(crate::lc::qc_cfg_digest(&with), legacy);

        let dir = std::env::temp_dir().join(format!("fdpl-pause-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("lc")).unwrap();
        std::fs::write(
            dir.join("lc/bridge.json"),
            r#"{"start_height":116957,"network_id":2300,"key_root":"ab","qc_header_version":4,"qc_start_height":353091,"vote_rounds_pause_from":371037,"vote_rounds_resume_at":385000}"#,
        )
        .unwrap();
        let mut n = lone_node("v3");
        n.cfg.network_id = 2300;
        n.cfg.vote_rounds_from_height = 369_998;
        n.cfg.vote_rounds_pause_from = 371_037;
        n.cfg.vote_rounds_resume_at = 380_000;
        n.keys_dir = Some(dir.clone());
        n.apply_qc_bridge_cfg();
        let st = n.bridge_cfg_status().unwrap();
        let r: Vec<String> = serde_json::from_value(st["drift_reasons"].clone()).unwrap();
        assert_eq!(r, vec!["vote_rounds_pause_differs_from_running".to_string()], "{st}");
        assert_eq!(st["running_vote_rounds_pause"], serde_json::json!([371_037, 380_000]));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// v2.9.58: a lagging seat (tip=h) used to verify a round-0 OK for h+2
    /// against height h+1 (`ok_vote_height` ignores the wire height) and drop
    /// it. Now it is buffered (signature checked against its own height) and
    /// counted through the normal path once h+2 opens.
    #[test]
    fn future_oks_are_buffered_and_replayed_when_height_opens() {
        let mut net = six_after_one(1);
        let order = net.nodes["v1"].lottery_order();
        let a = pack_in_round(&mut net, &order[0], 0);
        assert_eq!(a.height, 2);
        let lag = order[5].clone();
        for (id, n) in net.nodes.iter_mut() {
            if *id != lag {
                n.ingest_ledger_catchup(&a).expect("commit h=2");
            }
        }
        // Body X for h=3 (unknown to the lagging seat; never needs to exist).
        let x = crate::sha256_hex(b"fpl-2958-future-body-h3");
        let voters: Vec<String> = order[0..3].to_vec();
        let sigs: Vec<(String, String)> = voters
            .iter()
            .map(|v| (v.clone(), net.nodes[v].sign_ok_vote_round(3, 0, &x)))
            .collect();
        let me_sig = net.nodes[&lag].sign_ok_vote_round(3, 0, &x);
        let n = net.nodes.get_mut(&lag).unwrap();
        n.cfg.require_vote_sigs = true;
        assert_eq!(n.tip_height, 1);
        // Pre-2.9.58 path: verified as h=2 → bad sig → dropped.
        for (v, sig) in &sigs {
            assert_eq!(n.vote_ok_round_ex(&x, v, sig, 0), (false, false, false));
        }
        assert!(n.round_votes.values().all(|r| r.values().all(|m| m.values().all(|(h, _)| *h != x))));
        // 2.9.58 wire path: buffered, nothing counted yet.
        for (v, sig) in &sigs {
            assert_eq!(n.vote_ok_wire(3, &x, v, sig, 0), (false, false, false));
        }
        assert_eq!(n.future_oks.len(), 3);
        // Duplicates, bad signatures, our own id and heights past the window
        // are not buffered.
        let (v0, s0) = &sigs[0];
        let _ = n.vote_ok_wire(3, &x, v0, s0, 0);
        let _ = n.vote_ok_wire(3, &x, &voters[1], s0, 0);
        let _ = n.vote_ok_wire(3, &x, &lag.clone(), &me_sig, 0);
        let far = 1 + Node::FUTURE_OK_WINDOW + 1;
        let _ = n.vote_ok_wire(far, &x, v0, s0, 0);
        assert_eq!(n.future_oks.len(), 3, "dup / bad sig / self / out of window ignored");
        // Catch up h=2: h=3 opens and the buffered OKs are counted.
        // (harness ledgers carry unsigned certs; signatures were checked when
        // the OKs were buffered, against their own height)
        n.cfg.require_vote_sigs = false;
        n.ingest_ledger_catchup(&a).expect("lagging seat catches up h=2");
        n.cfg.require_vote_sigs = true;
        assert_eq!(n.tip_height, 2);
        assert!(n.future_oks.is_empty());
        let r0 = n.round_votes.get(&3).and_then(|r| r.get(&0)).cloned().unwrap_or_default();
        let counted: BTreeSet<String> = r0
            .iter()
            .filter(|(_, (h, _))| *h == x)
            .map(|(v, _)| v.clone())
            .collect();
        assert_eq!(counted, voters.iter().cloned().collect::<BTreeSet<_>>(), "{r0:?}");
        assert!(n.pending_slashes.is_empty(), "replay is not equivocation");
        // A 4th OK arriving live now reaches the 4-of-6 commit quorum count.
        let v3 = order[3].clone();
        let s3 = net.nodes[&v3].sign_ok_vote_round(3, 0, &x);
        let n = net.nodes.get_mut(&lag).unwrap();
        let (soft, _, fresh) = n.vote_ok_wire(3, &x, &v3, &s3, 0);
        assert!(fresh);
        assert!(soft, "buffered 3 + live 1 = 4 of 6");
    }

    #[test]
    fn future_ok_buffer_is_bounded() {
        let mut net = six_after_one(1);
        let order = net.nodes["v1"].lottery_order();
        let lag = order[5].clone();
        let v = order[0].clone();
        let mut entries = Vec::new();
        for i in 0..(Node::FUTURE_OK_CAP + 40) {
            let hash = crate::sha256_hex(format!("b{i}").as_bytes());
            let h = 3 + (i as u64 % 4);
            entries.push((h, hash.clone(), net.nodes[&v].sign_ok_vote_round(h, 0, &hash)));
        }
        let n = net.nodes.get_mut(&lag).unwrap();
        n.cfg.require_vote_sigs = true;
        for (h, hash, sig) in &entries {
            let _ = n.vote_ok_wire(*h, hash, &v, sig, 0);
        }
        assert_eq!(n.future_oks.len(), Node::FUTURE_OK_CAP);
        // Oldest dropped first.
        assert_eq!(n.future_oks.last().unwrap().ledger_hash, entries.last().unwrap().1);
        assert_ne!(n.future_oks[0].ledger_hash, entries[0].1);
    }

    // ---------------------------------------------------------------
    // v2.9.59: packer pacing
    // ---------------------------------------------------------------

    fn pace_cfg() -> ChainConfig {
        // Live-like timing: 1 s pack budget, 3 s progress timeout.
        ChainConfig {
            pack_budget_ms: 1_000,
            max_txs_per_ledger: 0,
            progress_timeout_ms: 3_000,
            vote_rounds_from_height: 1,
            ..Default::default()
        }
    }

    /// Tick-driven sim of the live seal loop on 6 seats at `tx_every_ms`
    /// (one payment per interval) for `sim_ms`: every 100 ms all clocks
    /// advance, the round-0 winner packs when the binary's gate would let
    /// it (soft tip, no pending, not `pace_wait`), every seat stages and
    /// OKs, and every seat is asked for a view-change vote.
    /// Returns (blocks, txs committed, txs submitted, view-change votes,
    /// max gap between commits in ms).
    fn pace_sim(pace_ms: u64, tx_every_ms: u64, sim_ms: u64) -> (u64, u64, u64, u64, u64) {
        pace_sim_hold(pace_ms, 0, tx_every_ms, sim_ms)
    }

    /// `raw_hold_ms` > 0: the winner instead holds for that long with no cap
    /// (negative control proving the sim detects round-0 timeouts).
    fn pace_sim_hold(pace_ms: u64, raw_hold_ms: u64, tx_every_ms: u64, sim_ms: u64) -> (u64, u64, u64, u64, u64) {
        let mut net = Network::bootstrap(&SIX, 1000, &users(), pace_cfg());
        net.pong_all();
        for n in net.nodes.values_mut() {
            n.pace_min_interval_ms = pace_ms;
        }
        let ids: Vec<String> = net.nodes.keys().cloned().collect();
        let senders = ["alice", "bob", "carol"];
        let (mut blocks, mut txs, mut sent, mut vcs) = (0u64, 0u64, 0u64, 0u64);
        let (mut last_commit, mut max_gap) = (0u64, 0u64);
        let mut t = 0u64;
        while t < sim_ms {
            t += 100;
            for n in net.nodes.values_mut() {
                n.tick(100);
            }
            net.pong_all();
            if t % tx_every_ms == 0 {
                let from = senders[(sent as usize) % senders.len()];
                net.payment(from, "dave", 1, 1).unwrap();
                sent += 1;
            }
            for n in net.nodes.values_mut() {
                n.best_peer_tip = n.tip_height;
            }
            let w = net.nodes["v1"].lottery_packer().expect("winner");
            let packed = {
                let n = net.nodes.get_mut(&w).unwrap();
                let hold = if raw_hold_ms > 0 {
                    n.height_view_round == 0 && n.now_ms.saturating_sub(n.height_open_ms) < raw_hold_ms
                } else {
                    n.pace_wait()
                };
                if n.tip_is_soft() && n.pending_proposal.is_none() && !hold {
                    n.pack_or_skip(&w).expect("pack")
                } else {
                    None
                }
            };
            if let Some(led) = packed {
                for (id, n) in net.nodes.iter_mut() {
                    // v2.9.59 prestage gate passes every valid round-mode
                    // proposal on every receiver (the off-lock warm-up runs).
                    if *id != w {
                        match n.prestage_root_input(&led) {
                            crate::Prestage::Run(job) => {
                                assert_eq!(job.run(), led.state_root_after);
                            }
                            _ => panic!("round-mode prestage gate rejected a valid proposal on {id}"),
                        }
                    }
                    n.accept_ledger(&led).expect("stage");
                }
                for n in net.nodes.values_mut() {
                    for id in &ids {
                        n.vote_ok(&led.ledger_hash, id);
                    }
                }
                for n in net.nodes.values() {
                    assert_eq!(n.tip_height, led.height, "commit everywhere");
                }
                blocks += 1;
                txs += led.txs.len() as u64;
                if last_commit > 0 {
                    max_gap = max_gap.max(t - last_commit);
                }
                last_commit = t;
            }
            for n in net.nodes.values_mut() {
                if n.maybe_view_change_vote().is_some() {
                    vcs += 1;
                }
            }
        }
        (blocks, txs, sent, vcs, max_gap)
    }

    #[test]
    fn pacing_lowers_block_rate_same_throughput_no_view_changes() {
        // 5 tx/s for 2 simulated minutes.
        let (b0, tx0, sent0, vc0, _) = pace_sim(0, 200, 120_000);
        let (b1, tx1, sent1, vc1, gap1) = pace_sim(2_500, 200, 120_000);
        eprintln!(
            "unpaced: {b0} blocks {tx0}/{sent0} txs vc={vc0}; paced 2.5s: {b1} blocks {tx1}/{sent1} txs vc={vc1} max_gap={gap1}ms"
        );
        assert_eq!(vc0, 0, "baseline sim must not view-change");
        assert_eq!(vc1, 0, "pacing must not trigger round-0 view-changes");
        assert!(tx0 + 1 >= sent0, "unpaced committed {tx0}/{sent0}");
        assert!(tx1 + 20 >= sent1, "paced committed {tx1}/{sent1}");
        assert!(b1 * 4 <= b0, "paced {b1} vs unpaced {b0} blocks");
        assert!(gap1 <= 3_000, "max gap {gap1}");
        assert!(tx1 / b1.max(1) >= 10, "tx/block {}", tx1 / b1.max(1));
        // Negative control: an uncapped 8 s hold (beyond the 6.6 s round-0
        // silence timeout) does make peers view-change in the same sim.
        let (_, _, _, vc_bad, _) = pace_sim_hold(0, 8_000, 200, 30_000);
        assert!(vc_bad > 0, "control: sim must detect round-0 timeouts");
    }

    #[test]
    fn pacing_ends_early_on_full_mempool_and_after_view_change() {
        // 50 tx/s: the 128-tx threshold would end pacing; at 2.5 s that is
        // 125 txs, so lower the threshold to see it bite.
        let mut net = Network::bootstrap(&SIX, 1000, &users(), pace_cfg());
        net.pong_all();
        let w = net.nodes["v1"].lottery_packer().unwrap();
        {
            let n = net.nodes.get_mut(&w).unwrap();
            n.pace_min_interval_ms = 2_500;
            n.pace_mempool_txs = 3;
            n.tip_advanced_ms = n.now_ms;
        }
        net.payment("alice", "dave", 1, 1).unwrap();
        assert!(net.nodes[&w].pace_wait(), "1 tx, fresh height: wait");
        net.payment("bob", "dave", 1, 1).unwrap();
        net.payment("carol", "dave", 1, 1).unwrap();
        assert!(!net.nodes[&w].pace_wait(), "threshold reached: seal now");
        let n = net.nodes.get_mut(&w).unwrap();
        n.pace_mempool_txs = 128;
        assert!(n.pace_wait());
        // Next-height gossip resets `height_open_ms` but cannot extend the
        // wait: pacing is anchored on the parent-commit clock.
        for _ in 0..25 {
            n.tick(100);
            n.note_next_height_activity();
        }
        assert!(!n.pace_wait(), "pace window elapsed");
        n.tip_advanced_ms = n.now_ms;
        assert!(n.pace_wait());
        n.height_view_round = 1;
        assert!(!n.pace_wait(), "a view-change seals a short pool");
        n.height_view_round = 0;
        n.pace_min_interval_ms = 0;
        assert!(!n.pace_wait(), "0 = off");
    }

    /// The cap keeps pace + one full live pack window (budget + NeedTxs
    /// grace + seal/gossip slack) inside peers' round-0 silence timeout, for
    /// any configured interval and timing knobs.
    #[test]
    fn pacing_cap_stays_inside_round0_silence_timeout() {
        for budget in [0u64, 500, 1_000, 2_000] {
            for progress in [1_000u64, 2_500, 3_000, 5_000] {
                let mut net = Network::bootstrap(&SIX, 1000, &users(), ChainConfig {
                    pack_budget_ms: budget,
                    progress_timeout_ms: progress,
                    vote_rounds_from_height: 1,
                    ..Default::default()
                });
                // Peers see the pacing winner as live (it pongs every seal tick
                // with its tip), i.e. not `active_packer_unavailable`.
                net.pong_all();
                let n = net.nodes.get_mut("v1").unwrap();
                assert!(!n.active_packer_unavailable());
                for want in [1u64, 2_500, 3_000, 10_000, u64::MAX / 4] {
                    n.pace_min_interval_ms = want;
                    let eff = n.pace_effective_ms();
                    assert!(eff <= want);
                    assert!(
                        eff + n.live_pack_timeout_ms() <= n.round_silence_timeout_ms(0),
                        "budget={budget} progress={progress} want={want} eff={eff}"
                    );
                    // Legacy (non-round) path: proposal timeout is 4x progress.
                    assert!(eff + n.live_pack_timeout_ms() <= n.proposal_timeout_ms().max(n.live_pack_timeout_ms()));
                }
            }
        }
        // Live flags (pack budget 1000): 2.5 s is not clipped.
        let mut net = Network::bootstrap(&SIX, 1000, &users(), pace_cfg());
        net.pong_all();
        let n = net.nodes.get_mut("v1").unwrap();
        n.pace_min_interval_ms = 2_500;
        assert_eq!(n.pace_effective_ms(), 2_500);
        assert_eq!(n.round_silence_timeout_ms(0), 6_600);
    }

    // ------------------------------------------------------------------
    // v2.9.79: 671185 stall (2026-10-21). Round-0 proposer for h+1 was a
    // cert-less seat; three of the next six were cert-less, the recert round
    // (counted against the next committee) never reached 4 and cert holders
    // alone (3) could not reach 4 view-change votes. ~66 min halt.
    // ------------------------------------------------------------------

    /// h=2 committed everywhere; only `holders` keep the cert.
    fn tip_cert_on(net: &mut Network, holders: &[String]) -> (u64, Ledger) {
        let h = 2;
        let order = net.nodes["v1"].lottery_order();
        let a = pack_in_round(net, &order[0], 0);
        let all: Vec<String> = SIX.iter().map(|s| s.to_string()).collect();
        for id in &all {
            let n = net.nodes.get_mut(id).unwrap();
            if holders.contains(id) {
                n.open_bodies.insert(a.ledger_hash.clone(), a.clone());
                n.seen_at_height.insert(h, (a.packer.clone(), a.ledger_hash.clone()));
                n.pending_proposal = Some(a.clone());
                for v in &order[0..4] {
                    let _ = n.vote_ok_round_ex(&a.ledger_hash, v, "", 0);
                }
                assert!(n.certs.contains_key(&h), "{id} holds cert");
            } else {
                n.ingest_ledger_catchup(&a).expect("catch-up commit");
                assert!(!n.certs.contains_key(&h), "{id} cert-less");
                // Live seats are on v4 headers, which carry the frozen sealing
                // committee; this test chain seals pre-v4 bodies.
                if let Some(l) = n.chain.last_mut() {
                    if l.current_committee.is_empty() {
                        l.current_committee = order.clone();
                    }
                }
            }
            assert_eq!(n.tip_height, h);
        }
        for n in net.nodes.values_mut() {
            n.best_peer_tip = h;
            n.freeze_open_height_schedule();
            n.sync_round_skips(h + 1);
        }
        (h, a)
    }

    #[test]
    fn s671185_certless_winner_rebuilds_cert_from_relayed_oks() {
        let mut net = six_after_one(1);
        let holder = "v1".to_string();
        let (h, a) = tip_cert_on(&mut net, &[holder.clone()]);
        let relay = net.nodes[&holder].tip_cert_relay();
        assert!(relay.len() >= 4, "holder relays the original OKs");
        for id in SIX.iter().filter(|id| **id != "v1") {
            let n = net.nodes.get_mut(*id).unwrap();
            let e = n.may_pack_locally(id).err().unwrap_or_default();
            // Pre-fix: any cert-less seat that wins h+1 is stuck here.
            assert!(n.certs.get(&h).is_none());
            let _ = e;
            let mut done = false;
            for (v, sig, r) in &relay {
                done |= n.note_tip_cert_vote(h, &a.ledger_hash, v, sig, *r);
            }
            assert!(done, "{id} rebuilt cert");
            let c = n.certs.get(&h).expect("cert");
            assert!(n.verify_cert(c).is_ok());
            let e = n.may_pack_locally(id).err().unwrap_or_default();
            assert!(!e.contains("no tip cert"), "{id}: {e}");
        }
    }

    #[test]
    fn tip_cert_votes_reject_wrong_hash_height_and_short_sets() {
        let mut net = six_after_one(1);
        let (h, a) = tip_cert_on(&mut net, &["v1".to_string()]);
        let relay = net.nodes["v1"].tip_cert_relay();
        let n = net.nodes.get_mut("v2").unwrap();
        // Wrong hash / wrong height: ignored.
        for (v, sig, r) in &relay {
            assert!(!n.note_tip_cert_vote(h, "deadbeef", v, sig, *r));
            assert!(!n.note_tip_cert_vote(h + 1, &a.ledger_hash, v, sig, *r));
        }
        assert!(n.certs.get(&h).is_none());
        // Only 3 voters: below 4-of-6, no cert.
        for (v, sig, r) in relay.iter().take(3) {
            assert!(!n.note_tip_cert_vote(h, &a.ledger_hash, v, sig, *r));
        }
        assert!(n.certs.get(&h).is_none());
        // Non-committee "voter" never counts.
        assert!(!n.note_tip_cert_vote(h, &a.ledger_hash, "mallory", "", relay[0].2));
        assert!(n.certs.get(&h).is_none());
    }

    #[test]
    fn s671185_certless_seats_vote_round_forward_after_2x_timeout() {
        let mut net = six_after_one(1);
        let order = net.nodes["v1"].lottery_order();
        // Three holders, three cert-less (incl. order[0] = h+1 proposer in
        // the next freeze once we re-freeze — we only need cert-less voters).
        let holders: Vec<String> = order[3..6].to_vec();
        let (h, _a) = tip_cert_on(&mut net, &holders);
        let pto = net.nodes["v1"].proposal_timeout_ms();
        let certless: Vec<String> = SIX
            .iter()
            .map(|s| s.to_string())
            .filter(|id| !holders.contains(id))
            .collect();
        for id in &certless {
            let n = net.nodes.get_mut(id).unwrap();
            n.round_open_ms = n.now_ms;
            n.height_open_ms = n.now_ms;
            n.now_ms += pto + 1;
            assert!(!n.certless_round_vc_allowed(), "{id}: not before 2x timeout");
            assert!(n.maybe_view_change_vote().is_none());
            n.now_ms += pto;
            assert!(n.certless_round_vc_allowed(), "{id}: allowed after 2x timeout");
        }
        let _ = h;
    }

    #[test]
    fn certless_vc_never_on_legacy_heights() {
        let mut net = six_after_one(u64::MAX);
        let n = net.nodes.get_mut("v1").unwrap();
        n.certs.clear();
        n.now_ms += n.proposal_timeout_ms() * 10;
        assert!(!n.certless_round_vc_allowed());
        assert!(n.maybe_view_change_vote().is_none());
    }

    #[test]
    fn pong_fresh_silent_proposer_slot_capped_at_proposal_timeout() {
        let mut cfg = cfg(1);
        cfg.progress_timeout_ms = 9_000;
        cfg.pack_budget_ms = 4_000;
        let mut net = Network::bootstrap(&SIX, 1000, &users(), cfg);
        net.pong_all();
        let n = net.nodes.get_mut("v1").unwrap();
        // Heartbeats keep every seat fresh; silence still ends by 36s.
        assert!(n.round_silence_timeout_ms(0) <= n.proposal_timeout_ms());
        assert_eq!(n.proposal_timeout_ms(), 36_000);
    }
}
