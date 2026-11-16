// Copyright (c) 2025-2026 BEARTEC. All rights reserved. See LICENSE.
//! BRIDGE: the BitVM2 operator network wired into the ledger.
//!
//! Everything here is refused / inert before the combined bridge height
//! (`params_v2::TESTNET_2300_BRIDGE_FROM_HEIGHT`, `u64::MAX` today), so the
//! state transition and commitment root are unchanged until Scott arms it.
//!
//! - `OperatorRegister` locks a 5,000 FPL bond (100% slashable) and records
//!   the operator's BTC x-only graph key, reward script and capacity advert.
//! - `OperatorHeartbeat` = liveness slot + watch unit + capacity advert.
//! - `OperatorGraphBind` binds the operator's presigned graph txids for a
//!   deposit. `OperatorSlash` proves (SPV on the BTC rail) a BitVM2 Disprove /
//!   DisproveChain spending that graph -> bond slashed 100%: bounty share to
//!   the operator whose declared reward script received the Disprove reward
//!   output, the rest burned; slashed operator jailed / removed.
//! - Attested claims finalize to `PaidOptimistic` after
//!   [`BITVM2_PAYOUT_FINALITY_LEDGERS`] and credit the attesting operator's
//!   proven payout volume.
//! - A claim still `AwaitingPegout` [`BITVM2_PEGOUT_REFUND_LEDGERS`] after it
//!   opened (or after the bridge height, whichever is later) is `Refunded`: the
//!   burned FBTC is credited back to the withdrawer. Kits stop fronting a claim
//!   once half the window has passed, so a refund cannot race an honest payout.
//! - Epoch settle pays the 5% operator bucket through the registry; unpaid
//!   remainder returns to treasury; finished unbonds get their bond back.
//!
//! Falcon holds no BTC and no keys here: BTC only moves through the presigned
//! graphs on Bitcoin; the ledger only reads Bitcoin (headers + SPV proofs).
//! Payouts are fronted from operators' own BTC; the AMM pools are never used.

use crate::operator_registry::{classify_disprove, OperatorParams};
use crate::{Node, Tx, TxBody};

/// Ledgers a BitVM2 withdraw may sit in `AwaitingPegout` before it is
/// refunded (~48 h at ~4 s/ledger; 2x the payout finality window). OPEN
/// DECISION (Scott). Kits refuse to front after half of it
/// (`FRONT_CUTOFF_LEDGERS`), leaving >= 24 h for an in-flight peg-out to reach
/// 6 confirmations and be attested.
pub const BITVM2_PEGOUT_REFUND_LEDGERS: u64 = 43_200;

/// Ledgers after a successful `Bitvm2AttestV2` before the claim counts as a
/// finished payout for operator rewards (~24 h at ~4 s/ledger). The user
/// payment itself is SPV-proven at attest time; this window lets a BTC-side
/// Disprove of the same operator land (and forfeit the epoch credit) first.
/// Open decision (Scott).
pub const BITVM2_PAYOUT_FINALITY_LEDGERS: u64 = 21_600;

impl Node {
    /// Combined bridge release (M1 attest + operator network) active at `height`.
    pub fn bridge_at(&self, height: u64) -> bool {
        self.bitvm2_m1_at(height)
    }

    /// Decided operator parameters (preset B with Scott's bond 5k / slash 100% / 5%).
    pub fn operator_params(&self) -> OperatorParams {
        OperatorParams::default()
    }

    pub(crate) fn apply_operator_tx(&mut self, tx: &Tx) -> Result<(), String> {
        let h = self.tip_height.saturating_add(1);
        if !self.bridge_at(h) {
            return Err("operator: bridge not active at this height".into());
        }
        let p = self.operator_params();
        let epoch = self.current_epoch();
        match &tx.body {
            TxBody::OperatorRegister { btc_xonly, reward_spk_hex, gossip_url, capacity_sats } => {
                let mut sender = self.state.get(&tx.account);
                if sender.balance < tx.amount {
                    return Err("operator: insufficient balance for bond".into());
                }
                if let Some(r) = self.bridge.operators.by_account(&tx.account) {
                    if r.btc_xonly_hex != btc_xonly.trim().to_ascii_lowercase() {
                        return Err("operator: top-up must name the registered btc key".into());
                    }
                    self.bridge
                        .operators
                        .rebond(&p, epoch, &tx.account, tx.amount)
                        .map_err(|e| e.to_string())?;
                } else {
                    self.bridge
                        .operators
                        .register_ex(&p, &tx.account, btc_xonly, reward_spk_hex, gossip_url, *capacity_sats, tx.amount, h)
                        .map_err(|e| e.to_string())?;
                }
                sender.balance -= tx.amount;
                self.state.accounts.insert(tx.account.clone(), sender);
            }
            TxBody::OperatorHeartbeat { capacity_sats } => {
                let slot = self.current_epoch_slot();
                self.bridge
                    .operators
                    .heartbeat(&p, &tx.account, slot)
                    .map_err(|e| e.to_string())?;
                self.bridge
                    .operators
                    .set_capacity(&tx.account, *capacity_sats, h)
                    .map_err(|e| e.to_string())?;
            }
            TxBody::OperatorUnbond => {
                self.bridge
                    .operators
                    .begin_unbond(&p, epoch, &tx.account)
                    .map_err(|e| e.to_string())?;
            }
            TxBody::OperatorGraphBind { deposit_txid, kick_off_2_txid, assert_final_txid, depositor_account, cosign } => {
                if !depositor_account.is_empty() && !self.state.accounts.contains_key(depositor_account.trim()) {
                    return Err("operator: depositor_account is not a Falcon account".into());
                }
                if *cosign {
                    self.bridge
                        .operators
                        .cosign_graph(&tx.account, deposit_txid, kick_off_2_txid, assert_final_txid, h)
                        .map_err(|e| e.to_string())?;
                } else {
                    self.bridge
                        .operators
                        .bind_graph(&tx.account, deposit_txid, kick_off_2_txid, assert_final_txid, h)
                        .map_err(|e| e.to_string())?;
                }
                if !depositor_account.is_empty() {
                    let x = self
                        .bridge
                        .operators
                        .by_account(&tx.account)
                        .map(|r| r.btc_xonly_hex.clone())
                        .unwrap_or_default();
                    self.bridge.operators.set_graph_depositor(deposit_txid, &x, depositor_account);
                }
            }
            TxBody::Btc4PegIn { raw_tx_hex, btc_height, merkle_path, merkle_index } => {
                self.btc4_peg_in(raw_tx_hex, *btc_height, merkle_path, *merkle_index)?;
            }
            TxBody::OperatorSlash {
                operator_btc_xonly,
                deposit_txid,
                raw_tx_hex,
                btc_height,
                merkle_path,
                merkle_index,
            } => {
                let bind = self
                    .bridge
                    .operators
                    .graph_binding(deposit_txid, operator_btc_xonly)
                    .cloned()
                    .ok_or_else(|| "operator slash: no graph binding for (deposit, operator)".to_string())?;
                if bind.cosign {
                    return Err("operator slash: co-signer binding; slash the graph's operator".into());
                }
                let ptx = self.btc_rail_included_tx(raw_tx_hex, *btc_height, merkle_path, *merkle_index)?;
                let _kind = classify_disprove(&ptx, &bind)?;
                let reward_to = self
                    .bridge
                    .operators
                    .account_by_reward_spk(&ptx.outputs[1].1, &bind.account);
                let tag = format!("graph:{}:{}", bind.deposit_txid, bind.operator_btc_xonly_hex);
                let (_cut, bounty, _burned) = self
                    .bridge
                    .operators
                    .disprove(&p, epoch, &tag, &bind.operator_btc_xonly_hex, reward_to.as_deref())
                    .map_err(|e| e.to_string())?;
                if bounty > 0 {
                    if let Some(w) = reward_to {
                        *self.claimable.entry(w).or_insert(0) += bounty;
                    }
                }
            }
            _ => return Err("operator: not an operator body".into()),
        }
        Ok(())
    }

    /// SPV: `raw_tx_hex` is included at `btc_height` on the BTC rail with at
    /// least `BITVM2_PEGOUT_MIN_CONFS` confirmations.
    pub fn btc_rail_included_tx(
        &self,
        raw_tx_hex: &str,
        btc_height: u64,
        merkle_path: &[String],
        merkle_index: u32,
    ) -> Result<crate::btc_spv::ParsedTx, String> {
        // BTC4 (testnet4) first; legacy BTC kept for evidence already on it.
        // A bound graph's txids only exist on one chain, so either is sound.
        let rail = match self.bridge.rail(crate::bridge::RAIL_BTC4) {
            Ok(r4) if r4.headers.contains_key(&btc_height) => r4,
            _ => self.bridge.rail(crate::bridge::RAIL_BTC)?,
        };
        self.rail_included_tx(rail, raw_tx_hex, btc_height, merkle_path, merkle_index)
    }

    fn rail_included_tx(
        &self,
        rail: &crate::bridge::RailState,
        raw_tx_hex: &str,
        btc_height: u64,
        merkle_path: &[String],
        merkle_index: u32,
    ) -> Result<crate::btc_spv::ParsedTx, String> {
        let hdr = rail
            .headers
            .get(&btc_height)
            .ok_or_else(|| format!("no BTC header at {btc_height}"))?;
        if hdr.raw.is_empty() {
            return Err("BTC header at that height has no raw header".into());
        }
        let need = crate::bitvm2_exit::BITVM2_PEGOUT_MIN_CONFS;
        if rail.tip_height < btc_height || rail.tip_height - btc_height + 1 < need {
            return Err(format!("evidence needs {need} BTC confirmations"));
        }
        let raw = crate::btc_spv::hex_decode(raw_tx_hex)?;
        let tx = crate::btc_spv::parse_tx(&raw)?;
        let sib = crate::btc_spv::siblings_from_path(merkle_path)?;
        crate::btc_spv::verify_merkle(&tx.txid_display, &sib, merkle_index, &hdr.merkle_root)?;
        Ok(tx)
    }

    /// Attested BitVM2 claims -> `PaidOptimistic` after the finality window;
    /// credits the attesting operator's proven payout volume. Inert before
    /// the bridge height.
    pub(crate) fn bridge_finalize_claims(&mut self) {
        let h = self.tip_height.saturating_add(1);
        if !self.bridge_at(h) {
            return;
        }
        for asset in [crate::bridge::RAIL_BTC, crate::bridge::RAIL_BTC4] {
            self.bridge_finalize_rail(h, asset);
        }
    }

    fn bridge_finalize_rail(&mut self, h: u64, asset: &str) {
        let epoch = self.current_epoch();
        let Ok(rail) = self.bridge.rail_mut(asset) else {
            return;
        };
        let from_h = self.bitvm2_m1_from_height;
        let mut refunds = Vec::new();
        for c in rail.bitvm2_claims.values_mut() {
            if c.status == crate::bitvm2_exit::Bitvm2Status::AwaitingPegout
                && h >= c.open_height.max(from_h).saturating_add(BITVM2_PEGOUT_REFUND_LEDGERS)
            {
                c.status = crate::bitvm2_exit::Bitvm2Status::Refunded;
                refunds.push((c.from.clone(), c.amount));
            }
        }
        for (_, amt) in &refunds {
            rail.total_burned = rail.total_burned.saturating_sub(*amt);
        }
        let mut done = Vec::new();
        for c in rail.bitvm2_claims.values_mut() {
            if c.status == crate::bitvm2_exit::Bitvm2Status::ClaimPosted
                && c.attest_height > 0
                && h >= c.attest_height.saturating_add(BITVM2_PAYOUT_FINALITY_LEDGERS)
            {
                c.status = crate::bitvm2_exit::Bitvm2Status::PaidOptimistic;
                let id = if c.claim_id.is_empty() { c.note_id.clone() } else { c.claim_id.clone() };
                done.push((id, c.operator.clone(), c.amount));
            }
        }
        for (from, amt) in refunds {
            self.defi.credit_asset(&from, asset, amt);
        }
        for (id, op, amt) in done {
            // Unregistered attesters still finalize; they just earn nothing.
            let _ = self.bridge.operators.credit_payout_account(epoch, &id, &op, amt);
        }
        // Fix B: free settled leaves so the fixed-depth (16) tree keeps room.
        // Runs after the status moves above, same ledger, on every seat.
        if self.bitvm2_leaf_prune_at(h) {
            if let Ok(rail) = self.bridge.rail_mut(asset) {
                let _ = rail.prune_settled_bitvm2_leaves();
            }
        }
    }

    /// Which rail holds the BitVM2 claim `note_id` (BTC4 first).
    pub fn bitvm2_rail_for_note(&self, note_id: &str) -> &'static str {
        match self.bridge.rail(crate::bridge::RAIL_BTC4) {
            Ok(r) if r.bitvm2_claims.contains_key(note_id) => crate::bridge::RAIL_BTC4,
            _ => crate::bridge::RAIL_BTC,
        }
    }

    /// BRIDGE: testnet4 peg-in mint (see `TxBody::Btc4PegIn`).
    pub fn btc4_peg_in(
        &mut self,
        raw_tx_hex: &str,
        btc_height: u64,
        merkle_path: &[String],
        merkle_index: u32,
    ) -> Result<u64, String> {
        let h = self.tip_height.saturating_add(1);
        if !self.bridge_at(h) {
            return Err("btc4 peg-in: bridge not active at this height".into());
        }
        let rail = self.bridge.rail(crate::bridge::RAIL_BTC4)?;
        let ptx = self.rail_included_tx(rail, raw_tx_hex, btc_height, merkle_path, merkle_index)?;
        let txid = ptx.txid_display.to_ascii_lowercase();
        if rail.spent_deposits.contains(&txid) {
            return Err("btc4 peg-in: already minted".into());
        }
        let active: Vec<String> = self
            .bridge
            .operators
            .operators
            .values()
            .filter(|r| matches!(r.status, crate::operator_registry::OperatorStatus::Active))
            .map(|r| r.btc_xonly_hex.clone())
            .collect();
        if active.is_empty() {
            return Err("btc4 peg-in: no active operators".into());
        }
        let mut depositor: Option<String> = None;
        let mut has_graph = false;
        for x in &active {
            let b = self
                .bridge
                .operators
                .graph_binding(&txid, x)
                .ok_or("btc4 peg-in: not every active operator bound a graph for this deposit")?;
            has_graph |= !b.cosign;
            if b.depositor_account.is_empty() {
                return Err("btc4 peg-in: binding names no depositor account".into());
            }
            match &depositor {
                None => depositor = Some(b.depositor_account.clone()),
                Some(d) if d != &b.depositor_account => {
                    return Err("btc4 peg-in: operators bound different depositor accounts".into())
                }
                _ => {}
            }
        }
        if !has_graph {
            return Err("btc4 peg-in: only co-signer bindings, no operator graph".into());
        }
        let to = depositor.expect("non-empty active set");
        let amount = ptx
            .outputs
            .first()
            .map(|o| o.0)
            .filter(|v| *v > 0)
            .ok_or("btc4 peg-in: confirm tx has no deposit output")?;
        let r = self.bridge.rail_mut(crate::bridge::RAIL_BTC4)?;
        r.spent_deposits.insert(txid);
        r.total_minted = r.total_minted.saturating_add(amount);
        self.defi.credit_asset(&to, crate::bridge::RAIL_BTC4, amount);
        Ok(amount)
    }

    /// BRIDGE: burn `BTC4` and open a BitVM2 claim an operator fronts on testnet4.
    pub fn btc4_withdraw(&mut self, from: &str, amount: u64, external_to: &str) -> Result<String, String> {
        if !self.bridge_at(self.tip_height.saturating_add(1)) {
            return Err("btc4 withdraw: bridge not active at this height".into());
        }
        if amount == 0 {
            return Err("btc4 withdraw: zero amount".into());
        }
        self.bridge.rail(crate::bridge::RAIL_BTC4)?.bitvm2_claim_tree_check()?;
        self.defi.debit_asset(from, crate::bridge::RAIL_BTC4, amount)?;
        let tip = self.tip_height;
        let r = self.bridge.rail_mut(crate::bridge::RAIL_BTC4)?;
        let note = r.withdraw(from, amount, external_to, tip)?;
        r.open_bitvm2_withdraw(&note, from, external_to, amount, tip)?;
        Ok(note)
    }

    /// Epoch settle: pay `bucket` through the registry into `claimable`,
    /// return finished unbonds. Returns the FPL distributed from the bucket
    /// (the caller refunds `bucket - distributed` to treasury). Inert (returns
    /// 0, touches nothing) before the bridge height.
    pub(crate) fn settle_operators(&mut self, epoch: u64, bucket: u64) -> u64 {
        if !self.bridge_at(self.tip_height.saturating_add(1)) {
            return 0;
        }
        let p = self.operator_params();
        let (pays, _rest) = self.bridge.operators.settle_epoch(&p, epoch, bucket);
        let mut dist = 0u64;
        for (a, v) in pays {
            *self.claimable.entry(a).or_insert(0) += v;
            dist = dist.saturating_add(v);
        }
        for (a, bond) in self.bridge.operators.release_unbonded(epoch) {
            if bond > 0 {
                self.credit_native(&a, bond);
            }
        }
        dist.min(bucket)
    }
}
