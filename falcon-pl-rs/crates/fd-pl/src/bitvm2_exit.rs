// Copyright (c) 2025-2026 BEARTEC. All rights reserved. See LICENSE.
//! BitVM2 BTC exit mode (Phase D) — operator-fronting + Groth16 Claim.

use serde::{Deserialize, Serialize};

pub use fd_pl_bitvm2::protocol::claim_id as bitvm2_claim_id;
pub use fd_pl_bitvm2::withdraw_ops::{
    checkpoint_header_hash, header_hash_placeholder, mimc_leaf_hex, mimc_root_hex_from_leaves,
    pegout_txid_bytes, prove_withdraw_attest, prove_withdraw_attest_with_keys,
    verify_stored_withdraw_attest_vk_bytes, verify_withdraw_attest, verify_withdraw_attest_vk_bytes,
};

/// M1: compressed Groth16 verifying key for `FplWithdrawValid` (arkworks compressed,
/// = `falcon-pl-bitvm2-setup vk-import`). Empty = no key: `Bitvm2AttestV2` is refused.
///
/// TESTNET 2300 key from the logged single-operator setup of 2026-10-19 (Hermez 2^18 phase 1,
/// Falcon phase-2 contributions with discarded entropy, beacon = Bitcoin mainnet block 972174):
/// transcript + re-verify steps in `docs/bridge/ceremony/testnet-vk-2026-10-19/`. Used only from
/// the M1 height (= `TESTNET_2300_BRIDGE_FROM_HEIGHT`, u64::MAX here). NOT a mainnet key: mainnet
/// needs the multi-party ceremony.
pub const BITVM2_WITHDRAW_VK_HEX: &str = "e2f26dbea299f5223b646cb1fb33eadb059d9407559d7441dfd902e3a79a4d2dabb73dc17fbc13021e2471e0c08bd67d8401f52b73d6d07483794cad4778180e0c06f33bbc4c79a9cadef253a68084d382f17788f885c9afd176f7cb2f036789edf692d95cbdde46ddda5ef7d422436779445c5e66006a42761e1f12efde0018c212f3aeb785e49712e7a9353349aaf1255dfb31b7bf60723a480d9293938e19d8a07c9bd35509b258e6b0f6562ae91aa87230e4d419edfbbc01b00ae47d20197fbd7aa7961df9f5d2f0c68afafed4324a431de85ebe9fb01f1062ac064408a50e00000000000000dea7219de876f32f15667226d442235c689972c010f9ba1ec405627e5e68620c8dcd972539b413f5028a40d8c9769dd2c36900b36bc85e137e54833781ca1982c0ab34f8c6f9fd0ccaf32c61f61c5439226be9ee47f7e7461053b9a520a59f89d137fb07c2e8a31629c7aef9839c3a23bcc5fb21f6ed1308c4ce6e8ad880921ab4e9410f681ce0e644b587fd3c31e0326b6b95fb95c9d293aa277b17c867b02f562cb36f37067d95dd2cfc6a13187cb9456316241209d6e93c4fd93221421585d9230198a2bfa3e8fcaf189a498674f2dc530ff0ee5852a9f03ac90375be469a7cc0c624ccfbf9da9e190652fedfa455a459ab5c85ba019249a4d5fcacb8182bf4777febd4350821e42b4575a9f6922244efc1a29878f239d93068890ea78b2bfae57713df826861950c3979ebba6425207bc33fb60ddba77345471612309e18efffc30d3f4466e25d4e2b6fe2e7aac74254b292f9ef5b1d5dc107c9a013b90b9b408013bb723a0bd78bc36411cda46e9baad7c99a2746024b24586c4a94478cc4d43f2a91c050e5c7eb3839e77016ace6765477afea3b01b89318e78e445c9effcc90ed39ea0203fb5f43d1633229d05f498681a3f82bb2054cbff6e5372396";
/// sha256 of the decoded `BITVM2_WITHDRAW_VK_HEX` bytes (published with the transcript).
pub const BITVM2_WITHDRAW_VK_SHA256: &str = "4a1cabbccc33907e7bb20aa9a4ca3681920daab53a3a0e781e80ff403d5b4763";

/// M1 withdraw VK for `network_id`: the testnet key above on the public
/// testnet (BTC testnet4 rail, network 2300) only; empty everywhere else, so
/// `Bitvm2AttestV2` is refused off testnet4 (mainnet needs the multi-party key).
pub fn withdraw_vk_for_network(network_id: u32) -> Vec<u8> {
    if network_id == crate::NETWORK_ID_PUBLIC_TESTNET_2300 {
        hex::decode(BITVM2_WITHDRAW_VK_HEX).unwrap_or_default()
    } else {
        Vec::new()
    }
}

/// Every this many FPL ledgers (from M1 activation) the BTC rail records the
/// parent ledger hash as an attestation checkpoint.
pub const BITVM2_CHECKPOINT_INTERVAL: u64 = 64;
/// Checkpoints kept in rail state (~65k ledgers at the interval above).
pub const BITVM2_CHECKPOINT_KEEP: usize = 1024;
/// A checkpoint must be at least this many ledgers below the applying height.
pub const BITVM2_CHECKPOINT_FINALITY: u64 = 2;
/// Bitcoin confirmations a peg-out needs before it can be attested.
pub const BITVM2_PEGOUT_MIN_CONFS: u64 = 6;

fn is_zero(v: &u64) -> bool {
    *v == 0
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum BtcExitMode {
    #[default]
    Watch,
    Bitvm2,
}

impl BtcExitMode {
    pub fn parse(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "bitvm2" | "bitvm" => Self::Bitvm2,
            _ => Self::Watch,
        }
    }

    pub fn from_env() -> Self {
        std::env::var("BTC_EXIT_MODE")
            .map(|v| Self::parse(&v))
            .unwrap_or(Self::Watch)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Watch => "watch",
            Self::Bitvm2 => "bitvm2",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Bitvm2Status {
    AwaitingPegout,
    PegoutPosted,
    ClaimPosted,
    Challenged,
    PaidOptimistic,
    Disproved,
    /// BRIDGE: no peg-out attested within the refund window
    /// (`bridge_operators::BITVM2_PEGOUT_REFUND_LEDGERS`); burned FBTC credited back.
    Refunded,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Bitvm2Claim {
    pub note_id: String,
    pub from: String,
    pub dest: String,
    pub amount: u64,
    pub open_height: u64,
    pub status: Bitvm2Status,
    pub mimc_leaf_hex: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub pegout_txid_hex: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub claim_txid_hex: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub claim_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub statement_digest_hex: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub proof_hex: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub public_hex: Vec<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub operator: String,
    /// M1: FPL checkpoint height the attestation proof is bound to (0 = pre-M1).
    #[serde(default, skip_serializing_if = "is_zero")]
    pub checkpoint_height: u64,
    /// M1: Bitcoin height of the block that includes the peg-out (0 = pre-M1).
    #[serde(default, skip_serializing_if = "is_zero")]
    pub pegout_btc_height: u64,
    /// BRIDGE: FPL ledger height the M1 attestation applied at (0 = pre-M1);
    /// starts the payout finality window (`PaidOptimistic`).
    #[serde(default, skip_serializing_if = "is_zero")]
    pub attest_height: u64,
}

pub fn append_mimc_leaf(leaves: &mut Vec<String>, note_id: &str, dest_h160: &[u8; 20], amount: u64) {
    leaves.push(mimc_leaf_hex(note_id, dest_h160, amount));
}

pub fn mimc_root_from_leaves(leaves: &[String]) -> Result<String, String> {
    mimc_root_hex_from_leaves(leaves)
}

pub fn prove_withdraw(
    note_id: &str,
    dest_h160: &[u8; 20],
    amount: u64,
    height: u64,
    header_hash: &[u8; 32],
    pegout_txid: &[u8; 32],
    mimc_leaves: &[String],
    operator: &str,
) -> Result<(String, Vec<String>, String, String), String> {
    prove_withdraw_attest(
        note_id,
        dest_h160,
        amount,
        height,
        header_hash,
        pegout_txid,
        mimc_leaves,
        operator,
    )
}

pub fn verify_attest(
    note_id: &str,
    dest_h160: &[u8; 20],
    amount: u64,
    height: u64,
    header_hash: &[u8; 32],
    pegout_txid: &[u8; 32],
    mimc_leaves: &[String],
    proof_hex: &str,
    public_hex: &[String],
    statement_digest_hex: &str,
) -> Result<(), String> {
    verify_withdraw_attest(
        note_id,
        dest_h160,
        amount,
        height,
        header_hash,
        pegout_txid,
        mimc_leaves,
        proof_hex,
        public_hex,
        statement_digest_hex,
    )
}
