// Copyright (c) 2025-2026 BEARTEC. All rights reserved. See LICENSE.
//! Pluggable signing: HMAC-dev (fast) or Falcon-512 (PQ).

use hmac::{Hmac, Mac};
use pqcrypto_falcon::falcon512;
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _, SecretKey as _};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
#[cfg(test)]
use sha2::Digest;
use std::collections::BTreeMap;
use std::path::Path;
use thiserror::Error;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum CryptoScheme {
    #[default]
    HmacDev,
    Falcon512,
}

impl CryptoScheme {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "hmac" | "hmac-dev" | "hmac-sha256-dev" | "dev" => Some(Self::HmacDev),
            "falcon" | "falcon-512" | "falcon512" | "pq" => Some(Self::Falcon512),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::HmacDev => "hmac-sha256-dev",
            Self::Falcon512 => "falcon-512",
        }
    }
}

#[derive(Debug, Error)]
pub enum CryptoErr {
    #[error("no secret for {0}")]
    NoSecret(String),
    #[error("bad key: {0}")]
    BadKey(String),
    #[error("io: {0}")]
    Io(String),
    #[error("sign failed: {0}")]
    Sign(String),
}

/// v2.11.6 lean body: prefix of a signature carried as canonical, padded,
/// standard-alphabet base64 instead of hex (~33% fewer bytes per Falcon sig).
/// Hex never contains ':', so the two forms cannot be confused.
pub const LEAN_SIG_PREFIX: &str = "b64:";

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard base64 with `=` padding.
pub fn b64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for c in data.chunks(3) {
        let n = (c[0] as u32) << 16
            | (*c.get(1).unwrap_or(&0) as u32) << 8
            | *c.get(2).unwrap_or(&0) as u32;
        out.push(B64[(n >> 18) as usize & 63] as char);
        out.push(B64[(n >> 12) as usize & 63] as char);
        out.push(if c.len() > 1 { B64[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if c.len() > 2 { B64[n as usize & 63] as char } else { '=' });
    }
    out
}

/// Strict decoder: padded, standard alphabet, and **canonical** (re-encoding
/// gives the same text, so one signature has exactly one lean spelling).
pub fn b64_decode(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    if b.is_empty() || b.len() % 4 != 0 {
        return None;
    }
    let val = |c: u8| -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some((c - b'A') as u32),
            b'a'..=b'z' => Some((c - b'a' + 26) as u32),
            b'0'..=b'9' => Some((c - b'0' + 52) as u32),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    };
    let mut out = Vec::with_capacity(b.len() / 4 * 3);
    let last = b.len() / 4 - 1;
    for (i, q) in b.chunks(4).enumerate() {
        let pad = q.iter().rev().take_while(|&&c| c == b'=').count();
        if pad > 2 || (pad > 0 && i != last) {
            return None;
        }
        let mut n = 0u32;
        for &c in &q[..4 - pad] {
            n = (n << 6) | val(c)?;
        }
        n <<= 6 * pad as u32;
        out.push((n >> 16) as u8);
        if pad < 2 {
            out.push((n >> 8) as u8);
        }
        if pad < 1 {
            out.push(n as u8);
        }
    }
    if b64_encode(&out) != s {
        return None;
    }
    Some(out)
}

/// True if `sig` uses the lean (`b64:`) spelling.
pub fn is_lean_sig(sig: &str) -> bool {
    sig.starts_with(LEAN_SIG_PREFIX)
}

/// Signature bytes from either spelling: legacy hex or lean `b64:`.
pub fn sig_bytes(sig: &str) -> Option<Vec<u8>> {
    match sig.strip_prefix(LEAN_SIG_PREFIX) {
        Some(b) => b64_decode(b),
        None => hex::decode(sig).ok(),
    }
}

/// Canonical lowercase hex of a signature in either spelling. Hashes and
/// roots are always taken over this form, so the wire spelling never
/// changes consensus values.
pub fn sig_to_hex(sig: &str) -> Option<String> {
    if !is_lean_sig(sig) {
        return Some(sig.to_ascii_lowercase()).filter(|_| hex::decode(sig).is_ok());
    }
    sig_bytes(sig).map(hex::encode)
}

/// Lean (`b64:`) spelling of a signature in either spelling.
pub fn sig_to_lean(sig: &str) -> Option<String> {
    sig_bytes(sig).map(|b| format!("{LEAN_SIG_PREFIX}{}", b64_encode(&b)))
}

/// True when `s` is non-empty, even-length, lowercase hex: the only spelling
/// that survives a bytes round trip unchanged (`hex::encode` is lowercase).
pub fn is_canonical_hex(s: &str) -> bool {
    !s.is_empty() && s.len() % 2 == 0 && s.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
}

/// Hello capability: this binary sends and accepts `b64:` tx signatures and
/// carried tx public keys in tx gossip (`submit_tx`, `txs_batch`,
/// `txs_by_ids`). Negotiated per session; not a consensus rule. A peer that
/// does not advertise it only ever gets hex.
pub const CAP_LEAN_TX_GOSSIP_V1: &str = "lean-tx-gossip-v1";

/// Local switch for lean tx gossip. On by default; `FPL_LEAN_TX_GOSSIP=0`
/// (or `false`/`off`) stops advertising the capability and sending `b64:`
/// sigs. Receiving `b64:` gossip sigs is always accepted (strict decode).
pub fn lean_tx_gossip_enabled() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| {
        !matches!(
            std::env::var("FPL_LEAN_TX_GOSSIP").ok().as_deref().map(str::trim),
            Some("0") | Some("false") | Some("off") | Some("no")
        )
    })
}

/// True if a Hello capability list advertises [`CAP_LEAN_TX_GOSSIP_V1`].
pub fn peer_has_lean_tx_gossip(capabilities: &[String]) -> bool {
    capabilities.iter().any(|c| c == CAP_LEAN_TX_GOSSIP_V1)
}

/// Gossip spelling of a pooled tx signature (or carried public key) for a
/// lean-capable peer.
/// Only canonical lowercase hex is rewritten, so the receiver's
/// [`gossip_sig_to_hex`] gives back the exact same string. Anything else
/// (empty, upper-case, already `b64:`) is sent unchanged.
pub fn gossip_lean_sig(sig: &str) -> Option<String> {
    if !is_canonical_hex(sig) {
        return None;
    }
    hex::decode(sig).ok().map(|b| format!("{LEAN_SIG_PREFIX}{}", b64_encode(&b)))
}

/// Receiver side of tx gossip: a `b64:` sig must be canonical padded base64
/// and becomes lowercase hex; any other spelling is returned unchanged (the
/// normal admission checks judge it as before). `Err` = drop the tx.
pub fn gossip_sig_to_hex(sig: &str) -> Result<std::borrow::Cow<'_, str>, String> {
    match sig.strip_prefix(LEAN_SIG_PREFIX) {
        Some(b) => b64_decode(b)
            .map(|v| std::borrow::Cow::Owned(hex::encode(v)))
            .ok_or_else(|| "non-canonical lean tx signature in gossip".to_string()),
        None => Ok(std::borrow::Cow::Borrowed(sig)),
    }
}

/// Lossless compact form of a hex field held in RAM (mempool). Canonical
/// lowercase hex is kept as raw bytes (half the size); any other text is
/// kept verbatim, so [`CompactHex::as_text`] always returns the input.
#[derive(Clone, PartialEq, Eq)]
pub enum CompactHex {
    Bytes(Box<[u8]>),
    Text(Box<str>),
}

impl CompactHex {
    pub fn new(s: &str) -> Self {
        if is_canonical_hex(s) {
            if let Ok(b) = hex::decode(s) {
                return CompactHex::Bytes(b.into_boxed_slice());
            }
        }
        CompactHex::Text(s.into())
    }

    /// The original text (hex is re-encoded on demand).
    pub fn as_text(&self) -> std::borrow::Cow<'_, str> {
        match self {
            CompactHex::Bytes(b) => std::borrow::Cow::Owned(hex::encode(b)),
            CompactHex::Text(t) => std::borrow::Cow::Borrowed(t),
        }
    }

    /// Raw bytes when the field was canonical hex.
    pub fn bytes(&self) -> Option<&[u8]> {
        match self {
            CompactHex::Bytes(b) => Some(b),
            CompactHex::Text(_) => None,
        }
    }

    pub fn is_empty(&self) -> bool {
        match self {
            CompactHex::Bytes(b) => b.is_empty(),
            CompactHex::Text(t) => t.is_empty(),
        }
    }

    /// Equal to `s` as text, without allocating for the bytes form.
    pub fn eq_text(&self, s: &str) -> bool {
        match self {
            CompactHex::Bytes(b) => {
                s.len() == b.len() * 2 && hex::decode(s).is_ok_and(|v| v[..] == b[..]) && is_canonical_hex(s)
            }
            CompactHex::Text(t) => &**t == s,
        }
    }

    /// Heap bytes held by this field.
    pub fn heap_bytes(&self) -> usize {
        match self {
            CompactHex::Bytes(b) => b.len(),
            CompactHex::Text(t) => t.len(),
        }
    }
}

impl std::fmt::Debug for CompactHex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.as_text())
    }
}

/// SHA-256 hex. v2.9.59: computed with `ring` (runtime-detected SHA-NI /
/// AVX2 / SSSE3 code; same digest as `sha2`, ~1.8x faster on CPUs without
/// SHA-NI such as the Skylake seats).
pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(sha256_raw(data))
}

/// Raw SHA-256 (32 bytes). Outer v4 ledger hash is this, not hex-then-hash.
pub fn sha256_raw(data: &[u8]) -> [u8; 32] {
    let d = ring::digest::digest(&ring::digest::SHA256, data);
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_ref());
    out
}

/// Incremental SHA-256 (ring), for multi-part hashes such as the spliced
/// state root. Same digest as `sha2::Sha256` over the concatenation.
#[derive(Clone)]
pub struct FastSha256(ring::digest::Context);

impl Default for FastSha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl FastSha256 {
    pub fn new() -> Self {
        Self(ring::digest::Context::new(&ring::digest::SHA256))
    }
    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }
    pub fn finalize(self) -> [u8; 32] {
        let d = self.0.finish();
        let mut out = [0u8; 32];
        out.copy_from_slice(d.as_ref());
        out
    }
}

pub(crate) fn hex_eq(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

// ---------------------------------------------------------------------------
// Key material
// ---------------------------------------------------------------------------

pub enum SecretKey {
    Hmac(String),
    Falcon(falcon512::SecretKey),
}

pub enum PublicKey {
    Hmac(String),
    Falcon(falcon512::PublicKey),
}

impl PublicKey {
    pub fn to_hex(&self) -> String {
        match self {
            Self::Hmac(s) => s.clone(),
            Self::Falcon(pk) => hex::encode(pk.as_bytes()),
        }
    }

    pub fn from_hex(scheme: CryptoScheme, hex_pk: &str) -> Result<Self, CryptoErr> {
        match scheme {
            CryptoScheme::HmacDev => Ok(Self::Hmac(hex_pk.to_string())),
            CryptoScheme::Falcon512 => {
                let bytes = hex::decode(hex_pk).map_err(|e| CryptoErr::BadKey(e.to_string()))?;
                let pk = falcon512::PublicKey::from_bytes(&bytes)
                    .map_err(|e| CryptoErr::BadKey(format!("{e:?}")))?;
                Ok(Self::Falcon(pk))
            }
        }
    }
}

pub struct KeyRing {
    pub scheme: CryptoScheme,
    secrets: BTreeMap<String, SecretKey>,
    publics: BTreeMap<String, PublicKey>,
}

impl Default for KeyRing {
    fn default() -> Self {
        Self::new(CryptoScheme::HmacDev)
    }
}

impl std::fmt::Debug for KeyRing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyRing")
            .field("scheme", &self.scheme)
            .field("secrets", &self.secrets.len())
            .field("publics", &self.publics.len())
            .finish()
    }
}

impl Clone for KeyRing {
    fn clone(&self) -> Self {
        // Re-export via hex roundtrip so Falcon keys are cloneable.
        let mut out = Self::new(self.scheme);
        for (id, pk) in self.export_publics() {
            let _ = out.insert_public(&id, &pk);
        }
        for (id, sk) in &self.secrets {
            match sk {
                SecretKey::Hmac(s) => {
                    out.secrets.insert(id.clone(), SecretKey::Hmac(s.clone()));
                }
                SecretKey::Falcon(sk) => {
                    let bytes = sk.as_bytes().to_vec();
                    if let Ok(sk2) = falcon512::SecretKey::from_bytes(&bytes) {
                        out.secrets.insert(id.clone(), SecretKey::Falcon(sk2));
                    }
                }
            }
        }
        out
    }
}

impl KeyRing {
    pub fn new(scheme: CryptoScheme) -> Self {
        Self {
            scheme,
            secrets: BTreeMap::new(),
            publics: BTreeMap::new(),
        }
    }

    pub fn generate_id(&mut self, id: &str) {
        match self.scheme {
            CryptoScheme::HmacDev => {
                let sk = format!("pl-secret:{id}");
                let pk = format!("pl-pub:{}", &sha256_hex(id.as_bytes())[..16]);
                self.secrets.insert(id.to_string(), SecretKey::Hmac(sk));
                self.publics.insert(id.to_string(), PublicKey::Hmac(pk));
            }
            CryptoScheme::Falcon512 => {
                let (pk, sk) = falcon512::keypair();
                self.secrets
                    .insert(id.to_string(), SecretKey::Falcon(sk));
                self.publics
                    .insert(id.to_string(), PublicKey::Falcon(pk));
            }
        }
    }

    pub fn generate_many(&mut self, ids: impl IntoIterator<Item = impl AsRef<str>>) {
        for id in ids {
            self.generate_id(id.as_ref());
        }
    }

    /// Seat payout: a new one-entry signing ring holding `from`'s key pair
    /// under `to` (the seat key under its `<id>#seat` sender). `None` when
    /// `from` has no secret here.
    pub fn single_as(&self, from: &str, to: &str) -> Option<KeyRing> {
        let sk = match self.secrets.get(from)? {
            SecretKey::Hmac(s) => SecretKey::Hmac(s.clone()),
            SecretKey::Falcon(sk) => {
                SecretKey::Falcon(falcon512::SecretKey::from_bytes(sk.as_bytes()).ok()?)
            }
        };
        let pk = PublicKey::from_hex(self.scheme, &self.public_hex(from)?).ok()?;
        let mut out = KeyRing::new(self.scheme);
        out.secrets.insert(to.to_string(), sk);
        out.publics.insert(to.to_string(), pk);
        Some(out)
    }

    pub fn public_hex(&self, id: &str) -> Option<String> {
        self.publics.get(id).map(|p| p.to_hex())
    }

    /// Insert a public key for `id`.
    ///
    /// **Never overwrites** a different key for the same id (v2.7 / checklist A1).
    /// Same-hex re-insert is a no-op. Genesis / test harnesses use this after
    /// `generate_id`; wire paths must not call this for an unknown attacker key.
    pub fn insert_public(&mut self, id: &str, hex_pk: &str) -> Result<(), CryptoErr> {
        let pk = PublicKey::from_hex(self.scheme, hex_pk)?;
        if let Some(known) = self.publics.get(id) {
            if !hex_eq(&known.to_hex(), hex_pk) {
                return Err(CryptoErr::BadKey(format!(
                    "refusing key overwrite for {id}"
                )));
            }
            return Ok(());
        }
        self.publics.insert(id.to_string(), pk);
        Ok(())
    }

    /// v2.9.62 A6: set `id`'s key from the chain (a BondV2 with a verified
    /// proof of possession). This is the one path allowed to replace a
    /// first-seen (e.g. Hello-learned) key: the root is authoritative.
    pub fn set_public_from_chain(&mut self, id: &str, hex_pk: &str) -> Result<(), CryptoErr> {
        let pk = PublicKey::from_hex(self.scheme, hex_pk)?;
        self.publics.insert(id.to_string(), pk);
        Ok(())
    }

    /// Merkle batches check the key carried on the tx (or the key already
    /// stored for that account). The seat ring is filled on apply, so a
    /// first payment must verify before `id` is in the ring. A ring entry
    /// that disagrees with the carried key is still a mismatch.
    pub fn verify_carried_key(
        &self,
        id: &str,
        public_key_hex: &str,
        message: &str,
        sig_hex: &str,
    ) -> Result<(), String> {
        if let Some(known) = self.public_hex(id) {
            if !hex_eq(&known, public_key_hex) {
                return Err("bad tx crypto: key mismatch".into());
            }
        }
        if self.verify_pop(id, public_key_hex, message, sig_hex) {
            Ok(())
        } else {
            Err("bad tx crypto: bad signature".into())
        }
    }

    /// 2.9.79 (seat/account split): from the Fix B height an account tx is
    /// checked against the account's **on-chain** key when it has one, never
    /// the node ring. The ring also holds seat (consensus) keys under the same
    /// id, so a seat named like an account (e.g. `nodesafe`) would otherwise
    /// shadow the wallet key. Seat votes/proposals keep using the ring.
    pub fn verify_account_sig(
        &self,
        id: &str,
        carried_hex: &str,
        onchain_hex: Option<&str>,
        message: &str,
        sig_hex: &str,
    ) -> Result<(), String> {
        let Some(onchain) = onchain_hex else {
            return self.verify_carried_key(id, carried_hex, message, sig_hex);
        };
        if !carried_hex.is_empty() && !hex_eq(onchain, carried_hex) {
            return Err("sender key does not match account".into());
        }
        if self.verify_pop(id, onchain, message, sig_hex) {
            Ok(())
        } else {
            Err("bad tx crypto: bad signature".into())
        }
    }

    /// v2.9.62 A6: verify a proof of possession for `id` under `public_key_hex`
    /// (not the ring's stored key).
    pub fn verify_pop(&self, id: &str, public_key_hex: &str, message: &str, sig_hex: &str) -> bool {
        match self.scheme {
            CryptoScheme::HmacDev => {
                let expect_pk = format!("pl-pub:{}", &sha256_hex(id.as_bytes())[..16]);
                hex_eq(&expect_pk, public_key_hex) && Self::verify_hmac_id(id, message, sig_hex)
            }
            CryptoScheme::Falcon512 => match PublicKey::from_hex(self.scheme, public_key_hex) {
                Ok(pk) => Self::verify_with_public(&pk, message, sig_hex),
                Err(_) => false,
            },
        }
    }

    /// True if this ring already has a public key for `id`.
    pub fn has_public(&self, id: &str) -> bool {
        self.publics.contains_key(id)
    }

    pub fn sign(&self, id: &str, message: &str) -> Result<String, CryptoErr> {
        let sk = self
            .secrets
            .get(id)
            .ok_or_else(|| CryptoErr::NoSecret(id.into()))?;
        match sk {
            SecretKey::Hmac(secret) => {
                let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
                    .map_err(|e| CryptoErr::Sign(e.to_string()))?;
                mac.update(message.as_bytes());
                Ok(hex::encode(mac.finalize().into_bytes()))
            }
            SecretKey::Falcon(sk) => {
                let sig = falcon512::detached_sign(message.as_bytes(), sk);
                Ok(hex::encode(sig.as_bytes()))
            }
        }
    }

    pub fn verify(&self, id: &str, message: &str, sig_hex: &str) -> bool {
        // Prefer embedded-style: use known public if present
        let Some(pk) = self.publics.get(id) else {
            return false;
        };
        Self::verify_with_public(pk, message, sig_hex)
    }

    pub fn verify_with_public(pk: &PublicKey, message: &str, sig_hex: &str) -> bool {
        match pk {
            PublicKey::Hmac(pk_s) => {
                // HMAC-dev: secret is deterministic from id only when pk matches demo scheme;
                // for demo we re-derive secret from reverse is not possible; store that
                // hmac verify needs secret. For Hmac we check by re-signing if we have secret,
                // else parse pk as containing account link "pl-pub:..." and use demo secret map.
                // Simpler: HMAC mode always uses secret = pl-secret:{id} and pk is derived;
                // verify path for embedded pk uses sign equality with derived secret from id
                // handled at call site for txs. Here for packer: id is known.
                let _ = (pk_s, message, sig_hex);
                false // use verify_hmac_id
            }
            PublicKey::Falcon(pk) => {
                let Ok(sig_bytes) = hex::decode(sig_hex) else {
                    return false;
                };
                let Ok(sig) = falcon512::DetachedSignature::from_bytes(&sig_bytes) else {
                    return false;
                };
                falcon512::verify_detached_signature(&sig, message.as_bytes(), pk).is_ok()
            }
        }
    }

    pub fn verify_hmac_id(id: &str, message: &str, sig_hex: &str) -> bool {
        let secret = format!("pl-secret:{id}");
        let mut mac = match HmacSha256::new_from_slice(secret.as_bytes()) {
            Ok(m) => m,
            Err(_) => return false,
        };
        mac.update(message.as_bytes());
        hex::encode(mac.finalize().into_bytes()) == sig_hex
    }

    pub fn verify_message(
        &self,
        scheme: CryptoScheme,
        id: &str,
        public_key_hex: &str,
        message: &str,
        sig_hex: &str,
    ) -> Result<(), String> {
        match scheme {
            CryptoScheme::HmacDev => {
                let expect_pk = format!("pl-pub:{}", &sha256_hex(id.as_bytes())[..16]);
                if !hex_eq(&expect_pk, public_key_hex) {
                    return Err("bad tx crypto: key mismatch".into());
                }
                if Self::verify_hmac_id(id, message, sig_hex) {
                    Ok(())
                } else {
                    Err("bad tx crypto: bad signature".into())
                }
            }
            CryptoScheme::Falcon512 => {
                // Registry-only: unknown id cannot introduce a key via the wire
                // (checklist A1 / REVIEW #1). First-seen keys come from genesis
                // keys-dir, Bond, or an enroll tx (Pay / name / vault).
                let Some(known) = self.publics.get(id) else {
                    return Err("bad tx crypto: unknown key".into());
                };
                if !hex_eq(&known.to_hex(), public_key_hex) {
                    return Err("bad tx crypto: key mismatch".into());
                }
                if Self::verify_with_public(known, message, sig_hex) {
                    Ok(())
                } else {
                    Err("bad tx crypto: bad signature".into())
                }
            }
        }
    }

    pub fn export_publics(&self) -> BTreeMap<String, String> {
        self.publics
            .iter()
            .map(|(k, v)| (k.clone(), v.to_hex()))
            .collect()
    }

    pub fn save_dir(&self, dir: impl AsRef<Path>) -> Result<(), CryptoErr> {
        let d = dir.as_ref();
        std::fs::create_dir_all(d).map_err(|e| CryptoErr::Io(e.to_string()))?;
        let pubs = self.export_publics();
        let meta = serde_json::json!({
            "scheme": self.scheme.as_str(),
            "publics": pubs,
        });
        std::fs::write(
            d.join("pl_keys.json"),
            serde_json::to_string_pretty(&meta).unwrap() + "\n",
        )
        .map_err(|e| CryptoErr::Io(e.to_string()))?;
        for (id, sk) in &self.secrets {
            let pk = self.publics.get(id).map(|p| p.to_hex()).unwrap_or_default();
            let sk_hex = match sk {
                SecretKey::Hmac(s) => hex::encode(s.as_bytes()),
                SecretKey::Falcon(s) => hex::encode(s.as_bytes()),
            };
            let payload = serde_json::json!({
                "id": id,
                "scheme": self.scheme.as_str(),
                "public_key": pk,
                "secret_key": sk_hex,
            });
            let path = d.join(format!("{id}.json"));
            std::fs::write(&path, serde_json::to_string_pretty(&payload).unwrap() + "\n")
                .map_err(|e| CryptoErr::Io(e.to_string()))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
            }
        }
        Ok(())
    }

    /// Load **all** per-id secret files in `dir` (legacy soak / ctl wallets).
    pub fn load_dir(dir: impl AsRef<Path>) -> Result<Self, CryptoErr> {
        Self::load_dir_filter(dir, None)
    }

    /// Production load: every public from `pl_keys.json`, secrets only for `keep_secrets`.
    pub fn load_dir_slim(
        dir: impl AsRef<Path>,
        keep_secrets: &[&str],
    ) -> Result<Self, CryptoErr> {
        let keep: std::collections::BTreeSet<String> =
            keep_secrets.iter().map(|s| (*s).to_string()).collect();
        Self::load_dir_filter(dir, Some(&keep))
    }

    fn load_dir_filter(
        dir: impl AsRef<Path>,
        keep_secrets: Option<&std::collections::BTreeSet<String>>,
    ) -> Result<Self, CryptoErr> {
        let d = dir.as_ref();
        let meta_text = std::fs::read_to_string(d.join("pl_keys.json"))
            .map_err(|e| CryptoErr::Io(e.to_string()))?;
        let meta: serde_json::Value =
            serde_json::from_str(&meta_text).map_err(|e| CryptoErr::BadKey(e.to_string()))?;
        let scheme = CryptoScheme::parse(meta["scheme"].as_str().unwrap_or("hmac"))
            .ok_or_else(|| CryptoErr::BadKey("scheme".into()))?;
        let mut ring = Self::new(scheme);
        if let Some(pubs) = meta["publics"].as_object() {
            for (id, v) in pubs {
                if let Some(h) = v.as_str() {
                    ring.insert_public(id, h)?;
                }
            }
        }
        if let Some(keep) = keep_secrets {
            for id in keep {
                let path = d.join(format!("{id}.json"));
                if !path.exists() {
                    continue;
                }
                let text = std::fs::read_to_string(&path).map_err(|e| CryptoErr::Io(e.to_string()))?;
                let v: serde_json::Value =
                    serde_json::from_str(&text).map_err(|e| CryptoErr::BadKey(e.to_string()))?;
                if let Some(pk) = v["public_key"].as_str() {
                    let _ = ring.insert_public(id, pk);
                }
                if let Some(sk_hex) = v["secret_key"].as_str() {
                    match scheme {
                        CryptoScheme::HmacDev => {
                            let bytes = hex::decode(sk_hex).map_err(|e| CryptoErr::BadKey(e.to_string()))?;
                            let s = String::from_utf8(bytes)
                                .map_err(|e| CryptoErr::BadKey(e.to_string()))?;
                            ring.secrets.insert(id.clone(), SecretKey::Hmac(s));
                        }
                        CryptoScheme::Falcon512 => {
                            let bytes =
                                hex::decode(sk_hex).map_err(|e| CryptoErr::BadKey(e.to_string()))?;
                            let sk = falcon512::SecretKey::from_bytes(&bytes)
                                .map_err(|e| CryptoErr::BadKey(format!("{e:?}")))?;
                            ring.secrets.insert(id.clone(), SecretKey::Falcon(sk));
                        }
                    }
                }
            }
            return Ok(ring);
        }
        for entry in std::fs::read_dir(d).map_err(|e| CryptoErr::Io(e.to_string()))? {
            let entry = entry.map_err(|e| CryptoErr::Io(e.to_string()))?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if name == "pl_keys.json" || !name.ends_with(".json") {
                continue;
            }
            let text =
                std::fs::read_to_string(entry.path()).map_err(|e| CryptoErr::Io(e.to_string()))?;
            let v: serde_json::Value =
                serde_json::from_str(&text).map_err(|e| CryptoErr::BadKey(e.to_string()))?;
            let id = v["id"].as_str().unwrap_or("").to_string();
            if id.is_empty() {
                continue;
            }
            if let Some(keep) = keep_secrets {
                if !keep.contains(&id) {
                    // Publics already came from pl_keys.json; skip other secrets.
                    continue;
                }
            }
            if let Some(pk) = v["public_key"].as_str() {
                let _ = ring.insert_public(&id, pk);
            }
            if let Some(sk_hex) = v["secret_key"].as_str() {
                match scheme {
                    CryptoScheme::HmacDev => {
                        let bytes = hex::decode(sk_hex).map_err(|e| CryptoErr::BadKey(e.to_string()))?;
                        let s = String::from_utf8(bytes)
                            .map_err(|e| CryptoErr::BadKey(e.to_string()))?;
                        ring.secrets.insert(id, SecretKey::Hmac(s));
                    }
                    CryptoScheme::Falcon512 => {
                        let bytes =
                            hex::decode(sk_hex).map_err(|e| CryptoErr::BadKey(e.to_string()))?;
                        let sk = falcon512::SecretKey::from_bytes(&bytes)
                            .map_err(|e| CryptoErr::BadKey(format!("{e:?}")))?;
                        ring.secrets.insert(id, SecretKey::Falcon(sk));
                    }
                }
            }
        }
        Ok(ring)
    }
}

#[cfg(test)]
mod fast_sha_tests {
    use super::*;

    /// v2.9.59: the ring-backed hashes are byte-identical to `sha2` for every
    /// length class (empty, sub-block, block edges, multi-MB) and for
    /// arbitrary incremental split points.
    #[test]
    fn ring_sha256_matches_sha2_for_all_lengths_and_splits() {
        let mut x: u32 = 0x9e37_79b9;
        let mut data = vec![0u8; 3_000_123];
        for b in data.iter_mut() {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            *b = x as u8;
        }
        let lens = [0usize, 1, 3, 55, 56, 63, 64, 65, 119, 127, 128, 129, 1000, 65_536, 1_048_577, 3_000_123];
        for &n in &lens {
            let d = &data[..n];
            let want: [u8; 32] = Sha256::digest(d).into();
            assert_eq!(sha256_raw(d), want, "len {n}");
            assert_eq!(sha256_hex(d), hex::encode(want), "hex len {n}");
            for cut in [0, n / 3, n / 2, n.saturating_sub(1), n] {
                let mut h = FastSha256::new();
                h.update(&d[..cut]);
                let mid = h.clone();
                h.update(&d[cut..]);
                assert_eq!(h.finalize(), want, "split len {n} at {cut}");
                let pre: [u8; 32] = Sha256::digest(&d[..cut]).into();
                assert_eq!(mid.finalize(), pre, "prefix len {n} at {cut}");
            }
        }
    }
}
