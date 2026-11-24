// Copyright (c) 2025-2026 BEARTEC. All rights reserved. See LICENSE.
//! v2.9.58 "lean node": the ETH execution-header map (2.11.13: generic
//! [`CachedMap`], also used for the rail header chains) with a cached canonical
//! JSON encoding, plus a commitment-root hasher that reuses it.
//!
//! Until v2.9.60 the map was never pruned (~126k headers, ~199 MB of the
//! ~207 MB snapshot on testnet 2300, 2026-10-08). From that release's
//! activation height, `BridgeState::prune_eth_exec_headers` drops headers
//! below a rolling floor ([`ExecHeaderMap::pruned_below`] replaces the map
//! only when a header is removed, and can reuse a prior result). The full
//! commitment root is `sha256(serde_json(accounts, defi, bridge, vals,
//! claimable))`; before 2.9.58 every root (pack, verify, commit, every status
//! request) re-serialized and re-hashed all of it under `node.lock`.
//!
//! Nothing here changes a single output byte:
//! * [`ExecHeaderMap`] serializes exactly like the `BTreeMap` it wraps (and
//!   like the v2.9.56 `Arc<BTreeMap>`), so snapshots, wire bodies and the root
//!   input are unchanged.
//! * [`sha256_hex_split`] produces `sha256(serde_json::to_vec(value))`
//!   byte-for-byte. It serializes the value with the map replaced by a
//!   per-process random placeholder, splices the cached map JSON back in while
//!   hashing, and memoizes `(sha256(prefix), map generation, sha256(suffix))
//!   -> root`, so recomputing the root of an identical state (verify → commit →
//!   status) costs only the small prefix/suffix (~4 MB), not 207 MB.
//! * Anything unexpected (placeholder seen 0 times with a non-empty map, or
//!   more than once) falls back to the plain full serialization.

use std::cell::Cell;
use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

use parking_lot::Mutex;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::eth_exec::EthExecHeader;

static NEXT_GEN: AtomicU64 = AtomicU64::new(1);

fn next_gen() -> u64 {
    NEXT_GEN.fetch_add(1, Ordering::Relaxed)
}

/// Copy-on-write `u64 → V` map with a content generation and a cached
/// canonical JSON encoding (v2.9.58 for ETH exec headers; 2.11.13 also the
/// rail header chains, [`RailHeaderMap`]).
///
/// Clones share the map, its generation id and its JSON cache. The only way
/// to mutate is [`CachedMap::make_mut`], which assigns a fresh generation
/// and drops the cache for this handle; other clones keep theirs. So equal
/// generation ⇒ identical contents.
pub struct CachedMap<V> {
    map: Arc<BTreeMap<u64, V>>,
    gen: u64,
    json: Arc<OnceLock<Arc<Vec<u8>>>>,
    bounds: Arc<OnceLock<(u64, u64)>>,
}

/// ETH execution header map (number → header).
pub type ExecHeaderMap = CachedMap<EthExecHeader>;
/// 2.11.13: a rail's header chain (height → header). Clone = refcount bump.
pub type RailHeaderMap = CachedMap<crate::bridge::RailHeader>;

impl<V> Clone for CachedMap<V> {
    fn clone(&self) -> Self {
        Self {
            map: self.map.clone(),
            gen: self.gen,
            json: self.json.clone(),
            bounds: self.bounds.clone(),
        }
    }
}

impl<V> Default for CachedMap<V> {
    fn default() -> Self {
        Self::new(BTreeMap::new())
    }
}

impl<V: std::fmt::Debug> std::fmt::Debug for CachedMap<V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.map.fmt(f)
    }
}

impl<V> std::ops::Deref for CachedMap<V> {
    type Target = BTreeMap<u64, V>;
    fn deref(&self) -> &Self::Target {
        &self.map
    }
}

impl<V> From<BTreeMap<u64, V>> for CachedMap<V> {
    fn from(m: BTreeMap<u64, V>) -> Self {
        Self::new(m)
    }
}

impl<V: PartialEq> PartialEq for CachedMap<V> {
    fn eq(&self, other: &Self) -> bool {
        self.gen == other.gen || *self.map == *other.map
    }
}

impl<V> CachedMap<V> {
    pub fn new(map: BTreeMap<u64, V>) -> Self {
        Self {
            map: Arc::new(map),
            gen: next_gen(),
            json: Arc::new(OnceLock::new()),
            bounds: Arc::new(OnceLock::new()),
        }
    }

    /// Content generation (equal ⇒ identical contents).
    pub fn generation(&self) -> u64 {
        self.gen
    }

    /// Same underlying allocation (clone was a refcount bump).
    pub fn ptr_eq(a: &Self, b: &Self) -> bool {
        Arc::ptr_eq(&a.map, &b.map)
    }

    /// `compute(map)` once per generation (e.g. the connected exec range,
    /// which walks ~126k keys and is shown in every status).
    pub fn cached_bounds(&self, compute: impl FnOnce(&BTreeMap<u64, V>) -> (u64, u64)) -> (u64, u64) {
        *self.bounds.get_or_init(|| compute(&self.map))
    }

    /// Whether the JSON cache is populated (tests / metrics).
    pub fn json_cached(&self) -> bool {
        self.json.get().is_some()
    }
}

impl<V: Clone> CachedMap<V> {
    /// Mutable access (copies the map if shared). New generation, empty cache.
    pub fn make_mut(&mut self) -> &mut BTreeMap<u64, V> {
        self.gen = next_gen();
        self.json = Arc::new(OnceLock::new());
        self.bounds = Arc::new(OnceLock::new());
        Arc::make_mut(&mut self.map)
    }
}

impl<V: Serialize> CachedMap<V> {
    /// `serde_json::to_vec(&map)`, computed once per generation.
    pub fn canonical_json(&self) -> Arc<Vec<u8>> {
        self.json
            .get_or_init(|| Arc::new(serde_json::to_vec(&*self.map).unwrap_or_default()))
            .clone()
    }
}

impl ExecHeaderMap {
    /// Headers with `number < floor` removed.
    ///
    /// `None` when nothing would be removed (empty map, or every key is
    /// already `>= floor`): the caller keeps this generation. Otherwise the
    /// kept headers, exactly `retain(|n, _| *n >= floor)`. A repeated call
    /// with the same source generation and floor returns a clone of the first
    /// result (same `Arc`, generation and JSON cache). The memo is
    /// process-local and holds the last [`PRUNE_MEMO_CAP`] results; it never
    /// changes contents. Equal generation still means identical contents.
    pub fn pruned_below(&self, floor: u64) -> Option<Self> {
        if self.map.range(..floor).next().is_none() {
            return None;
        }
        let gen = self.gen;
        if let Some(hit) = prune_memo()
            .lock()
            .iter()
            .rev()
            .find(|(g, f, _)| *g == gen && *f == floor)
            .map(|(_, _, m)| m.clone())
        {
            return Some(hit);
        }
        let kept = self
            .map
            .range(floor..)
            .map(|(k, v)| (*k, v.clone()))
            .collect();
        let out = Self::new(kept);
        let mut memo = prune_memo().lock();
        if let Some((_, _, existing)) = memo.iter().rev().find(|(g, f, _)| *g == gen && *f == floor)
        {
            return Some(existing.clone());
        }
        if memo.len() >= PRUNE_MEMO_CAP {
            memo.pop_front();
        }
        memo.push_back((gen, floor, out.clone()));
        Some(out)
    }
}

// Bound of 2: pack/verify/commit/dry-run share one start-of-draft cut, plus one in-block re-prune. Each entry strongly holds a full pruned map (~80 MB after H) and its JSON cache.
const PRUNE_MEMO_CAP: usize = 2;

fn prune_memo() -> &'static Mutex<VecDeque<(u64, u64, ExecHeaderMap)>> {
    static M: OnceLock<Mutex<VecDeque<(u64, u64, ExecHeaderMap)>>> = OnceLock::new();
    M.get_or_init(|| Mutex::new(VecDeque::with_capacity(PRUNE_MEMO_CAP)))
}

/// A map serialized as a placeholder during a split.
trait Captured {
    fn generation(&self) -> u64;
    fn json(&self) -> Arc<Vec<u8>>;
}

impl<V: Serialize> Captured for CachedMap<V> {
    fn generation(&self) -> u64 {
        self.gen
    }
    fn json(&self) -> Arc<Vec<u8>> {
        self.canonical_json()
    }
}

thread_local! {
    static PLACEHOLDER_MODE: Cell<u32> = const { Cell::new(0) };
    /// Maps serialized as the placeholder during the current split (cheap
    /// clones), in serialization order, so the splice always uses the map
    /// that was actually embedded at each position.
    static CAPTURED: std::cell::RefCell<Vec<Box<dyn Captured>>> = std::cell::RefCell::new(Vec::new());
}

/// Random per-process placeholder. Contains control characters, which
/// serde_json always escapes, and 128 random bits, so no string in user data
/// can serialize to the same bytes without guessing them.
fn placeholder() -> &'static str {
    static P: OnceLock<String> = OnceLock::new();
    P.get_or_init(|| format!("\u{1}fpl-exec-map:{:032x}\u{1}", rand::random::<u128>()))
}

/// The placeholder as it appears in serde_json output (quoted, escaped).
fn placeholder_json() -> &'static [u8] {
    static P: OnceLock<Vec<u8>> = OnceLock::new();
    P.get_or_init(|| serde_json::to_vec(placeholder()).expect("placeholder json"))
}

struct PlaceholderGuard;

impl PlaceholderGuard {
    fn enter() -> Self {
        PLACEHOLDER_MODE.with(|m| m.set(m.get() + 1));
        PlaceholderGuard
    }
}

impl Drop for PlaceholderGuard {
    fn drop(&mut self) {
        PLACEHOLDER_MODE.with(|m| m.set(m.get().saturating_sub(1)));
    }
}

impl<V: Serialize + Clone + 'static> Serialize for CachedMap<V> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if PLACEHOLDER_MODE.with(|m| m.get()) > 0 {
            CAPTURED.with(|c| c.borrow_mut().push(Box::new(self.clone())));
            return s.serialize_str(placeholder());
        }
        self.map.serialize(s)
    }
}

impl<'de, V: Deserialize<'de>> Deserialize<'de> for CachedMap<V> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(Self::new(BTreeMap::deserialize(d)?))
    }
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    let first = needle[0];
    let mut i = 0;
    while i + needle.len() <= hay.len() {
        match hay[i..hay.len() - needle.len() + 1].iter().position(|b| *b == first) {
            None => return None,
            Some(off) => {
                let j = i + off;
                if &hay[j..j + needle.len()] == needle {
                    return Some(j);
                }
                i = j + 1;
            }
        }
    }
    None
}

/// Result of serializing with each cached map replaced by the placeholder.
enum Split {
    /// Placeholder absent: `bytes` is already the exact plain serialization
    /// (maps empty and skipped, or not part of the value).
    Plain(Vec<u8>),
    /// One placeholder per captured map, at `ats` (in order).
    Many { bytes: Vec<u8>, ats: Vec<usize>, maps: Vec<Box<dyn Captured>> },
    /// Placeholder count does not match the captured maps — fall back.
    Ambiguous,
}

fn split<T: Serialize + ?Sized>(value: &T) -> Split {
    let outer = PLACEHOLDER_MODE.with(|m| m.get()) > 0;
    if outer {
        // Nested split (not used today): keep it simple and exact.
        return Split::Ambiguous;
    }
    CAPTURED.with(|c| c.borrow_mut().clear());
    let res = {
        let _g = PlaceholderGuard::enter();
        serde_json::to_vec(value)
    };
    let maps = CAPTURED.with(|c| std::mem::take(&mut *c.borrow_mut()));
    let Ok(bytes) = res else {
        return Split::Ambiguous;
    };
    let pat = placeholder_json();
    let mut ats = Vec::new();
    let mut from = 0usize;
    while let Some(off) = find(&bytes[from..], pat) {
        ats.push(from + off);
        from += off + pat.len();
    }
    if ats.is_empty() && maps.is_empty() {
        return Split::Plain(bytes);
    }
    if ats.len() != maps.len() {
        return Split::Ambiguous;
    }
    Split::Many { bytes, ats, maps }
}

/// Non-map segments of a split (between placeholders), in order.
fn segments<'a>(bytes: &'a [u8], ats: &[usize]) -> Vec<&'a [u8]> {
    let pl = placeholder_json().len();
    let mut out = Vec::with_capacity(ats.len() + 1);
    let mut prev = 0usize;
    for &at in ats {
        out.push(&bytes[prev..at]);
        prev = at + pl;
    }
    out.push(&bytes[prev..]);
    out
}

type MemoKey = ([u8; 32], Vec<u64>);

fn memo() -> &'static Mutex<VecDeque<(MemoKey, String)>> {
    static M: OnceLock<Mutex<VecDeque<(MemoKey, String)>>> = OnceLock::new();
    M.get_or_init(|| Mutex::new(VecDeque::new()))
}

const MEMO_CAP: usize = 32;

static FULL_HASHES: AtomicU64 = AtomicU64::new(0);
static MEMO_HITS: AtomicU64 = AtomicU64::new(0);

#[cfg(test)]
thread_local! {
    static TL_FULL: Cell<u64> = const { Cell::new(0) };
}

/// Test-only: full map hashes done on the calling thread (exact even with
/// tests running in parallel).
#[cfg(test)]
pub fn thread_full_hashes() -> u64 {
    TL_FULL.with(|c| c.get())
}

/// (full map hashes, memo hits) since process start.
pub fn root_stats() -> (u64, u64) {
    (
        FULL_HASHES.load(Ordering::Relaxed),
        MEMO_HITS.load(Ordering::Relaxed),
    )
}

/// `sha256(serde_json::to_vec(value))`, byte-for-byte, with every embedded
/// [`CachedMap`] spliced in from its per-generation JSON cache and the root
/// memoized on (sha256 of the non-map segments, map generations).
pub fn sha256_hex_split<T: Serialize + ?Sized>(value: &T) -> String {
    match split(value) {
        Split::Plain(bytes) => crate::crypto::sha256_hex(&bytes),
        Split::Ambiguous => {
            crate::crypto::sha256_hex(&serde_json::to_vec(value).unwrap_or_default())
        }
        Split::Many { bytes, ats, maps } => {
            let segs = segments(&bytes, &ats);
            let mut d = crate::crypto::FastSha256::new();
            for seg in &segs {
                d.update(&(seg.len() as u64).to_be_bytes());
                d.update(seg);
            }
            let seg_digest: [u8; 32] = d.finalize();
            let key = (seg_digest, maps.iter().map(|m| m.generation()).collect::<Vec<_>>());
            if let Some(r) = memo().lock().iter().find(|(k, _)| *k == key).map(|(_, r)| r.clone()) {
                MEMO_HITS.fetch_add(1, Ordering::Relaxed);
                return r;
            }
            let mut h = crate::crypto::FastSha256::new();
            for (i, seg) in segs.iter().enumerate() {
                h.update(seg);
                if let Some(m) = maps.get(i) {
                    h.update(&m.json()[..]);
                }
            }
            let root = hex::encode(h.finalize());
            FULL_HASHES.fetch_add(1, Ordering::Relaxed);
            #[cfg(test)]
            TL_FULL.with(|c| c.set(c.get() + 1));
            let mut m = memo().lock();
            if !m.iter().any(|(k, _)| *k == key) {
                if m.len() >= MEMO_CAP {
                    m.pop_front();
                }
                m.push_back((key, root.clone()));
            }
            root
        }
    }
}

/// `serde_json::to_vec(value)` with every embedded map's cached JSON spliced
/// in (same bytes; saves re-encoding the header maps for every snapshot).
pub fn to_vec_split<T: Serialize + ?Sized>(value: &T) -> serde_json::Result<Vec<u8>> {
    match split(value) {
        Split::Plain(bytes) => Ok(bytes),
        Split::Ambiguous => serde_json::to_vec(value),
        Split::Many { bytes, ats, maps } => {
            let segs = segments(&bytes, &ats);
            let jsons: Vec<Arc<Vec<u8>>> = maps.iter().map(|m| m.json()).collect();
            let total = segs.iter().map(|s| s.len()).sum::<usize>()
                + jsons.iter().map(|j| j.len()).sum::<usize>();
            let mut out = Vec::with_capacity(total);
            for (i, seg) in segs.iter().enumerate() {
                out.extend_from_slice(seg);
                if let Some(j) = jsons.get(i) {
                    out.extend_from_slice(j);
                }
            }
            Ok(out)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hdr(i: u64) -> EthExecHeader {
        EthExecHeader {
            number: i,
            hash: format!("{:064x}", i + 1),
            parent_hash: format!("{:064x}", i),
            receipts_root: "00".repeat(32),
            rlp_hex: "f9".repeat(40),
        }
    }

    #[derive(Serialize)]
    struct Holder<'a> {
        a: &'a str,
        #[serde(skip_serializing_if = "is_empty")]
        m: &'a ExecHeaderMap,
        z: Vec<u64>,
    }
    fn is_empty(m: &&ExecHeaderMap) -> bool {
        m.is_empty()
    }

    #[test]
    fn serializes_exactly_like_btreemap_and_roundtrips() {
        let mut plain = BTreeMap::new();
        for i in 0..50 {
            plain.insert(i, hdr(i));
        }
        let m = ExecHeaderMap::new(plain.clone());
        assert_eq!(serde_json::to_vec(&m).unwrap(), serde_json::to_vec(&plain).unwrap());
        assert_eq!(&m.canonical_json()[..], &serde_json::to_vec(&plain).unwrap()[..]);
        let arc = Arc::new(plain.clone());
        assert_eq!(serde_json::to_vec(&m).unwrap(), serde_json::to_vec(&arc).unwrap());
        let back: ExecHeaderMap = serde_json::from_slice(&serde_json::to_vec(&m).unwrap()).unwrap();
        assert_eq!(*back, plain);
    }

    #[test]
    fn split_hash_and_bytes_equal_plain_across_mutations() {
        let mut m = ExecHeaderMap::default();
        for step in 0..40u64 {
            let h = Holder { a: "x\"y", m: &m, z: vec![step, 7] };
            let want = serde_json::to_vec(&h).unwrap();
            assert_eq!(sha256_hex_split(&h), crate::crypto::sha256_hex(&want), "step {step}");
            // memo hit returns the same
            assert_eq!(sha256_hex_split(&h), crate::crypto::sha256_hex(&want));
            assert_eq!(to_vec_split(&h).unwrap(), want);
            let g = m.generation();
            let keep = m.clone();
            m.make_mut().insert(step, hdr(step));
            if step % 5 == 0 {
                m.make_mut().remove(&(step / 2));
            }
            assert_ne!(m.generation(), g);
            assert_eq!(keep.generation(), g, "clone keeps generation");
            // old clone still hashes to its own (unchanged) content
            let h2 = Holder { a: "x\"y", m: &keep, z: vec![step, 7] };
            assert_eq!(sha256_hex_split(&h2), crate::crypto::sha256_hex(&want));
        }
    }

    #[test]
    fn placeholder_lookalike_in_user_data_falls_back() {
        let mut m = ExecHeaderMap::default();
        m.make_mut().insert(1, hdr(1));
        // Same placeholder text inside a user string → ambiguous → plain path.
        let fake = placeholder().to_string();
        let h = Holder { a: &fake, m: &m, z: vec![] };
        let want = {
            let v = serde_json::to_vec(&h).unwrap();
            crate::crypto::sha256_hex(&v)
        };
        assert_eq!(sha256_hex_split(&h), want);
        assert_eq!(to_vec_split(&h).unwrap(), serde_json::to_vec(&h).unwrap());
        // Empty map is skipped → plain path.
        let e = ExecHeaderMap::default();
        let h = Holder { a: "a", m: &e, z: vec![1] };
        assert_eq!(sha256_hex_split(&h), crate::crypto::sha256_hex(&serde_json::to_vec(&h).unwrap()));
    }

    #[derive(Serialize)]
    struct Two<'a> {
        a: &'a ExecHeaderMap,
        b: &'a ExecHeaderMap,
    }

    #[test]
    fn two_embedded_maps_splice_both() {
        let mut a = ExecHeaderMap::default();
        a.make_mut().insert(1, hdr(1));
        let mut b = ExecHeaderMap::default();
        b.make_mut().insert(2, hdr(2));
        let v = Two { a: &a, b: &b };
        let want = serde_json::to_vec(&v).unwrap();
        assert_eq!(sha256_hex_split(&v), crate::crypto::sha256_hex(&want));
        assert_eq!(sha256_hex_split(&v), crate::crypto::sha256_hex(&want), "memo hit");
        // Changing one map changes the root (its generation is in the key).
        b.make_mut().insert(3, hdr(3));
        let v2 = Two { a: &a, b: &b };
        assert_eq!(sha256_hex_split(&v2), crate::crypto::sha256_hex(&serde_json::to_vec(&v2).unwrap()));
        let v = Two { a: &a, b: &b };
        assert_eq!(to_vec_split(&v).unwrap(), want);
        // Normal serialization after a split is unaffected (mode reset).
        assert_eq!(serde_json::to_vec(&a).unwrap(), serde_json::to_vec(&*a).unwrap());
    }

    #[test]
    fn pruned_below_memoizes_same_source_and_floor() {
        let mut src = ExecHeaderMap::default();
        {
            let m = src.make_mut();
            for i in 1..=20 {
                m.insert(i, hdr(i));
            }
        }
        assert!(src.pruned_below(1).is_none(), "nothing below the first key");
        let g0 = src.generation();
        let floor = 8u64;
        let mut naive8: BTreeMap<_, _> = src.iter().map(|(k, v)| (*k, v.clone())).collect();
        naive8.retain(|n, _| *n >= floor);

        // Cap is 2 and other tests prune at the same time, so a hit can be
        // evicted between the two calls. Contents must match on every try.
        let mut shared_gen = None;
        for _ in 0..32 {
            let a = src.clone();
            let b = src.clone();
            let pa = a.pruned_below(floor).expect("prefix removed");
            let pb = b.pruned_below(floor).expect("prefix removed");
            assert_eq!(a.generation(), g0);
            assert!(ExecHeaderMap::ptr_eq(&a, &src));
            assert_eq!(&*pa, &naive8);
            assert_eq!(&*pb, &naive8);
            if pa.generation() == pb.generation() && ExecHeaderMap::ptr_eq(&pa, &pb) {
                assert!(std::sync::Arc::ptr_eq(
                    &pa.canonical_json(),
                    &pb.canonical_json()
                ));
                shared_gen = Some(pa.generation());
                break;
            }
        }
        let shared_gen = shared_gen.expect("same (generation, floor) reuses one pruned map");

        let other = src.pruned_below(12).expect("tighter floor removes more");
        assert_ne!(other.generation(), shared_gen, "a different floor is a different map");
        let mut naive12: BTreeMap<_, _> = src.iter().map(|(k, v)| (*k, v.clone())).collect();
        naive12.retain(|n, _| *n >= 12);
        assert_eq!(&*other, &naive12);
        let again8 = src.pruned_below(floor).expect("floor 8 still removes");
        assert_ne!(other.generation(), again8.generation());
        assert!(!ExecHeaderMap::ptr_eq(&other, &again8));
        let g_other = other.generation();
        assert!(other.pruned_below(12).is_none());
        assert_eq!(other.generation(), g_other);
    }
}
