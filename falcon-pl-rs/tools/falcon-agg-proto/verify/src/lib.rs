// Copyright (c) 2026 BEARTEC. All rights reserved. See LICENSE.
//! Prototype pure-Rust Falcon-512 verifier for the PQClean round-3 format that
//! `pqcrypto-falcon 0.3` (used by falcon-pl-node) produces:
//!
//! * public key: 897 B = header 0x09 + 512 x 14-bit coefficients
//! * detached signature: header 0x39 + 40-byte nonce + compressed s2
//!
//! `no_std`, no allocation, so it can run inside a zkVM guest. It is a
//! research prototype, cross-checked against pqcrypto-falcon in tests; it is
//! NOT used by the node and has not been audited or made constant-time
//! (verification only handles public data).
#![no_std]

use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;

pub const N: usize = 512;
pub const Q: u32 = 12289;
pub const PK_BYTES: usize = 897;
pub const NONCE_LEN: usize = 40;
/// Squared-norm bound for Falcon-512 (PQClean `l2bound[9]`).
pub const L2_BOUND: u32 = 34_034_726;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyError {
    BadPublicKey,
    BadSignature,
    NormTooLarge,
}

/// Decoded public key in NTT form (ready for repeated verifies).
#[derive(Clone)]
pub struct PublicKey {
    h_ntt: [u16; N],
}

// ---------- modular arithmetic mod q = 12289 ----------
#[inline(always)]
fn mq_add(a: u32, b: u32) -> u32 {
    let s = a + b;
    if s >= Q { s - Q } else { s }
}
#[inline(always)]
fn mq_sub(a: u32, b: u32) -> u32 {
    if a >= b { a - b } else { a + Q - b }
}
#[inline(always)]
fn mq_mul(a: u32, b: u32) -> u32 {
    (a * b) % Q
}
const fn pow_mod(mut b: u32, mut e: u32) -> u32 {
    let mut r = 1u32;
    b %= Q;
    while e > 0 {
        if e & 1 == 1 {
            r = (r * b) % Q;
        }
        b = (b * b) % Q;
        e >>= 1;
    }
    r
}
// psi = primitive 1024th root of unity mod q (psi^512 = -1), for the negacyclic twist.
const fn find_psi() -> u32 {
    let mut g = 2;
    loop {
        let c = pow_mod(g, (Q - 1) / 1024);
        if pow_mod(c, 512) == Q - 1 {
            return c;
        }
        g += 1;
    }
}
const PSI: u32 = find_psi();
const PSI_INV: u32 = pow_mod(PSI, Q - 2);
const N_INV: u32 = pow_mod(N as u32, Q - 2);

const fn bitrev9(mut x: usize) -> usize {
    let mut r = 0;
    let mut i = 0;
    while i < 9 {
        r = (r << 1) | (x & 1);
        x >>= 1;
        i += 1;
    }
    r
}

const fn make_tables() -> ([u16; N], [u16; N], [u16; N], [u16; N]) {
    // psi^i, psi^-i (twist) and omega^k, omega^-k for k < N/2 (omega = psi^2).
    let mut tw = [0u16; N];
    let mut twi = [0u16; N];
    let mut om = [0u16; N];
    let mut omi = [0u16; N];
    let omega = (PSI * PSI) % Q;
    let omega_inv = pow_mod(omega, Q - 2);
    let mut i = 0;
    let (mut p, mut pi, mut o, mut oi) = (1u32, 1u32, 1u32, 1u32);
    while i < N {
        tw[i] = p as u16;
        twi[i] = pi as u16;
        om[i] = o as u16;
        omi[i] = oi as u16;
        p = (p * PSI) % Q;
        pi = (pi * PSI_INV) % Q;
        o = (o * omega) % Q;
        oi = (oi * omega_inv) % Q;
        i += 1;
    }
    (tw, twi, om, omi)
}
const TABLES: ([u16; N], [u16; N], [u16; N], [u16; N]) = make_tables();

/// In-place cyclic NTT of size N with root table `roots` (omega^k).
fn ntt_cyclic(a: &mut [u32; N], roots: &[u16; N]) {
    for i in 0..N {
        let j = bitrev9(i);
        if i < j {
            a.swap(i, j);
        }
    }
    let mut len = 2;
    while len <= N {
        let step = N / len;
        let half = len / 2;
        let mut start = 0;
        while start < N {
            for k in 0..half {
                let w = roots[k * step] as u32;
                let u = a[start + k];
                let v = mq_mul(a[start + k + half], w);
                a[start + k] = mq_add(u, v);
                a[start + k + half] = mq_sub(u, v);
            }
            start += len;
        }
        len <<= 1;
    }
}

fn ntt_negacyclic(a: &mut [u32; N]) {
    for i in 0..N {
        a[i] = mq_mul(a[i], TABLES.0[i] as u32);
    }
    ntt_cyclic(a, &TABLES.2);
}

fn intt_negacyclic(a: &mut [u32; N]) {
    ntt_cyclic(a, &TABLES.3);
    for i in 0..N {
        a[i] = mq_mul(mq_mul(a[i], N_INV), TABLES.1[i] as u32);
    }
}

impl PublicKey {
    /// Decode the 897-byte PQClean public key.
    pub fn from_bytes(pk: &[u8]) -> Result<Self, VerifyError> {
        if pk.len() != PK_BYTES || pk[0] != 0x09 {
            return Err(VerifyError::BadPublicKey);
        }
        let mut h = [0u32; N];
        let (mut acc, mut acc_len, mut u) = (0u32, 0u32, 0usize);
        for &b in &pk[1..] {
            acc = (acc << 8) | b as u32;
            acc_len += 8;
            if acc_len >= 14 {
                acc_len -= 14;
                let w = (acc >> acc_len) & 0x3FFF;
                if w >= Q {
                    return Err(VerifyError::BadPublicKey);
                }
                h[u] = w;
                u += 1;
            }
        }
        if u != N || (acc & ((1 << acc_len) - 1)) != 0 {
            return Err(VerifyError::BadPublicKey);
        }
        ntt_negacyclic(&mut h);
        let mut h_ntt = [0u16; N];
        for i in 0..N {
            h_ntt[i] = h[i] as u16;
        }
        Ok(Self { h_ntt })
    }
}

/// PQClean `comp_decode` for logn = 9. Requires the encoding to use exactly
/// all of `buf` with zero trailing bits.
fn comp_decode(buf: &[u8], out: &mut [i16; N]) -> Result<(), VerifyError> {
    let (mut acc, mut acc_len, mut v) = (0u32, 0u32, 0usize);
    for slot in out.iter_mut() {
        if v >= buf.len() {
            return Err(VerifyError::BadSignature);
        }
        acc = (acc << 8) | buf[v] as u32;
        v += 1;
        let b = acc >> acc_len;
        let s = b & 128;
        let mut m = b & 127;
        loop {
            if acc_len == 0 {
                if v >= buf.len() {
                    return Err(VerifyError::BadSignature);
                }
                acc = (acc << 8) | buf[v] as u32;
                v += 1;
                acc_len = 8;
            }
            acc_len -= 1;
            if (acc >> acc_len) & 1 != 0 {
                break;
            }
            m += 128;
            if m > 2047 {
                return Err(VerifyError::BadSignature);
            }
        }
        if s != 0 && m == 0 {
            return Err(VerifyError::BadSignature);
        }
        *slot = if s != 0 { -(m as i16) } else { m as i16 };
    }
    if v != buf.len() || (acc & ((1u32 << acc_len) - 1)) != 0 {
        return Err(VerifyError::BadSignature);
    }
    Ok(())
}

/// SHAKE256(nonce || msg) -> point mod q (PQClean `hash_to_point_vartime`).
fn hash_to_point(nonce: &[u8], msg: &[u8], c: &mut [u32; N]) {
    let mut sh = Shake256::default();
    sh.update(nonce);
    sh.update(msg);
    let mut rd = sh.finalize_xof();
    let mut i = 0;
    let mut buf = [0u8; 2];
    while i < N {
        rd.read(&mut buf);
        let w = ((buf[0] as u32) << 8) | buf[1] as u32;
        if w < 61445 {
            c[i] = w % Q;
            i += 1;
        }
    }
}

/// Verify a PQClean Falcon-512 detached signature.
pub fn verify(pk: &PublicKey, msg: &[u8], sig: &[u8]) -> Result<(), VerifyError> {
    if sig.len() < 1 + NONCE_LEN + 1 || sig[0] != 0x39 {
        return Err(VerifyError::BadSignature);
    }
    let nonce = &sig[1..1 + NONCE_LEN];
    let mut s2 = [0i16; N];
    comp_decode(&sig[1 + NONCE_LEN..], &mut s2)?;
    let mut c = [0u32; N];
    hash_to_point(nonce, msg, &mut c);
    // s1 = c - s2 * h  (mod q, negacyclic)
    let mut t = [0u32; N];
    for i in 0..N {
        let x = s2[i] as i32;
        t[i] = if x < 0 { (x + Q as i32) as u32 } else { x as u32 };
    }
    ntt_negacyclic(&mut t);
    for i in 0..N {
        t[i] = mq_mul(t[i], pk.h_ntt[i] as u32);
    }
    intt_negacyclic(&mut t);
    let mut norm: u32 = 0;
    let mut ng: u32 = 0;
    for i in 0..N {
        let mut z = mq_sub(c[i], t[i]) as i32;
        if z > (Q as i32) / 2 {
            z -= Q as i32;
        }
        let s1 = z;
        let s2v = s2[i] as i32;
        norm = norm.wrapping_add((s1 * s1) as u32);
        ng |= norm;
        norm = norm.wrapping_add((s2v * s2v) as u32);
        ng |= norm;
    }
    // Saturate on overflow like PQClean `is_short`.
    norm |= 0u32.wrapping_sub(ng >> 31);
    if norm <= L2_BOUND {
        Ok(())
    } else {
        Err(VerifyError::NormTooLarge)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use pqcrypto_falcon::falcon512;
    use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _};
    use std::format;

    #[test]
    fn matches_pqcrypto_falcon() {
        for k in 0..8 {
            let (pk, sk) = falcon512::keypair();
            let pkd = PublicKey::from_bytes(pk.as_bytes()).unwrap();
            for m in 0..16 {
                let msg = format!("pl-ok:v2|2300|{k}|{m}|hash");
                let sig = falcon512::detached_sign(msg.as_bytes(), &sk);
                assert!(falcon512::verify_detached_signature(&sig, msg.as_bytes(), &pk).is_ok());
                assert_eq!(verify(&pkd, msg.as_bytes(), sig.as_bytes()), Ok(()));
                // wrong message
                assert!(verify(&pkd, b"other", sig.as_bytes()).is_err());
                // bit flip in s2
                let mut bad = sig.as_bytes().to_vec();
                let j = 50 + (m as usize * 7) % (bad.len() - 51);
                bad[j] ^= 0x10;
                let ours = verify(&pkd, msg.as_bytes(), &bad).is_ok();
                let theirs = falcon512::DetachedSignature::from_bytes(&bad)
                    .map(|s| falcon512::verify_detached_signature(&s, msg.as_bytes(), &pk).is_ok())
                    .unwrap_or(false);
                assert_eq!(ours, theirs, "agree on tampered sig");
            }
        }
    }
}

#[cfg(test)]
mod ntt_tests {
    use super::*;
    #[test]
    fn ntt_matches_naive() {
        let mut a = [0u32; N];
        let mut b = [0u32; N];
        for i in 0..N {
            a[i] = ((i * 37 + 11) as u32) % Q;
            b[i] = ((i * i * 5 + 3) as u32) % Q;
        }
        let mut naive = [0u32; N];
        for i in 0..N {
            for j in 0..N {
                let p = mq_mul(a[i], b[j]);
                let k = i + j;
                if k < N { naive[k] = mq_add(naive[k], p); } else { naive[k - N] = mq_sub(naive[k - N], p); }
            }
        }
        let (mut x, mut y) = (a, b);
        ntt_negacyclic(&mut x);
        ntt_negacyclic(&mut y);
        for i in 0..N { x[i] = mq_mul(x[i], y[i]); }
        intt_negacyclic(&mut x);
        assert_eq!(pow_mod(PSI, 512), Q - 1, "psi^512 = -1");
        assert_eq!(&x[..], &naive[..]);
    }
}
