// Copyright (c) 2025-2026 BEARTEC. All rights reserved. See LICENSE.
//! Per-connection zstd stream on the p2p wire (`zstd-stream-v1`).
//!
//! Negotiation: a node with zstd enabled (the default; `FPL_WIRE_ZSTD=0`
//! disables, `FPL_WIRE_ZSTD=1` leaves it on) adds [`CAP_ZSTD_STREAM_V1`] to
//! its Hello capabilities. A sender switches **its own direction** only after
//! it has read the peer's Hello carrying the capability. It writes one plain
//! [`MARKER_LINE`] and from then on sends length-prefixed binary frames:
//! `u32 big-endian length || zstd bytes`. Each frame is one wire line,
//! compressed in a single streaming context and flushed, so message
//! boundaries and latency are kept. A receiver only honours the marker when it
//! advertised the capability itself. Peers that do not advertise it (pre-2.11.7
//! releases, 2.11.7 with the flag off, ctl, load-net) never see a marker or a
//! frame: their sessions are byte-for-byte unchanged.
//!
//! Memory per connection is bounded by a 128 KiB window (`window_log` 17)
//! and small match tables; see [`context_bytes`]. Decompression is capped per
//! frame and per partial line, so a "zstd bomb" closes the session instead of
//! growing memory. Any decode error ends the session; the dial loop redials.

use std::borrow::Cow;
use std::collections::VecDeque;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use zstd::zstd_safe::{self, zstd_sys::ZSTD_EndDirective, CCtx, CParameter, DCtx, DParameter, InBuffer, OutBuffer};

/// Hello capability token.
pub const CAP_ZSTD_STREAM_V1: &str = "zstd-stream-v1";
/// Plain line a sender writes once, right before its first frame.
pub const MARKER_LINE: &str = "#zstd-stream-v1";
/// Default level (1..=3 allowed via `FPL_WIRE_ZSTD_LEVEL`).
pub const DEFAULT_LEVEL: i32 = 3;
/// 128 KiB window. Receivers refuse frames that need more.
pub const WINDOW_LOG: u32 = 17;
pub const HASH_LOG: u32 = 15;
pub const CHAIN_LOG: u32 = 15;
/// Largest compressed frame accepted (bytes after the length prefix).
pub const MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;
/// Largest decompressed output per frame and largest unterminated line.
/// Same as the existing piece reassembly cap, so no legal line is refused.
pub const MAX_OUT_BYTES: usize = crate::pieces::PIECE_MAX_TOTAL;

/// Serialises tests that mutate process-global `FPL_WIRE_ZSTD`.
pub static WIRE_ZSTD_ENV_LOCK: Mutex<()> = Mutex::new(());

/// Whether this node advertises and will send `zstd-stream-v1`.
///
/// On by default. `FPL_WIRE_ZSTD=0` turns it off; `FPL_WIRE_ZSTD=1` leaves it
/// on. Negotiation is unchanged: a peer that does not advertise the capability
/// still gets plain NDJSON.
pub fn enabled() -> bool {
    std::env::var("FPL_WIRE_ZSTD").map(|v| v != "0").unwrap_or(true)
}

/// Level from `FPL_WIRE_ZSTD_LEVEL`, clamped to 1..=3.
pub fn level() -> i32 {
    std::env::var("FPL_WIRE_ZSTD_LEVEL")
        .ok()
        .and_then(|v| v.parse::<i32>().ok())
        .unwrap_or(DEFAULT_LEVEL)
        .clamp(1, 3)
}

/// Add the capability when enabled.
pub fn with_capability(mut caps: Vec<String>, on: bool) -> Vec<String> {
    if on && !caps.iter().any(|c| c == CAP_ZSTD_STREAM_V1) {
        caps.push(CAP_ZSTD_STREAM_V1.to_string());
    }
    caps
}

pub fn peer_has(caps: &[String]) -> bool {
    caps.iter().any(|c| c == CAP_ZSTD_STREAM_V1)
}

fn bad(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

/// One direction's compressor (streaming context kept for the session).
pub struct Compressor {
    cctx: CCtx<'static>,
    buf: Vec<u8>,
}

fn zerr(code: usize) -> io::Error {
    bad(format!("zstd: {}", zstd_safe::get_error_name(code)))
}

impl Compressor {
    pub fn new(level: i32) -> io::Result<Self> {
        let mut cctx = CCtx::create();
        for p in [
            CParameter::CompressionLevel(level),
            CParameter::WindowLog(WINDOW_LOG),
            CParameter::HashLog(HASH_LOG),
            CParameter::ChainLog(CHAIN_LOG),
            CParameter::ChecksumFlag(false),
        ] {
            cctx.set_parameter(p).map_err(zerr)?;
        }
        Ok(Self { cctx, buf: vec![0u8; CCtx::out_size()] })
    }

    /// Compress one line into a length-prefixed frame (flushed, not ended).
    pub fn frame(&mut self, data: &[u8]) -> io::Result<Vec<u8>> {
        let mut out = Vec::with_capacity(4 + data.len() / 2 + 64);
        out.extend_from_slice(&[0u8; 4]);
        let mut inb = InBuffer::around(data);
        loop {
            let mut ob = OutBuffer::around(&mut self.buf[..]);
            let left = self
                .cctx
                .compress_stream2(&mut ob, &mut inb, ZSTD_EndDirective::ZSTD_e_flush)
                .map_err(zerr)?;
            let n = ob.pos();
            out.extend_from_slice(&self.buf[..n]);
            if left == 0 && inb.pos() == data.len() {
                break;
            }
        }
        let len = out.len() - 4;
        if len > MAX_FRAME_BYTES {
            return Err(bad("zstd frame over limit"));
        }
        out[..4].copy_from_slice(&(len as u32).to_be_bytes());
        Ok(out)
    }

    pub fn sizeof(&self) -> usize {
        self.cctx.sizeof() + self.buf.len()
    }
}

/// One direction's decompressor with output caps.
pub struct Decompressor {
    dctx: DCtx<'static>,
    buf: Vec<u8>,
}

impl Decompressor {
    pub fn new() -> io::Result<Self> {
        let mut dctx = DCtx::create();
        dctx.set_parameter(DParameter::WindowLogMax(WINDOW_LOG)).map_err(zerr)?;
        Ok(Self { dctx, buf: vec![0u8; DCtx::out_size()] })
    }

    /// Decode one frame payload, appending to `out`; error past `limit` bytes.
    pub fn frame(&mut self, payload: &[u8], out: &mut Vec<u8>, limit: usize) -> io::Result<()> {
        let mut inb = InBuffer::around(payload);
        let mut produced = 0usize;
        loop {
            let before = inb.pos();
            let mut ob = OutBuffer::around(&mut self.buf[..]);
            self.dctx.decompress_stream(&mut ob, &mut inb).map_err(zerr)?;
            let n = ob.pos();
            produced += n;
            if produced > limit {
                return Err(bad("zstd frame output over limit"));
            }
            out.extend_from_slice(&self.buf[..n]);
            if n == 0 && inb.pos() == before {
                if inb.pos() < payload.len() {
                    return Err(bad("zstd decode stalled"));
                }
                return Ok(());
            }
        }
    }

    pub fn sizeof(&self) -> usize {
        self.dctx.sizeof() + self.buf.len()
    }
}

/// Heap bytes of one compressor + one decompressor (both directions of a
/// connection) after real use, as reported by libzstd plus our buffers.
pub fn context_bytes(level: i32) -> io::Result<usize> {
    let mut c = Compressor::new(level)?;
    let mut d = Decompressor::new()?;
    let data: Vec<u8> = (0..600 * 1024u32).map(|i| (i.wrapping_mul(2654435761) >> 13) as u8).collect();
    let f = c.frame(&data)?;
    let mut out = Vec::new();
    d.frame(&f[4..], &mut out, MAX_OUT_BYTES)?;
    if out != data {
        return Err(bad("round trip mismatch"));
    }
    Ok(c.sizeof() + d.sizeof())
}

/// Writer half with optional compression of the outbound direction.
pub struct ZWriter<W> {
    pub inner: W,
    peer_ok: Arc<AtomicBool>,
    level: i32,
    comp: Option<Compressor>,
}

impl<W> ZWriter<W> {
    /// `peer_ok` is set by the read side once the peer's Hello advertised the
    /// capability (and this node has it enabled).
    pub fn new(inner: W, peer_ok: Arc<AtomicBool>, level: i32) -> Self {
        Self { inner, peer_ok, level, comp: None }
    }

    pub fn compressed(&self) -> bool {
        self.comp.is_some()
    }

    /// Bytes to put on the socket for one line. Plain until the peer opted in;
    /// then the marker (once) and a frame. Encoding advances the stream, so a
    /// caller that encoded a line must send it or end the session.
    pub fn encode<'a>(&mut self, line: &'a [u8]) -> io::Result<Cow<'a, [u8]>> {
        if self.comp.is_none() && self.peer_ok.load(Ordering::Relaxed) {
            let mut c = Compressor::new(self.level)?;
            let mut out = Vec::with_capacity(MARKER_LINE.len() + 1 + line.len() / 2);
            out.extend_from_slice(MARKER_LINE.as_bytes());
            out.push(b'\n');
            out.extend_from_slice(&c.frame(line)?);
            self.comp = Some(c);
            return Ok(Cow::Owned(out));
        }
        match self.comp.as_mut() {
            None => Ok(Cow::Borrowed(line)),
            Some(c) => Ok(Cow::Owned(c.frame(line)?)),
        }
    }
}

impl<W: AsyncWrite + Unpin> ZWriter<W> {
    pub async fn write_all(&mut self, line: &[u8]) -> io::Result<()> {
        let out = self.encode(line)?;
        self.inner.write_all(&out).await
    }

    pub async fn shutdown(&mut self) -> io::Result<()> {
        self.inner.shutdown().await
    }
}

/// Line reader that understands the marker and frames. In plain mode it
/// behaves like `tokio::io::Lines` (strips `\n` / `\r\n`, UTF-8 checked).
pub struct LineReader<R> {
    rd: BufReader<R>,
    accept: bool,
    dec: Option<Decompressor>,
    pending: VecDeque<String>,
    partial: Vec<u8>,
}

fn strip_eol(mut v: Vec<u8>) -> Vec<u8> {
    if v.last() == Some(&b'\n') {
        v.pop();
        if v.last() == Some(&b'\r') {
            v.pop();
        }
    }
    v
}

impl<R: AsyncRead + Unpin> LineReader<R> {
    /// `accept`: this node advertised the capability, so a marker switches
    /// the inbound direction to frames. Otherwise a marker is just a line.
    pub fn new(r: R, accept: bool) -> Self {
        Self { rd: BufReader::new(r), accept, dec: None, pending: VecDeque::new(), partial: Vec::new() }
    }

    pub fn compressed(&self) -> bool {
        self.dec.is_some()
    }

    pub async fn next_line(&mut self) -> io::Result<Option<String>> {
        loop {
            if let Some(l) = self.pending.pop_front() {
                return Ok(Some(l));
            }
            if self.dec.is_none() {
                let mut buf = Vec::new();
                if self.rd.read_until(b'\n', &mut buf).await? == 0 {
                    return Ok(None);
                }
                let s = String::from_utf8(strip_eol(buf))
                    .map_err(|_| bad("stream did not contain valid UTF-8"))?;
                if self.accept && s == MARKER_LINE {
                    self.dec = Some(Decompressor::new()?);
                    continue;
                }
                return Ok(Some(s));
            }
            let mut len = [0u8; 4];
            match self.rd.read_exact(&mut len).await {
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
                Err(e) => return Err(e),
            }
            let n = u32::from_be_bytes(len) as usize;
            if n == 0 || n > MAX_FRAME_BYTES {
                return Err(bad(format!("zstd frame length {n}")));
            }
            let mut payload = vec![0u8; n];
            self.rd.read_exact(&mut payload).await?;
            let room = MAX_OUT_BYTES.saturating_sub(self.partial.len());
            let dec = self.dec.as_mut().expect("compressed mode");
            dec.frame(&payload, &mut self.partial, room)?;
            let mut start = 0usize;
            while let Some(i) = self.partial[start..].iter().position(|&b| b == b'\n') {
                let line = self.partial[start..start + i + 1].to_vec();
                start += i + 1;
                let s = String::from_utf8(strip_eol(line))
                    .map_err(|_| bad("stream did not contain valid UTF-8"))?;
                self.pending.push_back(s);
            }
            self.partial.drain(..start);
            if self.partial.len() > MAX_OUT_BYTES {
                return Err(bad("zstd line over limit"));
            }
        }
    }
}
