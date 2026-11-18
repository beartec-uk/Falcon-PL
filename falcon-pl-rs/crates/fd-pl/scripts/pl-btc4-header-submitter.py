#!/usr/bin/env python3
"""Falcon PL fast BTC4 (Bitcoin testnet4) SPV header submitter.

Brought into the repo from falcon1 (it ran untracked as
/home/falcon/falcon-pl-public-testnet-2300/scripts/pl-btc4-header-submitter.py,
unit falcon-pl-btc4-header-submitter.service). Same wire behaviour as the live
script: headers come from the local Bitcoin Core (testnet4), each one is signed
by `falcon-pl-ctl submit-btc-header` against a throwaway local listener (the
ctl talks to it; we capture the signed message) and fanned out to every seat.

Changes against the live copy:

* **Waiting branches.** The rail can hold competing BTC4 branches next to the
  main chain (2.10.1 `btc_fork` / `btc_fork_alt`; the most-work rail's
  `btc_side`). The start height now also considers those: when a waiting
  branch's tip is on Core's active chain, the walk resumes from that tip
  instead of from the main-chain common ancestor, so it no longer re-submits
  the same "duplicate (pending fork)" headers on every pass.
* **Stuck warning.** If the rail tip has not moved for `STUCK_SECS` while
  testnet4 is ahead, a single clear `WARNING: BTC4 rail stuck ...` line is
  logged (rail tip, testnet4 tip, lag, waiting branches, last rejection), then
  again every `STUCK_REWARN_SECS`, and a `recovered` line once it moves.
* **Backoff.** A pass that makes no progress backs off (1 s doubling to
  `MAX_BACKOFF_SECS`) instead of looping every ~2 s. Progress resets it.

Env (defaults are the falcon1 values the live script hard-coded):
  FALCON_PL_CTL, FALCON_PL_RPC_ADDR, FALCON_PL_SUBMIT_FANOUT,
  FALCON_PL_HEADER_ACCOUNT, FALCON_PL_KEYS_DIR, FALCON_PL_NETWORK_ID,
  FPL_TN4_BITCOIN_CLI (space-separated argv prefix for bitcoin-cli),
  FPL_BTC4_STUCK_SECS (1800), FPL_BTC4_STUCK_REWARN_SECS (1800),
  FPL_BTC4_MAX_BACKOFF_SECS (60).

The keys dir is only passed to falcon-pl-ctl; this script never reads keys.
"""
import json
import os
import socket
import subprocess
import sys
import threading
import time

E = os.environ.get
CTL = E("FALCON_PL_CTL", "/opt/fpl-tn4btc/bin/falcon-pl-ctl")
RPC_ADDR = E("FALCON_PL_RPC_ADDR", "127.0.0.1:19301")
FANOUT = [
    a.strip()
    for a in E(
        "FALCON_PL_SUBMIT_FANOUT",
        "127.0.0.1:19301,100.115.112.95:19303,100.125.97.40:19306,100.108.46.34:19307,100.108.39.55:19312,100.106.108.37:19313",
    ).split(",")
    if a.strip()
]
ACCOUNT = E("FALCON_PL_HEADER_ACCOUNT", "btc-headers")
KEYS_DIR = E("FALCON_PL_KEYS_DIR", "/home/falcon/falcon-pl-public-testnet-2300/keys")
NETWORK_ID = E("FALCON_PL_NETWORK_ID", "2300")
BTC_CLI = (E("FPL_TN4_BITCOIN_CLI") or
           "/opt/fpl-tn4btc/bin/bitcoin-cli -conf=/opt/fpl-tn4btc/bitcoin.conf -datadir=/opt/fpl-tn4btc/data").split()


def _int(k, d):
    try:
        return int(E(k, str(d)))
    except ValueError:
        return d


STUCK_SECS = _int("FPL_BTC4_STUCK_SECS", 1800)
STUCK_REWARN_SECS = _int("FPL_BTC4_STUCK_REWARN_SECS", 1800)
MAX_BACKOFF_SECS = _int("FPL_BTC4_MAX_BACKOFF_SECS", 60)


def log(*a, err=False):
    print("[btc4-sync]", *a, file=sys.stderr if err else sys.stdout, flush=True)


# ---------------------------------------------------------------------------
# node / Core access (unchanged wire protocol)
# ---------------------------------------------------------------------------

def wire_query(addr, msg, timeout=4.0):
    host, port = addr.rsplit(":", 1)
    with socket.create_connection((host, int(port)), timeout=timeout) as s:
        s.settimeout(timeout)
        f = s.makefile("rwb", buffering=1 << 16)
        f.readline()  # hello
        f.write((json.dumps(msg) + "\n").encode())
        f.flush()
        for _ in range(64):
            line = f.readline()
            if not line:
                raise RuntimeError(f"{addr}: connection closed")
            m = json.loads(line)
            if m.get("type") not in ("hello", "pong"):
                return m
    raise RuntimeError(f"{addr}: no reply")


def btc4_rail(brief):
    m = wire_query(RPC_ADDR, {"type": "status_req", "include_accounts": False, "brief": brief},
                   timeout=5.0 if brief else 8.0)
    for rail in (m.get("body") or {}).get("rails", []):
        if isinstance(rail, dict) and rail.get("asset") == "BTC4":
            return rail
    raise RuntimeError("BTC4 rail not found")


def rail_tail(rail):
    return {int(x["height"]): str(x["hash"]).lower()
            for x in (rail.get("header_tail") or []) if "height" in x and "hash" in x}


def waiting_branches(rail):
    """Waiting branch tips the node reports: [(name, tip_height, tip_hash, len)].

    Reads the 2.10.1 slots (`btc_fork`, `btc_fork_alt`) and the most-work
    rail's `btc_side.tips`; a node that reports none of them gives []."""
    out = []
    for name in ("btc_fork", "btc_fork_alt"):
        b = rail.get(name)
        if isinstance(b, dict) and b.get("tip_hash"):
            out.append((name, int(b["tip_height"]), str(b["tip_hash"]).lower(), int(b.get("len", 0))))
    side = rail.get("btc_side")
    if isinstance(side, dict):
        for t in side.get("tips") or []:
            if t.get("tip_hash"):
                out.append(("btc_side", int(t["tip_height"]), str(t["tip_hash"]).lower(), int(t.get("len", 0))))
    return out


def get_seq():
    v = wire_query(RPC_ADDR, {"type": "account_query", "account": ACCOUNT}, timeout=3.0).get("body", {})
    return int(v.get("sequence", 0)), int(v.get("balance", 0))


def core(*args):
    return subprocess.check_output(BTC_CLI + [str(a) for a in args], text=True).strip()


def get_tn4_tip():
    return int(core("getblockcount"))


def get_tn4_hash(h):
    return core("getblockhash", h).lower()


def get_tn4_header(h):
    bhash = get_tn4_hash(h)
    return bhash, core("getblockheader", bhash, "false").lower()


def sign_btc4_header(seq, h, raw):
    """Run falcon-pl-ctl against a local fake node and capture the signed message."""
    captured = {}
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(4)
    port = srv.getsockname()[1]

    def handle():
        while "msg" not in captured:
            conn, _ = srv.accept()
            with conn:
                f = conn.makefile("rwb", buffering=1 << 16)
                f.write((json.dumps({"type": "hello", "id": "local", "public_key": "00",
                                     "network_id": int(NETWORK_ID)}) + "\n").encode())
                f.flush()
                line = f.readline()
                if not line:
                    continue
                req = json.loads(line)
                if req.get("type") == "status_req":
                    resp = {"type": "status", "body": {"suggested_fee": 1}}
                else:
                    captured["msg"] = req
                    resp = {"type": "ack", "body": {"ok": True}}
                f.write((json.dumps(resp) + "\n").encode())
                f.flush()
        srv.close()

    t = threading.Thread(target=handle, daemon=True)
    t.start()
    subprocess.run(
        [CTL, "--addr", f"127.0.0.1:{port}", "submit-btc-header", "--asset", "BTC4",
         "--account", ACCOUNT, "--raw", raw, "--height", str(h), "--sequence", str(seq),
         "--fee", "2", "--scheme", "falcon-512", "--keys-dir", KEYS_DIR, "--network-id", NETWORK_ID],
        check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=4.0,
    )
    t.join(timeout=1.5)
    return captured["msg"]


def fanout_submit(msg, state):
    """Returns True (accepted somewhere), "dup" (already held), or False.
    The last rejection map is kept in state["last_errs"] for the stuck warning."""
    res = {"accepted": False}

    def one(addr):
        try:
            r = wire_query(addr, msg, timeout=1.5)
            if r.get("type") != "err":
                res["accepted"] = True
            else:
                res.setdefault("errs", {})[addr] = str(r.get("msg") or r.get("error") or r)[:200]
        except Exception as e:
            res.setdefault("errs", {})[addr] = "exc: " + str(e)[:120]

    ths = [threading.Thread(target=one, args=(a,), daemon=True) for a in FANOUT]
    for t in ths:
        t.start()
    for t in ths:
        t.join(timeout=1.6)
    if res["accepted"]:
        return True
    errs = res.get("errs") or {}
    state["last_errs"] = errs
    if any("BTC duplicate header" in str(v) for v in errs.values()):
        log(f"duplicate (already held), advancing: {errs}", err=True)
        return "dup"
    log(f"rejected by all: {errs}", err=True)
    return False


# ---------------------------------------------------------------------------
# pure logic (unit-tested in test_pl_btc4_header_submitter.py)
# ---------------------------------------------------------------------------

def choose_start(tip_h, tip_hash, tail, branches, canon_hash):
    """Height to resume from (the next submitted header is start + 1).

    1. Rail tip on Core's active chain: resume at the tip.
    2. A waiting branch whose tip is on the active chain: resume at the
       highest such tip (the node already holds that branch; extending it is
       what makes it win). Returns (height, reason).
    3. Otherwise walk the main-chain tail back to the common ancestor.
    """
    if canon_hash(tip_h) == tip_hash:
        return tip_h, "tip"
    best = None
    for name, h, hs, _n in branches:
        try:
            if canon_hash(h) == hs and (best is None or h > best[0]):
                best = (h, name)
        except Exception:
            continue
    if best:
        return best[0], f"waiting branch {best[1]} tip {best[0]} is canonical"
    h = tip_h
    while h > 0:
        stored = tail.get(h, tip_hash if h == tip_h else None)
        if stored is None:
            break
        if canon_hash(h) == stored:
            return h, f"common ancestor {h}"
        h -= 1
    return max(0, tip_h - 1), "tail exhausted"


class StuckMonitor:
    """Warn once when the rail tip has not moved for `stuck_secs` while testnet4
    is ahead, then every `rewarn_secs`; note recovery once it moves."""

    def __init__(self, stuck_secs=STUCK_SECS, rewarn_secs=STUCK_REWARN_SECS, clock=time.time, sink=None):
        self.stuck_secs, self.rewarn_secs, self.clock = stuck_secs, rewarn_secs, clock
        self.sink = sink or (lambda line: log(line, err=True))
        self.last_tip = None
        self.since = None
        self.warned_at = None

    def observe(self, rail_tip, tn4_tip, branches=(), last_errs=None):
        now = self.clock()
        if rail_tip != self.last_tip:
            if self.warned_at is not None:
                self.sink(f"BTC4 rail recovered: tip {self.last_tip} -> {rail_tip} (testnet4 {tn4_tip})")
            self.last_tip, self.since, self.warned_at = rail_tip, now, None
            return None
        if tn4_tip <= rail_tip:
            self.since, self.warned_at = now, None
            return None
        stalled = now - self.since
        if stalled < self.stuck_secs:
            return None
        if self.warned_at is not None and now - self.warned_at < self.rewarn_secs:
            return None
        self.warned_at = now
        br = ", ".join(f"{n} {h} ({ln} hdr, {hs[:16]})" for n, h, hs, ln in branches) or "none"
        errs = "; ".join(f"{a}: {e}" for a, e in sorted((last_errs or {}).items())
                         if not str(e).startswith("exc:"))[:600] or "none"
        line = (f"WARNING: BTC4 rail stuck at {rail_tip} for {int(stalled // 60)} min; testnet4 tip {tn4_tip} "
                f"({tn4_tip - rail_tip} behind). Waiting branches: {br}. Last rejection: {errs}")
        self.sink(line)
        return line


def next_backoff(cur, progressed, cap=MAX_BACKOFF_SECS):
    if progressed:
        return 0.0
    return min(cap, max(1.0, cur * 2))


# ---------------------------------------------------------------------------

def main():
    hdr_cache = {}
    mon = StuckMonitor()
    state = {"last_errs": {}}
    backoff = 0.0
    while True:
        progressed = False
        try:
            rail = btc4_rail(brief=True)
            tip_h, tip_hash = int(rail["tip_height"]), str(rail["tip_hash"]).lower()
            tn4_tip = get_tn4_tip()
            if get_tn4_hash(tip_h) == tip_hash:
                start_h, why, branches = tip_h, "tip", []
            else:
                full = btc4_rail(brief=False)
                branches = waiting_branches(full)
                start_h, why = choose_start(tip_h, tip_hash, rail_tail(full), branches, get_tn4_hash)
                log(f"reorg/side: resuming at {start_h} ({why}); rail_tip={tip_h}")
            mon.observe(tip_h, tn4_tip, branches, state.get("last_errs"))
            if start_h >= tn4_tip:
                time.sleep(5.0)
                continue
            seq, bal = get_seq()
            log(f"starting from {start_h} (rail_tip={tip_h}) -> {tn4_tip} (seq={seq}, bal={bal})")
            cur_h = start_h
            while cur_h < tn4_tip:
                nxt = cur_h + 1
                if nxt not in hdr_cache or cur_h <= tip_h:
                    hdr_cache[nxt] = get_tn4_header(nxt)
                bhash, raw = hdr_cache[nxt]
                msg = sign_btc4_header(seq, nxt, raw)
                r = fanout_submit(msg, state)
                if r == "dup":
                    cur_h = nxt
                    hdr_cache.pop(nxt, None)
                    continue
                if not r:
                    break
                t0 = time.time()
                while time.time() - t0 < 4.5:
                    time.sleep(0.15)
                    new_seq, _ = get_seq()
                    if new_seq > seq:
                        seq = new_seq
                        cur_h = nxt
                        progressed = True
                        hdr_cache.pop(nxt, None)
                        if cur_h % 5 == 0 or cur_h == tn4_tip:
                            log(f"height={cur_h}/{tn4_tip} hash={bhash[:16]}... seq={seq}")
                        break
                else:
                    break
        except Exception as e:
            log(f"warn: {e}", err=True)
        backoff = next_backoff(backoff, progressed)
        time.sleep(backoff if backoff else 0.3)


if __name__ == "__main__":
    main()
