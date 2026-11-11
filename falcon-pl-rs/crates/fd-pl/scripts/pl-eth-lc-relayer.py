#!/usr/bin/env python3
"""The deployed host1 copy of this script differs from the repo; the operator must diff and reconcile before replacing it.

Relay Sepolia light-client updates and ETH/USDC deposit proofs onto 2300.

Gloas light-client headers carry only an execution block hash. While that head
is hash-only, mint_evm_lc fails permanently with "execution headers do not
reach LC head". After every LC update or bootstrap whose head is hash-only,
this script builds the EthExecHeaders batch (eth_getBlockByHash) and submits
it in the same mempool batch as the LC tx, before waiting for inclusion.
That submit is always before any mint. A mint is gated on status showing the
head resolved: execution_number != 0 and eth_exec_tip covering that number
(the node copies the number from the stored header with the LC hash).

Sequences. submit-eth-lc-update and submit-eth-lc-bootstrap have no
--sequence flag: ctl passes 0 and resolve_seq re-reads the COMMITTED account
sequence (the mempool is invisible). submit-eth-exec-headers --sequence 0 does
the same re-read, and submit_tx_inner evicts any mempool tx with that
account+sequence, so a header submitted with no --sequence drops the update
still sitting at N. This script reads N once (ctl account) immediately before
the LC tx, lets that tx resolve N, then sends each header chunk with
--sequence N+1, N+2, … (explicit, so ctl does not re-read). A mid-chain
failure stops the chain. Sequences that ctl accepted stay reserved until the
account query catches up. --sequence 0 is not usable: ctl treats 0 as "re-read".

There is no mempool listing. status.mempool is a count, WireMsg has no
mempool-contents query, and ctl has no per-account or per-sequence subcommand.
If the packer drops an accepted tx ("update does not advance finalized slot"
and the like), the committed sequence stays at N while this process's floor
stays above it. After ETH_SEQ_STUCK_SEC (default 180, clamped to 120..300)
the floor resets to the committed sequence and the loop resubmits. A valid
tx would have packed within a few blocks. Resubmitting at N evicts and
replaces only this account's own stale tx at N. A restart is not required.
Do not run mint (or any other signer) on this account while the daemon is
up: the floor is per process, so the other process will not see it.

Account. This daemon signs as watcher-eth-lc (FPL_WATCHER_ACCOUNT).
Auto-mint and the manual mint command sign as watcher-eth. They must not
share an account: there is no lockfile, and submit_tx_inner evicts the
other process's mempool tx. watcher-browser (BTC) and watcher-eth (mint)
are both refused, compared casefolded. On host1 the relayer drop-in
must be changed to watcher-eth-lc (key created and funded) in the same
step as deploying this script, or the daemon refuses to start. The mint
subcommand defaults to watcher-eth and refuses watcher-eth-lc. Do not
create or commit keys here, and do not change the server from this change.

Alerts. The daemon prints a line starting with ALERT when the LC execution
head has not moved for ETH_LC_STALE_SEC (default 3600), and when a V1 or V2
bridge Deposit inside the scan window is older than ETH_UNMINTED_DEPOSIT_SEC
(default 86400) and is not in the ETH/USDC rail spent_deposits. The scan
window defaults to the 50_400-block prune window (~7 days), not 7200, and
is fetched in eth_getLogs chunks. V3 (FalconQcBridgeV3, its own Deposit topic) has a separate scan,
scan_unminted_v3_deposits: ALERT unminted V3 deposit <id> age=<s>s when a V3
Deposit is older than ETH_V3_UNMINTED_SEC (default 1800) and its id is not in
body.eth_v3_resolutions. Each V3 scan ends with a 'V3 deposit scan' summary line.
Both alerts repeat, throttled by ETH_ALERT_EVERY_SEC (default 600).
Discord (optional): if DISCORD_HEALTH_WEBHOOK_URL (the node alerts' env var)
is set when the daemon starts, each unminted deposit (V1/V2 by txid, V3 by
deposit_id) is posted once, and one recovery note is posted when it mints.
Posted keys persist in ETH_DISCORD_STATE (default
run/bridge/eth-unminted-discord.json), so a restart does not repost. Unset
means no Discord at all. `discord-test` sends one labelled TEST message.
The scan's ETH_SCAN_BUDGET_SEC is split: eth_getLogs stops starting spans at
75% of it, and the timestamp lookups for logs already fetched get their own
allowance (at most 64 distinct blocks per cycle). A short timestamp pass
rewinds the cursor to the first unprocessed span instead of dropping logs.
An exec header over ETH_HEADER_CHUNK_BYTES is an ALERT and the batch is
refused before anything is submitted.

Header waves. One in-flight wave is at most ETH_HEADER_WAVE_BYTES of header
JSON (default and cap 2 MiB, floor 64 KiB). The cap counts header JSON only;
the tx/ledger envelope adds about 6% and the LC update rides in the first
wave, so it is half the 4 MiB LedgerBody lane on purpose. Do not raise it
toward 4 MiB. ETH_HEADER_CHUNK_BYTES (default 256 KiB, 64 KiB..wave) caps one
header tx. 0, negative or junk values use the default. The next wave waits
for the previous one to commit, polling every ETH_WAVE_POLL_SEC (default 2,
clamped 0.5..30) for at most ETH_SEQ_STUCK_SEC + 30s.

Watchers submit proofs. They cannot mint. RailDeposit needs an LC head plus a
receipt MPT against a header walk that ends at that head.

  pl-eth-lc-relayer.py bootstrap
  pl-eth-lc-relayer.py update
  pl-eth-lc-relayer.py daemon
  pl-eth-lc-relayer.py mint --account dave --txid 0x...
  pl-eth-lc-relayer.py discord-test
"""
from __future__ import annotations

import argparse
import atexit
import hashlib
import json
import math
import os
import random
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

_SCRIPT = Path(__file__).resolve()
if str(_SCRIPT.parent) not in sys.path:
    sys.path.insert(0, str(_SCRIPT.parent))
from eth_bridge_config import BEACON_RPC, ETH_RPC, FALCON_QC_BRIDGE, SEPOLIA_USDC  # noqa: E402
import fpl_discord_notify  # noqa: E402

ROOT = Path(os.environ.get("PL_ROOT", str(Path.home() / "falcon-pl-public-testnet-2300")))
CTL = Path(os.environ.get("FPL_CTL", str(ROOT / "bin/falcon-pl-ctl")))
KEYS = os.environ.get("FPL_KEYS", str(ROOT / "keys"))
RPC = os.environ.get("FPL_RPC", "127.0.0.1:19301")
BTC_WATCHER_ACCOUNT = "watcher-browser"
MINT_ACCOUNT = "watcher-eth"
ACCOUNT = os.environ.get("FPL_WATCHER_ACCOUNT", "watcher-eth-lc").strip() or "watcher-eth-lc"
SCHEME = os.environ.get("FPL_SCHEME", "falcon-512")
NETWORK_ID = os.environ.get("FPL_NETWORK_ID", "2300")
ADMIN = os.environ.get("FPL_ADMIN_SOCK", str(ROOT / "run/v1.admin.sock"))
UA = os.environ.get("FPL_UA", "falcon-pl-lc/2.9.40")
# Fallback is Lodestar Sepolia (eth_bridge_config.BEACON_RPC). SEPOLIA_BEACON
# overrides it; an installed beacon_rpc / BEACON_RPC still wins over the fallback.
BEACON = os.environ.get("SEPOLIA_BEACON", BEACON_RPC)
ETH_RPC = os.environ.get("ETH_RPC", ETH_RPC)
BRIDGE = os.environ.get("SEPOLIA_BRIDGE", FALCON_QC_BRIDGE).lower()
BOOT = Path(
    os.environ.get(
        "SEPOLIA_LC_BOOTSTRAP",
        str(Path.home() / "falcon-pl/falcon-pl-rs/crates/fd-pl/data/sepolia-lc-bootstrap.json"),
    )
)
ETH_LOCK = "c1113d2059c5d73f45968910fadfff7d88a3c4a4d8a0f754f15faa495d2c467b"
USDC_LOCK = "c8927e1f8b56b080b015ccf240c5d27c6f1525d52a6545a1c03c84326e483c1c"
ETH_TOKEN = "00" * 20
USDC_TOKEN = "1c7d4b196cb0c7b01d743fbc6116a902379c7238"
SLOTS_PER_PERIOD = 32 * 256
HEADER_CHUNK = int(os.environ.get("ETH_HEADER_CHUNK", "32"))
# Phase 2: alert when the LC exec head is stale, or a deposit is unminted.
STALE_EXEC_SEC = int(os.environ.get("ETH_LC_STALE_SEC", "3600"))
UNMINTED_DEPOSIT_SEC = int(os.environ.get("ETH_UNMINTED_DEPOSIT_SEC", "86400"))
# #27 keeps execution headers for 50_400 blocks (~7 days at 12s). An unminted
# deposit must stay inside the scan until that prune, or it ages out of the
# alert before the header window closes.
EXEC_PRUNE_BLOCKS = 50_400
BLOCK_SEC = 12
# config/sepolia-qc.json and config/sepolia-qc-v2.json. Deposits can land on
# either bridge; the configured BRIDGE alone misses the other. A third
# address is not scanned here (V3 has its own scan: scan_unminted_v3_deposits).
QC_BRIDGE_V1 = "0xf8F1471643792eb1cD5d0C31061629777E55bc48"
QC_BRIDGE_V2 = "0x811854827627024B38926Ea9DCc0f88ACd5fB23e"


def _seq_stuck_sec() -> float:
    """How long a floor may sit above the committed sequence. Clamped to 2–5 min."""
    try:
        raw = float(os.environ.get("ETH_SEQ_STUCK_SEC", "180"))
    except ValueError:
        raw = 180.0
    if not math.isfinite(raw):
        print(f"WARNING ETH_SEQ_STUCK_SEC={raw} not finite; using 180", flush=True)
        raw = 180.0
    if raw < 120 or raw > 300:
        print(
            f"WARNING ETH_SEQ_STUCK_SEC={raw} outside 120..300; clamping",
            flush=True,
        )
        raw = min(300.0, max(120.0, raw))
    return raw


SEQ_STUCK_SEC = _seq_stuck_sec()
# Next sequence this process has reserved. Account queries at or above this
# mean those txs committed. Lower means they are still in the mempool, or
# were dropped and the floor has not yet timed out.
_seq_floor = 0
# monotonic time when the floor first sat strictly above the committed sequence.
# Restarted when the committed sequence advances, so a long chain that is
# still packing does not look stuck.
_seq_stuck_since: float | None = None
# Committed sequence observed the last time the stuck clock was considered.
_stuck_watch_committed: int | None = None
_exec_watch = {"number": None, "since": None}
_last_deposit_scan = 0.0
_last_v3_scan = 0.0
_v3_seen: dict[str, dict] = {}

# Shared signer (host1 2026-10-20): auto-mint may also sign as this account
# when both run with FPL_SHARED_SIGNER=1. Every sequence-consuming section
# (LC update / bootstrap / header waves / backfill here; each mint there)
# holds an exclusive flock on signer_lock_path(account), and a holder only
# releases once the committed sequence covers everything it sent, so the
# other process always starts from a clean committed sequence.
SHARED_SIGNER = os.environ.get("FPL_SHARED_SIGNER", "").strip() == "1"


def signer_lock_path(account: str) -> Path:
    raw = os.environ.get("FPL_SIGNER_LOCK", "").strip()
    return Path(raw) if raw else ROOT / "run" / f"signer-{account.strip().casefold()}.lock"


class SignerLock:
    def __init__(self, account: str):
        self.path = signer_lock_path(account)
        self.fd = None

    def __enter__(self):
        import fcntl

        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.fd = open(self.path, "a+")
        fcntl.flock(self.fd.fileno(), fcntl.LOCK_EX)
        return self

    def __exit__(self, *exc):
        import fcntl

        if self.fd:
            fcntl.flock(self.fd.fileno(), fcntl.LOCK_UN)
            self.fd.close()
            self.fd = None


def drain_own_sequences(timeout: float | None = None) -> bool:
    """Before releasing the signer lock: wait until committed >= _seq_floor."""
    deadline = time.time() + (SEQ_STUCK_SEC + 30 if timeout is None else timeout)
    while True:
        try:
            committed = account_sequence()
        except Exception as e:
            print(f"WARN drain sequence read: {e}", flush=True)
            committed = -1
        if committed >= _seq_floor:
            return True
        if time.time() >= deadline:
            print(
                f"WARN signer lock released with sequences in flight "
                f"(committed {committed} < floor {_seq_floor})",
                flush=True,
            )
            return False
        time.sleep(2)
_last_stale_alert = 0.0
# Unminted scan resumes here after a budget stop, so the next cycle does not
# restart at the oldest V1 chunk and starve V2. addr "" means start at the top.
_scan_resume = {"addr": "", "from_block": -1}
# Block number -> timestamp from eth_getBlockByNumber, kept across scan cycles
# so a span rewound after a short timestamp pass does not pay for the same
# lookups again. Only positive timestamps are kept. Pruned below the window.
_block_ts_cache: dict[int, int] = {}
_BLOCK_TS_CACHE_MAX = 8192
# Block number -> wall time of a failed timestamp lookup. Not retried for
# _BLOCK_TS_RETRY_SEC, so one block that keeps failing on a slow RPC cannot
# pin the rewound cursor to its span and stop the rotation.
_block_ts_failed: dict[int, float] = {}
_BLOCK_TS_RETRY_SEC = 3600


class SequenceInFlight(RuntimeError):
    """A sequence this process submitted has not committed yet."""


# sysexits.h EX_CONFIG. systemd RestartPreventExitStatus=78 so a wrong
# account drop-in does not restart-loop. Exit 1 would, because Restart=always.
ACCOUNT_REFUSAL_EXIT = 78


class AccountRefusal(SystemExit):
    """Wrong signer account. Process status is ACCOUNT_REFUSAL_EXIT, not 1."""

    def __init__(self, message: str):
        self.message = message
        print(message, file=sys.stderr, flush=True)
        super().__init__(ACCOUNT_REFUSAL_EXIT)

    def __str__(self) -> str:
        return self.message


def _acct_key(name: str) -> str:
    return str(name or "").strip().casefold()


def resolve_account(cmd: str) -> str:
    """Daemon/update/bootstrap default to watcher-eth-lc. mint defaults to watcher-eth.

    An explicit FPL_WATCHER_ACCOUNT still wins. The mint default must not be
    the relayer account, or a manual mint evicts the daemon.
    """
    raw = os.environ.get("FPL_WATCHER_ACCOUNT", "").strip()
    if cmd == "mint":
        return raw or MINT_ACCOUNT
    return raw or "watcher-eth-lc"


def assert_dedicated_account() -> None:
    """Refuse the BTC submitter and the auto-mint account.

    Compared casefolded and stripped. Sharing either account evicts the
    other daemon's mempool txs. host1's drop-in still says watcher-eth
    until it is changed; this fails loud instead of cross-evicting.
    """
    key = _acct_key(ACCOUNT)
    if key == _acct_key(BTC_WATCHER_ACCOUNT):
        raise AccountRefusal(
            "FPL_WATCHER_ACCOUNT is watcher-browser, which signs BTC headers. "
            "The ETH LC relayer daemon signs as watcher-eth-lc. "
            "Do not point this script at watcher-browser."
        )
    if key == _acct_key(MINT_ACCOUNT):
        raise AccountRefusal(
            "FPL_WATCHER_ACCOUNT is watcher-eth, which signs auto-mint. "
            "The ETH LC relayer daemon must sign as watcher-eth-lc or the two "
            "processes evict each other's mempool txs. "
            "On host1, create and fund watcher-eth-lc and point the relayer "
            "drop-in /etc/systemd/system/falcon-pl-eth-lc-relayer.service.d/account.conf "
            "at FPL_WATCHER_ACCOUNT=watcher-eth-lc in the same step as deploying "
            "this script. Leaving that drop-in on watcher-eth makes this process "
            "refuse to start. Leave the auto-mint drop-in on watcher-eth."
        )


def assert_mint_account() -> None:
    """Manual mint must not sign as the relayer daemon or the BTC submitter."""
    if _acct_key(ACCOUNT) == _acct_key(BTC_WATCHER_ACCOUNT):
        raise AccountRefusal(
            f"mint refuses {BTC_WATCHER_ACCOUNT}, the BTC submitter (sequences would race). "
            "Manual mint defaults to watcher-eth. "
            "Unset FPL_WATCHER_ACCOUNT or set it to watcher-eth."
        )
    if _acct_key(ACCOUNT) == "watcher-eth-lc" and not SHARED_SIGNER:
        raise AccountRefusal(
            "mint refuses watcher-eth-lc, the ETH LC relayer daemon. "
            "Manual mint defaults to watcher-eth. "
            "Unset FPL_WATCHER_ACCOUNT or set it to watcher-eth "
            "(not the relayer account)."
        )


# --- keccak-256 (Ethereum; not NIST SHA3) ---------------------------------


def _rotl64(x: int, n: int) -> int:
    n %= 64
    return ((x << n) | (x >> (64 - n))) & 0xFFFFFFFFFFFFFFFF


_RC = (
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808A,
    0x8000000080008000,
    0x000000000000808B,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008A,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000A,
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
)
_RHO = (
    0,
    1,
    62,
    28,
    27,
    36,
    44,
    6,
    55,
    20,
    3,
    10,
    43,
    25,
    39,
    41,
    45,
    15,
    21,
    8,
    18,
    2,
    61,
    56,
    14,
)


def keccak256(data: bytes) -> bytes:
    st = [0] * 25
    rate = 136
    buf = bytearray(data)
    n = rate - (len(buf) % rate)
    if n == 1:
        buf.append(0x81)
    else:
        buf.append(0x01)
        buf.extend(b"\x00" * (n - 2))
        buf.append(0x80)
    for off in range(0, len(buf), rate):
        block = buf[off : off + rate]
        for i in range(rate // 8):
            st[i] ^= int.from_bytes(block[i * 8 : (i + 1) * 8], "little")
        for rnd in range(24):
            c = [st[x] ^ st[x + 5] ^ st[x + 10] ^ st[x + 15] ^ st[x + 20] for x in range(5)]
            d = [c[(x - 1) % 5] ^ _rotl64(c[(x + 1) % 5], 1) for x in range(5)]
            for x in range(5):
                for y in range(5):
                    st[x + 5 * y] ^= d[x]
            t = [0] * 25
            for x in range(5):
                for y in range(5):
                    t[y + 5 * ((2 * x + 3 * y) % 5)] = _rotl64(st[x + 5 * y], _RHO[x + 5 * y])
            for x in range(5):
                for y in range(5):
                    st[x + 5 * y] = t[x + 5 * y] ^ ((~t[((x + 1) % 5) + 5 * y]) & t[((x + 2) % 5) + 5 * y])
            st[0] ^= _RC[rnd]
    out = bytearray()
    for i in range(4):
        out.extend(st[i].to_bytes(8, "little"))
    return bytes(out)


def dest20(account: str) -> str:
    return hashlib.sha256(account.strip().lower().encode()).hexdigest()[:40]


# --- RLP ------------------------------------------------------------------


def rlp_header(length: int, is_list: bool) -> bytes:
    offset = 0xC0 if is_list else 0x80
    if length < 56:
        return bytes([offset + length])
    lb = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([offset + 55 + len(lb)]) + lb


def rlp_bytes(b: bytes) -> bytes:
    if len(b) == 1 and b[0] < 0x80:
        return b
    return rlp_header(len(b), False) + b


def rlp_int(n: int) -> bytes:
    if n == 0:
        return rlp_bytes(b"")
    length = (n.bit_length() + 7) // 8
    return rlp_bytes(n.to_bytes(length, "big"))


def rlp_join(items: list[bytes]) -> bytes:
    payload = b"".join(items)
    return rlp_header(len(payload), True) + payload


def hx(s) -> bytes:
    t = str(s or "").strip()
    if t.startswith(("0x", "0X")):
        t = t[2:]
    if len(t) % 2:
        t = "0" + t
    return bytes.fromhex(t) if t else b""


def uhex(s) -> int:
    t = str(s or "0").strip()
    return int(t, 16) if t.startswith(("0x", "0X")) else int(t or "0")


# --- HTTP / RPC -----------------------------------------------------------


def http_get(url: str) -> object:
    req = urllib.request.Request(
        url, headers={"User-Agent": UA, "Accept": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read().decode())


# 2026-11-02: the Sepolia RPC (tenderly public gateway) answers bursts with
# HTTP 429. Retry 429 / 5xx / rate-limit JSON errors with exponential backoff
# (honouring Retry-After), so one throttled call no longer fails a scan span.
ETH_RPC_RETRIES = max(0, int(os.environ.get("ETH_RPC_RETRIES", "5")))
ETH_RPC_BACKOFF_SEC = max(0.1, float(os.environ.get("ETH_RPC_BACKOFF_SEC", "2")))
ETH_RPC_BACKOFF_MAX_SEC = max(1.0, float(os.environ.get("ETH_RPC_BACKOFF_MAX_SEC", "30")))
# Pause between eth_getLogs calls in the unminted scans, so a 50k-block window
# (~52 calls) is not fired as one burst.
ETH_SCAN_PACE_SEC = max(0.0, float(os.environ.get("ETH_SCAN_PACE_SEC", "1.0")))
_rpc_stats = {"retries": 0, "throttled": 0}


def _rate_limited_error(err) -> bool:
    t = str(err).lower()
    return any(w in t for w in ("rate limit", "too many requests", "429", "exceeded", "capacity"))


def _eth_rpc_once(method: str, params: list) -> object:
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(
        ETH_RPC,
        data=body,
        headers={
            "User-Agent": UA,
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    )
    with urllib.request.urlopen(req, timeout=60) as r:
        out = json.loads(r.read().decode())
    if out.get("error"):
        raise RuntimeError(f"{method}: {out['error']}")
    return out.get("result")


def eth_rpc(method: str, params: list) -> object:
    attempt = 0
    while True:
        try:
            return _eth_rpc_once(method, params)
        except urllib.error.HTTPError as e:
            retry = e.code == 429 or 500 <= e.code < 600
            wait_hdr = e.headers.get("Retry-After") if e.headers else None
            if e.code == 429:
                _rpc_stats["throttled"] += 1
            err = e
        except RuntimeError as e:
            retry = _rate_limited_error(e)
            wait_hdr = None
            err = e
        if not retry or attempt >= ETH_RPC_RETRIES:
            raise err
        delay = min(ETH_RPC_BACKOFF_MAX_SEC, ETH_RPC_BACKOFF_SEC * (2 ** attempt))
        try:
            if wait_hdr:
                delay = min(ETH_RPC_BACKOFF_MAX_SEC, max(delay, float(wait_hdr)))
        except ValueError:
            pass
        delay *= 1.0 + random.random() * 0.25
        attempt += 1
        _rpc_stats["retries"] += 1
        time.sleep(delay)


# --- ctl ------------------------------------------------------------------


def ctl(*args: str, timeout: int = 180) -> str:
    """Run falcon-pl-ctl. stdout on success.

    On a non-zero exit, raise CalledProcessError carrying stdout and stderr
    (stderr is still echoed to our stderr, as before), so callers can tell a
    transient node answer such as `deferred-until-catchup` from a real reject.
    """
    env = os.environ.copy()
    env["FPL_ADMIN_SOCK"] = ADMIN
    cmd = [str(CTL), "--addr", RPC, *args]
    r = subprocess.run(cmd, text=True, timeout=timeout, env=env, capture_output=True)
    if r.stderr:
        sys.stderr.write(r.stderr)
        sys.stderr.flush()
    if r.returncode != 0:
        raise subprocess.CalledProcessError(r.returncode, cmd, output=r.stdout, stderr=r.stderr)
    return r.stdout


def status() -> dict:
    raw = subprocess.check_output([str(CTL), "--addr", RPC, "status"], text=True, timeout=20)
    i = raw.find("{")
    body = json.JSONDecoder().raw_decode(raw[i:])[0]
    return body.get("body") or body


def account_sequence() -> int:
    """Committed next sequence. Ignores the mempool (ctl resolve_seq does too).

    `falcon-pl-ctl account` prints WireMsg::Account: {"type":"account","body":{"sequence":N}}.
    That N is the next sequence a committed tx may use. A tx already in the
    mempool at N is invisible here, which is why callers must not re-read N
    for a follow-up tx.
    """
    raw = ctl("account", "--account", ACCOUNT, timeout=20)
    i = raw.find("{")
    if i < 0:
        raise RuntimeError(f"account query not json: {raw[:200]}")
    msg = json.JSONDecoder().raw_decode(raw[i:])[0]
    body = msg.get("body") if isinstance(msg, dict) else None
    if not isinstance(body, dict) or "sequence" not in body:
        raise RuntimeError(f"account query missing sequence: {raw[:200]}")
    return int(body["sequence"])


def _now() -> float:
    """Clock for the stuck-floor timeout. Tests patch this."""
    return time.monotonic()


def account_mempool_sequences() -> set[int] | None:
    """Sequences of this account still in the mempool, or None if unknown.

    None is the only result today. `falcon-pl-ctl status` reports `mempool`
    as a count. WireMsg has no query that lists mempool txs, and ctl has no
    subcommand for one account or one sequence. A count cannot say whether
    sequence N is still sitting there or the packer already dropped it.
    """
    return None


def _reset_stuck_floor(committed: int, why: str) -> None:
    """Drop the in-memory floor back to the committed sequence and log why."""
    global _seq_floor, _seq_stuck_since, _stuck_watch_committed
    print(
        f"WARNING sequence floor {_seq_floor} above committed {committed}: {why} "
        f"Resetting the floor to {committed} and resubmitting. "
        "submit_tx_inner evicts and replaces only this account's tx at that sequence.",
        flush=True,
    )
    _seq_floor = committed
    _seq_stuck_since = None
    _stuck_watch_committed = committed


def _stuck_should_reset(committed: int, now: float) -> bool:
    """True when it is safe to reuse the committed sequence.

    If a mempool view exists, reset only when every reserved sequence is
    confirmed gone. A sequence still listed is not reused, timeout or not.
    With no view (this node), reset after ETH_SEQ_STUCK_SEC. A tx that was
    still valid would have packed within a few blocks; resubmitting at the
    committed sequence replaces only our own stale tx.
    """
    global _seq_stuck_since, _stuck_watch_committed
    if _stuck_watch_committed is None:
        _stuck_watch_committed = committed
    elif committed > _stuck_watch_committed:
        # The chain is packing. Restart the clock so a long header run that
        # is still making progress never hits the 180s reset.
        _stuck_watch_committed = committed
        _seq_stuck_since = now
    if _seq_stuck_since is None:
        _seq_stuck_since = now
    visible = account_mempool_sequences()
    if visible is not None:
        inflight = set(range(committed, _seq_floor))
        still = sorted(inflight & set(visible))
        if still:
            return False
        _reset_stuck_floor(
            committed,
            "in-flight sequences are not in the mempool (packer dropped them).",
        )
        return True
    elapsed = now - float(_seq_stuck_since)
    if elapsed < SEQ_STUCK_SEC:
        return False
    _reset_stuck_floor(
        committed,
        "no mempool listing on this node (status mempool is a count only; "
        "ctl has no per-account mempool query); "
        f"floor stuck for {int(elapsed)}s (ETH_SEQ_STUCK_SEC={int(SEQ_STUCK_SEC)}). "
        "A tx that was still valid would have packed within a few blocks.",
    )
    return True


def alloc_fresh(n: int) -> list[int]:
    """Reserve n consecutive sequences for a new chain.

    Refuses while this process still has a submitted sequence the account
    query has not passed, until the stuck timeout (or a mempool view says
    those sequences are gone). Reusing earlier would evict a tx that is
    still in the mempool. After the timeout the floor resets to the
    committed sequence so a packer drop cannot stall the daemon until a
    manual restart.
    """
    global _seq_floor, _seq_stuck_since, _stuck_watch_committed
    if n <= 0:
        return []
    committed = account_sequence()
    now = _now()
    if committed >= _seq_floor:
        _seq_floor = committed
        _seq_stuck_since = None
        _stuck_watch_committed = committed
    elif not _stuck_should_reset(committed, now):
        elapsed = 0 if _seq_stuck_since is None else now - float(_seq_stuck_since)
        left = max(0, int(SEQ_STUCK_SEC - elapsed))
        visible = account_mempool_sequences()
        inflight = set(range(committed, _seq_floor))
        if visible is not None and inflight & set(visible):
            extra = (
                f"sequence(s) {sorted(inflight & set(visible))} are still in the mempool; "
                "not resetting."
            )
        else:
            extra = (
                f"Will reset in {left}s if still uncommitted "
                f"(ETH_SEQ_STUCK_SEC={int(SEQ_STUCK_SEC)})."
            )
        raise SequenceInFlight(
            f"refusing submit: committed next sequence is {committed} but "
            f"{_seq_floor - committed} sequence(s) are still in flight "
            f"(next free {_seq_floor}). {extra}"
        )
    seqs = list(range(committed, committed + n))
    _seq_floor = seqs[-1] + 1
    _stuck_watch_committed = committed
    if _seq_stuck_since is None:
        _seq_stuck_since = now
    return seqs


def alloc_follow(n: int) -> list[int]:
    """Reserve the next n sequences after ones just submitted. Does not re-read.

    Re-reading would hand back the committed sequence and evict the tx that
    is still in the mempool.
    """
    global _seq_floor
    if n <= 0:
        return []
    start = _seq_floor
    seqs = list(range(start, start + n))
    _seq_floor = seqs[-1] + 1
    return seqs


def release_unsent_from(seq: int) -> None:
    """Drop reservations at and after seq. Those ctl calls did not succeed."""
    global _seq_floor
    if _seq_floor > seq:
        _seq_floor = seq


def submit(kind: str, path: Path, sequence: int | None = None) -> str:
    """Submit one ctl tx.

    sequence is None for submit-eth-lc-update and submit-eth-lc-bootstrap.
    Those commands have no --sequence flag; ctl resolve_seq(0) uses the
    committed account sequence. Callers must have just read that sequence
    and must pass explicit sequence numbers for every later tx in the chain.

    A non-zero sequence is passed as --sequence. Zero is omitted because ctl
    treats --sequence 0 as "re-read the committed sequence", not as sequence 0.
    """
    args = [
        kind,
        "--account",
        ACCOUNT,
        "--json-file",
        str(path),
        "--scheme",
        SCHEME,
        "--keys-dir",
        KEYS,
        "--network-id",
        NETWORK_ID,
        "--fee",
        "2",
    ]
    if sequence is not None and sequence > 0:
        args.extend(["--sequence", str(sequence)])
    elif sequence == 0:
        print(
            "exec header sequence 0: omitting --sequence (ctl treats 0 as re-read)",
            flush=True,
        )
    out = ctl(*args)
    print(out[-500:], flush=True)
    return out


def beacon_finality_slot() -> int:
    fin = unwrap_lc_update(http_get(f"{BEACON}/eth/v1/beacon/light_client/finality_update"))
    return _finalized_slot(fin)


def lc_behind_beacon() -> tuple[bool, int, int]:
    st = status()
    lc = st.get("eth_lc") or {}
    cur = int(lc.get("finalized_slot") or 0)
    fin = beacon_finality_slot()
    return fin > cur, fin, cur


def wait_lc(pred, tries: int = 60, label: str = "lc") -> dict:
    last = {}
    for i in range(tries):
        st = status()
        last = st.get("eth_lc") or {}
        if pred(last):
            return last
        print(f"  wait {label} {last} ({i+1}/{tries})", flush=True)
        time.sleep(2)
    raise SystemExit(f"timeout waiting {label}: {last}")


# --- execution header / receipt MPT ---------------------------------------


def _header_field_present(block: dict, key: str) -> bool:
    """True when eth_getBlock JSON carries a real value (not null / empty)."""
    if key not in block or block[key] is None:
        return False
    v = block[key]
    return not (isinstance(v, str) and v.strip() in ("", "0x", "0X"))


def encode_exec_header(block: dict) -> bytes:
    nonce = hx(block.get("nonce"))
    if len(nonce) != 8:
        nonce = nonce.rjust(8, b"\x00")[-8:]
    items = [
        rlp_bytes(hx(block["parentHash"])),
        rlp_bytes(hx(block["sha3Uncles"])),
        rlp_bytes(hx(block["miner"])),
        rlp_bytes(hx(block["stateRoot"])),
        rlp_bytes(hx(block["transactionsRoot"])),
        rlp_bytes(hx(block["receiptsRoot"])),
        rlp_bytes(hx(block["logsBloom"])),
        rlp_int(uhex(block.get("difficulty") or "0x0")),
        rlp_int(uhex(block["number"])),
        rlp_int(uhex(block["gasLimit"])),
        rlp_int(uhex(block["gasUsed"])),
        rlp_int(uhex(block["timestamp"])),
        rlp_bytes(hx(block.get("extraData"))),
        rlp_bytes(hx(block.get("mixHash"))),
        rlp_bytes(nonce),
        rlp_int(uhex(block["baseFeePerGas"])),
        rlp_bytes(hx(block.get("withdrawalsRoot") or block.get("withdrawalsHash"))),
        rlp_int(uhex(block.get("blobGasUsed") or "0x0")),
        rlp_int(uhex(block.get("excessBlobGas") or "0x0")),
        rlp_bytes(hx(block.get("parentBeaconBlockRoot"))),
        rlp_bytes(hx(block.get("requestsHash"))),
    ]
    # Amsterdam execution header: blockAccessListHash (bytes32) then slotNumber
    # (uint), after requestsHash. Omitted when the EL JSON does not carry them,
    # so pre-Amsterdam blocks stay byte-identical. FPL checks keccak(rlp) == hash
    # and ignores trailing fields (eth_exec.rs decode_exec_header_meta).
    if _header_field_present(block, "blockAccessListHash"):
        items.append(rlp_bytes(hx(block.get("blockAccessListHash"))))
    if _header_field_present(block, "slotNumber"):
        items.append(rlp_int(uhex(block.get("slotNumber"))))
    return rlp_join(items)


def header_obj(block: dict) -> dict:
    rlp = encode_exec_header(block)
    got = keccak256(rlp).hex()
    want = hx(block["hash"]).hex()
    if got != want:
        raise RuntimeError(f"header rlp hash mismatch got={got} want={want} n={block.get('number')}")
    return {
        "number": uhex(block["number"]),
        "hash": want,
        "parent_hash": hx(block["parentHash"]).hex(),
        "receipts_root": hx(block["receiptsRoot"]).hex(),
        "rlp_hex": rlp.hex(),
    }


def encode_receipt(rec: dict) -> bytes:
    status = uhex(rec.get("status") or "0x1")
    cum = uhex(rec.get("cumulativeGasUsed") or "0x0")
    bloom = hx(rec.get("logsBloom"))
    if len(bloom) != 256:
        bloom = bloom.rjust(256, b"\x00")[-256:]
    logs = []
    for lg in rec.get("logs") or []:
        addr = hx(lg.get("address"))
        topics = [rlp_bytes(hx(t)) for t in (lg.get("topics") or [])]
        data = hx(lg.get("data"))
        logs.append(rlp_join([rlp_bytes(addr), rlp_join(topics), rlp_bytes(data)]))
    body = rlp_join([rlp_int(status), rlp_int(cum), rlp_bytes(bloom), rlp_join(logs)])
    tx_type = uhex(rec.get("type") or "0x0")
    if tx_type == 0:
        return body
    return bytes([tx_type]) + body


class NibTree:
    def __init__(self) -> None:
        self.children: dict[int, NibTree] = {}
        self.value: bytes | None = None

    def insert(self, nibs: list[int], val: bytes) -> None:
        n = self
        for x in nibs:
            n = n.children.setdefault(x, NibTree())
        n.value = val


def _to_mpt(n: NibTree):
    ch = sorted(n.children.items())
    if n.value is not None and not ch:
        return ("leaf", [], n.value)
    if n.value is None and len(ch) == 1:
        nib, child = ch[0]
        sub = _to_mpt(child)
        if sub[0] == "leaf":
            return ("leaf", [nib] + sub[1], sub[2])
        if sub[0] == "ext":
            return ("ext", [nib] + sub[1], sub[2])
        return ("ext", [nib], sub)
    kids: list = [None] * 16
    for nib, child in ch:
        kids[nib] = _to_mpt(child)
    return ("branch", kids, n.value)


def _hp(nibs: list[int], is_leaf: bool) -> bytes:
    odd = len(nibs) & 1
    flags = (0x20 if is_leaf else 0x00) | (0x10 if odd else 0x00)
    if odd:
        out = bytes([flags | nibs[0]])
        rest = nibs[1:]
    else:
        out = bytes([flags])
        rest = nibs
    for i in range(0, len(rest), 2):
        out += bytes([(rest[i] << 4) | rest[i + 1]])
    return out


def _encode_node(node) -> bytes:
    kind = node[0]
    if kind == "leaf":
        _, path, val = node
        return rlp_join([rlp_bytes(_hp(path, True)), rlp_bytes(val)])
    if kind == "ext":
        _, path, child = node
        raw = _encode_node(child)
        ref = raw if len(raw) < 32 else keccak256(raw)
        return rlp_join([rlp_bytes(_hp(path, False)), rlp_bytes(ref) if len(raw) >= 32 else raw])
    _, kids, val = node
    items = []
    for k in kids:
        if k is None:
            items.append(rlp_bytes(b""))
        else:
            raw = _encode_node(k)
            items.append(raw if len(raw) < 32 else rlp_bytes(keccak256(raw)))
    items.append(rlp_bytes(val if val is not None else b""))
    return rlp_join(items)


def _prove(node, key: list[int]) -> list[bytes]:
    out = []
    while True:
        out.append(_encode_node(node))
        kind = node[0]
        if kind == "leaf":
            break
        if kind == "ext":
            _, path, child = node
            if key[: len(path)] != path:
                raise RuntimeError("mpt ext path")
            key = key[len(path) :]
            node = child
            continue
        _, kids, _val = node
        if not key:
            break
        n = key[0]
        key = key[1:]
        node = kids[n]
        if node is None:
            raise RuntimeError("mpt missing child")
    return out


def nibbles(b: bytes) -> list[int]:
    o = []
    for x in b:
        o.append(x >> 4)
        o.append(x & 0x0F)
    return o


def receipt_index_key(index: int) -> bytes:
    return rlp_int(index)


def build_receipt_proof(receipts: list[dict], tx_index: int) -> tuple[str, str, list[str], bytes]:
    encoded = [encode_receipt(r) for r in receipts]
    tree = NibTree()
    for i, raw in enumerate(encoded):
        tree.insert(nibbles(receipt_index_key(i)), raw)
    root_node = _to_mpt(tree)
    root_rlp = _encode_node(root_node)
    root = keccak256(root_rlp).hex()
    nodes = _prove(root_node, nibbles(receipt_index_key(tx_index)))
    return root, encoded[tx_index].hex(), [n.hex() for n in nodes], encoded[tx_index]


def block_receipts(block_hex: str, tx_hashes: list[str]) -> list[dict]:
    try:
        rows = eth_rpc("eth_getBlockReceipts", [block_hex])
        if isinstance(rows, list) and rows:
            rows.sort(key=lambda r: uhex(r.get("transactionIndex") or "0x0"))
            return rows
    except Exception as e:
        print(f"eth_getBlockReceipts fallback: {e}", flush=True)
    out = []
    for h in tx_hashes:
        rec = eth_rpc("eth_getTransactionReceipt", [h])
        if not rec:
            raise RuntimeError(f"missing receipt {h}")
        out.append(rec)
    out.sort(key=lambda r: uhex(r.get("transactionIndex") or "0x0"))
    return out


def fetch_header(number: int) -> dict:
    b = eth_rpc("eth_getBlockByNumber", [hex(number), False])
    if not b:
        raise RuntimeError(f"no block {number}")
    return header_obj(b)


# --- LC commands ----------------------------------------------------------


def cmd_bootstrap() -> None:
    st = status()
    if st.get("eth_lc"):
        print("ETH LC already live", st["eth_lc"], flush=True)
        return
    if not BOOT.exists():
        raise SystemExit(f"missing bootstrap {BOOT}")
    doc = json.loads(BOOT.read_text())
    num, head = bootstrap_exec_ref(doc)
    headers: list[dict] = []
    if num == 0 and head:
        # Nothing is stored yet. The batch is the single head header, submitted
        # with the bootstrap before any inclusion wait and before any mint.
        headers, _end_n = prepare_hash_only_headers({"eth_exec_tip": 0}, head)
    print(f"bootstrap {BOOT} bytes={BOOT.stat().st_size}", flush=True)
    submit_lc_then_headers("submit-eth-lc-bootstrap", BOOT, headers)


def unwrap_lc_update(data: object) -> dict:
    """Normalize beacon updates/finality JSON to {"data": payload}.

    Lodestar returns a list, a {"data": ...} object, or a versioned envelope
    {"version": "...", "data": ...}, and the same envelopes can wrap
    attested/finalized headers. FPL reads the inner "data" object.
    """
    obj = data[0] if isinstance(data, list) and data else (None if isinstance(data, list) else data)
    if not isinstance(obj, dict):
        raise ValueError("empty light-client response")
    payload_keys = ("attested_header", "finalized_header", "header", "sync_aggregate")
    for _ in range(3):
        if any(k in obj for k in payload_keys):
            break
        inner = obj.get("data")
        if isinstance(inner, list):
            inner = inner[0] if inner else None
        if not isinstance(inner, dict):
            break
        obj = inner
    if not any(k in obj for k in payload_keys):
        raise ValueError("light-client response has no update body")
    obj = dict(obj)
    for key in ("attested_header", "finalized_header", "header"):
        h = obj.get(key)
        if (
            isinstance(h, dict)
            and "beacon" not in h
            and "slot" not in h
            and isinstance(h.get("data"), dict)
        ):
            obj[key] = h["data"]
    return {"data": obj}


def catchup_periods(lc_period: int, beacon_period: int) -> list[int]:
    """start_period values to submit before finality_update.

    The LC is behind while its period is less than the beacon's current
    period (signature slot of finality_update // SLOTS_PER_PERIOD). The
    update for period P finalizes a header in P, so it advances an LC at
    P-1. Fetch P = lc_period+1, ..., beacon_period, one at a time. An empty
    list means the stored period has caught the beacon and finality_update
    is next. (The period the LC already sits in is not re-fetched here; a
    missing next committee is a separate updates?start_period=lc_period.)
    """
    lc_period = int(lc_period)
    beacon_period = int(beacon_period)
    if beacon_period <= lc_period:
        return []
    return list(range(lc_period + 1, beacon_period + 1))


def _norm_hash(s) -> str:
    return str(s or "").strip().lower().removeprefix("0x")


def _exec_from_header(h: dict) -> tuple[int, str]:
    """(block number, hash) from one light-client header.

    Number is 0 when the header carries only execution_block_hash (Gloas).
    A pre-Gloas execution payload yields its block_number.
    """
    if not isinstance(h, dict):
        return 0, ""
    ex = h.get("execution")
    if isinstance(ex, dict):
        num = ex.get("block_number", ex.get("blockNumber"))
        bh = ex.get("block_hash", ex.get("blockHash", ""))
        if num is not None:
            n = int(num) if isinstance(num, int) else uhex(num)
            return n, _norm_hash(bh)
    return 0, _norm_hash(h.get("execution_block_hash"))


def _peel_header(h: dict) -> dict:
    if (
        isinstance(h, dict)
        and "beacon" not in h
        and "slot" not in h
        and isinstance(h.get("data"), dict)
    ):
        return h["data"]
    return h


def finalized_exec_ref(blob: dict) -> tuple[int, str]:
    """(block number, hash) from an update/finality finalized header."""
    d = blob.get("data") or blob
    if not isinstance(d, dict):
        return 0, ""
    return _exec_from_header(_peel_header(d.get("finalized_header") or {}))


def bootstrap_exec_ref(doc: object) -> tuple[int, str]:
    """(block number, hash) from an LC bootstrap JSON document."""
    if not isinstance(doc, dict):
        return 0, ""
    data = doc.get("data") if isinstance(doc.get("data"), dict) else doc
    if not isinstance(data, dict):
        return 0, ""
    return _exec_from_header(_peel_header(data.get("header") or {}))


def hash_only_head(lc: dict | None, blob: dict | None = None) -> str:
    """Execution hash when the LC head has no block number, else ""."""
    if lc:
        n = int(lc.get("execution_number") or 0)
        h = _norm_hash(lc.get("execution_block_hash"))
        if n != 0:
            return ""
        if h:
            return h
    if blob:
        num, h = finalized_exec_ref(blob)
        if num == 0 and h:
            return h
    return ""


def mint_head_ready(lc: dict, dep_n: int) -> bool:
    """True when dep_n is covered by a numbered LC execution head.

    execution_number == 0 with a hash is a Gloas head whose block number is
    not known yet. It is not block 0, and it must not open an empty header walk.
    A true result only starts the header walk. The rail-deposit mint stays
    gated on lc_head_resolved (stored header at the LC hash).
    """
    n = int((lc or {}).get("execution_number") or 0)
    if n == 0 and _norm_hash((lc or {}).get("execution_block_hash")):
        return False
    return int(dep_n) <= n


def lc_head_resolved(lc: dict | None) -> bool:
    """True when status shows the LC execution head is stored.

    execution_number != 0 and eth_exec_tip reaches that number. On Gloas the
    node copies the number from the stored header whose hash is
    execution_block_hash, so a hash-only head (number 0) is not resolved.
    """
    if not isinstance(lc, dict):
        return False
    n = int(lc.get("execution_number") or 0)
    if n == 0 or not _norm_hash(lc.get("execution_block_hash")):
        return False
    return int(lc.get("eth_exec_tip") or 0) >= n


def _finalized_slot(blob: dict) -> int:
    d = blob.get("data") or blob
    h = d.get("finalized_header") or {}
    b = h.get("beacon") or h
    return int(b.get("slot") or 0)


def _sig_slot(blob: dict) -> int:
    d = blob.get("data") or blob
    return int(d.get("signature_slot") or 0)


_tmp_dir: Path | None = None


def _tmp_path(name: str) -> Path:
    """Per-process scratch file for a ctl --json-file / --*-file argument.

    The daemon (watcher-eth-lc) and a minter (watcher-eth, via auto-mint or
    the mint subcommand) run as separate processes. A shared /tmp name let
    one overwrite the other's file before its ctl read it, so a reserved
    sequence could sign the other process's batch. Each process gets its own
    mkdtemp directory (mode 0700), removed at exit. Submissions within one
    process are sequential, so the basename can stay fixed.
    """
    global _tmp_dir
    if _tmp_dir is None or not _tmp_dir.is_dir():
        _tmp_dir = Path(tempfile.mkdtemp(prefix="fpl-eth-lc-"))
        atexit.register(shutil.rmtree, str(_tmp_dir), True)
    return _tmp_dir / name


def _write_update(blob: dict, name: str) -> Path:
    tmp = _tmp_path(name)
    tmp.write_text(json.dumps(blob))
    return tmp


def cmd_update(*, soft: bool = False) -> dict:
    st = status()
    lc = st.get("eth_lc")
    if not lc:
        raise SystemExit("bootstrap first")
    pack_wait = int(os.environ.get("PACK_WAIT_TRIES", "90" if soft else "60"))

    # A previous Gloas update may have left a hash-only head. Resolve it
    # before asking the beacon to move again.
    lc = _resolve_hash_only(lc, soft=soft)
    period = int(lc.get("period") or 0)
    cur_slot = int(lc.get("finalized_slot") or 0)
    next_pks = int(lc.get("next_pks") or 0)

    fin = unwrap_lc_update(http_get(f"{BEACON}/eth/v1/beacon/light_client/finality_update"))
    beacon_period = _sig_slot(fin) // SLOTS_PER_PERIOD
    fin_slot = _finalized_slot(fin)
    print(
        f"finality sig_period={beacon_period} lc_period={period} fin_slot={fin_slot} cur={cur_slot} next_pks={next_pks}",
        flush=True,
    )

    # Altair: a proof is valid only for the current committee period or the next.
    # Jumping to today's finality while several periods behind is accepted into
    # the mempool and then dropped at pack — that is why the LC froze.
    if next_pks == 0:
        raw = http_get(
            f"{BEACON}/eth/v1/beacon/light_client/updates?start_period={period}&count=1"
        )
        one = unwrap_lc_update(raw)
        lc2 = _apply_lc_update(
            lc,
            one,
            "sepolia-lc-next.json",
            lambda x: int(x.get("next_pks") or 0) == 512,
            "next_pks",
            tag=f"next-committee period={period}",
            soft=soft,
            tries=pack_wait if not soft else min(pack_wait, 20),
        )
        if lc2 is None:
            return status().get("eth_lc") or lc
        lc = lc2
        period = int(lc.get("period") or 0)
        cur_slot = int(lc.get("finalized_slot") or 0)

    # One sync period at a time until the LC period catches the beacon.
    # finality_update is submitted only after this loop.
    for nxt in catchup_periods(period, beacon_period):
        raw = http_get(
            f"{BEACON}/eth/v1/beacon/light_client/updates?start_period={nxt}&count=1"
        )
        one = unwrap_lc_update(raw)
        lc2 = _apply_lc_update(
            lc,
            one,
            "sepolia-lc-period.json",
            lambda x, want=nxt: int(x.get("period") or 0) >= want,
            f"period>={nxt}",
            tag=f"period catch-up {period} → {nxt} (beacon at {beacon_period})",
            soft=soft,
            tries=pack_wait if not soft else min(pack_wait, 30),
        )
        if lc2 is None:
            return status().get("eth_lc") or lc
        lc = lc2
        period = int(lc.get("period") or 0)
        cur_slot = int(lc.get("finalized_slot") or 0)

    if fin_slot <= cur_slot:
        print("LC already at/past finality_update", flush=True)
        return _resolve_hash_only(lc, fin, soft=soft)

    lc2 = _apply_lc_update(
        lc,
        fin,
        "sepolia-lc-finality.json",
        lambda x, want=fin_slot: int(x.get("finalized_slot") or 0) >= want,
        "finalized_slot",
        tag=f"finality → slot {fin_slot}",
        soft=soft,
        tries=pack_wait,
    )
    if lc2 is None:
        return status().get("eth_lc") or lc
    return lc2


def cmd_daemon() -> None:
    poll = int(os.environ.get("POLL_SEC", "10"))
    poll_behind = int(os.environ.get("POLL_SEC_BEHIND", "5"))
    while True:
        with SignerLock(ACCOUNT):
            try:
                st = status()
                if not st.get("eth_lc"):
                    cmd_bootstrap()
                else:
                    cmd_update(soft=True)
            except Exception as e:
                print(f"WARN {e}", flush=True)
            except SystemExit as e:
                # wait_lc() uses SystemExit; that must not kill the daemon.
                print(f"WARN {e}", flush=True)
            try:
                backfill_exec_hole(status())
            except Exception as e:
                print(f"WARN backfill {e}", flush=True)
            except SystemExit as e:
                print(f"WARN backfill {e}", flush=True)
            if SHARED_SIGNER:
                drain_own_sequences()
        # Fresh status every pass. A failed status() must not leave the V3
        # scan holding an older st whose eth_v3_resolutions predate a mint
        # (false "unminted V3 deposit" alerts after a node outage).
        st = None
        try:
            st = status()
            note_exec_head(st.get("eth_lc") or {})
            scan_unminted_deposits(st)
        except Exception as e:
            print(f"WARN alert {e}", flush=True)
        try:
            if st is None:
                raise RuntimeError("no fresh node status; skipping V3 unminted check")
            scan_unminted_v3_deposits(st)
        except Exception as e:
            print(f"WARN v3 alert {e}", flush=True)
        try:
            behind, fin, cur = lc_behind_beacon()
            if behind:
                print(f"LC behind beacon fin={fin} cur={cur} — retry in {poll_behind}s", flush=True)
                time.sleep(poll_behind)
            else:
                time.sleep(poll)
        except Exception as e:
            print(f"WARN beacon poll {e}", flush=True)
            time.sleep(poll)


# Public 2300 packs up to 128 txs (pl-start-public-2300.sh --max-txs 128).
# The LedgerBody lane drops a line once used+len exceeds BODY_QUEUE_BYTES
# (falcon_pl_node.rs, 4 * 1024 * 1024). An Amsterdam exec header JSON is
# 1,653 bytes in scripts/fixtures/gloas/exec-headers-amsterdam.json (fd-pl); a
# 32-header chunk is 52,896 bytes. 128 of those are 6,770,688 bytes, past
# the 4 MiB lane, so QC peers never get the body. A wave is capped at 2 MiB
# of serialized header JSON so one packed wave, plus the LC update and the
# ledger envelope, stays under that lane.
#
# The cap counts the header JSON only (json.dumps of each chunk). The tx and
# ledger envelope around it adds roughly 6% on the wire (2 MiB of header JSON
# is about 2.13 MiB in the body), and the LC update rides in the first wave.
# That is why the cap is half the lane and not the lane: do not raise the
# upper clamp toward 4 MiB. ETH_HEADER_WAVE_BYTES can only lower it, to no
# less than HEADER_WAVE_MIN (64 KiB, about 40 Amsterdam headers).
LEDGER_BODY_MAX = 4 * 1024 * 1024
HEADER_WAVE_DEFAULT = 2 * 1024 * 1024
HEADER_WAVE_MIN = 64 * 1024
_LC_WAVE_RESERVE = 64 * 1024
# (env name, raw value) pairs already warned about, so a bad env value warns once
# per process instead of on every call (header_wave_bytes runs 2-3 times per
# submission).
_env_warned: set[tuple[str, str]] = set()


def _warn_env_once(name: str, raw: str, msg: str) -> None:
    key = (name, str(raw))
    if key in _env_warned:
        return
    _env_warned.add(key)
    print(f"WARNING {name}={raw!r} {msg}", flush=True)


def _env_bytes(name: str, default: int, lo: int, hi: int) -> int:
    """Byte-size env knob. Junk, non-finite, 0 or negative use the default.

    A positive value below lo is raised to lo and one above hi lowered to hi,
    with one WARNING per distinct raw value.
    """
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        n = float(raw)
    except ValueError:
        _warn_env_once(name, raw, f"not a number; using {default}")
        return default
    if not math.isfinite(n) or n <= 0:
        _warn_env_once(name, raw, f"not a positive finite size; using {default}")
        return default
    n = int(n)
    if n < lo:
        _warn_env_once(name, raw, f"below the {lo}-byte floor; using {lo}")
        return lo
    if n > hi:
        _warn_env_once(name, raw, f"above the {hi}-byte cap; using {hi}")
        return hi
    return n


def header_wave_bytes() -> int:
    """Serialized header-JSON budget for one in-flight wave. 64 KiB..2 MiB.

    Default is 2 MiB, half of LEDGER_BODY_MAX, because the cap counts header
    JSON only (see the comment above). Junk, non-finite, 0 and negative use
    the default. A small positive value is raised to HEADER_WAVE_MIN. The
    upper clamp is the safety cap, not a request.
    """
    return _env_bytes("ETH_HEADER_WAVE_BYTES", HEADER_WAVE_DEFAULT, HEADER_WAVE_MIN, HEADER_WAVE_DEFAULT)


def header_chunk_bytes(wave: int | None = None) -> int:
    """Byte cap for one header tx. Default 256 KiB, kept within 64 KiB..wave.

    Junk, non-finite, 0 and negative use the default. A header bigger than
    this cap is refused (see header_chunks), so the floor keeps a misset knob
    from refusing every real ~1.7 KB header.
    """
    wave = header_wave_bytes() if wave is None else wave
    default = min(wave, 256 * 1024)
    return _env_bytes("ETH_HEADER_CHUNK_BYTES", default, min(HEADER_WAVE_MIN, wave), wave)


class OversizeHeader(RuntimeError):
    """One exec header is over the per-tx byte cap. Nothing was submitted."""


def _json_len(obj) -> int:
    return len(json.dumps(obj).encode())


def header_chunks(headers: list[dict]) -> list[list[dict]]:
    """Newest-first batches. Each batch is at most HEADER_CHUNK headers and header_chunk_bytes().

    A single header that is already over the byte cap is refused: ALERT,
    then OversizeHeader, before any sequence is reserved or any tx (LC
    update included) is submitted. Both callers chunk before alloc, so the
    floor is untouched and the next loop starts clean.

    Why refuse and not skip or submit alone. The batch is a parent-linked
    walk ending at the LC hash; skipping one header breaks connects_down and
    the head never resolves. Submitting it alone could exceed the 4 MiB lane
    and be dropped by every QC peer, which resubmits forever. A valid
    execution header is fixed-size apart from extraData (max 32 bytes), about
    1.7 KB, so with the 64 KiB floor on the cap this only fires on a broken
    or hostile RPC response. Refusing keeps the head hash-only, which the
    stale-head ALERT also reports, and the next loop retries.
    """
    count_cap = HEADER_CHUNK if HEADER_CHUNK > 0 else 32
    byte_cap = header_chunk_bytes()
    for h in headers:
        n = _json_len([h])
        if n > byte_cap:
            line = (
                f"ALERT exec header {h.get('number')} is {n} bytes, over the "
                f"ETH_HEADER_CHUNK_BYTES cap {byte_cap}; refusing the batch "
                "(no LC update and no headers submitted). Check ETH_RPC."
            )
            print(line, flush=True)
            raise OversizeHeader(line)
    chunks: list[list[dict]] = []
    i = len(headers)
    while i > 0:
        start = max(0, i - count_cap)
        j = start
        while j < i - 1 and _json_len(headers[j:i]) > byte_cap:
            j += 1
        chunks.append(headers[j:i])
        i = j
    return chunks


def pack_header_waves(chunks: list[list[dict]], *, with_lc: bool = False) -> list[list[list[dict]]]:
    """Group chunks so each wave's serialized JSON stays under the wave cap.

    The first wave leaves room for the LC update tx when with_lc is set.
    Later waves use the full cap. One chunk that is itself over the budget
    is a wave of its own.
    """
    cap = header_wave_bytes()
    # Chunks are at most header_chunk_bytes() <= cap. The first wave's LC
    # reserve can still leave one chunk over the reduced budget; it then goes
    # alone, and cap + reserve stays far under LEDGER_BODY_MAX.
    reserve = min(_LC_WAVE_RESERVE, cap // 4) if with_lc else 0
    budget = max(1, cap - reserve)
    waves: list[list[list[dict]]] = []
    cur: list[list[dict]] = []
    used = 0
    for ch in chunks:
        n = _json_len(ch)
        if cur and used + n > budget:
            waves.append(cur)
            cur = []
            used = 0
            budget = cap
        if not cur and n > budget:
            print(
                f"WARN header chunk {n} bytes exceeds the wave budget {budget}",
                flush=True,
            )
        cur.append(ch)
        used += n
    if cur:
        waves.append(cur)
    return waves


def submit_headers(headers: list[dict], sequence: int | None = None) -> None:
    if not headers:
        return
    tmp = _tmp_path("sepolia-exec-headers.json")
    tmp.write_text(json.dumps(headers))
    seq = "" if sequence is None else f" seq={sequence}"
    print(
        f"exec headers {headers[0]['number']}..{headers[-1]['number']} "
        f"n={len(headers)} bytes={tmp.stat().st_size}{seq}",
        flush=True,
    )
    # No sleep. A delay does not move the committed sequence, so the next
    # chunk would still re-read N and evict this one. The caller passes
    # distinct --sequence values instead.
    submit("submit-eth-exec-headers", tmp, sequence=sequence)


# Node answers that mean "not now", not "no". A header chunk that hits one is
# resubmitted at the same sequence instead of abandoning the rest of the walk.
# Before this, one `deferred-until-catchup` (the RPC node a block behind a
# peer) dropped the remaining lower chunks, and since the next loop only
# fetches above the stored exec tip, that range stayed a permanent hole
# (9 Oct 2026: Sepolia 11856687..11859306).
TRANSIENT_SUBMIT_MARKERS = (
    "deferred-until-catchup",
    "connection refused",
    "connection reset",
    "broken pipe",
    "os error 111",
    "os error 104",
    "pl rpc closed",
)


def _ctl_error_text(e: BaseException) -> str:
    parts = [str(e)]
    for attr in ("output", "stderr"):
        v = getattr(e, attr, None)
        if isinstance(v, bytes):
            v = v.decode("utf-8", "replace")
        if v:
            parts.append(str(v))
    return " ".join(parts).lower()


def is_transient_submit_error(e: BaseException) -> bool:
    """True for a ctl failure whose text is a known transient node answer."""
    if not isinstance(e, subprocess.CalledProcessError):
        return False
    text = _ctl_error_text(e)
    return any(m in text for m in TRANSIENT_SUBMIT_MARKERS)


def submit_retries() -> int:
    """ETH_SUBMIT_RETRIES, default 5, clamped 0..20 (0 = no retry)."""
    raw = os.environ.get("ETH_SUBMIT_RETRIES", "").strip()
    if not raw:
        return 5
    try:
        n = int(raw)
    except ValueError:
        _warn_env_once("ETH_SUBMIT_RETRIES", raw, "not an integer; using 5")
        return 5
    return max(0, min(20, n))


def submit_retry_sec() -> float:
    """ETH_SUBMIT_RETRY_SEC base backoff, default 3s, clamped 0..60 (linear per attempt)."""
    raw = os.environ.get("ETH_SUBMIT_RETRY_SEC", "").strip()
    if not raw:
        return 3.0
    try:
        v = float(raw)
    except ValueError:
        _warn_env_once("ETH_SUBMIT_RETRY_SEC", raw, "not a number; using 3")
        return 3.0
    if not math.isfinite(v):
        return 3.0
    return max(0.0, min(60.0, v))


def _sleep(sec: float) -> None:
    """Retry backoff. Tests patch this."""
    time.sleep(sec)


def submit_header_chunks(chunks: list[list[dict]], seqs: list[int]) -> None:
    """Submit chunks at the reserved sequences. Stop at the first ctl failure.

    A transient node answer (TRANSIENT_SUBMIT_MARKERS) is retried at the same
    sequence up to submit_retries() times with a linear backoff; ctl did not
    accept that tx, so the sequence is still free. Any other failure, or a
    transient one that outlasts the retries, stops the chain: sequences at
    and after it are released and the error is raised as before. Earlier
    sequences stay reserved until the account query passes them.
    """
    if len(chunks) != len(seqs):
        raise RuntimeError(f"header chunk/sequence mismatch {len(chunks)} != {len(seqs)}")
    retries = submit_retries()
    base = submit_retry_sec()
    for seq, chunk in zip(seqs, chunks):
        attempt = 0
        while True:
            try:
                submit_headers(chunk, sequence=seq)
                break
            except Exception as e:
                if is_transient_submit_error(e) and attempt < retries:
                    attempt += 1
                    wait = base * attempt
                    print(
                        f"WARN exec headers {chunk[0].get('number')}..{chunk[-1].get('number')} "
                        f"seq={seq} transient reject; retry {attempt}/{retries} in {wait:g}s",
                        flush=True,
                    )
                    _sleep(wait)
                    continue
                release_unsent_from(seq)
                raise


def _note_wave_committed(committed: int) -> None:
    """The account query has passed this wave. Drop the stuck clock."""
    global _seq_floor, _seq_stuck_since, _stuck_watch_committed
    if committed >= _seq_floor:
        _seq_floor = committed
        _seq_stuck_since = None
    _stuck_watch_committed = committed


WAVE_POLL_MIN = 0.5
WAVE_POLL_MAX = 30.0
# Extra time past ETH_SEQ_STUCK_SEC before a wave wait gives up on its own.
WAVE_WAIT_SLACK_SEC = 30.0


def wave_poll_sec() -> float:
    """ETH_WAVE_POLL_SEC, default 2. Clamped to 0.5..30 so 0 is not a tight loop."""
    raw = os.environ.get("ETH_WAVE_POLL_SEC", "").strip()
    if not raw:
        return 2.0
    try:
        poll = float(raw)
    except ValueError:
        _warn_env_once("ETH_WAVE_POLL_SEC", raw, "not a number; using 2")
        return 2.0
    if not math.isfinite(poll) or poll < 0:
        _warn_env_once("ETH_WAVE_POLL_SEC", raw, "not a non-negative finite number; using 2")
        return 2.0
    if poll < WAVE_POLL_MIN:
        _warn_env_once("ETH_WAVE_POLL_SEC", raw, f"below {WAVE_POLL_MIN}s; using {WAVE_POLL_MIN}")
        return WAVE_POLL_MIN
    if poll > WAVE_POLL_MAX:
        _warn_env_once("ETH_WAVE_POLL_SEC", raw, f"above {WAVE_POLL_MAX:g}s; using {WAVE_POLL_MAX:g}")
        return WAVE_POLL_MAX
    return poll


def wait_wave_committed(last_seq: int) -> None:
    """Block until the committed sequence is past last_seq.

    The next wave must not be submitted while these txs are still in flight:
    the packer can put a whole wave in one ledger. If the floor sits above
    the committed sequence, the same ETH_SEQ_STUCK_SEC reset used by
    alloc_fresh applies. A reset raises SequenceInFlight and does not start
    the next wave. A later loop re-reads the committed sequence.

    The wait is bounded by a monotonic deadline, ETH_SEQ_STUCK_SEC + 30s,
    not a try count, so a slow ctl (each account query can take up to its
    180s timeout) cannot stretch it to tens of minutes. At most one account
    query runs past the deadline.
    """
    poll = wave_poll_sec()
    deadline = _now() + SEQ_STUCK_SEC + WAVE_WAIT_SLACK_SEC
    while True:
        committed = account_sequence()
        if committed > last_seq:
            _note_wave_committed(committed)
            return
        now = _now()
        if _seq_floor > committed and _stuck_should_reset(committed, now):
            raise SequenceInFlight(
                f"header wave through sequence {last_seq} did not commit "
                f"(committed next is {committed}). Floor reset; "
                "not submitting the next wave."
            )
        if now >= deadline:
            raise SequenceInFlight(
                f"header wave through sequence {last_seq} still not committed "
                f"after {int(SEQ_STUCK_SEC + WAVE_WAIT_SLACK_SEC)}s "
                f"(committed next is {committed})"
            )
        time.sleep(min(poll, deadline - now))


def submit_header_chain(headers: list[dict]) -> None:
    """Header txs with no LC tx in front, in byte-capped waves.

    Within a wave the sequences are N, N+1, … from one read. The next wave
    waits until those sequences commit, then reads again.
    """
    chunks = header_chunks(headers)
    if not chunks:
        return
    for wave in pack_header_waves(chunks, with_lc=False):
        seqs = alloc_fresh(len(wave))
        submit_header_chunks(wave, seqs)
        wait_wave_committed(seqs[-1])


def alloc_confirmed_lc_sequence() -> int:
    """Reserve the LC sequence and confirm a fresh read still matches it.

    submit-eth-lc-update and submit-eth-lc-bootstrap have no --sequence flag.
    ctl re-reads the committed sequence at submit time. If N commits between
    alloc_fresh and that submit, ctl uses N+1 while the header chunk was
    reserved at N+1 and evicts the LC tx. A mismatch drops the reservation
    and tries once more. A second mismatch refuses the submit.
    """
    last: tuple[int, int] | None = None
    for _ in range(2):
        seq = alloc_fresh(1)[0]
        again = account_sequence()
        if again == seq:
            return seq
        last = (seq, again)
        release_unsent_from(seq)
    assert last is not None
    raise SequenceInFlight(
        f"committed sequence changed ({last[0]} -> {last[1]}) between reads; "
        "not submitting the LC tx, because a stale N would let the following "
        "header evict it"
    )


def submit_lc_then_headers(kind: str, path: Path, headers: list[dict]) -> None:
    """LC tx at committed N, then header chunks in byte-capped waves.

    The first wave is N+1, N+2, … submitted immediately after the LC tx, and
    is small enough that the packer can put that wave plus the LC update in
    one ledger without crossing the 4 MiB LedgerBody lane. Later waves wait
    until the previous wave's last sequence has committed, then re-read.

    The LC subcommands cannot take --sequence. Reading N here and submitting
    the LC tx next is what makes ctl's re-read return that same N, as long as
    this account has nothing else in flight. The read is checked again
    immediately before the submit (see alloc_confirmed_lc_sequence). Header
    chunks then use explicit sequences so they do not re-read N and evict the
    LC tx. Waiting for the LC tx to commit before the headers would also
    avoid the eviction, but it splits the pair across blocks. Mint stays
    blocked until the head resolves, and the hash-only head is unusable until
    both txs land, so one mempool batch is the tighter fix. A failure stops
    the chain; the next loop re-reads and will not reuse a sequence that was
    accepted.
    """
    chunks = header_chunks(headers)
    if not chunks:
        seq0 = alloc_confirmed_lc_sequence()
        try:
            submit(kind, path)  # resolves seq0; no --sequence flag on this command
        except Exception:
            release_unsent_from(seq0)
            raise
        return
    waves = pack_header_waves(chunks, with_lc=True)
    first, rest = waves[0], waves[1:]
    seq0 = alloc_confirmed_lc_sequence()
    try:
        submit(kind, path)  # resolves seq0; no --sequence flag on this command
    except Exception:
        release_unsent_from(seq0)
        raise
    seqs = alloc_follow(len(first))
    submit_header_chunks(first, seqs)
    wait_wave_committed(seqs[-1])
    for wave in rest:
        seqs = alloc_fresh(len(wave))
        submit_header_chunks(wave, seqs)
        wait_wave_committed(seqs[-1])


def prepare_hash_only_headers(lc: dict, head_hash: str) -> tuple[list[dict], int]:
    """Fetch an EthExecHeaders batch that ends at a Gloas execution hash.

    eth_getBlockByHash(hash, false) supplies the block number. The batch runs
    from the stored eth_exec_tip + 1 through that block (or just that block
    when nothing is stored). Does not submit.
    """
    h = _norm_hash(head_hash)
    if not h:
        return [], 0
    block = eth_rpc("eth_getBlockByHash", ["0x" + h, False])
    if not isinstance(block, dict) or block.get("number") is None:
        raise RuntimeError(f"eth_getBlockByHash {h} returned nothing")
    got = _norm_hash(block.get("hash"))
    if got != h:
        raise RuntimeError(f"eth_getBlockByHash {h} -> {got}")
    end_n = uhex(block.get("number"))
    tip = int((lc or {}).get("eth_exec_tip") or 0)
    start = tip + 1 if 0 < tip < end_n else end_n
    # The node keeps execution_number-50400 through execution_number
    # (50401 headers). Mint needs the header AT that floor, and when the
    # stored tip is floor-1 that header is also the connects_down link.
    # Cap to the floor itself, not floor+1. Below the window, clamp at 0
    # and leave a start that is already inside the window alone.
    floor_n = end_n - EXEC_PRUNE_BLOCKS
    if floor_n < 0:
        floor_n = 0
    if start < floor_n:
        print(
            f"WARN hash-only header walk {start}..{end_n} exceeds the "
            f"{EXEC_PRUNE_BLOCKS}-block prune window; starting at floor {floor_n}",
            flush=True,
        )
        start = floor_n
    print(
        f"hash-only LC head {h[:16]} block {end_n} headers {start}..{end_n} (tip {tip})",
        flush=True,
    )
    headers: list[dict] = []
    for n in range(start, end_n + 1):
        if n == end_n:
            headers.append(header_obj(block))
        else:
            headers.append(fetch_header(n))
        if len(headers) % 16 == 0:
            print(f"  fetched headers {headers[0]['number']}..{headers[-1]['number']}", flush=True)
    if _norm_hash(headers[-1]["hash"]) != h:
        raise RuntimeError(f"exec batch ends at {headers[-1]['hash']} not LC {h}")
    if len(headers) >= 2 and _norm_hash(headers[-2]["hash"]) != _norm_hash(headers[-1]["parent_hash"]):
        raise RuntimeError(f"exec header parent break before LC hash at {end_n}")
    return headers, end_n


def backfill_max_headers() -> int:
    """ETH_BACKFILL_MAX_HEADERS per daemon loop, default 1024, clamped 0..8192 (0 = off)."""
    raw = os.environ.get("ETH_BACKFILL_MAX_HEADERS", "").strip()
    if not raw:
        return 1024
    try:
        n = int(raw)
    except ValueError:
        _warn_env_once("ETH_BACKFILL_MAX_HEADERS", raw, "not an integer; using 1024")
        return 1024
    return max(0, min(8192, n))


def backfill_target(st: dict) -> int:
    """Lowest exec header worth having: the node's prune line.

    The node drops headers below `eth_exec_prune_floor` (= LC exec number -
    50,400) and refuses to mint any deposit below it, so nothing below is
    useful. Every deposit that can still mint is at or above that line, so
    filling down to it covers max(prune line, oldest unminted deposit) for
    every deposit, including V3 ones this relayer's V1/V2 scan does not see.
    """
    lc = st.get("eth_lc") or {}
    exec_n = int(lc.get("execution_number") or lc.get("eth_exec_tip") or 0)
    window_floor = exec_n - EXEC_PRUNE_BLOCKS if exec_n > EXEC_PRUNE_BLOCKS else 0
    prune = int(st.get("eth_exec_prune_floor") or 0)
    return max(prune, window_floor)


def backfill_exec_hole(st: dict) -> int:
    """Fill the gap under the connected stored range, newest-first, one slice per call.

    `eth_lc.eth_exec_floor` is the low end of the range connected down from
    the stored exec tip. When it sits above backfill_target(), headers just
    below it are missing (a hole, or never fetched). Submit the slice
    [max(target, floor - max), floor - 1]; its top header connects up to the
    stored header at `floor` (the node's connects_up rule), and each later
    chunk connects up to the one before it. Once the hole is closed the
    connected range runs down into the older stored headers and the floor
    drops to the target, so this stops. Returns the number of headers sent.
    """
    cap = backfill_max_headers()
    if cap <= 0:
        return 0
    lc = st.get("eth_lc") or {}
    conn = int(lc.get("eth_exec_floor") or 0)
    tip = int(lc.get("eth_exec_tip") or 0)
    if conn <= 0 or tip <= 0 or conn > tip:
        return 0
    target = backfill_target(st)
    if target <= 0 or conn <= target:
        return 0
    lo = max(target, conn - cap)
    hi = conn - 1
    print(
        f"backfill exec headers {lo}..{hi} (connected floor {conn}, target {target}, tip {tip})",
        flush=True,
    )
    headers = [fetch_header(n) for n in range(lo, hi + 1)]
    for i in range(1, len(headers)):
        if _norm_hash(headers[i].get("parent_hash")) != _norm_hash(headers[i - 1].get("hash")):
            raise RuntimeError(f"backfill parent break at {headers[i].get('number')}")
    submit_header_chain(headers)
    return len(headers)


def submit_prepared_headers(headers: list[dict]) -> None:
    """Submit header batches newest-first. No inclusion wait. Own sequence chain."""
    submit_header_chain(headers)


def _apply_lc_update(
    lc: dict,
    blob: dict,
    filename: str,
    pred,
    label: str,
    *,
    tag: str,
    soft: bool,
    tries: int,
) -> dict | None:
    """Submit one LC update and, if its head is hash-only, the exec headers.

    Headers are built first (execution-layer reads only) and submitted
    immediately after the LC tx, before any inclusion wait, so both can pack
    in one block. The same account sequences the update first. No mint runs
    on this path. Returns None when a later update or finality must not be
    submitted (soft pack timeout, or the head batch could not be built).
    """
    num, head = finalized_exec_ref(blob)
    headers: list[dict] = []
    end_n = 0
    if num == 0 and head:
        try:
            headers, end_n = prepare_hash_only_headers(lc, head)
        except Exception as e:
            if not soft:
                raise
            print(
                f"WARN hash-only LC head {head[:16]} not built ({e}); "
                "skipping this LC update so the head is not left unresolved",
                flush=True,
            )
            return None
    path = _write_update(blob, filename)
    print(f"{tag} bytes={path.stat().st_size}", flush=True)
    submit_lc_then_headers("submit-eth-lc-update", path, headers)
    try:
        lc = wait_lc(pred, tries=tries, label=label)
    except SystemExit as e:
        if not soft:
            raise
        if label == "finalized_slot":
            st2 = status()
            cur_lc = st2.get("eth_lc") or lc
            cur2 = int(cur_lc.get("finalized_slot") or 0)
            want = _finalized_slot(blob)
            if want > cur2:
                print(
                    f"WARN finality_update pending pack: {e} "
                    f"(exec={cur_lc.get('execution_number')} want_slot={want} have={cur2})",
                    flush=True,
                )
        elif label == "next_pks":
            print(f"WARN next_pks pending pack: {e}", flush=True)
        else:
            print(f"WARN period catch-up pending pack: {e}", flush=True)
        return None
    if headers:
        try:
            lc = wait_lc(
                lambda x, want=end_n: int(x.get("execution_number") or 0) >= want,
                tries=tries,
                label=f"exec-number>={end_n}",
            )
        except SystemExit as e:
            if not soft:
                raise
            print(f"WARN hash-only exec headers pending pack: {e}", flush=True)
            return None
    return lc


def submit_hash_only_exec_headers(lc: dict, *, soft: bool = False, head_hash: str = "") -> dict:
    """Submit EthExecHeaders for a hash-only head, then wait until the number resolves."""
    h = head_hash or hash_only_head(lc)
    if not h:
        return lc
    headers, end_n = prepare_hash_only_headers(lc, h)
    if not headers:
        return lc
    submit_header_chain(headers)
    pack_wait = int(os.environ.get("PACK_WAIT_TRIES", "90" if soft else "60"))
    try:
        return wait_lc(
            lambda x, want=end_n: int(x.get("execution_number") or 0) >= want,
            tries=pack_wait if not soft else min(pack_wait, 30),
            label=f"exec-number>={end_n}",
        )
    except SystemExit as e:
        if not soft:
            raise
        print(f"WARN hash-only exec headers pending pack: {e}", flush=True)
        return status().get("eth_lc") or lc


def _resolve_hash_only(lc: dict, blob: dict | None = None, *, soft: bool = False) -> dict:
    h = hash_only_head(lc, blob)
    if not h:
        return lc
    try:
        return submit_hash_only_exec_headers(lc, soft=soft, head_hash=h)
    except SystemExit:
        raise
    except Exception as e:
        if not soft:
            raise
        print(f"WARN hash-only exec head {h[:16]}: {e}", flush=True)
        return lc


def pick_deposit(txid: str, account: str, asset_hint: str = "") -> dict:
    rec = eth_rpc("eth_getTransactionReceipt", [txid if txid.startswith("0x") else "0x" + txid])
    if not rec:
        raise SystemExit(f"no receipt {txid}")
    if str(rec.get("status")) in ("0", "0x0"):
        raise SystemExit(f"sepolia tx failed {txid}")
    dest = dest20(account)
    picked = None
    for lg in rec.get("logs") or []:
        if (lg.get("address") or "").lower() != BRIDGE:
            continue
        topics = lg.get("topics") or []
        if len(topics) < 3:
            continue
        d20 = topics[1].lower().removeprefix("0x")[-40:]
        token = topics[2].lower().removeprefix("0x")[-40:]
        data = (lg.get("data") or "0x")[2:]
        amount = int(data[0:64], 16) if len(data) >= 64 else 0
        if d20 != dest:
            continue
        native = token == ETH_TOKEN
        asset = "ETH" if native else "USDC"
        if asset_hint and asset_hint.upper() != asset:
            continue
        picked = {
            "asset": asset,
            "token": token,
            "amount": amount,
            "dest20": dest,
            "lock": ETH_LOCK if native else USDC_LOCK,
            "block_number": uhex(rec.get("blockNumber")),
            "block_hash": (rec.get("blockHash") or "").lower().removeprefix("0x"),
            "tx_index": uhex(rec.get("transactionIndex") or "0x0"),
            "txid": (rec.get("transactionHash") or txid).lower().removeprefix("0x"),
        }
        break
    if not picked:
        raise SystemExit(f"no Deposit for dest20={dest} on {txid} bridge={BRIDGE}")
    return picked


def cmd_mint(account: str, txid: str, asset_hint: str = "") -> None:
    st = status()
    if not st.get("eth_lc"):
        raise SystemExit("bootstrap first")
    picked = pick_deposit(txid, account, asset_hint)
    dep_n = int(picked["block_number"])
    print(
        f"mint {picked['asset']} to {account} amount={picked['amount']} block={dep_n} tx={picked['txid'][:16]}",
        flush=True,
    )
    wait_n = int(os.environ.get("FPL_MINT_LC_TRIES", "360"))
    lc = {}
    head_n = 0
    for i in range(1, wait_n + 1):
        lc = cmd_update(soft=True)
        head_n = int(lc.get("execution_number") or 0)
        if mint_head_ready(lc, dep_n):
            break
        if head_n == 0 and _norm_hash(lc.get("execution_block_hash")):
            print(
                f"deposit block {dep_n} waiting on hash-only LC head "
                f"{_norm_hash(lc.get('execution_block_hash'))[:16]} ({i}/{wait_n})",
                flush=True,
            )
        else:
            print(
                f"deposit block {dep_n} > LC execution {head_n}; wait for finality_update ({i}/{wait_n})",
                flush=True,
            )
        time.sleep(int(os.environ.get("FPL_LC_WAIT_SEC", "10")))
    else:
        raise SystemExit(
            f"deposit block {dep_n} > LC execution {head_n}; wait for finality_update"
        )
    headers = []
    for n in range(dep_n, head_n + 1):
        headers.append(fetch_header(n))
        if len(headers) % 16 == 0:
            print(f"  fetched headers {headers[0]['number']}..{headers[-1]['number']}", flush=True)
    # newest-first so each batch ends at LC or connects upward.
    # Explicit sequences: the chunks must not each re-read the committed one.
    submit_header_chain(headers)
    # Mint only once the stored chain reaches the numbered LC head. On Gloas
    # execution_number stays 0 until that header's hash is stored.
    lc = wait_lc(
        lambda x: lc_head_resolved(x) and int(x.get("execution_number") or 0) >= head_n,
        tries=20,
        label="headers-pack",
    )
    if not lc_head_resolved(lc):
        raise SystemExit("LC execution head is not resolved; refusing mint")

    block = eth_rpc("eth_getBlockByNumber", [hex(dep_n), False])
    tx_hashes = block.get("transactions") or []
    recs = block_receipts(hex(dep_n), tx_hashes)
    root, raw_hex, nodes, _raw = build_receipt_proof(recs, int(picked["tx_index"]))
    want_root = hx(block["receiptsRoot"]).hex()
    if root != want_root:
        raise SystemExit(f"receipts_root mismatch built={root} block={want_root}")
    print(f"receipt mpt index={picked['tx_index']} nodes={len(nodes)} receipts={len(recs)}", flush=True)

    raw_file = _tmp_path("sepolia-receipt.hex")
    path_file = _tmp_path("sepolia-mpt-nodes.json")
    raw_file.write_text(raw_hex)
    path_file.write_text(json.dumps(nodes))
    lc = status().get("eth_lc") or {}
    if not lc_head_resolved(lc):
        raise SystemExit("LC execution head is not resolved; refusing mint")
    # submit-rail-deposit has no --sequence flag, so it re-reads the committed
    # sequence. Reserve that sequence first and refuse if a header tx from
    # this process is still in the mempool (the re-read would evict it).
    reserved = alloc_fresh(1)
    try:
        out = ctl(
            "submit-rail-deposit",
            "--account",
        ACCOUNT,
        "--asset",
        picked["asset"],
        "--to",
        account,
        "--amount",
        str(picked["amount"]),
        "--external-txid",
        picked["txid"],
        "--block-hash",
        picked["block_hash"],
        "--height",
        str(dep_n),
        "--raw-tx-file",
        str(raw_file),
        "--merkle-path-file",
        str(path_file),
        "--merkle-index",
        str(picked["tx_index"]),
        "--token",
        picked["token"],
        "--scheme",
        SCHEME,
        "--keys-dir",
        KEYS,
        "--network-id",
        NETWORK_ID,
        )
    except Exception:
        release_unsent_from(reserved[0])
        raise
    print(out[-800:], flush=True)


def cmd_selfcheck() -> None:
    empty = keccak256(b"").hex()
    want = "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    if empty != want:
        raise SystemExit(f"keccak empty {empty} != {want}")
    n = 11570070
    b = eth_rpc("eth_getBlockByNumber", [hex(n), False])
    h = header_obj(b)
    print(f"header ok {n} hash={h['hash'][:16]} receipts={h['receipts_root'][:16]}", flush=True)
    recs = block_receipts(hex(n), b.get("transactions") or [])
    root, _, nodes, _ = build_receipt_proof(recs, 0)
    want_root = hx(b["receiptsRoot"]).hex()
    print(f"mpt built={root[:16]} block={want_root[:16]} receipts={len(recs)} proof0={len(nodes)}", flush=True)
    if root != want_root:
        raise SystemExit("receipts_root selfcheck failed")
    print("selfcheck ok", flush=True)


def alert_every_sec() -> int:
    try:
        return max(0, int(os.environ.get("ETH_ALERT_EVERY_SEC", "600")))
    except ValueError:
        return 600


def note_exec_head(lc: dict | None, now: float | None = None) -> str | None:
    """ALERT when execution_number has not changed for STALE_EXEC_SEC.

    The clock starts when this process first sees a number, and restarts when
    the number changes. A hash-only head (number 0) that sits for the whole
    window alerts too. Repeat prints are throttled by ETH_ALERT_EVERY_SEC,
    the same knob as the deposit scan. Returns the line printed, or None.
    """
    global _last_stale_alert
    now = time.time() if now is None else now
    n = int((lc or {}).get("execution_number") or 0)
    if _exec_watch["number"] != n or _exec_watch["since"] is None:
        _exec_watch["number"] = n
        _exec_watch["since"] = now
        _last_stale_alert = 0.0
        return None
    age = now - float(_exec_watch["since"])
    if age < STALE_EXEC_SEC:
        return None
    every = alert_every_sec()
    if _last_stale_alert and now - _last_stale_alert < every:
        return None
    _last_stale_alert = now
    line = (
        f"ALERT stale LC exec head execution_number={n} "
        f"unchanged for {int(age)}s (threshold {STALE_EXEC_SEC}s)"
    )
    print(line, flush=True)
    return line


def deposit_event_topic() -> str:
    """V1/V2 Deposit(bytes32,address,uint256,bytes32). keccak, not a web call."""
    return "0x" + keccak256(b"Deposit(bytes32,address,uint256,bytes32)").hex()


def _norm_addr(raw: str) -> str:
    a = str(raw or "").strip().lower()
    if not a:
        return ""
    return a if a.startswith("0x") else "0x" + a


# Third-bridge addresses already reported, so the daemon does not warn every scan.
_skipped_bridges: set[str] = set()


def deposit_bridges() -> list[str]:
    """V1 and V2 FalconQcBridge only.

    V1 is config/sepolia-qc.json, V2 is config/sepolia-qc-v2.json. Deposits on
    either can still be unminted. A configured BRIDGE that is neither is
    skipped: V3's Deposit(bytes32,address,bytes20,address,uint256,uint64)
    topic is different; V3 is scanned by scan_unminted_v3_deposits.
    """
    allowed = {_norm_addr(QC_BRIDGE_V1), _norm_addr(QC_BRIDGE_V2)}
    out: list[str] = []
    for raw in (QC_BRIDGE_V1, QC_BRIDGE_V2, BRIDGE):
        a = _norm_addr(raw)
        if not a or a in out:
            continue
        if a not in allowed:
            if a not in _skipped_bridges:
                _skipped_bridges.add(a)
                print(
                    f"WARN deposit scan skipping {a}: not FalconQc V1/V2. "
                    "V3 Deposit topic differs; the V3 unminted scan comes with #29.",
                    flush=True,
                )
            continue
        out.append(a)
    return out


def spent_txids(st: dict) -> set[str]:
    """ETH/USDC rail spent_deposits from status. Those txids are already minted."""
    out: set[str] = set()
    for rail in st.get("rails") or []:
        if str(rail.get("asset") or "") not in ("ETH", "USDC"):
            continue
        for tx in rail.get("spent_deposits") or []:
            out.add(str(tx).lower().removeprefix("0x"))
    return out


def unminted_deposit_alerts(
    deposits: list[dict],
    spent: set[str],
    now: float,
    threshold: int | None = None,
) -> list[str]:
    """ALERT lines for deposits seen and still unminted past the threshold."""
    threshold = UNMINTED_DEPOSIT_SEC if threshold is None else threshold
    lines = []
    for dep in deposits:
        txid = str(dep.get("txid") or "").lower().removeprefix("0x")
        if not txid or txid in spent:
            continue
        ts = int(dep.get("timestamp") or 0)
        if ts <= 0:
            continue
        age = now - ts
        if age < threshold:
            continue
        lines.append(
            f"ALERT unminted deposit {txid} age={int(age)}s "
            f"(threshold {threshold}s) block={dep.get('block')}"
        )
    return lines


def deposit_scan_window_blocks(threshold_sec: int | None = None) -> int:
    """How many blocks back the unminted scan looks.

    Default is the 50_400-block prune window, and never less than that or
    less than 2x the unminted threshold (12s blocks) plus a day of margin.
    ETH_DEPOSIT_SCAN_BLOCKS can only widen the window. A 7200-block window
    is about one day, which is the threshold itself, so a deposit is
    alertable for a few minutes and then drops out of the scan.
    """
    threshold = UNMINTED_DEPOSIT_SEC if threshold_sec is None else int(threshold_sec)
    margin = 86400 // BLOCK_SEC
    floor = (2 * max(0, threshold)) // BLOCK_SEC + margin
    raw = os.environ.get("ETH_DEPOSIT_SCAN_BLOCKS", str(EXEC_PRUNE_BLOCKS))
    try:
        configured = int(raw)
    except ValueError:
        configured = EXEC_PRUNE_BLOCKS
    if configured <= 0:
        configured = EXEC_PRUNE_BLOCKS
    return max(configured, floor, EXEC_PRUNE_BLOCKS)


def _log_chunk_blocks() -> int:
    """eth_getLogs chunk size. Clamped to 1..2000. Junk or non-finite -> 2000."""
    raw = os.environ.get("ETH_LOG_CHUNK", "2000").strip()
    try:
        n = float(raw)
    except ValueError:
        _warn_env_once("ETH_LOG_CHUNK", raw, "not a number; using 2000")
        return 2000
    if not math.isfinite(n):
        _warn_env_once("ETH_LOG_CHUNK", raw, "not finite; using 2000")
        return 2000
    n = int(n)
    if n < 1 or n > 2000:
        _warn_env_once("ETH_LOG_CHUNK", raw, "outside 1..2000; clamping")
        return min(2000, max(1, n))
    return n


def scan_budget_sec() -> float:
    """Wall-clock cap for one unminted scan. Default 120s, clamped to 10..600.

    A 50_400-block window in 2000-block chunks is dozens of RPCs. One hung
    call is bounded by the HTTP timeout; this stops the scan from chaining
    those into a ~50 minute stall of the daemon loop.
    """
    raw = os.environ.get("ETH_SCAN_BUDGET_SEC", "120").strip()
    try:
        n = float(raw)
    except ValueError:
        _warn_env_once("ETH_SCAN_BUDGET_SEC", raw, "not a number; using 120")
        return 120.0
    if not math.isfinite(n):
        _warn_env_once("ETH_SCAN_BUDGET_SEC", raw, "not finite; using 120")
        return 120.0
    if n < 10 or n > 600:
        _warn_env_once("ETH_SCAN_BUDGET_SEC", raw, "outside 10..600; clamping")
        n = min(600.0, max(10.0, n))
    return n


def _block_chunks(start: int, end: int, chunk: int):
    cur = start
    while cur <= end:
        nxt = min(end, cur + chunk - 1)
        yield cur, nxt
        cur = nxt + 1


# (bridge, from_block) spans whose eth_getLogs failed; retried every scan.
_scan_failed_spans: set[tuple[str, int]] = set()


def scan_retry_sec() -> float:
    """Delay before re-running a scan that left a failed span. Default 60s."""
    try:
        return min(float(alert_every_sec()), max(10.0, float(os.environ.get("ETH_SCAN_RETRY_SEC", "60"))))
    except ValueError:
        return 60.0


# Share of ETH_SCAN_BUDGET_SEC the eth_getLogs pass may use. The rest is the
# timestamp pass's own allowance, so logs already in hand are not dropped
# because getLogs spent the whole budget.
SCAN_LOGS_SHARE = 0.75
# Distinct eth_getBlockByNumber lookups per scan cycle. Cached and already
# minted logs do not count.
SCAN_TS_LOOKUPS_MAX = 64


def scan_unminted_deposits(st: dict, now: float | None = None) -> list[str]:
    """Look at V1/V2 Deposit logs and print ALERT for old unminted ones.

    Throttled by ETH_ALERT_EVERY_SEC (default 600) only after eth_blockNumber
    succeeds. A failed head read does not arm that throttle, so the next
    daemon loop retries. While a deposit stays unminted and inside the
    window, the alert repeats on each scan. The window is
    deposit_scan_window_blocks (default 50_400), queried in ETH_LOG_CHUNK
    slices (clamped to 1..2000). One bridge's eth_getLogs failure skips the
    rest of that bridge and continues with the next. One log's
    eth_getBlockByNumber failure skips that log, and that block is not
    looked up again for _BLOCK_TS_RETRY_SEC (1 h) so it cannot pin a
    rewound cursor.

    Budget. ETH_SCAN_BUDGET_SEC (default 120, clamped 10..600) is split. The
    eth_getLogs pass stops starting new spans at SCAN_LOGS_SHARE (75%) of it
    and the cursor resumes at the next unvisited span (bridge, from_block),
    rotating through V1 and V2 and wrapping, so a short budget still covers
    every span. The timestamp pass then always runs for the logs in hand:
    its deadline is the later of the full budget and 25% of the budget from
    when it starts, it does at least one lookup, and at most
    SCAN_TS_LOOKUPS_MAX (64) distinct blocks. Logs already in spent_deposits
    need no lookup, and timestamps are cached across cycles. If the
    timestamp pass is cut short, the cursor rewinds to the span of the first
    log it did not process and that pass is not marked finished, so a slow
    RPC cannot visit every span and still never alert. V3 is scanned
    separately by scan_unminted_v3_deposits.
    """
    global _last_deposit_scan
    now = time.time() if now is None else now
    every = alert_every_sec()
    if now - _last_deposit_scan < every:
        return []
    try:
        head_n = uhex(eth_rpc("eth_blockNumber", []))
    except Exception as e:
        print(f"WARN deposit scan eth_blockNumber: {e}", flush=True)
        return []
    _last_deposit_scan = now
    budget = scan_budget_sec()
    t0 = time.monotonic()
    logs_deadline = t0 + budget * SCAN_LOGS_SHARE

    window = deposit_scan_window_blocks()
    start = max(0, head_n - window)
    topic = deposit_event_topic()
    chunk = _log_chunk_blocks()
    spans: list[tuple[str, int, int]] = []
    for addr in deposit_bridges():
        for frm, to in _block_chunks(start, head_n, chunk):
            spans.append((addr, frm, to))
    if not spans:
        lines: list[str] = []
        return lines
    resume_at = 0
    saved_addr = str(_scan_resume.get("addr") or "")
    saved_from = int(_scan_resume.get("from_block") if _scan_resume.get("from_block") is not None else -1)
    if saved_addr and saved_from >= 0:
        for i, (addr, frm, to) in enumerate(spans):
            if addr == saved_addr and to >= saved_from:
                resume_at = i
                break
        else:
            seen_addr = False
            for i, (addr, _frm, _to) in enumerate(spans):
                if addr == saved_addr:
                    seen_addr = True
                    continue
                if seen_addr:
                    resume_at = i
                    break
    order = list(range(resume_at, len(spans))) + list(range(0, resume_at))
    # Spans whose getLogs failed in an earlier cycle go first, so a range is
    # retried until it succeeds and never silently skipped. The rotation
    # cursor still moves on, so one failing bridge cannot starve the other.
    # The span at the rotation cursor still goes first, then the retries, so a
    # failing V1 cannot take V2's turn every cycle.
    head = order[:1] if saved_addr else []
    retry_idx = [i for i in order if (spans[i][0], spans[i][1]) in _scan_failed_spans and i not in head]
    order = head + retry_idx + [i for i in order if i not in set(retry_idx) and i not in head]
    failed: set[str] = set()
    finished = True
    # (span index, rows) in visit order. Timestamps are resolved in this
    # order so "first unprocessed log" maps back to one span.
    fetched: list[tuple[int, list]] = []
    for step, i in enumerate(order):
        # Skip a bridge whose getLogs already failed this cycle before the
        # deadline check, so a stop lands the cursor on the next bridge and
        # not on the failed bridge's next span.
        if spans[i][0] in failed:
            # Not visited this cycle: queue it so it is retried, not skipped.
            _scan_failed_spans.add((spans[i][0], spans[i][1]))
            continue
        if step and time.monotonic() >= logs_deadline:
            addr, frm, _to = spans[i]
            _scan_resume["addr"] = addr
            _scan_resume["from_block"] = frm
            finished = False
            print(
                f"WARN deposit scan getLogs stopped at {int(SCAN_LOGS_SHARE * 100)}% of "
                f"ETH_SCAN_BUDGET_SEC={int(budget)} after {step}/{len(spans)} spans; "
                f"resuming next cycle at {addr} {frm}",
                flush=True,
            )
            break
        addr, frm, to = spans[i]
        try:
            rows = eth_rpc(
                "eth_getLogs",
                [
                    {
                        "address": addr,
                        "topics": [topic],
                        "fromBlock": hex(frm),
                        "toBlock": hex(to),
                    }
                ],
            ) or []
        except Exception as e:
            print(f"WARN deposit scan {addr} {frm}..{to}: {e}", flush=True)
            # Never skip a range: remember the failed span; the next scan
            # (ETH_SCAN_RETRY_SEC later, not ETH_ALERT_EVERY_SEC) retries it first.
            _scan_failed_spans.add((addr, frm))
            failed.add(addr)
            continue
        finally:
            if ETH_SCAN_PACE_SEC:
                time.sleep(ETH_SCAN_PACE_SEC)
        _scan_failed_spans.discard((addr, frm))
        if isinstance(rows, dict):
            rows = [rows]
        if isinstance(rows, list) and rows:
            fetched.append((i, rows))
    for addr, frm in list(_scan_failed_spans):
        if frm < start:
            # Aged out of the window: nothing left to alert on there.
            _scan_failed_spans.discard((addr, frm))
    if _scan_failed_spans:
        # Retry soon instead of waiting the whole alert interval.
        _last_deposit_scan = now - every + scan_retry_sec()
        print(
            f"WARN deposit scan: {len(_scan_failed_spans)} failed span(s) queued for retry "
            f"in {int(scan_retry_sec())}s",
            flush=True,
        )
    if finished:
        _scan_resume["addr"] = spans[0][0]
        _scan_resume["from_block"] = spans[0][1]

    for bn in [b for b in _block_ts_cache if b < start]:
        del _block_ts_cache[bn]
    for bn in [b for b, at in _block_ts_failed.items() if b < start or now - at >= _BLOCK_TS_RETRY_SEC]:
        del _block_ts_failed[bn]
    spent = spent_txids(st)
    ts_start = time.monotonic()
    ts_deadline = max(t0 + budget, ts_start + budget * (1.0 - SCAN_LOGS_SHARE))
    lookups = 0
    cut_span: int | None = None
    cut_why = ""
    deposits = []
    for i, rows in fetched:
        for lg in rows:
            if not isinstance(lg, dict):
                continue
            txid = str(lg.get("transactionHash") or "").lower().removeprefix("0x")
            if not txid or txid in spent:
                continue
            bn = uhex(lg.get("blockNumber") or "0x0")
            ts = _block_ts_cache.get(bn)
            if ts is None and bn not in _block_ts_failed:
                if lookups >= SCAN_TS_LOOKUPS_MAX:
                    cut_span, cut_why = i, f"{SCAN_TS_LOOKUPS_MAX} block lookups"
                    break
                if lookups and time.monotonic() >= ts_deadline:
                    cut_span, cut_why = i, "the timestamp time allowance"
                    break
                lookups += 1
                try:
                    block = eth_rpc("eth_getBlockByNumber", [hex(bn), False]) or {}
                    ts = uhex(block.get("timestamp") or "0x0")
                except Exception as e:
                    print(f"WARN deposit scan block {bn}: {e}", flush=True)
                    ts = 0
                if ts > 0:
                    if len(_block_ts_cache) >= _BLOCK_TS_CACHE_MAX:
                        _block_ts_cache.pop(min(_block_ts_cache))
                    _block_ts_cache[bn] = ts
                else:
                    _block_ts_failed[bn] = now
            if not ts or ts <= 0:
                continue
            deposits.append({"txid": txid, "timestamp": ts, "block": bn})
        if cut_span is not None:
            break
    if cut_span is not None:
        addr, frm, _to = spans[cut_span]
        _scan_resume["addr"] = addr
        _scan_resume["from_block"] = frm
        print(
            f"WARN deposit scan timestamp pass stopped at {cut_why}; "
            f"rewinding to {addr} {frm} so those logs are checked next cycle",
            flush=True,
        )
    lines = unminted_deposit_alerts(deposits, spent, now)
    for line in lines:
        print(line, flush=True)
    discord_sync_unminted("eth:v12", lines, spent, UNMINTED_DEPOSIT_SEC, "V1/V2")
    return lines


V3_BRIDGE = os.environ.get(
    "FPL_SEPOLIA_QC_V3_BRIDGE", "0xEd4eE497F21a9255a59e87535FF2A6097592Cfd4"
).strip().lower()
# keccak256("Deposit(bytes32,address,bytes20,address,uint256,uint64)")
V3_DEPOSIT_TOPIC0 = "0xe7783c72791736d4d8af95660d4367bed2f98d8331a095422373e557a4318728"
V3_DEPOSIT_SIG = b"Deposit(bytes32,address,bytes20,address,uint256,uint64)"
# ETH_V3_UNMINTED_SEC first (the live falcon1 name), then
# ETH_UNMINTED_V3_DEPOSIT_SEC (PR #15 alias), else 1800 s.
V3_UNMINTED_SEC = int(
    os.environ.get("ETH_V3_UNMINTED_SEC")
    or os.environ.get("ETH_UNMINTED_V3_DEPOSIT_SEC")
    or "1800"
)
V3_SCAN_BLOCKS = int(os.environ.get("ETH_V3_SCAN_BLOCKS", "21600"))  # ~3 days = V3 expiry


def v3_deposit_topic() -> str:
    """V3_DEPOSIT_TOPIC0, checked against keccak of the contract event signature."""
    t = "0x" + keccak256(V3_DEPOSIT_SIG).hex()
    if t != V3_DEPOSIT_TOPIC0:
        raise RuntimeError(f"V3 Deposit topic mismatch {t} != {V3_DEPOSIT_TOPIC0}")
    return t


def v3_resolved_ids(st: dict) -> set[str]:
    return {
        str(r.get("deposit_id") or "").lower().removeprefix("0x")
        for r in (st.get("eth_v3_resolutions") or [])
    }


def v3_unminted_alerts(seen: dict[str, dict], resolved: set[str], now: float, threshold: int) -> list[str]:
    """ALERT lines for V3 deposits (by deposit_id) unresolved past the threshold."""
    lines = []
    for did, d in sorted(seen.items(), key=lambda kv: kv[1].get("timestamp", 0)):
        if did in resolved:
            continue
        ts = int(d.get("timestamp") or 0)
        if ts <= 0 or now - ts < threshold:
            continue
        lines.append(
            f"ALERT unminted V3 deposit {did} age={int(now - ts)}s (threshold {threshold}s) "
            f"block={d.get('block')} tx={d.get('txid')}"
        )
    return lines


def _v3_log_ts(lg: dict) -> int:
    data = str(lg.get("data") or "").lower().removeprefix("0x")
    if len(data) != 256:
        return 0
    try:
        return int(data[192:256], 16)
    except ValueError:
        return 0


def scan_unminted_v3_deposits(st: dict | None, now: float | None = None) -> list[str]:
    """V3 Deposit logs, newest span first, so a pruned RPC tail never hides recent ones.

    Seen deposits are kept in memory; resolved = status eth_v3_resolutions
    (the full map). Throttled like the V1/V2 scan (ETH_ALERT_EVERY_SEC).
    """
    global _last_v3_scan
    now = time.time() if now is None else now
    if not V3_BRIDGE or now - _last_v3_scan < alert_every_sec():
        return []
    st = st or status()
    topic = v3_deposit_topic()
    head_n = uhex(eth_rpc("eth_blockNumber", []))
    spans = 0
    complete = True
    _last_v3_scan = now
    chunk = _log_chunk_blocks()
    lo = max(0, head_n - V3_SCAN_BLOCKS)
    to = head_n
    while to >= lo:
        frm = max(lo, to - chunk + 1)
        try:
            rows = eth_rpc(
                "eth_getLogs",
                [{"address": V3_BRIDGE, "topics": [topic], "fromBlock": hex(frm), "toBlock": hex(to)}],
            ) or []
            spans += 1
        except Exception as e:
            print(f"WARN v3 deposit scan {frm}..{to}: {e}; retrying in {int(scan_retry_sec())}s", flush=True)
            # Do not drop the older spans for a whole alert interval.
            _last_v3_scan = now - alert_every_sec() + scan_retry_sec()
            complete = False
            break
        finally:
            if ETH_SCAN_PACE_SEC:
                time.sleep(ETH_SCAN_PACE_SEC)
        for lg in rows if isinstance(rows, list) else []:
            topics = lg.get("topics") or []
            if len(topics) != 3:
                continue
            did = str(topics[1]).lower().removeprefix("0x")
            _v3_seen.setdefault(did, {
                "timestamp": _v3_log_ts(lg),
                "block": uhex(lg.get("blockNumber") or "0x0"),
                "txid": str(lg.get("transactionHash") or ""),
            })
        to = frm - 1
    for did in [d for d, v in _v3_seen.items() if v.get("block", 0) < lo]:
        del _v3_seen[did]
    resolved = v3_resolved_ids(st)
    lines = v3_unminted_alerts(_v3_seen, resolved, now, V3_UNMINTED_SEC)
    for line in lines:
        print(line, flush=True)
    discord_sync_unminted("eth:v3", lines, resolved, V3_UNMINTED_SEC, "V3")
    print(
        f"V3 deposit scan bridge={V3_BRIDGE} blocks={lo}..{head_n} spans={spans} "
        f"deposits={len(_v3_seen)} resolved={len(resolved)} unminted={len(lines)} "
        f"threshold={V3_UNMINTED_SEC}s complete={complete}",
        flush=True,
    )
    return lines


DISCORD_TEST_LABEL = "TEST: Falcon relayer unminted-deposit alert (no action needed)"
DISCORD_STATE = Path(
    os.environ.get("ETH_DISCORD_STATE", str(ROOT / "run/bridge/eth-unminted-discord.json"))
)
# Set by init_discord() when the daemon starts; None = Discord off.
_discord: fpl_discord_notify.DiscordAlerts | None = None
_ALERT_ID_RE = re.compile(r"^ALERT unminted (?:V3 )?deposit ([0-9a-fA-F]+) ")


def init_discord(**kw) -> fpl_discord_notify.DiscordAlerts | None:
    """Read DISCORD_HEALTH_WEBHOOK_URL once. Unset: Discord stays off (no-op)."""
    global _discord
    d = fpl_discord_notify.DiscordAlerts(DISCORD_STATE, source="eth-lc-relayer", **kw)
    _discord = d if d.enabled else None
    print(f"discord alerts {'on' if _discord else 'off'} ({fpl_discord_notify.WEBHOOK_ENV})", flush=True)
    return _discord


def discord_sync_unminted(prefix: str, lines: list[str], minted: set[str], threshold: int, label: str) -> None:
    """Post each newly stuck deposit once; post a recovery once it has minted.

    Only called after a scan really ran (not when throttled), and a recovery
    needs positive evidence (txid in spent_deposits / deposit_id in
    eth_v3_resolutions), so an incomplete scan never clears an alert.
    """
    d = _discord
    if d is None:
        return
    try:
        mins = max(1, int(threshold) // 60)
        for line in lines:
            m = _ALERT_ID_RE.match(line)
            if not m:
                continue
            dep = m.group(1).lower()
            d.fire(
                f"{prefix}:{dep}",
                f"ETH/USDC {label} deposit unminted over {mins} min",
                line.removeprefix("ALERT ")[:1500],
            )
        for key in d.active_keys(prefix + ":"):
            dep = key.rsplit(":", 1)[-1]
            if dep in minted:
                d.resolve(key, f"{label} deposit {dep} minted")
        d.forget_stale()
        d.flush()
    except Exception as e:  # never let Discord break the relayer loop
        print(f"WARN discord {type(e).__name__}: {e}", flush=True)


def cmd_discord_test() -> int:
    d = fpl_discord_notify.DiscordAlerts(DISCORD_STATE, source="eth-lc-relayer")
    return 0 if d.send_test(DISCORD_TEST_LABEL) else 1


def announce_beacon() -> None:
    """Print the beacon URL in use. Warn, and keep going, if it is publicnode.

    publicnode's beacon is frozen at Gloas sync period 1378. The installed
    run/bridge/sepolia-qc.json beacon_rpc wins over the Lodestar fallback.
    """
    url = BEACON
    print(f"beacon {url}", flush=True)
    if "publicnode" in url.lower():
        print(
            "WARNING beacon URL contains publicnode, frozen at Gloas period 1378. "
            "Set SEPOLIA_BEACON or update run/bridge/sepolia-qc.json.",
            flush=True,
        )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", nargs="?", default="bootstrap")
    ap.add_argument("--account", default="")
    ap.add_argument("--txid", default="")
    ap.add_argument("--asset", default="")
    args = ap.parse_args()
    # Daemon and one-shot commands (bootstrap, update, selfcheck) sign as
    # watcher-eth-lc and refuse watcher-eth. mint signs as watcher-eth and
    # refuses watcher-eth-lc.
    global ACCOUNT
    cmd = args.cmd
    if cmd == "discord-test":
        # No signer, node or beacon needed: one labelled message, then exit.
        return cmd_discord_test()
    ACCOUNT = resolve_account(cmd)
    if cmd == "mint":
        assert_mint_account()
    else:
        assert_dedicated_account()
    announce_beacon()
    if cmd == "bootstrap":
        cmd_bootstrap()
    elif cmd == "update":
        cmd_update(soft=True)
    elif cmd == "daemon":
        init_discord()
        cmd_daemon()
    elif cmd == "mint":
        if not args.account or not args.txid:
            raise SystemExit("mint needs --account and --txid")
        cmd_mint(args.account, args.txid, args.asset)
    elif cmd == "selfcheck":
        cmd_selfcheck()
    else:
        raise SystemExit("bootstrap | update | daemon | mint | selfcheck | discord-test")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
