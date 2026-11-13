#!/usr/bin/env python3
"""Falcon PL BTC4 bridge load-test mode — extension of falcon-pl-loadgen.

Subcommands:
  once    One small peg-in then peg-out (precondition / TC-1).
  pegout  Peg-out only (retry 1b; does not open a new peg-in).
  run     Alternating batch loop (10 legs / 1 h, wait 6 h, 20 legs / 1 h).

Uses the existing intake API, falcon-pl-ctl, bitcoin-cli, and sign.mjs.
Never prints secret keys. Pause: LOADGEN_PAUSE=1 or a PAUSE file.
"""
from __future__ import annotations

import csv
import json
import os
import random
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone, timedelta
from pathlib import Path

# ---------------------------------------------------------------------------
# config

def utc_now() -> datetime:
    return datetime.now(timezone.utc)

def gmt() -> str:
    return utc_now().strftime("%Y-%m-%d %H:%M:%S GMT")

def iso() -> str:
    return utc_now().strftime("%Y-%m-%dT%H:%M:%SZ")

def log(msg: str) -> None:
    print(f"[{iso()}] {msg}", flush=True)

def env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()

def env_int(name: str, default: int) -> int:
    try:
        return int(env(name, str(default)))
    except ValueError:
        return default

def load_env_file(path: Path) -> None:
    if not path or not path.is_file():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        k = k.strip().removeprefix("export ")
        v = v.strip().strip('"').strip("'")
        if k and k not in os.environ:
            os.environ[k] = v

def paused(pause_file: Path) -> bool:
    if pause_file.exists():
        return True
    return env("LOADGEN_PAUSE", "0").lower() in ("1", "true", "yes")

# ---------------------------------------------------------------------------
# logging / record

def record_dir() -> Path:
    return Path(env("BRIDGE_RECORD_DIR", "/home/falcon/loadgen/bridge/record"))

def append_leg(row: dict) -> None:
    d = record_dir()
    d.mkdir(parents=True, exist_ok=True)
    jsonl = d / "logs" / "legs.jsonl"
    csvp = d / "logs" / "legs.csv"
    jsonl.parent.mkdir(parents=True, exist_ok=True)
    row = dict(row)
    row.setdefault("ts_gmt", gmt())
    with jsonl.open("a") as f:
        f.write(json.dumps(row, default=str) + "\n")
    fields = [
        "ts_gmt", "test_id", "case", "leg_id", "direction", "account",
        "amount_sats", "state", "tx_or_deposit_id", "fpl_height", "btc_height",
        "started_gmt", "ended_gmt", "latency_sec", "result", "error",
    ]
    new = not csvp.exists()
    with csvp.open("a", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        if new:
            w.writeheader()
        w.writerow({k: row.get(k, "") for k in fields})
    # daily summary line
    day = utc_now().strftime("%Y-%m-%d")
    daily = d / "logs" / f"daily-{day}.md"
    if not daily.exists():
        daily.write_text(f"# BTC4 bridge loadtest daily summary {day} GMT\n\n")
    with daily.open("a") as f:
        f.write(
            f"- {row.get('ts_gmt')}: {row.get('case')} {row.get('leg_id')} "
            f"{row.get('direction')} {row.get('account')} {row.get('amount_sats')} "
            f"{row.get('result')} {row.get('tx_or_deposit_id') or ''} "
            f"{(row.get('error') or '')[:120]}\n"
        )

# ---------------------------------------------------------------------------
# alerts (never log the webhook URL)

def discord_alert(text: str) -> None:
    url = env("DISCORD_HEALTH_WEBHOOK_URL") or env("DISCORD_WEBHOOK_URL")
    log(f"ALERT: {text}")
    if not url:
        return
    body = json.dumps({"content": text[:1800]}).encode()
    req = urllib.request.Request(
        url, data=body, method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            r.read()
        log("alert posted to Discord (webhook present, URL not logged)")
    except Exception as e:
        log(f"alert post failed: {type(e).__name__}")

# ---------------------------------------------------------------------------
# host tools

def ctl(*args: str, timeout: int = 60) -> str:
    bin = env("FPL_CTL", "/var/lib/falcon-pl-2300/bin/falcon-pl-ctl")
    addr = env("FPL_RPC", "127.0.0.1:19301")
    cmd = [bin, "--addr", addr, *args]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    out = (p.stdout or "") + (p.stderr or "")
    if p.returncode != 0:
        raise RuntimeError(f"ctl {' '.join(args)} failed: {out[-400:]}")
    return out

def ctl_json(*args: str, timeout: int = 90) -> dict:
    raw = ctl(*args, timeout=timeout)
    i = raw.find("{")
    if i < 0:
        raise RuntimeError(f"no json from ctl {args}: {raw[:200]}")
    return json.loads(raw[i:])

def account(name: str) -> dict:
    d = ctl_json("account", "--account", name)
    return d.get("body", d)

def fpl_status_rail() -> tuple[int, int, str, object]:
    # status is large — write to tmp on first call pattern not needed; parse here
    raw = ctl("status", timeout=60)
    b = json.loads(raw[raw.find("{"):]).get("body", {})
    tip = int(b.get("tip_height") or 0)
    for r in b.get("rails") or []:
        if r.get("asset") == "BTC4":
            return tip, int(r.get("tip_height") or 0), str(r.get("tip_hash") or ""), r.get("btc_fork")
    return tip, 0, "", None

def bitcoin(*args: str, timeout: int = 60) -> str:
    cli = env("BITCOIN_CLI", "/opt/fpl-tn4btc/bin/bitcoin-cli")
    conf = env("BITCOIN_CONF", "/opt/fpl-tn4btc/bitcoin.conf")
    data = env("BITCOIN_DATADIR", "/opt/fpl-tn4btc/data")
    wallet = env("BTC_WALLET", "fpl-operator")
    cmd = [cli, f"-conf={conf}", f"-datadir={data}", f"-rpcwallet={wallet}", *args]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if p.returncode != 0:
        raise RuntimeError(f"bitcoin-cli {' '.join(args)} failed: {(p.stderr or p.stdout)[-400:]}")
    return (p.stdout or "").strip()

def intake(method: str, path: str, body: dict | None = None, timeout: int = 30) -> dict:
    base = env("INTAKE", "http://127.0.0.1:8790").rstrip("/")
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        base + path, data=data, method=method,
        headers={"Content-Type": "application/json"} if data else {},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read().decode()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        err = e.read().decode()[-400:]
        raise RuntimeError(f"intake {method} {path} HTTP {e.code}: {err}") from e

def esplora_tip() -> int:
    url = env("ESPLORA", "https://mempool.space/testnet4/api").rstrip("/") + "/blocks/tip/height"
    with urllib.request.urlopen(url, timeout=20) as r:
        return int(r.read().decode().strip())

def esplora_tx_status(txid: str) -> dict:
    url = env("ESPLORA", "https://mempool.space/testnet4/api").rstrip("/") + f"/tx/{txid}/status"
    with urllib.request.urlopen(url, timeout=20) as r:
        return json.loads(r.read().decode())

# ---------------------------------------------------------------------------
# wallets

def ensure_fpl_wallet(account_name: str, keys_dir: Path) -> None:
    keys_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    kf = keys_dir / f"{account_name}.json"
    if kf.exists():
        return
    log(f"creating FPL wallet {account_name} in keys dir (key not printed)")
    ctl(
        "gen-wallet",
        "--keys-dir", str(keys_dir),
        "--account", account_name,
        "--scheme", "falcon-512",
    )
    try:
        os.chmod(keys_dir, 0o700)
        for p in keys_dir.iterdir():
            os.chmod(p, 0o600)
    except OSError:
        pass

def _wallet_public_key_hex(keys_dir: Path, account_name: str) -> str:
    """Read the Falcon public key from the wallet file. Never log the value."""
    kf = keys_dir / f"{account_name}.json"
    if not kf.is_file():
        raise RuntimeError(f"no wallet file for {account_name}")
    d = json.loads(kf.read_text())
    pk = (d.get("public_key") or "").strip()
    if not re.fullmatch(r"[0-9a-fA-F]+", pk) or len(pk) % 2:
        raise RuntimeError(f"unexpected public key for {account_name}")
    return pk

def key_commit_hash(pk_hex: str) -> str:
    """fd-pl key_commit_hash: lowercase sha256 of the raw 897-byte Falcon-512 pubkey."""
    import hashlib
    raw = bytes.fromhex(pk_hex.strip())
    if len(raw) == 898 and raw[0] == 0xFB:
        raw = raw[1:]
    if len(raw) != 897:
        raise RuntimeError(f"not a Falcon-512 public key (len={len(raw)})")
    return hashlib.sha256(raw).hexdigest()

def account_key_fp(account_name: str) -> str:
    try:
        return str(account(account_name).get("key_fp") or "").strip()
    except Exception:
        return ""

def fund_fpl(account_name: str, amount: int, keys_dir: Path, *, commit_key: bool = False) -> str:
    faucet_keys = env("LOADGEN_FAUCET_KEYS", "/home/falcon/falcon-pl-public-testnet-2300/keys")
    pre = account(account_name)
    before = int(pre.get("balance") or 0)
    args = [
        "--to", account_name,
        "--amount", str(amount),
        "--fee", "2",
        "--sequence", "0",
        "--scheme", "falcon-512",
        "--network-id", "2300",
        "--keys-dir", faucet_keys,
    ]
    # v2.9.65 C-1: PayToKey commits sha256(raw pubkey) so this named account can bind.
    # `pay` has no --key-hash; only `faucet` does.
    if commit_key:
        kh = key_commit_hash(_wallet_public_key_hex(keys_dir, account_name))
        log(f"FPL PayToKey {amount} -> {account_name} key_hash={kh[:16]}…")
        out = ctl("faucet", *args, "--key-hash", kh)
    else:
        out = ctl(
            "pay",
            "--from", env("LOADGEN_FAUCET_ACCOUNT", "faucet"),
            *args,
        )
    m = re.search(r"tx_id=([0-9a-f]{16,})", out)
    txid = m.group(1) if m else "unknown"
    log(f"FPL fund {amount} -> {account_name} tx {txid[:16]}… accepted")
    deadline = time.time() + 120
    while time.time() < deadline:
        bal = int(account(account_name).get("balance") or 0)
        if bal >= before + amount:
            log(f"FPL fund included, {account_name} bal={bal}")
            return txid
        time.sleep(4)
    raise RuntimeError(f"FPL fund {txid[:16]} not visible on {account_name} within 120s")

def ensure_key_bound(account_name: str, keys_dir: Path) -> None:
    """Commit the wallet key with PayToKey (if needed) and bind it with a 1 FPL spend.

    Named accounts like loadtest01 are not the key's classic address, so the first
    spend is refused until a funder commits sha256(raw pubkey) via faucet --key-hash.
    """
    fp = account_key_fp(account_name)
    if fp:
        log(f"{account_name} key already bound fp={fp}")
        return
    log(f"committing key for {account_name} via faucet PayToKey (key not printed)")
    fund_fpl(account_name, env_int("KEY_COMMIT_FPL", 10), keys_dir, commit_key=True)
    if account_key_fp(account_name):
        log(f"{account_name} key bound after PayToKey")
        return
    # First spend from the committed key binds it (same rule the wallet portal uses).
    faucet_acct = env("LOADGEN_FAUCET_ACCOUNT", "faucet")
    log(f"binding {account_name} key with 1 FPL pay to {faucet_acct}")
    out = ctl(
        "pay",
        "--from", account_name,
        "--to", faucet_acct,
        "--amount", "1",
        "--fee", "2",
        "--sequence", "0",
        "--scheme", "falcon-512",
        "--network-id", "2300",
        "--keys-dir", str(keys_dir),
    )
    m = re.search(r"tx_id=([0-9a-f]{16,})", out)
    txid = m.group(1) if m else "unknown"
    log(f"key-bind spend tx {txid[:16]}… accepted")
    deadline = time.time() + 120
    while time.time() < deadline:
        fp = account_key_fp(account_name)
        if fp:
            log(f"{account_name} key bound fp={fp} after spend")
            return
        time.sleep(4)
    raise RuntimeError(f"{account_name} key_fp still empty after bind spend {txid[:16]}")

def depositor_secret_path(home: Path, account_name: str) -> Path:
    d = home / "depositor-keys"
    d.mkdir(mode=0o700, parents=True, exist_ok=True)
    return d / f"{account_name}.secret"

def ensure_depositor_key(home: Path, account_name: str, sign_mjs: Path) -> str:
    """Return compressed pubkey hex; secret stays in a 0600 file, never printed."""
    sp = depositor_secret_path(home, account_name)
    if not sp.exists():
        secret = os.urandom(32).hex()
        sp.write_text(secret + "\n")
        os.chmod(sp, 0o600)
        log(f"created depositor key for {account_name} (not printed)")
    envk = dict(os.environ)
    envk["FPL_BROWSER_SECRET"] = sp.read_text().strip()
    p = subprocess.run(
        ["node", str(sign_mjs), "--pubkey"],
        capture_output=True, text=True, timeout=30, env=envk,
    )
    # drop secret from this process env copy
    envk.pop("FPL_BROWSER_SECRET", None)
    if p.returncode != 0:
        raise RuntimeError(f"sign --pubkey failed: {(p.stderr or p.stdout)[-200:]}")
    pub = (p.stdout or "").strip()
    if not re.fullmatch(r"[0-9a-f]{66}", pub):
        raise RuntimeError("unexpected pubkey length")
    return pub

def sign_depositor(home: Path, account_name: str, sign_mjs: Path, req_path: Path, out_path: Path) -> None:
    sp = depositor_secret_path(home, account_name)
    envk = dict(os.environ)
    envk["FPL_BROWSER_SECRET"] = sp.read_text().strip()
    p = subprocess.run(
        ["node", str(sign_mjs), str(req_path), str(out_path)],
        capture_output=True, text=True, timeout=60, env=envk,
    )
    envk.pop("FPL_BROWSER_SECRET", None)
    if p.returncode != 0:
        raise RuntimeError(f"sign failed: {(p.stderr or p.stdout)[-300:]}")
    log(f"signed depositor PSBTs for {account_name}")

# ---------------------------------------------------------------------------
# peg-in / peg-out

def peg_in(account_name: str, send_sats: int, home: Path, sign_mjs: Path, timeout_sec: int) -> dict:
    started = gmt()
    t0 = time.time()
    pub = ensure_depositor_key(home, account_name, sign_mjs)
    dep = intake("POST", "/v1/deposits", {"account": account_name, "depositor_pubkey": pub})
    dep_id = dep["id"]
    addr = dep["address"]
    need = int(dep.get("send_sats_min") or send_sats)
    if send_sats < need:
        send_sats = need
    log(f"peg-in opened {dep_id} for {account_name} send {send_sats} sats")
    # fund from operator wallet; do not print the address in alerts only — record it
    amt = f"{send_sats / 1e8:.8f}"
    txid = bitcoin("-named", "sendtoaddress", f"address={addr}", f"amount={amt}", "fee_rate=1")
    log(f"peg-in funded tx {txid[:16]}…")
    append_leg({
        "test_id": env("TEST_ID", "FPL-BTC4-BRIDGE-LOAD-2026-11-13"),
        "case": env("TEST_CASE", "TC"),
        "leg_id": dep_id,
        "direction": "peg-in",
        "account": account_name,
        "amount_sats": send_sats,
        "state": "funding_broadcast",
        "tx_or_deposit_id": f"{dep_id}/{txid}",
        "started_gmt": started,
        "result": "pending",
    })
    signed = False
    deadline = time.time() + timeout_sec
    last = ""
    while time.time() < deadline:
        if paused(Path(env("PAUSE_FILE", str(home / "PAUSE")))) and env("PAUSE_STOPS_WAIT", "0") == "1":
            raise RuntimeError("paused during peg-in wait")
        st = intake("GET", f"/v1/deposits/{dep_id}")
        state = st.get("state")
        if state != last:
            log(f"peg-in {dep_id} state={state} confs={st.get('confirmations')} err={(st.get('last_error') or '')[:80]}")
            last = state
        if state == "awaiting_signature" and not signed:
            work = home / "work" / dep_id
            work.mkdir(parents=True, exist_ok=True)
            req = st.get("depositor_request") or st
            req_path = work / "depositor_request.json"
            # intake public_view may nest the request
            if "psbts" not in (req if isinstance(req, dict) else {}):
                # fetch again / write known field
                req = st.get("depositor_request")
            if not req or "psbts" not in req:
                # some views omit psbts until we GET a richer body — try raw
                raise RuntimeError("no depositor_request.psbts in intake state")
            req_path.write_text(json.dumps(req))
            out_path = work / "signed.json"
            sign_depositor(home, account_name, sign_mjs, req_path, out_path)
            signed_body = json.loads(out_path.read_text())
            intake("POST", f"/v1/deposits/{dep_id}/signatures", signed_body, timeout=60)
            signed = True
            log(f"peg-in {dep_id} signatures posted")
        if state == "minted":
            ended = gmt()
            rec = {
                "test_id": env("TEST_ID", "FPL-BTC4-BRIDGE-LOAD-2026-11-13"),
                "case": env("TEST_CASE", "TC"),
                "leg_id": dep_id,
                "direction": "peg-in",
                "account": account_name,
                "amount_sats": send_sats,
                "state": "minted",
                "tx_or_deposit_id": f"{dep_id}/{txid}/{st.get('peg_in_confirm_txid') or ''}",
                "fpl_height": "",
                "btc_height": st.get("confirmations"),
                "started_gmt": started,
                "ended_gmt": ended,
                "latency_sec": int(time.time() - t0),
                "result": "pass",
            }
            append_leg(rec)
            rec["minted_sats"] = int(st.get("funding_sats") or send_sats) - env_int("PEG_IN_FEE", 590)
            rec["deposit_txid"] = st.get("deposit_txid") or txid
            rec["peg_in_confirm_txid"] = st.get("peg_in_confirm_txid")
            return rec
        if state in ("failed", "error", "rejected"):
            raise RuntimeError(f"peg-in {dep_id} {state}: {st.get('last_error')}")
        time.sleep(20)
    raise RuntimeError(f"peg-in {dep_id} timeout after {timeout_sec}s last={last}")

def peg_out(account_name: str, amount: int, dest: str, keys_dir: Path, timeout_sec: int) -> dict:
    started = gmt()
    t0 = time.time()
    fpl_before, rail_before, _, _ = fpl_status_rail()
    out = ctl(
        "submit-rail-withdraw",
        "--account", account_name,
        "--asset", "BTC4",
        "--amount", str(amount),
        "--external-to", dest,
        "--fee", "2",
        "--scheme", "falcon-512",
        "--network-id", "2300",
        "--keys-dir", str(keys_dir),
    )
    m = re.search(r"tx[= ]([0-9a-f]{16,})", out)
    burn_tx = m.group(1) if m else "unknown"
    log(f"peg-out burn submitted {burn_tx[:16]}… amount {amount} dest (operator wallet)")
    append_leg({
        "test_id": env("TEST_ID", "FPL-BTC4-BRIDGE-LOAD-2026-11-13"),
        "case": env("TEST_CASE", "TC"),
        "leg_id": burn_tx[:16],
        "direction": "peg-out",
        "account": account_name,
        "amount_sats": amount,
        "state": "burn_submitted",
        "tx_or_deposit_id": burn_tx,
        "fpl_height": fpl_before,
        "started_gmt": started,
        "result": "pending",
    })
    deadline = time.time() + timeout_sec
    last = ""
    while time.time() < deadline:
        # find claim by scanning BTC4 claims for this dest+amount+from
        _, _, _, rail = fpl_status_rail() if False else (0, 0, "", None)
        raw = ctl("status", timeout=60)
        b = json.loads(raw[raw.find("{"):]).get("body", {})
        claims = []
        for r in b.get("rails") or []:
            if r.get("asset") == "BTC4":
                claims = r.get("bitvm2_claims") or []
        hit = None
        for c in claims:
            if not isinstance(c, dict):
                continue
            if c.get("from") == account_name and c.get("dest") == dest and int(c.get("amount") or 0) == amount:
                # prefer newest
                hit = c
        if hit:
            st = hit.get("status")
            if st != last:
                log(f"peg-out {burn_tx[:16]} claim status={st} payout={(hit.get('pegout_txid_hex') or '')[:16]} attest={hit.get('attest_height')}")
                last = st
            if st in ("claim_posted", "paid_optimistic", "paid"):
                rec = {
                    "test_id": env("TEST_ID", "FPL-BTC4-BRIDGE-LOAD-2026-11-13"),
                    "case": env("TEST_CASE", "TC"),
                    "leg_id": (hit.get("note_id") or burn_tx)[:16],
                    "direction": "peg-out",
                    "account": account_name,
                    "amount_sats": amount,
                    "state": st,
                    "tx_or_deposit_id": f"{hit.get('note_id')}/{hit.get('pegout_txid_hex')}",
                    "fpl_height": hit.get("attest_height") or hit.get("open_height"),
                    "started_gmt": started,
                    "ended_gmt": gmt(),
                    "latency_sec": int(time.time() - t0),
                    "result": "pass",
                }
                append_leg(rec)
                rec["claim"] = {k: hit[k] for k in hit if not isinstance(hit[k], (list, dict))}
                return rec
        time.sleep(20)
    raise RuntimeError(f"peg-out {burn_tx[:16]} timeout after {timeout_sec}s last={last}")

def new_recycle_addr() -> str:
    # bech32 from operator wallet — funds return to us
    addr = bitcoin("getnewaddress", "bridge-loadtest", "bech32")
    if not addr.startswith("tb1"):
        raise RuntimeError("expected tb1 payout address")
    return addr

def unfinalized_claims(accounts: set[str]) -> int:
    raw = ctl("status", timeout=60)
    b = json.loads(raw[raw.find("{"):]).get("body", {})
    n = 0
    for r in b.get("rails") or []:
        if r.get("asset") != "BTC4":
            continue
        for c in r.get("bitvm2_claims") or []:
            if not isinstance(c, dict):
                continue
            if c.get("from") not in accounts:
                continue
            if c.get("status") in ("awaiting_pegout", "claim_posted"):
                n += 1
    return n

# ---------------------------------------------------------------------------
# watchdogs used by run()

class RailWatch:
    def __init__(self):
        self.over_since: float | None = None
        self.alerted = False

    def tick(self) -> int:
        tn4 = esplora_tip()
        _, rail, _, fork = fpl_status_rail()
        lag = tn4 - rail
        if lag > 6:
            if self.over_since is None:
                self.over_since = time.time()
            elif time.time() - self.over_since >= 30 * 60 and not self.alerted:
                discord_alert(
                    f"BTC4 rail lag {lag} headers for ≥30 min (rail {rail}, Testnet4 {tn4})."
                )
                self.alerted = True
        else:
            self.over_since = None
            self.alerted = False
        return lag

# ---------------------------------------------------------------------------
# commands

def cmd_once(home: Path) -> int:
    os.environ["TEST_CASE"] = env("TEST_CASE", "TC-1")
    keys = Path(env("LOADGEN_KEYS", str(home / "keys")))
    sign_mjs = Path(env("SIGN_MJS", str(home / "sign.mjs")))
    account_name = env("ONCE_ACCOUNT", "loadtest01")
    send = env_int("PEGIN_SATS", 55000)
    timeout = env_int("LEG_TIMEOUT_SECS", 6 * 3600)
    fpl_fund = env_int("FPL_FUND_AMOUNT", 10000)
    ensure_fpl_wallet(account_name, keys)
    # fund FPL if needed
    try:
        bal = int(account(account_name).get("balance") or 0)
    except Exception:
        bal = 0
    if bal < 1000:
        fund_fpl(account_name, fpl_fund, keys, commit_key=not account_key_fp(account_name))
    ensure_key_bound(account_name, keys)
    # rail lag gate
    tn4 = esplora_tip()
    fpl, rail, rh, fork = fpl_status_rail()
    log(f"precondition rail={rail} tn4={tn4} lag={tn4-rail} fpl={fpl} fork={fork}")
    if tn4 - rail > env_int("RAIL_SYNC_MAX_LAG", 2):
        log("ABORTED: rail not synced; not starting TC-1")
        return 2
    dest = new_recycle_addr()
    Path(home / "payout.addr").write_text(dest + "\n")
    try:
        pin = peg_in(account_name, send, home, sign_mjs, timeout)
    except Exception as e:
        log(f"TC-1 peg-in FAILED: {e}")
        append_leg({
            "case": "TC-1", "leg_id": "1a", "direction": "peg-in",
            "account": account_name, "amount_sats": send, "result": "fail",
            "error": str(e)[:300], "started_gmt": gmt(), "ended_gmt": gmt(),
        })
        discord_alert(f"BTC4 TC-1 peg-in failed: {e}")
        return 1
    minted = int(pin.get("minted_sats") or (send - 590))
    try:
        pout = peg_out(account_name, minted, dest, keys, timeout)
    except Exception as e:
        log(f"TC-1 peg-out FAILED: {e}")
        append_leg({
            "case": "TC-1", "leg_id": "1b", "direction": "peg-out",
            "account": account_name, "amount_sats": minted, "result": "fail",
            "error": str(e)[:300], "started_gmt": gmt(), "ended_gmt": gmt(),
        })
        discord_alert(f"BTC4 TC-1 peg-out failed: {e}")
        return 1
    log(f"TC-1 PASS peg-in {pin.get('tx_or_deposit_id')} peg-out {pout.get('tx_or_deposit_id')} "
        f"in {pin.get('latency_sec')}+{pout.get('latency_sec')}s")
    return 0

def cmd_pegout(home: Path) -> int:
    """Peg-out only (no peg-in). Used to retry TC-1 1b after a key-bind fix."""
    os.environ["TEST_CASE"] = env("TEST_CASE", "TC-1")
    keys = Path(env("LOADGEN_KEYS", str(home / "keys")))
    account_name = env("ONCE_ACCOUNT", "loadtest01")
    timeout = env_int("LEG_TIMEOUT_SECS", 6 * 3600)
    ensure_fpl_wallet(account_name, keys)
    ensure_key_bound(account_name, keys)
    acc = account(account_name)
    assets = acc.get("assets") or {}
    amount = env_int("PEGOUT_AMOUNT", 0) or int(assets.get("BTC4") or 0)
    if amount <= 0:
        log("ABORTED: no BTC4 balance to peg out")
        return 2
    dest = new_recycle_addr()
    Path(home / "payout.addr").write_text(dest + "\n")
    log(f"peg-out only {account_name} amount={amount} dest=operator-wallet")
    try:
        pout = peg_out(account_name, amount, dest, keys, timeout)
    except Exception as e:
        log(f"TC-1 peg-out FAILED: {e}")
        append_leg({
            "case": "TC-1", "leg_id": "1b", "direction": "peg-out",
            "account": account_name, "amount_sats": amount, "result": "fail",
            "error": str(e)[:300], "started_gmt": gmt(), "ended_gmt": gmt(),
        })
        discord_alert(f"BTC4 TC-1 peg-out failed: {e}")
        return 1
    log(f"TC-1 peg-out PASS {pout.get('tx_or_deposit_id')} in {pout.get('latency_sec')}s")
    return 0

def spend_today(home: Path) -> int:
    day = utc_now().strftime("%Y-%m-%d")
    p = record_dir() / "logs" / "legs.jsonl"
    if not p.exists():
        return 0
    tot = 0
    for line in p.read_text().splitlines():
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not str(r.get("ts_gmt") or r.get("started_gmt") or "").startswith(day):
            continue
        if r.get("direction") == "peg-in" and r.get("state") in ("funding_broadcast", "minted"):
            tot += int(r.get("amount_sats") or 0)
    return tot

def cmd_run(home: Path) -> int:
    keys = Path(env("LOADGEN_KEYS", str(home / "keys")))
    sign_mjs = Path(env("SIGN_MJS", str(home / "sign.mjs")))
    pause_file = Path(env("PAUSE_FILE", str(home / "PAUSE")))
    prefix = env("LOADGEN_PREFIX", "loadtest")
    n_wallets = env_int("LOADGEN_WALLETS", 4)
    accounts = [f"{prefix}{i:02d}" for i in range(1, n_wallets + 1)]
    send = env_int("PEGIN_SATS", 55000)
    timeout = env_int("LEG_TIMEOUT_SECS", 6 * 3600)
    fpl_fund = env_int("FPL_FUND_AMOUNT", 10000)
    fpl_floor = env_int("FPL_FLOOR", 2000)
    max_unfin = env_int("MAX_UNFINALIZED_CLAIMS", 4)
    max_day = env_int("MAX_SPEND_SATS_PER_DAY", 2_000_000)
    header_floor = env_int("HEADERS_FPL_FLOOR", 200)
    wait_gap = env_int("BATCH_GAP_SECS", 6 * 3600)
    batch_window = env_int("BATCH_WINDOW_SECS", 3600)
    sizes = [env_int("BATCH_SIZE_A", 10), env_int("BATCH_SIZE_B", 20)]
    watch = RailWatch()

    for a in accounts:
        ensure_fpl_wallet(a, keys)
        try:
            bal = int(account(a).get("balance") or 0)
        except Exception:
            bal = 0
        if bal < fpl_fund:
            try:
                fund_fpl(a, fpl_fund, keys, commit_key=not account_key_fp(a))
            except Exception as e:
                log(f"fund {a} failed: {e}")
        try:
            ensure_key_bound(a, keys)
        except Exception as e:
            log(f"key bind {a} failed: {e}")

    bi = 0
    while True:
        if paused(pause_file):
            log("paused (PAUSE file or LOADGEN_PAUSE=1); sleeping 30s")
            time.sleep(30)
            continue
        lag = watch.tick()
        try:
            hbal = int(account("btc-headers").get("balance") or 0)
        except Exception:
            hbal = 0
        if hbal and hbal < header_floor:
            discord_alert(f"btc-headers FPL balance low: {hbal}")
        size = sizes[bi % 2]
        log(f"starting batch {bi+1} size={size} window={batch_window}s lag={lag}")
        # randomize start offsets in the hour; half in, half out if the wallet has BTC4
        offsets = sorted(random.uniform(0, max(1, batch_window - 30)) for _ in range(size))
        batch_t0 = time.time()
        launched = 0
        for i, off in enumerate(offsets):
            if paused(pause_file):
                log("paused mid-batch; no new legs")
                break
            wait = batch_t0 + off - time.time()
            if wait > 0:
                time.sleep(wait)
            watch.tick()
            acct = accounts[i % len(accounts)]
            try:
                unfin = unfinalized_claims(set(accounts))
            except Exception as e:
                log(f"unfinalized query failed: {e}")
                unfin = max_unfin
            if unfin >= max_unfin:
                log(f"cap: {unfin} unfinalised claims (max {max_unfin}); skip leg")
                continue
            if spend_today(home) + send > max_day:
                log("cap: daily tBTC spend reached; skip remaining legs")
                discord_alert("BTC4 loadtest daily spend cap reached")
                break
            # prefer peg-out if this wallet has enough minted BTC4, else peg-in
            try:
                assets = account(acct).get("assets") or {}
                btc4 = int(assets.get("BTC4") or 0)
            except Exception:
                btc4 = 0
            minted_expect = send - env_int("PEG_IN_FEE", 590)
            def _run_leg(acct=acct, btc4=btc4, i=i, bi=bi):
                try:
                    if btc4 >= minted_expect:
                        dest = new_recycle_addr()
                        peg_out(acct, minted_expect, dest, keys, timeout)
                    else:
                        fpl = int(account(acct).get("balance") or 0)
                        if fpl < fpl_floor:
                            fund_fpl(acct, fpl_fund, keys)
                        peg_in(acct, send, home, sign_mjs, timeout)
                except Exception as e:
                    log(f"leg failed ({acct}): {e}")
                    append_leg({
                        "case": f"batch-{bi+1}", "leg_id": f"{bi+1}-{i+1}",
                        "direction": "peg-out" if btc4 >= minted_expect else "peg-in",
                        "account": acct, "amount_sats": send, "result": "fail",
                        "error": str(e)[:300], "started_gmt": gmt(), "ended_gmt": gmt(),
                    })
                    discord_alert(f"BTC4 loadtest leg failed ({acct}): {e}")
            import threading
            threading.Thread(target=_run_leg, name=f"leg-{bi+1}-{i+1}", daemon=True).start()
            launched += 1
        remain = batch_t0 + batch_window - time.time()
        if remain > 0 and not paused(pause_file):
            time.sleep(remain)
        log(f"batch {bi+1} launched {launched}/{size}; gap {wait_gap}s")
        gap_end = time.time() + wait_gap
        while time.time() < gap_end:
            if paused(pause_file):
                time.sleep(30)
                continue
            watch.tick()
            time.sleep(60)
        bi += 1

def main() -> int:
    argv = sys.argv[1:]
    cfg = Path(env("LOADGEN_CONFIG", ""))
    if argv and argv[0] not in ("once", "run"):
        # treat first arg as env file
        cfg = Path(argv[0])
        argv = argv[1:]
    if len(argv) >= 2 and argv[1].endswith(".env"):
        cfg = Path(argv[1])
    if cfg and cfg.is_file():
        load_env_file(cfg)
    # sidecar webhook env (0600); never logged
    load_env_file(Path("/home/falcon/loadgen/bridge/discord.env"))
    # also allow: bridge-run <env> or once <env>
    cmd = argv[0] if argv else env("BRIDGE_CMD", "run")
    if cmd in ("bridge-run", "bridge_run"):
        cmd = "run"
    if cmd in ("bridge-once", "bridge_once"):
        cmd = "once"
    home = Path(env("BRIDGE_HOME", "/home/falcon/loadgen/bridge"))
    home.mkdir(parents=True, exist_ok=True)
    if "BRIDGE_RECORD_DIR" not in os.environ:
        os.environ["BRIDGE_RECORD_DIR"] = str(home / "record")
    if "PAUSE_FILE" not in os.environ:
        os.environ["PAUSE_FILE"] = str(home / "PAUSE")
    log(f"falcon_pl_bridge_loadgen {cmd} home={home}")
    if cmd == "once":
        return cmd_once(home)
    if cmd in ("pegout", "peg-out", "bridge_pegout"):
        return cmd_pegout(home)
    if cmd == "run":
        return cmd_run(home)
    print("usage: falcon_pl_bridge_loadgen.py [config.env] once|run|pegout", file=sys.stderr)
    return 2

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        log("interrupted")
        sys.exit(130)
