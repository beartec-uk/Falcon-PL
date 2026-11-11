#!/usr/bin/env python3
"""BTC4 (testnet4) Discord alerts: stale headers, submitter down/failing, unminted deposits.

A separate, read-only watcher. It does not sign, submit, or touch bitcoind,
the header submitter, the intake or any committee seat. It reads:

  * node status (falcon-pl-ctl status) for the BTC4 rail tip_height and
    spent_deposits (minted peg-in confirm txids), the same fields
    fpl-operator ledger.rs btc4_rail() and fpl_bridge_intake.py use;
  * the testnet4 explorer tip (Esplora /blocks/tip/height);
  * `systemctl show` ActiveState / NRestarts of the header submitter unit(s);
  * the bridge intake request files (BTC_INTAKE_STATE/<16 hex>.json).

Alerts (one post per problem, one recovery note when it clears; dedupe is
persisted in BTC_DISCORD_STATE, so a restart does not repost):

  btc4:headers:stale     rail tip is behind the explorer tip and has not moved
                         for BTC_HEADER_STALE_SEC (default 1800). Clears when
                         the lag is <= BTC_HEADER_RECOVER_LAG (default 1).
  btc4:submitter:<unit>:stopped
                         unit not active/activating for BTC_SUBMITTER_DOWN_SEC
                         (default 120). Clears when active again.
  btc4:submitter:<unit>:failing
                         >= BTC_SUBMITTER_RESTARTS (default 3) restarts inside
                         BTC_SUBMITTER_WINDOW_SEC (default 900): a crash loop.
                         Clears after a full window with no restart. A
                         submitter that runs but keeps failing to land headers
                         shows up as btc4:headers:stale.
  btc4:deposit:<confirm txid>
                         intake request in awaiting_mint (peg-in confirm has
                         >= 6 confs, so it is mintable) for BTC_UNMINTED_SEC
                         (default 1800) and its confirm txid not in BTC4
                         spent_deposits. Clears when it is in spent_deposits
                         or the request turns "minted".

Why 1800 s for stale headers: testnet4 targets 10-minute blocks but is bursty
and has long gaps, so "no new rail header for N minutes" alone is noise; the
alert only counts time while the explorer is AHEAD of the rail. A healthy
submitter lands a new header within about a minute (pl-btc-header-submitter
POLL_SEC 20 + ADOPT_SEC 25..40; fpl-operator btc4_header_duty every 20 s).
30 minutes behind is ~30x that, rides out explorer and ledger blips, and is
the same 30-minute bar as the unminted-deposit alerts: a peg-in needs 6 more
headers on the rail to mint, so a 30-minute header stall is the first point
it can hold up a mint.

Discord is optional: the webhook is read once at start from
DISCORD_HEALTH_WEBHOOK_URL (the node alerts' env var). Unset = no-op.

  pl-btc-alert-watch.py              # loop every BTC_ALERT_POLL_SEC (60)
  pl-btc-alert-watch.py --once       # one pass
  pl-btc-alert-watch.py --test headers-stale|submitter-stopped|submitter-failing|deposit-unminted
                                     # one labelled TEST message, then exit
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))
import fpl_discord_notify  # noqa: E402

E = os.environ.get
ROOT = Path(E("PL_ROOT", "/home/falcon/falcon-pl-public-testnet-2300"))
CTL = E("FPL_CTL", str(ROOT / "bin/falcon-pl-ctl"))
RPC = E("FPL_RPC", "127.0.0.1:19301").split(",")[0].strip()
ASSET = E("BTC_ALERT_ASSET", "BTC4")
EXPLORER = E("BTC4_EXPLORER", "https://mempool.space/testnet4/api").rstrip("/")
SUBMITTER_UNITS = [u.strip() for u in E("BTC_SUBMITTER_UNITS", "falcon-pl-btc4-header-submitter.service").split(",") if u.strip()]
INTAKE_STATE = Path(E("BTC_INTAKE_STATE", "/opt/fpl-operator/intake"))
STATE = Path(E("BTC_DISCORD_STATE", "/var/lib/falcon-pl-btc-alert-watch/discord.json"))


def _int_env(name: str, default: int) -> int:
    try:
        v = int(str(E(name, str(default))).strip())
        return v if v > 0 else default
    except ValueError:
        return default


STALE_SEC = _int_env("BTC_HEADER_STALE_SEC", 1800)
RECOVER_LAG = _int_env("BTC_HEADER_RECOVER_LAG", 1)
DOWN_SEC = _int_env("BTC_SUBMITTER_DOWN_SEC", 120)
RESTARTS = _int_env("BTC_SUBMITTER_RESTARTS", 3)
WINDOW_SEC = _int_env("BTC_SUBMITTER_WINDOW_SEC", 900)
UNMINTED_SEC = _int_env("BTC_UNMINTED_SEC", 1800)
POLL_SEC = _int_env("BTC_ALERT_POLL_SEC", 60)

TEST_LABELS = {
    "headers-stale": "TEST: Falcon BTC4 header-stale alert (no action needed)",
    "submitter-stopped": "TEST: Falcon BTC4 header-submitter stopped alert (no action needed)",
    "submitter-failing": "TEST: Falcon BTC4 header-submitter failing alert (no action needed)",
    "deposit-unminted": "TEST: Falcon BTC4 unminted-deposit alert (no action needed)",
}
_REQ_RE = re.compile(r"[0-9a-f]{16}\.json")


def log(msg: str) -> None:
    print(time.strftime("%H:%M:%S"), msg, flush=True)


# ---- sources (each replaceable in tests) -------------------------------------
def read_status() -> dict:
    out = subprocess.run([CTL, "--addr", RPC, "status"], capture_output=True, text=True, timeout=60).stdout
    i = out.find("{")
    st = json.loads(out[i:]) if i >= 0 else {}
    return st.get("body") if isinstance(st.get("body"), dict) else st


def read_explorer_tip() -> int:
    with urllib.request.urlopen(EXPLORER + "/blocks/tip/height", timeout=20) as r:
        return int(r.read().decode().strip())


def read_unit(unit: str) -> dict:
    out = subprocess.run(
        ["systemctl", "show", unit, "-p", "ActiveState", "-p", "NRestarts"],
        capture_output=True, text=True, timeout=20,
    ).stdout
    kv = dict(line.split("=", 1) for line in out.splitlines() if "=" in line)
    return {"active": kv.get("ActiveState", "unknown"), "restarts": int(kv.get("NRestarts") or 0)}


def read_intake(state_dir: Path) -> list[dict]:
    out = []
    for f in sorted(state_dir.iterdir()):
        if not _REQ_RE.fullmatch(f.name):
            continue
        try:
            out.append(json.loads(f.read_text()))
        except (OSError, ValueError):
            continue
    return out


def rail_of(st: dict, asset: str) -> dict | None:
    for r in st.get("rails") or []:
        if isinstance(r, dict) and r.get("asset") == asset:
            return r
    return None


# ---- watcher -------------------------------------------------------------------
class Watch:
    def __init__(self, alerts: fpl_discord_notify.DiscordAlerts, *, clock=time.time,
                 status=read_status, explorer_tip=read_explorer_tip, unit=read_unit,
                 intake=read_intake, units=None, intake_dir: Path = INTAKE_STATE):
        self.d = alerts
        self.clock = clock
        self.status = status
        self.explorer_tip = explorer_tip
        self.unit = unit
        self.intake = intake
        self.units = SUBMITTER_UNITS if units is None else units
        self.intake_dir = intake_dir
        self.rail_tip: int | None = None
        self.rail_since = 0.0
        self.down_since: dict[str, float] = {}
        self.restart_log: dict[str, list[tuple[float, int]]] = {}
        self._warned: set[str] = set()

    def _warn_once(self, key: str, msg: str) -> None:
        if key not in self._warned:
            self._warned.add(key)
            log("WARN " + msg)

    def check_headers(self, st: dict | None, now: float) -> None:
        rail = rail_of(st or {}, ASSET) if st else None
        if rail is None:
            return  # node unreachable: node alerts cover that; do not guess
        tip = int(rail.get("tip_height") or 0)
        if tip != self.rail_tip:
            self.rail_tip, self.rail_since = tip, now
        try:
            ext = int(self.explorer_tip())
        except Exception as e:  # noqa: BLE001
            log(f"WARN explorer tip: {type(e).__name__}")
            return
        lag = ext - tip
        key = f"{ASSET.lower()}:headers:stale"
        if lag > 0 and now - self.rail_since >= STALE_SEC:
            self.d.fire(key, f"{ASSET} headers stale (testnet4)",
                        f"rail tip {tip} behind explorer tip {ext} by {lag}; rail unchanged for "
                        f"{int(now - self.rail_since)}s (threshold {STALE_SEC}s)")
        elif lag <= RECOVER_LAG and self.d.is_active(key):
            self.d.resolve(key, f"rail tip {tip} caught up (explorer {ext})")

    def check_units(self, now: float) -> None:
        for u in self.units:
            try:
                info = self.unit(u)
            except Exception as e:  # noqa: BLE001
                log(f"WARN systemctl {u}: {type(e).__name__}")
                continue
            stop_key = f"{ASSET.lower()}:submitter:{u}:stopped"
            if info["active"] in ("active", "activating", "reloading"):
                self.down_since.pop(u, None)
                if self.d.is_active(stop_key):
                    self.d.resolve(stop_key, f"{u} is {info['active']} again")
            else:
                since = self.down_since.setdefault(u, now)
                if now - since >= DOWN_SEC:
                    self.d.fire(stop_key, f"{ASSET} header submitter stopped",
                                f"{u} is {info['active']} for {int(now - since)}s")
            hist = self.restart_log.setdefault(u, [])
            cur = int(info["restarts"])
            if hist and cur < hist[-1][1]:
                hist.clear()  # NRestarts resets on a manual start; count from here
            hist.append((now, cur))
            while len(hist) > 1 and now - hist[0][0] > WINDOW_SEC:
                hist.pop(0)
            n = hist[-1][1] - hist[0][1]
            span = now - hist[0][0]
            fail_key = f"{ASSET.lower()}:submitter:{u}:failing"
            if n >= RESTARTS:
                self.d.fire(fail_key, f"{ASSET} header submitter keeps failing",
                            f"{u} restarted {n} times in the last {int(span)}s (crash loop)")
            elif n == 0 and span >= WINDOW_SEC * 0.9 and self.d.is_active(fail_key):
                self.d.resolve(fail_key, f"{u}: no restart for {WINDOW_SEC // 60} min")

    def check_deposits(self, st: dict | None, now: float) -> None:
        rail = rail_of(st or {}, ASSET) if st else None
        spent = {str(t).lower() for t in ((rail or {}).get("spent_deposits") or []) if isinstance(t, str)}
        try:
            reqs = self.intake(self.intake_dir)
        except OSError as e:
            self._warn_once("intake", f"intake state {self.intake_dir}: {type(e).__name__}")
            reqs = []
        prefix = f"{ASSET.lower()}:deposit:"
        minted_by_state = set()
        for r in reqs:
            txid = str(r.get("peg_in_confirm_txid") or "").strip().lower()
            if not txid:
                continue
            if r.get("state") == "minted":
                minted_by_state.add(txid)
                continue
            if r.get("state") != "awaiting_mint" or rail is None or txid in spent:
                continue
            since = float(r.get("awaiting_mint_since") or r.get("updated") or 0)
            if since > 0 and now - since >= UNMINTED_SEC:
                self.d.fire(prefix + txid, f"{ASSET} deposit unminted over {UNMINTED_SEC // 60} min",
                            f"request {r.get('id')} confirm {txid} awaiting_mint for {int(now - since)}s "
                            f"(confirmations={r.get('confirmations')}, threshold {UNMINTED_SEC}s)")
        for key in self.d.active_keys(prefix):
            txid = key[len(prefix):]
            if txid in spent or txid in minted_by_state:
                self.d.resolve(key, f"deposit {txid} minted")

    def poll(self) -> int:
        now = self.clock()
        try:
            st = self.status()
        except Exception as e:  # noqa: BLE001
            log(f"WARN node status: {type(e).__name__}")
            st = None
        for f in (lambda: self.check_headers(st, now), lambda: self.check_units(now),
                  lambda: self.check_deposits(st, now)):
            try:
                f()
            except Exception as e:  # noqa: BLE001
                log(f"WARN check {type(e).__name__}: {e}")
        self.d.forget_stale(now)
        return self.d.flush()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--once", action="store_true")
    ap.add_argument("--test", choices=sorted(TEST_LABELS))
    a = ap.parse_args(argv)
    d = fpl_discord_notify.DiscordAlerts(STATE, source="btc-alert-watch")
    if a.test:
        return 0 if d.send_test(TEST_LABELS[a.test]) else 1
    log(f"btc alert watch asset={ASSET} units={','.join(SUBMITTER_UNITS)} intake={INTAKE_STATE} "
        f"stale={STALE_SEC}s unminted={UNMINTED_SEC}s discord={'on' if d.enabled else 'off'}")
    if not d.enabled:
        log(f"{fpl_discord_notify.WEBHOOK_ENV} not set; nothing to do")
        return 0
    w = Watch(d)
    while True:
        w.poll()
        if a.once:
            return 0
        time.sleep(POLL_SEC)


if __name__ == "__main__":
    raise SystemExit(main())
