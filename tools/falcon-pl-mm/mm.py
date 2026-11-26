#!/usr/bin/env python3
"""falcon-pl-mm: pair-generic testnet order-book maker.

Quotes a ladder (LEVELS per side, SPACING_BPS apart, QUOTE_MIN_FPL..QUOTE_MAX_FPL)
around a slow sine reference between BAND_LO and BAND_HI.
Reads chain state (height, order book, open orders, account balances/sequences)
via Falcon Cloud JSON-RPC (https://rpc.falcon-fpl.com/v1/rpc) when an API key
is configured, with optional legacy explorer/ctl fallback.
Writes (place-order / cancel-order) go through `falcon-pl-ctl` to stay clear
of Falcon Cloud Free tier's 10 tx/min submission cap.

Uses integer / Decimal arithmetic throughout so 18-decimal assets (e.g. ETH-FPL)
never suffer float precision loss. Never prints keys or env values.
"""
from decimal import Decimal, ROUND_DOWN, ROUND_HALF_UP, getcontext
import json
import math
import os
import shlex
import subprocess
import sys
import time
import urllib.request

getcontext().prec = 50

DEFAULT_CLOUD_RPC_URL = "https://rpc.falcon-fpl.com/v1/rpc"
DEFAULT_BASE_DECIMALS = {
    "USDC": 6,
    "BTC4": 8,
    "ETH": 18,
}


def load_env(path):
    cfg = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                cfg[k.strip()] = v.strip()
    return cfg


def base_asset(cfg):
    explicit = cfg.get("BASE_ASSET", "").strip()
    if explicit:
        return explicit
    return cfg["PAIR"].split("-")[0].strip()


def resolve_base_raw(cfg):
    raw_override = cfg.get("BASE_RAW_PER_COIN", "").strip()
    if raw_override:
        val = int(raw_override)
        if val <= 0:
            raise ValueError("BASE_RAW_PER_COIN must be positive")
        return val
    dec_override = cfg.get("BASE_DECIMALS", "").strip()
    if dec_override:
        dec = int(dec_override)
        if dec < 0 or dec > 36:
            raise ValueError("BASE_DECIMALS out of range")
        return 10 ** dec
    asset = base_asset(cfg).upper()
    if asset in DEFAULT_BASE_DECIMALS:
        return 10 ** DEFAULT_BASE_DECIMALS[asset]
    raise ValueError(f"Set BASE_RAW_PER_COIN or BASE_DECIMALS for {asset}")


def resolve_cloud_api_key(cfg):
    key = cfg.get("FALCON_CLOUD_API_KEY", "").strip() or os.environ.get("FALCON_CLOUD_API_KEY", "").strip()
    if key:
        return key
    key_file = cfg.get("FALCON_CLOUD_API_KEY_FILE", "").strip() or os.environ.get("FALCON_CLOUD_API_KEY_FILE", "").strip()
    if key_file and os.path.exists(key_file):
        with open(key_file) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    k, v = line.split("=", 1)
                    if k.strip() == "FALCON_CLOUD_API_KEY" and v.strip():
                        return v.strip()
                else:
                    return line
    return ""


def price_raw_from_obj(obj):
    if isinstance(obj, dict):
        p = obj.get("price")
        if isinstance(p, dict):
            return int(p["raw"])
        return int(p)
    return int(obj)


def ref_price(cfg, t):
    lo = Decimal(str(cfg["BAND_LO"]))
    hi = Decimal(str(cfg["BAND_HI"]))
    per = Decimal(str(cfg["PERIOD_S"]))
    sine = Decimal(str(0.5 + 0.5 * math.sin(2.0 * math.pi * float(t) / float(per))))
    return lo + (hi - lo) * sine


def ladder(cfg, mid):
    mid_dec = Decimal(str(mid))
    lv = int(cfg["LEVELS"])
    sp = Decimal(str(cfg["SPACING_BPS"])) / Decimal(10000)
    qmin = Decimal(str(cfg["QUOTE_MIN_FPL"]))
    qmax = Decimal(str(cfg["QUOTE_MAX_FPL"]))
    fpl_raw = Decimal(int(cfg.get("FPL_RAW_PER_FPL", "1")))
    base_raw = Decimal(resolve_base_raw(cfg))
    out = []
    denom = Decimal(max(lv - 1, 1))
    for i in range(1, lv + 1):
        q = qmin + (qmax - qmin) * Decimal(i - 1) / denom
        for side, px_dec in (
            ("buy", mid_dec * (Decimal(1) - sp * Decimal(i))),
            ("sell", mid_dec * (Decimal(1) + sp * Decimal(i))),
        ):
            if px_dec <= 0:
                continue
            px_int = int((px_dec * fpl_raw).to_integral_value(rounding=ROUND_HALF_UP))
            amount = int((q * base_raw / px_dec).to_integral_value(rounding=ROUND_DOWN))
            if px_int > 0 and amount > 0:
                out.append((side, px_int, amount))
    return out


def quote_ceil(amount, price, base_raw):
    return -(-int(amount) * int(price) // int(base_raw))


class IO:
    def __init__(self, cfg):
        self.cfg = cfg
        self.cloud_url = cfg.get("FALCON_CLOUD_RPC_URL", DEFAULT_CLOUD_RPC_URL).strip() or DEFAULT_CLOUD_RPC_URL
        self.cloud_key = resolve_cloud_api_key(cfg)
        self.read_source = cfg.get("READ_SOURCE", "cloud" if self.cloud_key else "explorer").strip().lower()

    def _run(self, cmd):
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        return r.stdout + r.stderr

    def ctl_tx(self, *a):
        c = self.cfg
        cmd = [
            c["CTL"], "--addr", c["RPC_ADDR"], *a,
            "--scheme", c.get("SCHEME", "falcon"),
            "--keys-dir", c["KEYS_DIR"],
            "--network-id", c["NETWORK_ID"],
        ]
        if c.get("DRY_RUN", "1") != "0":
            print("DRY", " ".join(shlex.quote(x) for x in a), flush=True)
            return "accepted (dry)"
        return self._run(cmd)

    def rpc(self, method, params):
        if not self.cloud_key:
            raise RuntimeError("FALCON_CLOUD_API_KEY not configured for cloud RPC")
        payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
        req = urllib.request.Request(
            self.cloud_url,
            data=payload,
            headers={
                "Authorization": f"Bearer {self.cloud_key}",
                "Content-Type": "application/json",
                "User-Agent": "falcon-pl-mm/3",
            },
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            body = json.load(resp)
        if body.get("error"):
            raise RuntimeError(f"rpc {method} error: {body['error']}")
        return body["result"]

    def http(self, u):
        req = urllib.request.Request(u, headers={"User-Agent": "falcon-pl-mm/3"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.load(resp)

    def height(self):
        if self.read_source == "cloud":
            st = self.rpc("fpl_status", {})
            val = st.get("tip_height") if st.get("tip_height") is not None else st.get("height")
            return int(val)
        return int(self.http(self.cfg.get("STATUS_URL", "https://falcon-fpl.com/api/status"))["height"])

    def account(self, w):
        asset = base_asset(self.cfg)
        if self.read_source == "cloud":
            b = self.rpc("fpl_getAccount", {"account": w})
        else:
            r = subprocess.run(
                [self.cfg["CTL"], "--addr", self.cfg["RPC_ADDR"], "account", "--account", w],
                capture_output=True, text=True, timeout=30,
            )
            b = json.loads(r.stdout)["body"]
        return int(b["balance"]), int((b.get("assets") or {}).get(asset, 0)), int(b["sequence"])

    def open_orders(self, w):
        pair = self.cfg["PAIR"]
        if self.read_source == "cloud":
            res = self.rpc("fpl_openOrders", {"account": w})
            raw_orders = res.get("orders") or []
        else:
            api = self.cfg.get("API", "https://falcon-fpl.com/api/v1")
            raw_orders = self.http(f"{api}/explorer/accounts/{w}/orders").get("orders") or []
        return [o for o in raw_orders if o.get("pair") == pair and o.get("owner", w) == w]

    def orderbook(self, pair):
        if self.read_source == "cloud":
            levels = int(self.cfg.get("BOOK_LEVELS", "50"))
            return self.rpc("fpl_orderBook", {"pair": pair, "levels": levels})
        api = self.cfg.get("API", "https://falcon-fpl.com/api/v1")
        return self.http(f"{api}/explorer/orderbook/{pair}")

    def now(self):
        return time.time()

    def sleep(self, s):
        time.sleep(s)


def retry(fn, tries=3, base=2.0, io=None):
    err = None
    for i in range(tries):
        try:
            return fn()
        except Exception as e:
            err = e
            if i + 1 < tries:
                (io.sleep if io else time.sleep)(base * (2 ** i))
    raise err


def short(out):
    """Last line(s) of ctl output, single-line, bounded (ctl prints no secrets)."""
    s = " ".join(out.strip().split())
    return s[-200:]


def load_json(path, default):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return default


def save_json(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(obj, f, indent=1, sort_keys=True)
    os.replace(tmp, path)


def tick(cfg, io, state):
    """One maker cycle. Returns a dict summary (also used by tests)."""
    pair = cfg["PAIR"]
    base_raw = resolve_base_raw(cfg)
    fpl_raw = int(cfg.get("FPL_RAW_PER_FPL", "1"))
    wallets = [w.strip() for w in cfg["WALLETS"].split(",") if w.strip()]
    fee_res = int(cfg.get("FEE_RESERVE_FPL", "50"))
    max_open = int(cfg.get("MAX_OPEN_PER_WALLET", "28"))
    cap_side = int(cfg.get("MAX_RESTING_PER_SIDE", str(int(cfg["LEVELS"]) * 12)))
    pend_max = int(cfg.get("PENDING_MAX_TICKS", "5"))
    summ = {"placed": [], "skipped": [], "rejected": [], "not_committed": [], "cancelled": 0, "error": None}
    now = io.now()
    ref = ref_price(cfg, now)

    try:
        height = int(retry(lambda: io.height(), io=io))
    except Exception as e:
        summ["error"] = f"status unavailable: {type(e).__name__}"
        return summ

    bal = {}
    for w in wallets:
        try:
            bal[w] = list(retry(lambda w=w: io.account(w), tries=2, io=io))
        except Exception as e:
            print("acct unavailable", w, type(e).__name__, flush=True)

    orders = {}
    for w in wallets:
        try:
            orders[w] = retry(lambda w=w: io.open_orders(w), tries=2, io=io)
        except Exception as e:
            print("orders unavailable", w, type(e).__name__, flush=True)

    busy = set()
    pend = state.setdefault("pending", {})
    for w in list(pend):
        p = pend[w]
        if w in bal and bal[w][2] > p["seq"]:
            del pend[w]
            continue
        p["ticks"] = p.get("ticks", 0) + 1
        if p["ticks"] > pend_max:
            summ["not_committed"].append((w, p.get("what", "")))
            print(f"NOT COMMITTED after {p['ticks']} ticks (node rejected/dropped): {w} {p.get('what', '')}", flush=True)
            del pend[w]
            continue
        busy.add(w)

    stale_bps = Decimal(str(cfg.get("STALE_BPS", "150"))) / Decimal(10000)
    if cfg.get("CANCEL_BEFORE_REQUOTE", "1") == "1" and ref > 0:
        for w, os_ in orders.items():
            if w in busy or w not in bal:
                continue
            st = sorted(
                o["id"]
                for o in os_
                if o.get("expiry_height") is None
                or abs(Decimal(price_raw_from_obj(o)) / Decimal(fpl_raw) - ref) / ref > stale_bps
            )
            if st:
                out = io.ctl_tx("cancel-order", "--who", w, "--order-id", str(st[0]))
                if "accepted" in out:
                    pend[w] = {"seq": bal[w][2], "ticks": 0, "what": f"cancel {st[0]}"}
                    summ["cancelled"] += 1
                else:
                    print("cancel rejected", w, st[0], short(out), flush=True)
                busy.add(w)

    live = lambda o: o.get("expiry_height") is None or int(o["expiry_height"]) >= height
    resting = {"buy": 0, "sell": 0}
    for os_ in orders.values():
        for o in os_:
            if live(o):
                resting[o["side"]] += 1

    try:
        ob = retry(lambda: io.orderbook(pair), tries=2, io=io)
        bb = max([price_raw_from_obj(o) for o in (ob.get("bids") or [])] or [0])
        ba = min([price_raw_from_obj(o) for o in (ob.get("asks") or [])] or [10 ** 30])
    except Exception as e:
        summ["error"] = f"orderbook unavailable: {type(e).__name__}"
        return summ

    exp = str(height + int(cfg.get("ORDER_EXPIRY_BLOCKS", "40")))
    used = set()
    avail = {w: [bal[w][0], bal[w][1]] for w in bal if w in orders}
    lad = ladder(cfg, ref)
    lad.sort(key=lambda x: 0 if x[0] == "sell" else 1)
    for side, px, amt in lad:
        if resting[side] >= cap_side:
            summ["skipped"].append((side, px, "side cap"))
            continue
        if (side == "sell" and px <= bb) or (side == "buy" and px >= ba):
            summ["skipped"].append((side, px, "would cross"))
            continue
        need_fpl = fee_res + (quote_ceil(amt, px, base_raw) if side == "buy" else 0)
        need_base = amt if side == "sell" else 0
        cands = [
            w for w in avail
            if w not in used
            and w not in busy
            and len(orders[w]) < max_open
            and avail[w][0] >= need_fpl
            and avail[w][1] >= need_base
        ]
        if not cands:
            summ["skipped"].append((side, px, "no funded wallet"))
            continue
        key = (lambda w: avail[w][1]) if side == "sell" else (lambda w: avail[w][0])
        w = max(cands, key=lambda w: (key(w), w))
        used.add(w)
        avail[w][0] -= need_fpl
        avail[w][1] -= need_base
        out = io.ctl_tx(
            "place-order", "--who", w, "--pair", pair, "--side", side,
            "--price", str(px), "--amount", str(amt), "--expiry-height", exp,
        )
        if "accepted" in out:
            pend[w] = {"seq": bal[w][2], "ticks": 0, "what": f"{side} {amt}@{px}"}
            resting[side] += 1
            summ["placed"].append((w, side, px, amt))
        else:
            summ["rejected"].append((w, side, short(out)))
            print(f"place rejected {w} {side} {amt}@{px}: {short(out)}", flush=True)

    if summ["skipped"]:
        agg = {}
        for s, _, why in summ["skipped"]:
            agg[f"{s}:{why}"] = agg.get(f"{s}:{why}", 0) + 1
        print("skipped", agg, flush=True)

    summ["ref"] = ref
    summ["height"] = height
    summ["inventory"] = {
        "fpl": sum(b[0] for b in bal.values()),
        "base": str(sum(b[1] for b in bal.values())),
        "wallets_ok": len(avail),
    }
    return summ


def cancel_all_tick(cfg, io, state):
    """Kill switch: cancel every open order on PAIR for every wallet, one per wallet per tick
    (each cancel needs the wallet's sequence to move before the next). Places nothing.
    Returns {"remaining", "cancelled", "busy", "error"}; remaining == 0 means the book is clear."""
    wallets = [w.strip() for w in cfg["WALLETS"].split(",") if w.strip()]
    pend_max = int(cfg.get("PENDING_MAX_TICKS", "5"))
    pend = state.setdefault("pending", {})
    out = {"remaining": 0, "cancelled": 0, "busy": 0, "error": None}
    for w in wallets:
        try:
            bal = retry(lambda w=w: io.account(w), tries=2, io=io)
            os_ = retry(lambda w=w: io.open_orders(w), tries=2, io=io)
        except Exception as e:
            out["error"] = f"read failed: {type(e).__name__}"
            out["remaining"] += 1  # unknown: never report clear on a failed read
            continue
        out["remaining"] += len(os_)
        p = pend.get(w)
        if p is not None:
            if bal[2] > p["seq"]:
                del pend[w]
            else:
                p["ticks"] = p.get("ticks", 0) + 1
                if p["ticks"] <= pend_max:
                    out["busy"] += 1
                    continue
                print(f"NOT COMMITTED after {p['ticks']} ticks: {w} {p.get('what', '')}", flush=True)
                del pend[w]
        if not os_:
            continue
        oid = sorted(int(o["id"]) for o in os_)[0]
        res = io.ctl_tx("cancel-order", "--who", w, "--order-id", str(oid))
        if "accepted" in res:
            pend[w] = {"seq": bal[2], "ticks": 0, "what": f"cancel-all {oid}"}
            out["cancelled"] += 1
        else:
            print("cancel-all rejected", w, oid, short(res), flush=True)
    return out


def update_health(cfg, io, state, summ):
    path = cfg.get("HEALTH_FILE", "/var/lib/falcon-pl-mm/health.json")
    warn_ticks = int(cfg.get("EMPTY_WARN_TICKS", "3"))
    ok_ticks = int(cfg.get("RECOVER_OK_TICKS", "2"))
    h = state.setdefault("health", {"status": "ok", "bad": 0, "good": 0})
    bids = asks = None
    try:
        ob = io.orderbook(cfg["PAIR"])
        bids, asks = len(ob.get("bids") or []), len(ob.get("asks") or [])
    except Exception:
        pass
    bad = bids is None or bids == 0 or asks == 0 or summ.get("error") is not None
    h["bad"], h["good"] = (h["bad"] + 1, 0) if bad else (0, h["good"] + 1)
    prev = h["status"]
    if prev == "ok" and h["bad"] >= warn_ticks:
        h["status"] = "warn"
        h["since"] = io.now()
    elif prev == "warn" and h["good"] >= ok_ticks:
        h["status"] = "ok"
        h["since"] = io.now()
    if h["status"] != prev:
        print(f"HEALTH {prev}->{h['status']} bids={bids} asks={asks} err={summ.get('error')}", flush=True)
    out = {
        "ts": int(io.now()),
        "pair": cfg["PAIR"],
        "status": h["status"],
        "since": int(h.get("since", 0)),
        "bids": bids,
        "asks": asks,
        "consecutive_bad_ticks": h["bad"],
        "placed": len(summ.get("placed", [])),
        "rejected": len(summ.get("rejected", [])),
        "not_committed": len(summ.get("not_committed", [])),
        "skipped_no_funds": sum(1 for s in summ.get("skipped", []) if s[2] == "no funded wallet"),
        "error": summ.get("error"),
        "inventory": summ.get("inventory"),
        "height": summ.get("height"),
    }
    try:
        save_json(path, out)
    except Exception as e:
        print("health write failed", type(e).__name__, flush=True)
    return out


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "/etc/falcon-pl-mm/mm.env"
    fails = 0
    while True:
        cfg = load_env(path)
        if os.path.exists(cfg.get("MM_CANCEL_ALL", "/nonexistent")):
            # Kill switch: pull every resting order on this pair, then exit. Never places.
            sp = cfg.get("STATE_FILE", "/var/lib/falcon-pl-mm/state.json")
            state = load_json(sp, {})
            res = cancel_all_tick(cfg, IO(cfg), state)
            try:
                save_json(sp, state)
            except Exception as e:
                print("state write failed", type(e).__name__, flush=True)
            print(
                f"MM_CANCEL_ALL remaining={res['remaining']} cancelled={res['cancelled']} "
                f"waiting={res['busy']} error={res['error']}",
                flush=True,
            )
            if res["remaining"] == 0 and not res["error"]:
                print("MM_CANCEL_ALL: no open orders left, exiting", flush=True)
                return
            if cfg.get("ONCE") == "1":
                return
            time.sleep(float(cfg.get("TICK_S", "20")))
            continue
        if os.path.exists(cfg.get("MM_PAUSE", "/nonexistent")):
            time.sleep(10)
            continue
        sp = cfg.get("STATE_FILE", "/var/lib/falcon-pl-mm/state.json")
        state = load_json(sp, {})
        io = IO(cfg)
        try:
            summ = tick(cfg, io, state)
        except Exception as e:
            summ = {
                "error": f"tick failed: {type(e).__name__}",
                "placed": [],
                "skipped": [],
                "rejected": [],
                "not_committed": [],
            }
        update_health(cfg, io, state, summ)
        try:
            save_json(sp, state)
        except Exception as e:
            print("state write failed", type(e).__name__, flush=True)
        if summ.get("error"):
            fails += 1
            print("tick error", summ["error"], flush=True)
        else:
            fails = 0
            print(
                f"tick ref={summ['ref']:.0f} h={summ['height']} placed={len(summ['placed'])} "
                f"rejected={len(summ['rejected'])} cancelled={summ['cancelled']} skipped={len(summ['skipped'])}",
                flush=True,
            )
        if cfg.get("ONCE") == "1":
            return
        base = float(cfg["TICK_S"])
        time.sleep(min(base * (2 ** min(fails, 4)), 600) if fails else base)


if __name__ == "__main__":
    main()
