#!/usr/bin/env python3
"""falcon-pl-mmtaker: pair-generic testnet taker flow.

Crosses the spread with short-expiry limit orders from configured taker wallets,
biased toward the MM sine reference (same BAND_LO/BAND_HI/PERIOD_S as mm.env).
Env is re-read each loop.

Reads chain state (order book, tip height, account balances) via Falcon Cloud
JSON-RPC (https://rpc.falcon-fpl.com/v1/rpc) when FALCON_CLOUD_API_KEY /
FALCON_CLOUD_API_KEY_FILE is configured, with optional explorer/ctl fallback.
Writes (place-order) stay on `falcon-pl-ctl` to stay clear of the Free tier's
10 tx/min cap.

Uses integer / Decimal arithmetic throughout so 18-decimal assets (ETH-FPL)
never suffer float precision loss. Never prints keys or env values.
"""
from decimal import Decimal, ROUND_DOWN, ROUND_HALF_UP, getcontext
import json
import math
import os
import random
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


def env(p):
    c = {}
    with open(p) as f:
        for l in f:
            l = l.strip()
            if l and not l.startswith("#") and "=" in l:
                k, v = l.split("=", 1)
                c[k.strip()] = v.strip()
    return c


def base_asset(c):
    explicit = c.get("BASE_ASSET", "").strip()
    if explicit:
        return explicit
    return c["PAIR"].split("-")[0].strip()


def resolve_base_raw(c):
    raw_override = c.get("BASE_RAW_PER_COIN", "").strip()
    if raw_override:
        val = int(raw_override)
        if val <= 0:
            raise ValueError("BASE_RAW_PER_COIN must be positive")
        return val
    dec_override = c.get("BASE_DECIMALS", "").strip()
    if dec_override:
        dec = int(dec_override)
        if dec < 0 or dec > 36:
            raise ValueError("BASE_DECIMALS out of range")
        return 10 ** dec
    asset = base_asset(c).upper()
    if asset in DEFAULT_BASE_DECIMALS:
        return 10 ** DEFAULT_BASE_DECIMALS[asset]
    raise ValueError(f"Set BASE_RAW_PER_COIN or BASE_DECIMALS for {asset}")


def resolve_cloud_api_key(c):
    key = c.get("FALCON_CLOUD_API_KEY", "").strip() or os.environ.get("FALCON_CLOUD_API_KEY", "").strip()
    if key:
        return key
    key_file = c.get("FALCON_CLOUD_API_KEY_FILE", "").strip() or os.environ.get("FALCON_CLOUD_API_KEY_FILE", "").strip()
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


def get(u):
    req = urllib.request.Request(u, headers={"User-Agent": "mmtaker/3"})
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.load(resp)


def rpc(c, method, params):
    url = c.get("FALCON_CLOUD_RPC_URL", DEFAULT_CLOUD_RPC_URL).strip() or DEFAULT_CLOUD_RPC_URL
    key = resolve_cloud_api_key(c)
    if not key:
        raise RuntimeError("FALCON_CLOUD_API_KEY not configured for cloud RPC")
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(
        url,
        data=payload,
        headers={
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
            "User-Agent": "mmtaker/3",
        },
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        body = json.load(resp)
    if body.get("error"):
        raise RuntimeError(f"rpc {method} error: {body['error']}")
    return body["result"]


def use_cloud(c):
    mode = c.get("READ_SOURCE", "").strip().lower()
    if mode == "cloud":
        return True
    if mode == "explorer":
        return False
    return bool(resolve_cloud_api_key(c))


def fetch_book_and_tip(c):
    if use_cloud(c):
        ob = rpc(c, "fpl_orderBook", {"pair": c["PAIR"], "levels": int(c.get("BOOK_LEVELS", "50"))})
        st = rpc(c, "fpl_status", {})
        tip = st.get("tip_height") if st.get("tip_height") is not None else st.get("height")
        return ob, int(tip)
    ob = get(c["API"] + "/explorer/orderbook/" + c["PAIR"])
    tip = int(get(c["STATUS_URL"])["height"])
    return ob, tip


def ctl(c, *a):
    cmd = [c["CTL"], "--addr", c["RPC_ADDR"], *a]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    return r.stdout + r.stderr


def acct(c, w):
    """(fpl, base_raw) or None when unavailable (fail closed)."""
    asset = base_asset(c)
    try:
        if use_cloud(c):
            b = rpc(c, "fpl_getAccount", {"account": w})
        else:
            b = json.loads(ctl(c, "account", "--account", w))["body"]
        return int(b["balance"]), int((b.get("assets") or {}).get(asset, 0))
    except Exception:
        return None


def top(ob):
    """(best_bid, best_ask) raw ints, or a reason string if the book is unusable."""
    if not isinstance(ob, dict):
        return "malformed"
    bids, asks = ob.get("bids"), ob.get("asks")
    if not isinstance(bids, list) or not isinstance(asks, list):
        return "malformed"
    if not bids and not asks:
        return "empty book"
    if not asks:
        return "no asks"
    if not bids:
        return "no bids"
    try:
        bid = max(price_raw_from_obj(b) for b in bids)
        ask = min(price_raw_from_obj(a) for a in asks)
    except Exception:
        return "malformed"
    if bid <= 0 or ask <= 0:
        return "malformed"
    return bid, ask


def ref_price(c, now):
    lo = Decimal(str(c["BAND_LO"]))
    hi = Decimal(str(c["BAND_HI"]))
    per = Decimal(str(c["PERIOD_S"]))
    sine = Decimal(str(0.5 + 0.5 * math.sin(2.0 * math.pi * float(now) / float(per))))
    return lo + (hi - lo) * sine


def decide(c, bid, ask, now, bal, rnd):
    """Pick (side, px, amt, mid, ref) or None. bal=(fpl, base_raw)."""
    base_raw = Decimal(resolve_base_raw(c))
    fpl_raw = Decimal(int(c.get("FPL_RAW_PER_FPL", "1")))
    fee_buf = int(c.get("FEE_BUFFER_FPL", "100"))
    ref = ref_price(c, now)
    mid = (Decimal(int(bid)) + Decimal(int(ask))) / Decimal(2)
    bias = Decimal(str(c["BIAS"]))
    pbuy = float(bias if mid < ref else (Decimal(1) - bias))
    side = "buy" if rnd.random() < pbuy else "sell"
    q = Decimal(str(rnd.uniform(float(c["QUOTE_MIN_FPL"]), float(c["QUOTE_MAX_FPL"]))))
    walk = Decimal(1) + Decimal(str(c["CROSS_BPS"])) / Decimal(10000)

    def calc(s):
        if s == "buy":
            px_dec = Decimal(int(ask)) * walk
            px_int = int((px_dec * fpl_raw).to_integral_value(rounding=ROUND_HALF_UP))
        else:
            px_dec = Decimal(int(bid)) / walk
            px_int = int((px_dec * fpl_raw).to_integral_value(rounding=ROUND_DOWN))
        if px_int <= 0:
            return 0, 0
        amt_int = int((q * base_raw / (Decimal(px_int) / fpl_raw)).to_integral_value(rounding=ROUND_DOWN))
        return px_int, amt_int

    px, amt = calc(side)
    fpl, base_bal = int(bal[0]), int(bal[1])
    if side == "buy" and (fpl < q + fee_buf or amt <= 0):
        side = "sell"
        px, amt = calc("sell")
    if side == "sell" and (base_bal < amt or amt <= 0):
        side = "buy"
        px, amt = calc("buy")
    if px <= 0 or amt <= 0:
        return None
    if (side == "buy" and fpl < q + fee_buf) or (side == "sell" and base_bal < amt):
        return None
    return side, px, amt, mid, ref


class Idle:
    """Log only on state change; capped exponential backoff while unhealthy."""
    def __init__(s):
        s.reason = None
        s.n = 0

    def bad(s, reason, base):
        if reason != s.reason:
            print(f"taker idle: {reason}", flush=True)
        elif s.n % 60 == 0:
            print(f"taker still idle: {reason} ({s.n} checks)", flush=True)
        s.reason = reason
        s.n += 1
        return min(base * (2 ** min(s.n, 5)), 300.0)

    def good(s):
        if s.reason is not None:
            print(f"taker resumed after {s.n} idle checks ({s.reason})", flush=True)
        s.reason = None
        s.n = 0


def main():
    p = sys.argv[1]
    i = 0
    idle = Idle()
    rnd = random.Random()
    while True:
        c = env(p)
        base = float(c["INTERVAL_S"])
        if os.path.exists(c["TAKER_PAUSE"]) or c.get("TAKER_ENABLED", "1") != "1":
            time.sleep(10)
            continue
        try:
            ob, tip = fetch_book_and_tip(c)
        except Exception as e:
            time.sleep(idle.bad(f"api unavailable ({type(e).__name__})", base))
            continue
        t = top(ob)
        if isinstance(t, str):
            time.sleep(idle.bad(t, base))
            continue
        bid, ask = t
        wallets = [w.strip() for w in c["WALLETS"].split(",") if w.strip()]
        w = wallets[i % len(wallets)]
        i += 1
        bal = acct(c, w)
        if bal is None:
            time.sleep(idle.bad(f"account {w} unavailable", base))
            continue
        asset = base_asset(c).lower()
        d = decide(c, bid, ask, time.time(), bal, rnd)
        if d is None:
            print(f"{w} skip: insufficient inventory fpl={bal[0]} {asset}={bal[1]}", flush=True)
            time.sleep(base)
            continue
        idle.good()
        side, px, amt, mid, ref = d
        out = ctl(
            c, "place-order", "--who", w, "--pair", c["PAIR"], "--side", side,
            "--price", str(px), "--amount", str(amt),
            "--expiry-height", str(tip + int(c["EXPIRY_BLOCKS"])),
            "--scheme", c.get("SCHEME", "falcon"),
            "--keys-dir", c["KEYS_DIR"],
            "--network-id", c["NETWORK_ID"],
        )
        ok = "accepted" in out
        print(
            f"{w} {side} px={px} amt={amt} mid={mid:.0f} ref={ref:.0f} "
            f"fpl={bal[0]} {asset}={bal[1]} "
            f"{'submitted' if ok else 'REJECTED ' + ' '.join(out.split())[-200:]}",
            flush=True,
        )
        time.sleep(base * rnd.uniform(0.6, 1.4))


if __name__ == "__main__":
    main()
