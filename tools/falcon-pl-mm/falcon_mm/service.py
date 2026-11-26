# Copyright (c) 2025-2026 BEARTEC. All rights reserved. See LICENSE.
"""Unified falcon-mm loop. Shadow mode never submits writes."""
from __future__ import annotations

import json
import os
import random
import sys
import time
from typing import Any, Callable

from .alerts import AlertGate, post_alert
from .caps import DailyCaps
from .config import MmConfig, PairConfig, pair_to_mm_env, public_summary
from .inventory import WalletBal, below_target, gaps_for_pair, snapshot, total
from .rebalance import AmmSwap, Transfer, plan_amm_swaps, plan_wallet_transfers

# Reuse the proven pair-generic maker/taker, including the one-sided book fix.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import mm  # noqa: E402
import mmtaker  # noqa: E402


def load_json(path: str, default):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return default


def save_json(path: str, obj) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(obj, f, indent=1, sort_keys=True)
    os.replace(tmp, path)


def _short(out: str) -> str:
    s = " ".join((out or "").strip().split())
    return s[-200:]


class Engine:
    def __init__(self, cfg: MmConfig, io_factory: Callable[[dict], Any] | None = None):
        self.cfg = cfg
        self.io_factory = io_factory or (lambda env: mm.IO(env))
        self.rnd = random.Random()
        self.alerts = AlertGate(cfg.alert_min_interval_s)
        self.caps = DailyCaps()
        self.taker_index: dict[str, int] = {}

    def _alert(self, key: str, text: str, now: float | None = None) -> None:
        if not self.alerts.allow(key, now=now):
            return
        ok = post_alert(text, env_file=self.cfg.discord_env_file)
        print(f"ALERT {key} posted={ok}", flush=True)

    def _ctl(self, env: dict, *args: str) -> str:
        if self.cfg.dry_writes:
            print("SHADOW", " ".join(args), flush=True)
            return "accepted (shadow)"
        io = self.io_factory(env)
        return io.ctl_tx(*args)

    def _account(self, io, wallet: str, base: str) -> WalletBal | None:
        try:
            fpl, base_raw, _seq = io.account(wallet)
            return WalletBal(wallet=wallet, fpl=int(fpl), assets={base: int(base_raw)})
        except Exception as e:
            print("acct unavailable", wallet, type(e).__name__, flush=True)
            return None

    def _pools(self, io) -> list[dict]:
        fetch = getattr(io, "pools", None)
        if callable(fetch):
            try:
                return list(fetch() or [])
            except Exception as e:
                print("pools unavailable", type(e).__name__, flush=True)
        return []

    def tick_pair(self, pair: PairConfig, state: dict, now: float | None = None) -> dict:
        summ: dict[str, Any] = {
            "pair": pair.pair,
            "placed": [],
            "taker": None,
            "transfers": [],
            "swaps": [],
            "skipped": [],
            "error": None,
            "paused": False,
            "cap_blocked": False,
        }
        if not pair.enabled or pair.is_paused():
            summ["paused"] = True
            return summ
        env = pair_to_mm_env(self.cfg, pair)
        io = self.io_factory(env)
        wallets = pair.all_wallets()
        bals_list = []
        for w in wallets + [t for t in self.cfg.treasury_wallets if t not in wallets]:
            row = self._account(io, w, pair.base_asset)
            if row:
                bals_list.append(row)
        bals = snapshot(bals_list)
        gaps = gaps_for_pair(bals, pair.all_wallets(), pair.inventory_targets)
        short = below_target(gaps)
        if short:
            bits = ", ".join(f"{g.wallet} {g.asset} have={g.have} target={g.target}" for g in short)
            print(f"inventory short {pair.pair}: {bits}", flush=True)
            self._alert(
                f"inv:{pair.pair}",
                f"falcon-mm [{self.cfg.mode}] {pair.pair} inventory below target: {bits}",
                now=now,
            )

        if self.cfg.rebalance_enabled and self.cfg.wallet_transfer_first:
            xfers = plan_wallet_transfers(bals, gaps)
            for xf in xfers:
                if not self._within_caps(pair, xf.asset, xf.amount, now=now):
                    summ["cap_blocked"] = True
                    continue
                out = self._submit_transfer(env, xf)
                summ["transfers"].append({"src": xf.src, "dest": xf.dest, "asset": xf.asset, "amount": xf.amount, "result": _short(out)})
                if "accepted" in out:
                    self.caps.record(
                        pair.pair,
                        add_base=xf.amount if xf.asset == pair.base_asset else 0,
                        add_fpl=xf.amount if xf.asset == "FPL" else 0,
                        now=now,
                    )

        if self.cfg.rebalance_enabled:
            pools = self._pools(io)
            swaps = plan_amm_swaps(
                bals,
                pair.inventory_targets,
                pools,
                max_frac=self.cfg.amm_max_pool_frac,
                wallets=pair.all_wallets(),
            )
            for sw in swaps:
                if not self._within_caps(pair, sw.token_in, sw.amount_in, now=now):
                    summ["cap_blocked"] = True
                    continue
                out = self._submit_swap(env, sw)
                summ["swaps"].append({
                    "in": sw.token_in, "out": sw.token_out, "amount": sw.amount_in,
                    "pool": sw.pool_id, "result": _short(out),
                })
                if "accepted" in out:
                    self.caps.record(
                        pair.pair,
                        add_base=sw.amount_in if sw.token_in == pair.base_asset else 0,
                        add_fpl=sw.amount_in if sw.token_in == "FPL" else 0,
                        now=now,
                    )

        # Maker tick (shadow uses DRY_RUN via env). Absorb one-sided taker afterwards.
        mm_state = state.setdefault("mm", {}).setdefault(pair.pair, {})
        try:
            maker = mm.tick(env, io, mm_state)
        except Exception as e:
            maker = {"error": f"tick failed: {type(e).__name__}", "placed": [], "skipped": [], "rejected": [], "not_committed": []}
        summ["placed"] = maker.get("placed") or []
        summ["maker_error"] = maker.get("error")
        if maker.get("error"):
            summ["error"] = maker["error"]

        # Taker: one wallet per loop, including one-sided books.
        try:
            self._taker_once(pair, env, io, bals, summ)
        except Exception as e:
            print("taker error", pair.pair, type(e).__name__, flush=True)

        try:
            ob = io.orderbook(pair.pair)
            bids, asks = len(ob.get("bids") or []), len(ob.get("asks") or [])
            if bids == 0 or asks == 0:
                self._alert(
                    f"book:{pair.pair}",
                    f"falcon-mm [{self.cfg.mode}] {pair.pair} one-sided or empty book bids={bids} asks={asks}",
                    now=now,
                )
        except Exception:
            pass
        return summ

    def _within_caps(self, pair: PairConfig, asset: str, amount: int, now: float | None = None) -> bool:
        add_base = amount if asset == pair.base_asset else 0
        add_fpl = amount if asset == "FPL" else 0
        ok = self.caps.allow(
            pair.pair,
            cap_base=pair.daily_cap_base,
            cap_fpl=pair.daily_cap_fpl,
            add_base=add_base,
            add_fpl=add_fpl,
            now=now,
        )
        if not ok:
            print(f"daily cap {pair.pair} blocked {asset} {amount}", flush=True)
            self._alert(
                f"cap:{pair.pair}",
                f"falcon-mm [{self.cfg.mode}] {pair.pair} daily cap reached; paused further size this London day",
                now=now,
            )
        return ok

    def _submit_transfer(self, env: dict, xf: Transfer) -> str:
        if xf.asset == "FPL":
            return self._ctl(env, "pay", "--from", xf.src, "--to", xf.dest, "--amount", str(xf.amount))
        return self._ctl(
            env, "pay-asset", "--from", xf.src, "--to", xf.dest,
            "--asset", xf.asset, "--amount", str(xf.amount),
        )

    def _submit_swap(self, env: dict, sw: AmmSwap) -> str:
        # who: first maker with inventory of token_in; IO doesn't pick here — caller can refine.
        who = env.get("WALLETS", "").split(",")[0].strip()
        return self._ctl(
            env, "swap-route", "--who", who,
            "--token-in", sw.token_in, "--token-out", sw.token_out,
            "--amount-in", str(sw.amount_in),
        )

    def _taker_once(self, pair: PairConfig, env: dict, io, bals: dict[str, WalletBal], summ: dict) -> None:
        takers = pair.taker_wallets or pair.maker_wallets
        if not takers:
            return
        i = self.taker_index.get(pair.pair, 0)
        w = takers[i % len(takers)]
        self.taker_index[pair.pair] = i + 1
        try:
            ob = io.orderbook(pair.pair)
            tip = io.height()
        except Exception as e:
            summ["taker"] = {"idle": f"api unavailable ({type(e).__name__})"}
            return
        t = mmtaker.top(ob)
        if isinstance(t, str):
            summ["taker"] = {"idle": t}
            return
        bid, ask = t
        b = bals.get(w)
        if b is None:
            summ["taker"] = {"idle": f"account {w} unavailable"}
            return
        bal = (b.fpl, b.get(pair.base_asset))
        d = mmtaker.decide(env, bid, ask, time.time(), bal, self.rnd)
        if d is None:
            summ["taker"] = {"skip": w, "fpl": bal[0], "base": bal[1]}
            return
        side, px, amt, mid, ref = d
        if not self._within_caps(pair, pair.base_asset if side == "sell" else "FPL", amt if side == "sell" else int(env["QUOTE_MIN_FPL"])):
            summ["cap_blocked"] = True
            return
        out = self._ctl(
            env, "place-order", "--who", w, "--pair", pair.pair, "--side", side,
            "--price", str(px), "--amount", str(amt),
            "--expiry-height", str(int(tip) + int(pair.expiry_blocks)),
        )
        ok = "accepted" in out
        summ["taker"] = {"wallet": w, "side": side, "px": px, "amt": amt, "ok": ok}
        if ok:
            self.caps.record(
                pair.pair,
                add_base=amt if side == "sell" else 0,
                add_fpl=int(float(env["QUOTE_MIN_FPL"])) if side == "buy" else 0,
            )

    def tick(self, state: dict, now: float | None = None) -> dict:
        report = {"mode": self.cfg.mode, "pairs": {}, "error": None}
        for name, pair in self.cfg.pairs.items():
            report["pairs"][name] = self.tick_pair(pair, state, now=now)
        return report


def run_forever(cfg: MmConfig, once: bool = False) -> None:
    os.makedirs(cfg.state_dir, exist_ok=True)
    raw = load_json(cfg.state_file, {})
    engine = Engine(cfg)
    engine.caps = DailyCaps.from_dict(raw.get("caps"))
    engine.alerts = AlertGate.from_dict(raw.get("alerts"), cfg.alert_min_interval_s)
    engine._alert(
        "start",
        "falcon-mm started in {mode} on Falcon testnet; pairs={pairs}. Existing units stay live.".format(
            mode=cfg.mode,
            pairs=",".join(cfg.pairs),
        ),
    )
    print("start", json.dumps(public_summary(cfg)), flush=True)
    while True:
        state = load_json(cfg.state_file, {})
        engine.caps = DailyCaps.from_dict(state.get("caps"))
        try:
            report = engine.tick(state)
        except Exception as e:
            report = {"mode": cfg.mode, "pairs": {}, "error": type(e).__name__}
            print("tick failed", type(e).__name__, flush=True)
        state["caps"] = engine.caps.to_dict()
        state["alerts"] = engine.alerts.to_dict()
        state["last_report"] = {
            "mode": report["mode"],
            "error": report.get("error"),
            "pairs": {
                n: {
                    "paused": p.get("paused"),
                    "placed": len(p.get("placed") or []),
                    "transfers": len(p.get("transfers") or []),
                    "swaps": len(p.get("swaps") or []),
                    "taker": p.get("taker"),
                    "error": p.get("error"),
                    "cap_blocked": p.get("cap_blocked"),
                }
                for n, p in (report.get("pairs") or {}).items()
            },
        }
        try:
            save_json(cfg.state_file, state)
            save_json(cfg.health_file, {"ts": int(time.time()), **state["last_report"]})
        except Exception as e:
            print("state write failed", type(e).__name__, flush=True)
        if once:
            return
        time.sleep(cfg.tick_s)
