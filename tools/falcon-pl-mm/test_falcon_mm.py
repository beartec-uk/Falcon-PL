#!/usr/bin/env python3
# Copyright (c) 2025-2026 BEARTEC. All rights reserved. See LICENSE.
from decimal import Decimal
import json
import os
import tempfile
import time
import unittest

from falcon_mm.caps import DailyCaps, london_day
from falcon_mm.config import load_config, pair_to_mm_env, public_summary
from falcon_mm.inventory import WalletBal, gaps_for_pair, below_target
from falcon_mm.rebalance import plan_amm_swaps, plan_wallet_transfers
from falcon_mm.service import Engine


def write_cfg(tmp, **overrides):
    raw = {
        "mode": "shadow",
        "state_dir": tmp,
        "health_file": os.path.join(tmp, "health.json"),
        "state_file": os.path.join(tmp, "state.json"),
        "amm_max_pool_frac": "0.02",
        "rebalance_enabled": True,
        "tick_s": 1,
        "pairs": {
            "ETH-FPL": {
                "base_asset": "ETH",
                "base_decimals": 18,
                "maker_wallets": ["mmeth01", "mmeth02"],
                "taker_wallets": ["mmtakereth01"],
                "inventory_targets": {"ETH": str(10 ** 18), "FPL": "1000"},
                "daily_cap_base": str(10 ** 19),
                "daily_cap_fpl": "100000",
                "band_lo": "48000",
                "band_hi": "52000",
                "levels": "1",
                "quote_min_fpl": "500",
                "quote_max_fpl": "500",
                "spacing_bps": "25",
            }
        },
    }
    raw.update(overrides)
    path = os.path.join(tmp, "config.json")
    with open(path, "w") as f:
        json.dump(raw, f)
    return path


class FakeIO:
    def __init__(self, env, accounts=None, book=None, pools=None, height=1000):
        self.cfg = env
        self.accounts = accounts or {}
        self.book = book or {"bids": [{"price": 49000}], "asks": [{"price": 51000}]}
        self._pools = pools or []
        self._height = height
        self.ctl_calls = []
        self.dry_calls = []

    def account(self, w):
        row = self.accounts[w]
        return row[0], row[1], row[2]

    def open_orders(self, w):
        return []

    def orderbook(self, pair):
        return self.book

    def height(self):
        return self._height

    def pools(self):
        return self._pools

    def now(self):
        return 0

    def sleep(self, s):
        return

    def ctl_tx(self, *args):
        if self.cfg.get("DRY_RUN", "1") != "0":
            self.dry_calls.append(args)
            return "accepted (dry)"
        self.ctl_calls.append(args)
        return 'tx_id=abc {"type":"ok","msg":"accepted"}'


class TestConfig(unittest.TestCase):
    def test_load_and_public_summary_omits_secrets(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = write_cfg(tmp, cloud_api_key_file="/etc/falcon-mm/cloud-api-key")
            cfg = load_config(path)
            self.assertEqual(cfg.mode, "shadow")
            self.assertTrue(cfg.dry_writes)
            self.assertEqual(cfg.pairs["ETH-FPL"].base_asset, "ETH")
            summ = public_summary(cfg)
            blob = json.dumps(summ)
            self.assertNotIn("cloud_api_key", blob)
            self.assertNotIn("/etc/falcon-mm/cloud-api-key", blob)
            env = pair_to_mm_env(cfg, cfg.pairs["ETH-FPL"])
            self.assertEqual(env["DRY_RUN"], "1")


class TestRebalance(unittest.TestCase):
    def test_moves_between_our_wallets_first_without_going_below_target(self):
        bals = {
            "mmeth01": WalletBal("mmeth01", fpl=5000, assets={"ETH": 3 * 10 ** 18}),
            "mmeth02": WalletBal("mmeth02", fpl=5000, assets={"ETH": 0}),
        }
        targets = {"ETH": 10 ** 18, "FPL": 1000}
        gaps = gaps_for_pair(bals, ["mmeth01", "mmeth02"], targets)
        self.assertEqual(len(below_target(gaps)), 1)
        xfers = plan_wallet_transfers(bals, gaps)
        self.assertEqual(len(xfers), 1)
        xf = xfers[0]
        self.assertEqual(xf.src, "mmeth01")
        self.assertEqual(xf.dest, "mmeth02")
        self.assertEqual(xf.asset, "ETH")
        self.assertEqual(xf.amount, 10 ** 18)
        # donor stays at or above target
        self.assertGreaterEqual(bals["mmeth01"].get("ETH") - xf.amount, targets["ETH"])

    def test_amm_swap_capped_at_two_percent_of_pool(self):
        bals = {
            "mmeth01": WalletBal("mmeth01", fpl=100_000, assets={"ETH": 0}),
        }
        # overall short ETH, long FPL. Pool has 50 ETH (50e18).
        pools = [{"id": "eth-fpl", "asset_a": "FPL", "asset_b": "ETH", "reserve_a": "5000000", "reserve_b": str(50 * 10 ** 18)}]
        # one wallet, target 1 ETH and 0 FPL so FPL is long, ETH short
        swaps = plan_amm_swaps(bals, {"ETH": 10 ** 18, "FPL": 0}, pools, max_frac=Decimal("0.02"))
        self.assertEqual(len(swaps), 1)
        sw = swaps[0]
        self.assertEqual(sw.token_in, "FPL")
        self.assertEqual(sw.token_out, "ETH")
        # 2% of 5_000_000 FPL reserve
        self.assertEqual(sw.max_in, 100_000)
        self.assertEqual(sw.amount_in, 100_000)

    def test_cross_asset_plans_first_leg_through_fpl(self):
        bals = {
            "mmeth01": WalletBal("mmeth01", fpl=10, assets={"ETH": 5 * 10 ** 18}),
        }
        pools = [
            {"id": "eth-fpl", "asset_a": "ETH", "asset_b": "FPL", "reserve_a": str(50 * 10 ** 18), "reserve_b": "5000000"},
            {"id": "usdc-fpl", "asset_a": "USDC", "asset_b": "FPL", "reserve_a": "1000000000000", "reserve_b": "5000000"},
        ]
        # short USDC (target high), long ETH
        swaps = plan_amm_swaps(
            bals,
            {"ETH": 10 ** 18, "USDC": 10 ** 12, "FPL": 0},
            pools,
            max_frac=Decimal("0.02"),
        )
        self.assertTrue(swaps)
        self.assertEqual(swaps[0].token_in, "ETH")
        self.assertEqual(swaps[0].token_out, "FPL")
        self.assertLessEqual(swaps[0].amount_in, int(0.02 * 50 * 10 ** 18))


class TestCaps(unittest.TestCase):
    def test_daily_cap_and_london_day(self):
        caps = DailyCaps()
        self.assertTrue(caps.allow("ETH-FPL", cap_base=100, cap_fpl=0, add_base=50, now=0))
        caps.record("ETH-FPL", add_base=50, now=0)
        self.assertFalse(caps.allow("ETH-FPL", cap_base=100, cap_fpl=0, add_base=60, now=0))
        self.assertTrue(london_day(0))  # 1970-01-01 in London

    def test_pause_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            pause = os.path.join(tmp, "ETH.pause")
            path = write_cfg(tmp)
            cfg = load_config(path)
            p = cfg.pairs["ETH-FPL"]
            p.pause_file = pause
            self.assertFalse(p.is_paused())
            open(pause, "w").close()
            self.assertTrue(p.is_paused())


class TestShadowEngine(unittest.TestCase):
    def test_shadow_logs_but_does_not_forward_writes_to_ctl(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = write_cfg(tmp)
            cfg = load_config(path)
            accounts = {
                "mmeth01": (5000, 3 * 10 ** 18, 7),
                "mmeth02": (5000, 0, 3),
                "mmtakereth01": (8000, 10 ** 18, 2),
            }
            pools = [{
                "id": "eth-fpl",
                "asset_a": "ETH",
                "asset_b": "FPL",
                "reserve_a": str(50 * 10 ** 18),
                "reserve_b": "5000000",
            }]
            ios = []

            def factory(env):
                io = FakeIO(env, accounts=accounts, pools=pools)
                ios.append(io)
                return io

            eng = Engine(cfg, io_factory=factory)
            report = eng.tick({})
            eth = report["pairs"]["ETH-FPL"]
            self.assertFalse(eth["paused"])
            self.assertTrue(eth["transfers"])
            self.assertEqual(eth["transfers"][0]["src"], "mmeth01")
            self.assertEqual(eth["transfers"][0]["dest"], "mmeth02")
            # shadow path must not invoke FakeIO.ctl_tx
            self.assertEqual(sum(len(io.ctl_calls) for io in ios), 0)
            self.assertEqual(eth["transfers"][0]["result"], "accepted (shadow)")

    def test_one_sided_taker_still_sells_into_bids(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = write_cfg(tmp)
            cfg = load_config(path)
            accounts = {
                "mmeth01": (50, 10 ** 18, 1),
                "mmeth02": (50, 10 ** 18, 1),
                "mmtakereth01": (50, 10 ** 18, 1),
            }
            book = {"bids": [{"price": 49500}], "asks": []}

            def factory(env):
                return FakeIO(env, accounts=accounts, book=book)

            eng = Engine(cfg, io_factory=factory)
            # disable rebalance so the tick is just book making / taking
            cfg.rebalance_enabled = False
            report = eng.tick({})
            taker = report["pairs"]["ETH-FPL"]["taker"]
            self.assertIsNotNone(taker)
            self.assertEqual(taker.get("side"), "sell")
            self.assertTrue(taker.get("ok"))


class TestCancelAllEngine(unittest.TestCase):
    def test_cancel_all_file_cancels_orders_and_places_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = write_cfg(tmp, mode="live")
            cfg = load_config(path)
            kill = os.path.join(tmp, "cancel-all")
            cfg.cancel_all_file = kill
            accounts = {
                "mmeth01": (5000, 3 * 10 ** 18, 7),
                "mmeth02": (5000, 0, 3),
                "mmtakereth01": (8000, 10 ** 18, 2),
            }
            orders = {"mmeth01": [{"id": 4, "pair": "ETH-FPL"}, {"id": 2, "pair": "ETH-FPL"}], "mmeth02": [], "mmtakereth01": []}
            ios = []

            class OrdersIO(FakeIO):
                def open_orders(self, w):
                    return list(orders.get(w, []))

            def factory(env):
                io = OrdersIO(env, accounts=accounts)
                ios.append(io)
                return io

            eng = Engine(cfg, io_factory=factory)
            # Without the file: normal tick (no cancel_all key).
            self.assertNotIn("cancel_all", eng.tick({})["pairs"]["ETH-FPL"])
            open(kill, "w").close()
            ios.clear()
            state = {}
            eth = eng.tick(state)["pairs"]["ETH-FPL"]
            self.assertTrue(eth["paused"])
            self.assertEqual(eth["cancel_all"]["remaining"], 2)
            calls = [c for io in ios for c in io.ctl_calls]
            self.assertEqual(calls, [("cancel-order", "--who", "mmeth01", "--order-id", "2")])
            self.assertEqual(eth["placed"], [])
            self.assertEqual(eth["transfers"], [])


if __name__ == "__main__":
    unittest.main()
