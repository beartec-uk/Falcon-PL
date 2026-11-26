#!/usr/bin/env python3
from decimal import Decimal
import os
import random
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mm
import mmtaker


class TestPairGenericDecimal(unittest.TestCase):
    def test_base_asset_and_decimals_resolution(self):
        self.assertEqual(mm.base_asset({"PAIR": "ETH-FPL"}), "ETH")
        self.assertEqual(mm.base_asset({"PAIR": "USDC-FPL", "BASE_ASSET": "USDC"}), "USDC")
        self.assertEqual(mm.resolve_base_raw({"PAIR": "ETH-FPL"}), 10 ** 18)
        self.assertEqual(mm.resolve_base_raw({"PAIR": "USDC-FPL"}), 10 ** 6)
        self.assertEqual(mm.resolve_base_raw({"PAIR": "BTC4-FPL"}), 10 ** 8)
        self.assertEqual(mm.resolve_base_raw({"PAIR": "FOO-FPL", "BASE_DECIMALS": "18"}), 10 ** 18)
        self.assertEqual(mm.resolve_base_raw({"PAIR": "FOO-FPL", "BASE_RAW_PER_COIN": "1000000000000000000"}), 10 ** 18)

    def test_eth_18_decimal_ladder_uses_exact_decimal_math(self):
        cfg = {
            "PAIR": "ETH-FPL",
            "BASE_ASSET": "ETH",
            "BASE_DECIMALS": "18",
            "FPL_RAW_PER_FPL": "1",
            "LEVELS": "2",
            "SPACING_BPS": "25",
            "QUOTE_MIN_FPL": "500",
            "QUOTE_MAX_FPL": "1000",
        }
        mid = Decimal("50000")
        lad = mm.ladder(cfg, mid)
        self.assertEqual(len(lad), 4)
        buy1 = [x for x in lad if x[0] == "buy"][0]
        self.assertEqual(buy1[1], 49875)
        expected_amt = (Decimal("500") * Decimal(10 ** 18)) // Decimal("49875")
        self.assertEqual(buy1[2], int(expected_amt))
        q_cost = mm.quote_ceil(buy1[2], buy1[1], 10 ** 18)
        self.assertEqual(q_cost, 500)

    def test_mmtaker_decide_18_decimals_and_pair_generic(self):
        cfg = {
            "PAIR": "ETH-FPL",
            "BASE_ASSET": "ETH",
            "BASE_DECIMALS": "18",
            "FPL_RAW_PER_FPL": "1",
            "BAND_LO": "48000",
            "BAND_HI": "52000",
            "PERIOD_S": "21600",
            "BIAS": "1.0",
            "QUOTE_MIN_FPL": "500",
            "QUOTE_MAX_FPL": "500",
            "CROSS_BPS": "15",
            "FEE_BUFFER_FPL": "50",
        }
        bal = (10000, 10 ** 18)
        res = mmtaker.decide(cfg, 49500, 50500, 0, bal, random.Random(1))
        self.assertIsNotNone(res)
        side, px, amt, mid, ref = res
        self.assertIn(side, ("buy", "sell"))
        self.assertGreater(px, 0)
        self.assertGreater(amt, 10 ** 15)

    def test_mmtaker_top_handles_cloud_and_explorer_shapes(self):
        self.assertEqual(
            mmtaker.top({"bids": [{"price": 80}], "asks": [{"price": 85}]}),
            (80, 85),
        )
        self.assertEqual(
            mmtaker.top({"bids": [{"price": {"raw": "4180000"}}], "asks": [{"price": {"raw": "4200000"}}]}),
            (4180000, 4200000),
        )
        self.assertEqual(mmtaker.top({"bids": [], "asks": [{"price": 85}]}), (None, 85))
        self.assertEqual(mmtaker.top({"bids": [{"price": 80}], "asks": []}), (80, None))
        self.assertEqual(mmtaker.top({"bids": [], "asks": []}), "empty book")

    def _taker_cfg(self):
        return {
            "PAIR": "ETH-FPL",
            "BASE_ASSET": "ETH",
            "BASE_DECIMALS": "18",
            "FPL_RAW_PER_FPL": "1",
            "BAND_LO": "48000",
            "BAND_HI": "52000",
            "PERIOD_S": "21600",
            "BIAS": "0.5",
            "QUOTE_MIN_FPL": "500",
            "QUOTE_MAX_FPL": "500",
            "CROSS_BPS": "15",
            "FEE_BUFFER_FPL": "50",
        }

    def test_mmtaker_sells_into_bids_when_there_are_no_asks(self):
        # Enough ETH to sell; FPL is irrelevant for the sell path.
        bal = (50, 10 ** 18)
        res = mmtaker.decide(self._taker_cfg(), 49500, None, 0, bal, random.Random(1))
        self.assertIsNotNone(res)
        side, px, amt, mid, ref = res
        self.assertEqual(side, "sell")
        self.assertEqual(mid, Decimal(49500))
        self.assertGreater(amt, 10 ** 15)
        # CROSS_BPS 15: sell price is bid / 1.0015, rounded down
        self.assertLess(px, 49500)
        self.assertGreater(px, 49400)

    def test_mmtaker_buys_asks_when_there_are_no_bids(self):
        bal = (10000, 0)
        res = mmtaker.decide(self._taker_cfg(), None, 50500, 0, bal, random.Random(1))
        self.assertIsNotNone(res)
        side, px, amt, mid, ref = res
        self.assertEqual(side, "buy")
        self.assertEqual(mid, Decimal(50500))
        self.assertGreater(amt, 10 ** 15)
        self.assertGreater(px, 50500)

    def test_mmtaker_skips_one_sided_book_without_inventory_for_that_side(self):
        # No ETH to sell into bids, and no asks to buy.
        res = mmtaker.decide(self._taker_cfg(), 49500, None, 0, (10000, 0), random.Random(1))
        self.assertIsNone(res)
        # No FPL to buy asks, and no bids to sell.
        res = mmtaker.decide(self._taker_cfg(), None, 50500, 0, (0, 10 ** 18), random.Random(1))
        self.assertIsNone(res)

    def test_mm_tick_reads_via_cloud_rpc_and_writes_via_ctl(self):
        cfg = {
            "PAIR": "ETH-FPL",
            "BASE_ASSET": "ETH",
            "BASE_DECIMALS": "18",
            "FPL_RAW_PER_FPL": "1",
            "WALLETS": "ethmm01,ethmm02",
            "LEVELS": "1",
            "SPACING_BPS": "25",
            "QUOTE_MIN_FPL": "500",
            "QUOTE_MAX_FPL": "500",
            "BAND_LO": "50000",
            "BAND_HI": "50000",
            "PERIOD_S": "21600",
            "FALCON_CLOUD_RPC_URL": "https://rpc.falcon-fpl.com/v1/rpc",
            "FALCON_CLOUD_API_KEY": "test-key",
            "CTL": "falcon-pl-ctl",
            "RPC_ADDR": "127.0.0.1:19313",
            "SCHEME": "falcon",
            "KEYS_DIR": "/tmp/keys",
            "NETWORK_ID": "2300",
            "DRY_RUN": "0",
        }
        io = mm.IO(cfg)
        self.assertEqual(io.read_source, "cloud")

        rpc_calls = []

        def fake_rpc(method, params):
            rpc_calls.append((method, params))
            if method == "fpl_status":
                return {"tip_height": 1000}
            if method == "fpl_getAccount":
                return {"balance": 10000, "assets": {"ETH": 10 ** 18}, "sequence": 7}
            if method == "fpl_openOrders":
                return {"orders": []}
            if method == "fpl_orderBook":
                return {"bids": [{"price": 49000}], "asks": [{"price": 51000}]}
            raise AssertionError(method)

        ctl_calls = []

        def fake_ctl(*args):
            ctl_calls.append(args)
            return 'tx_id=abc {"type":"ok","msg":"accepted"}'

        io.rpc = fake_rpc
        io.ctl_tx = fake_ctl
        io.now = lambda: 0

        state = {}
        summ = mm.tick(cfg, io, state)
        self.assertIsNone(summ["error"])
        self.assertEqual(len(summ["placed"]), 2)
        self.assertEqual(len(ctl_calls), 2)
        methods = [m for m, _ in rpc_calls]
        self.assertIn("fpl_status", methods)
        self.assertIn("fpl_getAccount", methods)
        self.assertIn("fpl_openOrders", methods)
        self.assertIn("fpl_orderBook", methods)

    def test_cloud_api_key_file_parsing(self):
        with tempfile.NamedTemporaryFile("w", delete=False) as tf:
            tf.write("# comment\nFALCON_CLOUD_API_KEY=secret_value\n")
            path = tf.name
        try:
            self.assertEqual(mm.resolve_cloud_api_key({"FALCON_CLOUD_API_KEY_FILE": path}), "secret_value")
            self.assertEqual(mmtaker.resolve_cloud_api_key({"FALCON_CLOUD_API_KEY_FILE": path}), "secret_value")
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
