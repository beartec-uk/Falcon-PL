#!/usr/bin/env python3
"""BTC4 rail-lag alert: > 6 blocks behind Testnet4 for 30 min -> one Discord line.
No network: tips, clock and the outbox are faked; the webhook is never touched.

Run: python3 test_rail_lag.py -v
"""
import json
import os
import tempfile
import unittest
from unittest import mock

from test_ceremony_supervision import load_intake


def intake():
    tmp = tempfile.mkdtemp()
    return load_intake(os.path.join(tmp, "h"), os.path.join(tmp, "p"))


class RailLag(unittest.TestCase):
    def setUp(self):
        self.m = intake()
        self.t = [0.0]
        self.tips = {"rail": 161859, "btc": 161859}
        self.posted = []
        self.w = self.m.RailLagWatch(rail_tip=lambda: self.tips["rail"], btc_tip=lambda: self.tips["btc"],
                                     clock=lambda: self.t[0], post=self.posted.append,
                                     blocks=6, secs=1800, realert=6 * 3600, check_every=60)

    def at(self, s, rail=None, btc=None):
        self.t[0] = s
        if rail is not None:
            self.tips["rail"] = rail
        if btc is not None:
            self.tips["btc"] = btc
        return self.w.check()

    def test_six_behind_never_alerts(self):
        for s in range(0, 7200, 60):
            self.assertIsNone(self.at(s, btc=161865))
        self.assertEqual(self.posted, [])

    def test_seven_behind_alerts_after_30_min_once(self):
        self.assertIsNone(self.at(0, btc=161866))
        self.assertIsNone(self.at(1740))
        line = self.at(1800)
        self.assertEqual(line, self.posted[-1])
        self.assertIn("BTC4 header rail is 7 blocks behind Testnet4 (rail 161859, Testnet4 161866) for 30 min", line)
        for s in range(1860, 1800 + 6 * 3600, 60):
            self.assertIsNone(self.at(s))
        self.assertIsNotNone(self.at(1800 + 6 * 3600))  # re-alert after STALL_REALERT
        self.assertEqual(len(self.posted), 2)

    def test_dip_under_limit_restarts_the_30_min_clock(self):
        self.at(0, btc=161870)
        self.at(1200, btc=161862)  # back within 6: episode ends (no alert yet, no recovery line)
        self.assertIsNone(self.at(1260, btc=161870))
        self.assertIsNone(self.at(2940))
        self.assertIsNotNone(self.at(3060))
        self.assertEqual(len(self.posted), 1)

    def test_recovery_line_only_after_an_alert(self):
        self.at(0, btc=161900)
        self.at(1800)
        line = self.at(1860, rail=161898)
        self.assertIn("caught up", line)
        self.assertEqual(len(self.posted), 2)

    def test_unknown_reading_neither_starts_nor_clears(self):
        self.at(0, btc=161900)
        self.tips["btc"] = None
        self.assertIsNone(self.at(1000))
        self.tips["btc"] = 161900
        self.assertIsNotNone(self.at(1800))

    def test_rate_limited_checks_and_disable(self):
        self.at(0, btc=161900)
        self.t[0] = 30
        self.assertIsNone(self.w.check())   # < check_every: no reading taken
        off = self.m.RailLagWatch(rail_tip=lambda: 1, btc_tip=lambda: 999, clock=lambda: 10 ** 6,
                                  post=self.posted.append, blocks=0)
        self.assertIsNone(off.check(force=True))

    def test_rail_tip_height_reads_ctl_status(self):
        st = {"body": {"rails": [{"asset": "BTC", "tip_height": 5}, {"asset": "BTC4", "tip_height": 162111}]}}
        with mock.patch.object(self.m, "falcon_ctl_status", return_value=st):
            self.assertEqual(self.m.rail_tip_height(), 162111)
        with mock.patch.object(self.m, "falcon_ctl_status", return_value={}):
            self.assertIsNone(self.m.rail_tip_height())

    def test_btc_tip_height_from_esplora(self):
        with mock.patch.object(self.m, "esplora", return_value=162117):
            self.assertEqual(self.m.btc_tip_height(), 162117)
        with mock.patch.object(self.m, "esplora", side_effect=OSError("down")):
            self.assertIsNone(self.m.btc_tip_height())

    def test_alert_goes_through_outbox_not_webhook_directly(self):
        m = intake()
        w = m.RailLagWatch(rail_tip=lambda: 1, btc_tip=lambda: 100, clock=lambda: 0.0, blocks=6, secs=0)
        with mock.patch.object(m.OUTBOX, "put") as put, mock.patch.object(m, "_post_discord_once") as raw:
            w.check(force=True)
            self.assertEqual(put.call_count, 1)
            raw.assert_not_called()


if __name__ == "__main__":
    unittest.main()
