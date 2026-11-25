"""Unit tests for pl-btc4-header-submitter.py (pure logic only; no node, no Core).

Run: python3 -m unittest falcon-pl-rs/crates/fd-pl/scripts/test_pl_btc4_header_submitter.py
"""
import importlib.util
import os
import unittest

_P = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pl-btc4-header-submitter.py")
_spec = importlib.util.spec_from_file_location("sub", _P)
sub = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sub)

# 161856..161860 from the 2026-11-17 stall (prefixes are enough here).
CANON = {161856: "39db55", 161857: "013101c1", 161858: "3fcb0e7f", 161859: "d7e70d00", 161860: "0001"}


def canon(h):
    return CANON[h]


class ChooseStart(unittest.TestCase):
    def test_tip_on_canonical(self):
        self.assertEqual(sub.choose_start(161858, "3fcb0e7f", {}, [], canon), (161858, "tip"))

    def test_stall_161859_uses_canonical_pending_fork(self):
        # Main = stale branch A at 161859; pending fork = canonical B to 161858.
        tail = {161859: "6c7ed7", 161858: "4dea5", 161857: "4ff223", 161856: "39db55"}
        br = [("btc_fork", 161858, "3fcb0e7f", 2)]
        h, why = sub.choose_start(161859, "6c7ed7", tail, br, canon)
        self.assertEqual(h, 161858)
        self.assertIn("btc_fork", why)

    def test_highest_canonical_branch_wins(self):
        tail = {161859: "6c7ed7", 161856: "39db55"}
        br = [("btc_fork", 161857, "013101c1", 1), ("btc_side", 161858, "3fcb0e7f", 2),
              ("btc_fork_alt", 161859, "1e9f85ba", 3)]
        self.assertEqual(sub.choose_start(161859, "6c7ed7", tail, br, canon)[0], 161858)

    def test_falls_back_to_common_ancestor(self):
        tail = {161859: "6c7ed7", 161858: "4dea5", 161857: "4ff223", 161856: "39db55"}
        self.assertEqual(sub.choose_start(161859, "6c7ed7", tail, [], canon), (161856, "common ancestor 161856"))

    def test_waiting_branches_reads_all_shapes(self):
        rail = {"btc_fork": {"len": 3, "tip_height": 161859, "tip_hash": "AA"},
                "btc_fork_alt": None,
                "btc_side": {"len": 4, "tips": [{"tip_height": 161860, "tip_hash": "bb", "len": 2}]}}
        self.assertEqual(sub.waiting_branches(rail), [("btc_fork", 161859, "aa", 3), ("btc_side", 161860, "bb", 2)])
        self.assertEqual(sub.waiting_branches({}), [])


class Stuck(unittest.TestCase):
    def setUp(self):
        self.t = [0.0]
        self.lines = []
        self.m = sub.StuckMonitor(stuck_secs=1800, rewarn_secs=1800, clock=lambda: self.t[0], sink=self.lines.append)

    def at(self, s, rail, tn4, **kw):
        self.t[0] = s
        return self.m.observe(rail, tn4, **kw)

    def test_warns_once_after_30_min_then_rewarns_and_recovers(self):
        self.assertIsNone(self.at(0, 161859, 161865))
        self.assertIsNone(self.at(1799, 161859, 161866))
        w = self.at(1800, 161859, 161866, branches=[("btc_fork", 161859, "1e9f85ba00", 3)],
                    last_errs={"127.0.0.1:19301": "BTC header parent mismatch: height 161859", "x:1": "exc: timed out"})
        self.assertIn("WARNING: BTC4 rail stuck at 161859 for 30 min", w)
        self.assertIn("7 behind", w)
        self.assertIn("btc_fork 161859 (3 hdr", w)
        self.assertIn("parent mismatch", w)
        self.assertNotIn("timed out", w)
        self.assertIsNone(self.at(2000, 161859, 161866))      # no spam
        self.assertIsNotNone(self.at(3600, 161859, 161867))   # re-warn
        self.at(3700, 161860, 161867)
        self.assertIn("recovered", self.lines[-1])
        self.assertEqual(len(self.lines), 3)

    def test_caught_up_rail_never_warns(self):
        for s in range(0, 10000, 600):
            self.assertIsNone(self.at(s, 162000, 162000))
        self.assertEqual(self.lines, [])


class Backoff(unittest.TestCase):
    def test_doubles_to_cap_and_resets(self):
        b = 0.0
        seen = []
        for _ in range(9):
            b = sub.next_backoff(b, False, cap=60)
            seen.append(b)
        self.assertEqual(seen[:4], [1.0, 2.0, 4.0, 8.0])
        self.assertEqual(seen[-1], 60)
        self.assertEqual(sub.next_backoff(b, True), 0.0)


if __name__ == "__main__":
    unittest.main()
