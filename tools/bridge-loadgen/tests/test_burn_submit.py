"""Burn submit: retry deferred, clean tree-full refusal, response logging,
landing check + 15-min alert (release list items 6, 7, 8 + claim tree full).

Run: python3 -m unittest discover -s tools/bridge-loadgen/tests -v
"""
import io
import os
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import falcon_pl_bridge_loadgen as L  # noqa: E402

TREE_FULL = ("ctl submit-rail-withdraw failed: Error: bitvm2 claim tree full (16/16) on BTC4: "
             "peg-outs need a capacity release")
OLD_TREE_FULL = "ctl submit-rail-withdraw failed: Error: too many leaves for MERKLE_DEPTH=4"
DEFERRED = "ctl submit-rail-withdraw failed: Error: deferred-until-catchup (local 888533 < peer 888534)"
OK = "accepted tx=5bc194f6aa11bb22cc33dd44ee55ff66 seq=4"


def run_submit(outcomes, env=None):
    calls = []
    sleeps = []

    def fake_ctl(*args, **kw):
        calls.append(args)
        o = outcomes[min(len(calls), len(outcomes)) - 1]
        if isinstance(o, Exception):
            raise o
        return o
    buf = io.StringIO()
    with mock.patch.object(L, "ctl", fake_ctl), mock.patch.dict(os.environ, env or {}), redirect_stdout(buf):
        try:
            res = L.submit_burn("loadtest04", 54410, "tb1qdest", Path("/k"), sleep=sleeps.append)
        except Exception as e:  # noqa: BLE001
            res = e
    return res, calls, sleeps, buf.getvalue()


class Classify(unittest.TestCase):
    def test_kinds(self):
        self.assertEqual(L.classify_submit(TREE_FULL), "tree_full")
        self.assertEqual(L.classify_submit(OLD_TREE_FULL), "tree_full")
        self.assertEqual(L.classify_submit(DEFERRED), "deferred")
        self.assertEqual(L.classify_submit(OK), "")
        self.assertEqual(L.classify_submit("insufficient balance"), "")


class SubmitBurn(unittest.TestCase):
    def test_ok_first_try_logs_response(self):
        res, calls, sleeps, out = run_submit([OK])
        self.assertEqual(res[0], "5bc194f6aa11bb22cc33dd44ee55ff66")
        self.assertEqual(len(calls), 1)
        self.assertIn("attempt 1/6 ok: accepted tx=5bc194f6", out)

    def test_deferred_is_retried_then_succeeds(self):
        res, calls, sleeps, out = run_submit([RuntimeError(DEFERRED), RuntimeError(DEFERRED), OK],
                                             {"BURN_SUBMIT_RETRY_SECS": "7"})
        self.assertIsInstance(res, tuple)
        self.assertEqual(len(calls), 3)
        self.assertEqual(sleeps, [7, 7])
        self.assertEqual(out.count("refused: ctl submit-rail-withdraw failed: Error: deferred"), 2)

    def test_deferred_ok_exit_also_retried(self):
        # very old nodes answered Ok deferred-until-catchup (AMD-20260827-1)
        res, calls, _, _ = run_submit(["Ok deferred-until-catchup", OK])
        self.assertIsInstance(res, tuple)
        self.assertEqual(len(calls), 2)

    def test_deferred_exhausted_is_clean_refusal(self):
        res, calls, sleeps, _ = run_submit([RuntimeError(DEFERRED)], {"BURN_SUBMIT_RETRIES": "3"})
        self.assertIsInstance(res, L.BurnRefused)
        self.assertEqual(res.reason, "deferred")
        self.assertIn("no funds moved", str(res))
        self.assertEqual(len(calls), 3)
        self.assertEqual(len(sleeps), 2)

    def test_tree_full_is_clean_refusal_not_retried(self):
        for msg in (TREE_FULL, OLD_TREE_FULL):
            res, calls, sleeps, out = run_submit([RuntimeError(msg)])
            self.assertIsInstance(res, L.BurnRefused)
            self.assertEqual(res.reason, "tree_full")
            self.assertEqual(len(calls), 1)
            self.assertEqual(sleeps, [])
            self.assertIn("refused", out)

    def test_other_errors_still_raise_runtime(self):
        res, calls, _, _ = run_submit([RuntimeError("ctl failed: insufficient balance")])
        self.assertIsInstance(res, RuntimeError)
        self.assertNotIsInstance(res, L.BurnRefused)
        self.assertEqual(len(calls), 1)

    def test_one_line_bounds(self):
        self.assertEqual(L.one_line("a\n  b\tc"), "a b c")
        self.assertTrue(L.one_line("x" * 1000, 50).endswith("…"))


def acct(seq, btc4):
    return {"sequence": seq, "assets": {"BTC4": btc4}}


class Landing(unittest.TestCase):
    def test_burn_landed(self):
        self.assertFalse(L.burn_landed(acct(4, 163230), acct(4, 163230), 54410))
        self.assertTrue(L.burn_landed(acct(4, 163230), acct(5, 108820), 54410))
        # seq moved by some other tx, BTC4 unchanged: not landed
        self.assertFalse(L.burn_landed(acct(4, 163230), acct(5, 163230), 54410))

    def test_alert_once_after_15_min_then_recovery(self):
        t = [1000.0]
        alerts = []
        with mock.patch.object(L, "discord_alert", alerts.append), redirect_stdout(io.StringIO()):
            w = L.BurnLandWatch("loadtest02", 54410, "878a16ffdeadbeef", acct(4, 163230), clock=lambda: t[0])
            self.assertEqual(w.alert_secs, 900)
            t[0] += 899
            self.assertFalse(w.check(acct(4, 163230)))
            self.assertEqual(alerts, [])
            t[0] += 1
            self.assertFalse(w.check(acct(4, 163230)))
            t[0] += 600
            self.assertFalse(w.check(None))
            self.assertEqual(len(alerts), 1)
            self.assertIn("878a16ff", alerts[0])
            self.assertIn("not landed after 15 min", alerts[0])
            self.assertTrue(w.check(acct(5, 108820)))
            self.assertEqual(len(alerts), 2)
            self.assertIn("landed late", alerts[1])

    def test_landing_in_time_never_alerts(self):
        t = [0.0]
        alerts = []
        with mock.patch.object(L, "discord_alert", alerts.append), redirect_stdout(io.StringIO()):
            w = L.BurnLandWatch("loadtest01", 54410, "f6c09539", acct(5, 54410), clock=lambda: t[0])
            t[0] = 120
            self.assertTrue(w.check(acct(6, 0)))
            t[0] = 5000
            self.assertTrue(w.check(None))
        self.assertEqual(alerts, [])


class RunLegRefusal(unittest.TestCase):
    def test_refusal_text(self):
        self.assertEqual(L.REFUSAL_TEXT["tree_full"], "BTC4 claim tree full")


if __name__ == "__main__":
    unittest.main()
