"""Unit tests for peg-in pacing and stall alerts (no network, no keys).

Run: python3 -m unittest discover -s tools/bridge-loadgen/tests -v
"""
import json
import os
import random
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import falcon_pl_bridge_loadgen as L  # noqa: E402


class FakeIntake:
    """Minimal fake of the intake API: per-id state, per-account listing."""

    def __init__(self):
        self.reqs = {}
        self.lock = threading.Lock()
        self.n = 0

    def add(self, acct, state):
        with self.lock:
            self.n += 1
            i = f"{self.n:016x}"
            self.reqs[i] = {"id": i, "account": acct, "state": state}
            return i

    def __call__(self, method, path, body=None, timeout=30):
        with self.lock:
            if method == "GET" and path.startswith("/v1/deposits?account="):
                a = path.split("=", 1)[1]
                return [dict(r) for r in self.reqs.values() if r["account"] == a]
            if method == "GET" and path.startswith("/v1/deposits/"):
                return dict(self.reqs[path.rsplit("/", 1)[1]])
        raise AssertionError(f"unexpected {method} {path}")


class Clock:
    def __init__(self):
        self.t = 1000.0

    def time(self):
        return self.t

    def sleep(self, s):
        self.t += s


class TmpRecord(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.env = mock.patch.dict(os.environ, {"BRIDGE_RECORD_DIR": self.tmp.name}, clear=False)
        self.env.start()
        for k in ("PEGIN_GATE_STATES", "DISCORD_HEALTH_WEBHOOK_URL", "DISCORD_WEBHOOK_URL"):
            os.environ.pop(k, None)

    def tearDown(self):
        self.env.stop()
        self.tmp.cleanup()


class BatchOffsetsTest(unittest.TestCase):
    def test_evenly_spaced_no_burst(self):
        offs = L.batch_offsets(10, 3600, 0.25, rng=random.Random(1))
        self.assertEqual(len(offs), 10)
        self.assertEqual(offs, sorted(offs))
        gaps = [b - a for a, b in zip(offs, offs[1:])]
        slot = (3600 - 30) / 10
        # min gap with 25% jitter is 0.75 of a slot (~268 s), never a burst
        self.assertGreater(min(gaps), slot * 0.74)
        self.assertLess(offs[-1], 3600)

    def test_twenty_legs(self):
        offs = L.batch_offsets(20, 3600, 0.25, rng=random.Random(7))
        gaps = [b - a for a, b in zip(offs, offs[1:])]
        self.assertGreater(min(gaps), 3570 / 20 * 0.74)

    def test_empty(self):
        self.assertEqual(L.batch_offsets(0, 3600), [])


class GateTest(TmpRecord):
    def mk(self, fake, clock, max_n=1, wait=600):
        return L.PegInGate(max_n, ["loadtest01", "loadtest02"], poll_secs=20, wait_max_secs=wait,
                           intake_fn=fake, sleep_fn=clock.sleep, clock=clock.time)

    def test_single_slot_blocks_second(self):
        fake, clock = FakeIntake(), Clock()
        g = self.mk(fake, clock, wait=60)
        g.acquire("a")
        g.bind(fake.add("loadtest01", "awaiting_funding"))
        with self.assertRaises(L.LegSkipped):
            g.acquire("b")
        self.assertEqual(g.held, 1)

    def test_release_frees_slot(self):
        fake, clock = FakeIntake(), Clock()
        g = self.mk(fake, clock)
        g.acquire("a")
        i = fake.add("loadtest01", "signed")
        g.bind(i)
        fake.reqs[i]["state"] = "presigned"
        g.release(i)
        g.acquire("b")  # must not raise
        self.assertEqual(g.held, 1)

    def test_external_inflight_counts(self):
        """A peg-in left by a previous loadgen process still blocks."""
        fake, clock = FakeIntake(), Clock()
        fake.add("loadtest02", "ceremony_pubkeys")
        g = self.mk(fake, clock, wait=100)
        with self.assertRaises(L.LegSkipped):
            g.acquire("a")

    def test_external_waits_then_proceeds(self):
        fake, clock = FakeIntake(), Clock()
        i = fake.add("loadtest02", "awaiting_signature")
        g = self.mk(fake, clock, wait=600)
        orig = clock.sleep

        def sleep(s):
            orig(s)
            if clock.t > 1100:
                fake.reqs[i]["state"] = "presigned"
        g._sleep = sleep
        g.acquire("a")
        self.assertGreater(clock.t, 1100)

    def test_terminal_and_other_accounts_ignored(self):
        fake, clock = FakeIntake(), Clock()
        fake.add("loadtest01", "minted")
        fake.add("loadtest01", "failed")
        fake.add("somebody-else", "signed")
        g = self.mk(fake, clock, wait=0)
        g.acquire("a")

    def test_journal_open_pegin_counts(self):
        fake, clock = FakeIntake(), Clock()
        i = fake.add("loadtest09", "signed")  # account not in gate list
        L.append_leg({"leg_id": i, "direction": "peg-in", "state": "funding_broadcast", "result": "pending"})
        g = self.mk(fake, clock, wait=0)
        with self.assertRaises(L.LegSkipped):
            g.acquire("a")
        L.append_leg({"leg_id": i, "direction": "peg-in", "state": "failed", "result": "error"})
        self.assertEqual(L.journal_open_pegins(), set())
        g.acquire("a")

    def test_unknown_state_is_busy(self):
        fake, clock = FakeIntake(), Clock()
        L.append_leg({"leg_id": "00000000000000ff", "direction": "peg-in",
                      "state": "funding_broadcast", "result": "pending"})
        g = self.mk(fake, clock, wait=0)
        with self.assertRaises(L.LegSkipped):
            g.acquire("a")  # intake 404 -> unknown -> fail safe

    def test_max_two(self):
        fake, clock = FakeIntake(), Clock()
        g = self.mk(fake, clock, max_n=2, wait=0)
        g.acquire("a"); g.bind(fake.add("loadtest01", "funded"))
        g.acquire("b"); g.bind(fake.add("loadtest02", "funded"))
        with self.assertRaises(L.LegSkipped):
            g.acquire("c")


class PegInFlowTest(TmpRecord):
    """Drive peg_in() against a fake intake that walks states; check the slot is
    released on ceremony completion, on failure, and that a stuck `signed`
    raises a Discord stall alert and a timeout alert."""

    def run_peg_in(self, states, timeout=10_000, stall=60):
        fake = FakeIntake()
        clock = Clock()
        seq = iter(states)
        cur = {"id": None}

        def intake_fn(method, path, body=None, timeout=30):
            if method == "POST" and path == "/v1/deposits":
                cur["id"] = fake.add(body["account"], "awaiting_funding")
                return {"id": cur["id"], "address": "tb1qtest", "send_sats_min": 50590}
            if method == "POST" and path.endswith("/signatures"):
                return {}
            if method == "GET" and path == f"/v1/deposits/{cur['id']}":
                try:
                    fake.reqs[cur["id"]]["state"] = next(seq)
                except StopIteration:
                    pass
                r = dict(fake.reqs[cur["id"]])
                if r["state"] == "awaiting_signature":
                    r["depositor_request"] = {"psbts": {}}
                return r
            return fake(method, path, body, timeout)

        alerts = []
        gate = L.PegInGate(1, ["loadtest01"], poll_secs=1, wait_max_secs=0, intake_fn=intake_fn,
                           sleep_fn=clock.sleep, clock=clock.time)
        home = Path(self.tmp.name)
        patches = [
            mock.patch.object(L, "intake", intake_fn),
            mock.patch.object(L, "ensure_depositor_key", lambda *a, **k: "02" + "11" * 32),
            mock.patch.object(L, "bitcoin", lambda *a, **k: "ab" * 32),
            mock.patch.object(L, "sign_depositor",
                              lambda home, acct, mjs, req, out: Path(out).write_text("{}")),
            mock.patch.object(L, "discord_alert", lambda t: alerts.append(t)),
            mock.patch.object(L.time, "time", clock.time),
            mock.patch.object(L.time, "sleep", clock.sleep),
            mock.patch.dict(os.environ, {"PEGIN_STALL_ALERT_SECS": str(stall), "PEGIN_POLL_SECS": "20"}),
        ]
        for p in patches:
            p.start()
        try:
            try:
                res = L.peg_in("loadtest01", 55000, home, home / "sign.mjs", timeout, gate=gate)
                err = None
            except Exception as e:  # noqa: BLE001
                res, err = None, e
        finally:
            for p in reversed(patches):
                p.stop()
        return res, err, gate, alerts

    def test_happy_path_releases_slot_early(self):
        states = ["awaiting_funding", "funded", "ceremony_pubkeys", "awaiting_signature", "signed",
                  "presigned", "broadcasting", "peg_in_confirmed", "awaiting_mint", "minted"]
        res, err, gate, alerts = self.run_peg_in(states)
        self.assertIsNone(err)
        self.assertEqual(res["state"], "minted")
        self.assertEqual(gate.held, 0)
        self.assertEqual(alerts, [])

    def test_failed_request_releases_slot(self):
        res, err, gate, alerts = self.run_peg_in(["awaiting_funding", "funded", "failed"])
        self.assertIsInstance(err, RuntimeError)
        self.assertEqual(gate.held, 0)

    def test_stuck_signed_alerts_then_times_out(self):
        states = ["awaiting_funding", "funded", "ceremony_pubkeys", "awaiting_signature"] + ["signed"] * 10_000
        res, err, gate, alerts = self.run_peg_in(states, timeout=3600, stall=600)
        self.assertIsInstance(err, RuntimeError)
        self.assertIn("stuck at state=signed", str(err))
        self.assertEqual(gate.held, 0)
        stall = [a for a in alerts if "stuck in state=signed" in a]
        self.assertEqual(len(stall), 1, alerts)          # exactly one stall alert
        self.assertTrue(any("TIMEOUT" in a for a in alerts), alerts)

    def test_discord_alert_never_logs_url(self):
        url = "https://discord.example/api/webhooks/123/SECRETTOKEN"
        out = []
        with mock.patch.dict(os.environ, {"DISCORD_HEALTH_WEBHOOK_URL": url}), \
                mock.patch.object(L, "log", lambda m: out.append(m)), \
                mock.patch.object(L.urllib.request, "urlopen", side_effect=OSError("offline")):
            L.discord_alert("hello")
        self.assertTrue(out)
        self.assertFalse(any("SECRETTOKEN" in m or "webhooks" in m for m in out), out)


if __name__ == "__main__":
    unittest.main()
