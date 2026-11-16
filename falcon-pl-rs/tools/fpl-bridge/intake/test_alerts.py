#!/usr/bin/env python3
"""Intake alerts: short wording (release list item 1), batching + retry on Discord rate
limit (item 2). No network: urlopen is faked; the webhook URL must never be logged.

Run: python3 test_alerts.py -v
"""
import io
import json
import os
import tempfile
import time
import unittest
import urllib.error
from unittest import mock

from test_ceremony_supervision import load_intake

URL = "https://discord.example/api/webhooks/1/SECRETTOKEN"


def intake():
    tmp = tempfile.mkdtemp()
    return load_intake(os.path.join(tmp, "h"), os.path.join(tmp, "p"))


class FakeResp:
    def __init__(self, headers=None):
        self.headers = headers or {}

    def read(self):
        return b""

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def http_error(code, headers=None, body=b""):
    return urllib.error.HTTPError(URL, code, "x", headers or {}, io.BytesIO(body))


class Wording(unittest.TestCase):
    def setUp(self):
        self.I = intake()

    def test_human_age(self):
        h = self.I.human_age
        self.assertEqual(h(30), "1 min")
        self.assertEqual(h(45 * 60), "45 min")
        self.assertEqual(h(5 * 3600), "5 h")
        self.assertEqual(h(9 * 86400 + 5), "9 days")

    def test_stage_timeout_fail_is_one_short_line(self):
        I = self.I
        posted = []
        now = 1_800_000_000
        r = {"id": "1443cc39aabbccdd", "state": "signed", "state_since": now - 9 * 86400,
             "kickoff": "cd" * 32 + ":0"}
        with mock.patch.object(I.OUTBOX, "put", posted.append), \
                mock.patch.object(I, "broadcast_seen", return_value=False), \
                mock.patch.object(I, "kill_ceremony_procs", return_value=[]), \
                mock.patch.object(I, "log"):
            self.assertTrue(I.supervise(r, now))
        self.assertEqual(r["state"], "failed")
        self.assertEqual(posted, ["❌ Peg-in 1443cc39 failed: stuck signing 9 days. Funds safe, kickoff released."])

    def test_stall_with_final_json_short(self):
        I = self.I
        posted = []
        now = 1_800_000_000
        r = {"id": "65bb17492517646e", "state": "presigned", "state_since": now - 2 * 86400}
        os.makedirs(I.gdir(r), exist_ok=True)
        open(os.path.join(I.gdir(r), "final.json"), "w").write("{}")
        with mock.patch.object(I.OUTBOX, "put", posted.append), mock.patch.object(I, "log"):
            I.supervise(r, now)
        self.assertEqual(r["state"], "presigned")
        self.assertEqual(len(posted), 1)
        self.assertTrue(posted[0].startswith("⚠️ Peg-in 65bb1749 stalled: stuck waiting for ledger binding 2 days; "
                                             "signed graphs exist."), posted[0])
        self.assertLess(len(posted[0]), 160)

    def test_full_detail_still_logged(self):
        I = self.I
        logged = []
        with mock.patch.object(I.OUTBOX, "put"), \
                mock.patch.object(I, "log", lambda *a: logged.append(" ".join(map(str, a)))):
            I.alert("failed", {"id": "abc"}, "long detail with pids", short="❌ short")
        self.assertTrue(any("long detail with pids" in m for m in logged))


class Retry(unittest.TestCase):
    def setUp(self):
        self.I = intake()

    def run_post(self, effects):
        calls, sleeps, logged = [], [], []

        def fake_urlopen(req, timeout=10):
            calls.append(req)
            e = effects[min(len(calls), len(effects)) - 1]
            if isinstance(e, Exception):
                raise e
            return e
        with mock.patch.dict(os.environ, {"DISCORD_HEALTH_WEBHOOK_URL": URL}), \
                mock.patch.object(self.I.urllib.request, "urlopen", fake_urlopen), \
                mock.patch.object(self.I, "log", lambda *a: logged.append(" ".join(map(str, a)))):
            ok = self.I._post_discord("hi", sleep=sleeps.append)
        self.assertFalse(any("SECRETTOKEN" in m or "webhooks" in m for m in logged), logged)
        return ok, calls, sleeps, logged

    def test_user_agent_kept(self):
        ok, calls, _, _ = self.run_post([FakeResp()])
        self.assertTrue(ok)
        self.assertEqual(calls[0].get_header("User-agent"), "fpl-bridge-intake")

    def test_429_honours_retry_after_header(self):
        ok, calls, sleeps, _ = self.run_post([http_error(429, {"Retry-After": "2.5"}), FakeResp()])
        self.assertTrue(ok)
        self.assertEqual(len(calls), 2)
        self.assertEqual(sleeps, [2.5])

    def test_429_body_retry_after(self):
        ok, _, sleeps, _ = self.run_post([http_error(429, {}, json.dumps({"retry_after": 0.7}).encode()), FakeResp()])
        self.assertTrue(ok)
        self.assertEqual(sleeps, [0.7])

    def test_5xx_and_network_back_off(self):
        ok, calls, sleeps, _ = self.run_post([http_error(502), OSError("reset"), FakeResp()])
        self.assertTrue(ok)
        self.assertEqual(sleeps, [2, 4])

    def test_4xx_dropped_without_retry(self):
        ok, calls, sleeps, logged = self.run_post([http_error(403)])
        self.assertFalse(ok)
        self.assertEqual(len(calls), 1)
        self.assertTrue(any("dropped" in m for m in logged))

    def test_gives_up_after_max_retries(self):
        ok, calls, _, _ = self.run_post([http_error(429, {"Retry-After": "1"})])
        self.assertFalse(ok)
        self.assertEqual(len(calls), self.I.ALERT_MAX_RETRIES)

    def test_empty_bucket_paces(self):
        ok, _, sleeps, _ = self.run_post([FakeResp({"X-RateLimit-Remaining": "0", "X-RateLimit-Reset-After": "1.5"})])
        self.assertTrue(ok)
        self.assertEqual(sleeps, [1.5])


class Batching(unittest.TestCase):
    def setUp(self):
        self.I = intake()

    def test_pack(self):
        p = self.I.pack_alerts
        self.assertEqual(p(["a", "b"]), ["a\nb"])
        self.assertEqual(p(["x" * 10, "y" * 10], limit=15), ["x" * 10, "y" * 10])
        self.assertEqual(len(p(["z" * 50], limit=20)[0]), 20)
        self.assertEqual(p([]), [])

    def test_burst_of_14_is_one_post_none_lost(self):
        posts = []
        box = self.I.AlertOutbox(post=lambda t: posts.append(t) or True, batch_secs=0, sleep=lambda s: None)
        msgs = [f"❌ Peg-in {i:08x} failed: stuck signing 9 days. Funds safe, kickoff released." for i in range(14)]
        for m in msgs:
            box._q.append(m)
        self.assertEqual(box.flush(), 1)
        self.assertEqual(posts[0].split("\n"), msgs)
        self.assertEqual(box.pending(), 0)

    def test_background_thread_delivers_in_order(self):
        posts = []
        box = self.I.AlertOutbox(post=lambda t: posts.append(t) or True, batch_secs=0.05)
        for i in range(5):
            box.put(f"m{i}")
        deadline = time.time() + 3
        while not posts and time.time() < deadline:
            time.sleep(0.02)
        time.sleep(0.1)
        self.assertEqual("\n".join(posts).split("\n"), [f"m{i}" for i in range(5)])

    def test_failed_post_counts_dropped(self):
        box = self.I.AlertOutbox(post=lambda t: False, batch_secs=0)
        box._q.extend(["a", "b"])
        box.flush()
        self.assertEqual(box.dropped, 2)

    def test_alert_dedupe_still_applies(self):
        I = self.I
        posted = []
        with mock.patch.object(I.OUTBOX, "put", posted.append), mock.patch.object(I, "log"):
            I.alert("coordinator_died", {"id": "r1"}, "x", short="s1")
            I.alert("coordinator_died", {"id": "r1"}, "x", short="s1")
        self.assertEqual(posted, ["s1"])


if __name__ == "__main__":
    unittest.main()
