#!/usr/bin/env python3
"""Offline tests for the Discord alerts (fpl_discord_notify, relayer, BTC watch).

  python3 crates/fd-pl/scripts/test_fpl_discord_alerts.py

The webhook is a local mock HTTP server on 127.0.0.1 (random port). No real
Discord URL appears here, and nothing leaves the machine.
"""
from __future__ import annotations

import importlib.util
import io
import json
import os
import sys
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest.mock import patch

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))
import fpl_discord_notify as dn  # noqa: E402


def _load(name, file):
    spec = importlib.util.spec_from_file_location(name, _HERE / file)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


rel = _load("relayer_dn", "pl-eth-lc-relayer.py")
rel.ETH_SCAN_PACE_SEC = 0.0
btc = _load("btcwatch_dn", "pl-btc-alert-watch.py")


class MockWebhook:
    """Local HTTP endpoint that records JSON bodies. status/429 are settable."""

    def __init__(self):
        self.bodies: list[dict] = []
        self.status = 204
        self.retry_after = None
        outer = self

        class H(BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802
                n = int(self.headers.get("content-length") or 0)
                body = json.loads(self.rfile.read(n) or b"{}")
                if outer.status == 429:
                    payload = json.dumps({"retry_after": outer.retry_after or 1}).encode()
                    self.send_response(429)
                    self.send_header("content-type", "application/json")
                    self.send_header("content-length", str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)
                    return
                if 200 <= outer.status < 300:
                    outer.bodies.append(body)
                self.send_response(outer.status)
                self.send_header("content-length", "0")
                self.end_headers()

            def log_message(self, *a):
                pass

        self.srv = HTTPServer(("127.0.0.1", 0), H)
        # http, not https: tests pass the URL in directly (webhook_from_env
        # insists on https for real config).
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}/api/webhooks/test/mock-token"
        self.t = threading.Thread(target=self.srv.serve_forever, daemon=True)
        self.t.start()

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()

    def embeds(self):
        return [e for b in self.bodies for e in b.get("embeds", [])]


class Clock:
    def __init__(self, t=1_000_000.0):
        self.t = t

    def __call__(self):
        return self.t


class Base(unittest.TestCase):
    def setUp(self):
        self.hook = MockWebhook()
        self.tmp = tempfile.TemporaryDirectory()
        self.state = Path(self.tmp.name) / "discord.json"
        self.clock = Clock()

    def tearDown(self):
        self.hook.close()
        self.tmp.cleanup()

    def alerts(self, webhook="hook", **kw):
        url = self.hook.url if webhook == "hook" else webhook
        return dn.DiscordAlerts(self.state, webhook=url, clock=self.clock, sleep=lambda s: None, **kw)


class NotifierTests(Base):
    def test_webhook_env_only_and_https(self):
        self.assertIsNone(dn.webhook_from_env({}))
        self.assertIsNone(dn.webhook_from_env({dn.WEBHOOK_ENV: "  "}))
        buf = io.StringIO()
        with redirect_stdout(buf):
            self.assertIsNone(dn.webhook_from_env({dn.WEBHOOK_ENV: "http://x.invalid/secret-part"}))
        self.assertNotIn("secret-part", buf.getvalue())
        self.assertEqual(dn.webhook_from_env({dn.WEBHOOK_ENV: "https://x.invalid/h"}), "https://x.invalid/h")
        self.assertEqual(dn.WEBHOOK_ENV, "DISCORD_HEALTH_WEBHOOK_URL")

    def test_no_webhook_is_noop(self):
        d = self.alerts(webhook=None)
        self.assertFalse(d.enabled)
        self.assertFalse(d.fire("k", "t", "x"))
        self.assertEqual(d.flush(), 0)
        self.assertFalse(d.resolve("k"))
        self.assertFalse(self.state.exists())
        self.assertEqual(self.hook.bodies, [])

    def test_fire_once_then_recovery_once(self):
        d = self.alerts()
        self.assertTrue(d.fire("k", "Thing broke", "detail"))
        self.assertEqual(d.flush(), 1)
        self.assertFalse(d.fire("k", "Thing broke", "detail"))
        self.assertEqual(d.flush(), 0)
        self.clock.t += 600
        self.assertTrue(d.resolve("k", "fixed"))
        self.assertEqual(d.flush(), 1)
        self.assertEqual(d.flush(), 0)
        titles = [e["title"] for e in self.hook.embeds()]
        self.assertEqual(len(titles), 2)
        self.assertTrue(titles[0].startswith("🔴 Thing broke"))
        self.assertTrue(titles[1].startswith("✅ Recovered: Thing broke"))
        self.assertIn("cleared after 10 min", self.hook.embeds()[1]["description"])
        self.assertTrue(all(b["allowed_mentions"] == {"parse": []} for b in self.hook.bodies))

    def test_failed_post_retries_next_flush(self):
        d = self.alerts()
        self.hook.status = 500
        d.fire("k", "t", "x")
        buf = io.StringIO()
        with redirect_stdout(buf):
            self.assertEqual(d.flush(), 0)
        self.assertNotIn("mock-token", buf.getvalue())
        self.assertIn("HTTP 500", buf.getvalue())
        self.hook.status = 204
        self.assertEqual(d.flush(), 1)

    def test_unnotified_alert_clears_silently(self):
        d = self.alerts()
        self.hook.status = 500
        d.fire("k", "t", "x")
        with redirect_stdout(io.StringIO()):
            d.flush()
        self.hook.status = 204
        self.assertFalse(d.resolve("k"))
        self.assertEqual(d.flush(), 0)
        self.assertEqual(self.hook.embeds(), [])

    def test_batching_and_rate_limit(self):
        d = self.alerts()
        for i in range(45):
            d.fire(f"k{i}", f"t{i}", "x")
        self.assertEqual(d.flush(), dn.MAX_MESSAGES_PER_FLUSH)  # 3 messages x 10 embeds
        self.assertEqual([len(b["embeds"]) for b in self.hook.bodies], [10, 10, 10])
        self.assertEqual(d.flush(), 2)  # remaining 15
        self.assertEqual(len(self.hook.embeds()), 45)
        self.assertEqual(d.flush(), 0)

    def test_429_pauses(self):
        d = self.alerts()
        d.fire("k", "t", "x")
        self.hook.status, self.hook.retry_after = 429, 30
        with redirect_stdout(io.StringIO()):
            self.assertEqual(d.flush(), 0)
        self.hook.status = 204
        self.assertEqual(d.flush(), 0)  # still paused
        self.clock.t += 31
        self.assertEqual(d.flush(), 1)

    def test_restart_keeps_state(self):
        d = self.alerts()
        d.fire("k", "t", "x")
        d.flush()
        d2 = self.alerts()
        self.assertFalse(d2.fire("k", "t", "x"))
        self.assertEqual(d2.flush(), 0)
        self.assertTrue(d2.resolve("k"))
        self.assertEqual(d2.flush(), 1)
        self.assertEqual(len(self.hook.embeds()), 2)

    def test_send_test_label(self):
        d = self.alerts()
        with redirect_stdout(io.StringIO()):
            self.assertTrue(d.send_test("TEST: x (no action needed)"))
        self.assertEqual(self.hook.bodies[0]["content"], "TEST: x (no action needed)")
        self.assertFalse(self.state.exists())  # a test touches no alert state


class RelayerTests(Base):
    TXA = "aa" * 32
    TXB = "bb" * 32

    def setUp(self):
        super().setUp()
        rel._v3_seen.clear()
        rel._last_v3_scan = 0.0
        self._prev = rel._discord
        rel._discord = self.alerts(source="eth-lc-relayer")

    def tearDown(self):
        rel._discord = self._prev
        super().tearDown()

    def _lines(self, *ids):
        return [f"ALERT unminted deposit {i} age=1900s (threshold 1800s) block=5" for i in ids]

    def test_first_alert_posts_repeat_does_not(self):
        rel.discord_sync_unminted("eth:v12", self._lines(self.TXA), set(), 1800, "V1/V2")
        rel.discord_sync_unminted("eth:v12", self._lines(self.TXA), set(), 1800, "V1/V2")
        rel.discord_sync_unminted("eth:v12", self._lines(self.TXA), set(), 1800, "V1/V2")
        e = self.hook.embeds()
        self.assertEqual(len(e), 1)
        self.assertIn("unminted over 30 min", e[0]["title"])
        self.assertIn(self.TXA, e[0]["description"])

    def test_mint_posts_recovery_once(self):
        rel.discord_sync_unminted("eth:v12", self._lines(self.TXA), set(), 1800, "V1/V2")
        rel.discord_sync_unminted("eth:v12", [], {self.TXA}, 1800, "V1/V2")
        rel.discord_sync_unminted("eth:v12", [], {self.TXA}, 1800, "V1/V2")
        e = self.hook.embeds()
        self.assertEqual(len(e), 2)
        self.assertTrue(e[1]["title"].startswith("✅ Recovered"))

    def test_absent_from_scan_is_not_recovery(self):
        rel.discord_sync_unminted("eth:v12", self._lines(self.TXA), set(), 1800, "V1/V2")
        rel.discord_sync_unminted("eth:v12", [], set(), 1800, "V1/V2")  # partial scan
        self.assertEqual(len(self.hook.embeds()), 1)

    def test_restart_does_not_repost(self):
        rel.discord_sync_unminted("eth:v12", self._lines(self.TXA), set(), 1800, "V1/V2")
        rel._discord = self.alerts(source="eth-lc-relayer")  # new process, same state file
        rel.discord_sync_unminted("eth:v12", self._lines(self.TXA), set(), 1800, "V1/V2")
        self.assertEqual(len(self.hook.embeds()), 1)
        rel.discord_sync_unminted("eth:v12", [], {self.TXA}, 1800, "V1/V2")
        self.assertEqual(len(self.hook.embeds()), 2)

    def test_no_webhook_noop(self):
        rel._discord = None
        rel.discord_sync_unminted("eth:v12", self._lines(self.TXA), set(), 1800, "V1/V2")
        with patch.dict(os.environ, {dn.WEBHOOK_ENV: ""}), patch.object(rel, "DISCORD_STATE", self.state):
            with redirect_stdout(io.StringIO()):
                self.assertIsNone(rel.init_discord())
                self.assertEqual(rel.cmd_discord_test(), 1)
        self.assertEqual(self.hook.bodies, [])
        self.assertFalse(self.state.exists())

    def test_many_stuck_batched(self):
        ids = [f"{i:064x}" for i in range(25)]
        rel.discord_sync_unminted("eth:v12", self._lines(*ids), set(), 1800, "V1/V2")
        self.assertEqual([len(b["embeds"]) for b in self.hook.bodies], [10, 10, 5])

    def test_v3_scan_end_to_end(self):
        now = 2_000_000
        old = now - rel.V3_UNMINTED_SEC

        def log(dep, ts):
            data = "0x" + ("00" * 32) * 3 + format(ts, "064x")
            return {"topics": [rel.V3_DEPOSIT_TOPIC0, "0x" + dep, "0x" + "00" * 32],
                    "data": data, "blockNumber": hex(9_990), "transactionHash": "0x" + "ee" * 32}

        logs = [log(self.TXA, old), log(self.TXB, now - 60)]

        def fake_rpc(method, params):
            if method == "eth_blockNumber":
                return hex(10_000)
            return logs if int(params[0]["toBlock"], 16) == 10_000 else []

        with patch.object(rel, "eth_rpc", fake_rpc), redirect_stdout(io.StringIO()):
            rel.scan_unminted_v3_deposits({"eth_v3_resolutions": []}, now=now)
            rel._last_v3_scan = 0.0
            rel.scan_unminted_v3_deposits({"eth_v3_resolutions": []}, now=now + 700)
            rel._last_v3_scan = 0.0
            rel.scan_unminted_v3_deposits({"eth_v3_resolutions": [{"deposit_id": self.TXA}]}, now=now + 1400)
        e = self.hook.embeds()
        self.assertEqual(len(e), 2, [x["title"] for x in e])
        self.assertIn("V3 deposit unminted over 30 min", e[0]["title"])
        self.assertIn(self.TXA, e[0]["description"])
        self.assertTrue(e[1]["title"].startswith("✅ Recovered"))

    def test_discord_test_subcommand_label(self):
        with patch.dict(os.environ, {dn.WEBHOOK_ENV: "https://example.invalid/x"}), \
                patch.object(dn, "http_post", lambda url, body: (self.hook.bodies.append(body) or True, None)), \
                patch.object(rel, "DISCORD_STATE", self.state), redirect_stdout(io.StringIO()):
            self.assertEqual(self._run_main(), 0)
        self.assertEqual(self.hook.bodies[0]["content"],
                         "TEST: Falcon relayer unminted-deposit alert (no action needed)")

    def _run_main(self):
        with patch.object(sys, "argv", ["pl-eth-lc-relayer.py", "discord-test"]):
            return rel.main()


class BtcWatchTests(Base):
    TX = "cd" * 32

    def setUp(self):
        super().setUp()
        self.st = {"rails": [{"asset": "BTC4", "tip_height": 100, "spent_deposits": []}]}
        self.ext = 100
        self.unit_info = {"active": "active", "restarts": 0}
        self.reqs: list[dict] = []
        self.w = self._watch()

    def _watch(self):
        return btc.Watch(self.alerts(source="btc-alert-watch"), clock=self.clock,
                         status=lambda: self.st, explorer_tip=lambda: self.ext,
                         unit=lambda u: dict(self.unit_info), intake=lambda d: self.reqs,
                         units=["falcon-pl-btc4-header-submitter.service"])

    def titles(self):
        return [e["title"] for e in self.hook.embeds()]

    def step(self, sec):
        self.clock.t += sec
        with redirect_stdout(io.StringIO()):
            self.w.poll()

    def test_headers_stale_fire_once_and_recover(self):
        self.step(0)
        self.ext = 103
        self.step(btc.STALE_SEC - 60)
        self.assertEqual(self.titles(), [])
        self.step(60)
        self.step(60)
        self.step(600)
        self.assertEqual(len(self.titles()), 1)
        self.assertIn("BTC4 headers stale", self.titles()[0])
        self.st["rails"][0]["tip_height"] = 103
        self.step(60)
        self.step(60)
        self.assertEqual(len(self.titles()), 2)
        self.assertTrue(self.titles()[1].startswith("✅ Recovered: BTC4 headers stale"))

    def test_quiet_chain_is_not_stale(self):
        self.step(0)
        self.step(4 * 3600)  # no new testnet4 block: rail == explorer
        self.assertEqual(self.titles(), [])

    def test_node_down_does_not_fire_stale(self):
        self.step(0)
        self.ext = 110
        self.st = {}
        self.step(btc.STALE_SEC * 2)
        self.assertEqual(self.titles(), [])

    def test_submitter_stopped_and_back(self):
        self.step(0)
        self.unit_info["active"] = "inactive"
        self.step(30)
        self.step(btc.DOWN_SEC)
        self.step(60)
        self.assertEqual(len(self.titles()), 1)
        self.assertIn("header submitter stopped", self.titles()[0])
        self.unit_info["active"] = "active"
        self.step(60)
        self.assertTrue(self.titles()[1].startswith("✅ Recovered: BTC4 header submitter stopped"))

    def test_submitter_crash_loop(self):
        self.step(0)
        for _ in range(btc.RESTARTS):
            self.unit_info["restarts"] += 1
            self.step(60)
        self.step(60)
        self.assertEqual(sum("keeps failing" in t for t in self.titles()), 1)
        for _ in range(btc.WINDOW_SEC // 60 + 1):
            self.step(60)
        self.assertEqual(sum("Recovered: BTC4 header submitter keeps failing" in t for t in self.titles()), 1)

    def test_deposit_unminted_restart_and_mint(self):
        self.reqs = [{"id": "0123456789abcdef", "state": "awaiting_mint", "updated": self.clock.t,
                      "peg_in_confirm_txid": self.TX, "confirmations": 6}]
        self.step(btc.UNMINTED_SEC - 60)
        self.assertEqual(self.titles(), [])
        self.step(60)
        self.step(60)
        self.assertEqual(len(self.titles()), 1)
        self.assertIn("BTC4 deposit unminted over 30 min", self.titles()[0])
        self.w = self._watch()  # restart
        self.step(60)
        self.assertEqual(len(self.titles()), 1)
        self.st["rails"][0]["spent_deposits"] = [self.TX.upper()]
        self.step(60)
        self.step(60)
        self.assertEqual(len(self.titles()), 2)
        self.assertTrue(self.titles()[1].startswith("✅ Recovered: BTC4 deposit unminted"))

    def test_minted_state_recovers(self):
        self.reqs = [{"id": "0123456789abcdef", "state": "awaiting_mint", "updated": self.clock.t - 4000,
                      "peg_in_confirm_txid": self.TX}]
        self.step(0)
        self.reqs[0]["state"] = "minted"
        self.step(60)
        self.assertEqual(len(self.titles()), 2)

    def test_no_webhook_noop(self):
        with patch.dict(os.environ, {dn.WEBHOOK_ENV: ""}), patch.object(btc, "STATE", self.state), \
                redirect_stdout(io.StringIO()):
            self.assertEqual(btc.main(["--once"]), 0)
            self.assertEqual(btc.main(["--test", "headers-stale"]), 1)
        w = btc.Watch(dn.DiscordAlerts(self.state, webhook=None), clock=self.clock,
                      status=lambda: self.st, explorer_tip=lambda: 999, unit=lambda u: {"active": "failed", "restarts": 9},
                      intake=lambda d: [], units=["x.service"])
        self.clock.t += 10 * 3600
        with redirect_stdout(io.StringIO()):
            self.assertEqual(w.poll(), 0)
        self.assertEqual(self.hook.bodies, [])
        self.assertFalse(self.state.exists())

    def test_test_labels(self):
        sent = []
        with patch.dict(os.environ, {dn.WEBHOOK_ENV: "https://example.invalid/x"}), \
                patch.object(dn, "http_post", lambda url, body: (sent.append(body) or True, None)), \
                patch.object(btc, "STATE", self.state), redirect_stdout(io.StringIO()):
            for kind in sorted(btc.TEST_LABELS):
                self.assertEqual(btc.main(["--test", kind]), 0)
        self.assertEqual([b["content"] for b in sent], [btc.TEST_LABELS[k] for k in sorted(btc.TEST_LABELS)])
        self.assertTrue(all(b["content"].startswith("TEST: ") and b["content"].endswith("(no action needed)") for b in sent))


if __name__ == "__main__":
    unittest.main()
