#!/usr/bin/env python3
"""Unit tests for intake ceremony supervision (concurrency cap, coordinator restart,
stage timeouts, alerts). No network, no bitcoin, no real coordinator: /proc is faked
with a directory tree and process spawning is stubbed.

Run: python3 test_ceremony_supervision.py -v
"""
import importlib.util
import json
import os
import sys
import tempfile
import time
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent


def load_intake(home, proc):
    os.environ["FPL_OP_HOME"] = home
    os.environ["FPL_PROC"] = proc
    os.environ["FPL_EX"] = "/opt/fpl-operator/bin"
    os.environ["FPL_LOCAL_SEAT"] = "falcon1"
    for k in ("FPL_OPERATOR_SECRET_FILE", "FPL_DISCORD_WEBHOOK_URL", "DISCORD_HEALTH_WEBHOOK_URL",
              "FPL_DISCORD_ENV_FILE"):
        os.environ.pop(k, None)
    name = "fpl_bridge_intake_sup"
    spec = importlib.util.spec_from_file_location(name, HERE / "fpl_bridge_intake.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


class FakeProc:
    def __init__(self, root):
        self.root = Path(root)
        self.next = 1000

    def add(self, argv, state="S", rss_mb=10):
        self.next += 1
        d = self.root / str(self.next)
        d.mkdir(parents=True)
        (d / "cmdline").write_bytes(b"\0".join(a.encode() for a in argv) + b"\0")
        (d / "stat").write_text(f"{self.next} (x) {state} 1 1")
        (d / "status").write_text(f"Name:\tx\nVmRSS:\t{rss_mb * 1024} kB\n")
        return self.next

    def kill(self, pid):
        import shutil
        shutil.rmtree(self.root / str(pid), ignore_errors=True)

    def zombie(self, pid):
        (self.root / str(pid) / "stat").write_text(f"{pid} (x) Z 1 1")
        (self.root / str(pid) / "cmdline").write_bytes(b"")


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.home = os.path.join(cls.tmp.name, "home")
        cls.procdir = os.path.join(cls.tmp.name, "proc")
        os.makedirs(cls.procdir)
        cls.I = load_intake(cls.home, cls.procdir)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def setUp(self):
        I = self.I
        for f in os.listdir(I.STATE):
            os.remove(os.path.join(I.STATE, f))
        import shutil
        shutil.rmtree(self.procdir); os.makedirs(self.procdir)
        self.proc = FakeProc(self.procdir)
        self.alerts = []
        self.spawned = []
        self.seen = {}           # txid -> True/False/None
        self.mem = 15000
        I._ALERTED.clear()
        P = mock.patch.object
        self.patches = [
            P(I, "alert", lambda kind, r, msg, min_interval=900: self.alerts.append((kind, r.get("id"), msg))),
            P(I, "tx_seen", lambda txid: self.seen.get(txid, False) if txid else False),
            P(I, "mem_available_mb", lambda: self.mem),
            P(I, "spawn_ceremony_coordinator", self.fake_spawn_coord),
            P(I, "spawn_broadcast", self.fake_spawn_bcast),
            P(I.os, "kill", lambda pid, sig: self.proc.kill(pid)),
        ]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in reversed(self.patches):
            p.stop()

    # stubs
    def fake_spawn_coord(self, r, d, restart=False):
        pid = self.proc.add([self.I.EX + "/fpl_ceremony_coordinator", "--dir", d, "--network", "testnet4"], rss_mb=50)
        r["coord_pid"] = pid
        r["coord_spawned"] = int(time.time())
        if not restart:
            r["coord_attempts"] = 1
        self.spawned.append(("coord", r["id"], restart))
        return pid

    def fake_spawn_bcast(self, r, d):
        pid = self.proc.add([self.I.EX + "/fpl_ceremony_coordinator", "--dir", d, "--resume", "--broadcast-peg-in"])
        r["bcast_pid"] = pid; r["bcast_spawned"] = int(time.time())
        self.spawned.append(("bcast", r["id"]))
        return pid

    def req(self, rid, state, age=0, **kw):
        now = int(time.time())
        r = {"id": rid, "account": "loadtest01", "state": state, "created": now - age - 10,
             "updated": now - age, "state_since": now - age, "funding": "aa" * 32 + ":0", "funding_sats": 55000,
             "kickoff": rid[:4] + "ko:0", "kickoff_sats": 15000000, "deposit_txid": "d" + rid[1:] * 4,
             "peg_in_confirm_txid": "c" + rid[1:] * 4, "depositor_pubkey": "02" + "11" * 32}
        r.update(kw)
        with open(self.I.path(rid), "w") as f:
            json.dump(r, f)
        os.makedirs(self.I.gdir(r), exist_ok=True)
        return r

    def load(self, rid):
        return self.I.load(rid)

    def coord(self, r, resume=False):
        argv = [self.I.EX + "/fpl_ceremony_coordinator", "--dir", self.I.gdir(r)] + (["--resume"] if resume else [])
        return self.proc.add(argv, rss_mb=4300)

    def participant(self, r, seat="falcon1"):
        return self.proc.add([self.I.EX + "/fpl_ceremony_participant", "--dir", self.I.gdir(r), "--id", seat])


class ConcurrencyCap(Base):
    def test_slot_free_counts_live_coordinators_only(self):
        a = self.req("a000000000000001", "signed")
        b = self.req("b000000000000001", "signed")
        self.coord(a)
        self.assertTrue(self.I.ceremony_slot_free()[0])
        pb = self.coord(b)
        ok, why = self.I.ceremony_slot_free()
        self.assertFalse(ok); self.assertIn("2 ceremonies running", why)
        self.proc.zombie(pb)                      # a zombie is not a live ceremony
        self.assertTrue(self.I.ceremony_slot_free()[0])

    def test_resume_processes_do_not_count(self):
        a = self.req("a000000000000002", "broadcasting")
        self.coord(a, resume=True); self.coord(a, resume=True)
        self.assertTrue(self.I.ceremony_slot_free()[0])

    def test_memory_headroom_includes_ramp(self):
        a = self.req("a000000000000003", "ceremony_pubkeys")
        self.proc.add([self.I.EX + "/fpl_ceremony_coordinator", "--dir", self.I.gdir(a)], rss_mb=100)
        self.mem = 9000   # 9000 - (4608-100) = 4492 < 4608+1024
        ok, why = self.I.ceremony_slot_free()
        self.assertFalse(ok); self.assertIn("memory", why)
        self.mem = 11000
        self.assertTrue(self.I.ceremony_slot_free()[0])

    def test_funded_deferred_when_full_then_proceeds(self):
        """Four fundings in one block: only MAX_CEREMONIES start; the rest wait in
        `funded` with a reason; no kickoff is reserved for the waiting ones."""
        I = self.I
        reqs = [self.req(f"f00000000000000{i}", "funded", kickoff=None, kickoff_sats=None) for i in range(4)]
        kos = iter([(f"k{i}:0", 15000000) for i in range(10)])
        with mock.patch.object(I, "pick_kickoff", lambda need: next(kos)), \
                mock.patch.object(I.subprocess, "Popen", lambda *a, **k: mock.Mock(pid=1)), \
                mock.patch.object(I, "PEG_IN_FEE", 590), mock.patch.object(I, "PEG_OUT_FEE", 1000):
            I.worker_pass()
        states = [self.load(r["id"]) for r in reqs]
        started = [r for r in states if r["state"] == "ceremony_pubkeys"]
        waiting = [r for r in states if r["state"] == "funded"]
        self.assertEqual(len(started), I.MAX_CEREMONIES)
        self.assertEqual(len(waiting), 4 - I.MAX_CEREMONIES)
        for r in waiting:
            self.assertIn("waiting_ceremony_slot", r["last_error"])
            self.assertFalse(r.get("kickoff"))
        self.assertEqual(I.reserved_kickoff_set(states), {r["kickoff"] for r in started})


class CoordinatorSupervision(Base):
    def test_dead_coordinator_before_graphs_is_restarted_with_backoff(self):
        I = self.I
        r = self.req("a100000000000001", "signed", coord_spawned=int(time.time()) - 600, coord_attempts=1)
        self.participant(r)
        now = time.time()
        I.worker_pass(now)
        r1 = self.load(r["id"])
        self.assertEqual(r1["state"], "signed")
        self.assertIn("coord_dead_since", r1)
        self.assertEqual([a[0] for a in self.alerts], ["coordinator_died"])
        self.assertEqual(self.spawned, [])        # backoff not elapsed yet
        I.worker_pass(now + I.COORD_BACKOFF_SECS + 1)
        r2 = self.load(r["id"])
        self.assertEqual(self.spawned, [("coord", r["id"], True)])
        self.assertEqual(r2["coord_attempts"], 2)
        self.assertNotIn("coord_dead_since", r2)
        self.assertIn("coordinator_restarted", [a[0] for a in self.alerts])

    def test_live_coordinator_untouched(self):
        r = self.req("a100000000000002", "signed", coord_spawned=1)
        self.coord(r); self.participant(r)
        self.I.worker_pass()
        self.assertEqual(self.load(r["id"])["state"], "signed")
        self.assertEqual(self.alerts, []); self.assertEqual(self.spawned, [])

    def test_retries_exhausted_marks_failed_and_releases_kickoff(self):
        I = self.I
        r = self.req("a100000000000003", "signed", coord_spawned=1, coord_attempts=I.COORD_MAX_RETRIES + 1)
        self.participant(r)
        I.worker_pass()
        f = self.load(r["id"])
        self.assertEqual(f["state"], "failed")
        self.assertEqual(f["failed_reason"], "coordinator_retries_exhausted")
        self.assertNotIn(r["kickoff"], I.reserved_kickoffs())
        self.assertIn("failed", [a[0] for a in self.alerts])
        self.assertEqual(I.ceremony_procs(I.gdir(r)), [])   # participant killed

    def test_died_after_graphs_published_fails_not_restarts(self):
        I = self.I
        r = self.req("a100000000000004", "signed", coord_spawned=1)
        self.participant(r)
        Path(I.gdir(r), "graphs.json").write_text("{}")
        I.worker_pass()
        f = self.load(r["id"])
        self.assertEqual(f["state"], "failed")
        self.assertEqual(f["failed_reason"], "coordinator_died_mid_signing")
        self.assertEqual(self.spawned, [])

    def test_local_participant_gone_fails(self):
        r = self.req("a100000000000005", "awaiting_signature", coord_spawned=1)
        self.I.worker_pass()
        f = self.load(r["id"])
        self.assertEqual(f["state"], "failed"); self.assertEqual(f["failed_reason"], "participant_died")

    def test_restart_waits_for_slot(self):
        I = self.I
        r = self.req("a100000000000006", "signed", coord_spawned=1, coord_dead_since=1)
        self.participant(r)
        for i in range(I.MAX_CEREMONIES):
            o = self.req(f"b10000000000000{i}", "signed"); self.coord(o); self.participant(o)
        I.worker_pass()
        f = self.load(r["id"])
        self.assertEqual(f["state"], "signed")
        self.assertIn("waiting for slot", f["last_error"])
        self.assertEqual(self.spawned, [])

    def test_final_json_present_means_no_restart(self):
        I = self.I
        r = self.req("a100000000000007", "signed", coord_spawned=1)
        Path(I.gdir(r), "final.json").write_text("{}")
        I.worker_pass()
        self.assertEqual(self.load(r["id"])["state"], "presigned")
        self.assertEqual(self.spawned, [])

    def test_incident_65bb_shape(self):
        """65bb: signed, coordinator OOM-killed before graphs.json, both participants
        alive -> the supervisor restarts the coordinator (it would have recovered)."""
        I = self.I
        r = self.req("65bb17492517646e", "signed", coord_spawned=1)
        self.participant(r)
        I.worker_pass(time.time())
        I.worker_pass(time.time() + I.COORD_BACKOFF_SECS + 1)
        self.assertEqual(self.spawned, [("coord", r["id"], True)])
        self.assertEqual(self.load(r["id"])["state"], "signed")


class StageTimeouts(Base):
    def test_every_non_terminal_state_has_a_timeout(self):
        I = self.I
        for s in ("awaiting_funding",) + I.PRE_BROADCAST_STATES + I.POST_BROADCAST_STATES:
            self.assertGreater(I.stage_timeout(s), 0, s)

    def test_pre_broadcast_timeout_fails_and_releases(self):
        I = self.I
        for s in I.PRE_BROADCAST_STATES:
            with self.subTest(s=s):
                rid = "c" + format(I.PRE_BROADCAST_STATES.index(s), "015x")
                r = self.req(rid, s, age=I.stage_timeout(s) + 60, coord_spawned=int(time.time()))
                self.coord(r); self.participant(r)
                I.worker_pass()
                f = self.load(rid)
                self.assertEqual(f["state"], "failed")
                self.assertEqual(f["failed_reason"], "stage_timeout_" + s)
                self.assertIn("stage timeout", f["last_error"])
                self.assertNotIn(r["kickoff"], I.reserved_kickoffs())
                self.assertEqual(I.ceremony_procs(I.gdir(r)), [])

    def test_not_failed_if_deposit_already_broadcast(self):
        I = self.I
        r = self.req("c100000000000001", "presigned", age=I.stage_timeout("presigned") + 60)
        self.seen[r["deposit_txid"]] = True
        I.worker_pass()
        f = self.load(r["id"])
        self.assertEqual(f["state"], "presigned")
        self.assertIn("NOT failed", f["stalled"])
        self.assertIn(r["kickoff"], I.reserved_kickoffs())
        self.assertIn("stalled", [a[0] for a in self.alerts])

    def test_esplora_unknown_defers_fail(self):
        I = self.I
        r = self.req("c100000000000002", "signed", age=I.stage_timeout("signed") + 60)
        self.seen[r["deposit_txid"]] = None
        I.worker_pass()
        f = self.load(r["id"])
        self.assertEqual(f["state"], "signed"); self.assertIn("fail deferred", f["last_error"])

    def test_post_broadcast_stalls_with_realert_not_fail(self):
        I = self.I
        r = self.req("c100000000000003", "awaiting_mint", age=I.stage_timeout("awaiting_mint") + 60)
        now = time.time()
        I.worker_pass(now)
        I.worker_pass(now + 60)
        f = self.load(r["id"])
        self.assertEqual(f["state"], "awaiting_mint")
        self.assertEqual([a[0] for a in self.alerts].count("stalled"), 1)
        I.worker_pass(now + I.STALL_REALERT_SECS + 61)
        self.assertEqual([a[0] for a in self.alerts].count("stalled"), 2)

    def test_env_override(self):
        with mock.patch.dict(os.environ, {"FPL_STAGE_TIMEOUT_SIGNED": "60"}):
            self.assertEqual(self.I.stage_timeout("signed"), 60)

    def test_state_since_tracks_transitions(self):
        I = self.I
        r = self.req("c100000000000004", "awaiting_signature", age=5000)
        r = I.load(r["id"]); old = r["state_since"]
        r["last_error"] = "x"; I.save(r)
        self.assertEqual(I.load(r["id"])["state_since"], old)      # same state: age kept
        r["state"] = "signed"; I.save(r)
        self.assertGreaterEqual(I.load(r["id"])["state_since"], int(time.time()) - 2)

    def test_legacy_record_without_state_since_uses_updated(self):
        I = self.I
        r = self.req("c100000000000005", "awaiting_signature", age=0)
        d = json.load(open(I.path(r["id"]))); d.pop("state_since"); d["updated"] = int(time.time()) - 9 * 86400
        json.dump(d, open(I.path(r["id"]), "w"))
        rows = I.plan(I.all_reqs())
        self.assertEqual(rows[0]["action"], "fail")
        self.assertGreater(rows[0]["age_h"], 200)

    def test_plan_is_read_only(self):
        I = self.I
        r = self.req("c100000000000006", "awaiting_signature", age=10 * 86400)
        before = open(I.path(r["id"])).read()
        rows = I.plan(I.all_reqs())
        self.assertEqual(open(I.path(r["id"])).read(), before)
        self.assertEqual([x["action"] for x in rows], ["fail"])


class BroadcastSupervision(Base):
    def test_dead_broadcast_respawned_when_confirm_unseen(self):
        I = self.I
        r = self.req("d100000000000001", "broadcasting", bcast_spawned=1, bcast_attempts=1)
        I.worker_pass()
        self.assertEqual(self.spawned, [("bcast", r["id"])])
        self.assertEqual(self.load(r["id"])["bcast_attempts"], 2)

    def test_no_respawn_when_confirm_seen(self):
        I = self.I
        r = self.req("d100000000000002", "broadcasting", bcast_spawned=1)
        self.seen[r["peg_in_confirm_txid"]] = True
        with mock.patch.object(I, "esplora", side_effect=Exception("offline")):
            I.worker_pass()
        self.assertEqual(self.spawned, [])

    def test_exhausted_broadcast_stalls(self):
        I = self.I
        r = self.req("d100000000000003", "broadcasting", bcast_spawned=1, bcast_attempts=I.COORD_MAX_RETRIES + 1)
        I.worker_pass()
        f = self.load(r["id"])
        self.assertEqual(f["state"], "broadcasting"); self.assertIn("manual action", f["stalled"])


class ReviewFixes(Base):
    def test_final_json_never_released_on_timeout(self):
        """Copilot high: presigned graphs stay usable -> stall, keep kickoff."""
        I = self.I
        r = self.req("e100000000000001", "presigned", age=I.stage_timeout("presigned") + 60)
        Path(I.gdir(r), "final.json").write_text("{}")
        I.worker_pass()
        f = self.load(r["id"])
        self.assertEqual(f["state"], "presigned")
        self.assertIn("final.json", f["stalled"])
        self.assertIn(r["kickoff"], I.reserved_kickoffs())
        self.assertEqual(I.plan(I.all_reqs())[0]["action"], "stall")

    def test_awaiting_funding_timeout_configurable(self):
        I = self.I
        r = self.req("e100000000000002", "awaiting_funding", age=120, address="tb1qx")
        with mock.patch.dict(os.environ, {"FPL_STAGE_TIMEOUT_AWAITING_FUNDING": "60"}):
            self.assertTrue(I.step(I.load(r["id"])) is True)
        with mock.patch.dict(os.environ, {"FPL_STAGE_TIMEOUT_AWAITING_FUNDING": "0"}), \
                mock.patch.object(I, "esplora", lambda path: []):
            rr = I.load(r["id"])
            self.assertFalse(I.step(rr)); self.assertEqual(rr["state"], "awaiting_funding")

    def test_participant_dead_with_live_coordinator_fails(self):
        I = self.I
        r = self.req("e100000000000003", "signed", coord_spawned=1)
        self.coord(r)
        I.worker_pass()
        f = self.load(r["id"])
        self.assertEqual(f["state"], "failed"); self.assertEqual(f["failed_reason"], "participant_died")
        self.assertEqual(I.ceremony_procs(I.gdir(r)), [])

    def test_plan_matches_supervision_safety(self):
        I = self.I
        a = self.req("e100000000000004", "signed", age=I.stage_timeout("signed") + 60)
        b = self.req("e100000000000005", "signed", age=I.stage_timeout("signed") + 60)
        c = self.req("e100000000000006", "signed", coord_spawned=1)
        self.participant(c)
        self.seen[a["deposit_txid"]] = True
        self.seen[b["deposit_txid"]] = None
        acts = {x["id"]: x["action"] for x in I.plan(I.all_reqs())}
        self.assertEqual(acts, {a["id"]: "stall", b["id"]: "defer", c["id"]: "coordinator_dead"})


class AlertSafety(unittest.TestCase):
    def test_webhook_url_never_logged(self):
        tmp = tempfile.mkdtemp()
        I = load_intake(os.path.join(tmp, "h"), os.path.join(tmp, "p"))
        url = "https://discord.example/api/webhooks/1/SECRETTOKEN"
        logged = []
        with mock.patch.dict(os.environ, {"DISCORD_HEALTH_WEBHOOK_URL": url}), \
                mock.patch.object(I, "log", lambda *a: logged.append(" ".join(map(str, a)))), \
                mock.patch.object(I.urllib.request, "urlopen", side_effect=OSError("down")):
            I._post_discord("hello")
            I.alert("failed", {"id": "x"}, "msg")
            time.sleep(0.2)
        self.assertTrue(logged)
        self.assertFalse(any("SECRETTOKEN" in m or "webhooks" in m for m in logged), logged)

    def test_env_file_webhook(self):
        tmp = tempfile.mkdtemp()
        I = load_intake(os.path.join(tmp, "h"), os.path.join(tmp, "p"))
        f = os.path.join(tmp, "discord.env")
        open(f, "w").write("DISCORD_HEALTH_WEBHOOK_URL=https://example/w\n")
        with mock.patch.dict(os.environ, {"FPL_DISCORD_ENV_FILE": f}):
            self.assertEqual(I._webhook_url(), "https://example/w")


if __name__ == "__main__":
    unittest.main()
