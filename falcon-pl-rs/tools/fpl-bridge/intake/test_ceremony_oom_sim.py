#!/usr/bin/env python3
"""Isolated simulated-OOM test for intake ceremony supervision, with REAL processes.

A fake `fpl_ceremony_coordinator` (bash -> python, argv[0] kept so /proc matching works)
allocates memory and waits; the test SIGKILLs it exactly as the kernel OOM killer does.
The real intake supervisor (real /proc scan, real Popen, real zombie handling) must:
  1. notice the dead coordinator, alert, back off, restart it, and finish the ceremony;
  2. after FPL_COORD_MAX_RETRIES deaths, mark the request failed, release its kickoff,
     kill the local participant, and alert.
Optional real kernel OOM: FPL_TEST_REAL_OOM=1 runs the fake coordinator under
`systemd-run --scope -p MemoryMax=…` (needs root + systemd), letting the memcg kill it.
Nothing touches the network or a real bridge. Run: python3 test_ceremony_oom_sim.py -v
"""
import importlib.util
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent

FAKE_COORD = textwrap.dedent(r'''
    import os, sys, time, json
    a = sys.argv[1:]
    d = a[a.index("--dir") + 1]
    runs = os.path.join(d, "fake_runs")
    n = int(open(runs).read()) + 1 if os.path.exists(runs) else 1
    open(runs, "w").write(str(n))
    die_runs = int(os.environ.get("FAKE_DIE_RUNS", "1"))
    mb = int(os.environ.get("FAKE_ALLOC_MB", "64"))
    if n <= die_runs:
        buf = bytearray(mb << 20)          # grow like a real coordinator, then wait to be killed
        for i in range(0, len(buf), 4096):
            buf[i] = 1
        open(os.path.join(d, f"fake_ready_{n}"), "w").close()
        time.sleep(3600)
    else:
        assert os.path.exists(os.path.join(d, "peg_in_signed.json"))
        time.sleep(0.3)
        open(os.path.join(d, "final.json"), "w").write("{}")
        open(os.path.join(d, "transcript.json"), "w").write(json.dumps({"attestations": []}))
''')
FAKE_PART = 'import time, sys; time.sleep(3600)\n'


def write_exe(path, py_code):
    code = path.with_suffix(".py")
    code.write_text(py_code)
    path.write_text(f'#!/bin/bash\nexec -a "$0" {sys.executable} {code} "$@"\n')
    path.chmod(0o755)


class OomSim(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="fpl-oom-sim-")
        self.home = os.path.join(self.tmp, "home")
        self.bin = Path(self.tmp, "bin"); self.bin.mkdir()
        write_exe(self.bin / "fpl_ceremony_coordinator", FAKE_COORD)
        write_exe(self.bin / "fpl_ceremony_participant", FAKE_PART)
        env = {"FPL_OP_HOME": self.home, "FPL_EX": str(self.bin), "FPL_LOCAL_SEAT": "falcon1",
               "FPL_NETWORK": "testnet4", "FPL_SEATS": "falcon1,falcon2,beartec-brain",
               "FPL_COORD_BACKOFF_SECS": "1", "FPL_COORD_BACKOFF_MAX_SECS": "2", "FPL_COORD_GRACE_SECS": "0",
               "FPL_COORD_MAX_RETRIES": "2", "FPL_CEREMONY_MEM_MB": "64", "FPL_MEM_HEADROOM_MB": "16"}
        self.envp = mock.patch.dict(os.environ, env); self.envp.start()
        os.environ.pop("FPL_PROC", None)
        for k in ("FPL_DISCORD_WEBHOOK_URL", "DISCORD_HEALTH_WEBHOOK_URL", "FPL_DISCORD_ENV_FILE"):
            os.environ.pop(k, None)
        spec = importlib.util.spec_from_file_location("fpl_intake_oomsim", HERE / "fpl_bridge_intake.py")
        self.I = importlib.util.module_from_spec(spec); spec.loader.exec_module(self.I)
        self.alerts = []
        self.p = [mock.patch.object(self.I, "alert", lambda k, r, m, min_interval=900: self.alerts.append((k, m))),
                  mock.patch.object(self.I, "tx_seen", lambda txid: False)]
        for p in self.p:
            p.start()
        self.children = []

    def tearDown(self):
        for p in reversed(self.p):
            p.stop()
        for pid, _, _ in self.I.ceremony_procs(None):
            if self.home in " ".join(self.I._cmdline(pid)):
                try:
                    os.kill(pid, signal.SIGKILL)
                except OSError:
                    pass
        self.envp.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def make_request(self, rid):
        I = self.I
        r = {"id": rid, "account": "loadtest01", "state": "signed", "created": int(time.time()) - 300,
             "funding": "ab" * 32 + ":0", "funding_sats": 55000, "kickoff": "cd" * 32 + ":0",
             "kickoff_sats": 15047987, "deposit_txid": "ef" * 32, "peg_in_confirm_txid": "01" * 32,
             "depositor_pubkey": "02" + "11" * 32}
        d = I.gdir(r); os.makedirs(d)
        Path(d, "peg_in_signed.json").write_text("{}")
        I.spawn_ceremony_coordinator(r, d)          # attempt 1 (real Popen)
        self.participant = subprocess.Popen([str(self.bin / "fpl_ceremony_participant"), "--dir", d, "--id", "falcon1"],
                                            start_new_session=True)
        I.save(r)
        return r, d

    def wait_file(self, f, t=20):
        t0 = time.time()
        while not os.path.exists(f):
            self.assertLess(time.time() - t0, t, f"timeout waiting for {f}")
            time.sleep(0.05)

    def oom_kill(self, d):
        """SIGKILL the live coordinator for d (what the memcg OOM killer does)."""
        live = self.I.live_ceremony_coordinators()
        pid = live[os.path.normpath(d)]
        self.assertGreater(self.I._rss_mb(pid), 32)   # it really allocated memory
        os.kill(pid, signal.SIGKILL)
        t0 = time.time()
        while os.path.normpath(d) in self.I.live_ceremony_coordinators():
            self.assertLess(time.time() - t0, 10); time.sleep(0.05)
        return pid

    def drive(self, rid, until, t=40):
        t0 = time.time()
        while True:
            self.I.worker_pass()
            r = self.I.load(rid)
            if until(r):
                return r
            self.assertLess(time.time() - t0, t, f"stuck: {r}")
            time.sleep(0.2)

    def test_oom_killed_coordinator_is_restarted_and_ceremony_completes(self):
        os.environ["FAKE_DIE_RUNS"] = "1"
        r, d = self.make_request("65bb17492517646e")
        self.wait_file(os.path.join(d, "fake_ready_1"))
        self.oom_kill(d)
        r = self.drive(r["id"], lambda x: x["state"] == "presigned")
        kinds = [k for k, _ in self.alerts]
        self.assertIn("coordinator_died", kinds)
        self.assertIn("coordinator_restarted", kinds)
        self.assertEqual(r["coord_attempts"], 2)
        self.assertTrue(os.path.exists(os.path.join(d, "final.json")))
        self.assertIn("coordinator restart attempt 2", Path(d, "coordinator.log").read_text())

    def test_repeated_oom_exhausts_retries_then_fails_and_releases(self):
        os.environ["FAKE_DIE_RUNS"] = "99"
        r, d = self.make_request("a5a5a5a5a5a5a5a5")
        killed = 0
        t0 = time.time()
        while self.I.load(r["id"])["state"] != "failed":
            self.assertLess(time.time() - t0, 60)
            n = killed + 1
            ready = os.path.join(d, f"fake_ready_{n}")
            if os.path.exists(ready) and os.path.normpath(d) in self.I.live_ceremony_coordinators():
                self.oom_kill(d); killed += 1
            self.I.worker_pass()
            time.sleep(0.2)
        f = self.I.load(r["id"])
        self.assertEqual(killed, 1 + self.I.COORD_MAX_RETRIES)
        self.assertEqual(f["failed_reason"], "coordinator_retries_exhausted")
        self.assertNotIn(r["kickoff"], self.I.reserved_kickoffs())
        self.assertIn("failed", [k for k, _ in self.alerts])
        self.participant.wait(timeout=10)             # local participant was terminated
        self.assertEqual(self.I.ceremony_procs(d), [])

    @unittest.skipUnless(os.environ.get("FPL_TEST_REAL_OOM") == "1" and os.geteuid() == 0
                         and shutil.which("systemd-run"), "real memcg OOM needs root + systemd (FPL_TEST_REAL_OOM=1)")
    def test_real_memcg_oom_kill(self):
        """Fake coordinator in a transient scope with a small MemoryMax: the kernel kills it."""
        os.environ["FAKE_DIE_RUNS"] = "1"; os.environ["FAKE_ALLOC_MB"] = "512"
        real_popen = subprocess.Popen

        def scoped(args, **kw):
            if os.path.basename(args[0]) == "fpl_ceremony_coordinator":
                args = ["systemd-run", "--scope", "--quiet", "-p", "MemoryMax=128M", "-p", "MemorySwapMax=0"] + list(args)
            return real_popen(args, **kw)
        with mock.patch.object(self.I.subprocess, "Popen", scoped):
            r, d = self.make_request("0000000000000bad")
            t0 = time.time()
            while not Path(d, "fake_runs").exists() or os.path.normpath(d) in self.I.live_ceremony_coordinators():
                self.assertLess(time.time() - t0, 30); time.sleep(0.1)
            os.environ["FAKE_ALLOC_MB"] = "8"
            r = self.drive(r["id"], lambda x: x["state"] == "presigned", t=60)
        self.assertIn("coordinator_restarted", [k for k, _ in self.alerts])


if __name__ == "__main__":
    unittest.main()
