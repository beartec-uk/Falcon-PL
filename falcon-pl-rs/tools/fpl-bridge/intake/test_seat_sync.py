#!/usr/bin/env python3
"""seat_sync.py (co-signer seats): spawn once, never respawn after a key was announced,
stop participants when the lead drops a request (including orphans from an earlier
seat_sync process), one bad request does not block the rest. No network, fake /proc.

Run: python3 test_seat_sync.py -v
"""
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent


def load(home, proc):
    os.environ.update(FPL_OP_HOME=home, FPL_PROC=proc, FPL_SEAT_ID="falcon2",
                      FPL_LEAD_SEAT_URL="http://lead:8791", FPL_EX="/opt/fpl-operator/bin")
    spec = importlib.util.spec_from_file_location("seat_sync_t", HERE / "seat_sync.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


class FakePopen:
    n = 1000

    def __init__(self, args, **kw):
        FakePopen.n += 1
        self.pid, self.args, self.alive, self.terminated = FakePopen.n, args, True, False

    def poll(self):
        return None if self.alive else 0

    def terminate(self):
        self.terminated, self.alive = True, False

    def wait(self, timeout=None):
        return 0

    def kill(self):
        self.alive = False


class SeatSync(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.home, self.proc = os.path.join(self.tmp, "h"), os.path.join(self.tmp, "proc")
        os.makedirs(self.proc)
        self.S = load(self.home, self.proc)
        self.files = {}      # rid -> [[rel, size]]
        self.blobs = {}
        self.live = []
        self.puts = []
        self.patches = [
            mock.patch.object(self.S, "get", self.fake_get),
            mock.patch.object(self.S, "put", lambda p, b: self.puts.append(p)),
            mock.patch.object(self.S.subprocess, "Popen", FakePopen),
            mock.patch.object(self.S, "log"),
        ]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()

    def fake_get(self, p):
        if p == "/seat/requests":
            return json.dumps(self.live).encode()
        if p.endswith("/files"):
            rid = p.split("/")[2]
            if rid == "bad":
                raise OSError("lead 500")
            return json.dumps(self.files.get(rid, [])).encode()
        return self.blobs[p]

    def fake_proc(self, pid, args):
        d = os.path.join(self.proc, str(pid))
        os.makedirs(d)
        Path(d, "cmdline").write_bytes(b"\0".join(a.encode() for a in args) + b"\0")

    def part_args(self, rid, seat="falcon2"):
        return ["/opt/fpl-operator/bin/fpl_ceremony_participant", "--dir",
                os.path.join(self.home, "graphs", "req-" + rid), "--id", seat, "--timeout-secs", "86400"]

    def test_spawns_once_and_uploads_own_files(self):
        self.live = ["r1"]
        self.files["r1"] = [["request.json", 2]]
        self.blobs["/seat/r1/file/request.json"] = b"{}"
        self.S.tick()
        self.assertIn("r1", self.S.procs)
        self.S.tick()
        self.assertEqual(len(self.S.procs), 1)
        d = os.path.join(self.home, "graphs", "req-r1")
        self.assertEqual(Path(d, "request.json").read_bytes(), b"{}")
        os.makedirs(os.path.join(d, "pub"))
        Path(d, "pub", "falcon2.json").write_text("{}")
        self.S.tick()
        self.assertEqual(self.puts, ["/seat/r1/file/pub/falcon2.json"])
        self.S.tick()
        self.assertEqual(len(self.puts), 1, "uploaded once")

    def test_no_respawn_after_restart_when_key_announced(self):
        d = os.path.join(self.home, "graphs", "req-r2", "pub")
        os.makedirs(d)
        Path(d, "falcon2.json").write_text("{}")
        self.live = ["r2"]
        self.S.tick()
        self.assertNotIn("r2", self.S.procs)

    def test_no_second_participant_if_one_is_still_running(self):
        self.fake_proc(4242, self.part_args("r3"))
        self.live = ["r3"]
        self.S.tick()
        self.assertNotIn("r3", self.S.procs)

    def test_stops_own_participant_when_request_dropped(self):
        self.live = ["r4"]
        self.S.tick()
        p = self.S.procs["r4"]
        self.live = []
        self.S.tick()
        self.assertTrue(p.terminated)
        self.assertNotIn("r4", self.S.procs)

    def test_stops_orphan_from_earlier_process_only_for_our_seat(self):
        self.fake_proc(5001, self.part_args("old"))
        self.fake_proc(5002, self.part_args("old", seat="beartec-brain"))
        self.fake_proc(5003, self.part_args("keep"))
        self.fake_proc(5004, ["/usr/bin/python3", "x.py", "--dir", "y"])
        stopped = []
        self.S.reap({"keep"}, stop_pid=stopped.append)
        self.assertEqual(stopped, [5001])

    def test_bad_request_does_not_block_others(self):
        self.live = ["bad", "r5"]
        self.S.tick()
        self.assertIn("r5", self.S.procs)

    def test_participant_pids_ignores_other_graph_roots(self):
        args = self.part_args("zz")
        args[2] = "/elsewhere/graphs/req-zz"
        self.fake_proc(6001, args)
        self.assertEqual(self.S.participant_pids(), {})

    def test_stop_pid_escalates(self):
        sent = []

        def kill(pid, sig):
            sent.append(sig)
        self.S._stop_pid(7, kill=kill, sleep=lambda s: None)
        self.assertEqual(sent[0], self.S.signal.SIGTERM)
        self.assertEqual(sent[-1], self.S.signal.SIGKILL)


if __name__ == "__main__":
    unittest.main()
