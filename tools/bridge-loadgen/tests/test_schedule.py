"""Batch schedule persists across restarts (release list item 10).

Run: python3 -m unittest discover -s tools/bridge-loadgen/tests -v
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import falcon_pl_bridge_loadgen as L  # noqa: E402

W, G = 3600, 21600


class ResumePlan(unittest.TestCase):
    def test_no_state_starts_batch_zero_now(self):
        p = L.resume_plan(None, 100.0, W, G)
        self.assertEqual((p["bi"], p["phase"], p["batch_t0"], p["next_leg"]), (0, "batch", 100.0, 0))

    def test_garbled_state_starts_fresh(self):
        self.assertEqual(L.resume_plan({"phase": "gap"}, 5.0, W, G)["bi"], 0)
        self.assertEqual(L.resume_plan({"bi": "x"}, 5.0, W, G)["bi"], 0)

    def test_mid_batch_resumes_next_leg_same_offsets(self):
        st = {"bi": 1, "phase": "batch", "batch_t0": 1000.0, "offsets": [0, 170, 340, 510], "next_leg": 2}
        p = L.resume_plan(st, 1400.0, W, G)
        self.assertEqual((p["bi"], p["phase"], p["next_leg"], p["batch_t0"]), (1, "batch", 2, 1000.0))
        self.assertEqual(p["offsets"], [0, 170, 340, 510])

    def test_batch_window_passed_goes_to_gap_from_window_end(self):
        # 14 Nov: apt-daily-upgrade restart 06:35 GMT reset the schedule
        st = {"bi": 0, "phase": "batch", "batch_t0": 1000.0, "offsets": [0, 100], "next_leg": 1}
        p = L.resume_plan(st, 1000.0 + W + 10, W, G)
        self.assertEqual((p["bi"], p["phase"], p["gap_end"]), (0, "gap", 1000.0 + W + G))

    def test_all_legs_launched_goes_to_gap(self):
        st = {"bi": 0, "phase": "batch", "batch_t0": 1000.0, "offsets": [0, 100], "next_leg": 2}
        self.assertEqual(L.resume_plan(st, 1200.0, W, G)["phase"], "gap")

    def test_gap_keeps_original_end(self):
        st = {"bi": 2, "phase": "gap", "batch_t0": 0.0, "gap_end": 50_000.0}
        p = L.resume_plan(st, 30_000.0, W, G)
        self.assertEqual((p["bi"], p["phase"], p["gap_end"]), (2, "gap", 50_000.0))

    def test_gap_over_starts_next_batch(self):
        st = {"bi": 2, "phase": "gap", "batch_t0": 0.0, "gap_end": 50_000.0}
        p = L.resume_plan(st, 50_001.0, W, G)
        self.assertEqual((p["bi"], p["phase"], p["next_leg"]), (3, "batch", 0))

    def test_batch_size_alternates_from_resumed_index(self):
        # bi 3 -> sizes[1] (20): a restart must not flip A/B
        sizes = [10, 20]
        st = {"bi": 2, "phase": "gap", "batch_t0": 0.0, "gap_end": 10.0}
        self.assertEqual(sizes[L.resume_plan(st, 11.0, W, G)["bi"] % 2], 20)


class SaveLoad(unittest.TestCase):
    def test_round_trip_and_atomic(self):
        with tempfile.TemporaryDirectory() as d, mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("BATCH_SCHEDULE_FILE", None)
            home = Path(d)
            self.assertIsNone(L.load_schedule(home))
            st = {"bi": 1, "phase": "batch", "batch_t0": 1.5, "offsets": [0.0, 2.5], "next_leg": 1}
            L.save_schedule(home, st)
            self.assertEqual(L.load_schedule(home), st)
            self.assertFalse((home / "schedule.tmp").exists())
            (home / "schedule.json").write_text("{not json")
            self.assertIsNone(L.load_schedule(home))


if __name__ == "__main__":
    unittest.main()


class _Stop(Exception):
    pass


class CmdRunResume(unittest.TestCase):
    """cmd_run picks up a saved mid-batch schedule: legs already launched are
    not relaunched, and the gap is persisted before waiting."""

    def test_resume_launches_only_remaining_legs(self):
        import time as _t
        with tempfile.TemporaryDirectory() as d:
            home = Path(d)
            now = _t.time()
            env = {"BATCH_SCHEDULE_FILE": str(home / "schedule.json"), "PAUSE_FILE": str(home / "PAUSE"),
                   "LOADGEN_WALLETS": "4", "BATCH_WINDOW_SECS": "3600", "BATCH_GAP_SECS": "21600",
                   "BRIDGE_RECORD_DIR": str(home / "rec"), "LOADGEN_KEYS": str(home / "keys")}
            L.save_schedule(home, {"bi": 1, "phase": "batch", "batch_t0": now - 60,
                                   "offsets": [0, 1, 2, 3, 4], "next_leg": 3})
            started = []

            class FakeThread:
                def __init__(self, target=None, name=None, daemon=None):
                    self.name = name

                def start(self):
                    started.append(self.name)

            def fake_sleep(secs):
                st = L.load_schedule(home)
                if st and st.get("phase") == "gap":
                    raise _Stop()

            class FakeWatch:
                def tick(self):
                    return 0

            with mock.patch.dict(os.environ, env), \
                 mock.patch.object(L, "ensure_fpl_wallet"), mock.patch.object(L, "ensure_key_bound"), \
                 mock.patch.object(L, "account", return_value={"balance": 99999, "assets": {}}), \
                 mock.patch.object(L, "unfinalized_claims", return_value=0), \
                 mock.patch.object(L, "spend_today", return_value=0), \
                 mock.patch.object(L, "RailWatch", FakeWatch), \
                 mock.patch.object(L.threading, "Thread", FakeThread), \
                 mock.patch.object(L.time, "sleep", side_effect=fake_sleep), \
                 mock.patch("sys.stdout"):
                with self.assertRaises(_Stop):
                    L.cmd_run(home)
            self.assertEqual(started, ["leg-2-4", "leg-2-5"])
            st = L.load_schedule(home)
            self.assertEqual((st["bi"], st["phase"]), (1, "gap"))
            self.assertGreater(st["gap_end"], now + 21000)
