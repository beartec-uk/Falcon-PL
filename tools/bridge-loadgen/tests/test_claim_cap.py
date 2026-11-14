"""Unit tests for the peg-out cap: claims paid to the user count as settled.

Run: python3 -m unittest discover -s tools/bridge-loadgen/tests -v
"""
import json
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import falcon_pl_bridge_loadgen as L  # noqa: E402

ACCTS = {"loadtest01", "loadtest02", "loadtest03", "loadtest04"}


def status_body(claims, asset="BTC4"):
    return {"rails": [{"asset": asset, "bitvm2_claims": claims}]}


def claim(frm, status, n=0):
    return {"from": frm, "status": status, "dest": f"tb1q{n}", "amount": 54410, "note_id": f"n{n}"}


class ClaimInFlight(unittest.TestCase):
    def test_paid_states_are_settled(self):
        for st in ("claim_posted", "paid_optimistic", "paid", "challenged",
                   "disproved", "refunded", "failed", "CLAIM_POSTED"):
            self.assertFalse(L.claim_in_flight(st), st)

    def test_pre_payout_states_in_flight(self):
        for st in ("awaiting_pegout", "pegout_posted"):
            self.assertTrue(L.claim_in_flight(st), st)

    def test_unknown_state_fails_safe(self):
        self.assertTrue(L.claim_in_flight("something_new"))
        self.assertTrue(L.claim_in_flight(None))


class CountInFlight(unittest.TestCase):
    def test_batch2_regression_counts_zero(self):
        # 13-14 Nov: four batch-2 peg-outs + TC-1 all claim_posted (paid).
        b = status_body([claim(f"loadtest0{i}", "claim_posted", i) for i in (1, 2, 3, 4)]
                        + [claim("loadtest01", "claim_posted", 9)])
        self.assertEqual(L.count_in_flight_claims(b, ACCTS), 0)

    def test_mixed(self):
        b = status_body([
            claim("loadtest01", "awaiting_pegout", 1),
            claim("loadtest02", "pegout_posted", 2),
            claim("loadtest03", "claim_posted", 3),
            claim("loadtest04", "failed", 4),
            claim("someone-else", "awaiting_pegout", 5),
        ])
        self.assertEqual(L.count_in_flight_claims(b, ACCTS), 2)

    def test_other_assets_ignored(self):
        b = status_body([claim("loadtest01", "awaiting_pegout")], asset="BTC")
        self.assertEqual(L.count_in_flight_claims(b, ACCTS), 0)

    def test_unfinalized_claims_adds_pending_burns(self):
        b = {"body": status_body([claim("loadtest01", "claim_posted"),
                                  claim("loadtest02", "awaiting_pegout", 2)])}
        with mock.patch.object(L, "ctl", return_value="ok " + json.dumps(b)):
            self.assertEqual(L.unfinalized_claims(ACCTS), 1)
            L._pending_add("k1")
            try:
                self.assertEqual(L.unfinalized_claims(ACCTS), 2)
            finally:
                L._pending_discard("k1")
            self.assertEqual(L.unfinalized_claims(ACCTS), 1)


class PegOutPendingSlot(unittest.TestCase):
    def test_slot_held_until_claim_visible_then_released(self):
        seen = []
        polls = iter([
            status_body([]),  # burn not yet in a claim
            status_body([{"from": "loadtest01", "dest": "tb1qx", "amount": 100,
                          "status": "claim_posted", "note_id": "nn",
                          "pegout_txid_hex": "ab" * 32, "attest_height": 5}]),
        ])

        def fake_ctl(*args, timeout=60):
            if args[0] == "submit-rail-withdraw":
                seen.append(("submit", L.pending_burns()))
                return "tx=" + "cd" * 32
            body = next(polls)
            seen.append(("poll", L.pending_burns()))
            return json.dumps({"body": body})

        with mock.patch.object(L, "ctl", side_effect=fake_ctl), \
             mock.patch.object(L, "fpl_status_rail", return_value=(1, 2, "", None)), \
             mock.patch.object(L, "append_leg"), \
             mock.patch.object(L.time, "sleep"):
            rec = L.peg_out("loadtest01", 100, "tb1qx", Path("/nonexistent"), 600)
        self.assertEqual(rec["state"], "claim_posted")
        self.assertEqual(seen[0], ("submit", 1))  # slot reserved before burn
        self.assertEqual(seen[1], ("poll", 1))
        self.assertEqual(L.pending_burns(), 0)

    def test_slot_released_on_submit_error(self):
        with mock.patch.object(L, "ctl", side_effect=RuntimeError("boom")), \
             mock.patch.object(L, "fpl_status_rail", return_value=(1, 2, "", None)):
            with self.assertRaises(RuntimeError):
                L.peg_out("loadtest01", 100, "tb1qx", Path("/nonexistent"), 600)
        self.assertEqual(L.pending_burns(), 0)


if __name__ == "__main__":
    unittest.main()
