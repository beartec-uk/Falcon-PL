#!/usr/bin/env python3
"""Unit tests for intake mint-completion and kickoff release. No network or bitcoin."""
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent


def load_intake():
    tmp = tempfile.mkdtemp(prefix="fpl-intake-test-")
    os.environ["FPL_OP_HOME"] = tmp
    os.environ.pop("FPL_OPERATOR_SECRET_FILE", None)
    name = "fpl_bridge_intake"
    path = HERE / "fpl_bridge_intake.py"
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


intake = load_intake()

# Confirm txids that were already in BTC4 spent_deposits while intake still
# showed awaiting_mint and reserved their kickoffs (2026-11-08 leak).
CONSUMED = [
    "8638545d2e86dc0f072038f9e43664a6bceeddcc120c9948b293287a471e6a80",
    "7c87929898ce39493b936ad2d10fb59ffbb1df6df531297520acac0010d7baa9",
    "038c7fe2a9481a10569f9e6184254644fc208f170d0801ee503e68d56c6c6051",
    "c63e5c685328071fa426d23185f5539b7f855fa58a09e92e35f181e3c0cf6c83",
]


class SpentDepositParsing(unittest.TestCase):
    def test_parses_body_wrapped_status(self):
        status = {"body": {"rails": [
            {"asset": "ETH", "spent_deposits": ["nope"]},
            {"asset": "BTC4", "spent_deposits": ["ABC", "def"], "tip_height": 1},
        ]}}
        self.assertEqual(intake.spent_deposit_txids(status), {"abc", "def"})

    def test_parses_unwrapped_status(self):
        status = {"rails": [{"asset": "BTC4", "spent_deposits": [CONSUMED[0].upper()]}]}
        self.assertEqual(intake.spent_deposit_txids(status), {CONSUMED[0]})

    def test_empty_on_bad_input(self):
        self.assertEqual(intake.spent_deposit_txids(None), set())
        self.assertEqual(intake.spent_deposit_txids([]), set())
        self.assertEqual(intake.spent_deposit_txids({}), set())
        self.assertEqual(intake.spent_deposit_txids({"body": None}), set())
        self.assertEqual(intake.spent_deposit_txids({"body": {"rails": "x"}}), set())


class RequestMinted(unittest.TestCase):
    def test_matches_confirm_txid_case_insensitive(self):
        spent = {CONSUMED[0]}
        req = {"state": "awaiting_mint", "peg_in_confirm_txid": CONSUMED[0].upper()}
        self.assertTrue(intake.request_minted(req, spent))

    def test_false_without_confirm_or_match(self):
        spent = {CONSUMED[0]}
        self.assertFalse(intake.request_minted({"state": "awaiting_mint"}, spent))
        self.assertFalse(intake.request_minted(
            {"peg_in_confirm_txid": CONSUMED[1], "state": "awaiting_mint"}, spent))


class ReservedKickoffs(unittest.TestCase):
    def test_minted_and_terminal_states_release(self):
        reqs = [
            {"kickoff": "aa:0", "state": "awaiting_mint"},
            {"kickoff": "bb:0", "state": "minted"},
            {"kickoff": "cc:0", "state": "failed"},
            {"kickoff": "dd:0", "state": "expired"},
            {"kickoff": "ee:0", "state": "awaiting_signature"},
            {"kickoff": "ff:0", "state": "waiting_operator_liquidity"},
            {"state": "funded"},
        ]
        self.assertEqual(intake.reserved_kickoff_set(reqs), {"aa:0", "ee:0", "ff:0"})

    def test_consumed_proofs_release_after_mark_minted(self):
        status = {"body": {"rails": [{"asset": "BTC4", "spent_deposits": list(CONSUMED)}]}}
        spent = intake.spent_deposit_txids(status)
        reqs = [
            {"id": "211dedde278f0f1d", "state": "awaiting_mint",
             "peg_in_confirm_txid": CONSUMED[0], "kickoff": "ko0:0"},
            {"id": "5f9e60053e0e812e", "state": "awaiting_mint",
             "peg_in_confirm_txid": CONSUMED[1], "kickoff": "ko1:0"},
            {"id": "996712085d595ed3", "state": "awaiting_mint",
             "peg_in_confirm_txid": CONSUMED[2], "kickoff": "ko2:0"},
            {"id": "b5f05387a49c7eac", "state": "awaiting_mint",
             "peg_in_confirm_txid": CONSUMED[3], "kickoff": "ko3:0"},
            {"id": "live000000000001", "state": "awaiting_signature",
             "peg_in_confirm_txid": "aa" * 32, "kickoff": "still:0"},
        ]
        # Before reconciliation the four minted proofs still pin their kickoffs
        # (awaiting_mint stays reserved until spent_deposits is observed).
        self.assertEqual(
            intake.reserved_kickoff_set(reqs),
            {"ko0:0", "ko1:0", "ko2:0", "ko3:0", "still:0"},
        )
        for req in reqs:
            if intake.request_minted(req, spent):
                req["state"] = "minted"
        self.assertEqual(intake.reserved_kickoff_set(reqs), {"still:0"})
        self.assertEqual(sum(1 for r in reqs if r["state"] == "minted"), 4)


if __name__ == "__main__":
    unittest.main()
