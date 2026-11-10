#!/usr/bin/env python3
"""Regression for the live 2026-11-05 timeouts scenario stall.

After PegOutConfirm (and/or KickOff1) spends the kickoff connector,
broadcast_kick_off_timeout fails with bitcoind -25 inputs-missingorspent.
The coordinator must treat that as a terminal skip, not retry forever.
"""
from pathlib import Path

LIVE = (
    "waiting: KICK_OFF_TIMEOUT: Esplora(HttpResponse { status: 400, message: "
    '"sendrawtransaction RPC error: {\\"code\\":-25,\\"message\\":\\"bad-txns-inputs-missingorspent\\"}" })'
)


def is_spent_input(e: str) -> bool:
    return "inputs-missingorspent" in e or "bad-txns-inputs-missingorspent" in e


def main() -> None:
    assert is_spent_input(LIVE), LIVE
    assert is_spent_input('bad-txns-inputs-missingorspent')
    assert not is_spent_input("non-BIP68-final")
    assert not is_spent_input("already in block chain")
    patch = Path(__file__).resolve().parents[1] / "patches/bitvm-7d1ca36-local-regtest.patch"
    text = patch.read_text()
    assert "fn is_spent_input" in text
    assert "KICK_OFF_TIMEOUT skipped: kickoff input already spent" in text
    # both run_scenario and resume paths
    assert text.count("KICK_OFF_TIMEOUT skipped: kickoff input already spent") == 2
    print("ok")


if __name__ == "__main__":
    main()
