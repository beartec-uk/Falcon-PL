# Copyright (c) 2025-2026 BEARTEC. All rights reserved. See LICENSE.
"""Inventory snapshots and target comparisons. Amounts are raw integer units."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class WalletBal:
    wallet: str
    fpl: int
    assets: dict[str, int] = field(default_factory=dict)

    def get(self, asset: str) -> int:
        if asset == "FPL":
            return self.fpl
        return int(self.assets.get(asset, 0))


@dataclass
class Gap:
    asset: str
    wallet: str
    have: int
    target: int

    @property
    def delta(self) -> int:
        return self.have - self.target


def snapshot(rows: list[WalletBal]) -> dict[str, WalletBal]:
    return {r.wallet: r for r in rows}


def total(rows: dict[str, WalletBal], asset: str) -> int:
    return sum(r.get(asset) for r in rows.values())


def gaps_for_pair(
    bals: dict[str, WalletBal],
    wallets: list[str],
    targets: dict[str, int],
) -> list[Gap]:
    """Per-wallet gaps against per-wallet targets (same target for each listed wallet)."""
    out = []
    for w in wallets:
        b = bals.get(w)
        if b is None:
            continue
        for asset, tgt in targets.items():
            if tgt <= 0:
                continue
            out.append(Gap(asset=asset, wallet=w, have=b.get(asset), target=int(tgt)))
    return out


def below_target(gaps: list[Gap]) -> list[Gap]:
    return [g for g in gaps if g.have < g.target]


def above_target(gaps: list[Gap], asset: str) -> list[Gap]:
    return [g for g in gaps if g.asset == asset and g.have > g.target]
