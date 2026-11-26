# Copyright (c) 2025-2026 BEARTEC. All rights reserved. See LICENSE.
"""Rebalance inventory: our wallets first, then small capped AMM swaps.

AMM swaps are capped at amm_max_pool_frac of the input-side pool reserve
(default 2%). Amounts are raw integer units. Pure planning; no I/O.
"""
from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, ROUND_DOWN

from .inventory import Gap, WalletBal, above_target, total


@dataclass(frozen=True)
class Transfer:
    src: str
    dest: str
    asset: str
    amount: int
    reason: str


@dataclass(frozen=True)
class AmmSwap:
    token_in: str
    token_out: str
    amount_in: int
    max_in: int
    pool_id: str
    reason: str


def plan_wallet_transfers(
    bals: dict[str, WalletBal],
    gaps: list[Gap],
    *,
    fee_buffer_fpl: int = 2,
) -> list[Transfer]:
    """Move surplus from our wallets to ones below target, never going below the donor's target.

    FPL transfers leave fee_buffer_fpl on the donor. No treasury or external wallets.
    """
    plans: list[Transfer] = []
    remaining = {g.wallet: dict() for g in gaps}
    # working copy of balances
    have = {w: {**b.assets, "FPL": b.fpl} for w, b in bals.items()}

    shorts = [g for g in gaps if g.have < g.target]
    shorts.sort(key=lambda g: (g.asset, g.target - g.have), reverse=False)

    for short in shorts:
        need = short.target - have.get(short.wallet, {}).get(short.asset, short.have)
        if need <= 0:
            continue
        donors = above_target(gaps, short.asset)
        donors = sorted(donors, key=lambda g: g.have - g.target, reverse=True)
        for d in donors:
            if d.wallet == short.wallet:
                continue
            donor_have = have.get(d.wallet, {}).get(short.asset, 0)
            spare = donor_have - d.target
            if short.asset == "FPL":
                spare = max(0, spare - fee_buffer_fpl)
            if spare <= 0:
                continue
            amt = min(spare, need)
            if amt <= 0:
                continue
            have[d.wallet][short.asset] = donor_have - amt
            dest_have = have.setdefault(short.wallet, {}).get(short.asset, 0)
            have[short.wallet][short.asset] = dest_have + amt
            plans.append(Transfer(
                src=d.wallet,
                dest=short.wallet,
                asset=short.asset,
                amount=amt,
                reason=f"wallet rebalance {short.asset}",
            ))
            need -= amt
            if need <= 0:
                break
    return plans


def _pool_reserve(pools: list[dict], token_in: str, token_out: str) -> tuple[str, int]:
    """Return (pool_id, input-side reserve) for a direct FPL pool, else ('', 0)."""
    for p in pools:
        a, b = p.get("asset_a"), p.get("asset_b")
        ra, rb = int(p.get("reserve_a") or 0), int(p.get("reserve_b") or 0)
        pid = str(p.get("id") or f"{a}-{b}")
        if a == token_in and b == token_out:
            return pid, ra
        if b == token_in and a == token_out:
            return pid, rb
    return "", 0


def plan_amm_swaps(
    bals: dict[str, WalletBal],
    targets: dict[str, int],
    pools: list[dict],
    *,
    max_frac: Decimal = Decimal("0.02"),
    wallets: list[str] | None = None,
) -> list[AmmSwap]:
    """If we are short overall in one asset and long in another, swap through FPL.

    Each swap is capped at max_frac of the input-side reserve. Cross-asset
    (f-asset to f-asset) is two legs via FPL; each leg is capped separately.
    Only uses inventory that is above the summed per-wallet target.
    """
    if wallets is None:
        wallets = list(bals)
    scoped = {w: bals[w] for w in wallets if w in bals}
    if not scoped:
        return []

    # targets are per-wallet; overall target is target * n wallets that we have
    n = len(scoped)
    overall_target = {a: int(t) * n for a, t in targets.items() if int(t) > 0}
    # include FPL even if only implied
    if "FPL" not in overall_target:
        overall_target["FPL"] = 0

    long_assets = []
    short_assets = []
    for asset, tgt in overall_target.items():
        have = total(scoped, asset)
        if have > tgt and have - tgt > 0:
            long_assets.append((asset, have - tgt))
        elif have < tgt:
            short_assets.append((asset, tgt - have))
    if not long_assets or not short_assets:
        return []

    long_assets.sort(key=lambda x: x[1], reverse=True)
    short_assets.sort(key=lambda x: x[1], reverse=True)
    plans: list[AmmSwap] = []

    def cap(token_in: str, token_out: str, want: int) -> AmmSwap | None:
        if want <= 0:
            return None
        pid, reserve = _pool_reserve(pools, token_in, token_out)
        if reserve <= 0:
            return None
        max_in = int((Decimal(reserve) * max_frac).to_integral_value(rounding=ROUND_DOWN))
        if max_in <= 0:
            return None
        amt = min(want, max_in)
        if amt <= 0:
            return None
        return AmmSwap(
            token_in=token_in,
            token_out=token_out,
            amount_in=amt,
            max_in=max_in,
            pool_id=pid,
            reason=f"amm rebalance {token_in}->{token_out} cap {max_frac}*pool",
        )

    for src, spare in long_assets:
        for dest, need in short_assets:
            if src == dest or need <= 0:
                continue
            if src != "FPL" and dest != "FPL":
                # two legs: src -> FPL, then FPL -> dest. Only plan the first
                # leg here (the second needs the FPL proceeds). The service
                # can run a second pass after fills. Cap each independently.
                leg = cap(src, "FPL", spare)
            else:
                leg = cap(src, dest, min(spare, need) if src == "FPL" else spare)
            if leg:
                plans.append(leg)
                # only one swap per long asset per tick to stay small
                break
    return plans
