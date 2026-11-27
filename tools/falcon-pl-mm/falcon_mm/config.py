# Copyright (c) 2025-2026 BEARTEC. All rights reserved. See LICENSE.
"""Load falcon-mm config. Never logs secrets or key material."""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any


DEFAULT_DECIMALS = {"USDC": 6, "BTC4": 8, "ETH": 18, "FPL": 0}
SECRET_KEYS = frozenset({
    "FALCON_CLOUD_API_KEY",
    "cloud_api_key",
    "DISCORD_WEBHOOK_URL",
    "FPL_DISCORD_WEBHOOK_URL",
    "DISCORD_HEALTH_WEBHOOK_URL",
})


def _s(v: Any, default: str = "") -> str:
    return str(v).strip() if v is not None else default


@dataclass
class PairConfig:
    pair: str
    base_asset: str
    base_decimals: int
    enabled: bool = True
    paused: bool = False
    pause_file: str = ""
    # Kill switch: while this file exists, cancel every open order on the pair and place nothing.
    cancel_all_file: str = ""
    maker_wallets: list[str] = field(default_factory=list)
    taker_wallets: list[str] = field(default_factory=list)
    inventory_targets: dict[str, int] = field(default_factory=dict)
    daily_cap_base: int = 0
    daily_cap_fpl: int = 0
    band_lo: str = "0"
    band_hi: str = "0"
    period_s: str = "21600"
    levels: str = "2"
    spacing_bps: str = "25"
    quote_min_fpl: str = "500"
    quote_max_fpl: str = "1000"
    bias: str = "0.5"
    cross_bps: str = "15"
    fee_buffer_fpl: str = "50"
    fee_reserve_fpl: str = "50"
    expiry_blocks: str = "40"
    tick_s: str = "20"
    interval_s: str = "15"

    def all_wallets(self) -> list[str]:
        out, seen = [], set()
        for w in self.maker_wallets + self.taker_wallets:
            if w and w not in seen:
                out.append(w)
                seen.add(w)
        return out

    def base_raw(self) -> int:
        return 10 ** self.base_decimals

    def is_paused(self) -> bool:
        if self.paused:
            return True
        return bool(self.pause_file and os.path.exists(self.pause_file))

    def cancel_all_requested(self, global_file: str = "") -> bool:
        return any(p and os.path.exists(p) for p in (self.cancel_all_file, global_file))


@dataclass
class MmConfig:
    mode: str  # shadow | dry-run | live
    pairs: dict[str, PairConfig]
    treasury_wallets: list[str] = field(default_factory=list)
    amm_max_pool_frac: Decimal = Decimal("0.02")
    rebalance_enabled: bool = True
    wallet_transfer_first: bool = True
    state_dir: str = "/var/lib/falcon-mm"
    health_file: str = "/var/lib/falcon-mm/health.json"
    state_file: str = "/var/lib/falcon-mm/state.json"
    discord_env_file: str = ""
    ctl: str = "falcon-pl-ctl"
    rpc_addr: str = "127.0.0.1:19313"
    keys_dir: str = ""
    scheme: str = "falcon"
    network_id: str = "2300"
    cloud_rpc_url: str = "https://rpc.falcon-fpl.com/v1/rpc"
    cloud_api_key_file: str = ""
    read_source: str = "cloud"
    # Kill switch for every pair (see PairConfig.cancel_all_file).
    cancel_all_file: str = ""
    tick_s: float = 20.0
    alert_min_interval_s: int = 900

    @property
    def dry_writes(self) -> bool:
        return self.mode in ("shadow", "dry-run")


def _int(v: Any, default: int = 0) -> int:
    if v is None or v == "":
        return default
    return int(str(v).strip())


def _pair(name: str, raw: dict[str, Any]) -> PairConfig:
    base = _s(raw.get("base_asset")) or name.split("-")[0].strip()
    dec = raw.get("base_decimals")
    if dec is None or dec == "":
        dec = DEFAULT_DECIMALS.get(base.upper())
        if dec is None:
            raise ValueError(f"Set base_decimals for pair {name}")
    targets = {}
    for k, v in (raw.get("inventory_targets") or {}).items():
        targets[str(k).strip()] = _int(v, 0)
    return PairConfig(
        pair=name,
        base_asset=base,
        base_decimals=int(dec),
        enabled=str(raw.get("enabled", True)).lower() not in ("0", "false", "no"),
        paused=str(raw.get("paused", False)).lower() in ("1", "true", "yes"),
        pause_file=_s(raw.get("pause_file")),
        cancel_all_file=_s(raw.get("cancel_all_file")),
        maker_wallets=[w.strip() for w in (raw.get("maker_wallets") or []) if str(w).strip()],
        taker_wallets=[w.strip() for w in (raw.get("taker_wallets") or []) if str(w).strip()],
        inventory_targets=targets,
        daily_cap_base=_int(raw.get("daily_cap_base"), 0),
        daily_cap_fpl=_int(raw.get("daily_cap_fpl"), 0),
        band_lo=_s(raw.get("band_lo"), "0"),
        band_hi=_s(raw.get("band_hi"), "0"),
        period_s=_s(raw.get("period_s"), "21600"),
        levels=_s(raw.get("levels"), "2"),
        spacing_bps=_s(raw.get("spacing_bps"), "25"),
        quote_min_fpl=_s(raw.get("quote_min_fpl"), "500"),
        quote_max_fpl=_s(raw.get("quote_max_fpl"), "1000"),
        bias=_s(raw.get("bias"), "0.5"),
        cross_bps=_s(raw.get("cross_bps"), "15"),
        fee_buffer_fpl=_s(raw.get("fee_buffer_fpl"), "50"),
        fee_reserve_fpl=_s(raw.get("fee_reserve_fpl"), "50"),
        expiry_blocks=_s(raw.get("expiry_blocks"), "40"),
        tick_s=_s(raw.get("tick_s"), "20"),
        interval_s=_s(raw.get("interval_s"), "15"),
    )


def load_config(path: str) -> MmConfig:
    with open(path) as f:
        raw = json.load(f)
    mode = _s(raw.get("mode"), "shadow").lower()
    if mode not in ("shadow", "dry-run", "live"):
        raise ValueError(f"mode must be shadow, dry-run, or live (got {mode!r})")
    pairs = {}
    for name, p in (raw.get("pairs") or {}).items():
        pairs[name] = _pair(name, p or {})
    frac = Decimal(str(raw.get("amm_max_pool_frac", "0.02")))
    if frac <= 0 or frac > 1:
        raise ValueError("amm_max_pool_frac must be in (0, 1]")
    return MmConfig(
        mode=mode,
        pairs=pairs,
        treasury_wallets=[w.strip() for w in (raw.get("treasury_wallets") or []) if str(w).strip()],
        amm_max_pool_frac=frac,
        rebalance_enabled=str(raw.get("rebalance_enabled", True)).lower() not in ("0", "false", "no"),
        wallet_transfer_first=str(raw.get("wallet_transfer_first", True)).lower() not in ("0", "false", "no"),
        state_dir=_s(raw.get("state_dir"), "/var/lib/falcon-mm"),
        health_file=_s(raw.get("health_file"), "/var/lib/falcon-mm/health.json"),
        state_file=_s(raw.get("state_file"), "/var/lib/falcon-mm/state.json"),
        discord_env_file=_s(raw.get("discord_env_file")),
        ctl=_s(raw.get("ctl"), "falcon-pl-ctl"),
        rpc_addr=_s(raw.get("rpc_addr"), "127.0.0.1:19313"),
        keys_dir=_s(raw.get("keys_dir")),
        scheme=_s(raw.get("scheme"), "falcon"),
        network_id=_s(raw.get("network_id"), "2300"),
        cloud_rpc_url=_s(raw.get("cloud_rpc_url"), "https://rpc.falcon-fpl.com/v1/rpc"),
        cloud_api_key_file=_s(raw.get("cloud_api_key_file")),
        read_source=_s(raw.get("read_source"), "cloud"),
        cancel_all_file=_s(raw.get("cancel_all_file")),
        tick_s=float(raw.get("tick_s", 20)),
        alert_min_interval_s=int(raw.get("alert_min_interval_s", 900)),
    )


def pair_to_mm_env(cfg: MmConfig, pair: PairConfig) -> dict[str, str]:
    """Legacy mm.py / mmtaker.py env dict (no secrets)."""
    wallets = pair.all_wallets()
    return {
        "PAIR": pair.pair,
        "BASE_ASSET": pair.base_asset,
        "BASE_DECIMALS": str(pair.base_decimals),
        "FPL_RAW_PER_FPL": "1",
        "WALLETS": ",".join(wallets),
        "LEVELS": pair.levels,
        "SPACING_BPS": pair.spacing_bps,
        "QUOTE_MIN_FPL": pair.quote_min_fpl,
        "QUOTE_MAX_FPL": pair.quote_max_fpl,
        "BAND_LO": pair.band_lo,
        "BAND_HI": pair.band_hi,
        "PERIOD_S": pair.period_s,
        "BIAS": pair.bias,
        "CROSS_BPS": pair.cross_bps,
        "FEE_BUFFER_FPL": pair.fee_buffer_fpl,
        "FEE_RESERVE_FPL": pair.fee_reserve_fpl,
        "ORDER_EXPIRY_BLOCKS": pair.expiry_blocks,
        "EXPIRY_BLOCKS": pair.expiry_blocks,
        "TICK_S": pair.tick_s,
        "INTERVAL_S": pair.interval_s,
        "CTL": cfg.ctl,
        "RPC_ADDR": cfg.rpc_addr,
        "SCHEME": cfg.scheme,
        "KEYS_DIR": cfg.keys_dir,
        "NETWORK_ID": cfg.network_id,
        "FALCON_CLOUD_RPC_URL": cfg.cloud_rpc_url,
        "FALCON_CLOUD_API_KEY_FILE": cfg.cloud_api_key_file,
        "READ_SOURCE": cfg.read_source,
        "DRY_RUN": "0" if cfg.mode == "live" else "1",
        "TAKER_ENABLED": "1",
        "TAKER_PAUSE": pair.pause_file or "/nonexistent",
        "MM_PAUSE": pair.pause_file or "/nonexistent",
    }


def public_summary(cfg: MmConfig) -> dict[str, Any]:
    """Safe to log or alert: no paths that might hold secrets, no keys."""
    return {
        "mode": cfg.mode,
        "pairs": {
            n: {
                "enabled": p.enabled,
                "paused": p.is_paused(),
                "base_asset": p.base_asset,
                "makers": p.maker_wallets,
                "takers": p.taker_wallets,
            }
            for n, p in cfg.pairs.items()
        },
        "rebalance_enabled": cfg.rebalance_enabled,
        "amm_max_pool_frac": str(cfg.amm_max_pool_frac),
    }
