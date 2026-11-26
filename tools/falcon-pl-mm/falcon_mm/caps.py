# Copyright (c) 2025-2026 BEARTEC. All rights reserved. See LICENSE.
"""Per-pair pause and daily caps (Europe/London calendar day)."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

LONDON = ZoneInfo("Europe/London")


def london_day(ts: float | None = None) -> str:
    if ts is None:
        dt = datetime.now(tz=LONDON)
    else:
        dt = datetime.fromtimestamp(ts, tz=timezone.utc).astimezone(LONDON)
    return dt.date().isoformat()


@dataclass
class DailyCaps:
    """In-memory usage, persisted by the service via to_dict/from_dict."""
    used: dict[str, dict] = field(default_factory=dict)

    def _bucket(self, pair: str, now: float | None = None) -> dict:
        day = london_day(now)
        b = self.used.get(pair)
        if not b or b.get("day") != day:
            b = {"day": day, "base": 0, "fpl": 0}
            self.used[pair] = b
        return b

    def allow(self, pair: str, *, cap_base: int, cap_fpl: int, add_base: int = 0, add_fpl: int = 0, now: float | None = None) -> bool:
        b = self._bucket(pair, now)
        if cap_base > 0 and b["base"] + add_base > cap_base:
            return False
        if cap_fpl > 0 and b["fpl"] + add_fpl > cap_fpl:
            return False
        return True

    def record(self, pair: str, *, add_base: int = 0, add_fpl: int = 0, now: float | None = None) -> None:
        b = self._bucket(pair, now)
        b["base"] += int(add_base)
        b["fpl"] += int(add_fpl)

    def to_dict(self) -> dict:
        return {"used": self.used}

    @classmethod
    def from_dict(cls, raw: dict | None) -> "DailyCaps":
        obj = cls()
        if raw and isinstance(raw.get("used"), dict):
            obj.used = raw["used"]
        return obj
