# Copyright (c) 2025-2026 BEARTEC. All rights reserved. See LICENSE.
"""#node-alerts posts. The webhook URL is never logged or included in exceptions."""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request


DISCORD_LIMIT = 1900
ALERT_UA = "falcon-mm"


def _webhook_url(env_file: str = "") -> str:
    u = os.environ.get("FPL_DISCORD_WEBHOOK_URL") or os.environ.get("DISCORD_HEALTH_WEBHOOK_URL") or ""
    path = env_file or os.environ.get("FPL_DISCORD_ENV_FILE") or ""
    if not u and path and os.path.isfile(path):
        with open(path) as fh:
            for line in fh:
                k, _, v = line.strip().partition("=")
                key = k.strip().removeprefix("export ")
                if key in ("FPL_DISCORD_WEBHOOK_URL", "DISCORD_HEALTH_WEBHOOK_URL") and v:
                    u = v.strip().strip('"').strip("'")
                    break
    return u


def post_alert(text: str, *, env_file: str = "", sleep=time.sleep) -> bool:
    """POST content to the health webhook. Returns True if delivered or no webhook is set."""
    u = _webhook_url(env_file)
    if not u:
        return True
    body = json.dumps({"content": text[:DISCORD_LIMIT]}).encode()
    req = urllib.request.Request(
        u,
        data=body,
        method="POST",
        headers={"Content-Type": "application/json", "User-Agent": ALERT_UA},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            resp.read()
        return True
    except urllib.error.HTTPError as e:
        if e.code == 429:
            try:
                ra = float((e.headers or {}).get("Retry-After") or 1)
            except (TypeError, ValueError):
                ra = 1.0
            sleep(min(max(ra, 0.1), 60))
            try:
                with urllib.request.urlopen(req, timeout=10) as resp:
                    resp.read()
                return True
            except Exception:
                return False
        return False
    except Exception:
        return False


class AlertGate:
    """Debounce alerts by key."""

    def __init__(self, min_interval_s: int = 900):
        self.min_interval_s = min_interval_s
        self._last: dict[str, float] = {}

    def allow(self, key: str, now: float | None = None) -> bool:
        t = time.time() if now is None else now
        prev = self._last.get(key, 0)
        if t - prev < self.min_interval_s:
            return False
        self._last[key] = t
        return True

    def to_dict(self) -> dict:
        return {"last": self._last}

    @classmethod
    def from_dict(cls, raw: dict | None, min_interval_s: int = 900) -> "AlertGate":
        g = cls(min_interval_s)
        if raw and isinstance(raw.get("last"), dict):
            g._last = {str(k): float(v) for k, v in raw["last"].items()}
        return g
