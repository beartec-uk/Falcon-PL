#!/usr/bin/env python3
"""Optional Discord alerts for the bridge daemons (ETH relayer, BTC watch).

Same delivery rules as the node alerts on falcon-fpl.com
(Falcon-faucet-wallet src/lib/network-health*.ts, docs/NETWORK-HEALTH.md):

- The webhook URL is read once, at start, from the same env var the node
  alerts use: DISCORD_HEALTH_WEBHOOK_URL. If it is unset or empty, every call
  here is a no-op: nothing is posted and no state file is written.
- Each problem (a key, e.g. "eth:v3:<deposit_id>") posts once. While it stays
  active nothing more is posted. When it clears, one recovery note is posted.
- A failed post is retried on the next flush; the alert stays un-notified.
- Mentions are disabled (allowed_mentions.parse = []).
- Messages carry up to 10 embeds (Discord's limit), so many problems at once
  are batched. At most MAX_MESSAGES_PER_FLUSH messages go out per flush, at
  least MIN_POST_GAP_SEC apart; the rest wait for the next flush. A 429
  pauses posting for the retry_after Discord returns.
- State (which keys were posted) is saved atomically to a small JSON file
  after every change, so a restart does not post again.

The webhook value is never printed or logged. Errors log only the HTTP status
or the exception class.
"""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Callable

WEBHOOK_ENV = "DISCORD_HEALTH_WEBHOOK_URL"
USERNAME = "Falcon Health Bot"
EMBEDS_PER_MESSAGE = 10
MAX_MESSAGES_PER_FLUSH = 3
MIN_POST_GAP_SEC = 2.0
# A key that never clears (e.g. a deposit that aged out of the scan) is
# dropped from the state file after this long, with no recovery post.
FORGET_AFTER_SEC = 14 * 86400
COLORS = {"critical": 0xF87171, "warning": 0xFACC15, "ok": 0x4ADE80, "test": 0x60A5FA}

# post(url, payload) -> (ok, retry_after_sec or None)
PostFn = Callable[[str, dict], "tuple[bool, float | None]"]


def _log(msg: str) -> None:
    print(msg, flush=True)


def webhook_from_env(env: dict | None = None) -> str | None:
    env = os.environ if env is None else env
    raw = str(env.get(WEBHOOK_ENV) or "").strip()
    if not raw:
        return None
    if not raw.startswith("https://"):
        _log(f"WARN {WEBHOOK_ENV} is set but is not an https URL; Discord alerts off")
        return None
    return raw


def http_post(url: str, payload: dict, timeout: float = 5.0) -> "tuple[bool, float | None]":
    """POST JSON. Never includes the URL in a log line or exception text."""
    body = json.dumps(payload).encode()
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={"content-type": "application/json", "user-agent": "falcon-pl-alerts/1"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return 200 <= r.status < 300, None
    except urllib.error.HTTPError as e:
        retry = None
        if e.code == 429:
            try:
                retry = float(json.loads(e.read() or b"{}").get("retry_after") or 5)
            except (ValueError, TypeError, json.JSONDecodeError):
                retry = 5.0
        _log(f"WARN discord post failed: HTTP {e.code}")
        return False, retry
    except Exception as e:  # noqa: BLE001 - never leak the URL via str(e)
        _log(f"WARN discord post failed: {type(e).__name__}")
        return False, None


class DiscordAlerts:
    """Once-per-problem Discord alerts with persisted dedupe state."""

    def __init__(
        self,
        state_path: str | os.PathLike,
        *,
        webhook: str | None = ...,  # type: ignore[assignment]
        source: str = "",
        post: PostFn | None = None,
        clock: Callable[[], float] = time.time,
        sleep: Callable[[float], None] = time.sleep,
        min_gap_sec: float = MIN_POST_GAP_SEC,
        max_messages: int = MAX_MESSAGES_PER_FLUSH,
    ) -> None:
        self.webhook = webhook_from_env() if webhook is ... else (webhook or None)
        self.state_path = Path(state_path)
        self.source = source
        self._post = post or http_post
        self._clock = clock
        self._sleep = sleep
        self.min_gap_sec = min_gap_sec
        self.max_messages = max_messages
        self._last_post = 0.0
        self._paused_until = 0.0
        self.state = {"alerts": {}, "recoveries": []}
        if self.enabled:
            self._load()

    @property
    def enabled(self) -> bool:
        return bool(self.webhook)

    # ---- state -------------------------------------------------------------
    def _load(self) -> None:
        try:
            raw = json.loads(self.state_path.read_text())
        except (OSError, ValueError):
            return
        if isinstance(raw, dict):
            alerts = raw.get("alerts") if isinstance(raw.get("alerts"), dict) else {}
            recs = raw.get("recoveries") if isinstance(raw.get("recoveries"), list) else []
            self.state = {"alerts": alerts, "recoveries": recs}

    def _save(self) -> None:
        try:
            self.state_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.state_path.with_name(self.state_path.name + ".tmp")
            tmp.write_text(json.dumps(self.state, indent=1, sort_keys=True))
            os.replace(tmp, self.state_path)
        except OSError as e:
            _log(f"WARN discord state save {self.state_path}: {type(e).__name__}")

    # ---- problem tracking ----------------------------------------------------
    def is_active(self, key: str) -> bool:
        return key in self.state["alerts"]

    def active_keys(self, prefix: str = "") -> list[str]:
        return sorted(k for k in self.state["alerts"] if k.startswith(prefix))

    def fire(self, key: str, title: str, detail: str, severity: str = "critical") -> bool:
        """Mark a problem active. Returns True if it is new (will be posted)."""
        if not self.enabled:
            return False
        if key in self.state["alerts"]:
            return False
        self.state["alerts"][key] = {
            "title": title,
            "detail": detail,
            "severity": severity if severity in COLORS else "critical",
            "since": self._clock(),
            "notified": False,
        }
        self._save()
        return True

    def resolve(self, key: str, detail: str = "") -> bool:
        """Clear a problem. Queues one recovery note if its alert was posted."""
        if not self.enabled:
            return False
        a = self.state["alerts"].pop(key, None)
        if a is None:
            return False
        if a.get("notified"):
            self.state["recoveries"].append(
                {"key": key, "title": a.get("title", key), "detail": detail or a.get("detail", ""), "since": a.get("since", 0)}
            )
        self._save()
        return bool(a.get("notified"))

    def forget_stale(self, now: float | None = None) -> None:
        now = self._clock() if now is None else now
        old = [k for k, a in self.state["alerts"].items() if now - float(a.get("since") or now) > FORGET_AFTER_SEC]
        for k in old:
            del self.state["alerts"][k]
        if old:
            self._save()

    # ---- delivery ------------------------------------------------------------
    def _embeds(self, now: float) -> list[tuple[str, str | None, dict]]:
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))
        tag = f" [{self.source}]" if self.source else ""
        out: list[tuple[str, str | None, dict]] = []
        for k, a in sorted(self.state["alerts"].items(), key=lambda kv: kv[1].get("since", 0)):
            if a.get("notified"):
                continue
            icon = "🔴" if a.get("severity") == "critical" else "⚠️"
            out.append(("fire", k, {
                "title": f"{icon} {a.get('title')}{tag}"[:256],
                "description": str(a.get("detail", ""))[:4000],
                "color": COLORS.get(a.get("severity"), COLORS["critical"]),
                "timestamp": ts,
            }))
        for r in self.state["recoveries"]:
            mins = max(1, round((now - float(r.get("since") or now)) / 60))
            out.append(("recover", r.get("key"), {
                "title": f"✅ Recovered: {r.get('title')}{tag}"[:256],
                "description": f"{r.get('detail', '')} — cleared after {mins} min"[:4000],
                "color": COLORS["ok"],
                "timestamp": ts,
            }))
        return out

    def _send(self, payload: dict) -> bool:
        now = self._clock()
        if now < self._paused_until:
            return False
        gap = self.min_gap_sec - (now - self._last_post)
        if self._last_post and gap > 0:
            self._sleep(gap)
        body = dict(payload)
        body.setdefault("username", USERNAME)
        body["allowed_mentions"] = {"parse": []}
        ok, retry = self._post(self.webhook or "", body)
        self._last_post = self._clock()
        if retry:
            self._paused_until = self._last_post + float(retry)
        return ok

    def flush(self) -> int:
        """Post pending alerts and recoveries. Returns messages delivered."""
        if not self.enabled:
            return 0
        now = self._clock()
        items = self._embeds(now)
        sent = 0
        for i in range(0, len(items), EMBEDS_PER_MESSAGE):
            if sent >= self.max_messages:
                break
            chunk = items[i : i + EMBEDS_PER_MESSAGE]
            if not self._send({"embeds": [e for _, _, e in chunk]}):
                break
            sent += 1
            done_recoveries = 0
            for kind, key, _ in chunk:
                if kind == "fire" and key in self.state["alerts"]:
                    self.state["alerts"][key]["notified"] = True
                elif kind == "recover":
                    done_recoveries += 1
            self.state["recoveries"] = self.state["recoveries"][done_recoveries:]
            self._save()
        return sent

    def send_test(self, label: str, detail: str = "") -> bool:
        """One clearly labelled test message. Touches no alert state."""
        if not self.enabled:
            _log(f"discord test: {WEBHOOK_ENV} not set; nothing sent")
            return False
        ok = self._send({
            "content": label,
            "embeds": [{
                "title": label[:256],
                "description": (detail or "Wiring check only. No action needed.")[:4000],
                "color": COLORS["test"],
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self._clock())),
            }],
        })
        _log(f"discord test: {'sent' if ok else 'FAILED'}")
        return ok
