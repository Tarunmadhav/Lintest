"""Alert dispatch with cooldown suppression and recovery notifications.

The manager keeps state in a small JSON file so cooldowns survive between
runs (important because under a systemd *timer* the process exits after
every pass).  State per alert key ``check::subject``::

    {"last_sent": "<iso datetime>", "firing": true, "severity": "...", "message": "..."}

Semantics
---------
* A problem whose key is not firing -> alert sent immediately.
* A problem whose key is firing and inside the cooldown -> suppressed.
* A problem whose key is firing but the cooldown has elapsed -> re-sent.
* A key that was firing and no longer appears among the problems ->
  a RECOVERED message (when ``send_recovery`` is on) and its entry is
  marked idle, so a new occurrence alerts immediately.
* If no channel could deliver an alert, the state is *not* recorded, so
  the next run retries instead of silently swallowing the problem.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence

from lintest.alerts.base import Alert, AlertChannel, alert_from_result
from lintest.models import CheckResult, Severity

logger = logging.getLogger(__name__)

_STATE_VERSION = 1


@dataclass
class DispatchSummary:
    """What the manager did during one dispatch."""

    sent: List[Alert] = field(default_factory=list)
    suppressed: List[Alert] = field(default_factory=list)
    recovered: List[Alert] = field(default_factory=list)

    def to_dict(self) -> Dict[str, int]:
        """Compact counts for logs/JSON output."""
        return {
            "sent": len(self.sent),
            "suppressed": len(self.suppressed),
            "recovered": len(self.recovered),
        }


def default_state_path() -> Path:
    """Pick a writable state location.

    Order: ``$LINTEST_STATE_FILE`` -> ``/var/lib/lintest/state.json`` (when
    writable, i.e. installed setups) -> ``~/.cache/lintest/state.json`` ->
    ``~/.lintest/state.json`` (non-POSIX).
    """
    env = os.environ.get("LINTEST_STATE_FILE")
    if env:
        return Path(env)
    if os.name == "posix":
        preferred = Path("/var/lib/lintest/state.json")
        try:
            preferred.parent.mkdir(parents=True, exist_ok=True)
            if os.access(preferred.parent, os.W_OK):
                return preferred
        except OSError:
            pass
        return Path.home() / ".cache" / "lintest" / "state.json"
    return Path.home() / ".lintest" / "state.json"


class AlertManager:
    """Fans results out to channels with cooldown/recovery bookkeeping."""

    def __init__(
        self,
        channels: Sequence[AlertChannel],
        cooldown_minutes: int = 30,
        send_recovery: bool = True,
        state_path: Optional[Path] = None,
        hostname: str = "",
        clock: Optional[Callable[[], datetime]] = None,
    ) -> None:
        self.channels: List[AlertChannel] = [
            c for c in channels if getattr(c, "enabled", True)
        ]
        self.cooldown = timedelta(minutes=cooldown_minutes)
        self.send_recovery = send_recovery
        self.state_path = Path(state_path) if state_path else default_state_path()
        self.hostname = hostname
        self._now: Callable[[], datetime] = clock or (
            lambda: datetime.now(timezone.utc)
        )
        self._state: Dict[str, dict] = self._load_state()

    # -- state persistence ---------------------------------------------------

    def _load_state(self) -> Dict[str, dict]:
        try:
            raw = self.state_path.read_text(encoding="utf-8")
            data = json.loads(raw)
            alerts = data.get("alerts", {})
            if isinstance(alerts, dict):
                return {str(k): v for k, v in alerts.items() if isinstance(v, dict)}
            logger.warning("malformed alert state in %s; starting fresh", self.state_path)
        except FileNotFoundError:
            pass
        except (OSError, ValueError) as exc:
            logger.warning("could not load alert state %s (%s); starting fresh",
                           self.state_path, exc)
        return {}

    def _save_state(self) -> None:
        try:
            self.state_path.parent.mkdir(parents=True, exist_ok=True)
            payload = {"version": _STATE_VERSION, "alerts": self._state}
            self.state_path.write_text(
                json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8"
            )
        except OSError as exc:
            logger.warning("could not save alert state %s: %s", self.state_path, exc)

    # -- delivery ------------------------------------------------------------

    def _deliver(self, alert: Alert) -> bool:
        """Send *alert* to every enabled channel; True if any succeeded."""
        delivered = False
        for channel in self.channels:
            try:
                if channel.send(alert):
                    delivered = True
            except Exception as exc:  # noqa: BLE001 -- a broken channel must not break dispatch
                logger.warning("channel %s raised %s", getattr(channel, "name", channel), exc)
        return delivered

    def _in_cooldown(self, key: str, now: datetime) -> bool:
        entry = self._state.get(key)
        if not entry or not entry.get("firing"):
            return False
        last = entry.get("last_sent")
        if not last:
            return False
        try:
            last_dt = datetime.fromisoformat(last)
        except ValueError:
            return False
        return (now - last_dt) < self.cooldown

    # -- main entry point ----------------------------------------------------

    def dispatch(self, results: Sequence[CheckResult]) -> DispatchSummary:
        """Process one run's results: send, suppress, and recover."""
        now = self._now()
        summary = DispatchSummary()
        problems = [r for r in results if r.is_problem()]
        problem_keys = {r.key for r in problems}

        for result in problems:
            alert = alert_from_result(result)
            if self._in_cooldown(alert.key, now):
                logger.debug("suppressed (cooldown): %s", alert.key)
                summary.suppressed.append(alert)
                continue
            if self._deliver(alert):
                summary.sent.append(alert)
                self._state[alert.key] = {
                    "last_sent": now.isoformat(),
                    "firing": True,
                    "severity": result.severity.value,
                    "message": result.message,
                }
            else:
                logger.debug("no channel delivered %s -- will retry next run", alert.key)

        for key, entry in list(self._state.items()):
            if not entry.get("firing") or key in problem_keys:
                continue
            if self.send_recovery:
                check, _, subject = key.partition("::")
                recovery = Alert(
                    severity=Severity.INFO,
                    check=check,
                    subject=subject,
                    message=f"RECOVERED: previous alert cleared ({entry.get('message', '')})",
                )
                if self._deliver(recovery):
                    summary.recovered.append(recovery)
            entry["firing"] = False

        self._save_state()
        return summary
