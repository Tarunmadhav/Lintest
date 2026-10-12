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
  the next run retries instead of silently swallowing the problem.  The same
  applies to a recovery notification that could not be delivered.
* A corrupt or hand-edited state file never aborts a run: unreadable entries
  are dropped and dispatch continues from a clean slate.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
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
    writable, i.e. installed setups) -> ``/run/lintest/state.json`` (writable
    tmpfs; state is lost on reboot) -> ``~/.cache/lintest/state.json`` ->
    ``~/.lintest/state.json`` (non-POSIX).
    """
    env = os.environ.get("LINTEST_STATE_FILE")
    if env:
        return Path(env)
    if os.name == "posix":
        for candidate in (Path("/var/lib/lintest/state.json"), Path("/run/lintest/state.json")):
            try:
                candidate.parent.mkdir(parents=True, exist_ok=True)
                if os.access(candidate.parent, os.W_OK):
                    return candidate
            except OSError:
                continue
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
        """Load the state file, tolerating *any* kind of corruption.

        A state file is bookkeeping, never a reason to abort a monitoring
        run, so every malformed shape (unreadable file, invalid JSON, a JSON
        array/scalar instead of an object, a non-object ``alerts`` section,
        non-object entries) degrades to "no state" plus a warning.
        """
        try:
            raw = self.state_path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return {}
        except OSError as exc:
            logger.warning("could not read alert state %s (%s); starting fresh",
                           self.state_path, exc)
            return {}
        try:
            data = json.loads(raw)
        except ValueError as exc:
            logger.warning("alert state %s is not valid JSON (%s); starting fresh",
                           self.state_path, exc)
            return {}
        if not isinstance(data, dict):
            logger.warning("alert state %s has unexpected top-level type %s; starting fresh",
                           self.state_path, type(data).__name__)
            return {}
        alerts = data.get("alerts", {})
        if not isinstance(alerts, dict):
            logger.warning("alert state %s has a malformed 'alerts' section; starting fresh",
                           self.state_path)
            return {}
        entries = {str(k): v for k, v in alerts.items() if isinstance(v, dict)}
        dropped = len(alerts) - len(entries)
        if dropped:
            logger.warning("ignored %d malformed alert state entr%s in %s",
                           dropped, "y" if dropped == 1 else "ies", self.state_path)
        return entries

    def _save_state(self) -> None:
        """Persist the state atomically (write temp file, then rename).

        The temporary name is unique per *write* (``tempfile.mkstemp``), not
        just per process, so overlapping dispatchers -- including threads
        inside one process -- can never interleave writes into the same temp
        file.  ``os.replace`` is atomic, so a reader always sees either the
        old or the new file, never a truncated one.
        """
        payload = {"version": _STATE_VERSION, "alerts": self._state}
        fd: Optional[int] = None
        tmp: Optional[Path] = None
        try:
            self.state_path.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp_name = tempfile.mkstemp(
                prefix=f"{self.state_path.name}.", suffix=".tmp",
                dir=self.state_path.parent,
            )
            tmp = Path(tmp_name)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                fd = None  # ownership transferred to the file object
                json.dump(payload, handle, indent=2, sort_keys=True)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, self.state_path)
            tmp = None  # consumed by the rename
        except OSError as exc:
            logger.warning("could not save alert state %s: %s", self.state_path, exc)
        finally:
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:  # pragma: no cover - best effort cleanup
                    pass
            if tmp is not None:
                try:
                    tmp.unlink(missing_ok=True)
                except OSError:  # pragma: no cover - best effort cleanup
                    pass
        try:
            os.chmod(self.state_path, 0o600)  # state is not secret, but not world-writable either
        except OSError:  # pragma: no cover - e.g. exotic filesystems
            pass

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
        """True when *key* is already firing and still inside the cooldown.

        Anything unexpected in the stored entry (a non-string timestamp, an
        unparseable one, a naive datetime) is treated as "no cooldown" so a
        stale state file can only cause a duplicate alert, never a crash and
        never a silenced one.
        """
        entry = self._state.get(key)
        if not isinstance(entry, dict) or not entry.get("firing"):
            return False
        last = entry.get("last_sent")
        if not isinstance(last, str) or not last:
            return False
        try:
            last_dt = datetime.fromisoformat(last)
        except ValueError:
            return False
        if last_dt.tzinfo is None:
            # State written by an older build (or hand-edited) without an
            # offset is assumed to be UTC, which is what we always write.
            last_dt = last_dt.replace(tzinfo=timezone.utc)
        try:
            return (now - last_dt) < self.cooldown
        except TypeError:  # pragma: no cover - naive `now` from a custom clock
            return False

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
            if not isinstance(entry, dict) or not entry.get("firing") or key in problem_keys:
                continue
            if self.send_recovery:
                check, _, subject = key.partition("::")
                recovery = Alert(
                    severity=Severity.INFO,
                    check=check,
                    subject=subject,
                    message=f"RECOVERED: previous alert cleared ({entry.get('message', '')})",
                )
                if not self._deliver(recovery):
                    # Keep the entry firing so the recovery notification is
                    # retried next run instead of being silently dropped.
                    logger.warning("recovery for %s could not be delivered; will retry", key)
                    continue
                summary.recovered.append(recovery)
            entry["firing"] = False

        self._save_state()
        return summary
