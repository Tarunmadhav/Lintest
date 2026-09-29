"""Shared data models for checks, alerts and reports.

All check functions return lists of :class:`CheckResult`, and one check
pass produces a :class:`CheckReport` summarising the run.
"""

from __future__ import annotations

import platform
import socket
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class Severity(str, Enum):
    """Severity of a check result."""

    OK = "OK"
    INFO = "INFO"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"
    ERROR = "ERROR"  # the check itself failed (config error, tool missing...)

    @property
    def rank(self) -> int:
        """Numeric rank used to compute the worst severity of a run."""
        return _RANK[self]

    def is_problem(self) -> bool:
        """True for anything that should be surfaced as an alert."""
        return self in (Severity.WARNING, Severity.CRITICAL, Severity.ERROR)


_RANK = {
    Severity.OK: 0,
    Severity.INFO: 1,
    Severity.WARNING: 2,
    Severity.CRITICAL: 3,
    Severity.ERROR: 4,
}


@dataclass
class CheckResult:
    """Outcome of a single check.

    Attributes:
        check: Machine-friendly check name, e.g. ``system.cpu``.
        severity: Result severity.
        message: Human-readable one-line summary (``OK`` state included).
        subject: What the check was about (mount point, service name,
            host, IP...).  Together with *check* it forms the alert key
            used for cooldown/recovery bookkeeping.
        details: Optional structured details for JSON/HTML output.
    """

    check: str
    severity: Severity
    message: str
    subject: str = ""
    details: Dict[str, Any] = field(default_factory=dict)

    @property
    def key(self) -> str:
        """Stable alert identity: ``check::subject``."""
        return f"{self.check}::{self.subject}"

    def is_problem(self) -> bool:
        """Convenience wrapper around :attr:`Severity.is_problem`."""
        return self.severity.is_problem()


def ok(check: str, message: str, subject: str = "", **details: Any) -> CheckResult:
    """Shorthand constructor for an OK result."""
    return CheckResult(check, Severity.OK, message, subject, details)


def info(check: str, message: str, subject: str = "", **details: Any) -> CheckResult:
    """Shorthand constructor for an INFO result."""
    return CheckResult(check, Severity.INFO, message, subject, details)


def warning(check: str, message: str, subject: str = "", **details: Any) -> CheckResult:
    """Shorthand constructor for a WARNING result."""
    return CheckResult(check, Severity.WARNING, message, subject, details)


def critical(check: str, message: str, subject: str = "", **details: Any) -> CheckResult:
    """Shorthand constructor for a CRITICAL result."""
    return CheckResult(check, Severity.CRITICAL, message, subject, details)


def error(check: str, message: str, subject: str = "", **details: Any) -> CheckResult:
    """Shorthand constructor for an ERROR result (check itself failed)."""
    return CheckResult(check, Severity.ERROR, message, subject, details)


@dataclass
class FailedLoginSummary:
    """Aggregated failed-SSH-login information for the security check."""

    window_minutes: int
    total: int
    top_ips: List[str] = field(default_factory=list)
    counts_by_ip: Dict[str, int] = field(default_factory=dict)
    source: str = ""  # e.g. "/var/log/auth.log" or "journalctl"


@dataclass
class CheckReport:
    """Result of one full check pass across every enabled area."""

    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at: Optional[datetime] = None
    hostname: str = field(default_factory=socket.gethostname)
    platform: str = field(default_factory=lambda: f"{platform.system()} {platform.release()}")
    results: List[CheckResult] = field(default_factory=list)
    config_path: Optional[str] = None

    def finish(self) -> None:
        """Stamp the end time (called once by the runner)."""
        if self.finished_at is None:
            self.finished_at = datetime.now(timezone.utc)

    @property
    def duration_seconds(self) -> float:
        """Wall-clock duration of the pass."""
        end = self.finished_at or datetime.now(timezone.utc)
        return max(0.0, (end - self.started_at).total_seconds())

    @property
    def warnings(self) -> List[CheckResult]:
        """All WARNING results."""
        return [r for r in self.results if r.severity is Severity.WARNING]

    @property
    def criticals(self) -> List[CheckResult]:
        """All CRITICAL results."""
        return [r for r in self.results if r.severity is Severity.CRITICAL]

    @property
    def errors(self) -> List[CheckResult]:
        """All ERROR results (checks that could not run)."""
        return [r for r in self.results if r.severity is Severity.ERROR]

    @property
    def problems(self) -> List[CheckResult]:
        """Anything that is not OK/INFO."""
        return [r for r in self.results if r.is_problem()]

    @property
    def worst(self) -> Severity:
        """The most severe result of the pass (OK when nothing failed)."""
        if not self.results:
            return Severity.OK
        return max(self.results, key=lambda r: r.severity.rank).severity

    @property
    def exit_code(self) -> int:
        """Process exit code: 1 when any CRITICAL was found, else 0.

        WARNING and ERROR results do not affect the exit code, matching
        the spec ("Exit code 1 if any CRITICAL alert is found").
        """
        return 1 if self.criticals else 0

    def to_dict(self) -> Dict[str, Any]:
        """Serialise the report for the JSON output mode."""
        return {
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "duration_seconds": round(self.duration_seconds, 3),
            "hostname": self.hostname,
            "platform": self.platform,
            "config_path": self.config_path,
            "summary": {
                "total": len(self.results),
                "ok": sum(1 for r in self.results if r.severity is Severity.OK),
                "warnings": len(self.warnings),
                "criticals": len(self.criticals),
                "errors": len(self.errors),
                "worst": self.worst.value,
                "exit_code": self.exit_code,
            },
            "results": [
                {
                    "check": r.check,
                    "severity": r.severity.value,
                    "subject": r.subject,
                    "message": r.message,
                    "details": r.details,
                }
                for r in self.results
            ],
        }
