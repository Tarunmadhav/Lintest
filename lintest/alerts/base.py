"""Alert data model and the :class:`AlertChannel` interface.

An :class:`Alert` is a check result prepared for delivery.  Channels
implement :meth:`AlertChannel.send`, which must return ``True``/``False``
and must never raise -- delivery problems are logged, not thrown.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass

from lintest.models import CheckResult, Severity

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Alert:
    """A single alertable event, ready for delivery to channels."""

    severity: Severity
    check: str
    subject: str
    message: str

    @property
    def key(self) -> str:
        """Stable identity used for cooldown bookkeeping."""
        return f"{self.check}::{self.subject}"

    def label(self) -> str:
        """One-line human-readable rendering."""
        subject = f"[{self.subject}] " if self.subject else ""
        return f"{self.check} {subject}-- {self.message}"


def alert_from_result(result: CheckResult) -> Alert:
    """Convert a :class:`CheckResult` into an :class:`Alert`."""
    return Alert(
        severity=result.severity,
        check=result.check,
        subject=result.subject,
        message=result.message,
    )


class AlertChannel(ABC):
    """Interface for alert delivery channels (console, Telegram, ...)."""

    #: Channel name used in logs and summaries.
    name: str = "channel"
    #: Disabled channels are skipped by the manager.
    enabled: bool = True

    @abstractmethod
    def send(self, alert: Alert) -> bool:
        """Deliver *alert*; return True when delivered.  Must not raise."""
        raise NotImplementedError
