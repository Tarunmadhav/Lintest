"""Console alert channel -- always-available fallback delivery."""

from __future__ import annotations

import logging
import sys
from datetime import datetime, timezone
from typing import Optional, TextIO

from lintest.alerts.base import Alert, AlertChannel
from lintest.models import Severity

logger = logging.getLogger(__name__)

_ANSI = {
    Severity.CRITICAL: "\033[91m",  # red
    Severity.WARNING: "\033[93m",   # yellow
    Severity.ERROR: "\033[95m",     # magenta
    Severity.INFO: "\033[92m",      # green
    Severity.OK: "\033[92m",        # green
}
_RESET = "\033[0m"


class ConsoleChannel(AlertChannel):
    """Prints alerts to a stream (stderr by default).  Never fails hard."""

    name = "console"

    def __init__(self, enabled: bool = True, stream: Optional[TextIO] = None) -> None:
        self.enabled = enabled
        self._stream: TextIO = stream if stream is not None else sys.stderr

    def send(self, alert: Alert) -> bool:
        try:
            ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
            line = f"{ts} {alert.severity.value:<8} {alert.label()}"
            try:
                tty = self._stream.isatty()
            except (AttributeError, ValueError):
                tty = False
            if tty:
                line = f"{_ANSI.get(alert.severity, '')}{line}{_RESET}"
            print(line, file=self._stream, flush=True)
            return True
        except Exception as exc:  # noqa: BLE001 -- alerts must never crash the run
            logger.warning("console channel failed to print: %s", exc)
            return False
