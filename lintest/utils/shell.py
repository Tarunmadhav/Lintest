"""Subprocess helpers used by the service and network checks.

Every command is run through :func:`run_command`, which *never raises* for
ordinary failure modes (missing binary, non-zero exit, timeout).  Instead
it returns a :class:`CommandResult` describing what happened, so callers
can turn problems into check results instead of exceptions.
"""

from __future__ import annotations

import logging
import subprocess  # nosec B404 -- only used with argv lists, never shell=True
from dataclasses import dataclass
from typing import List, Optional, Sequence

logger = logging.getLogger(__name__)


class CommandError(Exception):
    """Raised only for programming errors (e.g. empty argv)."""


@dataclass
class CommandResult:
    """Outcome of an external command.

    Attributes:
        argv: The argument vector that was (attempted to be) run.
        returncode: Exit code; ``-1`` when unknown (missing binary or timeout).
        stdout: Decoded standard output (errors replaced).
        stderr: Decoded standard error (errors replaced).
        timed_out: True when the command exceeded *timeout*.
        missing: True when the executable could not be found at all.
    """

    argv: List[str]
    returncode: int
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    missing: bool = False

    @property
    def ran(self) -> bool:
        """True when the process actually started and finished."""
        return not self.missing and not self.timed_out

    def first_line(self) -> str:
        """First non-empty line of stdout, stripped."""
        for line in self.stdout.splitlines():
            line = line.strip()
            if line:
                return line
        return ""


def run_command(
    argv: Sequence[str],
    timeout: float = 10.0,
    cwd: Optional[str] = None,
) -> CommandResult:
    """Run *argv* without a shell and capture its output.

    Args:
        argv: Argument vector, e.g. ``["systemctl", "is-active", "nginx"]``.
        timeout: Kill the process after this many seconds.
        cwd: Optional working directory.

    Returns:
        A :class:`CommandResult`; ``missing``/``timed_out`` flag the two
        abnormal modes.  Does not raise for any of those cases.

    Raises:
        CommandError: If *argv* is empty (a caller bug, not a runtime event).
    """
    argv = [str(part) for part in argv]
    if not argv:
        raise CommandError("run_command() requires a non-empty argv")

    logger.debug("Running command: %s (timeout=%.1fs)", " ".join(argv), timeout)
    try:
        proc = subprocess.run(  # nosec B603 -- fixed argv, no shell
            argv,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            cwd=cwd,
            check=False,
        )
    except FileNotFoundError:
        logger.debug("Command not found: %s", argv[0])
        return CommandResult(argv=argv, returncode=-1, missing=True,
                             stderr=f"{argv[0]}: command not found")
    except PermissionError as exc:
        logger.debug("Command not executable: %s (%s)", argv[0], exc)
        return CommandResult(argv=argv, returncode=-1, missing=True,
                             stderr=f"{argv[0]}: {exc}")
    except subprocess.TimeoutExpired:
        logger.debug("Command timed out after %.1fs: %s", timeout, argv[0])
        return CommandResult(argv=argv, returncode=-1, timed_out=True,
                             stderr=f"{argv[0]}: timed out after {timeout:.0f}s")

    return CommandResult(
        argv=argv,
        returncode=proc.returncode,
        stdout=proc.stdout or "",
        stderr=proc.stderr or "",
    )
