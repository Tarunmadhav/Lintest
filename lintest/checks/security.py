"""Failed SSH login detection from /var/log/auth.log (or journalctl).

Two timestamp styles are auto-detected per line:

* **auth.log** — ``Jul 12 03:14:15 host sshd[4242]: Failed password for
  root from 203.0.113.5 port 4242 ssh2``
* **journalctl short-precise** — ``2024-07-12T03:14:15.123456+00:00 host
  sshd[4242]: Failed password ...``

Both ``Failed password ...`` and ``Invalid user ...`` pre-auth lines are
counted.  The parser is deliberately tolerant: unmatched lines are
ignored, so partial or rotated logs never break the check.

Timestamps in auth.log carry no year and no timezone, so they are
interpreted in the host's **local time** with the current year, with a
wrap-around guard (a December log read in January is dated to the
previous year, never pushed a year into the future).

The parsing/filtering/aggregation helpers are pure functions so they can
be unit-tested without touching the filesystem or journal.
"""

from __future__ import annotations

import logging
import re
import sys
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from lintest.config import Config
from lintest.models import CheckResult, FailedLoginSummary, critical, info, ok, warning
from lintest.utils.shell import run_command

logger = logging.getLogger(__name__)

#: Matches the ``sshd[pid]:`` line prefix in both timestamp styles.  OpenSSH
#: 9.8+ logs some messages from ``sshd-session[pid]``, so that prefix is
#: accepted too -- missing it would silently report "0 failed logins".
_SSHD_PREFIX_RE = re.compile(
    r"^(?:"
    r"(?P<ts_syslog>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
    r"|(?P<ts_iso>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
    r")\s+\S+\s+sshd(?:-session)?\[\d+\]:\s*(?P<msg>.*)$"
)
#: ``Failed password for root from 1.2.3.4 port 22 ssh2`` (also publickey etc.)
_FAILED_RE = re.compile(
    r"Failed \S+(?:/pam)? for (?:invalid user )?(?P<user>\S+) "
    r"from (?P<ip>[0-9a-fA-F.:]+) port \d+"
)
#: ``Invalid user oracle from 1.2.3.4 port 51022`` (pre-auth probing)
_INVALID_USER_RE = re.compile(
    r"Invalid user (?P<user>\S+) from (?P<ip>[0-9a-fA-F.:]+)"
)

#: Tolerance added after ``now`` when filtering, to absorb small clock skew
#: between the log source and the monitoring host.
_FUTURE_SKEW = timedelta(minutes=2)

#: Upper bound on how many bytes of the auth log are read per pass.  Only the
#: tail can contain events inside the (short) rolling window, and slurping a
#: multi-hundred-megabyte ``auth.log`` every five minutes would waste I/O and
#: memory.  4 MiB is far more than any realistic window needs.
MAX_LOG_READ_BYTES = 4 * 1024 * 1024


@dataclass(frozen=True)
class LogEvent:
    """One failed-login event extracted from a log line."""

    ts: datetime  # naive local time
    ip: str
    user: str
    raw: str


# ---------------------------------------------------------------------------
# Pure parsing helpers
# ---------------------------------------------------------------------------


def _parse_syslog_ts(text: str, now: datetime, year_hint: Optional[int] = None) -> datetime:
    """Parse ``Jul 12 03:14:15`` (no year) into a naive local datetime.

    Uses *year_hint* (default: the current year) and pushes the date back
    one year when it lands more than a day in the future, which handles
    reading old December logs in January.
    """
    year = year_hint if year_hint is not None else now.year
    candidate = datetime.strptime(f"{year} {text}", "%Y %b %d %H:%M:%S")
    if candidate - now > timedelta(days=1):
        candidate = candidate.replace(year=year - 1)
    return candidate


def _parse_iso_ts(text: str) -> datetime:
    """Parse an ISO-8601 timestamp (journalctl short-precise) to naive local."""
    text = text.replace(",", ".")
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    # fromisoformat on 3.10 does not accept "+0000" (no colon) -- normalise.
    if len(text) >= 5 and text[-5] in "+-" and ":" not in text[-5:]:
        text = text[:-5] + text[-5:-2] + ":" + text[-2:]
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone().replace(tzinfo=None)
    return parsed


def parse_auth_line(
    line: str,
    now: Optional[datetime] = None,
    year_hint: Optional[int] = None,
) -> Optional[LogEvent]:
    """Extract a failed-login event from one log line.

    Returns ``None`` for anything that is not an sshd failed-login line
    (other daemons, successful logins, sudo lines, garbage...).
    """
    now = now or datetime.now()
    match = _SSHD_PREFIX_RE.match(line.strip())
    if not match:
        return None

    failed = _FAILED_RE.search(match.group("msg")) or _INVALID_USER_RE.search(
        match.group("msg")
    )
    if not failed:
        return None

    try:
        if match.group("ts_syslog"):
            ts = _parse_syslog_ts(match.group("ts_syslog"), now, year_hint)
        else:
            ts = _parse_iso_ts(match.group("ts_iso"))
    except ValueError:
        # Line *shape* matched but the timestamp is nonsense (a corrupted or
        # truncated log entry, e.g. "Jul 32 99:99:99").  A tolerant parser
        # ignores it instead of failing the whole security check.
        logger.debug("unparseable timestamp in log line: %r", line[:120])
        return None
    return LogEvent(ts=ts, ip=failed.group("ip"), user=failed.group("user"), raw=line.rstrip())


def filter_window(
    events: Sequence[LogEvent], now: datetime, window_minutes: int
) -> List[LogEvent]:
    """Keep only events inside ``[now - window, now + skew]``."""
    start = now - timedelta(minutes=window_minutes)
    end = now + _FUTURE_SKEW
    return [e for e in events if start <= e.ts <= end]


def aggregate(events: Sequence[LogEvent], top_n: int) -> Tuple[int, List[str], Dict[str, int]]:
    """Return ``(total, top_ips, counts_by_ip)`` for *events*."""
    counts: Counter = Counter(e.ip for e in events)
    top = [ip for ip, _ in counts.most_common(top_n)]
    return len(events), top, dict(counts)


def summarize_lines(
    lines: Sequence[str],
    now: datetime,
    window_minutes: int,
    top_ips: int,
    source: str,
) -> FailedLoginSummary:
    """Parse raw log *lines* and produce a :class:`FailedLoginSummary`."""
    events: List[LogEvent] = []
    for line in lines:
        event = parse_auth_line(line, now=now)
        if event is not None:
            events.append(event)
    recent = filter_window(events, now, window_minutes)
    total, top, counts = aggregate(recent, top_ips)
    return FailedLoginSummary(
        window_minutes=window_minutes, total=total, top_ips=top,
        counts_by_ip=counts, source=source,
    )


# ---------------------------------------------------------------------------
# Log collection
# ---------------------------------------------------------------------------


def _read_lines(path: Path, max_bytes: int = MAX_LOG_READ_BYTES) -> List[str]:
    """Read the *tail* of a log file defensively.

    At most *max_bytes* are read, so a huge or rapidly growing ``auth.log``
    cannot exhaust memory.  Undecodable bytes become U+FFFD, and when the file
    was truncated the first (partial) line is dropped so it can never be
    parsed as a half-written event.
    """
    with path.open("rb") as handle:
        try:
            size = path.stat().st_size
        except OSError:  # pragma: no cover - stat rarely fails after open()
            size = 0
        truncated = size > max_bytes
        if truncated:
            handle.seek(size - max_bytes)
        data = handle.read(max_bytes)
    lines = data.decode("utf-8", errors="replace").splitlines()
    if truncated and lines:
        logger.debug("read last %d of %d bytes of %s", max_bytes, size, path)
        lines = lines[1:]
    return lines


def collect_failed_logins(cfg: Config, now: Optional[datetime] = None) -> FailedLoginSummary:
    """Collect failed SSH logins from auth.log, falling back to journalctl.

    Never raises: every failure mode degrades to an empty summary with a
    distinguishing ``source`` ("" means "no source was available").
    """
    now = now or datetime.now()
    window = cfg.security.window_minutes
    empty = FailedLoginSummary(window_minutes=window, total=0, source="")

    path = Path(cfg.security.auth_log_path)
    if path.is_file():
        try:
            lines = _read_lines(path)
        except OSError as exc:
            logger.warning("cannot read %s: %s", path, exc)
        else:
            return summarize_lines(lines, now, window, cfg.security.top_ips, str(path))

    if not cfg.security.use_journalctl_fallback:
        logger.warning("auth log %s not found and journalctl fallback is disabled", path)
        return empty

    res = run_command(
        ["journalctl", "-q", "--no-pager", "-o", "short-precise",
         "-u", "ssh", "-u", "sshd", "--since", f"-{window} min"],
        timeout=cfg.general.timeout_for(15.0),
    )
    if res.ran and res.returncode == 0:
        return summarize_lines(res.stdout.splitlines(), now, window,
                               cfg.security.top_ips, "journalctl")

    logger.warning(
        "no SSH auth source available (auth log %s missing; journalctl %s)",
        path, "not found" if res.missing else f"failed: {res.stderr.strip()[:120]}",
    )
    return empty


# ---------------------------------------------------------------------------
# Check runner
# ---------------------------------------------------------------------------


def _classify_logins(total: int, threshold: int) -> Tuple[str, str]:
    """Classify a failed-login count; warning starts at half the threshold."""
    if total >= threshold:
        return "CRITICAL", f"at or above the critical threshold ({threshold})"
    if total >= max(1, threshold // 2):
        return "WARNING", f"above half of the critical threshold ({threshold})"
    return "OK", ""


def run_security_check(cfg: Config, now: Optional[datetime] = None) -> List[CheckResult]:
    """Check failed SSH logins over the configured window."""
    summary = collect_failed_logins(cfg, now)
    threshold = cfg.thresholds.failed_ssh_logins
    details = {
        "total": summary.total,
        "window_minutes": summary.window_minutes,
        "threshold": threshold,
        "top_ips": summary.top_ips,
        "counts_by_ip": summary.counts_by_ip,
        "source": summary.source,
    }

    if not summary.source:
        if sys.platform == "win32":
            # Expected on Windows (no auth.log, no journalctl): an explicit
            # 'skipped' status, not a WARNING that would alert on every pass.
            return [info(
                "security.ssh",
                "security.ssh skipped on Windows -- no SSH auth source "
                "(auth.log and journalctl are Linux-only)",
                "ssh", **details,
            )]
        return [warning(
            "security.ssh",
            "no SSH auth source available (auth log missing, journalctl unavailable)",
            "ssh", **details,
        )]

    message = f"{summary.total} failed SSH logins in the last {summary.window_minutes} min"
    if summary.top_ips:
        tops = ", ".join(f"{ip} x{summary.counts_by_ip[ip]}" for ip in summary.top_ips)
        message += f" (top: {tops}; source: {summary.source})"
    else:
        message += f" (source: {summary.source})"

    severity, reason = _classify_logins(summary.total, threshold)
    if severity == "OK":
        return [ok("security.ssh", message, "ssh", **details)]
    full = f"{message} -- {reason}"
    if severity == "WARNING":
        return [warning("security.ssh", full, "ssh", **details)]
    return [critical("security.ssh", full, "ssh", **details)]
