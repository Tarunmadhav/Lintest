"""Network checks: ICMP ping, TCP port connectivity and DNS resolution.

* Ping uses the platform ``ping`` binary through :func:`run_command` and
  falls back to a TCP-connect latency probe against port 443 when the
  binary is missing or the probe fails entirely (common in unprivileged
  containers).
* TCP checks use plain sockets with a configurable timeout.
* DNS resolves the configured host via the system resolver, or an
  explicitly configured resolver when ``network.dns_servers`` is set.
"""

from __future__ import annotations

import logging
import math
import re
import socket
import sys
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from lintest.checks.base import run_check
from lintest.config import Config
from lintest.models import CheckResult, critical, error, info, ok, warning
from lintest.utils.shell import run_command

logger = logging.getLogger(__name__)

#: Round-trip time above which a ping is flagged (milliseconds).
LATENCY_WARN_MS = 500.0
#: Port used for the TCP fallback when ICMP ping is unavailable.
TCP_FALLBACK_PORT = 443

_RTT_RE = re.compile(r"=([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)\s*ms")
_TIME_RE = re.compile(r"time[=<]([\d.]+)\s*ms")
#: Windows ping summary: ``Average = 12ms`` (min/max/avg line).
_WIN_AVG_RE = re.compile(r"Average\s*=\s*([\d.]+)\s*ms", re.IGNORECASE)
#: Packet loss: iputils ``0% packet loss`` and Windows ``(100% loss)``.
_LOSS_RE = re.compile(r"([\d.]+)%(?:\s*packet)?\s*loss", re.IGNORECASE)


@dataclass
class PingOutcome:
    """Parsed result of one ping probe."""

    host: str
    transmitted: int = 0
    received: int = 0
    loss_percent: float = 100.0
    avg_ms: Optional[float] = None
    #: True when the output contained *at least one* recognisable ping field
    #: (a packet-loss line, an rtt summary or a per-reply ``time=`` value).
    #: When this is False the probe produced no usable evidence at all -- the
    #: binary may be missing options, lack the privileges it needs, or be a
    #: different implementation -- so "100% packet loss" must not be claimed.
    parseable: bool = False

    @property
    def ok(self) -> bool:
        """True when at least one reply arrived."""
        return self.received > 0


def _parse_ping_output(host: str, stdout: str, count: int) -> PingOutcome:
    """Extract packet loss and average RTT from ping's stdout.

    Handles both the summary line (Linux/iputils ``rtt min/avg/max/mdev``)
    and per-line ``time=XX ms`` replies (BusyBox, macOS, some MinGW builds).
    """
    outcome = PingOutcome(host=host)
    match = _RTT_RE.search(stdout)
    if match:
        outcome.avg_ms = float(match.group(2))
        outcome.parseable = True
    else:
        win_avg = _WIN_AVG_RE.search(stdout)
        if win_avg:
            outcome.avg_ms = float(win_avg.group(1))
            outcome.parseable = True
        else:
            times = [float(m.group(1)) for m in _TIME_RE.finditer(stdout)]
            if times:
                outcome.avg_ms = sum(times) / len(times)
                outcome.parseable = True

    loss_match = _LOSS_RE.search(stdout)
    if loss_match:
        outcome.parseable = True
        outcome.loss_percent = float(loss_match.group(1))
        outcome.transmitted = count
        outcome.received = round(count * (1 - outcome.loss_percent / 100.0))
    else:
        replies = len(_TIME_RE.findall(stdout))
        outcome.received = replies
        outcome.transmitted = count
        outcome.loss_percent = 100.0 if replies == 0 else round(100.0 * (count - replies) / count, 1)
    return outcome


def _tcp_latency(host: str, port: int, timeout: float) -> Optional[float]:
    """Measure TCP connect latency in ms, or None when unreachable."""
    start = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return (time.monotonic() - start) * 1000.0
    except OSError as exc:
        logger.debug("TCP probe to %s:%s failed: %s", host, port, exc)
        return None


def _ping_per_probe_seconds(cfg: Config) -> int:
    """Per-reply wait, in whole seconds (iputils/BusyBox ``-W`` unit)."""
    return max(1, math.ceil(cfg.network.ping_timeout_seconds))


def _ping_deadline_seconds(cfg: Config) -> int:
    """Overall ping deadline, in whole seconds (``-w`` unit)."""
    return max(1, math.ceil(cfg.network.ping_count * cfg.network.ping_timeout_seconds))


def _ping_argv(cfg: Config, host: str) -> List[str]:
    """Build the ``ping`` argument vector for the current platform.

    Linux/iputils uses ``-c`` (count), ``-W`` (per-reply wait) and ``-w``
    (overall deadline) in **whole seconds**; Windows ``ping`` uses ``-n``
    (count) and ``-w`` (per-reply timeout) in **milliseconds** and has no
    deadline option.  Either way an unreachable host costs at most
    ``ping_count * ping_timeout_seconds`` instead of hanging until the outer
    subprocess timeout kills the process.
    """
    if sys.platform == "win32":
        return [
            "ping",
            "-n", str(cfg.network.ping_count),
            "-w", str(int(round(cfg.network.ping_timeout_seconds * 1000))),
            host,
        ]
    return [
        "ping",
        "-c", str(cfg.network.ping_count),
        "-W", str(_ping_per_probe_seconds(cfg)),
        "-w", str(_ping_deadline_seconds(cfg)),
        host,
    ]


def _split_host_port(spec: str) -> Tuple[Optional[str], Optional[int]]:
    """Split ``host:port`` or ``[v6]:port`` into (host, port)."""
    spec = spec.strip()
    if spec.startswith("["):  # IPv6 literal form
        host, _, rest = spec[1:].partition("]")
        port_str = rest.lstrip(":")
        if host and port_str.isdigit():
            return host, int(port_str)
        return None, None
    host, _, port_str = spec.rpartition(":")
    if host and port_str.isdigit() and 1 <= int(port_str) <= 65535:
        return host, int(port_str)
    return None, None


def _tcp_fallback(cfg: Config, host: str, reason: str) -> CheckResult:
    """Degrade to a TCP-connect probe against :data:`TCP_FALLBACK_PORT`.

    Used when ICMP cannot be used at all (no ``ping`` binary, or a probe
    that produced no parseable output).  *reason* is recorded in the result
    so reports explain *why* ICMP was skipped.
    """
    latency = _tcp_latency(host, TCP_FALLBACK_PORT, cfg.network.tcp_timeout_seconds)
    if latency is not None:
        return info(
            "network.ping",
            f"host {host} reachable via TCP :{TCP_FALLBACK_PORT} in {latency:.0f} ms "
            f"({reason})",
            host, latency_ms=round(latency, 1), method="tcp_fallback", note=reason)
    return critical(
        "network.ping",
        f"host {host} unreachable: {reason} and the TCP probe to "
        f":{TCP_FALLBACK_PORT} failed",
        host, method="tcp_fallback", note=reason)


def _check_ping(cfg: Config, host: str) -> CheckResult:
    """Ping one host; degrade to a TCP latency probe when ICMP is unusable."""
    timeout = cfg.general.timeout_for(_ping_deadline_seconds(cfg) + 2)
    res = run_command(_ping_argv(cfg, host), timeout=timeout)

    if res.missing:
        return _tcp_fallback(cfg, host, reason="the ping binary is unavailable")

    outcome = _parse_ping_output(host, res.stdout, cfg.network.ping_count)

    if res.timed_out:
        return critical("network.ping", f"ping to {host} timed out after "
                        f"{timeout:.0f}s", host, method="icmp")
    if not outcome.parseable:
        # The probe produced no usable ICMP evidence (unsupported options, no
        # ICMP privileges, output we cannot parse).  Saying "100% packet loss"
        # here would be a false CRITICAL, so fall back to TCP instead.
        first_err = next((line.strip() for line in res.stderr.splitlines() if line.strip()), "")
        detail = first_err[:120] or f"ping exited with status {res.returncode}"
        return _tcp_fallback(cfg, host, reason=f"the ICMP probe was unusable ({detail})")
    if not outcome.ok:
        return critical("network.ping", f"host {host} unreachable: 100% packet loss ({cfg.network.ping_count} probes)",
                        host, method="icmp", loss_percent=100.0)

    avg = outcome.avg_ms
    loss = outcome.loss_percent
    details = {"method": "icmp", "loss_percent": loss, "avg_ms": round(avg, 1) if avg is not None else None,
               "received": outcome.received, "transmitted": outcome.transmitted}
    if avg is not None and avg > LATENCY_WARN_MS:
        return warning("network.ping", f"host {host} reachable but slow: avg {avg:.0f} ms, loss {loss:.0f}%",
                       host, **details)
    msg = f"host {host} reachable: avg {avg:.0f} ms, loss {loss:.0f}%" if avg is not None \
        else f"host {host} reachable, loss {loss:.0f}%"
    return ok("network.ping", msg, host, **details)


def _check_tcp(cfg: Config, spec: str) -> CheckResult:
    """TCP-connect check for one ``host:port`` spec."""
    host, port = _split_host_port(spec)
    if host is None or port is None:
        return error("network.tcp", f"invalid host:port spec {spec!r}", spec)
    target = f"{host}:{port}"
    latency = _tcp_latency(host, port, cfg.network.tcp_timeout_seconds)
    if latency is None:
        return critical("network.tcp", f"cannot connect to {target} "
                        f"(timeout {cfg.network.tcp_timeout_seconds:.0f}s)", target, port=port)
    return ok("network.tcp", f"connected to {target} in {latency:.0f} ms", target,
              port=port, latency_ms=round(latency, 1))


@dataclass
class ResolveOutcome:
    """Result of one resolver attempt."""

    address: Optional[str] = None
    #: ``"dig"``, ``"system"`` or ``"none"`` (the tool was not usable).
    method: str = "none"
    error: str = ""


def _resolve(host: str, server: Optional[str]) -> ResolveOutcome:
    """Resolve *host*, optionally against a specific DNS *server*."""
    if server:
        res = run_command(["dig", "+short", f"@{server}", host], timeout=5)
        if res.missing:
            return ResolveOutcome(None, "none", "dig is not installed")
        if res.ran and res.returncode == 0:
            first = res.first_line()
            if first:
                return ResolveOutcome(first, "dig")
            return ResolveOutcome(None, "dig", "empty answer")
        first_err = next((line.strip() for line in res.stderr.splitlines() if line.strip()), "")
        logger.debug("dig against %s failed: %s", server, res.stderr.strip())
        return ResolveOutcome(None, "dig", first_err[:120] or f"dig exited with status {res.returncode}")
    try:
        return ResolveOutcome(socket.gethostbyname(host), "system")
    except OSError as exc:
        logger.debug("gethostbyname(%s) failed: %s", host, exc)
        return ResolveOutcome(None, "system", str(exc))


def _check_dns(cfg: Config) -> CheckResult:
    """DNS resolution sanity check."""
    host = cfg.network.dns_host
    servers = cfg.network.dns_servers
    if not servers:
        outcome = _resolve(host, None)
        if outcome.address:
            return ok("network.dns", f"resolved {host} -> {outcome.address} (system resolver)",
                      host, address=outcome.address)
        return critical("network.dns",
                        f"failed to resolve {host} via system resolver: {outcome.error}", host)

    outcomes: Dict[str, ResolveOutcome] = {s: _resolve(host, s) for s in servers}
    if all(o.method == "none" for o in outcomes.values()):
        # ``dig`` is not installed, so a "all configured servers failed" verdict
        # would blame DNS for a missing utility.  Use the system resolver instead.
        system = _resolve(host, None)
        if system.address:
            return warning(
                "network.dns",
                f"dig is not installed; resolved {host} -> {system.address} via the system "
                f"resolver (per-server checks against {', '.join(servers)} were skipped)",
                host, address=system.address, servers=servers, method="system")
        return critical(
            "network.dns",
            f"failed to resolve {host}: dig is not installed and the system resolver "
            f"also failed ({system.error})", host, servers=servers)

    failures = [s for s, o in outcomes.items() if not o.address]
    if not failures:
        return ok("network.dns", f"resolved {host} via {len(servers)} configured server(s)", host,
                  servers=servers)
    if len(failures) == len(servers):
        return critical("network.dns", f"failed to resolve {host} via all {len(servers)} "
                        f"configured server(s): {', '.join(failures)}", host, servers=servers)
    return warning("network.dns", f"resolved {host}, but these servers failed: {', '.join(failures)}",
                   host, servers=servers, failed=failures)


def run_network_checks(cfg: Config) -> List[CheckResult]:
    """Run all enabled network checks (ping, TCP ports, DNS).

    Every individual probe is wrapped by :func:`run_check` so one
    unreachable host or a resolver crash cannot abort the remaining
    probes.
    """
    results: List[CheckResult] = []
    for host in cfg.network.ping_hosts:
        results.extend(run_check(f"network.ping[{host}]", _check_ping, cfg, host))
    for spec in cfg.network.tcp_ports:
        results.extend(run_check(f"network.tcp[{spec}]", _check_tcp, cfg, spec))
    if cfg.network.dns_host:
        results.extend(run_check("network.dns", _check_dns, cfg))
    return results
