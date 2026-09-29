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
import re
import socket
import time
from dataclasses import dataclass
from typing import List, Optional, Tuple

from lintest.config import Config
from lintest.checks.base import run_check
from lintest.models import CheckResult, critical, error, info, ok, warning
from lintest.utils.shell import run_command

logger = logging.getLogger(__name__)

#: Round-trip time above which a ping is flagged (milliseconds).
LATENCY_WARN_MS = 500.0
#: Port used for the TCP fallback when ICMP ping is unavailable.
TCP_FALLBACK_PORT = 443

_RTT_RE = re.compile(r"=([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)\s*ms")
_TIME_RE = re.compile(r"time[=<]([\d.]+)\s*ms")


@dataclass
class PingOutcome:
    """Parsed result of one ping probe."""

    host: str
    transmitted: int = 0
    received: int = 0
    loss_percent: float = 100.0
    avg_ms: Optional[float] = None

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
    else:
        times = [float(m.group(1)) for m in _TIME_RE.finditer(stdout)]
        if times:
            outcome.avg_ms = sum(times) / len(times)

    loss_match = re.search(r"([\d.]+)%\s*packet loss", stdout)
    if loss_match:
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


def _check_ping(cfg: Config, host: str) -> CheckResult:
    """Ping one host; degrade to a TCP latency probe when ICMP is unusable."""
    argv = ["ping", "-c", str(cfg.network.ping_count),
            "-W", str(int(cfg.network.ping_timeout_seconds * 1000)), host]
    res = run_command(argv, timeout=cfg.general.timeout_for(cfg.network.ping_count * cfg.network.ping_timeout_seconds + 2))

    if res.missing:
        latency = _tcp_latency(host, TCP_FALLBACK_PORT, cfg.network.tcp_timeout_seconds)
        if latency is not None:
            return info(
                "network.ping", f"ping binary unavailable; TCP probe to {host}:{TCP_FALLBACK_PORT} "
                f"succeeded in {latency:.0f} ms", host, latency_ms=round(latency, 1), method="tcp_fallback")
        return critical("network.ping", f"host {host} unreachable (no ping binary, TCP probe failed)", host,
                        method="tcp_fallback")

    outcome = _parse_ping_output(host, res.stdout, cfg.network.ping_count)

    if res.timed_out:
        return critical("network.ping", f"ping to {host} timed out after "
                        f"{cfg.general.timeout_for(cfg.network.ping_count * cfg.network.ping_timeout_seconds + 2):.0f}s",
                        host, method="icmp")
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


def _resolve(host: str, server: Optional[str]) -> Optional[str]:
    """Resolve *host*, optionally against a specific DNS *server*."""
    if server:
        res = run_command(["dig", "+short", f"@{server}", host], timeout=5)
        if res.ran and res.returncode == 0:
            first = res.first_line()
            return first or None
        logger.debug("dig against %s failed: %s", server, res.stderr.strip())
        return None
    try:
        return socket.gethostbyname(host)
    except OSError as exc:
        logger.debug("gethostbyname(%s) failed: %s", host, exc)
        return None


def _check_dns(cfg: Config) -> CheckResult:
    """DNS resolution sanity check."""
    host = cfg.network.dns_host
    servers = cfg.network.dns_servers
    if not servers:
        addr = _resolve(host, None)
        if addr:
            return ok("network.dns", f"resolved {host} -> {addr} (system resolver)", host, address=addr)
        return critical("network.dns", f"failed to resolve {host} via system resolver", host)

    failures = [s for s in servers if not _resolve(host, s)]
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
