"""System metric checks: CPU, RAM, per-mount disk usage and load average.

All metrics come from :mod:`psutil`.  Each metric is classified with the
configured thresholds (CRITICAL at/above the limit, WARNING within a 10
point band below it) and becomes one :class:`CheckResult`.
"""

from __future__ import annotations

import logging
import os
from typing import List

import psutil

from lintest.checks.base import run_check
from lintest.config import Config, warning_band
from lintest.models import CheckResult, Severity, critical, ok, warning

logger = logging.getLogger(__name__)

#: How long to sample CPU usage, in seconds.  psutil needs a non-zero
#: interval for a meaningful instantaneous reading.
CPU_SAMPLE_SECONDS = 0.5


def _classify(threshold: float, value: float) -> tuple[Severity, str]:
    """Map *value* against *threshold* to a severity + message suffix.

    The WARNING band comes from :func:`lintest.config.warning_band` so small
    thresholds (``load1_per_core``) get a proportional band instead of the
    10-point band used for percentages.
    """
    if value >= threshold:
        return Severity.CRITICAL, f"at or above critical threshold ({threshold:.0f})"
    band = warning_band(threshold)
    if value >= threshold - band:
        return Severity.WARNING, f"within {band:g} points of critical threshold ({threshold:.0f})"
    return Severity.OK, ""


def _check_cpu(cfg: Config) -> CheckResult:
    """CPU utilisation check."""
    percent = psutil.cpu_percent(interval=CPU_SAMPLE_SECONDS)
    threshold = cfg.thresholds.cpu_percent
    severity, reason = _classify(threshold, percent)
    cores = psutil.cpu_count(logical=True) or 1
    message = f"CPU usage {percent:.1f}% ({cores} cores)"
    if severity is Severity.OK:
        return ok("system.cpu", message, "cpu", percent=round(percent, 1), threshold=threshold, cores=cores)
    full = f"{message} -- {reason}"
    if severity is Severity.WARNING:
        return warning("system.cpu", full, "cpu", percent=round(percent, 1), threshold=threshold)
    return critical("system.cpu", full, "cpu", percent=round(percent, 1), threshold=threshold)


def _check_ram(cfg: Config) -> CheckResult:
    """Memory utilisation check (percentage of total)."""
    mem = psutil.virtual_memory()
    percent = mem.percent
    threshold = cfg.thresholds.ram_percent
    severity, reason = _classify(threshold, percent)
    used_gib = mem.used / 1024**3
    total_gib = mem.total / 1024**3
    message = f"RAM usage {percent:.1f}% ({used_gib:.1f}/{total_gib:.1f} GiB)"
    details = {"percent": round(percent, 1), "threshold": threshold,
               "used_gib": round(used_gib, 2), "total_gib": round(total_gib, 2)}
    if severity is Severity.OK:
        return ok("system.ram", message, "ram", **details)
    full = f"{message} -- {reason}"
    if severity is Severity.WARNING:
        return warning("system.ram", full, "ram", **details)
    return critical("system.ram", full, "ram", **details)


def _should_skip_mount(mountpoint: str, fstype: str, cfg: Config) -> bool:
    """True when a mount point is excluded by prefix or filesystem type."""
    if fstype in cfg.system.exclude_filesystems:
        return True
    norm = mountpoint.rstrip("/") or "/"
    for prefix in cfg.system.ignore_mount_prefixes:
        p = prefix.rstrip("/")
        if norm == p or norm.startswith(p + "/"):
            return True
    return False


def _check_disks(cfg: Config) -> List[CheckResult]:
    """Per-mount-point disk usage checks."""
    results: List[CheckResult] = []
    try:
        partitions = psutil.disk_partitions(all=False)
    except Exception as exc:  # pragma: no cover - defensive, psutil rarely raises
        logger.warning("disk_partitions failed: %s", exc)
        partitions = []

    for part in partitions:
        mount = part.mountpoint
        if _should_skip_mount(mount, part.fstype, cfg):
            logger.debug("Skipping mount %s (%s)", mount, part.fstype)
            continue
        try:
            usage = psutil.disk_usage(mount)
        except (PermissionError, OSError) as exc:
            results.append(
                warning("system.disk", f"cannot read usage of {mount}: {exc}", mount)
            )
            continue

        percent = usage.percent
        threshold = cfg.thresholds.disk_threshold_for(mount)
        severity, reason = _classify(threshold, percent)
        free_gib = usage.free / 1024**3
        total_gib = usage.total / 1024**3
        message = f"disk {mount} {percent:.1f}% used ({free_gib:.1f}/{total_gib:.1f} GiB free on {part.fstype})"
        details = {"percent": round(percent, 1), "threshold": threshold,
                   "free_gib": round(free_gib, 2), "total_gib": round(total_gib, 2),
                   "fstype": part.fstype}
        if severity is Severity.OK:
            results.append(ok("system.disk", message, mount, **details))
        elif severity is Severity.WARNING:
            results.append(warning("system.disk", f"{message} -- {reason}", mount, **details))
        else:
            results.append(critical("system.disk", f"{message} -- {reason}", mount, **details))

    if not results:
        results.append(ok("system.disk", "no real mount points found to check", "disk"))
    return results


def _check_load(cfg: Config) -> List[CheckResult]:
    """Load average check, normalised by logical core count.

    Only the 1-minute average is evaluated; on platforms without
    ``os.getloadavg`` (e.g. Windows) an INFO result is returned instead.
    """
    if not hasattr(os, "getloadavg"):
        return [ok("system.load", "load average not available on this platform", "load")]
    try:
        load1, load5, load15 = os.getloadavg()
    except OSError as exc:  # pragma: no cover - defensive
        return [warning("system.load", f"could not read load average: {exc}", "load")]

    cores = psutil.cpu_count(logical=True) or 1
    per_core = load1 / cores
    threshold = cfg.thresholds.load1_per_core
    severity, reason = _classify(threshold, per_core)
    message = f"load1 {load1:.2f} ({per_core:.2f}/core over {cores} cores; 5m {load5:.2f}, 15m {load15:.2f})"
    details = {"load1": round(load1, 2), "load5": round(load5, 2), "load15": round(load15, 2),
               "per_core": round(per_core, 2), "threshold": threshold, "cores": cores}
    if severity is Severity.OK:
        return [ok("system.load", message, "load", **details)]
    full = f"{message} -- {reason}"
    if severity is Severity.WARNING:
        return [warning("system.load", full, "load", **details)]
    return [critical("system.load", full, "load", **details)]


def run_system_checks(cfg: Config) -> List[CheckResult]:
    """Run all enabled system metric checks and return their results.

    Each sub-check is individually wrapped by :func:`run_check`, so a
    psutil hiccup on one metric cannot take down the others.
    """
    results: List[CheckResult] = []
    results.extend(run_check("system.cpu", _check_cpu, cfg))
    results.extend(run_check("system.ram", _check_ram, cfg))
    results.extend(run_check("system.disk", _check_disks, cfg))
    results.extend(run_check("system.load", _check_load, cfg))
    return results
