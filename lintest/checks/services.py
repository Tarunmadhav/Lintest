"""Service checks via ``systemctl is-active``.

Each configured service is probed with ``systemctl is-active <name>``.
Critical services produce CRITICAL results when inactive; warning-tier
services only produce WARNING results.  When systemctl itself is missing
(non-systemd host) a single ERROR result is produced.
"""

from __future__ import annotations

import logging
import sys
from typing import List

from lintest.config import Config
from lintest.models import CheckResult, critical, error, info, ok, warning
from lintest.utils.shell import run_command

logger = logging.getLogger(__name__)

#: systemctl states that count as "running".
ACTIVE_STATES = {"active"}
#: systemctl states that are not active but also not failures (skipped by config design).
INACTIVE_STATES = {"inactive", "failed"}


def _check_one_service(cfg: Config, name: str, tier: str) -> CheckResult:
    """Check a single service and classify by *tier* ("critical"/"warning")."""
    timeout = cfg.general.timeout_for(override=5.0)
    res = run_command(["systemctl", "is-active", name], timeout=timeout)

    if res.missing:
        if sys.platform == "win32":
            # Windows has no systemctl: report an explicit, non-problem status
            # instead of an ERROR that would alert on every pass.
            return info(
                "services.systemctl",
                f"service checks unsupported on Windows -- systemctl is Linux-only "
                f"(cannot check service '{name}')",
                name,
                tier=tier,
            )
        return error(
            "services.systemctl",
            f"systemctl not available -- cannot check service '{name}'",
            name,
            tier=tier,
        )
    if res.timed_out:
        return error("services.systemctl", f"systemctl timed out checking '{name}'", name, tier=tier)

    state = res.first_line().lower() or f"exit={res.returncode}"
    if state in ACTIVE_STATES:
        return ok("services.active", f"service '{name}' is {state}", name, tier=tier, state=state)

    message = f"service '{name}' is {state} (tier: {tier})"
    details = {"tier": tier, "state": state}
    if tier == "critical":
        return critical("services.active", message, name, **details)
    return warning("services.active", message, name, **details)


def run_service_checks(cfg: Config) -> List[CheckResult]:
    """Check every configured service (critical tier first, then warning)."""
    results: List[CheckResult] = []
    for name in cfg.services.critical:
        results.append(_check_one_service(cfg, name, tier="critical"))
    for name in cfg.services.warning:
        results.append(_check_one_service(cfg, name, tier="warning"))
    return results
