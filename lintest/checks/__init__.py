"""Health checks: system metrics, services, network and security.

Each module exposes a ``run_xxx(cfg)`` function returning a list of
:class:`lintest.models.CheckResult`.  Failing checks must never raise out
of the runner -- :mod:`lintest.checks.base` guarantees that.
"""

from lintest.checks.base import run_check
from lintest.checks.network import run_network_checks
from lintest.checks.security import run_security_check
from lintest.checks.services import run_service_checks
from lintest.checks.system import run_system_checks

__all__ = [
    "run_check",
    "run_network_checks",
    "run_security_check",
    "run_service_checks",
    "run_system_checks",
]
