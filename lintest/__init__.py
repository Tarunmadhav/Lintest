"""LinTest -- a Linux server health monitor with alerting.

LinTest checks system metrics (CPU, RAM, disks, load), systemd services,
network reachability (ping, TCP ports, DNS) and failed SSH logins, then
alerts via Telegram (with a console fallback) when configured thresholds
are breached.  It is designed to run from a systemd timer or cron.

Module map::

    lintest.config      configuration loading and validation
    lintest.models      shared data models (CheckResult, Severity, ...)
    lintest.checks      individual health checks
    lintest.alerts      alert channels (console, Telegram) + cooldown logic
    lintest.reporting   JSON / HTML output
    lintest.utils       logging setup and subprocess helpers
    lintest.main        CLI entry point
"""

__version__ = "1.0.0"

__all__ = ["__version__"]
