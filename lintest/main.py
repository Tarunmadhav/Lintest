"""Command-line interface and orchestration for LinTest.

Flow of a single pass::

    load config -> setup logging -> run enabled checks (crash-isolated)
    -> dispatch alerts (cooldown + recovery) -> print / JSON / HTML report
    -> exit 1 if any CRITICAL result, else 0
"""

from __future__ import annotations

import argparse
import logging
import sys
import time
from pathlib import Path
from typing import List, Optional, Sequence

from lintest import __version__
from lintest.alerts.base import AlertChannel
from lintest.alerts.console import ConsoleChannel
from lintest.alerts.manager import AlertManager, DispatchSummary
from lintest.alerts.telegram import TelegramChannel
from lintest.checks import (
    run_network_checks,
    run_security_check,
    run_service_checks,
    run_system_checks,
)
from lintest.checks.base import run_check
from lintest.config import Config, ConfigError, load_config
from lintest.models import CheckReport
from lintest.reporting.html_report import write_html_report
from lintest.reporting.json_output import write_json_report
from lintest.utils.logging_setup import setup_logging

logger = logging.getLogger(__name__)

OUTPUT_MODES = ("text", "json")
#: File name used when ``--report html`` is given without an explicit path.
DEFAULT_REPORT_NAME = "lintest-report.html"

_SEV_MARK = {"OK": ".", "INFO": "i", "WARNING": "!", "CRITICAL": "X", "ERROR": "?"}


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="lintest",
        description="LinTest -- Linux server health monitor with alerting.",
        epilog="Secrets (Telegram token/chat id) are read from environment "
               "variables -- see .env.example.",
    )
    parser.add_argument(
        "--config", "-c", metavar="PATH",
        help="path to config.yaml (default: ./config.yaml if present, else built-in defaults)")
    parser.add_argument(
        "--output", "-o", choices=OUTPUT_MODES, default="text",
        help="output mode: human-readable text or machine-readable JSON on stdout")
    parser.add_argument(
        "--report", metavar="PATH|FORMAT",
        help="write an HTML status report to PATH (or use '--report html' for "
             f"./{DEFAULT_REPORT_NAME})")
    parser.add_argument(
        "--once", action="store_true",
        help="perform exactly one check pass even if schedule.mode=daemon")
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="enable DEBUG console logging")
    parser.add_argument(
        "--dry-run", action="store_true",
        help="run all checks and produce output, but do not dispatch alerts "
             "or touch cooldown state")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def resolve_report_path(value: str) -> Path:
    """Turn the ``--report`` argument into a concrete file path."""
    if value.strip().lower() == "html":
        return Path(DEFAULT_REPORT_NAME)
    return Path(value)


def collect_results(cfg: Config, report: CheckReport) -> None:
    """Run every enabled check area and append its results to *report*."""
    if cfg.system.enabled:
        report.results.extend(run_check("system", run_system_checks, cfg))
    if cfg.services.enabled:
        report.results.extend(run_check("services", run_service_checks, cfg))
    if cfg.network.enabled:
        report.results.extend(run_check("network", run_network_checks, cfg))
    if cfg.security.enabled:
        report.results.extend(run_check("security", run_security_check, cfg))


def build_channels(cfg: Config, hostname: str) -> List[AlertChannel]:
    """Instantiate the configured alert channels (enabled ones only)."""
    channels: List[AlertChannel] = []
    if cfg.alerts.console.enabled:
        channels.append(ConsoleChannel(enabled=True))
    channels.append(TelegramChannel(cfg.alerts.telegram, hostname=hostname))
    return [c for c in channels if c.enabled]


def _safe_print(line: str) -> None:
    """Print *line* without ever crashing on a console that cannot encode it.

    Windows consoles may use a legacy code page (cp1252 and friends); a
    mount point, hostname or message containing characters outside it would
    otherwise raise ``UnicodeEncodeError`` and abort the whole report with a
    traceback.  The line is retried with replacement characters instead --
    lossy display beats a crashed monitoring pass.
    """
    try:
        print(line)
    except UnicodeEncodeError:
        encoding = getattr(sys.stdout, "encoding", None) or "utf-8"
        safe = line.encode(encoding, errors="replace").decode(encoding)
        print(safe)


def print_text_report(report: CheckReport, dispatch: Optional[DispatchSummary]) -> None:
    """Human-readable report on stdout."""
    started = report.started_at.strftime("%Y-%m-%d %H:%M:%SZ")
    _safe_print(f"LinTest {__version__} | host {report.hostname} | {started}")
    _safe_print("-" * 78)
    for r in report.results:
        mark = _SEV_MARK.get(r.severity.value, "?")
        subject = f"[{r.subject}]" if r.subject else ""
        _safe_print(f" {mark} {r.severity.value:<8} {r.check:<18} {subject:<22} {r.message}")
    _safe_print("-" * 78)

    summary = report.to_dict()["summary"]
    counts = (f"{summary['ok']} ok, {summary['warnings']} warning(s), "
              f"{summary['criticals']} critical, {summary['errors']} error(s) "
              f"in {report.duration_seconds:.1f}s")
    if dispatch is not None:
        d = dispatch.to_dict()
        counts += (f" | alerts sent: {d['sent']}, suppressed: {d['suppressed']}, "
                   f"recovered: {d['recovered']}")
    _safe_print(f"Result: {report.worst.value} ({counts}) | exit code {report.exit_code}")


def run_pass(cfg: Config, output: str, report_arg: Optional[str], dispatch: bool) -> int:
    """Execute one full check pass and return the process exit code."""
    report = CheckReport(config_path=str(cfg.config_path) if cfg.config_path else None)
    collect_results(cfg, report)
    report.finish()

    dispatch_summary: Optional[DispatchSummary] = None
    channels = build_channels(cfg, report.hostname)
    if channels:
        manager = AlertManager(
            channels,
            cooldown_minutes=cfg.alerts.cooldown_minutes,
            send_recovery=cfg.alerts.send_recovery,
        )
        if dispatch:
            dispatch_summary = manager.dispatch(report.results)
            for alert in dispatch_summary.sent:
                logger.info("alert sent: %s", alert.label())
            for alert in dispatch_summary.recovered:
                logger.info("recovery sent: %s", alert.label())
            if dispatch_summary.suppressed:
                logger.info("%d alert(s) suppressed by cooldown",
                            len(dispatch_summary.suppressed))
        else:
            logger.info("dry run: alert dispatch skipped (%d problem(s) found)",
                        len(report.problems))
    elif report.problems:
        logger.warning("%d problem(s) found but no alert channel is enabled",
                       len(report.problems))

    if output == "json":
        write_json_report(report, dispatch_summary)
    else:
        print_text_report(report, dispatch_summary)

    if report_arg:
        try:
            path = write_html_report(report, str(resolve_report_path(report_arg)),
                                     dispatch_summary)
            logger.info("HTML report written to %s", path)
        except OSError as exc:
            logger.error("could not write HTML report: %s", exc)

    return report.exit_code


def run_daemon(cfg: Config, args: argparse.Namespace) -> int:
    """Loop forever, sleeping between passes (``schedule.mode: daemon``)."""
    logger.info("daemon mode: check pass every %d second(s)",
                cfg.schedule.interval_seconds)
    while True:
        try:
            run_pass(cfg, args.output, args.report, dispatch=not args.dry_run)
        except Exception:  # noqa: BLE001 -- the loop must survive anything
            logger.exception("check pass failed; retrying next interval")
        time.sleep(cfg.schedule.interval_seconds)


def main(argv: Optional[Sequence[str]] = None) -> int:
    """CLI entry point.  Returns the process exit code."""
    args = build_parser().parse_args(argv)

    try:
        cfg = load_config(args.config)
    except ConfigError as exc:
        print(f"Configuration error:\n{exc}", file=sys.stderr)
        return 2

    setup_logging(cfg.logging, verbose=args.verbose)
    logger.debug("config: %s", cfg.config_path or "built-in defaults")

    if args.once or cfg.schedule.mode != "daemon":
        try:
            return run_pass(cfg, args.output, args.report, dispatch=not args.dry_run)
        except KeyboardInterrupt:
            logger.info("interrupted")
            return 130

    try:
        return run_daemon(cfg, args)
    except KeyboardInterrupt:
        logger.info("daemon stopped")
        return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
