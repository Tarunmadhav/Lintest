"""CLI behaviour: exit codes, output modes, reports and dry runs.

Every test disables the real check areas and injects synthetic results, so the
suite never probes the host it runs on.
"""

from __future__ import annotations

import io
import json
import sys
from pathlib import Path

import pytest

import lintest.main as main_mod
from lintest.config import (
    AlertsConfig,
    Config,
    ConsoleConfig,
    LoggingConfig,
    ScheduleConfig,
    SystemConfig,
    TelegramConfig,
)
from lintest.models import CheckReport, Severity, critical, ok, warning

BASE_CONFIG = """
schedule:
  mode: {mode}
  interval_seconds: 10
system:
  enabled: true
services:
  enabled: false
network:
  enabled: false
security:
  enabled: false
alerts:
  cooldown_minutes: 30
  console:
    enabled: false
  telegram:
    enabled: false
logging:
  level: INFO
  file: ""
"""


def write_config(tmp_path: Path, mode: str = "timer") -> str:
    path = tmp_path / "config.yaml"
    path.write_text(BASE_CONFIG.format(mode=mode), encoding="utf-8")
    return str(path)


def isolate_state(monkeypatch, tmp_path) -> Path:
    state = tmp_path / "state.json"
    monkeypatch.setenv("LINTEST_STATE_FILE", str(state))
    return state


def fake_checks(monkeypatch, results):
    monkeypatch.setattr(main_mod, "run_system_checks", lambda cfg: list(results))
    monkeypatch.setattr(main_mod, "run_service_checks", lambda cfg: [])
    monkeypatch.setattr(main_mod, "run_network_checks", lambda cfg: [])
    monkeypatch.setattr(main_mod, "run_security_check", lambda cfg: [])


class TestArgumentParsing:
    def test_version_exits_zero(self, capsys):
        with pytest.raises(SystemExit) as exc:
            main_mod.main(["--version"])
        assert exc.value.code == 0
        assert "lintest" in capsys.readouterr().out

    def test_unknown_flag_exits_two(self):
        with pytest.raises(SystemExit) as exc:
            main_mod.main(["--nope"])
        assert exc.value.code == 2

    def test_report_html_maps_to_default_name(self):
        assert main_mod.resolve_report_path("html") == Path(main_mod.DEFAULT_REPORT_NAME)
        assert main_mod.resolve_report_path("HTML") == Path(main_mod.DEFAULT_REPORT_NAME)
        assert main_mod.resolve_report_path("out/report.html") == Path("out/report.html")


class TestExitCodes:
    def test_critical_result_exits_one(self, monkeypatch, tmp_path, capsys):
        isolate_state(monkeypatch, tmp_path)
        fake_checks(monkeypatch, [critical("system.cpu", "CPU 99%", "cpu")])
        code = main_mod.main(["--config", write_config(tmp_path), "--dry-run"])
        assert code == 1
        assert "exit code 1" in capsys.readouterr().out

    def test_warning_only_exits_zero(self, monkeypatch, tmp_path):
        isolate_state(monkeypatch, tmp_path)
        fake_checks(monkeypatch, [warning("system.ram", "RAM high", "ram")])
        assert main_mod.main(["--config", write_config(tmp_path)]) == 0

    def test_all_ok_exits_zero(self, monkeypatch, tmp_path):
        isolate_state(monkeypatch, tmp_path)
        fake_checks(monkeypatch, [ok("system.cpu", "fine", "cpu")])
        assert main_mod.main(["--config", write_config(tmp_path)]) == 0

    def test_config_error_exits_two(self, tmp_path, capsys):
        bad = tmp_path / "bad.yaml"
        bad.write_text("thresholds:\n  cpu_percent: 900\n", encoding="utf-8")
        assert main_mod.main(["--config", str(bad)]) == 2
        assert "Configuration error" in capsys.readouterr().err

    def test_missing_config_file_exits_two(self, tmp_path):
        assert main_mod.main(["--config", str(tmp_path / "nope.yaml")]) == 2

    def test_keyboard_interrupt_exits_130(self, monkeypatch, tmp_path):
        def interrupted(*a, **k):
            raise KeyboardInterrupt
        monkeypatch.setattr(main_mod, "run_pass", interrupted)
        assert main_mod.main(["--config", write_config(tmp_path)]) == 130

    def test_once_flag_wins_over_daemon_mode(self, monkeypatch, tmp_path):
        monkeypatch.setattr(main_mod, "run_daemon",
                            lambda cfg, args: pytest.fail("--once must not enter the daemon loop"))
        fake_checks(monkeypatch, [ok("system.cpu", "fine", "cpu")])
        isolate_state(monkeypatch, tmp_path)
        assert main_mod.main(["--config", write_config(tmp_path, mode="daemon"), "--once"]) == 0

    def test_timer_mode_never_enters_the_daemon_loop(self, monkeypatch, tmp_path):
        monkeypatch.setattr(main_mod, "run_daemon",
                            lambda cfg, args: pytest.fail("timer mode must not daemonise"))
        fake_checks(monkeypatch, [ok("system.cpu", "fine", "cpu")])
        isolate_state(monkeypatch, tmp_path)
        assert main_mod.main(["--config", write_config(tmp_path)]) == 0

    def test_daemon_mode_stops_cleanly_on_interrupt(self, monkeypatch, tmp_path):
        monkeypatch.setattr(main_mod, "run_pass", lambda *a, **k: 0)

        def sleep(*a, **k):
            raise KeyboardInterrupt
        monkeypatch.setattr(main_mod.time, "sleep", sleep)
        assert main_mod.main(["--config", write_config(tmp_path, mode="daemon")]) == 0


class TestOutputModes:
    def test_json_mode_emits_parseable_json(self, monkeypatch, tmp_path, capsys):
        isolate_state(monkeypatch, tmp_path)
        fake_checks(monkeypatch, [critical("system.cpu", "CPU 99%", "cpu"),
                                  ok("system.ram", "fine", "ram")])
        assert main_mod.main(["--config", write_config(tmp_path), "--output", "json", "--dry-run"]) == 1
        payload = json.loads(capsys.readouterr().out)
        assert payload["summary"]["criticals"] == 1
        assert payload["summary"]["exit_code"] == 1
        assert payload["summary"]["worst"] == "CRITICAL"
        assert {r["check"] for r in payload["results"]} == {"system.cpu", "system.ram"}

    def test_json_mode_reports_alerts(self, monkeypatch, tmp_path, capsys):
        isolate_state(monkeypatch, tmp_path)
        fake_checks(monkeypatch, [critical("system.cpu", "CPU 99%", "cpu")])
        cfg = Config(
            system=SystemConfig(enabled=True),
            alerts=AlertsConfig(console=ConsoleConfig(enabled=True),
                                telegram=TelegramConfig(enabled=False)),
        )
        main_mod.run_pass(cfg, "json", None, dispatch=True)
        payload = json.loads(capsys.readouterr().out)
        assert payload["alerts"]["sent"][0]["check"] == "system.cpu"

    def test_html_report_is_written_and_escaped(self, monkeypatch, tmp_path):
        isolate_state(monkeypatch, tmp_path)
        target = tmp_path / "report.html"
        fake_checks(monkeypatch, [critical("system.cpu", "CPU <script>alert(1)</script>", "cpu")])
        code = main_mod.main(["--config", write_config(tmp_path),
                              "--report", str(target), "--dry-run"])
        assert code == 1
        html = target.read_text(encoding="utf-8")
        assert "<script>" not in html
        assert "&lt;script&gt;" in html
        assert "CRITICAL" in html

    def test_unwritable_html_report_does_not_break_the_run(self, monkeypatch, tmp_path):
        isolate_state(monkeypatch, tmp_path)
        fake_checks(monkeypatch, [ok("system.cpu", "fine", "cpu")])
        code = main_mod.main(["--config", write_config(tmp_path),
                              "--report", str(tmp_path), "--dry-run"])
        assert code == 0  # the report failure is logged, not fatal

    def test_text_report_lists_every_result(self, monkeypatch, tmp_path, capsys):
        isolate_state(monkeypatch, tmp_path)
        fake_checks(monkeypatch, [ok("system.cpu", "fine", "cpu"),
                                  warning("system.ram", "warm", "ram"),
                                  critical("system.disk", "full", "/")])
        main_mod.main(["--config", write_config(tmp_path), "--dry-run"])
        out = capsys.readouterr().out
        assert "system.cpu" in out and "system.ram" in out and "system.disk" in out
        assert "| exit code 1" in out


class TestDryRunAndState:
    def test_dry_run_does_not_touch_cooldown_state(self, monkeypatch, tmp_path):
        state = isolate_state(monkeypatch, tmp_path)
        fake_checks(monkeypatch, [critical("system.cpu", "CPU 99%", "cpu")])
        main_mod.main(["--config", write_config(tmp_path), "--dry-run"])
        assert not state.exists()

    def test_real_run_arms_the_cooldown(self, monkeypatch, tmp_path):
        state = isolate_state(monkeypatch, tmp_path)
        fake_checks(monkeypatch, [critical("system.cpu", "CPU 99%", "cpu")])
        cfg = Config(
            system=SystemConfig(enabled=True),
            alerts=AlertsConfig(console=ConsoleConfig(enabled=True),
                                telegram=TelegramConfig(enabled=False)),
        )
        main_mod.run_pass(cfg, "text", None, dispatch=True)
        assert json.loads(state.read_text(encoding="utf-8"))["alerts"]["system.cpu::cpu"]["firing"] is True

    def test_dry_run_with_channels_logs_and_skips_dispatch(self, monkeypatch, tmp_path, caplog):
        state = isolate_state(monkeypatch, tmp_path)
        fake_checks(monkeypatch, [critical("system.cpu", "CPU 99%", "cpu")])
        cfg = Config(
            system=SystemConfig(enabled=True),
            alerts=AlertsConfig(console=ConsoleConfig(enabled=True),
                                telegram=TelegramConfig(enabled=False)),
        )
        with caplog.at_level("INFO", logger="lintest.main"):
            assert main_mod.run_pass(cfg, "text", None, dispatch=False) == 1
        assert "dry run: alert dispatch skipped (1 problem(s) found)" in caplog.text
        assert not state.exists()

    def test_suppressed_alerts_are_logged(self, monkeypatch, tmp_path, caplog):
        isolate_state(monkeypatch, tmp_path)
        fake_checks(monkeypatch, [critical("system.cpu", "CPU 99%", "cpu")])
        cfg = Config(
            system=SystemConfig(enabled=True),
            alerts=AlertsConfig(console=ConsoleConfig(enabled=True),
                                telegram=TelegramConfig(enabled=False)),
        )
        main_mod.run_pass(cfg, "text", None, dispatch=True)
        with caplog.at_level("INFO", logger="lintest.main"):
            main_mod.run_pass(cfg, "text", None, dispatch=True)
        assert "suppressed by cooldown" in caplog.text

    def test_no_channel_enabled_is_warned_about(self, monkeypatch, tmp_path, caplog):
        isolate_state(monkeypatch, tmp_path)
        fake_checks(monkeypatch, [critical("system.cpu", "CPU 99%", "cpu")])
        cfg = Config(system=SystemConfig(enabled=True),
                     alerts=AlertsConfig(console=ConsoleConfig(enabled=False),
                                         telegram=TelegramConfig(enabled=False)))
        with caplog.at_level("WARNING", logger="lintest.main"):
            assert main_mod.run_pass(cfg, "text", None, dispatch=True) == 1
        assert "no alert channel is enabled" in caplog.text

    def test_second_run_without_a_channel_still_reports(self, monkeypatch, tmp_path, capsys):
        isolate_state(monkeypatch, tmp_path)
        fake_checks(monkeypatch, [critical("system.cpu", "CPU 99%", "cpu")])
        cfg = Config(system=SystemConfig(enabled=True), schedule=ScheduleConfig(),
                     alerts=AlertsConfig(console=ConsoleConfig(enabled=False),
                                         telegram=TelegramConfig(enabled=False)))
        assert main_mod.run_pass(cfg, "text", None, dispatch=True) == 1
        assert "exit code 1" in capsys.readouterr().out


class TestChannelBuilding:
    def test_console_only(self):
        cfg = Config(alerts=AlertsConfig(console=ConsoleConfig(enabled=True),
                                         telegram=TelegramConfig(enabled=False)))
        channels = main_mod.build_channels(cfg, "host")
        assert [c.name for c in channels] == ["console"]

    def test_telegram_needs_credentials(self, monkeypatch):
        monkeypatch.delenv("LINTEST_TELEGRAM_TOKEN", raising=False)
        monkeypatch.delenv("LINTEST_TELEGRAM_CHAT_ID", raising=False)
        cfg = Config(alerts=AlertsConfig(console=ConsoleConfig(enabled=False),
                                         telegram=TelegramConfig(enabled=True)))
        assert main_mod.build_channels(cfg, "host") == []

    def test_telegram_enabled_with_credentials(self, monkeypatch):
        monkeypatch.setenv("LINTEST_TELEGRAM_TOKEN", "token")
        monkeypatch.setenv("LINTEST_TELEGRAM_CHAT_ID", "42")
        cfg = Config(alerts=AlertsConfig(console=ConsoleConfig(enabled=False),
                                         telegram=TelegramConfig(enabled=True)))
        channels = main_mod.build_channels(cfg, "host")
        assert [c.name for c in channels] == ["telegram"]
        assert channels[0].available is True

    def test_console_and_telegram_together(self, monkeypatch):
        monkeypatch.setenv("LINTEST_TELEGRAM_TOKEN", "token")
        monkeypatch.setenv("LINTEST_TELEGRAM_CHAT_ID", "42")
        cfg = Config(alerts=AlertsConfig(console=ConsoleConfig(enabled=True),
                                         telegram=TelegramConfig(enabled=True)))
        assert [c.name for c in main_mod.build_channels(cfg, "host")] == ["console", "telegram"]


class TestLoggingSetup:
    def test_log_directory_is_created(self, tmp_path, monkeypatch):
        from lintest.utils.logging_setup import setup_logging
        log_file = tmp_path / "nested" / "lintest.log"
        setup_logging(LoggingConfig(level="INFO", file=str(log_file)))
        import logging
        logging.getLogger("lintest").info("hello")
        assert log_file.is_file()
        assert "hello" in log_file.read_text(encoding="utf-8")

    def test_unwritable_log_file_is_not_fatal(self, monkeypatch, tmp_path):
        from lintest.utils import logging_setup
        monkeypatch.setattr(logging_setup.Path, "mkdir",
                            lambda *a, **k: (_ for _ in ()).throw(OSError("read-only fs")))
        logging_setup.setup_logging(LoggingConfig(level="INFO", file=str(tmp_path / "x" / "y.log")))
        import logging
        handlers = logging.getLogger("lintest").handlers
        assert len(handlers) == 1  # console only

    def test_verbose_flag_lowers_the_threshold(self):
        import logging

        from lintest.utils.logging_setup import setup_logging
        setup_logging(LoggingConfig(level="WARNING", file=""), verbose=True)
        assert logging.getLogger("lintest").handlers[0].level == logging.DEBUG
        setup_logging(LoggingConfig(level="WARNING", file=""), verbose=False)
        assert logging.getLogger("lintest").handlers[0].level == logging.WARNING

    def test_logging_severity_helpers(self):
        assert Severity.OK.is_problem() is False
        assert Severity.INFO.is_problem() is False
        assert Severity.WARNING.is_problem() is True
        assert Severity.CRITICAL.is_problem() is True
        assert Severity.ERROR.is_problem() is True
        assert Severity.CRITICAL.rank > Severity.WARNING.rank > Severity.OK.rank


class TestConsoleEncoding:
    """A legacy console code page (cp1252 on Windows) must never abort the
    report: unencodable characters degrade to '?' instead of raising."""

    def test_text_report_survives_a_cp1252_console(self, monkeypatch):
        buf = io.BytesIO()
        stream = io.TextIOWrapper(buf, encoding="cp1252", newline="")
        monkeypatch.setattr(sys, "stdout", stream)

        report = CheckReport()
        report.results.append(ok("system.disk",
                                 "disk C:\\Users\\\u65e5\u672c\\ 50.0% used",
                                 "C:\\Users\\\u65e5\u672c"))
        report.finish()
        main_mod.print_text_report(report, None)  # must not raise
        stream.flush()

        text = buf.getvalue().decode("cp1252")
        assert "LinTest" in text
        assert "Result: OK" in text
        assert "50.0% used" in text  # the message survives, lossily
