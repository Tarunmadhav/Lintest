"""Tests for alert channels, cooldown logic and recovery messages."""

from __future__ import annotations

import io
import json
from datetime import datetime, timedelta, timezone
from typing import List

from lintest.alerts.base import Alert, alert_from_result
from lintest.alerts.console import ConsoleChannel
from lintest.alerts.manager import AlertManager
from lintest.alerts.telegram import TelegramChannel
from lintest.models import Severity, critical, warning


class FakeClock:
    """Controllable clock so cooldown windows can be advanced in tests."""

    def __init__(self, start: datetime) -> None:
        self._now = start

    def __call__(self) -> datetime:
        return self._now

    def advance(self, minutes: float = 0.0, seconds: float = 0.0) -> None:
        self._now += timedelta(minutes=minutes, seconds=seconds)


class RecordingChannel:
    """Minimal channel that records every delivered alert."""

    name = "recording"

    def __init__(self) -> None:
        self.sent: List[Alert] = []

    def send(self, alert: Alert) -> bool:
        self.sent.append(alert)
        return True


def make_manager(tmp_path, clock, cooldown_minutes=30, send_recovery=True, channels=None):
    channels = channels if channels is not None else [RecordingChannel()]
    manager = AlertManager(
        channels,
        cooldown_minutes=cooldown_minutes,
        send_recovery=send_recovery,
        state_path=tmp_path / "state.json",
        clock=clock,
    )
    return manager, channels[0]


def cpu_critical(percent=95.0):
    return critical("system.cpu", f"CPU usage {percent}%", "cpu", percent=percent)


class TestAlertBasics:
    def test_alert_key_format(self):
        alert = alert_from_result(cpu_critical())
        assert alert.key == "system.cpu::cpu"

    def test_alert_from_result_carries_fields(self):
        alert = alert_from_result(cpu_critical())
        assert alert.severity is Severity.CRITICAL
        assert alert.check == "system.cpu"
        assert alert.subject == "cpu"


class TestConsoleChannel:
    def test_send_writes_formatted_line(self):
        stream = io.StringIO()
        channel = ConsoleChannel(enabled=True, stream=stream)
        alert = alert_from_result(cpu_critical())
        assert channel.send(alert) is True
        out = stream.getvalue()
        assert "CRITICAL" in out and "system.cpu" in out

    def test_disabled_channel_flag(self):
        assert ConsoleChannel(enabled=False).enabled is False


class TestTelegramChannel:
    def test_disabled_without_env(self, monkeypatch):
        from lintest.config import TelegramConfig

        monkeypatch.delenv("LINTEST_TELEGRAM_TOKEN", raising=False)
        monkeypatch.delenv("LINTEST_TELEGRAM_CHAT_ID", raising=False)
        channel = TelegramChannel(TelegramConfig())
        assert channel.available is False

    def test_format_escapes_html(self, monkeypatch):
        from lintest.config import TelegramConfig

        monkeypatch.setenv("LINTEST_TELEGRAM_TOKEN", "t")
        monkeypatch.setenv("LINTEST_TELEGRAM_CHAT_ID", "1")
        channel = TelegramChannel(TelegramConfig(), hostname="srv1")
        alert = Alert(Severity.CRITICAL, "system.cpu", "cpu", "usage <b>bad</b>")
        text = channel._format(alert)
        assert "&lt;b&gt;" in text
        assert "srv1" in text


class TestCooldownAndRecovery:
    def test_first_problem_sends(self, tmp_path):
        clock = FakeClock(datetime(2025, 7, 15, 12, 0, tzinfo=timezone.utc))
        manager, channel = make_manager(tmp_path, clock)
        summary = manager.dispatch([cpu_critical()])
        assert len(summary.sent) == 1
        assert len(channel.sent) == 1
        assert channel.sent[0].severity is Severity.CRITICAL

    def test_second_run_within_cooldown_suppressed(self, tmp_path):
        clock = FakeClock(datetime(2025, 7, 15, 12, 0, tzinfo=timezone.utc))
        manager, channel = make_manager(tmp_path, clock)
        manager.dispatch([cpu_critical()])
        clock.advance(minutes=10)
        summary = manager.dispatch([cpu_critical()])
        assert summary.suppressed and not summary.sent
        assert len(channel.sent) == 1  # only the original alert

    def test_alert_resent_after_cooldown(self, tmp_path):
        clock = FakeClock(datetime(2025, 7, 15, 12, 0, tzinfo=timezone.utc))
        manager, channel = make_manager(tmp_path, clock, cooldown_minutes=30)
        manager.dispatch([cpu_critical()])
        clock.advance(minutes=31)
        summary = manager.dispatch([cpu_critical()])
        assert len(summary.sent) == 1
        assert len(channel.sent) == 2

    def test_recovery_sent_when_cleared(self, tmp_path):
        clock = FakeClock(datetime(2025, 7, 15, 12, 0, tzinfo=timezone.utc))
        manager, channel = make_manager(tmp_path, clock)
        manager.dispatch([cpu_critical()])
        clock.advance(minutes=5)
        summary = manager.dispatch([])  # problem cleared
        assert len(summary.recovered) == 1
        recovery = channel.sent[-1]
        assert recovery.severity is Severity.INFO
        assert "RECOVERED" in recovery.message

    def test_recovery_can_be_disabled(self, tmp_path):
        clock = FakeClock(datetime(2025, 7, 15, 12, 0, tzinfo=timezone.utc))
        manager, channel = make_manager(tmp_path, clock, send_recovery=False)
        manager.dispatch([cpu_critical()])
        clock.advance(minutes=5)
        summary = manager.dispatch([])
        assert not summary.recovered
        # The key is still marked idle: a new occurrence alerts immediately.
        clock.advance(minutes=1)
        again = manager.dispatch([cpu_critical()])
        assert len(again.sent) == 1

    def test_realert_after_recovery(self, tmp_path):
        clock = FakeClock(datetime(2025, 7, 15, 12, 0, tzinfo=timezone.utc))
        manager, channel = make_manager(tmp_path, clock)
        manager.dispatch([cpu_critical()])
        clock.advance(minutes=5)
        manager.dispatch([])  # recovered
        clock.advance(minutes=1)
        summary = manager.dispatch([cpu_critical()])  # problem returns
        assert len(summary.sent) == 1

    def test_different_subjects_tracked_separately(self, tmp_path):
        clock = FakeClock(datetime(2025, 7, 15, 12, 0, tzinfo=timezone.utc))
        manager, channel = make_manager(tmp_path, clock)
        manager.dispatch([
            cpu_critical(),
            critical("system.disk", "disk / full", "/"),
        ])
        clock.advance(minutes=1)
        summary = manager.dispatch([cpu_critical()])  # disk ok, cpu still firing
        assert len(summary.suppressed) == 1
        assert len(summary.recovered) == 1

    def test_warnings_also_alert_and_cooldown(self, tmp_path):
        """WARNINGs are alertable events (just not exit-code-affecting)."""
        clock = FakeClock(datetime(2025, 7, 15, 12, 0, tzinfo=timezone.utc))
        manager, channel = make_manager(tmp_path, clock)
        summary = manager.dispatch([warning("system.ram", "RAM close to limit", "ram")])
        assert len(summary.sent) == 1
        assert channel.sent[0].severity is Severity.WARNING
        clock.advance(minutes=5)
        again = manager.dispatch([warning("system.ram", "RAM close to limit", "ram")])
        assert again.suppressed and not again.sent


class TestStatePersistence:
    def test_state_survives_new_manager(self, tmp_path):
        clock = FakeClock(datetime(2025, 7, 15, 12, 0, tzinfo=timezone.utc))
        manager, _ = make_manager(tmp_path, clock)
        manager.dispatch([cpu_critical()])

        clock.advance(minutes=5)
        manager2, _ = make_manager(tmp_path, clock)  # fresh process, same state file
        summary = manager2.dispatch([cpu_critical()])
        assert summary.suppressed, "cooldown must survive process restarts"

    def test_no_delivery_does_not_arm_cooldown(self, tmp_path):
        class DeadChannel:
            name = "dead"

            def send(self, alert: Alert) -> bool:
                return False

        clock = FakeClock(datetime(2025, 7, 15, 12, 0, tzinfo=timezone.utc))
        manager, _ = make_manager(tmp_path, clock, channels=[DeadChannel()])
        summary = manager.dispatch([cpu_critical()])
        assert not summary.sent
        assert not summary.suppressed

        # Replace with a working channel; the alert must go out immediately.
        clock.advance(minutes=1)
        manager2, channel = make_manager(tmp_path, clock)
        again = manager2.dispatch([cpu_critical()])
        assert len(again.sent) == 1
        assert len(channel.sent) == 1

    def test_state_file_is_json(self, tmp_path):
        clock = FakeClock(datetime(2025, 7, 15, 12, 0, tzinfo=timezone.utc))
        manager, _ = make_manager(tmp_path, clock)
        manager.dispatch([cpu_critical()])
        data = json.loads((tmp_path / "state.json").read_text(encoding="utf-8"))
        assert data["version"] == 1
        assert "system.cpu::cpu" in data["alerts"]
        assert data["alerts"]["system.cpu::cpu"]["firing"] is True
