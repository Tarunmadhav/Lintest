"""Delivery semantics: failed sends must never silence future alerts."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import List

from lintest.alerts.base import Alert
from lintest.alerts.manager import AlertManager
from lintest.models import Severity, critical


class Clock:
    def __init__(self, start: datetime = datetime(2025, 7, 15, 12, 0, tzinfo=timezone.utc)):
        self.now = start

    def __call__(self) -> datetime:
        return self.now

    def advance(self, minutes: float = 0) -> None:
        self.now += timedelta(minutes=minutes)


class FlakyChannel:
    """Delivers only when ``healthy``; records every attempt."""

    name = "flaky"

    def __init__(self, healthy: bool = True):
        self.healthy = healthy
        self.attempts: List[Alert] = []

    def send(self, alert: Alert) -> bool:
        self.attempts.append(alert)
        return self.healthy


def cpu():
    return critical("system.cpu", "CPU 99%", "cpu")


def manager(tmp_path, clock, channels, cooldown=30, send_recovery=True) -> AlertManager:
    return AlertManager(channels, cooldown_minutes=cooldown, send_recovery=send_recovery,
                        state_path=tmp_path / "state.json", clock=clock)


class TestAlertRetry:
    def test_failed_send_is_retried_immediately_on_the_next_run(self, tmp_path):
        clock = Clock()
        channel = FlakyChannel(healthy=False)
        mgr = manager(tmp_path, clock, [channel])
        assert mgr.dispatch([cpu()]).sent == []

        clock.advance(minutes=1)
        channel.healthy = True
        summary = mgr.dispatch([cpu()])
        assert len(summary.sent) == 1
        assert len(channel.attempts) == 2

    def test_failed_send_leaves_no_firing_entry(self, tmp_path):
        state = tmp_path / "state.json"
        mgr = manager(tmp_path, Clock(), [FlakyChannel(healthy=False)])
        mgr.dispatch([cpu()])
        assert json.loads(state.read_text(encoding="utf-8"))["alerts"] == {}

    def test_arming_happens_only_after_a_successful_send(self, tmp_path):
        clock = Clock()
        channel = FlakyChannel(healthy=False)
        mgr = manager(tmp_path, clock, [channel])
        mgr.dispatch([cpu()])
        channel.healthy = True
        mgr.dispatch([cpu()])
        clock.advance(minutes=5)
        # Now the cooldown is armed, so the third run is suppressed.
        assert len(mgr.dispatch([cpu()]).suppressed) == 1

    def test_partial_delivery_counts_as_delivered(self, tmp_path):
        class Dead:
            name = "dead"

            def send(self, alert: Alert) -> bool:
                return False

        ok = FlakyChannel(healthy=True)
        mgr = manager(tmp_path, Clock(), [Dead(), ok])
        assert len(mgr.dispatch([cpu()]).sent) == 1
        assert len(ok.attempts) == 1

    def test_only_the_undelivered_problem_is_retried(self, tmp_path):
        clock = Clock()
        channel = FlakyChannel(healthy=True)
        mgr = manager(tmp_path, clock, [channel])
        mgr.dispatch([cpu(), critical("system.ram", "RAM 99%", "ram")])

        channel.healthy = False
        clock.advance(minutes=1)
        state = json.loads((tmp_path / "state.json").read_text(encoding="utf-8"))["alerts"]
        assert state["system.cpu::cpu"]["firing"] is True
        assert state["system.ram::ram"]["firing"] is True


class TestRecoveryDelivery:
    def test_recovery_is_retried_when_delivery_fails(self, tmp_path):
        clock = Clock()
        channel = FlakyChannel(healthy=True)
        mgr = manager(tmp_path, clock, [channel])
        mgr.dispatch([cpu()])

        channel.healthy = False
        clock.advance(minutes=5)
        assert mgr.dispatch([]).recovered == []
        # Still marked firing, so the notification is not silently dropped.
        state = json.loads((tmp_path / "state.json").read_text(encoding="utf-8"))["alerts"]
        assert state["system.cpu::cpu"]["firing"] is True

        channel.healthy = True
        clock.advance(minutes=1)
        summary = mgr.dispatch([])
        assert len(summary.recovered) == 1
        assert "RECOVERED" in summary.recovered[0].message
        state = json.loads((tmp_path / "state.json").read_text(encoding="utf-8"))["alerts"]
        assert state["system.cpu::cpu"]["firing"] is False

    def test_recovery_is_not_sent_twice(self, tmp_path):
        clock = Clock()
        channel = FlakyChannel()
        mgr = manager(tmp_path, clock, [channel])
        mgr.dispatch([cpu()])
        clock.advance(minutes=5)
        assert len(mgr.dispatch([]).recovered) == 1
        clock.advance(minutes=5)
        assert mgr.dispatch([]).recovered == []

    def test_recovery_disabled_clears_state_without_delivering(self, tmp_path):
        clock = Clock()
        channel = FlakyChannel()
        mgr = manager(tmp_path, clock, [channel], send_recovery=False)
        mgr.dispatch([cpu()])
        clock.advance(minutes=5)
        assert mgr.dispatch([]).recovered == []
        state = json.loads((tmp_path / "state.json").read_text(encoding="utf-8"))["alerts"]
        assert state["system.cpu::cpu"]["firing"] is False

    def test_recovery_quotes_the_original_message(self, tmp_path):
        clock = Clock()
        channel = FlakyChannel()
        mgr = manager(tmp_path, clock, [channel])
        mgr.dispatch([critical("system.cpu", "CPU 99% on 8 cores", "cpu")])
        clock.advance(minutes=5)
        recovered = mgr.dispatch([]).recovered[0]
        assert "CPU 99% on 8 cores" in recovered.message
        assert recovered.severity is Severity.INFO

    def test_alert_after_recovery_is_delivered_again(self, tmp_path):
        clock = Clock()
        channel = FlakyChannel()
        mgr = manager(tmp_path, clock, [channel])
        mgr.dispatch([cpu()])
        clock.advance(minutes=5)
        mgr.dispatch([])
        clock.advance(minutes=1)
        assert len(mgr.dispatch([cpu()]).sent) == 1
        assert len(channel.attempts) == 3


class TestSummaryAccounting:
    def test_summary_counts_match_the_lists(self, tmp_path):
        clock = Clock()
        channel = FlakyChannel()
        mgr = manager(tmp_path, clock, [channel])
        summary = mgr.dispatch([cpu(), critical("system.ram", "RAM high", "ram")])
        assert summary.to_dict() == {"sent": 2, "suppressed": 0, "recovered": 0}

    def test_suppressed_then_recovered_accounting(self, tmp_path):
        clock = Clock()
        mgr = manager(tmp_path, clock, [FlakyChannel()])
        mgr.dispatch([cpu(), critical("system.ram", "RAM high", "ram")])
        clock.advance(minutes=1)
        summary = mgr.dispatch([cpu()])
        assert summary.to_dict() == {"sent": 0, "suppressed": 1, "recovered": 1}

    def test_problems_are_not_recovered_while_still_present(self, tmp_path):
        clock = Clock()
        mgr = manager(tmp_path, clock, [FlakyChannel()])
        mgr.dispatch([cpu()])
        clock.advance(minutes=1)
        assert mgr.dispatch([cpu()]).recovered == []
