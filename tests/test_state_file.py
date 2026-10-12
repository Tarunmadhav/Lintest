"""Alert state file: corruption tolerance, atomic writes, concurrency."""

from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timedelta, timezone
from typing import List

import pytest

from lintest.alerts.base import Alert
from lintest.alerts.manager import AlertManager
from lintest.models import critical


class Clock:
    def __init__(self, start: datetime):
        self.now = start

    def __call__(self) -> datetime:
        return self.now

    def advance(self, **kw):
        self.now += timedelta(**kw)


class Recorder:
    name = "recorder"

    def __init__(self, ok: bool = True):
        self.ok = ok
        self.sent: List[Alert] = []

    def send(self, alert: Alert) -> bool:
        self.sent.append(alert)
        return self.ok


def cpu_alert():
    return critical("system.cpu", "CPU high", "cpu")


def make_manager(path, clock, channels=None):
    return AlertManager(channels or [Recorder()], cooldown_minutes=30,
                        state_path=path, clock=clock)


START = datetime(2025, 7, 15, 12, 0, tzinfo=timezone.utc)


class TestCorruptState:
    """A broken state file must never abort a monitoring run."""

    @pytest.mark.parametrize("payload", [
        "{ not json at all",
        "",
        "\x00\x01binary",
    ])
    def test_unparseable_json_starts_fresh(self, tmp_path, payload):
        state = tmp_path / "state.json"
        state.write_text(payload, encoding="utf-8")
        manager = make_manager(state, Clock(START))
        summary = manager.dispatch([cpu_alert()])
        assert len(summary.sent) == 1
        assert json.loads(state.read_text(encoding="utf-8"))["alerts"]["system.cpu::cpu"]["firing"] is True

    @pytest.mark.parametrize("payload", [
        "[1, 2, 3]",
        '"just a string"',
        "42",
        "null",
    ])
    def test_wrong_top_level_type_starts_fresh(self, tmp_path, payload):
        """Regression: a JSON array used to raise AttributeError mid-run."""
        state = tmp_path / "state.json"
        state.write_text(payload, encoding="utf-8")
        manager = make_manager(state, Clock(START))
        assert len(manager.dispatch([cpu_alert()]).sent) == 1

    def test_alerts_section_of_wrong_type_starts_fresh(self, tmp_path):
        state = tmp_path / "state.json"
        state.write_text(json.dumps({"version": 1, "alerts": ["nope"]}), encoding="utf-8")
        manager = make_manager(state, Clock(START))
        assert len(manager.dispatch([cpu_alert()]).sent) == 1

    def test_malformed_entries_are_dropped_but_valid_ones_kept(self, tmp_path):
        state = tmp_path / "state.json"
        state.write_text(json.dumps({
            "version": 1,
            "alerts": {
                "system.ram::ram": {"last_sent": START.isoformat(), "firing": True},
                "system.cpu::cpu": "not an object",
                "system.disk::/": 17,
            },
        }), encoding="utf-8")
        manager = make_manager(state, Clock(START))
        assert set(manager._state) == {"system.ram::ram"}
        # The surviving entry still suppresses inside its cooldown.
        summary = manager.dispatch([critical("system.ram", "warm", "ram")])
        assert len(summary.suppressed) == 1

    def test_missing_version_field_is_tolerated(self, tmp_path):
        state = tmp_path / "state.json"
        state.write_text(json.dumps({"alerts": {}}), encoding="utf-8")
        assert make_manager(state, Clock(START)).dispatch([cpu_alert()]).sent


class TestHostileEntries:
    def test_non_string_timestamp_is_ignored(self, tmp_path):
        state = tmp_path / "state.json"
        state.write_text(json.dumps({"alerts": {"system.cpu::cpu": {
            "last_sent": 1234567890, "firing": True}}}), encoding="utf-8")
        summary = make_manager(state, Clock(START)).dispatch([cpu_alert()])
        assert len(summary.sent) == 1

    def test_garbage_timestamp_string_is_ignored(self, tmp_path):
        state = tmp_path / "state.json"
        state.write_text(json.dumps({"alerts": {"system.cpu::cpu": {
            "last_sent": "yesterday-ish", "firing": True}}}), encoding="utf-8")
        assert len(make_manager(state, Clock(START)).dispatch([cpu_alert()]).sent) == 1

    def test_naive_timestamp_is_treated_as_utc(self, tmp_path):
        state = tmp_path / "state.json"
        state.write_text(json.dumps({"alerts": {"system.cpu::cpu": {
            "last_sent": "2025-07-15T11:50:00", "firing": True}}}), encoding="utf-8")
        summary = make_manager(state, Clock(START)).dispatch([cpu_alert()])
        assert len(summary.suppressed) == 1

    def test_entry_without_firing_flag_does_not_suppress(self, tmp_path):
        state = tmp_path / "state.json"
        state.write_text(json.dumps({"alerts": {"system.cpu::cpu": {
            "last_sent": START.isoformat()}}}), encoding="utf-8")
        assert len(make_manager(state, Clock(START)).dispatch([cpu_alert()]).sent) == 1

    def test_object_injected_into_memory_state_does_not_crash(self, tmp_path):
        manager = make_manager(tmp_path / "state.json", Clock(START))
        manager._state["junk"] = "not a dict"          # noqa: SLF001 - simulating corruption
        manager._state["weird-key"] = {"firing": True}  # noqa: SLF001
        summary = manager.dispatch([])
        assert [a.check for a in summary.recovered] == ["weird-key"]


class TestStatePathSelection:
    def test_env_override_wins(self, monkeypatch, tmp_path):
        from lintest.alerts.manager import default_state_path
        target = tmp_path / "custom.json"
        monkeypatch.setenv("LINTEST_STATE_FILE", str(target))
        assert default_state_path() == target

    def test_falls_back_to_a_writable_location(self, monkeypatch):
        from lintest.alerts import manager as manager_mod
        monkeypatch.delenv("LINTEST_STATE_FILE", raising=False)
        path = manager_mod.default_state_path()
        assert path.name == "state.json"
        assert path.parent.exists()


class TestCooldownTiming:
    def test_exactly_at_the_cooldown_resent(self, tmp_path):
        clock = Clock(START)
        state = tmp_path / "state.json"
        manager = make_manager(state, clock)
        manager.dispatch([cpu_alert()])
        clock.advance(minutes=30)
        assert len(manager.dispatch([cpu_alert()]).sent) == 1

    def test_one_second_before_cooldown_suppressed(self, tmp_path):
        clock = Clock(START)
        manager = make_manager(tmp_path / "state.json", clock)
        manager.dispatch([cpu_alert()])
        clock.advance(minutes=29, seconds=59)
        assert len(manager.dispatch([cpu_alert()]).suppressed) == 1

    def test_suppressed_alert_does_not_refresh_the_timestamp(self, tmp_path):
        clock = Clock(START)
        state = tmp_path / "state.json"
        manager = make_manager(state, clock)
        manager.dispatch([cpu_alert()])
        first = json.loads(state.read_text(encoding="utf-8"))["alerts"]["system.cpu::cpu"]["last_sent"]
        clock.advance(minutes=10)
        manager.dispatch([cpu_alert()])
        second = json.loads(state.read_text(encoding="utf-8"))["alerts"]["system.cpu::cpu"]["last_sent"]
        assert first == second

    def test_zero_cooldown_always_sends(self, tmp_path):
        clock = Clock(START)
        manager = AlertManager([Recorder()], cooldown_minutes=0, state_path=tmp_path / "s.json",
                               clock=clock)
        manager.dispatch([cpu_alert()])
        clock.advance(seconds=1)
        assert len(manager.dispatch([cpu_alert()]).sent) == 1


class TestAtomicPersistence:
    def test_no_temporary_files_left_behind(self, tmp_path):
        state = tmp_path / "state.json"
        make_manager(state, Clock(START)).dispatch([cpu_alert()])
        assert [p.name for p in tmp_path.iterdir()] == ["state.json"]

    def test_state_file_is_valid_json_after_every_run(self, tmp_path):
        state = tmp_path / "state.json"
        clock = Clock(START)
        manager = make_manager(state, clock)
        for _ in range(3):
            manager.dispatch([cpu_alert()])
            json.loads(state.read_text(encoding="utf-8"))
            clock.advance(minutes=31)

    def test_unwritable_state_path_is_not_fatal(self, tmp_path):
        blocker = tmp_path / "blocker"
        blocker.write_text("i am a file", encoding="utf-8")
        manager = AlertManager([Recorder()], state_path=blocker / "state.json", clock=Clock(START))
        summary = manager.dispatch([cpu_alert()])
        assert len(summary.sent) == 1  # delivery still happened, only persistence failed

    def test_os_replace_permission_error_is_survivable(self, tmp_path, monkeypatch):
        """Windows: ``os.replace`` raises PermissionError while the target is
        open (antivirus, another process).  Delivery must continue; only
        persistence fails, and no temp file is left behind."""
        state = tmp_path / "state.json"

        def boom(src, dst):
            raise PermissionError("state.json is in use by another process")

        monkeypatch.setattr("lintest.alerts.manager.os.replace", boom)
        summary = make_manager(state, Clock(START)).dispatch([cpu_alert()])
        assert len(summary.sent) == 1  # delivery is not blocked by persistence
        assert not state.exists()
        assert [p.name for p in tmp_path.iterdir()] == []  # temp cleaned up

    def test_state_file_is_owner_only_on_posix(self, tmp_path):
        if os.name != "posix":
            pytest.skip("POSIX permissions only")
        state = tmp_path / "state.json"
        make_manager(state, Clock(START)).dispatch([cpu_alert()])
        assert (state.stat().st_mode & 0o077) == 0


class TestConcurrentInvocations:
    def test_overlapping_runs_never_corrupt_the_state_file(self, tmp_path):
        """Two timers (or a cron overlap) must not produce a torn file."""
        state = tmp_path / "state.json"
        barrier = threading.Barrier(6)
        errors: List[BaseException] = []

        def worker(index: int) -> None:
            try:
                manager = AlertManager([Recorder()], state_path=state,
                                       clock=Clock(START + timedelta(minutes=index)))
                manager.dispatch([critical(f"area{index}.check", f"problem {index}", f"subject{index}")])
                barrier.wait(timeout=30)
                manager.dispatch([critical(f"area{index}.check", f"problem {index}", f"subject{index}")])
            except BaseException as exc:  # noqa: BLE001 - collected for the assertion
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(6)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=60)

        assert errors == []
        payload = json.loads(state.read_text(encoding="utf-8"))
        assert isinstance(payload["alerts"], dict)
        assert not [p for p in tmp_path.iterdir() if p.name.endswith(".tmp")]

    def test_late_started_run_reads_the_previous_state(self, tmp_path):
        """Cooldown survives between invocations (timer semantics)."""
        state = tmp_path / "state.json"
        first = make_manager(state, Clock(START))
        first.dispatch([cpu_alert()])
        second = make_manager(state, Clock(START + timedelta(minutes=5)))
        assert len(second.dispatch([cpu_alert()]).suppressed) == 1
