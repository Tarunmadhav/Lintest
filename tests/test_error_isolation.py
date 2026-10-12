"""Error isolation: one broken area or channel must never abort the run."""

from __future__ import annotations

import lintest.main as main_mod
from lintest.alerts.base import Alert
from lintest.alerts.manager import AlertManager
from lintest.checks.base import run_check
from lintest.config import (
    AlertsConfig,
    Config,
    ConsoleConfig,
    NetworkConfig,
    SecurityConfig,
    ServicesConfig,
    SystemConfig,
    TelegramConfig,
)
from lintest.models import CheckReport, Severity, critical, ok


class TestRunCheckGuard:
    def test_exception_becomes_an_error_result(self):
        def boom(cfg):
            raise ValueError("kaboom")
        results = run_check("system", boom, None)
        assert len(results) == 1
        assert results[0].severity is Severity.ERROR
        assert "ValueError" in results[0].message
        assert "kaboom" in results[0].message
        assert results[0].check == "system"

    def test_none_return_is_normalised_to_empty_list(self):
        assert run_check("x", lambda: None) == []

    def test_single_result_is_normalised_to_list(self):
        results = run_check("x", lambda: ok("x.y", "fine"))
        assert isinstance(results, list)
        assert results[0].severity is Severity.OK

    def test_generator_return_is_materialised(self):
        def gen():
            yield ok("a", "one")
            yield ok("b", "two")
        assert [r.check for r in run_check("x", gen)] == ["a", "b"]


def quiet_cfg(**overrides) -> Config:
    base = dict(
        system=SystemConfig(enabled=False),
        services=ServicesConfig(enabled=False),
        network=NetworkConfig(enabled=False),
        security=SecurityConfig(enabled=False),
        alerts=AlertsConfig(console=ConsoleConfig(enabled=False),
                            telegram=TelegramConfig(enabled=False)),
    )
    base.update(overrides)
    return Config(**base)


class TestAreaIsolation:
    def test_one_crashing_area_does_not_stop_the_others(self, monkeypatch):
        def boom(cfg):
            raise RuntimeError("system area exploded")

        monkeypatch.setattr(main_mod, "run_system_checks", boom)
        monkeypatch.setattr(main_mod, "run_service_checks", lambda cfg: [ok("services.active", "up", "sshd")])
        monkeypatch.setattr(main_mod, "run_network_checks", lambda cfg: [ok("network.ping", "up", "1.1.1.1")])
        monkeypatch.setattr(main_mod, "run_security_check", lambda cfg: [ok("security.ssh", "quiet", "ssh")])

        cfg = quiet_cfg(system=SystemConfig(enabled=True), services=ServicesConfig(enabled=True),
                        network=NetworkConfig(enabled=True), security=SecurityConfig(enabled=True))
        report = CheckReport()
        main_mod.collect_results(cfg, report)

        by_check = {r.check: r for r in report.results}
        assert set(by_check) == {"system", "services.active", "network.ping", "security.ssh"}
        assert by_check["system"].severity is Severity.ERROR
        assert all(r.severity is Severity.OK for k, r in by_check.items() if k != "system")

    def test_disabled_areas_are_not_run(self, monkeypatch):
        called = []
        for name in ("run_system_checks", "run_service_checks", "run_network_checks", "run_security_check"):
            monkeypatch.setattr(main_mod, name,
                                lambda cfg, _n=name: called.append(_n) or [ok(_n, "x")])
        report = CheckReport()
        main_mod.collect_results(quiet_cfg(), report)
        assert called == []
        assert report.results == []

    def test_report_still_renders_with_only_errors(self, monkeypatch, capsys, tmp_path):
        def boom(cfg):
            raise RuntimeError("nope")
        monkeypatch.setattr(main_mod, "run_system_checks", boom)
        monkeypatch.setenv("LINTEST_STATE_FILE", str(tmp_path / "state.json"))
        cfg = quiet_cfg(system=SystemConfig(enabled=True))
        code = main_mod.run_pass(cfg, "text", None, dispatch=True)
        out = capsys.readouterr().out
        assert code == 0  # ERROR alone does not drive exit code 1
        assert "ERROR" in out
        assert "exit code 0" in out

    def test_crashed_area_still_dispatches_an_alert(self, monkeypatch, tmp_path):
        def boom(cfg):
            raise RuntimeError("disk layer gone")
        monkeypatch.setattr(main_mod, "run_system_checks", boom)
        monkeypatch.setenv("LINTEST_STATE_FILE", str(tmp_path / "state.json"))
        cfg = quiet_cfg(
            system=SystemConfig(enabled=True),
            alerts=AlertsConfig(console=ConsoleConfig(enabled=True),
                                telegram=TelegramConfig(enabled=False)),
        )
        main_mod.run_pass(cfg, "text", None, dispatch=True)
        import json
        state = json.loads((tmp_path / "state.json").read_text(encoding="utf-8"))
        # run_check names the crashed area "system", so the alert key is system::system
        assert "system::system" in state["alerts"]
        assert state["alerts"]["system::system"]["severity"] == "ERROR"


class TestChannelIsolation:
    def test_a_channel_that_raises_does_not_block_the_others(self, tmp_path):
        delivered = []

        class Exploding:
            name = "exploding"
            enabled = True

            def send(self, alert: Alert) -> bool:
                raise RuntimeError("channel bug")

        class Working:
            name = "working"
            enabled = True

            def send(self, alert: Alert) -> bool:
                delivered.append(alert)
                return True

        manager = AlertManager([Exploding(), Working()], state_path=tmp_path / "state.json")
        summary = manager.dispatch([critical("system.cpu", "hot", "cpu")])
        assert len(summary.sent) == 1
        assert len(delivered) == 1

    def test_all_channels_failing_leaves_state_unarmed(self, tmp_path):
        class Dead:
            name = "dead"
            enabled = True

            def send(self, alert: Alert) -> bool:
                return False

        manager = AlertManager([Dead()], state_path=tmp_path / "state.json")
        summary = manager.dispatch([critical("system.cpu", "hot", "cpu")])
        assert summary.sent == []
        assert not (tmp_path / "state.json").exists() or \
            "system.cpu::cpu" not in (tmp_path / "state.json").read_text(encoding="utf-8")

    def test_broken_channel_is_skipped_by_the_manager(self, tmp_path):
        class Broken:
            name = "broken"
            enabled = False

            def send(self, alert: Alert) -> bool:  # pragma: no cover - never called
                raise AssertionError("disabled channel must not be used")

        manager = AlertManager([Broken()], state_path=tmp_path / "state.json")
        assert manager.channels == []
        assert manager.dispatch([critical("system.cpu", "hot", "cpu")]).sent == []
