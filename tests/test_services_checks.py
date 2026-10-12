"""Service check tests (``systemctl is-active``)."""

from __future__ import annotations

import sys

import pytest

from lintest.checks import services
from lintest.config import Config, ServicesConfig
from lintest.models import Severity
from lintest.utils.shell import CommandResult


def cfg(critical=("sshd",), warning=()) -> Config:
    return Config(services=ServicesConfig(critical=list(critical), warning=list(warning)))


def result(stdout="", returncode=0, **kw) -> CommandResult:
    return CommandResult(argv=["systemctl"], returncode=returncode, stdout=stdout, **kw)


class TestServiceChecks:
    def test_active_service_is_ok(self, monkeypatch):
        monkeypatch.setattr(services, "run_command", lambda *a, **k: result(stdout="active\n"))
        checks = services.run_service_checks(cfg())
        assert checks[0].severity is Severity.OK
        assert checks[0].subject == "sshd"

    def test_inactive_critical_service_is_critical(self, monkeypatch):
        monkeypatch.setattr(services, "run_command", lambda *a, **k: result(stdout="inactive\n", returncode=3))
        checks = services.run_service_checks(cfg())
        assert checks[0].severity is Severity.CRITICAL
        assert "inactive" in checks[0].message
        assert checks[0].details["tier"] == "critical"

    def test_failed_critical_service_is_critical(self, monkeypatch):
        monkeypatch.setattr(services, "run_command", lambda *a, **k: result(stdout="failed\n", returncode=3))
        checks = services.run_service_checks(cfg())
        assert checks[0].severity is Severity.CRITICAL

    def test_inactive_warning_tier_service_is_only_a_warning(self, monkeypatch):
        monkeypatch.setattr(services, "run_command",
                            lambda *a, **k: result(stdout="inactive\n", returncode=3))
        checks = services.run_service_checks(cfg(critical=(), warning=("nginx",)))
        assert checks[0].severity is Severity.WARNING
        assert checks[0].details["tier"] == "warning"

    def test_missing_systemctl_is_an_error(self, monkeypatch):
        """A host without systemd must not look like 'every service is down'."""
        # Linux behaviour, pinned explicitly (Windows reports 'unsupported'
        # instead -- see TestServiceChecksWindows).
        monkeypatch.setattr(sys, "platform", "linux")
        monkeypatch.setattr(services, "run_command",
                            lambda *a, **k: result(returncode=-1, missing=True,
                                                   stderr="systemctl: command not found"))
        checks = services.run_service_checks(cfg(critical=("sshd", "nginx")))
        assert {r.severity for r in checks} == {Severity.ERROR}
        assert "systemctl not available" in checks[0].message

    def test_systemctl_timeout_is_an_error(self, monkeypatch):
        monkeypatch.setattr(services, "run_command",
                            lambda *a, **k: result(returncode=-1, timed_out=True))
        checks = services.run_service_checks(cfg())
        assert checks[0].severity is Severity.ERROR
        assert "timed out" in checks[0].message

    def test_unexpected_state_is_reported_verbatim(self, monkeypatch):
        monkeypatch.setattr(services, "run_command", lambda *a, **k: result(stdout="activating\n"))
        checks = services.run_service_checks(cfg())
        assert checks[0].severity is Severity.CRITICAL
        assert "activating" in checks[0].message

    def test_empty_output_uses_exit_code(self, monkeypatch):
        monkeypatch.setattr(services, "run_command", lambda *a, **k: result(stdout="", returncode=4))
        checks = services.run_service_checks(cfg())
        assert "exit=4" in checks[0].message

    def test_critical_tier_is_checked_first(self, monkeypatch):
        monkeypatch.setattr(services, "run_command", lambda *a, **k: result(stdout="active\n"))
        checks = services.run_service_checks(cfg(critical=("sshd",), warning=("nginx",)))
        assert [r.subject for r in checks] == ["sshd", "nginx"]
        assert [r.details["tier"] for r in checks] == ["critical", "warning"]

    def test_no_services_configured_yields_no_results(self, monkeypatch):
        monkeypatch.setattr(services, "run_command",
                            lambda *a, **k: pytest.fail("systemctl must not be called"))
        assert services.run_service_checks(cfg(critical=(), warning=())) == []

    def test_command_receives_service_name(self, monkeypatch):
        seen = {}

        def spy(argv, timeout=10.0, cwd=None):
            seen["argv"] = list(argv)
            seen["timeout"] = timeout
            return result(stdout="active\n")
        monkeypatch.setattr(services, "run_command", spy)
        services.run_service_checks(cfg(critical=("sshd",)))
        assert seen["argv"] == ["systemctl", "is-active", "sshd"]
        assert seen["timeout"] > 0


class TestServiceChecksWindows:
    """On Windows systemctl does not exist: an explicit non-problem status."""

    @pytest.fixture(autouse=True)
    def _pin_windows(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "win32")

    def test_missing_systemctl_is_unsupported_not_critical(self, monkeypatch):
        monkeypatch.setattr(services, "run_command",
                            lambda *a, **k: result(returncode=-1, missing=True,
                                                   stderr="'systemctl' is not recognized"))
        checks = services.run_service_checks(cfg(critical=("sshd",), warning=("nginx",)))
        assert len(checks) == 2
        assert {r.severity for r in checks} == {Severity.INFO}
        assert all("unsupported on Windows" in r.message for r in checks)
        assert not any(r.is_problem() for r in checks)

    def test_windows_branch_does_not_hide_real_results_when_systemctl_exists(self, monkeypatch):
        """The platform branch only applies when the binary is missing."""
        monkeypatch.setattr(services, "run_command", lambda *a, **k: result(stdout="active\n"))
        checks = services.run_service_checks(cfg())
        assert checks[0].severity is Severity.OK
