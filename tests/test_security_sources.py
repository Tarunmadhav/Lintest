"""SSH login check: log sources, bounded reads, malformed lines, rollover."""

from __future__ import annotations

import sys
from datetime import datetime, timedelta

import pytest

from lintest.checks import security
from lintest.config import Config, SecurityConfig, ServicesConfig, ThresholdsConfig
from lintest.models import Severity
from lintest.utils.shell import CommandResult

from .conftest import invalid_user_line, make_security_cfg, sshd_line

NOW = datetime(2025, 7, 15, 10, 30, 0)


def journalctl_result(lines, returncode=0, missing=False, timed_out=False) -> CommandResult:
    return CommandResult(argv=["journalctl"], returncode=returncode,
                         stdout="\n".join(lines), missing=missing, timed_out=timed_out)


def journalctl_cfg(tmp_path, fallback=True, threshold=20) -> Config:
    return Config(
        thresholds=ThresholdsConfig(failed_ssh_logins=threshold),
        security=SecurityConfig(auth_log_path=str(tmp_path / "missing-auth.log"),
                                use_journalctl_fallback=fallback, window_minutes=15, top_ips=3),
        services=ServicesConfig(enabled=False),
    )


class TestBoundedReads:
    def test_only_the_tail_of_a_huge_log_is_read(self, tmp_path):
        log = tmp_path / "auth.log"
        junk = ("PAD" * 40 + "\n") * 500           # ~61 KB of rotated noise
        event = sshd_line(NOW - timedelta(minutes=1), ip="9.9.9.9")
        log.write_text(junk + event + "\n", encoding="utf-8")

        lines = security._read_lines(log, max_bytes=1024)
        assert any("9.9.9.9" in line for line in lines)
        assert len("".join(lines)) <= 1024

    def test_partial_first_line_is_dropped(self, tmp_path):
        log = tmp_path / "auth.log"
        junk_line = "PAD" * 40
        log.write_text((junk_line + "\n") * 20 + sshd_line(NOW, ip="1.2.3.4") + "\n",
                       encoding="utf-8")
        lines = security._read_lines(log, max_bytes=300)
        assert all(line.startswith("PAD") or "sshd" in line for line in lines)

    def test_undecodable_bytes_do_not_crash(self, tmp_path):
        log = tmp_path / "auth.log"
        payload = b"\xff\xfe tail of a corrupt file\n" + \
            sshd_line(NOW - timedelta(minutes=1), ip="5.5.5.5").encode() + b"\n"
        log.write_bytes(payload)
        lines = security._read_lines(log)
        summary = security.summarize_lines(lines, NOW, 15, 5, str(log))
        assert summary.total == 1

    def test_small_file_is_read_completely(self, tmp_path):
        log = tmp_path / "auth.log"
        log.write_text(sshd_line(NOW) + "\n", encoding="utf-8")
        assert len(security._read_lines(log)) == 1


class TestLogSources:
    def test_missing_file_without_fallback_reports_no_source(self, tmp_path, monkeypatch):
        # Linux behaviour, pinned explicitly (Windows reports 'skipped').
        monkeypatch.setattr(sys, "platform", "linux")
        cfg = make_security_cfg(tmp_path / "nope.log")
        summary = security.collect_failed_logins(cfg, now=NOW)
        assert summary.total == 0
        assert summary.source == ""
        result = security.run_security_check(cfg, now=NOW)[0]
        assert result.severity is Severity.WARNING
        assert "no SSH auth source" in result.message

    def test_journalctl_fallback_counts_logins(self, tmp_path, monkeypatch):
        cfg = journalctl_cfg(tmp_path)
        lines = [sshd_line(NOW - timedelta(minutes=2), ip="7.7.7.7"),
                 invalid_user_line(NOW - timedelta(minutes=1), ip="7.7.7.7")]
        # journalctl emits ISO timestamps; rewrite the sample lines accordingly.
        iso_lines = [line.replace(f"{NOW:%b} {NOW.day:>2} ", "2025-07-15T", 1).replace(
            f"{NOW:%H:%M:%S}", f"{NOW:%H:%M:%S}.000000+00:00", 1) for line in lines]
        monkeypatch.setattr(security, "run_command", lambda *a, **k: journalctl_result(iso_lines))
        summary = security.collect_failed_logins(cfg, now=NOW)
        assert summary.source == "journalctl"
        assert summary.total == 2

    def test_journalctl_missing_binary_reports_no_source(self, tmp_path, monkeypatch):
        monkeypatch.setattr(sys, "platform", "linux")
        cfg = journalctl_cfg(tmp_path)
        monkeypatch.setattr(security, "run_command",
                            lambda *a, **k: journalctl_result([], missing=True, returncode=-1))
        result = security.run_security_check(cfg, now=NOW)[0]
        assert result.severity is Severity.WARNING
        assert result.details["source"] == ""

    def test_journalctl_failure_reports_no_source(self, tmp_path, monkeypatch):
        cfg = journalctl_cfg(tmp_path)
        monkeypatch.setattr(security, "run_command",
                            lambda *a, **k: journalctl_result([], returncode=1))
        assert security.collect_failed_logins(cfg, now=NOW).source == ""

    def test_journalctl_timeout_reports_no_source(self, tmp_path, monkeypatch):
        monkeypatch.setattr(sys, "platform", "linux")
        cfg = journalctl_cfg(tmp_path)
        monkeypatch.setattr(security, "run_command",
                            lambda *a, **k: journalctl_result([], timed_out=True, returncode=-1))
        assert security.run_security_check(cfg, now=NOW)[0].severity is Severity.WARNING

    def test_missing_everything_is_skipped_on_windows(self, tmp_path, monkeypatch):
        """The real Windows path: no auth.log AND no journalctl -> 'skipped'."""
        monkeypatch.setattr(sys, "platform", "win32")
        monkeypatch.setattr(security, "run_command",
                            lambda *a, **k: journalctl_result([], missing=True, returncode=-1))
        cfg = journalctl_cfg(tmp_path)
        result = security.run_security_check(cfg, now=NOW)[0]
        assert result.severity is Severity.INFO
        assert "skipped on Windows" in result.message
        assert result.is_problem() is False

    def test_unreadable_auth_log_falls_back_to_journalctl(self, tmp_path, monkeypatch):
        log = tmp_path / "auth.log"
        log.write_text("present\n", encoding="utf-8")
        cfg = Config(
            thresholds=ThresholdsConfig(failed_ssh_logins=20),
            security=SecurityConfig(auth_log_path=str(log), use_journalctl_fallback=True,
                                    window_minutes=15, top_ips=3),
            services=ServicesConfig(enabled=False),
        )

        def boom(path, max_bytes=security.MAX_LOG_READ_BYTES):
            raise PermissionError("access denied")
        monkeypatch.setattr(security, "_read_lines", boom)
        monkeypatch.setattr(security, "run_command",
                            lambda *a, **k: journalctl_result([], returncode=1))
        summary = security.collect_failed_logins(cfg, now=NOW)
        assert summary.source == ""

    def test_empty_auth_log_is_a_valid_source(self, tmp_path):
        log = tmp_path / "auth.log"
        log.write_text("", encoding="utf-8")
        cfg = make_security_cfg(log, threshold=20)
        result = security.run_security_check(cfg, now=NOW)[0]
        assert result.severity is Severity.OK
        assert result.details["source"] == str(log)

    def test_journalctl_fallback_disabled_is_respected(self, tmp_path, monkeypatch):
        cfg = journalctl_cfg(tmp_path, fallback=False)
        monkeypatch.setattr(security, "run_command",
                            lambda *a, **k: pytest.fail("journalctl must not be called"))
        assert security.collect_failed_logins(cfg, now=NOW).source == ""


class TestTolerantParsing:
    @pytest.mark.parametrize("line", [
        "Jul 32 99:99:99 srv1 sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2",
        "2025-13-45T99:99:99Z srv1 sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2",
        "Foo 12 10:00:00 srv1 sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2",
    ])
    def test_invalid_timestamps_are_ignored_not_fatal(self, line):
        assert security.parse_auth_line(line, now=NOW) is None

    def test_malformed_lines_mixed_with_valid_ones(self, now):
        lines = [
            "Jul 32 99:99:99 srv1 sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2",
            sshd_line(now - timedelta(minutes=1), ip="1.2.3.4"),
            "\x00\x00 binary junk",
            "",
        ]
        summary = security.summarize_lines(lines, now, 15, 5, "mixed")
        assert summary.total == 1

    def test_sshd_session_prefix_is_supported(self):
        line = "Jul 15 10:25:00 srv1 sshd-session[4242]: Failed password for root from 8.8.8.8 port 22 ssh2"
        event = security.parse_auth_line(line, now=NOW)
        assert event is not None
        assert event.ip == "8.8.8.8"

    def test_leading_whitespace_is_tolerated(self):
        line = "   Jul 15 10:25:00 srv1 sshd[9]: Failed password for root from 6.6.6.6 port 1 ssh2"
        assert security.parse_auth_line(line, now=NOW).ip == "6.6.6.6"

    def test_iso_timestamp_with_comma_decimals(self):
        ts = security._parse_iso_ts("2025-07-15T10:30:00,123456+00:00")
        assert ts.microsecond == 123456

    def test_publickey_failure_is_counted(self):
        line = "Jul 15 10:25:00 srv1 sshd[9]: Failed publickey for deploy from 4.4.4.4 port 22 ssh2"
        assert security.parse_auth_line(line, now=NOW).user == "deploy"

    def test_successful_login_is_not_counted(self):
        line = "Jul 15 10:25:00 srv1 sshd[9]: Accepted password for root from 4.4.4.4 port 22 ssh2"
        assert security.parse_auth_line(line, now=NOW) is None


class TestYearRollover:
    def test_december_line_read_in_january_belongs_to_the_previous_year(self):
        january = datetime(2026, 1, 2, 10, 0, 0)
        ts = security._parse_syslog_ts("Dec 31 23:00:00", january)
        assert ts.year == 2025
        assert (ts.month, ts.day) == (12, 31)

    def test_january_line_read_in_january_keeps_the_current_year(self):
        january = datetime(2026, 1, 2, 10, 0, 0)
        ts = security._parse_syslog_ts("Jan 01 00:30:00", january)
        assert ts.year == 2026

    def test_same_day_line_is_not_shifted(self):
        ts = security._parse_syslog_ts("Jul 15 10:29:59", NOW)
        assert ts.year == NOW.year and ts.day == 15

    def test_year_hint_is_honoured(self):
        ts = security._parse_syslog_ts("Jan 05 08:00:00", NOW, year_hint=2024)
        assert ts.year == 2024

    def test_rollover_keeps_the_event_inside_the_window(self):
        """A Dec 31 attack read on Jan 1 00:05 must still be counted."""
        read_at = datetime(2026, 1, 1, 0, 5, 0)
        line = "Dec 31 23:58:00 srv1 sshd[3]: Failed password for root from 2.2.2.2 port 1 ssh2"
        summary = security.summarize_lines([line], read_at, window_minutes=15, top_ips=5, source="x")
        assert summary.total == 1


class TestWindowFiltering:
    def test_future_timestamps_within_skew_are_kept(self, now):
        event = security.LogEvent(ts=now + timedelta(minutes=1), ip="1.1.1.1", user="u", raw="")
        assert len(security.filter_window([event], now, 15)) == 1

    def test_far_future_timestamps_are_dropped(self, now):
        event = security.LogEvent(ts=now + timedelta(minutes=30), ip="1.1.1.1", user="u", raw="")
        assert security.filter_window([event], now, 15) == []

    def test_window_boundary_is_inclusive(self, now):
        event = security.LogEvent(ts=now - timedelta(minutes=15), ip="1.1.1.1", user="u", raw="")
        assert len(security.filter_window([event], now, 15)) == 1


class TestAggregation:
    def test_top_ips_are_limited_but_counts_are_complete(self, now):
        lines = []
        for index, ip in enumerate(["1.1.1.1", "1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4", "5.5.5.5"]):
            lines.append(sshd_line(now - timedelta(minutes=1), ip=ip))
        summary = security.summarize_lines(lines, now, 15, top_ips=2, source="x")
        assert summary.total == 6
        assert summary.top_ips == ["1.1.1.1", "2.2.2.2"]
        assert len(summary.counts_by_ip) == 5

    def test_aggregate_of_no_events(self):
        assert security.aggregate([], 5) == (0, [], {})


class TestSeverityThresholds:
    @pytest.mark.parametrize("total,threshold,expected", [
        (19, 20, "WARNING"),
        (20, 20, "CRITICAL"),
        (10, 20, "WARNING"),
        (9, 20, "OK"),
        (0, 20, "OK"),
        (1, 1, "CRITICAL"),
    ])
    def test_classification(self, total, threshold, expected):
        assert security._classify_logins(total, threshold)[0] == expected

    def test_critical_result_mentions_top_ips_and_source(self, tmp_path, now):
        log = tmp_path / "auth.log"
        log.write_text("\n".join(sshd_line(now - timedelta(minutes=1), ip="9.9.9.9")
                                 for _ in range(3)), encoding="utf-8")
        cfg = make_security_cfg(log, threshold=2)
        result = security.run_security_check(cfg, now=now)[0]
        assert result.severity is Severity.CRITICAL
        assert "9.9.9.9 x3" in result.message
        assert str(log) in result.message
        assert result.details["window_minutes"] == 15
