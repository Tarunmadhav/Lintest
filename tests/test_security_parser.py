"""Tests for the failed-SSH-login parser and the security check."""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone

from lintest.checks.security import (
    _classify_logins,
    _parse_iso_ts,
    aggregate,
    filter_window,
    parse_auth_line,
    run_security_check,
    summarize_lines,
)

from .conftest import (
    invalid_user_line,
    make_security_cfg,
    sshd_line,
)


class TestParseAuthLine:
    def test_failed_password_line(self, now):
        event = parse_auth_line(sshd_line(now), now=now)
        assert event is not None
        assert event.ip == "203.0.113.9"
        assert event.user == "root"
        assert event.ts == now

    def test_invalid_user_line(self, now):
        event = parse_auth_line(invalid_user_line(now, ip="198.51.100.7"), now=now)
        assert event is not None
        assert event.ip == "198.51.100.7"
        assert event.user == "oracle"

    def test_ipv6_address(self, now):
        line = sshd_line(now, ip="2001:db8::1")
        event = parse_auth_line(line, now=now)
        assert event is not None
        assert event.ip == "2001:db8::1"

    def test_unrelated_lines_ignored(self, now):
        for line in (
            "Jul 15 10:30:00 srv1 sshd[4242]: Accepted password for root from 10.0.0.5 port 2200 ssh2",
            "Jul 15 10:30:00 srv1 systemd[1]: Started Daily apt upgrade.",
            "Jul 15 10:30:00 srv1 sudo: tarun : TTY=pts/0 ; COMMAND=/bin/ls",
            "garbage line without any structure",
            "",
        ):
            assert parse_auth_line(line, now=now) is None

    def test_year_rollover_pushes_december_back(self, now):
        # A December line read "now" (July) must belong to the previous year.
        line = "Dec 31 23:00:00 srv1 sshd[7]: Failed password for root from 9.9.9.9 port 1 ssh2"
        event = parse_auth_line(line, now=now)
        assert event is not None
        assert event.ts.year == now.year - 1
        assert event.ts.month == 12
        # Sanity: the rollover logic is anchored on 'now', not on a literal year.
        assert event.ts < now


class TestParseIsoTs:
    def test_journalctl_precise(self):
        # +00:00 offsets are converted to the host's local naive time.
        expected = (
            datetime(2025, 7, 15, 10, 30, 0, 123456, tzinfo=timezone.utc)
            .astimezone().replace(tzinfo=None)
        )
        ts = _parse_iso_ts("2025-07-15T10:30:00.123456+00:00")
        assert ts == expected

    def test_z_suffix(self):
        expected = (
            datetime(2025, 7, 15, 10, 30, 0, tzinfo=timezone.utc)
            .astimezone().replace(tzinfo=None)
        )
        assert _parse_iso_ts("2025-07-15T10:30:00Z") == expected

    def test_no_colon_offset(self):
        expected = (
            datetime(2025, 7, 15, 10, 30, 0, tzinfo=timezone.utc)
            .astimezone().replace(tzinfo=None)
        )
        assert _parse_iso_ts("2025-07-15T10:30:00+0000") == expected

    def test_naive_timestamp_kept_as_local(self):
        # journalctl short-precise without offset is already local time.
        assert _parse_iso_ts("2025-07-15T10:30:00.123456") == datetime(
            2025, 7, 15, 10, 30, 0, 123456
        )


class TestWindowAndAggregate:
    def test_filter_window_keeps_recent_only(self, now):
        events = [
            parse_auth_line(sshd_line(now - timedelta(minutes=i)), now=now)
            for i in (1, 5, 14, 16, 30)
        ]
        recent = filter_window([e for e in events if e], now, 15)
        assert len(recent) == 3  # 1, 5 and 14 minutes ago

    def test_aggregate_counts_and_ranking(self, now):
        lines = [
            sshd_line(now - timedelta(minutes=2), ip="1.1.1.1"),
            sshd_line(now - timedelta(minutes=3), ip="1.1.1.1"),
            sshd_line(now - timedelta(minutes=4), ip="1.1.1.1"),
            invalid_user_line(now - timedelta(minutes=5), ip="2.2.2.2"),
        ]
        events = [e for e in (parse_auth_line(line, now=now) for line in lines) if e]
        total, top, counts = aggregate(events, 2)
        assert total == 4
        assert top[0] == "1.1.1.1"
        assert counts == {"1.1.1.1": 3, "2.2.2.2": 1}


class TestSummarizeLines:
    def test_summary_respects_window(self, now):
        lines = [
            sshd_line(now - timedelta(minutes=1), ip="1.1.1.1"),
            sshd_line(now - timedelta(minutes=90), ip="1.1.1.1"),
        ]
        summary = summarize_lines(lines, now, window_minutes=15, top_ips=5, source="test")
        assert summary.total == 1
        assert summary.top_ips == ["1.1.1.1"]
        assert summary.source == "test"


class TestClassifyLogins:
    def test_critical(self):
        assert _classify_logins(20, 20)[0] == "CRITICAL"
        assert _classify_logins(50, 20)[0] == "CRITICAL"

    def test_warning_half_threshold(self):
        assert _classify_logins(10, 20)[0] == "WARNING"

    def test_ok(self):
        assert _classify_logins(5, 20)[0] == "OK"


class TestRunSecurityCheck:
    def test_critical_when_over_threshold(self, tmp_path, now):
        log = tmp_path / "auth.log"
        log.write_text(
            "\n".join(sshd_line(now - timedelta(minutes=i), ip="9.9.9.9") for i in range(1, 4)),
            encoding="utf-8",
        )
        cfg = make_security_cfg(log, threshold=2)
        results = run_security_check(cfg, now=now)
        assert len(results) == 1
        assert results[0].severity.value == "CRITICAL"
        assert "3 failed SSH logins" in results[0].message
        assert "9.9.9.9" in results[0].message
        assert results[0].details["counts_by_ip"] == {"9.9.9.9": 3}

    def test_ok_when_quiet(self, tmp_path, now):
        log = tmp_path / "auth.log"
        log.write_text(
            "Jul 15 10:30:00 srv1 sshd[1]: Accepted publickey for tarun from 10.0.0.2 port 2200 ssh2\n"
            + sshd_line(now - timedelta(minutes=2)),
            encoding="utf-8",
        )
        cfg = make_security_cfg(log, threshold=20)
        results = run_security_check(cfg, now=now)
        assert results[0].severity.value == "OK"

    def test_no_source_warning(self, tmp_path, now, monkeypatch):
        # Linux behaviour, pinned explicitly (Windows reports 'skipped' -- see
        # test_no_source_is_skipped_on_windows).
        monkeypatch.setattr(sys, "platform", "linux")
        cfg = make_security_cfg(tmp_path / "does-not-exist.log")
        results = run_security_check(cfg, now=now)
        assert results[0].severity.value == "WARNING"
        assert "no SSH auth source" in results[0].message

    def test_no_source_is_skipped_on_windows(self, tmp_path, now, monkeypatch):
        monkeypatch.setattr(sys, "platform", "win32")
        cfg = make_security_cfg(tmp_path / "does-not-exist.log")
        results = run_security_check(cfg, now=now)
        assert results[0].severity.value == "INFO"
        assert "skipped on Windows" in results[0].message
        assert results[0].is_problem() is False
