"""Reporting tests: JSON output and the standalone HTML page."""

from __future__ import annotations

import io
import json

from lintest.alerts.base import Alert
from lintest.alerts.manager import DispatchSummary
from lintest.models import CheckReport, Severity, critical, error, ok, warning
from lintest.reporting.html_report import render_html_report, write_html_report
from lintest.reporting.json_output import build_json_report, write_json_report


def sample_report(**kw) -> CheckReport:
    report = CheckReport(**kw)
    report.results = [
        ok("system.cpu", "CPU usage 10.0%", "cpu", percent=10.0),
        warning("system.ram", "RAM usage 82.0%", "ram", percent=82.0),
        critical("system.disk", "disk / 95.0% used", "/", percent=95.0),
        error("services.systemctl", "systemctl not available", "sshd"),
    ]
    report.finish()
    return report


def dispatch_with_everything() -> DispatchSummary:
    return DispatchSummary(
        sent=[Alert(Severity.CRITICAL, "system.disk", "/", "disk / 95.0% used")],
        suppressed=[Alert(Severity.WARNING, "system.ram", "ram", "RAM usage 82.0%")],
        recovered=[Alert(Severity.INFO, "system.load", "load", "RECOVERED: previous alert cleared")],
    )


class TestJsonReport:
    def test_summary_counts(self):
        data = build_json_report(sample_report())
        assert data["summary"] == {
            "total": 4, "ok": 1, "warnings": 1, "criticals": 1, "errors": 1,
            "worst": "ERROR", "exit_code": 1,
        }

    def test_results_carry_details(self):
        data = build_json_report(sample_report())
        cpu = next(r for r in data["results"] if r["check"] == "system.cpu")
        assert cpu["details"]["percent"] == 10.0
        assert cpu["severity"] == "OK"

    def test_alerts_section_is_omitted_without_dispatch(self):
        assert "alerts" not in build_json_report(sample_report())

    def test_alerts_section_lists_every_bucket(self):
        data = build_json_report(sample_report(), dispatch_with_everything())
        assert data["alerts"]["sent"][0]["severity"] == "CRITICAL"
        assert data["alerts"]["suppressed"][0]["subject"] == "ram"
        assert data["alerts"]["recovered"][0]["message"].startswith("RECOVERED")

    def test_stream_output_is_valid_json(self):
        stream = io.StringIO()
        write_json_report(sample_report(), dispatch_with_everything(), stream=stream)
        payload = json.loads(stream.getvalue())
        assert payload["hostname"] == sample_report().hostname


class TestHtmlReport:
    def test_contains_every_result_and_badges(self):
        html = render_html_report(sample_report())
        assert "system.cpu" in html and "system.ram" in html and "system.disk" in html
        assert "CRITICAL" in html and "WARNING" in html and "ERROR" in html
        assert "<!DOCTYPE html>" in html

    def test_escapes_dynamic_values(self):
        report = CheckReport(hostname="<script>alert(1)</script>", platform="Linux & co")
        report.results = [critical("system.disk", "disk / is 95% <b>full</b>", "<img src=x>")]
        report.finish()
        html = render_html_report(report)
        assert "<script>" not in html
        assert "&lt;script&gt;" in html
        assert "&lt;b&gt;full&lt;/b&gt;" in html
        assert "<img" not in html
        assert "Linux &amp; co" in html

    def test_alerts_section_lists_sent_recovered_and_suppressed(self):
        html = render_html_report(sample_report(), dispatch_with_everything())
        assert "<h2>Alerts</h2>" in html
        assert "RECOVERED</span>" in html
        assert "1 alert(s) suppressed by cooldown" in html
        assert "system.disk" in html

    def test_empty_dispatch_says_no_alerts_sent(self):
        html = render_html_report(sample_report(), DispatchSummary())
        assert "No alerts sent." in html

    def test_no_alerts_section_without_dispatch(self):
        assert "<h2>Alerts</h2>" not in render_html_report(sample_report())

    def test_exit_code_is_shown(self):
        assert "exit code" in render_html_report(sample_report())
        clean = CheckReport()
        clean.results = [ok("system.cpu", "fine", "cpu")]
        clean.finish()
        assert ">0</span>" in render_html_report(clean)

    def test_no_results_placeholder(self):
        report = CheckReport()
        report.finish()
        assert "no results" in render_html_report(report)

    def test_write_creates_parent_directories(self, tmp_path):
        target = tmp_path / "nested" / "deep" / "report.html"
        written = write_html_report(sample_report(), str(target))
        assert written == target
        assert target.read_text(encoding="utf-8").startswith("<!DOCTYPE html>")
