"""Output formats: JSON dumps and the HTML status report."""

from lintest.reporting.html_report import render_html_report, write_html_report
from lintest.reporting.json_output import build_json_report, write_json_report

__all__ = ["build_json_report", "write_json_report", "render_html_report", "write_html_report"]
