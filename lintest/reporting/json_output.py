"""JSON output mode (``--output json``).

Emits a single JSON document to stdout containing the report summary,
every check result with its structured details, and the alert dispatch
summary.  Logs go to stderr, so the stream is safe to pipe into ``jq``.
"""

from __future__ import annotations

import json
import sys
from typing import Any, Dict, Optional, TextIO

from lintest.alerts.manager import DispatchSummary
from lintest.alerts.base import Alert
from lintest.models import CheckReport


def _alert_to_dict(alert: Alert) -> Dict[str, Any]:
    """Serialise an :class:`Alert` for the report."""
    return {
        "severity": alert.severity.value,
        "check": alert.check,
        "subject": alert.subject,
        "message": alert.message,
    }


def build_json_report(
    report: CheckReport, dispatch: Optional[DispatchSummary] = None
) -> Dict[str, Any]:
    """Build the full JSON document for one check pass."""
    data = report.to_dict()
    if dispatch is not None:
        data["alerts"] = {
            "sent": [_alert_to_dict(a) for a in dispatch.sent],
            "suppressed": [_alert_to_dict(a) for a in dispatch.suppressed],
            "recovered": [_alert_to_dict(a) for a in dispatch.recovered],
        }
    return data


def write_json_report(
    report: CheckReport,
    dispatch: Optional[DispatchSummary] = None,
    stream: Optional[TextIO] = None,
) -> None:
    """Write the JSON report to *stream* (stdout by default)."""
    out = stream if stream is not None else sys.stdout
    json.dump(build_json_report(report, dispatch), out, indent=2)
    out.write("\n")
