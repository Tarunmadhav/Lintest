"""Standalone HTML status report (``--report html`` or ``--report PATH``).

The output is a single self-contained file: inline CSS, no JavaScript,
no external assets -- safe to drop into a web root or open locally.  All
dynamic values are HTML-escaped.
"""

from __future__ import annotations

import html
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from lintest.alerts.manager import DispatchSummary
from lintest.models import CheckReport, Severity

_SEV_CLASS = {
    Severity.OK: "ok",
    Severity.INFO: "info",
    Severity.WARNING: "warn",
    Severity.CRITICAL: "crit",
    Severity.ERROR: "err",
}

_CSS = """
:root { color-scheme: dark; }
* { box-sizing: border-box; }
body { margin: 0; font: 14px/1.5 -apple-system, "Segoe UI", Roboto, sans-serif;
       background: #0f172a; color: #e2e8f0; }
.wrap { max-width: 960px; margin: 0 auto; padding: 24px 16px 48px; }
h1 { font-size: 22px; margin: 0 0 4px; }
h2 { font-size: 16px; margin: 28px 0 10px; color: #94a3b8;
     text-transform: uppercase; letter-spacing: .08em; }
.meta { color: #94a3b8; margin-bottom: 20px; }
.cards { display: flex; gap: 12px; flex-wrap: wrap; }
.card { flex: 1 1 120px; background: #1e293b; border-radius: 10px;
        padding: 14px 16px; border: 1px solid #334155; }
.card .num { font-size: 26px; font-weight: 700; }
.card .lbl { color: #94a3b8; font-size: 12px; text-transform: uppercase;
             letter-spacing: .06em; }
.num.ok { color: #4ade80; } .num.info { color: #38bdf8; }
.num.warn { color: #fbbf24; } .num.crit { color: #f87171; }
.num.err { color: #c084fc; }
table { width: 100%; border-collapse: collapse; background: #1e293b;
        border-radius: 10px; overflow: hidden; border: 1px solid #334155; }
th, td { text-align: left; padding: 9px 12px; border-bottom: 1px solid #334155;
         vertical-align: top; }
th { background: #273449; color: #94a3b8; font-size: 12px; text-transform: uppercase;
     letter-spacing: .06em; }
tr:last-child td { border-bottom: none; }
tr.ok td:first-child { border-left: 3px solid #4ade80; }
tr.info td:first-child { border-left: 3px solid #38bdf8; }
tr.warn td:first-child { border-left: 3px solid #fbbf24; }
tr.crit td:first-child { border-left: 3px solid #f87171; }
tr.err td:first-child { border-left: 3px solid #c084fc; }
.badge { display: inline-block; padding: 1px 9px; border-radius: 999px;
         font-size: 11px; font-weight: 700; }
.badge.ok { background: #14532d; color: #4ade80; }
.badge.info { background: #0c4a6e; color: #38bdf8; }
.badge.warn { background: #713f12; color: #fbbf24; }
.badge.crit { background: #7f1d1d; color: #f87171; }
.badge.err { background: #581c87; color: #c084fc; }
ul.alerts { list-style: none; padding: 0; margin: 0; }
ul.alerts li { background: #1e293b; border: 1px solid #334155; border-radius: 8px;
               padding: 10px 14px; margin-bottom: 8px; }
.empty { color: #64748b; font-style: italic; }
footer { margin-top: 32px; color: #64748b; font-size: 12px; }
"""


def render_html_report(
    report: CheckReport, dispatch: Optional[DispatchSummary] = None
) -> str:
    """Render one check pass as a complete HTML document."""
    esc = html.escape
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
    summary = report.to_dict()["summary"]

    cards = "".join(
        f'<div class="card"><div class="num {cls}">{value}</div>'
        f'<div class="lbl">{label}</div></div>'
        for cls, value, label in (
            ("ok", summary["ok"], "OK"),
            ("warn", summary["warnings"], "Warnings"),
            ("crit", summary["criticals"], "Critical"),
            ("err", summary["errors"], "Errors"),
            ("info", summary["total"], "Total checks"),
        )
    )

    rows = []
    for r in report.results:
        cls = _SEV_CLASS.get(r.severity, "info")
        rows.append(
            f"<tr class='{cls}'><td>{esc(r.check)}</td>"
            f"<td>{esc(r.subject) or '&mdash;'}</td>"
            f"<td><span class='badge {cls}'>{r.severity.value}</span></td>"
            f"<td>{esc(r.message)}</td></tr>"
        )
    table_rows = "".join(rows) or "<tr><td colspan='4' class='empty'>no results</td></tr>"

    alerts_html = ""
    if dispatch is not None:
        items = []
        for a in dispatch.sent:
            items.append(f"<li><span class='badge {_SEV_CLASS.get(a.severity, 'info')}'>"
                         f"{a.severity.value}</span> {esc(a.label())}</li>")
        for a in dispatch.recovered:
            items.append(f"<li><span class='badge ok'>RECOVERED</span> {esc(a.label())}</li>")
        suppressed_note = (
            f"<p class='empty'>{len(dispatch.suppressed)} alert(s) suppressed by cooldown.</p>"
            if dispatch.suppressed else ""
        )
        alerts_html = (
            "<h2>Alerts</h2>"
            + ("".join(f"<ul class='alerts'>{items_str}</ul>" if (items_str := "".join(items)) else
                       "<p class='empty'>No alerts sent.</p>"))
            + suppressed_note
        )

    exit_code = report.exit_code
    exit_style = "crit" if exit_code else "ok"
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>LinTest report &mdash; {esc(report.hostname)}</title>
<style>{_CSS}</style>
</head>
<body>
<div class="wrap">
  <h1>LinTest status &mdash; {esc(report.hostname)}</h1>
  <p class="meta">{esc(report.platform)} &middot; generated {generated} &middot;
     pass took {report.duration_seconds:.1f}s &middot;
     worst result <span class="badge {_SEV_CLASS.get(report.worst, 'info')}">{report.worst.value}</span> &middot;
     exit code <span class="badge {exit_style}">{exit_code}</span></p>

  <div class="cards">{cards}</div>

  {alerts_html}

  <h2>Check results</h2>
  <table>
    <thead><tr><th>Check</th><th>Subject</th><th>Severity</th><th>Message</th></tr></thead>
    <tbody>{table_rows}</tbody>
  </table>

  <footer>Generated by LinTest &middot; config: {esc(report.config_path or "built-in defaults")}</footer>
</div>
</body>
</html>
"""


def write_html_report(
    report: CheckReport,
    path: str,
    dispatch: Optional[DispatchSummary] = None,
) -> Path:
    """Write the HTML report to *path* and return it."""
    out_path = Path(path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(render_html_report(report, dispatch), encoding="utf-8")
    return out_path
