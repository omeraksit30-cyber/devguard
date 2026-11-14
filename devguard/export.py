"""Scan report export: JSON, Markdown and self-contained HTML.

Reports are built only from normalised database records, so they cannot contain
secret values by construction.
"""

from __future__ import annotations

import html
import json
import sqlite3
from typing import Any

from . import DISCLAIMER, __version__, db
from .db import load_findings, scan_detail
from .models import CATEGORIES, INCOMPLETE_RUN_STATUSES, SEVERITY_ORDER

CATEGORY_TITLES = {"dependency": "Dependencies", "secret": "Secrets", "config": "Configurations"}
HEURISTIC_NOTE = "Heuristic indicator, not a CVSS score."
REDACTED_NOTE = "Value redacted — DevGuard never stores or displays matched secrets."


def build_report(conn: sqlite3.Connection, scan: dict[str, Any]) -> dict[str, Any]:
    findings = load_findings(conn, scan)
    detail = scan_detail(conn, scan, findings)
    not_run = [r for r in detail["scanner_runs"] if r["status"] in INCOMPLETE_RUN_STATUSES]
    warning = None
    if detail["summary"]["risk"]["incomplete"]:
        warning = (f"This scan is incomplete. {len(not_run)} scanner(s) did not run. "
                   "Missing categories are unknown, not clean.")
    return {
        "devguard_version": __version__,
        "generated_at": db.utcnow(),
        "incomplete_warning": warning,
        "scanners_not_run": [{"scanner": r["scanner"], "category": r["category"], "status": r["status"],
                              "reason": r["error_message"]} for r in not_run],
        "scan": detail,
        "findings": findings,
        "disclaimer": DISCLAIMER,
    }


def to_json(report: dict[str, Any]) -> str:
    return json.dumps(report, indent=2, ensure_ascii=False)


def _ms(ms: int | None) -> str:
    return "—" if ms is None else f"{ms / 1000:.1f} s"


def _count(run: dict[str, Any]) -> str:
    return str(run["findings_count"]) if run["status"] == "success" else "unknown"


def _risk_text(report: dict[str, Any]) -> str:
    risk = report["scan"]["summary"]["risk"]
    text = f"{risk['score'] if risk['score'] is not None else '—'} ({risk['level'] or '—'})"
    if risk["incomplete"]:
        text += f" — Incomplete — {risk['scanners_not_run']} scanner(s) did not run"
    return text


def _location(f: dict[str, Any]) -> str:
    loc = f["file_path"] or ""
    if f["line_start"]:
        loc += f":{f['line_start']}"
    return loc or "—"


# ---------------------------------------------------------------- Markdown

def _md(value: Any) -> str:
    """Escape text for a GitHub-flavoured Markdown table cell."""
    s = "—" if value is None or value == "" else str(value)
    s = s.replace("\\", "\\\\").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    for ch in "|`*_[]":
        s = s.replace(ch, "\\" + ch)
    return " ".join(s.split())


def to_markdown(report: dict[str, Any]) -> str:
    scan, summary = report["scan"], report["scan"]["summary"]
    out = [f"# DevGuard scan report #{scan['id']}", ""]
    out += [f"- **Target:** {_md(scan['target_path'])}", f"- **Label:** {_md(scan['label'])}",
            f"- **Started:** {_md(scan['started_at'])}", f"- **Duration:** {_ms(scan['elapsed_ms'])}",
            f"- **Status:** {_md(scan['status'])}", ""]
    if report["incomplete_warning"]:
        out += [f"> **Warning:** {report['incomplete_warning']}", ">"]
        out += [f"> - {_md(r['scanner'])}: {_md(r['status'])} — {_md(r['reason'])}"
                for r in report["scanners_not_run"]]
        out.append("")
    out += ["## Scanners", "", "| Scanner | Version | Status | Duration | Findings |", "|---|---|---|---|---|"]
    out += [f"| {_md(r['scanner'])} | {_md(r['tool_version'])} | {_md(r['status'])} | {_ms(r['elapsed_ms'])} "
            f"| {_count(r)} |" for r in scan["scanner_runs"]]
    out += ["", "## Risk", "", f"**Risk score:** {_md(_risk_text(report))}", "", f"_{HEURISTIC_NOTE}_", ""]
    out += ["## Summary", "", "| Severity | Count |", "|---|---|"]
    out += [f"| {s.capitalize()} | {summary['by_severity'][s]} |" for s in SEVERITY_ORDER]
    out += ["", "| Category | Scanner status | Count |", "|---|---|---|"]
    for c in CATEGORIES:
        entry = summary["by_category"][c]
        count = entry["count"] if entry["count"] is not None else "unknown"
        out.append(f"| {CATEGORY_TITLES[c]} | {_md(entry['status'])} | {count} |")
    out += ["", "## Findings", ""]
    if not report["findings"]:
        out += ["No findings were recorded by the scanners that ran.", ""]
    for c in CATEGORIES:
        items = [f for f in report["findings"] if f["category"] == c]
        if not items:
            continue
        out += [f"### {CATEGORY_TITLES[c]} ({len(items)})", ""]
        if c == "secret":
            out += [f"_{REDACTED_NOTE}_", ""]
        out += ["| Severity | ID | Title | Affected target | Location | Remediation | Triage | Note |",
                "|---|---|---|---|---|---|---|---|"]
        out += [f"| {_md(f['severity'])} | {_md(f['rule_or_vulnerability_id'])} | {_md(f['title'])} "
                f"| {_md(f['affected_target'])} | {_md(_location(f))} | {_md(f['remediation'])} "
                f"| {_md(f['triage_status'])} | {_md(f['triage_note'])} |" for f in items]
        out.append("")
    out += ["---", "", f"_{DISCLAIMER}_", "", f"Generated by DevGuard {report['devguard_version']} "
            f"at {report['generated_at']}.", ""]
    return "\n".join(out)


# ---------------------------------------------------------------- HTML

_CSS = """
body{font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#1c2330;background:#fff;
max-width:1100px;margin:32px auto;padding:0 20px}
h1{font-size:24px}h2{font-size:18px;margin-top:32px;border-bottom:1px solid #d9dee7;padding-bottom:6px}
h3{font-size:15px;margin-top:24px}
table{border-collapse:collapse;width:100%;margin:10px 0;font-size:13px}
th,td{border:1px solid #d9dee7;padding:6px 8px;text-align:left;vertical-align:top}
th{background:#f3f5f9}
.warn{border:2px solid #b45309;background:#fff7e6;padding:12px 16px;border-radius:6px}
.sev{font-weight:600;white-space:nowrap}.muted{color:#5b6677}
footer{margin-top:40px;border-top:1px solid #d9dee7;padding-top:12px;color:#5b6677;font-size:13px}
dl{display:grid;grid-template-columns:120px 1fr;gap:4px 12px}dt{color:#5b6677}dd{margin:0}
"""


def to_html(report: dict[str, Any]) -> str:
    e = lambda v: html.escape("—" if v is None or v == "" else str(v), quote=True)
    scan, summary = report["scan"], report["scan"]["summary"]
    p: list[str] = [
        "<!doctype html>", '<html lang="en"><head><meta charset="utf-8">',
        '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'">',
        f"<title>DevGuard scan report #{e(scan['id'])}</title>", f"<style>{_CSS}</style></head><body>",
        f"<h1>DevGuard scan report #{e(scan['id'])}</h1>", "<dl>",
        f"<dt>Target</dt><dd>{e(scan['target_path'])}</dd>", f"<dt>Label</dt><dd>{e(scan['label'])}</dd>",
        f"<dt>Started</dt><dd>{e(scan['started_at'])}</dd>", f"<dt>Duration</dt><dd>{e(_ms(scan['elapsed_ms']))}</dd>",
        f"<dt>Status</dt><dd>{e(scan['status'])}</dd>", "</dl>",
    ]
    if report["incomplete_warning"]:
        p.append(f'<div class="warn"><strong>Warning:</strong> {e(report["incomplete_warning"])}<ul>')
        p += [f"<li>{e(r['scanner'])}: {e(r['status'])} — {e(r['reason'])}</li>" for r in report["scanners_not_run"]]
        p.append("</ul></div>")
    p.append("<h2>Scanners</h2><table><thead><tr><th>Scanner</th><th>Version</th><th>Status</th>"
             "<th>Duration</th><th>Findings</th></tr></thead><tbody>")
    p += [f"<tr><td>{e(r['scanner'])}</td><td>{e(r['tool_version'])}</td><td>{e(r['status'])}</td>"
          f"<td>{e(_ms(r['elapsed_ms']))}</td><td>{e(_count(r))}</td></tr>" for r in scan["scanner_runs"]]
    p.append("</tbody></table>")
    p.append(f"<h2>Risk</h2><p><strong>Risk score:</strong> {e(_risk_text(report))}</p>"
             f'<p class="muted">{e(HEURISTIC_NOTE)}</p>')
    p.append("<h2>Summary</h2><table><thead><tr><th>Severity</th><th>Count</th></tr></thead><tbody>")
    p += [f"<tr><td>{e(s.capitalize())}</td><td>{e(summary['by_severity'][s])}</td></tr>" for s in SEVERITY_ORDER]
    p.append("</tbody></table><table><thead><tr><th>Category</th><th>Scanner status</th><th>Count</th>"
             "</tr></thead><tbody>")
    for c in CATEGORIES:
        entry = summary["by_category"][c]
        count = entry["count"] if entry["count"] is not None else "unknown"
        p.append(f"<tr><td>{e(CATEGORY_TITLES[c])}</td><td>{e(entry['status'])}</td><td>{e(count)}</td></tr>")
    p.append("</tbody></table><h2>Findings</h2>")
    if not report["findings"]:
        p.append("<p>No findings were recorded by the scanners that ran.</p>")
    for c in CATEGORIES:
        items = [f for f in report["findings"] if f["category"] == c]
        if not items:
            continue
        p.append(f"<h3>{e(CATEGORY_TITLES[c])} ({len(items)})</h3>")
        if c == "secret":
            p.append(f'<p class="muted">{e(REDACTED_NOTE)}</p>')
        p.append("<table><thead><tr><th>Severity</th><th>ID</th><th>Title</th><th>Affected target</th>"
                 "<th>Location</th><th>Remediation</th><th>Triage</th><th>Note</th></tr></thead><tbody>")
        p += [f'<tr><td class="sev">{e(f["severity"])}</td><td>{e(f["rule_or_vulnerability_id"])}</td>'
              f"<td>{e(f['title'])}</td><td>{e(f['affected_target'])}</td><td>{e(_location(f))}</td>"
              f"<td>{e(f['remediation'])}</td><td>{e(f['triage_status'])}</td><td>{e(f['triage_note'])}</td></tr>"
              for f in items]
        p.append("</tbody></table>")
    p.append(f"<footer><p>{e(DISCLAIMER)}</p><p>Generated by DevGuard {e(report['devguard_version'])} "
             f"at {e(report['generated_at'])}.</p></footer></body></html>")
    return "\n".join(p)


FORMATS = {
    "json": (to_json, "application/json"),
    "md": (to_markdown, "text/markdown; charset=utf-8"),
    "html": (to_html, "text/html; charset=utf-8"),
}
