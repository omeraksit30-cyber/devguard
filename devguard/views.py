"""Read-model assembly shared by routes, export and evaluation."""

from __future__ import annotations

import sqlite3
from typing import Any

from . import db
from .engine.normalize import sort_findings
from .engine.risk import risk_level, risk_score
from .models import CATEGORIES, INCOMPLETE_RUN_STATUSES, SEVERITY_ORDER


def load_findings(conn: sqlite3.Connection, scan: dict[str, Any]) -> list[dict[str, Any]]:
    """All findings of a scan, severity-sorted, annotated with triage state."""
    triage = db.triage_map(conn, scan["target_path"])
    findings = db.get_findings(conn, scan["id"])
    for f in findings:
        t = triage.get(f["fingerprint"])
        f["triage_status"] = t["status"] if t else "open"
        f["triage_note"] = t["note"] if t else None
    return sort_findings(findings)


def recompute_risk(conn: sqlite3.Connection, scan_id: int) -> int | None:
    scan = db.get_scan(conn, scan_id)
    if scan is None or scan["status"] in ("queued", "running"):
        return None
    score = risk_score(db.get_findings(conn, scan_id), db.triage_map(conn, scan["target_path"]))
    db.update_scan(conn, scan_id, risk_score=score)
    return score


def build_summary(scan: dict[str, Any], runs: list[dict[str, Any]],
                  findings: list[dict[str, Any]]) -> dict[str, Any]:
    by_severity = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        by_severity[f["severity"]] = by_severity.get(f["severity"], 0) + 1
    by_category: dict[str, Any] = {c: {"status": "pending", "count": None, "reason": None} for c in CATEGORIES}
    for r in runs:
        # A count is reported only for a successful run; anything else is unknown (null), never 0.
        by_category[r["category"]] = {
            "status": r["status"],
            "count": r["findings_count"] if r["status"] == "success" else None,
            "reason": r["skip_reason"] or r["error_message"],
        }
    not_run = sum(1 for r in runs if r["status"] in INCOMPLETE_RUN_STATUSES)
    incomplete = scan["status"] in ("partial", "failed")
    return {
        "total": len(findings),
        "false_positives": sum(1 for f in findings if f.get("triage_status") == "false_positive"),
        "by_severity": by_severity,
        "by_category": by_category,
        "risk": {
            "score": scan["risk_score"],
            "level": risk_level(scan["risk_score"], incomplete),
            "incomplete": incomplete,
            "scanners_not_run": not_run,
        },
    }


def scan_detail(conn: sqlite3.Connection, scan: dict[str, Any],
                findings: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    runs = db.get_scanner_runs(conn, scan["id"])
    if findings is None:
        findings = load_findings(conn, scan)
    return {**scan, "scanner_runs": runs, "summary": build_summary(scan, runs, findings)}


def comparison(conn: sqlite3.Connection, base: dict[str, Any], head: dict[str, Any]) -> dict[str, Any]:
    from .engine.compare import compare_scans
    return compare_scans(base, head,
                         db.get_scanner_runs(conn, base["id"]), db.get_scanner_runs(conn, head["id"]),
                         load_findings(conn, base), load_findings(conn, head))
