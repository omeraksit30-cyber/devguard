from __future__ import annotations

import sqlite3
from typing import Literal

from fastapi import APIRouter, Depends, Query

from .. import db
from ..engine.normalize import sort_findings
from ..errors import ApiError
from ..models import Category, ScannerName, Severity
from ..views import load_findings
from . import get_conn, require_scan

router = APIRouter(prefix="/api")


@router.get("/scans/{scan_id}/findings")
def list_findings(
    scan_id: int,
    conn: sqlite3.Connection = Depends(get_conn),
    category: Category | None = None,
    severity: list[Severity] | None = Query(None),
    scanner: ScannerName | None = None,
    triage: Literal["open", "acknowledged", "false_positive", "all"] | None = None,
    q: str | None = Query(None, max_length=200),
    sort: Literal["severity", "category", "target"] = "severity",
    limit: int = Query(500, ge=1, le=2000),
    offset: int = Query(0, ge=0),
):
    scan = require_scan(conn, scan_id)
    items = load_findings(conn, scan)
    if category:
        items = [f for f in items if f["category"] == category]
    if severity:
        items = [f for f in items if f["severity"] in severity]
    if scanner:
        items = [f for f in items if f["scanner"] == scanner]
    if triage is None:  # default: hide false positives
        items = [f for f in items if f["triage_status"] != "false_positive"]
    elif triage != "all":
        items = [f for f in items if f["triage_status"] == triage]
    if q and q.strip():
        needle = q.strip().lower()
        items = [f for f in items if needle in f["title"].lower()
                 or needle in f["rule_or_vulnerability_id"].lower()
                 or needle in f["affected_target"].lower()]
    items = sort_findings(items, sort)
    return {"total": len(items), "items": items[offset:offset + limit]}


@router.get("/findings/{finding_id}")
def get_finding(finding_id: int, conn: sqlite3.Connection = Depends(get_conn)):
    f = db.get_finding(conn, finding_id)
    if f is None:
        raise ApiError(404, "finding_not_found", f"Finding {finding_id} does not exist.")
    scan = db.get_scan(conn, f["scan_id"])
    t = db.triage_map(conn, scan["target_path"]).get(f["fingerprint"])
    run = next((r for r in db.get_scanner_runs(conn, scan["id"]) if r["scanner"] == f["scanner"]), None)
    return {
        **f,
        "target_path": scan["target_path"],
        "scanner_version": run["tool_version"] if run else None,
        "triage": {"status": t["status"] if t else "open", "note": t["note"] if t else None,
                   "updated_at": t["updated_at"] if t else None},
        "seen_in_scans": db.scans_with_fingerprint(conn, scan["target_path"], f["fingerprint"]),
    }
