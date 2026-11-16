from __future__ import annotations

import sqlite3
from typing import Literal

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse

from .. import db
from ..db import scan_detail
from ..models import INCOMPLETE_RUN_STATUSES, ApiError, ScanCreate, ScanStatus
from ..paths import PathNotAllowed, validate_target
from . import get_conn, require_scan

router = APIRouter(prefix="/api/scans")


@router.post("", status_code=202)
def create_scan(body: ScanCreate, request: Request, conn: sqlite3.Connection = Depends(get_conn)):
    settings = request.app.state.settings
    try:
        target = validate_target(body.target_path, settings.allowed_roots)
    except PathNotAllowed as exc:
        raise ApiError(400, "path_not_allowed", str(exc)) from None
    label = (body.label or "").strip() or None
    scan_id = db.create_scan(conn, str(target), label)
    request.app.state.orchestrator.submit(scan_id)
    return JSONResponse(scan_detail(conn, db.get_scan(conn, scan_id)), status_code=202)


@router.get("")
def list_scans(conn: sqlite3.Connection = Depends(get_conn),
               target_path: str | None = Query(None, max_length=4096),
               status: ScanStatus | None = None,
               limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0)):
    scans = db.list_scans(conn, target_path, status, limit, offset)
    runs_by_scan = db.scanner_runs_by_scan(conn, [s["id"] for s in scans])
    for s in scans:
        runs = runs_by_scan[s["id"]]
        s["incomplete"] = s["status"] in ("partial", "failed")
        s["scanners_not_run"] = sum(1 for r in runs if r["status"] in INCOMPLETE_RUN_STATUSES)
        # Total is meaningful only when the scan is complete; otherwise it is a lower bound.
        s["findings_total"] = sum(r["findings_count"] or 0 for r in runs if r["status"] == "success")
    return {"items": scans, "targets": db.list_targets(conn)}


@router.get("/{scan_id}")
def get_scan(scan_id: int, conn: sqlite3.Connection = Depends(get_conn)):
    return scan_detail(conn, require_scan(conn, scan_id))


@router.delete("/{scan_id}")
def delete_scan(scan_id: int, conn: sqlite3.Connection = Depends(get_conn)):
    require_scan(conn, scan_id)
    if not db.delete_scan(conn, scan_id):
        raise ApiError(409, "scan_running", "A running scan cannot be deleted.")
    return {"deleted": scan_id}
