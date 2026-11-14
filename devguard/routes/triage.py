from __future__ import annotations

import sqlite3

from fastapi import APIRouter, Depends

from .. import db
from ..db import recompute_risk
from ..models import ApiError, TriageUpdate
from . import get_conn

router = APIRouter(prefix="/api")


@router.put("/findings/{finding_id}/triage")
def set_triage(finding_id: int, body: TriageUpdate, conn: sqlite3.Connection = Depends(get_conn)):
    f = db.get_finding(conn, finding_id)
    if f is None:
        raise ApiError(404, "finding_not_found", f"Finding {finding_id} does not exist.")
    scan = db.get_scan(conn, f["scan_id"])
    note = (body.note or "").strip() or None
    triage = db.set_triage(conn, scan["target_path"], f["fingerprint"], body.status, note)
    # Triage is keyed by (target, fingerprint); refresh the latest scan of that target.
    latest = db.latest_scan_id_for_target(conn, scan["target_path"])
    score = recompute_risk(conn, latest) if latest is not None else None
    return {"finding_id": finding_id, "triage": triage, "latest_scan_id": latest, "risk_score": score}
