from __future__ import annotations

import sqlite3

from fastapi import APIRouter, Depends, Query

from ..db import comparison
from ..models import ApiError
from . import get_conn, require_scan

router = APIRouter(prefix="/api")


@router.get("/compare")
def compare(base: int | None = Query(None, ge=1), head: int | None = Query(None, ge=1),
            base_scan_id: int | None = Query(None, ge=1), head_scan_id: int | None = Query(None, ge=1),
            conn: sqlite3.Connection = Depends(get_conn)):
    base_id = base if base is not None else base_scan_id
    head_id = head if head is not None else head_scan_id
    if base_id is None or head_id is None:
        raise ApiError(422, "validation_error", "Invalid request: query.base, query.head")
    if base_id == head_id:
        raise ApiError(400, "same_scan", "Choose two different scans to compare.")
    b, h = require_scan(conn, base_id), require_scan(conn, head_id)
    for s in (b, h):
        if s["status"] not in ("completed", "partial"):
            raise ApiError(409, "scan_not_comparable",
                           f"Scan #{s['id']} is {s['status']}; only completed or partial scans can be compared.")
    return comparison(conn, b, h)
