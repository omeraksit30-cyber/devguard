from __future__ import annotations

import sqlite3

from fastapi import APIRouter, Depends, Query

from ..errors import ApiError
from ..views import comparison
from . import get_conn, require_scan

router = APIRouter(prefix="/api")


@router.get("/compare")
def compare(base: int = Query(..., ge=1), head: int = Query(..., ge=1),
            conn: sqlite3.Connection = Depends(get_conn)):
    if base == head:
        raise ApiError(400, "same_scan", "Choose two different scans to compare.")
    b, h = require_scan(conn, base), require_scan(conn, head)
    for s in (b, h):
        if s["status"] not in ("completed", "partial"):
            raise ApiError(409, "scan_not_comparable",
                           f"Scan #{s['id']} is {s['status']}; only completed or partial scans can be compared.")
    return comparison(conn, b, h)
