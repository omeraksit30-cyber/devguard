"""API routers and shared request dependencies."""

from __future__ import annotations

import sqlite3
from typing import Any, Iterator

from fastapi import Request

from .. import db
from ..models import ApiError


def get_conn(request: Request) -> Iterator[sqlite3.Connection]:
    conn = db.connect(request.app.state.settings.database)
    try:
        yield conn
    finally:
        conn.close()


def require_scan(conn: sqlite3.Connection, scan_id: int) -> dict[str, Any]:
    scan = db.get_scan(conn, scan_id)
    if scan is None:
        raise ApiError(404, "scan_not_found", f"Scan {scan_id} does not exist.")
    return scan
