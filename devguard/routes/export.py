from __future__ import annotations

import sqlite3
from typing import Literal

from fastapi import APIRouter, Depends
from fastapi.responses import Response

from ..errors import ApiError
from ..export import FORMATS, build_report
from . import get_conn, require_scan

router = APIRouter(prefix="/api")


@router.get("/scans/{scan_id}/export")
def export_scan(scan_id: int, format: Literal["json", "md", "html"] = "json",
                conn: sqlite3.Connection = Depends(get_conn)):
    scan = require_scan(conn, scan_id)
    if scan["status"] in ("queued", "running"):
        raise ApiError(409, "scan_not_finished", "The scan has not finished yet.")
    render, media_type = FORMATS[format]
    return Response(render(build_report(conn, scan)), media_type=media_type, headers={
        "Content-Disposition": f'attachment; filename="devguard-scan-{scan_id}.{format}"'})
