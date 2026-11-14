from __future__ import annotations

import json
import sqlite3
from typing import Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, Response

from .. import db
from ..evaluation import evidence_markdown, run_evaluation
from ..models import ApiError
from . import get_conn

router = APIRouter(prefix="/api/evaluation")


def _present(run: dict[str, Any]) -> dict[str, Any]:
    raw = run.pop("results_json", None)
    run["results"] = json.loads(raw) if raw else None
    return run


def _require(conn: sqlite3.Connection, run_id: int) -> dict[str, Any]:
    run = db.get_evaluation_run(conn, run_id)
    if run is None:
        raise ApiError(404, "evaluation_not_found", f"Evaluation run {run_id} does not exist.")
    return _present(run)


@router.post("/run", status_code=202)
def start(request: Request, conn: sqlite3.Connection = Depends(get_conn)):
    run_id = db.create_evaluation_run(conn)
    if run_id is None:
        raise ApiError(409, "evaluation_running", "An evaluation run is already in progress.")
    app = request.app
    app.state.orchestrator.submit_call(run_evaluation, app.state.settings, app.state.orchestrator, run_id,
                                       getattr(app.state, "fixtures_dir", None))
    return JSONResponse(_require(conn, run_id), status_code=202)


@router.get("/runs")
def list_runs(conn: sqlite3.Connection = Depends(get_conn)):
    return {"items": [_present(r) for r in db.list_evaluation_runs(conn)]}


@router.get("/runs/{run_id}")
def get_run(run_id: int, conn: sqlite3.Connection = Depends(get_conn)):
    return _require(conn, run_id)


@router.get("/runs/{run_id}/export")
def export_run(run_id: int, conn: sqlite3.Connection = Depends(get_conn)):
    run = _require(conn, run_id)
    if run["status"] == "running":
        raise ApiError(409, "evaluation_running", "The evaluation run has not finished yet.")
    return Response(evidence_markdown(run), media_type="text/markdown; charset=utf-8", headers={
        "Content-Disposition": f'attachment; filename="devguard-evaluation-{run_id}.md"'})
