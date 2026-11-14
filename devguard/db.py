"""SQLite connection, schema and a thin repository layer. All SQL is parameterised."""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable, Iterator

from .engine.compare import compare_scans
from .engine.normalize import sort_findings
from .engine.risk import risk_level, risk_score
from .models import CATEGORIES, INCOMPLETE_RUN_STATUSES, SCANNER_CATEGORY, SEVERITY_ORDER

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  target_path   TEXT NOT NULL,
  label         TEXT,
  status        TEXT NOT NULL,
  created_at    TEXT NOT NULL,
  started_at    TEXT,
  finished_at   TEXT,
  elapsed_ms    INTEGER,
  risk_score    INTEGER
);
CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target_path, id);

CREATE TABLE IF NOT EXISTS scanner_runs (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id        INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  scanner        TEXT NOT NULL,
  category       TEXT NOT NULL,
  status         TEXT NOT NULL,
  tool_version   TEXT,
  exit_code      INTEGER,
  error_message  TEXT,
  skip_reason    TEXT,
  started_at     TEXT,
  finished_at    TEXT,
  elapsed_ms     INTEGER,
  findings_count INTEGER,
  UNIQUE (scan_id, scanner)
);

CREATE TABLE IF NOT EXISTS findings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  scanner TEXT NOT NULL,
  category TEXT NOT NULL,
  rule_or_vulnerability_id TEXT NOT NULL,
  title TEXT NOT NULL,
  severity TEXT NOT NULL,
  original_severity TEXT,
  affected_target TEXT NOT NULL,
  file_path TEXT,
  package_name TEXT,
  installed_version TEXT,
  fixed_version TEXT,
  line_start INTEGER,
  line_end INTEGER,
  resource TEXT,
  description TEXT NOT NULL,
  remediation TEXT NOT NULL,
  reference_url TEXT,
  fingerprint TEXT NOT NULL,
  first_seen TEXT NOT NULL,
  occurrences INTEGER NOT NULL DEFAULT 1,
  UNIQUE (scan_id, fingerprint)
);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id, category, severity);
CREATE INDEX IF NOT EXISTS idx_findings_fp   ON findings(fingerprint);

CREATE TABLE IF NOT EXISTS triage (
  target_path TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  status      TEXT NOT NULL,
  note        TEXT,
  updated_at  TEXT NOT NULL,
  PRIMARY KEY (target_path, fingerprint)
);

CREATE TABLE IF NOT EXISTS evaluation_runs (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at  TEXT NOT NULL,
  status      TEXT NOT NULL,
  vulnerable_scan_id INTEGER REFERENCES scans(id) ON DELETE SET NULL,
  fixed_scan_id      INTEGER REFERENCES scans(id) ON DELETE SET NULL,
  results_json TEXT
);
"""

FINDING_COLUMNS = (
    "scan_id", "scanner", "category", "rule_or_vulnerability_id", "title", "severity",
    "original_severity", "affected_target", "file_path", "package_name", "installed_version",
    "fixed_version", "line_start", "line_end", "resource", "description", "remediation",
    "reference_url", "fingerprint", "first_seen", "occurrences",
)


def utcnow() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def connect(path: Path) -> sqlite3.Connection:
    """Open a new connection. Each thread must use its own connection."""
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, timeout=30, isolation_level=None)  # autocommit; explicit transactions
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA busy_timeout = 30000")
    conn.execute("PRAGMA secure_delete = ON")  # overwrite deleted content on disk
    return conn


@contextmanager
def transaction(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    else:
        conn.execute("COMMIT")


def init_db(path: Path) -> None:
    """Create the schema and mark scans interrupted by a previous shutdown as failed."""
    conn = connect(path)
    try:
        conn.executescript(SCHEMA)
        with transaction(conn):
            now = utcnow()
            stale = [r["id"] for r in conn.execute(
                "SELECT id FROM scans WHERE status IN ('queued', 'running')")]
            for scan_id in stale:
                conn.execute(
                    "UPDATE scanner_runs SET status='failed', error_message=?, finished_at=?, "
                    "findings_count=NULL WHERE scan_id=? AND status IN ('pending', 'running')",
                    ("Interrupted by server restart", now, scan_id))
                conn.execute("UPDATE scans SET status='failed', finished_at=? WHERE id=?", (now, scan_id))
            conn.execute(
                "UPDATE evaluation_runs SET status='error' WHERE status='running'")
    finally:
        conn.close()


def _row(r: sqlite3.Row | None) -> dict[str, Any] | None:
    return dict(r) if r is not None else None


# ---------------------------------------------------------------- scans

def create_scan(conn: sqlite3.Connection, target_path: str, label: str | None) -> int:
    with transaction(conn):
        cur = conn.execute(
            "INSERT INTO scans (target_path, label, status, created_at) VALUES (?, ?, 'queued', ?)",
            (target_path, label, utcnow()))
        scan_id = cur.lastrowid
        conn.executemany(
            "INSERT INTO scanner_runs (scan_id, scanner, category, status) VALUES (?, ?, ?, 'pending')",
            [(scan_id, s, c) for s, c in SCANNER_CATEGORY.items()])
    return int(scan_id)


def get_scan(conn: sqlite3.Connection, scan_id: int) -> dict[str, Any] | None:
    return _row(conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone())


def list_scans(conn: sqlite3.Connection, target_path: str | None = None, status: str | None = None,
               limit: int = 50, offset: int = 0) -> list[dict[str, Any]]:
    where, params = [], []
    if target_path:
        where.append("target_path = ?")
        params.append(target_path)
    if status:
        where.append("status = ?")
        params.append(status)
    sql = "SELECT * FROM scans" + (" WHERE " + " AND ".join(where) if where else "")
    sql += " ORDER BY id DESC LIMIT ? OFFSET ?"
    return [dict(r) for r in conn.execute(sql, (*params, limit, offset))]


def update_scan(conn: sqlite3.Connection, scan_id: int, **fields: Any) -> None:
    allowed = {"status", "started_at", "finished_at", "elapsed_ms", "risk_score"}
    if not fields or not set(fields) <= allowed:
        raise ValueError(f"invalid scan fields: {set(fields) - allowed}")
    cols = ", ".join(f"{k}=?" for k in fields)  # keys come from the allowlist above
    conn.execute(f"UPDATE scans SET {cols} WHERE id=?", (*fields.values(), scan_id))


def delete_scan(conn: sqlite3.Connection, scan_id: int) -> None:
    with transaction(conn):
        conn.execute("DELETE FROM scans WHERE id=?", (scan_id,))


def latest_scan_id_for_target(conn: sqlite3.Connection, target_path: str) -> int | None:
    r = conn.execute("SELECT id FROM scans WHERE target_path=? ORDER BY id DESC LIMIT 1",
                     (target_path,)).fetchone()
    return r["id"] if r else None


# ---------------------------------------------------------------- scanner runs

def get_scanner_runs(conn: sqlite3.Connection, scan_id: int) -> list[dict[str, Any]]:
    return [dict(r) for r in conn.execute(
        "SELECT * FROM scanner_runs WHERE scan_id=? ORDER BY id", (scan_id,))]


def update_scanner_run(conn: sqlite3.Connection, scan_id: int, scanner: str, **fields: Any) -> None:
    allowed = {"status", "tool_version", "exit_code", "error_message", "skip_reason",
               "started_at", "finished_at", "elapsed_ms", "findings_count"}
    if not fields or not set(fields) <= allowed:
        raise ValueError(f"invalid scanner_run fields: {set(fields) - allowed}")
    if "error_message" in fields and fields["error_message"] is not None:
        fields["error_message"] = str(fields["error_message"])[:2000]
    cols = ", ".join(f"{k}=?" for k in fields)
    conn.execute(f"UPDATE scanner_runs SET {cols} WHERE scan_id=? AND scanner=?",
                 (*fields.values(), scan_id, scanner))


# ---------------------------------------------------------------- findings

def insert_findings(conn: sqlite3.Connection, findings: Iterable[dict[str, Any]]) -> None:
    placeholders = ", ".join("?" for _ in FINDING_COLUMNS)
    conn.executemany(
        f"INSERT INTO findings ({', '.join(FINDING_COLUMNS)}) VALUES ({placeholders})",
        [tuple(f.get(c) for c in FINDING_COLUMNS) for f in findings])


def get_findings(conn: sqlite3.Connection, scan_id: int) -> list[dict[str, Any]]:
    return [dict(r) for r in conn.execute("SELECT * FROM findings WHERE scan_id=?", (scan_id,))]


def get_finding(conn: sqlite3.Connection, finding_id: int) -> dict[str, Any] | None:
    return _row(conn.execute("SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone())


def first_seen_map(conn: sqlite3.Connection, target_path: str,
                   fingerprints: Iterable[str]) -> dict[str, str]:
    """Earliest scan start time per fingerprint for this target (previous scans only)."""
    fps = list(fingerprints)
    out: dict[str, str] = {}
    for i in range(0, len(fps), 500):
        chunk = fps[i:i + 500]
        q = ", ".join("?" for _ in chunk)
        for r in conn.execute(
                f"SELECT f.fingerprint, MIN(f.first_seen) AS fs FROM findings f "
                f"JOIN scans s ON s.id=f.scan_id WHERE s.target_path=? AND f.fingerprint IN ({q}) "
                f"GROUP BY f.fingerprint", (target_path, *chunk)):
            out[r["fingerprint"]] = r["fs"]
    return out


def scans_with_fingerprint(conn: sqlite3.Connection, target_path: str, fingerprint: str) -> list[int]:
    return [r["id"] for r in conn.execute(
        "SELECT s.id FROM scans s JOIN findings f ON f.scan_id=s.id "
        "WHERE s.target_path=? AND f.fingerprint=? ORDER BY s.id", (target_path, fingerprint))]


# ---------------------------------------------------------------- triage

def triage_map(conn: sqlite3.Connection, target_path: str) -> dict[str, dict[str, Any]]:
    return {r["fingerprint"]: dict(r) for r in conn.execute(
        "SELECT * FROM triage WHERE target_path=?", (target_path,))}


def set_triage(conn: sqlite3.Connection, target_path: str, fingerprint: str,
               status: str, note: str | None) -> dict[str, Any]:
    now = utcnow()
    with transaction(conn):
        conn.execute(
            "INSERT INTO triage (target_path, fingerprint, status, note, updated_at) VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT(target_path, fingerprint) DO UPDATE SET status=excluded.status, "
            "note=excluded.note, updated_at=excluded.updated_at",
            (target_path, fingerprint, status, note, now))
    return {"status": status, "note": note, "updated_at": now}


# ---------------------------------------------------------------- evaluation runs

def create_evaluation_run(conn: sqlite3.Connection) -> int:
    cur = conn.execute("INSERT INTO evaluation_runs (created_at, status) VALUES (?, 'running')", (utcnow(),))
    return int(cur.lastrowid)


def update_evaluation_run(conn: sqlite3.Connection, run_id: int, **fields: Any) -> None:
    allowed = {"status", "vulnerable_scan_id", "fixed_scan_id", "results_json"}
    if not fields or not set(fields) <= allowed:
        raise ValueError(f"invalid evaluation_run fields: {set(fields) - allowed}")
    cols = ", ".join(f"{k}=?" for k in fields)
    conn.execute(f"UPDATE evaluation_runs SET {cols} WHERE id=?", (*fields.values(), run_id))


def list_evaluation_runs(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    return [dict(r) for r in conn.execute("SELECT * FROM evaluation_runs ORDER BY id DESC")]


def get_evaluation_run(conn: sqlite3.Connection, run_id: int) -> dict[str, Any] | None:
    return _row(conn.execute("SELECT * FROM evaluation_runs WHERE id=?", (run_id,)).fetchone())


def list_targets(conn: sqlite3.Connection) -> list[str]:
    return [r["target_path"] for r in conn.execute(
        "SELECT DISTINCT target_path FROM scans ORDER BY target_path")]


# ---------------------------------------------------------------- read models

def load_findings(conn: sqlite3.Connection, scan: dict[str, Any]) -> list[dict[str, Any]]:
    """All findings of a scan, severity-sorted, annotated with triage state."""
    triage = triage_map(conn, scan["target_path"])
    findings = get_findings(conn, scan["id"])
    for f in findings:
        t = triage.get(f["fingerprint"])
        f["triage_status"] = t["status"] if t else "open"
        f["triage_note"] = t["note"] if t else None
    return sort_findings(findings)


def recompute_risk(conn: sqlite3.Connection, scan_id: int) -> int | None:
    scan = get_scan(conn, scan_id)
    if scan is None or scan["status"] in ("queued", "running"):
        return None
    score = risk_score(get_findings(conn, scan_id), triage_map(conn, scan["target_path"]))
    update_scan(conn, scan_id, risk_score=score)
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
    runs = get_scanner_runs(conn, scan["id"])
    if findings is None:
        findings = load_findings(conn, scan)
    return {**scan, "scanner_runs": runs, "summary": build_summary(scan, runs, findings)}


def comparison(conn: sqlite3.Connection, base: dict[str, Any], head: dict[str, Any]) -> dict[str, Any]:
    return compare_scans(base, head,
                         get_scanner_runs(conn, base["id"]), get_scanner_runs(conn, head["id"]),
                         load_findings(conn, base), load_findings(conn, head))

