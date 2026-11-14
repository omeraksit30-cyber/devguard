import pytest
from pydantic import ValidationError

from devguard import db
from devguard.models import RawFinding, Scan, ScannerRun, TriageUpdate


@pytest.fixture
def conn(tmp_path):
    path = tmp_path / "t.db"
    db.init_db(path)
    c = db.connect(path)
    yield c
    c.close()


def _finding(scan_id, fp="a" * 64, **kw):
    base = dict(scan_id=scan_id, scanner="trivy-config", category="config", rule_or_vulnerability_id="DS002",
                title="t", severity="high", original_severity="HIGH", affected_target="Dockerfile",
                file_path="Dockerfile", description="d", remediation="r", fingerprint=fp,
                first_seen=db.utcnow(), occurrences=1)
    base.update(kw)
    return base


def test_pragmas_and_tables(conn):
    assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"scans", "scanner_runs", "findings", "triage", "evaluation_runs"} <= tables


def test_create_scan_creates_three_pending_runs(conn):
    sid = db.create_scan(conn, "/x", "lbl")
    assert db.get_scan(conn, sid)["status"] == "queued"
    runs = db.get_scanner_runs(conn, sid)
    assert [r["scanner"] for r in runs] == ["trivy-dependency", "gitleaks", "trivy-config"]
    assert all(r["status"] == "pending" and r["findings_count"] is None for r in runs)


def test_delete_cascades(conn):
    sid = db.create_scan(conn, "/x", None)
    db.insert_findings(conn, [_finding(sid)])
    db.delete_scan(conn, sid)
    assert conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM scanner_runs").fetchone()[0] == 0


def test_unique_fingerprint_per_scan(conn):
    sid = db.create_scan(conn, "/x", None)
    db.insert_findings(conn, [_finding(sid)])
    with pytest.raises(Exception):
        db.insert_findings(conn, [_finding(sid)])


def test_restart_marks_interrupted_scans_failed(tmp_path):
    path = tmp_path / "r.db"
    db.init_db(path)
    c = db.connect(path)
    sid = db.create_scan(c, "/x", None)
    db.update_scan(c, sid, status="running")
    c.close()
    db.init_db(path)
    c = db.connect(path)
    assert db.get_scan(c, sid)["status"] == "failed"
    runs = db.get_scanner_runs(c, sid)
    assert all(r["status"] == "failed" and r["error_message"] == "Interrupted by server restart" for r in runs)
    c.close()


def test_update_rejects_unknown_columns(conn):
    sid = db.create_scan(conn, "/x", None)
    with pytest.raises(ValueError):
        db.update_scan(conn, sid, **{"status=1; DROP TABLE scans; --": "x"})


def test_triage_upsert_and_first_seen(conn):
    sid = db.create_scan(conn, "/x", None)
    db.insert_findings(conn, [_finding(sid, first_seen="2026-01-01T00:00:00.000Z")])
    assert db.first_seen_map(conn, "/x", ["a" * 64]) == {"a" * 64: "2026-01-01T00:00:00.000Z"}
    db.set_triage(conn, "/x", "a" * 64, "acknowledged", "n1")
    db.set_triage(conn, "/x", "a" * 64, "false_positive", None)
    assert db.triage_map(conn, "/x")["a" * 64]["status"] == "false_positive"


def test_models_validate():
    with pytest.raises(ValidationError):
        TriageUpdate(status="bogus")
    with pytest.raises(ValidationError):
        TriageUpdate(status="open", note="x" * 1001)
    with pytest.raises(ValidationError):
        RawFinding(rule_or_vulnerability_id="x", title="t", affected_target="a", remediation="r", Secret="s")


def test_scan_and_scanner_run_models_match_db_rows(conn):
    sid = db.create_scan(conn, "/x", "lbl")
    scan = Scan(**db.get_scan(conn, sid))
    assert scan.id == sid and scan.status == "queued"
    runs = [ScannerRun(**r) for r in db.get_scanner_runs(conn, sid)]
    assert len(runs) == 3 and all(r.status == "pending" for r in runs)
