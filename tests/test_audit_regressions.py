"""Regression tests for defects found in the November 2026 audit (F-01 … F-09)."""

import os
import shutil
import sys
import time
from pathlib import Path

import pytest

from conftest import run_scan
from devguard import db, runner
from devguard.adapters.base import relative_path
from devguard.adapters.gitleaks_secret import DEFAULT_CONFIG, GitleaksSecretAdapter
from devguard.config import ConfigError, load_settings

FIXTURE = Path(__file__).parent.parent / "fixtures" / "vulnerable-app"


# ------------------------------------------------------------------ F-01

def test_gitleaks_argv_ignores_project_supplied_suppressions():
    argv = GitleaksSecretAdapter("gitleaks").build_argv(Path("/t"), Path("/r/report.json"))
    assert argv[argv.index("--config") + 1] == str(DEFAULT_CONFIG) and DEFAULT_CONFIG.is_file()
    assert argv[argv.index("--gitleaks-ignore-path") + 1] == str(Path("/r"))
    assert "--ignore-gitleaks-allow" in argv and "--redact" in argv


@pytest.mark.integration
def test_target_cannot_switch_off_secret_detection(tmp_path):
    """A scanned project's own .gitleaks.toml, .gitleaksignore and allow comments change nothing."""
    ad = GitleaksSecretAdapter()
    if not runner.find_binary(ad.binary):
        pytest.skip("Gitleaks is required")

    def count(target):
        with runner.temp_report_dir() as tmp:
            report = tmp / "r.json"
            runner.run_tool(ad.build_argv(target, report), 120, tmp, keep_stderr=False)
            return len(ad.parse(runner.read_report(report, 50_000_000), target))

    clean = tmp_path / "clean"
    shutil.copytree(FIXTURE, clean)
    expected = count(clean)
    assert expected >= 3

    hostile = tmp_path / "hostile"
    shutil.copytree(FIXTURE, hostile)
    (hostile / ".gitleaks.toml").write_text("[allowlist]\npaths = ['''.*''']\n")
    (hostile / ".gitleaksignore").write_text("src/config.js:generic-api-key:5\n")
    cfg = hostile / "src" / "config.js"
    cfg.write_text("\n".join(line + " // gitleaks:allow" if '"' in line else line
                             for line in cfg.read_text().splitlines()) + "\n")
    assert count(hostile) == expected


# ------------------------------------------------------------------ F-02

def test_triage_rescored_scan_is_latest_finished_one(client, scan, settings, project):
    s = scan()
    before = s["summary"]["risk"]["score"]
    conn = db.connect(settings.database)
    try:
        queued_id = db.create_scan(conn, str(project), "still queued")   # never submitted to the worker
    finally:
        conn.close()
    crit = client.get(f"/api/scans/{s['id']}/findings?severity=critical").json()["items"][0]
    r = client.put(f"/api/findings/{crit['id']}/triage", json={"status": "false_positive"}).json()
    assert r["latest_scan_id"] == s["id"] != queued_id and r["risk_score"] == before - 10
    assert client.get(f"/api/scans/{s['id']}").json()["summary"]["risk"]["score"] == before - 10


@pytest.mark.parametrize("newer_status,rescored", [
    ("queued", "older"), ("running", "older"),              # unfinished scans have no score to refresh
    ("completed", "newer"), ("partial", "newer"), ("failed", "newer"),
])
def test_triage_rescoring_by_status_of_the_newer_scan(client, scan, settings, project, newer_status, rescored):
    s = scan()
    before = s["summary"]["risk"]["score"]
    conn = db.connect(settings.database)
    try:
        newer = db.create_scan(conn, str(project), "newer")
        db.update_scan(conn, newer, status=newer_status, risk_score=None if newer_status in ("queued", "running") else 0)
    finally:
        conn.close()
    crit = client.get(f"/api/scans/{s['id']}/findings?severity=critical").json()["items"][0]
    r = client.put(f"/api/findings/{crit['id']}/triage", json={"status": "false_positive"}).json()
    older_score = client.get(f"/api/scans/{s['id']}").json()["summary"]["risk"]["score"]
    newer_scan = client.get(f"/api/scans/{newer}").json()
    if rescored == "older":
        assert r["latest_scan_id"] == s["id"] and r["risk_score"] == older_score == before - 10
        assert newer_scan["status"] == newer_status and newer_scan["summary"]["risk"]["score"] is None
    else:
        # The newer finished scan is re-scored (it holds no findings here, so 0); the older scan keeps
        # the score it finished with — historical snapshots are never rewritten (DECISIONS D27).
        assert r["latest_scan_id"] == newer and r["risk_score"] == 0
        assert older_score == before
        assert newer_scan["summary"]["risk"]["level"] == ("none" if newer_status == "completed" else "unknown")


# ------------------------------------------------------------------ F-03

def test_timeout_returns_even_if_detached_grandchild_holds_stderr(tmp_path, monkeypatch):
    monkeypatch.setattr(runner, "POST_KILL_WAIT", 1)
    if sys.platform == "win32":
        # An intermediate child that exits immediately breaks the parent-PID chain walked by
        # taskkill /T while the grandchild keeps the inherited stderr handle open.
        grand = "import time; time.sleep(20)"
        mid = f"import subprocess, sys; subprocess.Popen([sys.executable, '-c', {grand!r}], close_fds=False)"
        parent = f"import subprocess, sys, time; subprocess.run([sys.executable, '-c', {mid!r}], close_fds=False); time.sleep(20)"
    else:
        child = "import os, time; os.setsid(); time.sleep(20)"
        parent = f"import subprocess, sys, time; subprocess.Popen([sys.executable, '-c', {child!r}]); time.sleep(20)"
    start = time.monotonic()
    r = runner.run_tool([sys.executable, "-c", parent], 1, tmp_path)
    assert r.timed_out and r.exit_code is None and time.monotonic() - start < 8


# ------------------------------------------------------------------ F-04

@pytest.mark.parametrize("body", [
    '[server]\nport = "not-an-int"\n',
    "[server]\nport = true\n",
    'server = "invalid"\n',
    "[scan]\ntimeout_seconds = true\n",
    "[scan]\ntimeout_seconds = 1.5\n",
    "[scan]\nallowed_roots = [1, 2]\n",
    "[tools]\ntrivy = 5\n",
    "[storage]\ndatabase = false\n",
])
def test_invalid_config_values_raise_config_error(tmp_path, body):
    cfg = tmp_path / "c.toml"
    cfg.write_text(body)
    with pytest.raises(ConfigError):
        load_settings(cfg)


# ------------------------------------------------------------------ F-05

def test_relative_path_never_climbs_out_of_the_scan_root(tmp_path):
    assert relative_path("../../etc/passwd", tmp_path) == "passwd"
    assert relative_path(r"..\..\etc\passwd", tmp_path) == "passwd"
    assert relative_path("../outside/secret.js", tmp_path) == "secret.js"
    assert relative_path("src/config.js", tmp_path) == "src/config.js"
    assert relative_path(r"src\config.js", tmp_path) == "src/config.js"
    assert relative_path(str(tmp_path / "k8s" / "deployment.yaml"), tmp_path) == "k8s/deployment.yaml"


# ------------------------------------------------------------------ F-06

def test_unreadable_allowed_root_does_not_break_config_endpoint(client, settings, monkeypatch):
    root = settings.allowed_roots[0]
    if sys.platform == "win32" or (hasattr(os, "geteuid") and os.geteuid() == 0):
        def deny(self):
            raise PermissionError(13, "Permission denied")
        monkeypatch.setattr(Path, "iterdir", deny)
        r = client.get("/api/system/config")
    else:
        root.chmod(0o000)
        try:
            r = client.get("/api/system/config")
        finally:
            root.chmod(0o755)
    assert r.status_code == 200 and r.json()["allowed_roots"][0]["directories"] == []


# ------------------------------------------------------------------ F-07

def test_scan_list_uses_a_constant_number_of_queries(settings, client):
    conn = db.connect(settings.database)
    try:
        ids = [db.create_scan(conn, "/x", None) for _ in range(20)]
        seen = []
        conn.set_trace_callback(seen.append)
        runs = db.scanner_runs_by_scan(conn, ids)
        conn.set_trace_callback(None)
    finally:
        conn.close()
    assert len(seen) == 1 and all(len(runs[i]) == 3 for i in ids)
    assert len(client.get("/api/scans?limit=200").json()["items"]) == 20


# ------------------------------------------------------------------ F-09

def test_conflict_responses_while_work_is_in_progress(client, settings, project):
    conn = db.connect(settings.database)
    try:
        queued = db.create_scan(conn, str(project), None)
        running = db.create_scan(conn, str(project), None)
        db.update_scan(conn, running, status="running")
        run_id = db.create_evaluation_run(conn)
    finally:
        conn.close()
    json_header = {"Content-Type": "application/json"}
    r = client.delete(f"/api/scans/{running}", headers=json_header)
    assert r.status_code == 409 and r.json()["error"] == "scan_running"
    for sid in (queued, running):
        r = client.get(f"/api/scans/{sid}/export?format=json")
        assert r.status_code == 409 and r.json()["error"] == "scan_not_finished"
    r = client.post("/api/evaluation/run", json={})
    assert r.status_code == 409 and r.json()["error"] == "evaluation_running"
    r = client.get(f"/api/evaluation/runs/{run_id}/export")
    assert r.status_code == 409 and r.json()["error"] == "evaluation_running"
    assert client.delete(f"/api/scans/{queued}", headers=json_header).status_code == 200
