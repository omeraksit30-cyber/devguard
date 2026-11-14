"""The most important tests: no fixture secret may appear anywhere DevGuard writes."""

import json
import logging
import shutil
import time
from pathlib import Path

import pytest

from conftest import SECRETS, run_scan

ROOT = Path(__file__).parent.parent


def assert_clean(name, blob):
    data = blob if isinstance(blob, bytes) else blob.encode()
    for s in SECRETS:
        assert s.encode() not in data, f"fixture secret leaked into {name}"


def test_secrets_never_leak_anywhere(client, scan, tools, settings, caplog):
    """Fake Gitleaks writes an UNREDACTED report; nothing downstream may contain a secret."""
    caplog.set_level(logging.DEBUG)
    assert len(SECRETS) >= 3
    s = scan(label="leak")
    sid = s["id"]
    secret_findings = client.get(f"/api/scans/{sid}/findings?category=secret").json()["items"]
    assert len(secret_findings) == len(SECRETS)
    client.put(f"/api/findings/{secret_findings[0]['id']}/triage", json={"status": "acknowledged", "note": "n"})
    s2 = scan()

    responses = {
        "scan": client.get(f"/api/scans/{sid}"), "scans": client.get("/api/scans"),
        "findings": client.get(f"/api/scans/{sid}/findings?triage=all"),
        "finding": client.get(f"/api/findings/{secret_findings[0]['id']}"),
        "compare": client.get(f"/api/compare?base={sid}&head={s2['id']}"),
        **{f"export-{f}": client.get(f"/api/scans/{sid}/export?format={f}") for f in ("json", "md", "html")},
    }
    for name, r in responses.items():
        assert r.status_code == 200, name
        assert_clean(name, r.content)

    client.close()  # flush connections
    for path in settings.database.parent.glob(settings.database.name + "*"):
        assert_clean(path.name, path.read_bytes())
    assert_clean("logs", caplog.text)


def test_gitleaks_stderr_is_never_stored(client, scan, tools):
    """Gitleaks stderr is never kept, even if the tool printed a secret before failing."""
    tools.mode["secret"] = "fail"
    s = scan()
    assert_clean("scan", json.dumps(s))


def test_temp_reports_are_removed(client, scan, tools):
    scan()
    report_dirs = {Path(c[c.index("--report-path" if c[1] == "dir" else "--output") + 1]).parent for c in tools.calls}
    assert len(report_dirs) == 3 and not any(d.exists() for d in report_dirs)


@pytest.mark.parametrize("fmt,ctype", [("json", "application/json"), ("md", "text/markdown"), ("html", "text/html")])
def test_export_formats(client, scan, fmt, ctype):
    s = scan(label="rel <1> | x")
    r = client.get(f"/api/scans/{s['id']}/export?format={fmt}")
    assert r.status_code == 200 and r.headers["content-type"].startswith(ctype)
    assert r.headers["content-disposition"] == f'attachment; filename="devguard-scan-{s["id"]}.{fmt}"'
    assert "DevGuard reports scanner observations, not proof that an application is secure." in r.text
    assert "not a CVSS score" in r.text or fmt == "json"
    if fmt == "json":
        body = r.json()
        assert body["incomplete_warning"] is None and len(body["findings"]) == s["summary"]["total"]
    if fmt == "html":
        assert "<script" not in r.text.lower() and "http://" not in r.text.split("<body>")[0]
        assert "rel &lt;1&gt; | x" in r.text


def test_export_escapes_scanner_text(client, scan, tools, monkeypatch):
    evil = '<script>alert(1)</script> | **x** <img src=x onerror=alert(1)>'
    from devguard.adapters.trivy_config import TrivyConfigAdapter
    orig = TrivyConfigAdapter.parse

    def parse(self, report, target):
        out = orig(self, report, target)
        return [o.model_copy(update={"title": evil, "remediation": evil}) for o in out]

    monkeypatch.setattr(TrivyConfigAdapter, "parse", parse)
    s = scan()
    html_doc = client.get(f"/api/scans/{s['id']}/export?format=html").text
    md_doc = client.get(f"/api/scans/{s['id']}/export?format=md").text
    assert "<script>" not in html_doc and "<img" not in html_doc
    assert "<script>" not in md_doc and "<img" not in md_doc


def test_incomplete_export_puts_warning_first(client, scan, tools):
    tools.missing.add("gitleaks")
    s = scan()
    for fmt in ("md", "html"):
        text = client.get(f"/api/scans/{s['id']}/export?format={fmt}").text
        warn = text.index("This scan is incomplete. 1 scanner(s) did not run.")
        assert warn < text.index("Scanners") and "unknown" in text
    body = client.get(f"/api/scans/{s['id']}/export?format=json").json()
    assert list(body)[2] == "incomplete_warning" and body["scanners_not_run"][0]["scanner"] == "gitleaks"
    assert client.get(f"/api/scans/{s['id']}/export?format=pdf").status_code == 422


def wait_eval(client, run_id):
    for _ in range(3000):
        run = client.get(f"/api/evaluation/runs/{run_id}").json()
        if run["status"] != "running":
            return run
        time.sleep(0.05)
    raise AssertionError("evaluation did not finish")


def test_evaluation_with_fake_tools(client, tools, settings):
    fixtures = settings.allowed_roots[0] / "fixtures"
    shutil.copytree(ROOT / "fixtures", fixtures)
    client.app.state.fixtures_dir = fixtures
    r = client.post("/api/evaluation/run", json={})
    assert r.status_code == 202 and r.json()["status"] == "running"
    run = wait_eval(client, r.json()["id"])
    checks = {c["id"]: c for c in run["results"]["checks"]}
    assert set(checks) == {"01", "02", "03", "04"}
    assert checks["01"]["passed"] and checks["03"]["passed"] and checks["04"]["passed"]
    # The fake returns identical findings for both fixtures, so nothing is "resolved".
    assert not checks["02"]["passed"] and run["status"] == "failed"
    assert run["vulnerable_scan_id"] and run["fixed_scan_id"]
    md = client.get(f"/api/evaluation/runs/{run['id']}/export")
    assert md.status_code == 200 and "| 03 | Safe failure | PASS |" in md.text
    assert_clean("evidence", md.content)
    assert client.get("/api/evaluation/runs").json()["items"][0]["id"] == run["id"]
    assert client.get("/api/evaluation/runs/999").status_code == 404


def test_evaluation_outside_allowed_roots_errors_cleanly(client, tools):
    r = client.post("/api/evaluation/run", json={})   # real fixtures dir is not in the test roots
    run = wait_eval(client, r.json()["id"])
    assert run["status"] == "error" and "allowed root" in run["results"]["error"]


@pytest.mark.integration
def test_real_evaluation_passes():
    from fastapi.testclient import TestClient
    from devguard import runner
    from devguard.app import create_app
    from devguard.config import load_settings
    import dataclasses, tempfile

    if not (runner.find_binary("trivy") and runner.find_binary("gitleaks")):
        pytest.skip("Trivy and Gitleaks are required")
    with tempfile.TemporaryDirectory() as tmp:
        settings = dataclasses.replace(load_settings(ROOT / "devguard.toml"), database=Path(tmp) / "it.db")
        with TestClient(create_app(settings), base_url="http://127.0.0.1:8000") as c:
            run = wait_eval(c, c.post("/api/evaluation/run", json={}).json()["id"])
            assert run["status"] == "passed", run["results"]
            for path in Path(tmp).glob("it.db*"):
                assert_clean(path.name, path.read_bytes())
