import pytest

from conftest import SECRETS, run_scan


def cat(scan, name):
    return scan["summary"]["by_category"][name]


def test_end_to_end_scan(client, scan):
    s = scan(label="first")
    assert s["status"] == "completed" and s["label"] == "first"
    assert {r["status"] for r in s["scanner_runs"]} == {"success"}
    assert all(r["tool_version"] == "9.9.9" for r in s["scanner_runs"])
    assert cat(s, "dependency")["count"] >= 3 and cat(s, "secret")["count"] == len(SECRETS)
    assert s["summary"]["total"] == sum(cat(s, c)["count"] for c in ("dependency", "secret", "config"))
    assert s["summary"]["risk"]["score"] > 0 and s["summary"]["risk"]["incomplete"] is False

    items = client.get(f"/api/scans/{s['id']}/findings").json()["items"]
    ranks = ["critical", "high", "medium", "low", "informational"]
    assert [ranks.index(f["severity"]) for f in items] == sorted(ranks.index(f["severity"]) for f in items)
    for f in items:
        assert f["remediation"] and f["scanner"] and len(f["fingerprint"]) == 64 and f["first_seen"]
        assert not (f["file_path"] or "").startswith("/")


def test_scanners_run_outside_target_directory(client, scan, tools):
    scan()
    assert len(tools.calls) == 3
    gitleaks = next(c for c in tools.calls if c[1] == "dir")
    assert "--redact" in gitleaks


def test_missing_binary_gives_partial_and_null_count(client, scan, tools):
    tools.missing.add("gitleaks")
    s = scan()
    assert s["status"] == "partial"
    assert cat(s, "secret") == {"status": "not_installed", "count": None,
                                "reason": "gitleaks was not found on PATH"}
    assert cat(s, "dependency")["status"] == "success" and cat(s, "config")["status"] == "success"
    assert s["summary"]["risk"]["incomplete"] is True and s["summary"]["risk"]["scanners_not_run"] == 1


@pytest.mark.parametrize("mode,status", [("timeout", "timeout"), ("fail", "failed"), ("badjson", "failed")])
@pytest.mark.parametrize("kind", ["dependency", "secret", "config"])
def test_safe_failure_never_reports_zero(client, scan, tools, mode, status, kind):
    tools.mode[kind] = mode
    s = scan()
    assert s["status"] == "partial"
    assert cat(s, kind)["status"] == status and cat(s, kind)["count"] is None
    run = next(r for r in s["scanner_runs"] if r["category"] == kind)
    assert run["findings_count"] is None and run["error_message"]


def test_gitleaks_failure_message_is_fixed(client, scan, tools):
    tools.mode["secret"] = "fail"
    run = next(r for r in scan()["scanner_runs"] if r["scanner"] == "gitleaks")
    assert run["error_message"] == "Gitleaks exited with code 2"


def test_all_scanners_failing_is_failed_and_unknown(client, scan, tools):
    tools.missing.update({"trivy", "gitleaks"})
    s = scan()
    assert s["status"] == "failed"
    assert s["summary"]["risk"]["level"] == "unknown" and s["summary"]["risk"]["scanners_not_run"] == 3


def test_skipped_is_not_clean(client, tools, settings):
    empty = settings.allowed_roots[0] / "empty"
    empty.mkdir()
    s = run_scan(client, empty)
    assert cat(s, "dependency") == {"status": "skipped", "count": None, "reason": "No package-lock.json found"}
    assert cat(s, "config")["status"] == "skipped" and s["status"] == "completed"


def test_clean_success_reports_zero(client, scan, tools):
    tools.mode.update(dependency="clean", secret="clean", config="clean")
    s = scan()
    assert s["status"] == "completed" and s["summary"]["total"] == 0
    assert cat(s, "secret")["count"] == 0 and s["summary"]["risk"]["level"] == "none"


def test_path_outside_roots_rejected(client, tools, tmp_path):
    body = run_scan(client, tmp_path, expect=400)
    assert body["error"] == "path_not_allowed" and str(tmp_path) not in body["message"].split(":")[0]
    assert tools.calls == []


def test_validation_error_does_not_echo_values(client, tools):
    r = client.post("/api/scans", json={"target_path": "/x", "bogus": SECRETS[0]})
    assert r.status_code == 422 and SECRETS[0] not in r.text


def test_first_seen_persists_across_scans(client, scan):
    a, b = scan(), scan()
    fa = client.get(f"/api/scans/{a['id']}/findings").json()["items"]
    fb = client.get(f"/api/scans/{b['id']}/findings").json()["items"]
    assert {f["fingerprint"] for f in fa} == {f["fingerprint"] for f in fb}
    assert {f["first_seen"] for f in fb} == {a["started_at"]}


def test_finding_filters(client, scan):
    sid = scan()["id"]
    get = lambda qs: client.get(f"/api/scans/{sid}/findings?{qs}").json()
    assert {f["category"] for f in get("category=secret")["items"]} == {"secret"}
    assert {f["severity"] for f in get("severity=critical&severity=low")["items"]} <= {"critical", "low"}
    assert all("lodash" in (f["title"] + f["affected_target"]).lower() for f in get("q=lodash")["items"])
    assert get("scanner=trivy-config")["total"] == get("category=config")["total"]
    assert len(get("limit=2&offset=1")["items"]) == 2
    assert client.get(f"/api/scans/{sid}/findings?category=nope").status_code == 422
    assert client.get("/api/scans/9999/findings").status_code == 404


def test_finding_detail(client, scan):
    s = scan()
    f = client.get(f"/api/scans/{s['id']}/findings?category=secret").json()["items"][0]
    d = client.get(f"/api/findings/{f['id']}").json()
    assert d["triage"]["status"] == "open" and d["seen_in_scans"] == [s["id"]]
    assert d["scanner_version"] == "9.9.9" and d["original_severity"] is None and d["severity"] == "high"
    assert client.get("/api/findings/99999").json()["error"] == "finding_not_found"


def test_list_and_delete(client, scan):
    a, b = scan(), scan()
    listed = client.get("/api/scans").json()
    assert [s["id"] for s in listed["items"]] == [b["id"], a["id"]]
    assert listed["items"][0]["findings_total"] == b["summary"]["total"]
    assert client.get("/api/scans?status=failed").json()["items"] == []
    r = client.delete(f"/api/scans/{a['id']}", headers={"Content-Type": "application/json"})
    assert r.status_code == 200
    assert client.get(f"/api/scans/{a['id']}").status_code == 404
    assert client.delete("/api/scans/999", headers={"Content-Type": "application/json"}).status_code == 404


def test_system_endpoints(client, settings, project):
    tools = client.get("/api/system/tools").json()
    assert {t["name"] for t in tools} == {"trivy", "gitleaks"}
    cfg = client.get("/api/system/config").json()
    assert cfg["allowed_roots"][0]["directories"] == [str(project)]


def test_real_subprocess_timeout_seconds_one(tmp_path):
    """End-to-end check with a real hanging child process and timeout_seconds = 1."""
    import sys
    from fastapi.testclient import TestClient
    from devguard.app import create_app
    from devguard.config import load_settings

    slow = tmp_path / "slow-scanner"
    slow.write_text(
        f"#!{sys.executable}\n"
        "import sys, time\n"
        "if '--version' in sys.argv or 'version' in sys.argv:\n"
        "    print('version 1.2.3')\n"
        "    sys.exit(0)\n"
        "time.sleep(10)\n"
    )
    slow.chmod(0o755)
    roots = tmp_path / "roots"
    proj = roots / "proj"
    proj.mkdir(parents=True)
    (proj / "package-lock.json").write_text("{}")
    (proj / "Dockerfile").write_text("FROM scratch\n")
    cfg = tmp_path / "devguard.toml"
    cfg.write_text(
        f'[server]\nhost="127.0.0.1"\nport=8000\n'
        f'[storage]\ndatabase="{tmp_path / "timeout.db"}"\n'
        f'[scan]\nallowed_roots=["{roots}"]\ntimeout_seconds=1\n'
        f'[tools]\ntrivy="{slow}"\ngitleaks="{slow}"\n'
    )
    with TestClient(create_app(load_settings(cfg)), base_url="http://127.0.0.1:8000") as c:
        s = run_scan(c, proj, label="timeout-check")
        assert s["status"] == "failed"
        assert {r["status"] for r in s["scanner_runs"]} == {"timeout"}
        for r in s["scanner_runs"]:
            assert r["findings_count"] is None
            assert "Timed out after 1 seconds" in r["error_message"]
        for k in ("dependency", "secret", "config"):
            assert s["summary"]["by_category"][k]["status"] == "timeout"
            assert s["summary"]["by_category"][k]["count"] is None
        assert s["summary"]["risk"]["incomplete"] is True
        assert s["summary"]["risk"]["level"] == "unknown"
