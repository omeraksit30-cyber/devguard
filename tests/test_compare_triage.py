from devguard.engine.compare import compare_scans

JSON = {"Content-Type": "application/json"}


def run(cat, status, scanner="x", reason=None):
    return {"category": cat, "status": status, "scanner": scanner, "skip_reason": reason}


def f(cat, fp):
    return {"category": cat, "fingerprint": fp}


def all_ok():
    return [run("dependency", "success"), run("secret", "success", "gitleaks"), run("config", "success")]


def scan_row(i, target="/t", score=10):
    return {"id": i, "target_path": target, "label": None, "status": "completed", "started_at": "x",
            "risk_score": score}


def test_new_persistent_resolved():
    base = [f("dependency", "a"), f("dependency", "b"), f("secret", "s1")]
    head = [f("dependency", "b"), f("dependency", "c"), f("config", "k")]
    r = compare_scans(scan_row(1, score=20), scan_row(2, score=5), all_ok(), all_ok(), base, head)
    assert [x["fingerprint"] for x in r["new"]] == ["c", "k"]
    assert sorted(x["fingerprint"] for x in r["resolved"]) == ["a", "s1"]
    assert [x["fingerprint"] for x in r["persistent"]] == ["b"]
    assert r["totals"] == {"new": 2, "resolved": 2, "persistent": 1}
    assert r["risk"] == {"base": 20, "head": 5, "delta": -15}
    assert r["targets_differ"] is False and r["fully_comparable"] is True


def test_timeout_makes_category_not_comparable_and_nothing_resolved():
    base = [f("secret", "s1"), f("secret", "s2"), f("dependency", "a")]
    head_runs = [run("dependency", "success"), run("secret", "timeout", "gitleaks"), run("config", "success")]
    r = compare_scans(scan_row(1), scan_row(7), all_ok(), head_runs, base, [f("dependency", "a")])
    secret = next(c for c in r["categories"] if c["category"] == "secret")
    assert secret["comparable"] is False and secret["resolved"] is None
    assert secret["reason"] == "gitleaks did not complete in scan #7 (timeout)"
    assert r["resolved"] == [] and r["new"] == []
    assert all(x["category"] != "secret" for k in ("new", "resolved", "persistent") for x in r[k])
    assert r["fully_comparable"] is False


def test_skipped_and_not_installed_are_not_comparable():
    for status in ("skipped", "not_installed", "failed", "pending"):
        base_runs = [run("dependency", status, "trivy-dependency", "No package-lock.json found"),
                     run("secret", "success"), run("config", "success")]
        r = compare_scans(scan_row(1), scan_row(2), base_runs, all_ok(), [], [f("dependency", "n")])
        assert r["categories"][0]["comparable"] is False and r["new"] == []


def test_targets_differ_flag():
    r = compare_scans(scan_row(1, "/a"), scan_row(2, "/b"), all_ok(), all_ok(), [], [])
    assert r["targets_differ"] is True


def test_compare_api(client, scan, tools):
    a = scan()
    tools.mode.update(dependency="clean", secret="timeout")
    b = scan()
    r = client.get(f"/api/compare?base={a['id']}&head={b['id']}").json()
    cats = {c["category"]: c for c in r["categories"]}
    assert cats["dependency"]["resolved"] >= 3 and cats["dependency"]["new"] == 0
    assert cats["secret"]["comparable"] is False and "timeout" in cats["secret"]["reason"]
    assert cats["config"]["persistent"] >= 5 and cats["config"]["resolved"] == 0
    assert all(x["category"] != "secret" for x in r["resolved"])
    assert client.get(f"/api/compare?base={a['id']}&head={a['id']}").status_code == 400
    assert client.get(f"/api/compare?base={a['id']}&head=999").status_code == 404


def test_compare_rejects_failed_scan(client, scan, tools):
    a = scan()
    tools.missing.update({"trivy", "gitleaks"})
    b = scan()
    r = client.get(f"/api/compare?base={a['id']}&head={b['id']}")
    assert r.status_code == 409 and r.json()["error"] == "scan_not_comparable"


def test_triage_lowers_risk_and_persists(client, scan):
    s = scan()
    before = s["summary"]["risk"]["score"]
    crit = client.get(f"/api/scans/{s['id']}/findings?severity=critical").json()["items"][0]
    r = client.put(f"/api/findings/{crit['id']}/triage", json={"status": "false_positive", "note": " test value "})
    assert r.status_code == 200 and r.json()["risk_score"] == before - 10
    assert r.json()["triage"]["note"] == "test value"

    default = client.get(f"/api/scans/{s['id']}/findings").json()["items"]
    assert crit["id"] not in [x["id"] for x in default]                       # hidden by default
    shown = client.get(f"/api/scans/{s['id']}/findings?triage=all").json()["items"]
    assert crit["id"] in [x["id"] for x in shown]                             # never deleted
    assert client.get(f"/api/scans/{s['id']}").json()["summary"]["false_positives"] == 1

    s2 = scan()                                                               # next scan of same target
    assert s2["summary"]["risk"]["score"] == before - 10
    fp = client.get(f"/api/scans/{s2['id']}/findings?triage=false_positive").json()["items"]
    assert [x["fingerprint"] for x in fp] == [crit["fingerprint"]] and fp[0]["triage_note"] == "test value"

    client.put(f"/api/findings/{crit['id']}/triage", json={"status": "open"})
    assert client.get(f"/api/scans/{s2['id']}").json()["summary"]["risk"]["score"] == before


def test_triage_validation(client, scan):
    s = scan()
    fid = client.get(f"/api/scans/{s['id']}/findings").json()["items"][0]["id"]
    assert client.put(f"/api/findings/{fid}/triage", json={"status": "wontfix"}).status_code == 422
    assert client.put(f"/api/findings/{fid}/triage", json={"status": "open", "note": "x" * 1001}).status_code == 422
    assert client.put("/api/findings/99999/triage", json={"status": "open"}).status_code == 404
    r = client.put(f"/api/findings/{fid}/triage", json={"status": "open"}, headers={"Origin": "http://evil.test"})
    assert r.status_code == 403
