"""Fixture evaluation run: scans both fixtures and checks the four acceptance criteria."""

from __future__ import annotations

import json
import logging
import platform
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from . import DISCLAIMER, db
from .config import PROJECT_ROOT, Settings
from .db import comparison, load_findings, scan_detail
from .export import FORMATS, _md, build_report
from .models import CATEGORIES, Finding
from .paths import validate_target

log = logging.getLogger("devguard.evaluation")

FINDING_FIELDS = set(Finding.model_fields)


def _check(cid: str, name: str, problems: list[str], evidence: str) -> dict[str, Any]:
    return {"id": cid, "name": name, "passed": not problems,
            "evidence": evidence if not problems else "; ".join(problems)}


def _counts(detail: dict[str, Any]) -> dict[str, Any]:
    return {c: detail["summary"]["by_category"][c] for c in CATEGORIES}


def run_evaluation(settings: Settings, orchestrator, run_id: int, fixtures_dir: Path | None = None) -> None:
    """Runs on the scan queue worker, so scans are executed inline, one after another."""
    fixtures_dir = fixtures_dir or PROJECT_ROOT / "fixtures"
    conn = db.connect(settings.database)
    try:
        expected = json.loads((fixtures_dir / "expected.json").read_text())
        forbidden = [s for s in (PROJECT_ROOT / expected["forbidden_strings_file"]).read_text().split() if s]
        vulnerable = validate_target(str(fixtures_dir / "vulnerable-app"), settings.allowed_roots)
        fixed = validate_target(str(fixtures_dir / "fixed-app"), settings.allowed_roots)

        def scan(target: Path, label: str) -> dict[str, Any]:
            scan_id = db.create_scan(conn, str(target), label)
            orchestrator.run_scan(scan_id)
            return db.get_scan(conn, scan_id)

        s_vuln = scan(vulnerable, "evaluation: vulnerable-app")
        db.update_evaluation_run(conn, run_id, vulnerable_scan_id=s_vuln["id"])
        s_repeat = scan(vulnerable, "evaluation: vulnerable-app (repeat)")
        s_fixed = scan(fixed, "evaluation: fixed-app")
        db.update_evaluation_run(conn, run_id, fixed_scan_id=s_fixed["id"])

        scans = {"vulnerable": s_vuln, "vulnerable_repeat": s_repeat, "fixed": s_fixed}
        details = {k: scan_detail(conn, s) for k, s in scans.items()}
        findings = {k: load_findings(conn, s) for k, s in scans.items()}
        comp = (comparison(conn, s_vuln, s_fixed)
                if all(s["status"] in ("completed", "partial") for s in (s_vuln, s_fixed)) else None)
        checks = []

        # 01 Coverage ------------------------------------------------------
        problems, parts = [], []
        for c in CATEGORIES:
            entry = details["vulnerable"]["summary"]["by_category"][c]
            minimum = expected["vulnerable-app"][c]["min_findings"]
            if entry["status"] != "success":
                problems.append(f"{c}: scanner status is {entry['status']}")
            elif entry["count"] < minimum:
                problems.append(f"{c}: {entry['count']} findings, expected at least {minimum}")
            else:
                parts.append(f"{c} {entry['count']} (min {minimum})")
        checks.append(_check("01", "Coverage", problems, "vulnerable-app findings: " + ", ".join(parts)))

        # 02 Data integrity ------------------------------------------------
        problems = []
        invalid = 0
        for items in findings.values():
            for f in items:
                try:
                    Finding(**{k: v for k, v in f.items() if k in FINDING_FIELDS})
                    if not (f["title"] and f["remediation"] and f["affected_target"]):
                        invalid += 1
                except ValidationError:
                    invalid += 1
        if invalid:
            problems.append(f"{invalid} finding(s) violate the finding contract")
        fp_a = {f["fingerprint"] for f in findings["vulnerable"]}
        fp_b = {f["fingerprint"] for f in findings["vulnerable_repeat"]}
        if fp_a != fp_b or not fp_a:
            problems.append(f"repeat scan fingerprints differ ({len(fp_a ^ fp_b)} mismatches)")
        resolved_txt = []
        if comp is None:
            problems.append("comparison unavailable: a fixture scan failed")
        else:
            for entry in comp["categories"]:
                minimum = expected["comparison"]["resolved_min"][entry["category"]]
                if not entry["comparable"]:
                    problems.append(f"{entry['category']}: not comparable ({entry['reason']})")
                elif entry["resolved"] < minimum:
                    problems.append(f"{entry['category']}: {entry['resolved']} resolved, expected at least {minimum}")
                else:
                    resolved_txt.append(f"{entry['category']} {entry['resolved']}")
        fx = details["fixed"]["summary"]["by_category"]
        max_secret = expected["fixed-app"]["secret"]["max_findings"]
        if fx["secret"]["status"] != "success" or fx["secret"]["count"] > max_secret:
            problems.append("fixed-app: secret expectation not met")
        high = sum(1 for f in findings["fixed"] if f["category"] == "config" and f["severity"] in ("high", "critical"))
        if fx["config"]["status"] != "success" or high > expected["fixed-app"]["config"]["max_high_or_critical"]:
            problems.append("fixed-app: high/critical configuration findings remain")
        total = sum(len(v) for v in findings.values())
        checks.append(_check("02", "Data integrity", problems,
                             f"{total} findings match the contract; repeat scan produced identical "
                             f"{len(fp_a)} fingerprints; resolved: {', '.join(resolved_txt)}"))

        # 03 Safe failure (no fixture secret anywhere) ----------------------
        problems = []
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        surfaces: dict[str, bytes] = {}
        for suffix in ("", "-wal"):
            path = Path(str(settings.database) + suffix)
            if path.exists():
                surfaces[f"database file{suffix}"] = path.read_bytes()
        for key, s in scans.items():
            surfaces[f"API scan payload ({key})"] = json.dumps(details[key]).encode()
            surfaces[f"API findings payload ({key})"] = json.dumps(findings[key]).encode()
            report = build_report(conn, s)
            for fmt, (render, _) in FORMATS.items():
                surfaces[f"{fmt} export ({key})"] = render(report).encode()
        if comp is not None:
            surfaces["API compare payload"] = json.dumps(comp).encode()
        leaks = sorted({name for name, blob in surfaces.items() for s in forbidden if s.encode() in blob})
        if leaks:
            problems.append("fixture secret found in: " + ", ".join(leaks))
        if not forbidden:
            problems.append("forbidden strings file is empty")
        checks.append(_check("03", "Safe failure", problems,
                             f"{len(forbidden)} fixture secrets absent from {len(surfaces)} surfaces "
                             "(database bytes, API payloads, JSON/Markdown/HTML exports)"))

        # 04 Reproducibility -----------------------------------------------
        versions = {r["scanner"]: r["tool_version"] for r in details["vulnerable"]["scanner_runs"]}
        environment = {
            "os": platform.platform(),
            "python": platform.python_version(),
            "trivy": versions.get("trivy-dependency") or versions.get("trivy-config"),
            "gitleaks": versions.get("gitleaks"),
        }
        problems = [f"{k} version not recorded" for k, v in environment.items() if not v]
        problems += [f"{k}: duration not recorded" for k, s in scans.items() if s["elapsed_ms"] is None]
        checks.append(_check("04", "Reproducibility", problems,
                             "; ".join(f"{k} {v}" for k, v in environment.items())
                             + "; durations and finding counts recorded for 3 scans"))

        results = {
            "environment": environment,
            "scans": {k: {"id": s["id"], "target_path": s["target_path"], "status": s["status"],
                          "elapsed_ms": s["elapsed_ms"], "risk_score": s["risk_score"],
                          "by_category": _counts(details[k])} for k, s in scans.items()},
            "comparison": None if comp is None else {
                "totals": comp["totals"], "risk": comp["risk"],
                "categories": comp["categories"]},
            "checks": checks,
        }
        status = "passed" if all(c["passed"] for c in checks) else "failed"
        db.update_evaluation_run(conn, run_id, status=status, results_json=json.dumps(results))
        log.info("Evaluation run %d: %s", run_id, status)
    except Exception as exc:
        log.error("Evaluation run %d errored: %s", run_id, type(exc).__name__)
        db.update_evaluation_run(conn, run_id, status="error", results_json=json.dumps(
            {"error": f"Evaluation could not run ({type(exc).__name__}). Check that the fixtures "
                      "directory is inside an allowed root and that expected.json is present."}))
    finally:
        conn.close()


def evidence_markdown(run: dict[str, Any]) -> str:
    """Report-ready Markdown for one evaluation run."""
    res = run.get("results") or {}
    out = [f"# DevGuard evaluation run #{run['id']}", "", f"- **Date:** {run['created_at']}",
           f"- **Result:** {run['status'].upper()}", ""]
    if res.get("error"):
        return "\n".join(out + [_md(res["error"]), ""])
    out += ["## Environment", "", "| Item | Value |", "|---|---|"]
    out += [f"| {_md(k)} | {_md(v)} |" for k, v in res.get("environment", {}).items()]
    out += ["", "## Fixture scans", "",
            "| Scan | ID | Status | Duration | Dependencies | Secrets | Configurations | Risk score |",
            "|---|---|---|---|---|---|---|---|"]
    for name, s in res.get("scans", {}).items():
        cell = lambda c: s["by_category"][c]["count"] if s["by_category"][c]["count"] is not None \
            else s["by_category"][c]["status"]
        dur = "—" if s["elapsed_ms"] is None else f"{s['elapsed_ms'] / 1000:.1f} s"
        out.append(f"| {_md(name)} | {s['id']} | {_md(s['status'])} | {dur} | {cell('dependency')} "
                   f"| {cell('secret')} | {cell('config')} | {_md(s['risk_score'])} |")
    out += ["", "## Acceptance criteria", "", "| # | Criterion | Result | Evidence |", "|---|---|---|---|"]
    out += [f"| {c['id']} | {_md(c['name'])} | {'PASS' if c['passed'] else 'FAIL'} | {_md(c['evidence'])} |"
            for c in res.get("checks", [])]
    comp = res.get("comparison")
    if comp:
        out += ["", "## Comparison: vulnerable-app → fixed-app", "",
                "| Category | New | Resolved | Persistent |", "|---|---|---|---|"]
        for c in comp["categories"]:
            out.append(f"| {_md(c['category'])} | {c['new']} | {c['resolved']} | {c['persistent']} |"
                       if c["comparable"] else f"| {_md(c['category'])} | Not comparable — {_md(c['reason'])} | | |")
        out += ["", f"Risk score: {comp['risk']['base']} → {comp['risk']['head']} (heuristic, not CVSS)."]
    out += ["", "---", "", f"_{DISCLAIMER}_", ""]
    return "\n".join(out)
