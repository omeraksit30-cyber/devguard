from pathlib import Path

import pytest

from devguard.engine.fingerprint import fingerprint
from devguard.engine.normalize import normalize_severity, sort_findings, to_findings
from devguard.engine.risk import risk_level, risk_score
from devguard.models import RawFinding
from devguard.orchestrator import derive_scan_status


def raw(**kw):
    base = dict(rule_or_vulnerability_id="R1", title="t", affected_target="a", remediation="r")
    base.update(kw)
    return RawFinding(**base)


@pytest.mark.parametrize("value,expected", [
    ("CRITICAL", "critical"), ("HIGH", "high"), ("MEDIUM", "medium"), ("LOW", "low"),
    ("high", "high"), ("UNKNOWN", "informational"), ("", "informational"), (None, "informational"),
    ("banana", "informational"),
])
def test_severity_mapping(value, expected):
    assert normalize_severity(value, "dependency") == expected


def test_secrets_are_always_high():
    assert normalize_severity(None, "secret") == "high"


def test_sorting():
    fs = [
        dict(severity="low", category="config", affected_target="b", rule_or_vulnerability_id="1"),
        dict(severity="critical", category="secret", affected_target="z", rule_or_vulnerability_id="1"),
        dict(severity="critical", category="dependency", affected_target="y", rule_or_vulnerability_id="1"),
        dict(severity="critical", category="dependency", affected_target="a", rule_or_vulnerability_id="1"),
        dict(severity="informational", category="config", affected_target="a", rule_or_vulnerability_id="1"),
    ]
    out = sort_findings(fs)
    assert [(f["severity"], f["category"], f["affected_target"]) for f in out] == [
        ("critical", "dependency", "a"), ("critical", "dependency", "y"), ("critical", "secret", "z"),
        ("low", "config", "b"), ("informational", "config", "a")]
    assert sort_findings(fs, "target")[0]["affected_target"] == "a"


def test_fingerprint_stable_and_root_independent():
    a = raw(package_name="lodash", installed_version="4.17.15", file_path="package-lock.json")
    assert fingerprint("dependency", a) == fingerprint("dependency", a.model_copy())
    assert len(fingerprint("dependency", a)) == 64
    # Fingerprints use only relative paths, so two different scan roots agree.
    from devguard.adapters.gitleaks_secret import GitleaksSecretAdapter
    rep = lambda root: [{"RuleID": "x", "File": f"{root}/src/c.js", "StartLine": 4}]
    f1 = GitleaksSecretAdapter().parse(rep("/a/vulnerable-app"), Path("/a/vulnerable-app"))[0]
    f2 = GitleaksSecretAdapter().parse(rep("/b/fixed-app"), Path("/b/fixed-app"))[0]
    assert fingerprint("secret", f1) == fingerprint("secret", f2)


def test_fingerprint_parts_matter():
    base = raw(file_path="f", line_start=3)
    assert fingerprint("secret", base) != fingerprint("secret", raw(file_path="f", line_start=4))
    assert fingerprint("secret", base) != fingerprint("config", base)
    assert fingerprint("config", raw(file_path="f", resource="a")) != fingerprint("config", raw(file_path="f", resource="b"))
    # Text that is not part of the identity does not change it.
    assert fingerprint("secret", base) == fingerprint("secret", raw(file_path="f", line_start=3, description="other"))


def test_dedup_counts_occurrences():
    rows = to_findings([raw(file_path="f"), raw(file_path="f"), raw(file_path="g")], "trivy-config", "config")
    assert sorted(r["occurrences"] for r in rows) == [1, 2]


def test_risk_score_and_false_positive_exclusion():
    fs = [dict(severity=s, fingerprint=s) for s in ("critical", "high", "medium", "low", "informational")]
    assert risk_score(fs, {}) == 18
    assert risk_score(fs, {"critical": {"status": "false_positive"}}) == 8
    assert risk_score(fs, {"critical": {"status": "acknowledged"}}) == 18


@pytest.mark.parametrize("score,level", [(0, "none"), (1, "low"), (9, "low"), (10, "moderate"),
                                         (29, "moderate"), (30, "high"), (59, "high"), (60, "severe")])
def test_risk_levels(score, level):
    assert risk_level(score, False) == level


def test_incomplete_scan_is_never_none():
    assert risk_level(0, True) == "unknown"
    assert risk_level(None, False) is None


@pytest.mark.parametrize("runs,expected", [
    (["success", "success", "success"], "completed"),
    (["success", "skipped", "skipped"], "completed"),
    (["success", "success", "failed"], "partial"),
    (["success", "timeout", "skipped"], "partial"),
    (["success", "not_installed", "success"], "partial"),
    (["skipped", "skipped", "skipped"], "failed"),
    (["failed", "timeout", "not_installed"], "failed"),
    (["skipped", "failed", "skipped"], "failed"),
])
def test_scan_status_derivation(runs, expected):
    assert derive_scan_status(runs) == expected
