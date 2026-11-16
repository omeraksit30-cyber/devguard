import json
import logging
from pathlib import Path

import pytest

from conftest import symlink_or_skip
from devguard.adapters.gitleaks_secret import GitleaksSecretAdapter
from devguard.adapters.trivy_config import TrivyConfigAdapter
from devguard.adapters.trivy_dependency import TrivyDependencyAdapter

SAMPLES = Path(__file__).parent / "samples"
TARGET = Path("fixtures/vulnerable-app")
SECRETS = (Path(__file__).parent / "fixture_secrets.txt").read_text().split()


def sample(name):
    return json.loads((SAMPLES / name).read_text())


def unredacted_gitleaks_report(target="/abs/proj"):
    """Hand-built report as Gitleaks would emit WITHOUT --redact (worst case)."""
    return [{
        "RuleID": "generic-api-key", "Description": "Detected a Generic API Key",
        "StartLine": i + 1, "EndLine": i + 1, "StartColumn": 1, "EndColumn": 50,
        "Match": f'key = "{s}"', "Secret": s, "Line": f'const key = "{s}";',
        "File": f"{target}/src/config.js", "SymlinkFile": "", "Commit": s, "Entropy": 4.5,
        "Author": s, "Email": s, "Date": "", "Message": f"added {s}", "Tags": [s],
        "Fingerprint": f"{s}:generic-api-key:{i + 1}",
    } for i, s in enumerate(SECRETS)]


# ---------------------------------------------------------------- trivy dependency

def test_dependency_parses_real_sample():
    fs = TrivyDependencyAdapter().parse(sample("trivy_dependency_vulnerable-app.json"), TARGET)
    assert len(fs) >= 3
    assert {f.package_name for f in fs} >= {"lodash", "minimist"}
    for f in fs:
        assert f.file_path == "package-lock.json"
        assert f.affected_target == f"{f.package_name}@{f.installed_version}"
        assert f.original_severity in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}
        assert f.remediation.startswith(("Upgrade ", "No fixed version"))
        assert len(f.description) <= 4000
    assert TrivyDependencyAdapter().parse(sample("trivy_dependency_fixed-app.json"), TARGET) == []


def test_dependency_remediation_and_title_fallback():
    report = {"Results": [{"Target": "package-lock.json", "Type": "npm", "Vulnerabilities": [
        {"VulnerabilityID": "CVE-1", "PkgName": "a", "InstalledVersion": "1.0.0", "FixedVersion": "1.0.1"},
        {"VulnerabilityID": "CVE-2", "PkgName": "b", "InstalledVersion": "2.0.0"},
        {"PkgName": "missing-id", "InstalledVersion": "1"},
    ]}, {"Target": "requirements.txt", "Type": "pip", "Vulnerabilities": [
        {"VulnerabilityID": "CVE-3", "PkgName": "c", "InstalledVersion": "1"}]}]}
    a, b = TrivyDependencyAdapter().parse(report, TARGET)
    assert a.remediation == "Upgrade a from 1.0.0 to 1.0.1 or later, then regenerate package-lock.json."
    assert a.title == "CVE-1 in a"
    assert b.fixed_version is None and b.remediation.startswith("No fixed version")


def test_dependency_precheck(tmp_path):
    ad = TrivyDependencyAdapter()
    assert ad.precheck(tmp_path) == "No package-lock.json found"
    (tmp_path / "node_modules" / "x").mkdir(parents=True)
    (tmp_path / "node_modules" / "x" / "package-lock.json").write_text("{}")
    assert ad.precheck(tmp_path) is not None       # node_modules is ignored
    outside = tmp_path.parent / "outside-package-lock.json"
    outside.write_text("{}")
    symlink_or_skip(tmp_path / "package-lock.json", outside)
    assert ad.precheck(tmp_path) is not None       # symlinked lockfile is ignored
    (tmp_path / "package-lock.json").unlink()
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "package-lock.json").write_text("{}")
    assert ad.precheck(tmp_path) is None


def test_dependency_argv_disables_other_scanners():
    argv = TrivyDependencyAdapter("trivy").build_argv(Path("/t"), Path("/r/report.json"))
    assert argv[:4] == ["trivy", "fs", "--scanners", "vuln"] and argv[-1] == str(Path("/t"))


# ---------------------------------------------------------------- trivy config

def test_config_parses_real_sample():
    fs = TrivyConfigAdapter().parse(sample("trivy_config_vulnerable-app.json"), TARGET)
    assert len(fs) >= 5
    assert {f.file_path for f in fs} == {"Dockerfile", "k8s/deployment.yaml"}
    for f in fs:
        assert f.rule_or_vulnerability_id and f.title and f.remediation
    fixed = TrivyConfigAdapter().parse(sample("trivy_config_fixed-app.json"), TARGET)
    assert not [f for f in fixed if f.original_severity in ("HIGH", "CRITICAL")]


def test_config_only_fail_and_never_reads_code():
    report = {"Results": [{"Target": "Dockerfile", "Misconfigurations": [
        {"ID": "X1", "Title": "t", "Status": "PASS", "Severity": "HIGH"},
        {"AVDID": "AVD-2", "Title": "t2", "Status": "FAIL", "Severity": "LOW", "Description": "d",
         "Message": "m", "Resolution": "", "CauseMetadata": {
             "Resource": "Deployment/app", "StartLine": 3, "EndLine": 4,
             "Code": {"Lines": [{"Content": "ENV PASSWORD=SuperSecretValue123"}]}}},
        {"Status": "FAIL", "Title": "no id"},
    ]}]}
    (f,) = TrivyConfigAdapter().parse(report, TARGET)
    assert f.rule_or_vulnerability_id == "AVD-2" and f.description == "d\n\nm"
    assert f.remediation == "Review the rule reference and adjust the configuration."
    assert f.affected_target == "Dockerfile (Deployment/app)" and (f.line_start, f.line_end) == (3, 4)
    assert "SuperSecretValue123" not in f.model_dump_json()


def test_config_precheck(tmp_path):
    ad = TrivyConfigAdapter()
    assert ad.precheck(tmp_path) == "No Dockerfile or YAML manifests found"
    outside = tmp_path.parent / "outside-Dockerfile"
    outside.write_text("FROM scratch")
    symlink_or_skip(tmp_path / "Dockerfile", outside)
    assert ad.precheck(tmp_path) is not None       # symlinked Dockerfile is ignored
    (tmp_path / "Dockerfile").unlink()
    (tmp_path / "Dockerfile.prod").write_text("FROM x")
    assert ad.precheck(tmp_path) is None


# ---------------------------------------------------------------- gitleaks

def test_gitleaks_parses_real_sample():
    fs = GitleaksSecretAdapter().parse(sample("gitleaks_vulnerable-app.json"), TARGET)
    assert len(fs) >= 3
    assert {f.file_path for f in fs} == {".env.example", "src/config.js"}
    for f in fs:
        assert f.original_severity is None and f.title == f"Potential secret: {f.rule_or_vulnerability_id}"
        assert f.affected_target == f"{f.file_path}:{f.line_start}"
    assert GitleaksSecretAdapter().parse(sample("gitleaks_fixed-app.json"), TARGET) == []


def test_recorded_gitleaks_sample_is_redacted():
    raw = (SAMPLES / "gitleaks_vulnerable-app.json").read_text()
    assert all(s not in raw for s in SECRETS)


def test_gitleaks_unredacted_report_never_leaks(caplog):
    caplog.set_level(logging.DEBUG)
    report = unredacted_gitleaks_report() + [{"Secret": SECRETS[0], "Match": SECRETS[0]}, SECRETS[0]]
    fs = GitleaksSecretAdapter().parse(report, Path("/abs/proj"))
    assert len(fs) == len(SECRETS)
    blob = json.dumps([f.model_dump() for f in fs]) + caplog.text
    assert all(s not in blob for s in SECRETS)
    assert fs[0].file_path == "src/config.js"


def test_gitleaks_argv_always_redacts():
    argv = GitleaksSecretAdapter("gitleaks").build_argv(Path("/t"), Path("/r/report.json"))
    assert "--redact" in argv and argv[:3] == ["gitleaks", "dir", str(Path("/t"))]
    assert argv[argv.index("--exit-code") + 1] == "0"
    assert GitleaksSecretAdapter.keep_stderr is False


# ---------------------------------------------------------------- robustness

@pytest.mark.parametrize("adapter", [TrivyDependencyAdapter(), TrivyConfigAdapter()])
@pytest.mark.parametrize("report", [
    {}, {"Results": None}, {"Results": []}, {"Results": [None, 5, "x"]},
    {"Results": [{"Target": "f", "Vulnerabilities": None, "Misconfigurations": None}]},
    {"Results": [{"Vulnerabilities": [{}, None], "Misconfigurations": [{}, None, {"Status": "FAIL"}]}]},
    {"Results": [{"Target": 7, "Vulnerabilities": [{"VulnerabilityID": 1, "PkgName": [], "Severity": {}}],
                  "Misconfigurations": [{"Status": "FAIL", "ID": 3, "Title": None, "CauseMetadata": "x"}]}]},
])
def test_trivy_parsers_tolerate_odd_reports(adapter, report):
    assert adapter.parse(report, TARGET) == []


@pytest.mark.parametrize("adapter", [TrivyDependencyAdapter(), TrivyConfigAdapter()])
def test_trivy_parsers_reject_wrong_top_level(adapter):
    with pytest.raises(ValueError):
        adapter.parse([], TARGET)


def test_gitleaks_parser_robustness():
    ad = GitleaksSecretAdapter()
    assert ad.parse([], TARGET) == []
    assert ad.parse([{}, None, {"RuleID": "x"}, {"RuleID": "x", "File": "f", "StartLine": "3"}], TARGET) == []
    with pytest.raises(ValueError):
        ad.parse({"findings": []}, TARGET)
