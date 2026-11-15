import pytest
from fastapi.testclient import TestClient

from devguard.app import create_app
from devguard.config import load_settings


@pytest.fixture
def settings(tmp_path, monkeypatch):
    cfg = tmp_path / "devguard.toml"
    roots = tmp_path / "roots"
    roots.mkdir()
    cfg.write_text(
        f'[server]\nhost="127.0.0.1"\nport=8000\n'
        f'[storage]\ndatabase="{(tmp_path / "test.db").as_posix()}"\n'
        f'[scan]\nallowed_roots=["{roots.as_posix()}"]\ntimeout_seconds=30\n'
    )
    return load_settings(cfg)


@pytest.fixture
def client(settings):
    with TestClient(create_app(settings), base_url="http://127.0.0.1:8000") as c:
        yield c


# ---------------------------------------------------------------- fake scanners

import json
import time
from pathlib import Path

from devguard import orchestrator as orch_module
from devguard import runner as real_runner

SAMPLES = Path(__file__).parent / "samples"
SECRETS = (Path(__file__).parent / "fixture_secrets.txt").read_text().split()


def unredacted_gitleaks_report(target):
    """What Gitleaks would write WITHOUT --redact: the worst case for leak tests."""
    return [{
        "RuleID": "generic-api-key", "Description": "Detected a Generic API Key",
        "StartLine": i + 1, "EndLine": i + 1, "Match": f'key = "{s}"', "Secret": s,
        "Line": f'const key = "{s}";', "File": f"{target}/src/config.js", "Commit": s,
        "Author": s, "Email": s, "Message": f"added {s}", "Tags": [s],
        "Fingerprint": f"{s}:generic-api-key:{i + 1}",
    } for i, s in enumerate(SECRETS)]


class FakeTools:
    """Replaces binary lookup and process execution; writes canned reports."""

    def __init__(self):
        self.missing: set[str] = set()
        self.mode: dict[str, str] = {}      # "dependency" | "secret" | "config" -> ok|clean|timeout|fail|badjson
        self.calls: list[list[str]] = []

    def find_binary(self, name):
        return None if name in self.missing else f"/fake/bin/{name}"

    def tool_version(self, argv):
        return "9.9.9"

    def run_tool(self, argv, timeout, cwd, keep_stderr=True):
        self.calls.append(argv)
        kind = {"fs": "dependency", "config": "config", "dir": "secret"}[argv[1]]
        flag = "--report-path" if kind == "secret" else "--output"
        report = Path(argv[argv.index(flag) + 1])
        target = argv[2] if kind == "secret" else argv[-1]
        mode = self.mode.get(kind, "ok")
        if mode == "timeout":
            return real_runner.ToolResult(None, "", True, 1000)
        if mode == "fail":
            # Gitleaks stderr carries a secret here: the orchestrator must ignore it entirely.
            return real_runner.ToolResult(2, f"leaked {SECRETS[0]}" if kind == "secret" else "fatal error", False, 5)
        if mode == "badjson":
            report.write_text('{"Results": [')
        elif mode == "clean":
            report.write_text("[]" if kind == "secret" else '{"Results": []}')
        elif kind == "secret":
            report.write_text(json.dumps(unredacted_gitleaks_report(target)))
        else:
            name = "trivy_dependency" if kind == "dependency" else "trivy_config"
            report.write_text((SAMPLES / f"{name}_vulnerable-app.json").read_text())
        return real_runner.ToolResult(0, "", False, 5)


@pytest.fixture
def tools(monkeypatch):
    fake = FakeTools()
    for name in ("find_binary", "tool_version", "run_tool"):
        monkeypatch.setattr(orch_module.runner, name, getattr(fake, name))
    return fake


@pytest.fixture
def project(settings):
    p = settings.allowed_roots[0] / "proj"
    (p / "src").mkdir(parents=True)
    (p / "package-lock.json").write_text("{}")
    (p / "Dockerfile").write_text("FROM scratch\n")
    (p / "src" / "config.js").write_text("module.exports = {};\n")
    return p


def run_scan(client, target, label=None, expect=202):
    r = client.post("/api/scans", json={"target_path": str(target), "label": label})
    assert r.status_code == expect, r.text
    if expect != 202:
        return r.json()
    scan_id = r.json()["id"]
    for _ in range(500):
        scan = client.get(f"/api/scans/{scan_id}").json()
        if scan["status"] not in ("queued", "running"):
            return scan
        time.sleep(0.02)
    raise AssertionError("scan did not finish")


@pytest.fixture
def scan(client, tools, project):
    return lambda **kw: run_scan(client, project, **kw)


def symlink_or_skip(link, target, **kw):
    """Create a symlink; skip the test where the OS account may not create one (Windows without Developer Mode)."""
    try:
        link.symlink_to(target, **kw)
    except OSError:
        pytest.skip("symlinks cannot be created on this system")
