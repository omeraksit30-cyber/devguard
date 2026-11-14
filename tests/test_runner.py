import json
import sys

import pytest

from devguard import runner


def test_run_success_and_stderr_tail(tmp_path):
    r = runner.run_tool([sys.executable, "-c", "import sys; sys.stderr.write('e'*5000); sys.exit(3)"], 10, tmp_path)
    assert r.exit_code == 3 and not r.timed_out and len(r.stderr_tail) == 2000


def test_stderr_discarded_when_not_kept(tmp_path):
    r = runner.run_tool([sys.executable, "-c", "import sys; sys.stderr.write('TOPSECRET')"], 10, tmp_path,
                        keep_stderr=False)
    assert r.exit_code == 0 and r.stderr_tail == ""


def test_timeout_kills_process(tmp_path):
    r = runner.run_tool([sys.executable, "-c", "import time; time.sleep(30)"], 1, tmp_path)
    assert r.timed_out and r.exit_code is None and r.elapsed_ms < 10_000


def test_no_shell_interpretation(tmp_path):
    marker = tmp_path / "pwned"
    runner.run_tool([sys.executable, "-c", "pass", f"; touch {marker}", f"$(touch {marker})"], 10, tmp_path)
    assert not marker.exists()


def test_argv_must_be_list(tmp_path):
    with pytest.raises(ValueError):
        runner.run_tool("echo hi", 5, tmp_path)  # type: ignore[arg-type]


def test_missing_binary():
    assert runner.find_binary("definitely-not-a-real-tool-xyz") is None


def test_tool_version_parses():
    assert runner.tool_version([sys.executable, "-c", "print('Version: 0.76.2\\nmore')"]) == "0.76.2"
    assert runner.tool_version(["/nonexistent/binary"]) is None


def test_temp_dir_removed_even_on_error():
    with pytest.raises(RuntimeError):
        with runner.temp_report_dir() as d:
            (d / "report.json").write_text("{}")
            assert (d.stat().st_mode & 0o777) == 0o700
            raise RuntimeError
    assert not d.exists()


def test_read_report(tmp_path):
    p = tmp_path / "r.json"
    p.write_text(json.dumps({"a": 1}))
    assert runner.read_report(p, 100) == {"a": 1}
    with pytest.raises(runner.ReportError):
        runner.read_report(p, 3)                       # too large
    p.write_text('{"Secret": "hunter2-broken')
    with pytest.raises(runner.ReportError) as exc:
        runner.read_report(p, 1000)                    # malformed
    assert "hunter2" not in str(exc.value)
    with pytest.raises(runner.ReportError):
        runner.read_report(tmp_path / "missing.json", 100)
