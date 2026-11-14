"""Safe subprocess wrapper. Every scanner invocation goes through run_tool()."""

from __future__ import annotations

import json
import os
import re
import shutil
import signal
import subprocess
import tempfile
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

STDERR_TAIL = 2000
_VERSION_RE = re.compile(r"\d+\.\d+\.\d+[\w.\-+]*")


@dataclass(frozen=True)
class ToolResult:
    exit_code: int | None
    stderr_tail: str
    timed_out: bool
    elapsed_ms: int


class ReportError(Exception):
    """The scanner report is missing, too large or not valid JSON. Message is content-free."""


def find_binary(name: str) -> str | None:
    """Resolve a tool name or absolute path to an executable, or None if not installed."""
    return shutil.which(name)


def _kill_tree(proc: subprocess.Popen) -> None:
    try:
        os.killpg(proc.pid, signal.SIGKILL)  # the scanner runs in its own session
    except (ProcessLookupError, PermissionError):
        pass
    proc.kill()


def run_tool(argv: list[str], timeout: int, cwd: Path, keep_stderr: bool = True) -> ToolResult:
    """Run a tool without a shell. stdout is discarded; reports are written to files.

    keep_stderr=False discards stderr entirely (used for Gitleaks, whose diagnostics
    could contain matched content).
    """
    if not isinstance(argv, list) or not argv or not all(isinstance(a, str) for a in argv):
        raise ValueError("argv must be a non-empty list of strings")
    start = time.monotonic()
    proc = subprocess.Popen(
        argv,
        shell=False,
        cwd=str(cwd),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE if keep_stderr else subprocess.DEVNULL,
        env=os.environ.copy(),
        start_new_session=True,
    )
    timed_out = False
    try:
        _, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        _kill_tree(proc)
        _, err = proc.communicate()
    except BaseException:
        _kill_tree(proc)
        proc.wait()
        raise
    elapsed_ms = int((time.monotonic() - start) * 1000)
    tail = (err or b"").decode("utf-8", "replace")[-STDERR_TAIL:] if keep_stderr else ""
    return ToolResult(None if timed_out else proc.returncode, tail, timed_out, elapsed_ms)


def tool_version(argv: list[str]) -> str | None:
    """Run a version command (e.g. ['trivy', '--version']) and extract x.y.z."""
    try:
        out = subprocess.run(argv, shell=False, capture_output=True, timeout=15,
                             stdin=subprocess.DEVNULL, env=os.environ.copy())
    except (OSError, subprocess.SubprocessError):
        return None
    m = _VERSION_RE.search(out.stdout.decode("utf-8", "replace"))
    return m.group(0) if m else None


@contextmanager
def temp_report_dir() -> Iterator[Path]:
    """Private (0700) temp directory that is always removed, even on error."""
    d = Path(tempfile.mkdtemp(prefix="devguard-"))
    try:
        yield d
    finally:
        shutil.rmtree(d, ignore_errors=True)


def read_report(path: Path, max_bytes: int) -> Any:
    """Load a JSON report, enforcing the size limit. Never includes content in errors."""
    try:
        size = path.stat().st_size
    except OSError:
        raise ReportError("Scanner did not produce a report file") from None
    if size > max_bytes:
        raise ReportError(f"Scanner report exceeds the size limit ({size} > {max_bytes} bytes)")
    try:
        with open(path, "rb") as fh:
            return json.loads(fh.read(max_bytes + 1))
    except (OSError, ValueError, RecursionError):
        raise ReportError("Scanner report is not valid JSON") from None
