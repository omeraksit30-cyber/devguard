"""Scan lifecycle: queueing, parallel adapter execution, status derivation."""

from __future__ import annotations

import logging
import time
from concurrent.futures import Future, ThreadPoolExecutor
from pathlib import Path
from typing import Iterable, Sequence

from . import db, runner
from .adapters.base import ScannerAdapter
from .adapters.gitleaks_secret import GitleaksSecretAdapter
from .adapters.trivy_config import TrivyConfigAdapter
from .adapters.trivy_dependency import TrivyDependencyAdapter
from .config import Settings
from .engine.normalize import to_findings
from .engine.risk import risk_score
from .models import INCOMPLETE_RUN_STATUSES

log = logging.getLogger("devguard.orchestrator")


def default_adapters(settings: Settings) -> list[ScannerAdapter]:
    # Adding a scanner = one adapter file + one line here.
    return [
        TrivyDependencyAdapter(settings.trivy),
        GitleaksSecretAdapter(settings.gitleaks),
        TrivyConfigAdapter(settings.trivy),
    ]


def derive_scan_status(run_statuses: Iterable[str]) -> str:
    statuses = list(run_statuses)
    if "success" not in statuses:
        return "failed"
    if any(s in INCOMPLETE_RUN_STATUSES or s in ("pending", "running") for s in statuses):
        return "partial"
    return "completed"


class Orchestrator:
    def __init__(self, settings: Settings, adapters: Sequence[ScannerAdapter] | None = None):
        self.settings = settings
        self.adapters = list(adapters) if adapters is not None else default_adapters(settings)
        self._queue = ThreadPoolExecutor(max_workers=1, thread_name_prefix="devguard-scan")

    def submit(self, scan_id: int) -> Future:
        return self._queue.submit(self.run_scan, scan_id)

    def submit_call(self, fn, *args) -> Future:
        """Queue an arbitrary job (used by the evaluation run) behind pending scans."""
        return self._queue.submit(fn, *args)

    def shutdown(self) -> None:
        self._queue.shutdown(wait=False, cancel_futures=True)

    # ------------------------------------------------------------ scan

    def run_scan(self, scan_id: int) -> None:
        conn = db.connect(self.settings.database)
        try:
            scan = db.get_scan(conn, scan_id)
            if scan is None or scan["status"] != "queued":
                return  # deleted while queued, or already handled
            started_at, t0 = db.utcnow(), time.monotonic()
            db.update_scan(conn, scan_id, status="running", started_at=started_at)
            target = Path(scan["target_path"])
            log.info("Scan %d started", scan_id)

            with ThreadPoolExecutor(max_workers=max(1, len(self.adapters)),
                                    thread_name_prefix="devguard-adapter") as pool:
                futures = [pool.submit(self._run_adapter, scan_id, target, started_at, a)
                           for a in self.adapters]
                for f in futures:
                    f.result()  # _run_adapter never raises

            runs = db.get_scanner_runs(conn, scan_id)
            status = derive_scan_status(r["status"] for r in runs)
            score = risk_score(db.get_findings(conn, scan_id), db.triage_map(conn, scan["target_path"]))
            db.update_scan(conn, scan_id, status=status, finished_at=db.utcnow(),
                           elapsed_ms=int((time.monotonic() - t0) * 1000), risk_score=score)
            log.info("Scan %d finished: %s", scan_id, status)
        except Exception as exc:  # last-resort guard so the queue worker survives
            log.error("Scan %d crashed: %s", scan_id, type(exc).__name__)
            try:
                db.update_scan(conn, scan_id, status="failed", finished_at=db.utcnow(), risk_score=0)
            except Exception:
                pass
        finally:
            conn.close()

    # ------------------------------------------------------------ one adapter

    def _run_adapter(self, scan_id: int, target: Path, scan_started_at: str, adapter: ScannerAdapter) -> None:
        conn = db.connect(self.settings.database)  # each thread uses its own connection
        sensitive = not adapter.keep_stderr
        t0 = time.monotonic()

        def finish(status: str, **fields) -> None:
            db.update_scanner_run(conn, scan_id, adapter.name, status=status, finished_at=db.utcnow(),
                                  elapsed_ms=int((time.monotonic() - t0) * 1000), **fields)
            log.info("Scan %d %s: %s (exit=%s, findings=%s)", scan_id, adapter.name, status,
                     fields.get("exit_code"), fields.get("findings_count"))

        try:
            binary = runner.find_binary(adapter.binary)
            if binary is None:
                return finish("not_installed", error_message=f"{adapter.binary} was not found on PATH")
            db.update_scanner_run(conn, scan_id, adapter.name,
                                  tool_version=runner.tool_version([binary, *adapter.version_argv()[1:]]))

            skip_reason = adapter.precheck(target)
            if skip_reason:
                return finish("skipped", skip_reason=skip_reason)

            db.update_scanner_run(conn, scan_id, adapter.name, status="running", started_at=db.utcnow())
            with runner.temp_report_dir() as tmp:
                report_path = tmp / "report.json"
                argv = adapter.build_argv(target, report_path)
                argv[0] = binary
                # cwd is the private temp dir, not the target: tools must not pick up
                # configuration files (e.g. trivy.yaml) from the scanned project.
                result = runner.run_tool(argv, self.settings.timeout_seconds, tmp,
                                         keep_stderr=adapter.keep_stderr)
                if result.timed_out:
                    return finish("timeout",
                                  error_message=f"Timed out after {self.settings.timeout_seconds} seconds")
                if result.exit_code != 0:
                    message = (f"Gitleaks exited with code {result.exit_code}" if sensitive
                               else result.stderr_tail.strip() or f"Exited with code {result.exit_code}")
                    return finish("failed", exit_code=result.exit_code, error_message=message)
                try:
                    report = runner.read_report(report_path, self.settings.max_report_bytes)
                except runner.ReportError as exc:
                    return finish("failed", exit_code=result.exit_code, error_message=str(exc))
            # The temp dir (and the raw report file) is gone from here on.

            rows = to_findings(adapter.parse(report, target), adapter.name, adapter.category)
            del report
            scan = db.get_scan(conn, scan_id)
            if scan is None:
                return
            known = db.first_seen_map(conn, scan["target_path"], [r["fingerprint"] for r in rows])
            for r in rows:
                r["scan_id"] = scan_id
                r["first_seen"] = known.get(r["fingerprint"], scan_started_at)
            with db.transaction(conn):
                db.insert_findings(conn, rows)
                finish("success", exit_code=result.exit_code, findings_count=len(rows))
        except Exception as exc:
            # Never store exception text for sensitive adapters; it could echo report content.
            message = (f"{adapter.name} failed while processing its report" if sensitive
                       else f"Unexpected error: {type(exc).__name__}")
            log.warning("Scan %d %s raised %s", scan_id, adapter.name, type(exc).__name__)
            try:
                finish("failed", error_message=message, findings_count=None)
            except Exception:
                pass
        finally:
            conn.close()
