# DevGuard — Regression Test Report

Date: 2026-11-17. Local machine: macOS, Python 3.12, Trivy 0.76.2, Gitleaks 8.30.1. Windows results come from GitHub Actions (`windows-latest`).

## Commands and results

| Check | Command | Result |
|-------|---------|--------|
| Unit and API tests | `.venv/bin/pytest -q` | 165 passed, 0 failed, 0 skipped (6 integration tests deselected) |
| Integration tests (real scanners, headless Chrome) | `.venv/bin/pytest -q -m integration` | 6 passed |
| Regression tests on pre-fix code | new test file run in a worktree of `78ee6a6` | 15 failed, 1 passed (the F-09 test, expected) |
| Browser journey script | headless Chrome over DevTools protocol, two isolated servers | 65 of 65 checks passed, 281 requests, none outside `127.0.0.1`, no console or CSP errors, no server tracebacks |
| Narrow viewports | `.venv/bin/pytest -q -m integration -k narrow` (375 px and 320 px, six routes) | 2 passed; with the pre-fix stylesheet both fail (History 866 px wide) |
| Linux smoke test | unit suite and app start in a `python:3.12-slim` container (aarch64, non-root user) | 165 passed; `/api/health` and `/` respond; scanners not installed there |
| Secret leak check | `strings <db> \| grep -F -f tests/fixture_secrets.txt` | 0 matches |
| Python dependency vulnerabilities | `trivy fs --scanners vuln requirements.txt` | 0 |
| Incomplete scans in the UI (D32, D33) | `.venv/bin/pytest -q -m integration -k incomplete` | 1 passed; fails with the pre-change UI code (a failed scan showed risk "0", a partial scan was compared as "-N (lower)") |
| Windows + macOS CI | GitHub Actions run for `1f7e1b2` | both jobs passed: 165 unit + 2 real-scanner tests each |

Totals on macOS: **171 passed, 0 failed, 0 blocked, 0 skipped.**

## Regression test per finding

| Finding | Test (`tests/test_audit_regressions.py`) | Fails on `78ee6a6` | Passes now |
|---------|-------------------------------------------|--------------------|------------|
| F-01 | `test_gitleaks_argv_ignores_project_supplied_suppressions` | yes | yes |
| F-01 | `test_target_cannot_switch_off_secret_detection` (integration) | yes | yes |
| F-02 | `test_triage_rescored_scan_is_latest_finished_one` | yes | yes |
| F-02 | `test_triage_rescoring_by_status_of_the_newer_scan` (5 cases) | not run on old code | yes |
| F-03 | `test_timeout_returns_even_if_detached_grandchild_holds_stderr` | yes | yes |
| F-04 | `test_invalid_config_values_raise_config_error` (8 cases) | yes, all 8 | yes |
| F-05 | `test_relative_path_never_climbs_out_of_the_scan_root` | yes | yes |
| F-06 | `test_unreadable_allowed_root_does_not_break_config_endpoint` | yes | yes |
| F-07 | `test_scan_list_uses_a_constant_number_of_queries` | yes | yes |
| F-09 | `test_conflict_responses_while_work_is_in_progress` | no (behaviour was already correct) | yes |

F-08 is covered by `test_browser_no_horizontal_overflow_on_narrow_screens` in `tests/test_browser_cdp.py` (375 px and 320 px). It fails against the stylesheet of `78ee6a6` and passes now. It needs Chrome and is skipped where Chrome is not found.

## Coverage

Measured with coverage.py (branch mode) over the unit suite, `--source=devguard`:

- **Total: 93 %** (1373 statements, 79 missed; 332 branches, 34 partially covered).
- 16 of 29 modules are fully covered.
- Lowest: `__main__.py` 0 % (server launcher, exercised only by running the app), `runner.py` 85 % (Windows-only branches cannot run on macOS), `evaluation.py` 85 %, `orchestrator.py` 87 %.

Integration tests were not included in the coverage run.

## Not verified

- The changes made after `92a0c8e` (CSS for 320 px, extra F-02 tests, the narrow-viewport test, documentation) had not run on Windows when this report was written; the GitHub Actions run for the commit that contains this report shows the result.
- Linux: only the unit suite and application start were tried. Real scanners and the UI were not tested on Linux.
- The browser tests run on macOS only; the UI has not been opened in a browser on Windows.
- No load or performance benchmark was run.
- Firefox and Safari were not tested.
