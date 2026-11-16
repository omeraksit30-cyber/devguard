# DevGuard — Remediation Report (audit findings F-01 to F-09)

Date: 2026-11-17. Baseline before fixes: commit `78ee6a6`. Fixes: `464e4f9`, `e9c85c8`, `92a0c8e`, plus the follow-up changes listed under "Git status" in `production_readiness_report.md`.

Every finding is **FIXED**. No finding is open, partially fixed or regressed. Each regression test below was run against the pre-fix code (`78ee6a6`) and failed there, except F-09, which adds tests for behaviour that was already correct.

| ID | Severity | Status | Fixed in |
|----|----------|--------|----------|
| F-01 | High | Fixed | `464e4f9` |
| F-02 | Medium | Fixed (2A); 2B kept by design, see below | `464e4f9` |
| F-03 | Medium | Fixed on macOS and Windows | `464e4f9`, `92a0c8e` |
| F-04 | Medium | Fixed | `464e4f9` |
| F-05 | Medium | Fixed | `464e4f9`, `e9c85c8` |
| F-06 | Medium | Fixed | `464e4f9` |
| F-07 | Low | Fixed | `464e4f9` |
| F-08 | Low | Fixed, extended to 320 px | `464e4f9` + follow-up commit |
| F-09 | Info | Tests added | `464e4f9` |

## F-01 — Scanned project could switch off secret detection

- **Original issue:** a `.gitleaks.toml` inside the scanned directory (for example one that allowlists every path) made Gitleaks return no findings; DevGuard showed "success, 0 secrets". `gitleaks:allow` comments had the same effect per line.
- **Root cause:** running the scanner from a private temp directory isolates Trivy's `trivy.yaml` / `.trivyignore`, but Gitleaks reads its config from the scanned path.
- **Fix:** Gitleaks always runs with `--config devguard/adapters/gitleaks.toml` (built-in rules only), `--gitleaks-ignore-path <empty report dir>` and `--ignore-gitleaks-allow`.
- **Files:** `devguard/adapters/gitleaks_secret.py`, `devguard/adapters/gitleaks.toml`, `docs/DECISIONS.md` (D30).
- **Regression tests:** `test_gitleaks_argv_ignores_project_supplied_suppressions`, `test_target_cannot_switch_off_secret_detection` (real Gitleaks 8.30.1; a hostile copy of the fixture with all three suppression methods still yields the same count).
- **Result:** before the fix 4 findings dropped to 0 / 3 / 2 for the three methods; after it all three give 4. Passes on macOS and Windows (CI).
- **Checked, not affected:** Trivy with `.trivyignore` and `trivy.yaml` inside the target (23 config and 22 dependency findings unchanged).
- **Remaining risk:** project-level Gitleaks allowlists are never honoured, so legitimate exceptions must be triaged as false positives. Trivy inline `#trivy:ignore` comments were tried once on the Dockerfile without effect, but were not tested on every rule type.

## F-02 — Triage re-scoring picked an unfinished scan

- **Original issue (2A):** with a newer scan `queued` or `running`, a triage change returned `risk_score: null` and no finished scan was re-scored.
- **Root cause:** `latest_scan_id_for_target()` did not filter by status.
- **Fix:** it now selects the latest scan whose status is not `queued` or `running`.
- **Files:** `devguard/db.py`, `docs/DECISIONS.md` (D31).
- **Regression tests:** `test_triage_rescored_scan_is_latest_finished_one`, `test_triage_rescoring_by_status_of_the_newer_scan` (newer scan queued, running, completed, partial, failed).
- **Design decision (2B):** an older scan keeps the score it finished with while its finding list shows current triage. This is specified behaviour (spec §8.2, D27): only the latest finished scan is re-scored, so the risk trend stays a record of what was known at the time. Historical snapshots are not overwritten.
- **Remaining risk:** on an older scan's page the false-positive count is current while the score is historical. This can confuse a reader; it is documented, not changed.

## F-03 — Scan queue could stall after a scanner timeout

- **Original issue:** after a timeout, `proc.communicate()` waited for a detached grandchild that still held the stderr pipe; the single queue worker was blocked.
- **Fix:** the post-kill wait is bounded (`POST_KILL_WAIT = 3` s). On POSIX the pipe is then closed. On Windows it is left alone, because closing a pipe that subprocess's reader thread is blocked on waits for that read to end.
- **Files:** `devguard/runner.py`.
- **Regression test:** `test_timeout_returns_even_if_detached_grandchild_holds_stderr`.
- **Result:** the first version of the fix still took 20 s on Windows (CI run for `e9c85c8` failed); `92a0c8e` passes on both platforms.
- **Remaining risk:** on Windows the abandoned pipe and reader thread live until the grandchild exits.

## F-04 — Invalid `devguard.toml` types

- **Original issue:** `port = "x"` or `server = "x"` raised an unhandled exception; `port = true` was accepted as 1.
- **Fix:** sections must be tables, integers must be real integers (booleans rejected), strings non-empty; all violations raise `ConfigError`.
- **Files:** `devguard/config.py`. **Test:** `test_invalid_config_values_raise_config_error` (8 cases).

## F-05 — Relative paths climbing out of the scan root

- **Original issue:** a scanner-reported `../../etc/passwd` was stored verbatim.
- **Fix:** a relative path containing `..` is reduced to its file name; backslash-separated relative paths are normalised to `/`.
- **Files:** `devguard/adapters/base.py`. **Test:** `test_relative_path_never_climbs_out_of_the_scan_root`.
- **Remaining risk:** on macOS/Linux a file whose name really contains a backslash is displayed with `/`.

## F-06 — Unreadable allowed root returned 500

- **Fix:** `OSError` while listing a root yields an empty directory list for that root.
- **Files:** `devguard/routes/system.py`. **Test:** `test_unreadable_allowed_root_does_not_break_config_endpoint` (real `chmod 000` on POSIX; injected `PermissionError` on Windows).

## F-07 — N+1 queries in the scan list

- **Fix:** `scanner_runs_by_scan()` loads the runs of all listed scans in one query.
- **Files:** `devguard/db.py`, `devguard/routes/scans.py`. **Test:** `test_scan_list_uses_a_constant_number_of_queries`.

## F-08 — Narrow-screen overflow and a wasted request while polling

- **Fix:** rows, page-head children, grid cells and form fields may shrink to the viewport; grid columns use `minmax(min(…, 100%), 1fr)`. The compare-list request is skipped while a scan is still running.
- **Files:** `devguard/static/css/app.css`, `devguard/static/js/views/scan.js`.
- **Verification:** headless Chrome, `scrollWidth == clientWidth` on all six routes at 375 px and 320 px (before: History 528/375, scan page 468/375; at 320 px Dashboard 356, Compare 375, Evaluation 356).
- **Regression test:** `test_browser_no_horizontal_overflow_on_narrow_screens` (375 px and 320 px); fails with the pre-fix stylesheet.
- **Remaining risk:** measured in Chrome only.

## F-09 — Untested 409 responses

- **Test:** `test_conflict_responses_while_work_is_in_progress` covers delete-while-running, export of queued/running scans, a second evaluation run, and evidence export of a running evaluation.
