# DevGuard — Final Readiness Summary

Date: 2026-11-17. Baseline: commit `1f7e1b2` on `main`. The UI-accuracy changes of this final phase (listed below) are committed together with this update. Local results below were produced on that tree before committing.

## Verdict

**PASS for the intended deployment: one user, on their own machine, on `127.0.0.1`.** DevGuard is not designed for, and must not be used as, a network-exposed or multi-user service: it has no authentication and scans directories of the host it runs on.

## Quality gate

| Check | Command or method | Result |
|-------|-------------------|--------|
| Unit and API tests (macOS) | `.venv/bin/pytest -q` | **PASS** — 165 passed |
| Integration tests (macOS) | `.venv/bin/pytest -q -m integration` | **PASS** — 6 passed (real Trivy 0.76.2 and Gitleaks 8.30.1, headless Chrome) |
| Audit regressions F-01 … F-09 | `tests/test_audit_regressions.py`, `tests/test_browser_cdp.py -k narrow` | **PASS** — all pass now; on pre-fix code (`78ee6a6`) 15 of 16 fail, and both narrow-viewport tests fail with the pre-fix stylesheet |
| Browser journeys | headless-Chrome script, 65 checks, two isolated servers | **PASS** — 65 of 65; no request outside `127.0.0.1`; no console or CSP error |
| Narrow screens | automated, 375 px and 320 px, six routes | **PASS** |
| Incomplete scans never read as clean or improved | `.venv/bin/pytest -q -m integration -k incomplete` | **PASS** — fails with the pre-change UI code |
| Secret leak check | `strings <db> \| grep -F -f tests/fixture_secrets.txt` | **PASS** — 0 matches |
| Python dependency vulnerabilities | `trivy fs --scanners vuln requirements.txt` | **PASS** — 0 |
| Coverage | coverage.py, branch mode, unit suite | **93 %** (1373 statements, 79 missed; 332 branches, 34 partial) |
| macOS and Windows, commit `1f7e1b2` | GitHub Actions `macos-latest`, `windows-latest` | **PASS** — 165 unit + 2 real-scanner tests on each |
| macOS and Windows, the commit containing this update | GitHub Actions | see the Actions run for that commit; not known at the time of writing |
| Windows, UI in a browser | — | **NOT VERIFIED** |
| Linux smoke test | unit suite + app start in `python:3.12-slim` (aarch64, non-root) | **PASS** — 165 passed; `/api/health` and `/` respond |
| Linux, real scanners and UI | — | **NOT VERIFIED** |
| Browsers other than Chrome | — | **NOT VERIFIED** |
| Load / large repositories | — | **NOT VERIFIED** |
| Clean install from the public repository | fresh clone, new virtual environment, unit suite (done at commit `0320372`) | **PASS** at that commit; not repeated for the current tree |

## Consistency review

- The three earlier reports were checked against the test output of this phase and updated where counts changed (integration tests 3 → 5, total 168 → 170) and where a gap was closed (F-08 now has an automated test; Linux has a smoke test).
- README, specification and implementation: no contradiction found on scanners, statuses, risk weights and levels, triage re-scoring, configuration keys or API paths (`docs/API.md` and `docs/DATA_MODEL.md` were compared with the registered routes and the schema earlier, at `edf68e8`, and the endpoints added since are documented).
- One inaccuracy remains by choice: on Linux the in-app install hint suggests Homebrew. Linux is not a supported target.

## Changes made in the final phase (UI accuracy)

Two misleading displays were reproduced on real data and fixed in the browser UI only (API, stored scores and scoring rules unchanged; DECISIONS D32, D33):

- A failed scan showed a risk score of "0" on the dashboard; an incomplete scan with score 0 now shows "—" ("No score available"), and a partial scan's score is labelled a lower bound.
- Comparing a completed scan with a partial one showed a green "-20 (lower)" that came only from the scanner that did not run; the Compare page now shows "Not directly comparable" when either scan is incomplete, and by default selects the two most recent completed scans of one target.
- The risk trend no longer plots incomplete scans that have no usable score.
- Files: `devguard/static/js/{dom,charts}.js`, `devguard/static/js/views/{compare,components,dashboard,evaluation}.js`, `devguard/static/css/app.css` (one rule), `tests/test_browser_cdp.py` (`test_browser_incomplete_scans_never_read_as_clean_or_improved`), `docs/DECISIONS.md`, `docs/audit/`.

Earlier phase (commit `1f7e1b2`): narrow-screen fixes and test, triage re-scoring tests, README sections, audit reports.

## Outstanding limitations

- No authentication; localhost only.
- Trivy's stderr tail (2000 characters) is stored, as specified.
- Older scans show the score they finished with next to current triage state.
- Project-level Gitleaks allowlists are ignored by design.
- Dependencies: Node.js `package-lock.json` only. No live Kubernetes cluster is inspected.
- Scans run one at a time.
- Vendored Swagger UI 5.34.1 is not updated automatically.

## Still open after this commit

1. Confirm that the GitHub Actions run for this commit passes on both `macos-latest` and `windows-latest` (the run is linked from the commit on GitHub).
2. Optional: open the UI once in a browser on Windows.

After this commit DevGuard is feature-frozen for academic submission; only confirmed critical defects justify further code changes.
