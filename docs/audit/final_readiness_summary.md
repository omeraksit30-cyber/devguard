# DevGuard — Final Readiness Summary

Date: 2026-11-17. Baseline: commit `92a0c8e` on `main`. The changes of this phase (listed below) are committed together with this file. Local results below were produced on that tree before committing.

## Verdict

**PASS for the intended deployment: one user, on their own machine, on `127.0.0.1`.** DevGuard is not designed for, and must not be used as, a network-exposed or multi-user service: it has no authentication and scans directories of the host it runs on.

## Quality gate

| Check | Command or method | Result |
|-------|-------------------|--------|
| Unit and API tests (macOS) | `.venv/bin/pytest -q` | **PASS** — 165 passed |
| Integration tests (macOS) | `.venv/bin/pytest -q -m integration` | **PASS** — 5 passed (real Trivy 0.76.2 and Gitleaks 8.30.1, headless Chrome) |
| Audit regressions F-01 … F-09 | `tests/test_audit_regressions.py`, `tests/test_browser_cdp.py -k narrow` | **PASS** — all pass now; on pre-fix code (`78ee6a6`) 15 of 16 fail, and both narrow-viewport tests fail with the pre-fix stylesheet |
| Browser journeys | headless-Chrome script, 65 checks, two isolated servers | **PASS** — 65 of 65; no request outside `127.0.0.1`; no console or CSP error |
| Narrow screens | automated, 375 px and 320 px, six routes | **PASS** |
| Secret leak check | `strings <db> \| grep -F -f tests/fixture_secrets.txt` | **PASS** — 0 matches |
| Python dependency vulnerabilities | `trivy fs --scanners vuln requirements.txt` | **PASS** — 0 |
| Coverage | coverage.py, branch mode, unit suite | **93 %** (1373 statements, 79 missed; 332 branches, 34 partial) |
| Windows, commit `92a0c8e` | GitHub Actions `windows-latest` | **PASS** — 160 unit + 2 real-scanner tests |
| Windows, the commit containing this file | GitHub Actions `windows-latest` | see the Actions run for that commit; not known at the time of writing |
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

## Changes made in this phase

- `tests/test_browser_cdp.py` — `test_browser_no_horizontal_overflow_on_narrow_screens` (375 px, 320 px).
- `devguard/static/css/app.css` — grid columns, grid cells and form fields may shrink to the viewport (fixes overflow at 320 px).
- `tests/test_audit_regressions.py` — triage re-scoring when the newer scan is queued, running, completed, partial or failed.
- `README.md` — purpose, architecture, scan workflow, risk levels, security design, testing method, tested platforms.
- `docs/audit/` — `remediation_report.md`, `regression_test_report.md`, `production_readiness_report.md`, this file.

No application logic changed in this phase apart from the stylesheet.

## Outstanding limitations

- No authentication; localhost only.
- Trivy's stderr tail (2000 characters) is stored, as specified.
- Older scans show the score they finished with next to current triage state.
- Project-level Gitleaks allowlists are ignored by design.
- Dependencies: Node.js `package-lock.json` only. No live Kubernetes cluster is inspected.
- Scans run one at a time.
- Vendored Swagger UI 5.34.1 is not updated automatically.

## Still open after this commit

1. Confirm that the GitHub Actions run for this commit passes on both `macos-latest` and `windows-latest`.
2. Optional: open the UI once in a browser on Windows.
