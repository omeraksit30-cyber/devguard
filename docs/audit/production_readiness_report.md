# DevGuard — Production Readiness Report

Date: 2026-11-17.

## Verdict

**Ready for its intended use: a single-user tool that runs on the developer's own machine, bound to `127.0.0.1`.** All nine audit findings are fixed, 170 tests pass on macOS, and the last pushed commit passes on Windows and macOS in CI.

**Not ready, and not designed, to be exposed on a network or shared by several users.** It has no authentication, no per-user data separation, and it scans directories on the host it runs on. The configuration loader refuses any host other than `127.0.0.1` / `localhost`.

## Evidence

| Area | State | Evidence |
|------|-------|----------|
| Unit and API tests | Pass | 165 passed (`pytest -q`) |
| Real scanners end to end | Pass | evaluation test with Trivy 0.76.2 and Gitleaks 8.30.1, four acceptance criteria |
| Browser behaviour | Pass | 65 journey checks plus the repository's CDP test (real mouse events, downloads, `/docs`) |
| Narrow screens | Pass | automated browser test at 375 px and 320 px |
| Incomplete scans are never shown as clean or improved | Pass | automated browser test: dashboard, trend chart, Compare (D32, D33) |
| Secret handling | Pass | no fixture secret in the database, API payloads, exports or logs |
| Request hardening | Pass | Host allowlist (DNS rebinding), Origin and fetch-metadata checks, JSON-only writes, strict CSP, no CDN |
| Scan policy integrity | Pass | scanned projects cannot suppress Gitleaks findings (F-01) |
| Timeout recovery | Pass | macOS and Windows, including a detached grandchild |
| Python dependencies | Pass | 0 known vulnerabilities in the pinned `requirements.txt` |
| Coverage | 93 % | line + branch, unit suite |
| Windows | Pass for `1f7e1b2` | GitHub Actions `windows-latest`: 165 unit + 2 real-scanner tests |

## Remaining risks and known limitations

- **Trivy stderr is stored** (last 2000 characters, per the specification). Trivy does not normally print file content there, but this is not guaranteed (DECISIONS D17).
- **No authentication.** Any local process or user on the same machine that can reach the port can read findings and start scans of allowed roots.
- **Older scans show a historical score** next to current triage state (F-02, by design).
- **Project-level Gitleaks allowlists are ignored** (F-01, by design).
- **A secret that moves to another line** appears as "resolved + new" (fingerprint includes the line).
- **Only Node.js `package-lock.json`** is supported for dependencies; no live Kubernetes cluster is inspected.
- **Vendored Swagger UI 5.34.1** (`/docs`) is not updated automatically.
- **Single queue worker:** scans run one at a time; a scan can take up to `timeout_seconds` per scanner.

## Unverified environments

- Windows: UI in a real browser; `winget` install steps from the README. For the changes after `92a0c8e`, see the GitHub Actions run of the commit that contains this report.
- Linux: unit suite and application start pass in a container; real scanners and the UI were not tested. The in-app install hint suggests Homebrew on Linux as well.
- Browsers other than Chrome.
- Behaviour under load or with very large repositories and reports near the 50 MB limit.

## Unresolved defects

None known.

## Git status at the time of writing

Baseline `92a0c8e` on `main`. Changed after it and committed together with this report:

- `devguard/static/css/app.css` — narrow-screen layout down to 320 px
- `tests/test_audit_regressions.py` — additional F-02 scenarios
- `tests/test_browser_cdp.py` — narrow-viewport regression test
- `README.md` — purpose, architecture, security design, testing and tested platforms
- `docs/audit/` — the audit reports
