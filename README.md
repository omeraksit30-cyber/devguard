# DevGuard

DevGuard is a local, modular DevSecOps prototype. It scans a project directory from three angles, merges the results into one dashboard, and shows what changed between scans. It does not implement its own vulnerability engine: it runs existing open-source scanners and normalises their output.

| Category | Scanner | What it checks |
|----------|---------|----------------|
| Dependencies | Trivy (`fs`, vulnerabilities only) | Known vulnerabilities in Node.js `package-lock.json` |
| Secrets | Gitleaks (`dir`) | Credential-like patterns in files |
| Configurations | Trivy (`config`) | Static misconfigurations in Dockerfiles and Kubernetes YAML |

> DevGuard reports scanner observations, not proof that an application is secure.

Course project for SEN4931 — Special Topics in Software Engineering I, Bahçeşehir University.

## Why

A developer who wants to check a repository usually runs several scanners and reads several reports, each with its own format and severity labels. DevGuard gives those reports one schema, one severity scale, one place to review and triage them, and a before/after comparison — while being strict about two things that are easy to get wrong: a scan that did not run must never look clean, and a detected secret must never be copied anywhere.

It is a local developer tool. It listens on `127.0.0.1` only, has no user accounts, and is not meant to be deployed on a network.

## Architecture

```
browser (127.0.0.1) ──► FastAPI routes ──► orchestrator ──► adapters ──► Trivy / Gitleaks (subprocess)
                              │                 │
                              ▼                 ▼
                        SQLite (WAL)  ◄──  finding engine (normalise · fingerprint · risk · compare)
```

| Component | Responsibility |
|-----------|----------------|
| `routes/`, `app.py` | HTTP API, request checks (Host, Origin, JSON-only writes), security headers, static UI |
| `paths.py` | Accepts only existing directories inside `allowed_roots` |
| `orchestrator.py` | One scan at a time; runs the three adapters in parallel; derives the scan status |
| `runner.py` | Starts a scanner without a shell, in a private temp directory, with a timeout and process-tree kill |
| `adapters/` | Build the command line and parse the JSON report of one scanner each |
| `engine/` | Severity mapping, stable fingerprints, de-duplication, risk score, scan comparison |
| `db.py` | SQLite schema and all queries (parameterised) |
| `export.py`, `evaluation.py` | JSON / Markdown / HTML reports; fixture-based acceptance run |
| `static/` | UI in plain HTML, CSS and ES modules; charts are inline SVG |

Stack: Python 3.12, FastAPI, Uvicorn, Pydantic 2, SQLite (standard library), pytest. Versions are pinned in `requirements.txt`. The UI has no framework, build step or CDN.

### What happens during a scan

1. `POST /api/scans` validates the target against `allowed_roots` and queues the scan.
2. Each adapter first checks whether it has anything to scan (no `package-lock.json` → `skipped`) and whether its tool is installed (`not_installed`).
3. The tool runs with a time limit; its report is written to a private temp directory and size-checked before parsing.
4. The adapter keeps only the fields DevGuard needs. For Gitleaks that is the rule ID, description, file and line numbers — never the match.
5. Findings are normalised, fingerprinted, de-duplicated and stored. The scan becomes `completed`, `partial` (some scanners did not run) or `failed`.
6. The risk score is computed and stored with the scan.

## Requirements

- macOS (Apple Silicon or Intel) or Windows 10/11. Linux is not a supported target; see [Tested platforms](#tested-platforms).
- Python 3.11 or newer; developed and tested with 3.12 (macOS ships 3.9; install a newer one with `brew install python@3.12`)
- Trivy 0.60+ and Gitleaks 8.19+

## Setup

```bash
brew install trivy gitleaks
python3 -m venv .venv && source .venv/bin/activate   # use python3.12 if python3 is older than 3.11
pip install -r requirements.txt
python -m devguard        # http://127.0.0.1:8000
```

On Windows (PowerShell):

```powershell
winget install AquaSecurity.Trivy Gitleaks.Gitleaks Python.Python.3.12
# open a new terminal so the tools are on PATH
py -3.12 -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m devguard        # http://127.0.0.1:8000
```

In `devguard.toml` on Windows, write paths with forward slashes (`C:/Users/me/projects`) or single-quoted (`'C:\Users\me\projects'`).

On its first run Trivy downloads its vulnerability database. This needs internet access and makes the first scan noticeably slower. After that, the DevGuard UI itself makes no request to anything other than `127.0.0.1`.

## Using it

1. Open <http://127.0.0.1:8000> and choose **New scan**.
2. Pick a directory under an allowed root (by default `./fixtures`), confirm you are authorised to scan it, and start.
3. Review findings on the scan page: filter by category, severity and triage state, open a finding for remediation advice, and mark false positives.
4. Use **Compare** to see new, resolved and persistent findings between two scans.
5. Export a scan as JSON, Markdown or a self-contained HTML file.
6. **Evaluation** scans the bundled fixtures and checks the four acceptance criteria; the evidence can be exported as Markdown.

To scan your own projects, add their parent directory to `allowed_roots` in `devguard.toml` and restart.

## Configuration — `devguard.toml`

| Key | Default | Meaning |
|-----|---------|---------|
| `server.host` / `server.port` | `127.0.0.1` / `8000` | DevGuard refuses to start on any host other than `127.0.0.1` or `localhost` |
| `storage.database` | `data/devguard.db` | SQLite file |
| `scan.allowed_roots` | `["./fixtures"]` | Only directories under these roots can be scanned |
| `scan.timeout_seconds` | `300` | Per-scanner time limit |
| `scan.max_report_bytes` | `52428800` | Larger scanner reports mark the run as failed |
| `tools.trivy` / `tools.gitleaks` | `trivy` / `gitleaks` | Binary name on `PATH` or an absolute path |

Set `DEVGUARD_CONFIG=/path/to/file.toml` to use a different configuration file.

## How results should be read

- **A missing or failed scan is never shown as clean.** If a scanner did not run, its category shows a status (`Not installed`, `Timed out`, `Failed`, `Skipped`) instead of a number, and the API returns `count: null`.
- **Missing data is never counted as resolved.** A category is compared only when its scanner succeeded in both scans.
- **Secret values are never stored or shown.** Gitleaks runs with `--redact`, and the parser reads only the rule ID, rule description, file path and line numbers.
- **The risk score is a heuristic**, not a CVSS score: critical 10, high 5, medium 2, low 1, informational 0, summed over all findings except those triaged as false positive. Levels: 0 none, 1–9 low, 10–29 moderate, 30–59 high, 60+ severe. An incomplete scan is never labelled "none".
- **A triage change re-scores the latest finished scan of that target.** Older scans keep the score they finished with, so the trend chart is a record of what was known at the time.

## Security design

| Concern | Measure |
|---------|---------|
| Reaching the tool from outside | Binds to loopback only; any other `server.host` is refused at start-up |
| Hostile web pages (CSRF, DNS rebinding) | `Host` allowlist, `Origin` check and JSON-only bodies on writes, cross-site fetch metadata refused, CORS disabled |
| Script injection through scanner output | No `innerHTML`; strict Content-Security-Policy (`script-src 'self'`); exports are HTML-escaped and carry their own CSP |
| Command injection | Scanners are started from an argument list, never through a shell |
| Scanning arbitrary directories | Target must resolve (symlinks followed) to a directory inside `allowed_roots` |
| Secret leakage | `--redact`, an allowlist of parsed keys, Gitleaks stderr discarded; a test greps the database, API payloads, exports and logs for the fixture secrets |
| A scanned project weakening the scan | Scanners run from a private directory; Gitleaks is forced onto its built-in rules and ignores the project's `.gitleaks.toml`, `.gitleaksignore` and `gitleaks:allow` comments |
| Third-party front-end code | None loaded from the network; Swagger UI for `/docs` is vendored |

The reasoning behind each choice is recorded in [docs/DECISIONS.md](docs/DECISIONS.md).

## Tests

```bash
pytest                    # unit, API, safe-failure and leak tests; no scanners needed
pytest -m integration     # real Trivy and Gitleaks, plus headless-Chrome tests (skipped if Chrome is missing)
```

How the project is tested:

- **Unit and API tests** use fake scanners that replay recorded Trivy and Gitleaks output, so they run anywhere. They cover parsing, fingerprints, risk and comparison rules, every failure mode (tool missing, timeout, bad report) and the "never clean, never leaked" rules.
- **Integration tests** run the real scanners against `fixtures/` and check the four acceptance criteria: coverage of all three categories, data integrity across scans, safe failure, and reproducibility.
- **Browser tests** drive headless Chrome through the DevTools protocol: real mouse events, file downloads, `/docs`, and layout at 375 px and 320 px.
- **Regression tests** for the nine findings of the November 2026 audit are in `tests/test_audit_regressions.py`.
- **CI** (`.github/workflows/tests.yml`) runs the unit suite and the real-scanner tests on macOS and Windows for every push.

Results, coverage and reproduction commands are in [docs/audit/](docs/audit/); start with `final_readiness_summary.md`.

### Tested platforms

| Platform | Unit tests | Real scanners | UI in a browser |
|----------|-----------|---------------|-----------------|
| macOS | yes | yes | yes (Chrome) |
| Windows | yes (CI) | yes (CI) | not tested |
| Linux | yes (container smoke test) | not tested | not tested |

## Project layout

```
devguard/            application package
  adapters/          one file per scanner, all behind adapters/base.py
  engine/            normalisation, fingerprints, risk score, comparison
  routes/            HTTP API
  static/            UI (plain HTML/CSS/ES modules, no build step, no CDN)
fixtures/            vulnerable-app and fixed-app test projects (all credentials are fake)
tests/               pytest suite and recorded scanner output
docs/                API.md, DATA_MODEL.md, DECISIONS.md, audit/ (audit and test reports)
```

Adding a scanner means writing one adapter that implements `ScannerAdapter` and adding one line to `default_adapters()` in `devguard/orchestrator.py`.

## Notes

- **Fake credentials and GitHub push protection.** `fixtures/vulnerable-app` contains randomly generated fake tokens so that Gitleaks has something to find. GitHub push protection may block a push that contains them. If that happens, change the format of the fake value (and update `tests/fixture_secrets.txt`); do not disable push protection.
- **Known limitations** are listed in [docs/DECISIONS.md](docs/DECISIONS.md), for example: a secret that moves to another line appears as "resolved + new".

## Team

| Member | Workstream | Modules |
|--------|-----------|---------|
| Ömer Akşit | Dependency scanning | `adapters/trivy_dependency.py`, its tests, fixture dependencies |
| Muhammed Ali Zorluer | Secret detection | `adapters/gitleaks_secret.py`, redaction and leak tests, fake-token fixtures |
| Emre Can Sevinç | Docker & Kubernetes | `adapters/trivy_config.py`, Dockerfile / Kubernetes fixtures |
| Kağan Serbest | Platform | API, orchestrator, database, finding engine, UI, comparison |
