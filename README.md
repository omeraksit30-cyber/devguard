# DevGuard

DevGuard is a local, modular DevSecOps prototype. It scans a project directory from three angles, merges the results into one dashboard, and shows what changed between scans. It does not implement its own vulnerability engine: it runs existing open-source scanners and normalises their output.

| Category | Scanner | What it checks |
|----------|---------|----------------|
| Dependencies | Trivy (`fs`, vulnerabilities only) | Known vulnerabilities in Node.js `package-lock.json` |
| Secrets | Gitleaks (`dir`) | Credential-like patterns in files |
| Configurations | Trivy (`config`) | Static misconfigurations in Dockerfiles and Kubernetes YAML |

> DevGuard reports scanner observations, not proof that an application is secure.

Course project for SEN4931 — Special Topics in Software Engineering I, Bahçeşehir University.

## Requirements

- macOS (Apple Silicon or Intel)
- Python 3.11 or newer (macOS ships 3.9; install a newer one with `brew install python@3.12`)
- Trivy 0.60+ and Gitleaks 8.19+

## Setup

```bash
brew install trivy gitleaks
python3 -m venv .venv && source .venv/bin/activate   # use python3.12 if python3 is older than 3.11
pip install -r requirements.txt
python -m devguard        # http://127.0.0.1:8000
```

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
- **The risk score is a heuristic**, not a CVSS score: critical 10, high 5, medium 2, low 1, excluding false positives.

## Tests

```bash
pytest                    # unit, API, safe-failure and leak tests; no scanners needed
pytest -m integration     # end-to-end evaluation with real Trivy and Gitleaks
```

## Project layout

```
devguard/            application package
  adapters/          one file per scanner, all behind adapters/base.py
  engine/            normalisation, fingerprints, risk score, comparison
  routes/            HTTP API
  static/            UI (plain HTML/CSS/ES modules, no build step, no CDN)
fixtures/            vulnerable-app and fixed-app test projects (all credentials are fake)
tests/               pytest suite and recorded scanner output
docs/                API.md, DATA_MODEL.md, DECISIONS.md
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
