# Implementation decisions

Decisions taken where the specification was silent or ambiguous. The simplest, safest interpretation was chosen.

| # | Topic | Decision |
|---|-------|----------|
| D1 | Python version | Developed and tested on Python 3.12 (Homebrew `python@3.12`); macOS system Python 3.9 is too old for `tomllib`. |
| D2 | Extra security headers | In addition to the required headers, responses carry `X-Frame-Options: DENY`, `frame-ancestors 'none'`, COOP/CORP `same-origin`, and `Cache-Control: no-store` on `/api/*`. |
| D3 | JSON content type on state-changing requests | Requests to `/api/*` using POST/PUT/PATCH/DELETE without `Content-Type: application/json` get `403 json_required`, including bodiless ones such as DELETE. The UI always sends the header. |
| D4 | Validation errors | `422 validation_error` lists only the offending field locations; submitted values are never echoed back (a body could contain a secret). |
| D5 | Fingerprint stability | A secret's fingerprint includes its start line, and a dependency's includes its installed version. If a secret moves to another line or a package version changes, the finding shows up as "resolved + new". |
| D6 | Non-npm results | `trivy fs` may report other ecosystems if their lockfiles exist. Results whose `Type` is present and not `npm` are ignored, since only Node.js is in scope. |
| D7 | Trivy 0.76 output | Recorded samples show rule IDs as `DS-0001` / `KSV-0001` (no `AVDID` key) and no `CauseMetadata.Resource`. The parser still reads `AVDID` and `Resource` when present, so older/newer versions work. Without a resource name, same-rule findings in one file collapse into one finding with `occurrences > 1`. |
| D8 | Gitleaks paths | Gitleaks reports paths as given on the command line. Paths are made relative to the scan root; an absolute path that is somehow outside the root is reduced to its file name. |
| D9 | Gitleaks stderr | `run_tool(..., keep_stderr=False)` sends Gitleaks stderr to `/dev/null`, so it is never held in memory at all. |
| D10 | Process isolation | Scanners run in their own session; on timeout the whole process group is killed (SIGKILL). |
| D11 | Unredacted test sample | The "unredacted Gitleaks report" used by leak tests is built in memory from `tests/fixture_secrets.txt` instead of being stored as another file, so fake secrets live in exactly one place outside the fixture. |
