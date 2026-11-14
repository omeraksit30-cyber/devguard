# Implementation decisions

Decisions taken where the specification was silent or ambiguous. The simplest, safest interpretation was chosen.

| # | Topic | Decision |
|---|-------|----------|
| D1 | Python version | Developed and tested on Python 3.12 (Homebrew `python@3.12`); macOS system Python 3.9 is too old for `tomllib`. |
| D2 | Extra security headers | In addition to the required headers, responses carry `X-Frame-Options: DENY`, `frame-ancestors 'none'`, COOP/CORP `same-origin`, and `Cache-Control: no-store` on `/api/*`. |
| D3 | JSON content type on state-changing requests | Requests to `/api/*` using POST/PUT/PATCH/DELETE without `Content-Type: application/json` get `403 json_required`, including bodiless ones such as DELETE. The UI always sends the header. |
| D4 | Validation errors | `422 validation_error` lists only the offending field locations; submitted values are never echoed back (a body could contain a secret). |
| D5 | Fingerprint stability | A secret's fingerprint includes its start line, and a dependency's includes its installed version. If a secret moves to another line or a package version changes, the finding shows up as "resolved + new". |
