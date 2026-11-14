# DevGuard HTTP API

Base path `/api`. All responses are JSON unless stated. Interactive documentation is served at `/docs`.

**Errors** always have the shape `{"error": "<code>", "message": "<readable text>"}`.

**Security rules**

- The server binds to `127.0.0.1` only. CORS is disabled.
- `POST`, `PUT`, `PATCH` and `DELETE` require `Content-Type: application/json` (`403 json_required`). If an `Origin` header is present it must be `http://127.0.0.1:<port>` or `http://localhost:<port>` (`403 origin_not_allowed`).
- Every response carries `Content-Security-Policy`, `X-Content-Type-Options: nosniff` and `Referrer-Policy: no-referrer`.
- Validation failures return `422 validation_error` naming the fields only; submitted values are never echoed.

## System

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/health` | `{"status": "ok"}` |
| GET | `/api/system/tools` | List of `{name, installed, version, path, install_hint}` for Trivy and Gitleaks |
| GET | `/api/system/config` | `{allowed_roots: [{path, exists, directories[]}], timeout_seconds}` |

## Scans

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/scans` | Body `{"target_path": str, "label": str?}` → `202` with the scan object. `400 path_not_allowed` if the path is not a directory inside an allowed root. |
| GET | `/api/scans` | Newest first. Query: `target_path`, `status`, `limit` (default 50, max 200), `offset`. Returns `{"items": [...], "targets": [...]}`; each item adds `incomplete`, `scanners_not_run`, `findings_total`. |
| GET | `/api/scans/{id}` | Scan + `scanner_runs[]` + `summary`. `404 scan_not_found`. |
| DELETE | `/api/scans/{id}` | Deletes the scan and its findings. `409 scan_running` while running. |

Scan `status`: `queued`, `running`, `completed`, `partial`, `failed`.
Scanner run `status`: `pending`, `running`, `success`, `failed`, `timeout`, `not_installed`, `skipped`.

`summary`:

```json
{
  "total": 23,
  "false_positives": 0,
  "by_severity": {"critical": 2, "high": 9, "medium": 8, "low": 4, "informational": 0},
  "by_category": {
    "dependency": {"status": "success", "count": 14, "reason": null},
    "secret":     {"status": "timeout", "count": null, "reason": "Timed out after 300 seconds"},
    "config":     {"status": "success", "count": 9, "reason": null}
  },
  "risk": {"score": 85, "level": "severe", "incomplete": true, "scanners_not_run": 1}
}
```

`count` is `null`, never `0`, unless the scanner run status is `success`. `risk.level` is `none`, `low`, `moderate`, `high`, `severe`, or `unknown` (score 0 on an incomplete scan); it is `null` while the scan is running.

## Findings

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/scans/{id}/findings` | `{"total": n, "items": [...]}`, filtered and sorted |
| GET | `/api/findings/{id}` | One finding plus `target_path`, `scanner_version`, `triage {status, note, updated_at}` and `seen_in_scans[]`. `404 finding_not_found`. |

Query parameters for the list: `category` (`dependency`\|`secret`\|`config`), `severity` (repeatable), `scanner`, `triage` (`open`\|`acknowledged`\|`false_positive`\|`all`; omitted = everything except false positives), `q` (searches title, ID and affected target), `sort` (`severity`\|`category`\|`target`), `limit` (default 500, max 2000), `offset`. List items include `triage_status` and `triage_note`. Finding fields are described in [DATA_MODEL.md](DATA_MODEL.md).

## Compare

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/compare?base={id}&head={id}` | `409 scan_not_comparable` unless both scans are `completed` or `partial`; `400 same_scan` if the IDs are equal. |

Response: `base`, `head` (scan briefs), `targets_differ`, `fully_comparable`, `categories[]`, `totals {new, resolved, persistent}`, `risk {base, head, delta}`, and the three finding lists `new`, `resolved`, `persistent`.

A category is comparable only if its scanner run is `success` in both scans. Otherwise:

```json
{"category": "secret", "comparable": false, "reason": "gitleaks did not complete in scan #7 (timeout)",
 "new": null, "resolved": null, "persistent": null}
```

and none of its findings appear in any list.

## Triage

| Method | Path | Description |
|--------|------|-------------|
| PUT | `/api/findings/{id}/triage` | Body `{"status": "open"\|"acknowledged"\|"false_positive", "note": str?}` (note ≤ 1000 characters). Returns `{finding_id, triage, latest_scan_id, risk_score}`. |

Triage is keyed by `(target_path, fingerprint)`, so it applies to the same finding in every scan of that target. The risk score of the target's latest scan is recalculated.

## Export

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/scans/{id}/export?format=json\|md\|html` | File download (`Content-Disposition: attachment`). `409 scan_not_finished` while the scan is queued or running. |

## Evaluation

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/evaluation/run` | Starts the fixture evaluation → `202`. `409 evaluation_running` if one is in progress. |
| GET | `/api/evaluation/runs` | `{"items": [...]}`, newest first |
| GET | `/api/evaluation/runs/{id}` | One run. `status`: `running`, `passed`, `failed`, `error`. `results` holds `environment`, `scans`, `comparison` and `checks[] {id, name, passed, evidence}`. |
| GET | `/api/evaluation/runs/{id}/export` | Evidence as a Markdown file download |
