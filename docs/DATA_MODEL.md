# DevGuard data model

## Finding contract

Every adapter converts scanner output to this shape. Storage and UI never see a tool-specific format.

| Field | Type | Description |
|-------|------|-------------|
| `id` | int | Primary key |
| `scan_id` | int | Owning scan |
| `scanner` | str | `trivy-dependency` \| `gitleaks` \| `trivy-config` |
| `category` | str | `dependency` \| `secret` \| `config` |
| `rule_or_vulnerability_id` | str | e.g. `CVE-2021-23337`, `generic-api-key`, `DS-0002` |
| `title` | str | Short title |
| `severity` | str | Normalised: `critical` \| `high` \| `medium` \| `low` \| `informational` |
| `original_severity` | str \| null | Raw scanner value; `null` for Gitleaks |
| `affected_target` | str | Display value: `lodash@4.17.15`, `Dockerfile`, `src/config.js:5` |
| `file_path` | str \| null | Path **relative to the scan root** |
| `package_name`, `installed_version`, `fixed_version` | str \| null | `dependency` only |
| `line_start`, `line_end` | int \| null | `secret`, and `config` when available |
| `resource` | str \| null | `config`: Kubernetes resource name when the scanner reports one |
| `description` | str | Explanation (rule description for secrets, never matched text) |
| `remediation` | str | Suggested fix |
| `reference_url` | str \| null | Primary link from the scanner |
| `fingerprint` | str | Stable SHA-256 hex |
| `first_seen` | str | ISO 8601 UTC start time of the first scan of the same target that contained this fingerprint |
| `occurrences` | int | Raw records merged into this finding within one scan |

There is no field for a secret value, and adapters cannot add one: the model rejects unknown fields.

## Severity

| Raw value | Normalised |
|-----------|------------|
| `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` | `critical` / `high` / `medium` / `low` |
| `UNKNOWN`, empty, unrecognised | `informational` |
| Any Gitleaks finding | `high` (DevGuard policy; Gitleaks assigns no severity) |

Sort order: severity, then category (`dependency`, `secret`, `config`), then `affected_target`.

## Fingerprint

`sha256("|".join(parts))`:

| Category | Parts |
|----------|-------|
| `dependency` | `dependency`, vulnerability ID, package name, installed version, lockfile relative path |
| `secret` | `secret`, rule ID, file relative path, start line |
| `config` | `config`, rule ID, file relative path, resource name (empty string if none) |

Fingerprints are never derived from a secret value or a hash of one. Because paths are relative, two directories holding versions of the same project produce comparable fingerprints.

## Risk score

`score = Σ weight(severity)` over findings not triaged as `false_positive`, with weights critical 10, high 5, medium 2, low 1, informational 0.

| Score | Level |
|-------|-------|
| 0 | `none` (`unknown` if the scan is incomplete) |
| 1–9 | `low` |
| 10–29 | `moderate` |
| 30–59 | `high` |
| 60+ | `severe` |

## Status semantics

| Scanner run status | Meaning | Category result |
|--------------------|---------|-----------------|
| `success` | Tool ran and its report was parsed | Findings (including 0) are reliable |
| `failed` | Non-zero exit, invalid JSON, oversized report or processing error | Unknown |
| `timeout` | Time limit exceeded; process killed | Unknown |
| `not_installed` | Binary not found | Unknown |
| `skipped` | Nothing to scan (e.g. no `package-lock.json`) | Not applicable — not "clean" |

Scan status is derived from its three scanner runs:

- `completed` — all are `success` or `skipped`, and at least one is `success`
- `partial` — at least one `success` and at least one `failed` / `timeout` / `not_installed`
- `failed` — none is `success`

On startup, scans left `queued` or `running` become `failed` and their unfinished scanner runs get `error_message = "Interrupted by server restart"`.

## SQLite schema

Created at startup with `CREATE TABLE IF NOT EXISTS` (see `devguard/db.py`). `foreign_keys = ON`, `journal_mode = WAL`, `secure_delete = ON`. All timestamps are ISO 8601 UTC.

| Table | Purpose | Key columns |
|-------|---------|-------------|
| `scans` | One row per scan | `target_path` (absolute, resolved), `label`, `status`, `created_at`, `started_at`, `finished_at`, `elapsed_ms`, `risk_score` |
| `scanner_runs` | One row per scanner per scan, `UNIQUE (scan_id, scanner)` | `status`, `tool_version`, `exit_code`, `error_message` (≤ 2000 chars), `skip_reason`, `elapsed_ms`, `findings_count` (set only when `status = success`) |
| `findings` | Finding contract above, `UNIQUE (scan_id, fingerprint)` | indexed on `(scan_id, category, severity)` and `fingerprint` |
| `triage` | Primary key `(target_path, fingerprint)` | `status` (`open` \| `acknowledged` \| `false_positive`), `note` (≤ 1000 chars), `updated_at` |
| `evaluation_runs` | Fixture evaluation history | `status` (`running` \| `passed` \| `failed` \| `error`), `vulnerable_scan_id`, `fixed_scan_id`, `results_json` |

`scanner_runs` and `findings` are deleted with their scan (`ON DELETE CASCADE`). Deleting a scan referenced by an evaluation run sets that reference to `NULL`.
