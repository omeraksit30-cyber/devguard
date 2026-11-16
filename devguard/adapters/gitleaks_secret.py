"""Gitleaks directory scan.

Two layers of defence keep secret values out of DevGuard:
  1. Gitleaks is always invoked with --redact.
  2. The parser reads ONLY the allowlisted keys below. `Secret`, `Match`, `Line`,
     `Message`, `Author`, `Email`, `Commit`, `Fingerprint` and every other key are
     never read, assigned or logged.
"""

from __future__ import annotations

import logging
from pathlib import Path

from ..models import RawFinding
from .base import integer, relative_path, text

log = logging.getLogger("devguard.adapters.gitleaks")

DEFAULT_CONFIG = Path(__file__).with_name("gitleaks.toml")
ALLOWED_KEYS = ("RuleID", "Description", "File", "StartLine", "EndLine")
REMEDIATION = (
    "Remove the value from the file, rotate the credential at its provider, and load it from an "
    "environment variable or secret manager. If this is a test value, mark the finding as false positive."
)


class GitleaksSecretAdapter:
    name = "gitleaks"
    category = "secret"
    keep_stderr = False  # stderr is never stored or logged for Gitleaks

    def __init__(self, binary: str = "gitleaks"):
        self.binary = binary

    def version_argv(self) -> list[str]:
        return [self.binary, "version"]

    def precheck(self, target: Path) -> str | None:
        return None

    def build_argv(self, target: Path, report_path: Path) -> list[str]:
        # The scanned project must not be able to switch detection off, so its own
        # .gitleaks.toml, .gitleaksignore and "gitleaks:allow" comments are all ignored.
        return [self.binary, "dir", str(target), "--report-format", "json",
                "--report-path", str(report_path), "--redact", "--no-banner", "--exit-code", "0",
                "--config", str(DEFAULT_CONFIG), "--gitleaks-ignore-path", str(report_path.parent),
                "--ignore-gitleaks-allow"]

    def parse(self, report: dict | list, target: Path) -> list[RawFinding]:
        if not isinstance(report, list):
            raise ValueError("Unexpected Gitleaks report structure")
        findings: list[RawFinding] = []
        skipped = 0
        for record in report:
            if not isinstance(record, dict):
                skipped += 1
                continue
            # Allowlist extraction: nothing outside ALLOWED_KEYS is ever touched.
            rule_id, description, file_raw, start, end = (record.get(k) for k in ALLOWED_KEYS)
            rule_id = text(rule_id, 200)
            file_path = relative_path(file_raw, target)
            line_start = integer(start)
            if not (rule_id and file_path and line_start):
                skipped += 1
                continue
            findings.append(RawFinding(
                rule_or_vulnerability_id=rule_id,
                title=f"Potential secret: {rule_id}",
                original_severity=None,
                affected_target=f"{file_path}:{line_start}",
                file_path=file_path,
                line_start=line_start,
                line_end=integer(end) or line_start,
                description=text(description, 1000) or "Pattern matched by a Gitleaks rule.",
                remediation=REMEDIATION,
            ))
        if skipped:
            log.warning("Skipped %d secret record(s) with missing required fields", skipped)
        return findings
