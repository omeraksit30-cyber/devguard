"""Trivy filesystem scan restricted to known vulnerabilities in npm lockfiles."""

from __future__ import annotations

import logging
from pathlib import Path

from ..models import RawFinding
from .base import items, relative_path, text, walk_files

log = logging.getLogger("devguard.adapters.trivy_dependency")


class TrivyDependencyAdapter:
    name = "trivy-dependency"
    category = "dependency"
    keep_stderr = True

    def __init__(self, binary: str = "trivy"):
        self.binary = binary

    def version_argv(self) -> list[str]:
        return [self.binary, "--version"]

    def precheck(self, target: Path) -> str | None:
        if any(name == "package-lock.json" for name in walk_files(target)):
            return None
        return "No package-lock.json found"

    def build_argv(self, target: Path, report_path: Path) -> list[str]:
        # --scanners vuln keeps Trivy's own secret/misconfig scanners off.
        return [self.binary, "fs", "--scanners", "vuln", "--format", "json", "--quiet",
                "--output", str(report_path), str(target)]

    def parse(self, report: dict | list, target: Path) -> list[RawFinding]:
        if not isinstance(report, dict):
            raise ValueError("Unexpected Trivy report structure")
        findings: list[RawFinding] = []
        skipped = 0
        for result in items(report.get("Results")):
            if result.get("Type") not in (None, "npm"):  # Node.js only (see DECISIONS D6)
                continue
            file_path = relative_path(result.get("Target"), target)
            for v in items(result.get("Vulnerabilities")):
                vuln_id = text(v.get("VulnerabilityID"), 200)
                pkg = text(v.get("PkgName"), 300)
                installed = text(v.get("InstalledVersion"), 100)
                if not (vuln_id and pkg and installed):
                    skipped += 1
                    continue
                fixed = text(v.get("FixedVersion"), 300)
                if fixed:
                    remediation = (f"Upgrade {pkg} from {installed} to {fixed} or later, "
                                   "then regenerate package-lock.json.")
                else:
                    remediation = ("No fixed version is published yet. Consider replacing the package or "
                                   "applying a mitigation; re-check after scanner database updates.")
                findings.append(RawFinding(
                    rule_or_vulnerability_id=vuln_id,
                    title=text(v.get("Title"), 500) or f"{vuln_id} in {pkg}",
                    original_severity=text(v.get("Severity"), 50),
                    affected_target=f"{pkg}@{installed}",
                    file_path=file_path,
                    package_name=pkg,
                    installed_version=installed,
                    fixed_version=fixed,
                    description=text(v.get("Description"), 4000) or "",
                    remediation=remediation,
                    reference_url=text(v.get("PrimaryURL"), 2000),
                ))
        if skipped:
            log.warning("Skipped %d vulnerability record(s) with missing required fields", skipped)
        return findings
