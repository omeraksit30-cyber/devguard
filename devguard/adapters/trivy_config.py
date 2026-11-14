"""Trivy static misconfiguration scan for Dockerfiles and Kubernetes manifests."""

from __future__ import annotations

import logging
from pathlib import Path

from ..models import RawFinding
from .base import integer, items, relative_path, text, walk_files

log = logging.getLogger("devguard.adapters.trivy_config")

DEFAULT_REMEDIATION = "Review the rule reference and adjust the configuration."


class TrivyConfigAdapter:
    name = "trivy-config"
    category = "config"
    keep_stderr = True

    def __init__(self, binary: str = "trivy"):
        self.binary = binary

    def version_argv(self) -> list[str]:
        return [self.binary, "--version"]

    def precheck(self, target: Path) -> str | None:
        for name in walk_files(target):
            if name.startswith("Dockerfile") or name.endswith((".yaml", ".yml")):
                return None
        return "No Dockerfile or YAML manifests found"

    def build_argv(self, target: Path, report_path: Path) -> list[str]:
        return [self.binary, "config", "--format", "json", "--quiet",
                "--output", str(report_path), str(target)]

    def parse(self, report: dict | list, target: Path) -> list[RawFinding]:
        if not isinstance(report, dict):
            raise ValueError("Unexpected Trivy report structure")
        findings: list[RawFinding] = []
        skipped = 0
        for result in items(report.get("Results")):
            file_path = relative_path(result.get("Target"), target)
            for m in items(result.get("Misconfigurations")):
                if m.get("Status") != "FAIL":
                    continue
                rule_id = text(m.get("ID"), 200) or text(m.get("AVDID"), 200)
                title = text(m.get("Title"), 500)
                if not (rule_id and title and file_path):
                    skipped += 1
                    continue
                # Only line numbers and the resource name are read from CauseMetadata.
                # CauseMetadata.Code (source lines) is never read: it may contain secrets.
                cause = m.get("CauseMetadata")
                cause = cause if isinstance(cause, dict) else {}
                resource = text(cause.get("Resource"), 300)
                description = "\n\n".join(
                    p for p in (text(m.get("Description"), 3000), text(m.get("Message"), 1000)) if p)
                findings.append(RawFinding(
                    rule_or_vulnerability_id=rule_id,
                    title=title,
                    original_severity=text(m.get("Severity"), 50),
                    affected_target=f"{file_path} ({resource})" if resource else file_path,
                    file_path=file_path,
                    line_start=integer(cause.get("StartLine")),
                    line_end=integer(cause.get("EndLine")),
                    resource=resource,
                    description=description,
                    remediation=text(m.get("Resolution"), 2000) or DEFAULT_REMEDIATION,
                    reference_url=text(m.get("PrimaryURL"), 2000),
                ))
        if skipped:
            log.warning("Skipped %d misconfiguration record(s) with missing required fields", skipped)
        return findings
