"""Pydantic models and shared enumerations."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

Category = Literal["dependency", "secret", "config"]
Severity = Literal["critical", "high", "medium", "low", "informational"]
ScannerName = Literal["trivy-dependency", "gitleaks", "trivy-config"]
ScanStatus = Literal["queued", "running", "completed", "partial", "failed"]
RunStatus = Literal["pending", "running", "success", "failed", "timeout", "not_installed", "skipped"]
TriageStatus = Literal["open", "acknowledged", "false_positive"]

SEVERITY_ORDER: tuple[str, ...] = ("critical", "high", "medium", "low", "informational")
CATEGORIES: tuple[str, ...] = ("dependency", "secret", "config")
SCANNER_CATEGORY: dict[str, str] = {
    "trivy-dependency": "dependency",
    "gitleaks": "secret",
    "trivy-config": "config",
}
INCOMPLETE_RUN_STATUSES = {"failed", "timeout", "not_installed"}


class ApiError(Exception):
    """Standard API error rendered as {"error": code, "message": text}."""

    def __init__(self, status: int, error: str, message: str):
        super().__init__(message)
        self.status, self.error, self.message = status, error, message


class RawFinding(BaseModel):
    """Adapter output before fingerprinting and storage. Never carries secret values."""

    model_config = ConfigDict(extra="forbid")

    rule_or_vulnerability_id: str = Field(min_length=1)
    title: str = Field(min_length=1)
    original_severity: str | None = None
    affected_target: str = Field(min_length=1)
    file_path: str | None = None
    package_name: str | None = None
    installed_version: str | None = None
    fixed_version: str | None = None
    line_start: int | None = None
    line_end: int | None = None
    resource: str | None = None
    description: str = ""
    remediation: str = Field(min_length=1)
    reference_url: str | None = None


class Finding(RawFinding):
    id: int | None = None
    scan_id: int
    scanner: ScannerName
    category: Category
    severity: Severity
    fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    first_seen: str
    occurrences: int = Field(default=1, ge=1)


class ScanCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_path: str = Field(min_length=1, max_length=4096)
    label: str | None = Field(default=None, max_length=200)


class TriageUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: TriageStatus
    note: str | None = Field(default=None, max_length=1000)


class ScannerRun(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: int | None = None
    scan_id: int
    scanner: ScannerName
    category: Category
    status: RunStatus
    tool_version: str | None = None
    exit_code: int | None = None
    error_message: str | None = None
    skip_reason: str | None = None
    started_at: str | None = None
    finished_at: str | None = None
    elapsed_ms: int | None = None
    findings_count: int | None = None


class Scan(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: int | None = None
    target_path: str
    label: str | None = None
    status: ScanStatus
    created_at: str
    started_at: str | None = None
    finished_at: str | None = None
    elapsed_ms: int | None = None
    risk_score: int | None = None

