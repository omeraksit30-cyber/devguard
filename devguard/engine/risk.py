"""DevGuard risk score: a simple heuristic indicator, not a CVSS score."""

from __future__ import annotations

from typing import Any, Iterable, Mapping

WEIGHTS = {"critical": 10, "high": 5, "medium": 2, "low": 1, "informational": 0}


def risk_score(findings: Iterable[Mapping[str, Any]], triage: Mapping[str, Mapping[str, Any]]) -> int:
    """Sum of severity weights, excluding findings triaged as false positive."""
    return sum(
        WEIGHTS.get(f["severity"], 0) for f in findings
        if triage.get(f["fingerprint"], {}).get("status") != "false_positive")


def risk_level(score: int | None, incomplete: bool) -> str | None:
    if score is None:
        return None
    if score == 0:
        return "unknown" if incomplete else "none"  # an incomplete scan is never "none"
    if score <= 9:
        return "low"
    if score <= 29:
        return "moderate"
    if score <= 59:
        return "high"
    return "severe"
