"""Severity/category normalisation, ordering and de-duplication."""

from __future__ import annotations

from typing import Any, Iterable

from ..models import CATEGORIES, SEVERITY_ORDER, RawFinding
from .fingerprint import fingerprint

_SEVERITY_MAP = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
_SEV_RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}
_CAT_RANK = {c: i for i, c in enumerate(CATEGORIES)}


def normalize_severity(original: str | None, category: str) -> str:
    if category == "secret":
        return "high"  # DevGuard policy: Gitleaks does not assign severity
    if not isinstance(original, str):
        return "informational"
    return _SEVERITY_MAP.get(original.strip().upper(), "informational")


def sort_key(f: dict[str, Any]) -> tuple:
    """Critical -> Informational, then category, then affected target."""
    return (_SEV_RANK.get(f["severity"], 99), _CAT_RANK.get(f["category"], 99),
            f["affected_target"].lower(), f["rule_or_vulnerability_id"])


def sort_findings(findings: Iterable[dict[str, Any]], sort: str = "severity") -> list[dict[str, Any]]:
    if sort == "category":
        key = lambda f: (_CAT_RANK.get(f["category"], 99),) + sort_key(f)
    elif sort == "target":
        key = lambda f: (f["affected_target"].lower(),) + sort_key(f)
    else:
        key = sort_key
    return sorted(findings, key=key)


def to_findings(raws: Iterable[RawFinding], scanner: str, category: str) -> list[dict[str, Any]]:
    """Normalise, fingerprint and de-duplicate adapter output (first record wins)."""
    by_fp: dict[str, dict[str, Any]] = {}
    for raw in raws:
        fp = fingerprint(category, raw)
        if fp in by_fp:
            by_fp[fp]["occurrences"] += 1
            continue
        row = raw.model_dump()
        row.update(scanner=scanner, category=category, fingerprint=fp, occurrences=1,
                   severity=normalize_severity(raw.original_severity, category))
        by_fp[fp] = row
    return list(by_fp.values())
