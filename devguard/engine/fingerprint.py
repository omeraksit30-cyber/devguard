"""Stable finding fingerprints. Never derived from a secret value or its hash."""

from __future__ import annotations

import hashlib

from ..models import RawFinding


def fingerprint(category: str, f: RawFinding) -> str:
    if category == "dependency":
        parts = [f.rule_or_vulnerability_id, f.package_name or "", f.installed_version or "", f.file_path or ""]
    elif category == "secret":
        parts = [f.rule_or_vulnerability_id, f.file_path or "", str(f.line_start or "")]
    elif category == "config":
        parts = [f.rule_or_vulnerability_id, f.file_path or "", f.resource or ""]
    else:
        raise ValueError(f"unknown category: {category}")
    return hashlib.sha256("|".join([category, *parts]).encode("utf-8")).hexdigest()
