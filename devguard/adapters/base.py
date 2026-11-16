"""ScannerAdapter interface and helpers shared by all adapters."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Iterator, Protocol

from ..models import RawFinding

PRUNED_DIRS = {"node_modules", ".git"}


class ScannerAdapter(Protocol):
    name: str            # e.g. "trivy-dependency"
    category: str        # e.g. "dependency"
    binary: str          # tool name or absolute path
    keep_stderr: bool    # False when stderr could carry sensitive content

    def version_argv(self) -> list[str]: ...
    def precheck(self, target: Path) -> str | None: ...            # skip reason or None
    def build_argv(self, target: Path, report_path: Path) -> list[str]: ...
    def parse(self, report: dict | list, target: Path) -> list[RawFinding]: ...


def walk_files(target: Path) -> Iterator[str]:
    """Yield regular file names under target, skipping node_modules/.git and symlinks."""
    for root, dirs, files in os.walk(target, followlinks=False):
        dirs[:] = [d for d in dirs if d not in PRUNED_DIRS and not Path(root, d).is_symlink()]
        for f in files:
            if not Path(root, f).is_symlink():
                yield f


def relative_path(raw: object, target: Path) -> str | None:
    """Express a scanner-reported path relative to the scan root (POSIX separators).

    Absolute paths outside the root are reduced to their file name so that no
    unrelated filesystem layout is stored.
    """
    if not isinstance(raw, str) or not raw:
        return None
    p = Path(raw)
    for base in (target, target.resolve()):
        try:
            return p.relative_to(base).as_posix()
        except ValueError:
            pass
    if p.is_absolute():
        try:
            return p.resolve().relative_to(target.resolve()).as_posix()
        except (ValueError, OSError):
            return p.name
    if ".." in p.parts:
        return p.name  # a relative path that climbs out of the scan root keeps only its file name
    return p.as_posix()  # on Windows this also turns backslashes into forward slashes


def text(value: object, limit: int) -> str | None:
    """Return a stripped, length-limited string, or None for missing/non-string values."""
    if not isinstance(value, str):
        return None
    value = value.strip()
    return value[:limit] if value else None


def integer(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else None


def items(value: object) -> list[dict]:
    """Tolerant list accessor: None / wrong type -> [], non-dict entries dropped."""
    return [v for v in value if isinstance(v, dict)] if isinstance(value, list) else []
