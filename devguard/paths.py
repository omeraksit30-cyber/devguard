"""Target path validation against the configured allowlist."""

from __future__ import annotations

from pathlib import Path
from typing import Sequence

from .config import get_settings


class PathNotAllowed(ValueError):
    """The requested target is not a directory inside an allowed root."""


def validate_target(raw: str, allowed_roots: Sequence[Path] | None = None) -> Path:
    roots = [Path(r).resolve() for r in (allowed_roots if allowed_roots is not None
                                         else get_settings().allowed_roots)]
    # One generic message for every failure: lists the allowed roots, reveals nothing else.
    error = PathNotAllowed(
        "Target must be an existing directory inside one of the allowed roots: "
        + ", ".join(str(r) for r in roots))

    if not isinstance(raw, str) or not raw.strip() or "\x00" in raw or raw.lstrip().startswith("-"):
        raise error
    try:
        resolved = Path(raw).expanduser().resolve(strict=True)  # follows symlinks
    except (OSError, RuntimeError, ValueError):
        raise error from None
    if not resolved.is_dir() or str(resolved).startswith("-"):
        raise error
    if not any(resolved.is_relative_to(root) for root in roots):
        raise error
    return resolved
