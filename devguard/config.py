"""Loads and validates devguard.toml."""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
ALLOWED_HOSTS = {"127.0.0.1", "localhost"}


class ConfigError(RuntimeError):
    pass


@dataclass(frozen=True)
class Settings:
    host: str
    port: int
    database: Path
    allowed_roots: tuple[Path, ...]
    timeout_seconds: int
    max_report_bytes: int
    trivy: str
    gitleaks: str


def _resolve(raw: str) -> Path:
    p = Path(raw).expanduser()
    if not p.is_absolute():
        p = PROJECT_ROOT / p
    return p.resolve()


def load_settings(path: Path | None = None) -> Settings:
    path = path or Path(os.environ.get("DEVGUARD_CONFIG", PROJECT_ROOT / "devguard.toml"))
    try:
        with open(path, "rb") as fh:
            data = tomllib.load(fh)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"Cannot read configuration file {path}: {exc}") from exc

    server = data.get("server", {})
    storage = data.get("storage", {})
    scan = data.get("scan", {})
    tools = data.get("tools", {})

    host = str(server.get("host", "127.0.0.1"))
    if host not in ALLOWED_HOSTS:
        raise ConfigError(
            f"server.host must be one of {sorted(ALLOWED_HOSTS)}; got {host!r}. "
            "DevGuard only serves on the local loopback interface."
        )

    port = int(server.get("port", 8000))
    if not 1 <= port <= 65535:
        raise ConfigError(f"server.port out of range: {port}")

    roots = scan.get("allowed_roots", ["./fixtures"])
    if not isinstance(roots, list) or not roots:
        raise ConfigError("scan.allowed_roots must be a non-empty list")

    timeout = int(scan.get("timeout_seconds", 300))
    max_bytes = int(scan.get("max_report_bytes", 50 * 1024 * 1024))
    if timeout < 1 or max_bytes < 1:
        raise ConfigError("scan.timeout_seconds and scan.max_report_bytes must be positive")

    return Settings(
        host=host,
        port=port,
        database=_resolve(storage.get("database", "data/devguard.db")),
        allowed_roots=tuple(_resolve(str(r)) for r in roots),
        timeout_seconds=timeout,
        max_report_bytes=max_bytes,
        trivy=str(tools.get("trivy", "trivy")),
        gitleaks=str(tools.get("gitleaks", "gitleaks")),
    )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return load_settings()
