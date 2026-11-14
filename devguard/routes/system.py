from __future__ import annotations

from fastapi import APIRouter, Request

from .. import runner

router = APIRouter(prefix="/api")


@router.get("/health")
def health():
    return {"status": "ok"}


@router.get("/system/tools")
def tools(request: Request):
    s = request.app.state.settings
    out = []
    for name, configured, version_args in (("trivy", s.trivy, ["--version"]),
                                           ("gitleaks", s.gitleaks, ["version"])):
        path = runner.find_binary(configured)
        out.append({
            "name": name,
            "installed": path is not None,
            "version": runner.tool_version([path, *version_args]) if path else None,
            "path": path,
            "install_hint": f"brew install {name}",
        })
    return out


@router.get("/system/config")
def config(request: Request):
    s = request.app.state.settings
    roots = []
    for root in s.allowed_roots:
        children = []
        if root.is_dir():
            children = sorted(str(p) for p in root.iterdir()
                              if p.is_dir() and not p.is_symlink() and not p.name.startswith("."))
        roots.append({"path": str(root), "exists": root.is_dir(), "directories": children})
    return {"allowed_roots": roots, "timeout_seconds": s.timeout_seconds}
