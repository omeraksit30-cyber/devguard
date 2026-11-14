"""FastAPI application: router registration, security middleware, static files."""

from __future__ import annotations

import logging
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

from . import __version__
from .config import Settings, get_settings

log = logging.getLogger("devguard")

STATIC_DIR = Path(__file__).parent / "static"
STATE_CHANGING = {"POST", "PUT", "PATCH", "DELETE"}
SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; "
        "frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    ),
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
}


class ApiError(Exception):
    """Raised by routes to return the standard error shape."""

    def __init__(self, status: int, error: str, message: str):
        self.status, self.error, self.message = status, error, message


def error_response(status: int, error: str, message: str) -> JSONResponse:
    return JSONResponse({"error": error, "message": message}, status_code=status)


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    app = FastAPI(title="DevGuard", version=__version__)
    app.state.settings = settings
    allowed_origins = {f"http://127.0.0.1:{settings.port}", f"http://localhost:{settings.port}"}

    @app.middleware("http")
    async def security_middleware(request: Request, call_next):
        if request.method in STATE_CHANGING and request.url.path.startswith("/api/"):
            origin = request.headers.get("origin")
            if origin is not None and origin not in allowed_origins:
                response = error_response(403, "origin_not_allowed", "Cross-origin requests are not allowed.")
            elif request.headers.get("content-type", "").split(";")[0].strip().lower() != "application/json":
                response = error_response(403, "json_required", "Content-Type must be application/json.")
            else:
                response = await call_next(request)
        else:
            response = await call_next(request)
        for k, v in SECURITY_HEADERS.items():
            response.headers.setdefault(k, v)
        if request.url.path.startswith("/api/"):
            response.headers.setdefault("Cache-Control", "no-store")
        return response

    @app.exception_handler(ApiError)
    async def _api_error(_: Request, exc: ApiError):
        return error_response(exc.status, exc.error, exc.message)

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(_: Request, exc: StarletteHTTPException):
        code = {404: "not_found", 405: "method_not_allowed"}.get(exc.status_code, "http_error")
        return error_response(exc.status_code, code, str(exc.detail))

    @app.exception_handler(RequestValidationError)
    async def _validation_error(_: Request, exc: RequestValidationError):
        # Report field locations only; never echo submitted values back.
        fields = ", ".join(".".join(str(p) for p in e.get("loc", ())) for e in exc.errors())
        return error_response(422, "validation_error", f"Invalid request: {fields}")

    @app.get("/api/health")
    def health():
        return {"status": "ok"}

    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(STATIC_DIR / "index.html")

    return app
