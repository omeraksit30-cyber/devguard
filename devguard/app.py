"""FastAPI application: router registration, security middleware, static files."""

from __future__ import annotations

import logging
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

from contextlib import asynccontextmanager

from . import __version__, db
from .config import Settings, get_settings
from .models import ApiError
from .orchestrator import Orchestrator
from .routes import compare, evaluation, export, findings, scans, system, triage

log = logging.getLogger("devguard")

STATIC_DIR = Path(__file__).parent / "static"
STATE_CHANGING = {"POST", "PUT", "PATCH", "DELETE"}
SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; "
        "object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    ),
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "camera=(), geolocation=(), microphone=()",
}
DOCS_CSP = (
    "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "img-src 'self' data: https://fastapi.tiangolo.com; "
    "object-src 'none'; frame-ancestors 'none'; base-uri 'none'"
)


def error_response(status: int, error: str, message: str) -> JSONResponse:
    return JSONResponse({"error": error, "message": message}, status_code=status)


def create_app(settings: Settings | None = None, orchestrator: Orchestrator | None = None) -> FastAPI:
    settings = settings or get_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        db.init_db(settings.database)
        yield
        app.state.orchestrator.shutdown()

    app = FastAPI(title="DevGuard", version=__version__, lifespan=lifespan)
    app.state.settings = settings
    app.state.orchestrator = orchestrator or Orchestrator(settings)
    allowed_origins = {f"http://127.0.0.1:{settings.port}", f"http://localhost:{settings.port}"}
    allowed_hosts = {"127.0.0.1", "localhost", f"127.0.0.1:{settings.port}", f"localhost:{settings.port}", "testserver"}

    @app.middleware("http")
    async def security_middleware(request: Request, call_next):
        host = request.headers.get("host", "").strip().lower()
        if host and host not in allowed_hosts:
            response = error_response(403, "host_not_allowed", "Requests must target the local loopback host.")
        elif request.url.path.startswith("/api/") and request.headers.get("sec-fetch-site", "").lower() == "cross-site":
            response = error_response(403, "origin_not_allowed", "Cross-site API requests are not allowed.")
        elif request.method in STATE_CHANGING and request.url.path.startswith("/api/"):
            origin = request.headers.get("origin")
            if origin is not None and origin not in allowed_origins:
                response = error_response(403, "origin_not_allowed", "Cross-origin requests are not allowed.")
            elif request.headers.get("content-type", "").split(";")[0].strip().lower() != "application/json":
                response = error_response(403, "json_required", "Content-Type must be application/json.")
            else:
                response = await call_next(request)
        else:
            response = await call_next(request)
        if request.url.path in ("/docs", "/redoc"):
            response.headers.setdefault("Content-Security-Policy", DOCS_CSP)
        for k, v in SECURITY_HEADERS.items():
            response.headers.setdefault(k, v)
        if request.url.path.startswith("/api/"):
            response.headers.setdefault("Cache-Control", "no-store")
            response.headers.setdefault("Vary", "Origin, Sec-Fetch-Site")
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

    for module in (system, scans, findings, compare, triage, export, evaluation):
        app.include_router(module.router)

    @app.api_route("/api/{rest:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
                   include_in_schema=False)
    def api_not_found(rest: str):
        raise ApiError(404, "not_found", "Unknown API endpoint.")

    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(STATIC_DIR / "index.html")

    return app
