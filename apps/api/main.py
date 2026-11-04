"""Sentinel X versioned FastAPI backend.

Creates the FastAPI app with:
  * /api/v1 versioned routes
  * Local demo auth (Bearer token)
  * CORS restricted to localhost
  * Request-size caps
  * Rate limiting (token bucket per client IP)
  * Idempotency keys
  * Redacted error responses
  * Server-Sent Events event stream with sequence + reconnect
  * OpenAPI (auto-generated, served at /api/v1/openapi.json)

Local-only default: binds to 127.0.0.1. No arbitrary target URLs.
"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.utils import get_openapi
from fastapi.responses import JSONResponse

from .schemas import ErrorResponse, HealthResponse, LabelMode

# ------------------------------------------------------------------ constants

APP_VERSION = "0.1.0"
API_V1_PREFIX = "/api/v1"

MAX_REQUEST_BODY = 1024 * 1024  # 1 MB
RATE_LIMIT_RPS = 60.0
RATE_LIMIT_BURST = 200

_rate_tokens: dict[str, deque[float]] = defaultdict(deque)


def _client_key(request: Request) -> str:
    host = request.client.host if request.client else "unknown"
    return host


def _rate_limited(key: str) -> bool:
    now = time.monotonic()
    dq = _rate_tokens[key]
    while dq and dq[0] <= now - 1.0:
        dq.popleft()
    if len(dq) >= RATE_LIMIT_BURST:
        return True
    dq.append(now)
    return False


# ------------------------------------------------------------------ middleware

async def _size_and_rate_middleware(request: Request, call_next):
    key = _client_key(request)
    if _rate_limited(key):
        return JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            content=ErrorResponse(
                error="rate limited",
                code="RATE_LIMITED",
                detail="too many requests; slow down",
            ).model_dump(mode="json"),
        )
    body = await request.body()
    if len(body) > MAX_REQUEST_BODY:
        return JSONResponse(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            content=ErrorResponse(
                error="request body too large",
                code="PAYLOAD_TOO_LARGE",
                detail=f"max {MAX_REQUEST_BODY} bytes",
            ).model_dump(mode="json"),
        )

    # Starlette caches body() and replays it to the downstream app. Replacing
    # receive with an endless http.request breaks disconnect handling for SSE.
    return await call_next(request)


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield


# ------------------------------------------------------------------ app factory

def create_app() -> FastAPI:
    app = FastAPI(
        title="Sentinel X API",
        version=APP_VERSION,
        description=(
            "Local demo backend for the Sentinel X Agent Security Digital Twin.\n"
            "Local-only: binds 127.0.0.1. No public targets. No arbitrary target URLs."
        ),
        docs_url="/api/v1/docs",
        redoc_url="/api/v1/redoc",
        openapi_url="/api/v1/openapi.json",
        lifespan=lifespan,
    )

    # CORS: localhost only
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://127.0.0.1", "http://localhost"],
        allow_origin_regex=r"^http://(127\.0\.0\.1|localhost)(:\d+)?$",
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "Idempotency-Key", "Last-Event-ID"],
        max_age=600,
    )

    # Size + rate limiting
    app.middleware("http")(_size_and_rate_middleware)

    # Routers under /api/v1
    from .routes import router as api_router
    app.include_router(api_router, prefix="/api/v1")

    # Root health (no auth)
    @app.get("/health", response_model=HealthResponse, tags=["health"])
    async def root_health():
        return HealthResponse(
            status="ok",
            version=APP_VERSION,
            mode=LabelMode.SIMULATED,
            model_available=False,
            features=[
                "sessions", "runs", "events", "policy", "evidence",
                "findings", "containment", "metrics", "targets",
                "scans", "patches", "approvals", "shield", "escalations",
                "reports", "guard", "event-stream",
            ],
        )

    # Custom OpenAPI: bearer security + local-only note
    def _openapi() -> dict[str, Any]:
        if app.openapi_schema:
            return app.openapi_schema
        schema = get_openapi(
            title=app.title,
            version=app.version,
            description=app.description,
            routes=app.routes,
        )
        schema["components"]["securitySchemes"] = {
            "BearerAuth": {
                "type": "http",
                "scheme": "bearer",
                "bearerFormat": "Opaque demo token",
            },
        }
        for path_item in schema.get("paths", {}).values():
            for method, op in path_item.items():
                if method.lower() in {"post", "put", "patch", "delete"}:
                    op.setdefault("security", [{"BearerAuth": []}])
        app.openapi_schema = schema
        return schema

    app.openapi = _openapi

    # Global error handler: redacted, never leak internals
    @app.exception_handler(HTTPException)
    async def _http_error_handler(request: Request, exc: HTTPException):
        return JSONResponse(
            status_code=exc.status_code,
            content=ErrorResponse(
                error=str(exc.detail) if isinstance(exc.detail, str) else "error",
                code="HTTP_ERROR",
                detail=None,
            ).model_dump(mode="json"),
        )

    @app.exception_handler(Exception)
    async def _unexpected_error_handler(request: Request, exc: Exception):
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=ErrorResponse(
                error="internal server error",
                code="INTERNAL_ERROR",
                detail=None,
            ).model_dump(mode="json"),
        )

    return app


# module-level app instance (for uvicorn / tests)
app = create_app()
