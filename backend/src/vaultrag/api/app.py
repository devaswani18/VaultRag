from __future__ import annotations

import logging
import re
import time
import uuid
from typing import Any

from fastapi import Depends, FastAPI, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from vaultrag.auth.dependencies import get_ctx
from vaultrag.config import get_settings
from vaultrag.context import RequestContext
from vaultrag.errors import AppError
from vaultrag.logging_utils import log_event, request_id_var

logger = logging.getLogger(__name__)

REQUEST_ID_REGEX = re.compile(r"^[A-Za-z0-9-]{8,64}$")
APP_VERSION = "0.1.0"


class VaultRAGMiddleware(BaseHTTPMiddleware):
    """Unified middleware handling request ID extraction, security headers, and access logging."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        # 1. Request ID validation and binding
        incoming_req_id = request.headers.get("X-Request-Id")
        if incoming_req_id and REQUEST_ID_REGEX.match(incoming_req_id):
            req_id = incoming_req_id
        else:
            req_id = str(uuid.uuid4())

        request.state.request_id = req_id
        token = request_id_var.set(req_id)

        # 2. Timing and downstream processing
        start_time = time.monotonic()
        try:
            response = await call_next(request)
        finally:
            request_id_var.reset(token)

        duration_ms = round((time.monotonic() - start_time) * 1000, 2)

        # 3. Security headers
        response.headers["X-Request-Id"] = req_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Referrer-Policy"] = "no-referrer"

        # 4. Access logging (NEVER log query strings or request bodies)
        log_event(
            "http_access",
            method=request.method,
            path=request.url.path,
            status=response.status_code,
            duration_ms=duration_ms,
        )

        return response


def create_app() -> FastAPI:
    """FastAPI application factory with security middleware and standard error handling."""
    settings = get_settings()

    # Docs and OpenAPI schema are disabled outside local development
    is_local = settings.env.lower() == "local" or settings.local_mode
    docs_url = "/docs" if is_local else None
    redoc_url = None
    openapi_url = "/openapi.json" if is_local else None

    app = FastAPI(
        title="VaultRAG API",
        version=APP_VERSION,
        docs_url=docs_url,
        redoc_url=redoc_url,
        openapi_url=openapi_url,
    )

    # Attach core middleware
    app.add_middleware(VaultRAGMiddleware)

    # --------------------------------------------------------------------------
    # Exception Handlers
    # --------------------------------------------------------------------------
    @app.exception_handler(AppError)
    async def app_error_handler(request: Request, exc: AppError) -> JSONResponse:
        req_id = getattr(request.state, "request_id", None) or request_id_var.get() or "unknown"
        error_payload: dict[str, Any] = {
            "code": exc.code,
            "message": exc.message,
            "request_id": req_id,
        }
        if exc.details:
            error_payload["details"] = exc.details

        response = JSONResponse(
            status_code=exc.status,
            content={"error": error_payload},
        )
        response.headers["X-Request-Id"] = req_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        req_id = getattr(request.state, "request_id", None) or request_id_var.get() or "unknown"
        safe_details = [
            {
                "loc": [str(loc) for loc in err.get("loc", [])],
                "msg": err.get("msg", "Invalid value"),
                "type": err.get("type", "validation_error"),
            }
            for err in exc.errors()
        ]
        response = JSONResponse(
            status_code=422,
            content={
                "error": {
                    "code": "validation_failed",
                    "message": "Validation failed",
                    "details": safe_details,
                    "request_id": req_id,
                }
            },
        )
        response.headers["X-Request-Id"] = req_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        req_id = getattr(request.state, "request_id", None) or request_id_var.get() or "unknown"
        logger.exception("Unhandled server exception: %s", type(exc).__name__)
        response = JSONResponse(
            status_code=500,
            content={
                "error": {
                    "code": "internal_error",
                    "message": "An unexpected error occurred",
                    "request_id": req_id,
                }
            },
        )
        response.headers["X-Request-Id"] = req_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    # --------------------------------------------------------------------------
    # Base Routes
    # --------------------------------------------------------------------------
    @app.get("/health")
    async def health() -> dict[str, str]:
        """Public health check endpoint (no authentication required)."""
        return {
            "status": "ok",
            "version": APP_VERSION,
        }

    @app.get("/me")
    async def get_me(ctx: RequestContext = Depends(get_ctx)) -> dict[str, Any]:  # noqa: B008
        """Return the authenticated caller's identity and tenant context."""
        return {
            "tenant_id": ctx.tenant_id,
            "user_id": ctx.user_id,
            "roles": sorted(r.value for r in ctx.roles),
            "request_id": ctx.request_id,
        }

    return app
