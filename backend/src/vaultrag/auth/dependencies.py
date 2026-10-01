from __future__ import annotations

import contextlib
import logging
import time
import uuid
from collections.abc import Callable
from typing import Any

from fastapi import Depends, Request

from vaultrag.auth.jwt_verifier import verify_id_token
from vaultrag.clients.dynamo import TenantRepo
from vaultrag.context import RequestContext, Role
from vaultrag.errors import Forbidden, NotFound, Unauthorized
from vaultrag.logging_utils import request_id_var, tenant_id_var, user_id_var

logger = logging.getLogger(__name__)

TENANT_CACHE_TTL_SECS = 60.0
_TENANT_CACHE: dict[str, tuple[dict[str, Any], float]] = {}


def clear_tenant_cache() -> None:
    """Clear in-memory tenant validation cache (used in tests)."""
    global _TENANT_CACHE
    _TENANT_CACHE.clear()


def get_ctx(request: Request) -> RequestContext:
    """FastAPI dependency: Authenticate request token and return tenant-scoped RequestContext.

    1. Reads and validates 'Authorization: Bearer <token>' header.
    2. Verifies ID token signature and claims.
    3. Loads tenant from DynamoDB (with 60s in-memory cache) and checks status == 'active'.
    4. Sets logging contextvars for request tracing.
    """
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        raise Unauthorized("Missing Authorization header")

    parts = auth_header.strip().split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise Unauthorized("Invalid Authorization header format. Expected 'Bearer <token>'")

    token = parts[1]
    claims = verify_id_token(token)

    # 3. Load tenant configuration and check status (with 60s cache)
    now = time.monotonic()
    tenant_data: dict[str, Any] | None = None

    if claims.tenant_id in _TENANT_CACHE:
        cached_item, expiry = _TENANT_CACHE[claims.tenant_id]
        if now < expiry:
            tenant_data = cached_item

    if tenant_data is None:
        repo = TenantRepo()
        try:
            tenant_data = repo.get(claims.tenant_id)
        except NotFound:
            raise Forbidden(f"Tenant '{claims.tenant_id}' not found") from None

        _TENANT_CACHE[claims.tenant_id] = (tenant_data, now + TENANT_CACHE_TTL_SECS)

    status = str(tenant_data.get("status", "")).lower()
    if status != "active":
        raise Forbidden(f"Tenant '{claims.tenant_id}' is inactive")

    # 4. Set request_id, tenant_id, user_id contextvars
    req_id = (
        getattr(request.state, "request_id", None)
        or request_id_var.get()
        or request.headers.get("x-request-id")
        or str(uuid.uuid4())
    )
    request_id_var.set(req_id)
    tenant_id_var.set(claims.tenant_id)
    user_id_var.set(claims.sub)

    return RequestContext(
        tenant_id=claims.tenant_id,
        user_id=claims.sub,
        roles=claims.roles,
        request_id=req_id,
    )


def require_role(*roles: Role | str) -> Callable[[RequestContext], RequestContext]:
    """FastAPI helper dependency to enforce required roles. Admins are ALWAYS allowed."""
    normalized_roles: set[Role] = set()
    for r in roles:
        if isinstance(r, Role):
            normalized_roles.add(r)
        elif isinstance(r, str):
            with contextlib.suppress(ValueError):
                normalized_roles.add(Role(r.lower()))

    def _role_checker(ctx: RequestContext = Depends(get_ctx)) -> RequestContext:  # noqa: B008
        # Admin is always permitted
        if ctx.is_admin:
            return ctx

        if any(ctx.has_role(r) for r in normalized_roles):
            return ctx

        raise Forbidden("Insufficient permissions for this resource")

    return _role_checker
