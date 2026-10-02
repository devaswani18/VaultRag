"""Admin usage statistics endpoint: GET /admin/usage.

Restricted strictly to callers with the 'admin' role.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, Query

from vaultrag.audit.usage import get_usage
from vaultrag.auth.dependencies import require_role
from vaultrag.context import RequestContext, Role

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/admin/usage", tags=["admin-usage"])


@router.get("")
async def get_tenant_usage(
    days: int = Query(default=30, ge=1, le=365),
    ctx: RequestContext = Depends(require_role(Role.admin)),  # noqa: B008
) -> dict[str, Any]:
    """Retrieve usage metering data over the specified number of days (default 30)."""
    usage_records = get_usage(ctx.tenant_id, days=days)
    return {
        "tenant_id": ctx.tenant_id,
        "days": days,
        "usage": usage_records,
    }
