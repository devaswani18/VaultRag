"""Admin audit trail endpoints: pagination, verification, cryptographic anchors, and CSV export.

Restricted strictly to callers with the 'admin' role.
"""

from __future__ import annotations

import csv
import io
import logging
from decimal import Decimal
from typing import Any

from boto3.dynamodb.conditions import Key
from fastapi import APIRouter, Depends, Query, Response

from vaultrag.audit.hashchain import (
    _get_audit_table,
    append_event,
    canonical_json,
    export_anchor,
    verify_chain,
)
from vaultrag.auth.dependencies import require_role
from vaultrag.clients.dynamo import _decimals_to_floats
from vaultrag.context import RequestContext, Role

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/admin/audit", tags=["admin-audit"])


def _sanitize_csv_cell(val: Any) -> str:
    """Neutralize CSV formula injection by prepending a single quote to dangerous characters."""
    if val is None:
        return ""
    text = canonical_json(val) if isinstance(val, (dict, list)) else str(val)

    if text and text[0] in ("=", "+", "-", "@", "\t", "\r"):
        return f"'{text}"
    return text


@router.get("")
async def list_audit_records(
    limit: int = Query(default=50, ge=1, le=100),
    cursor: str | None = Query(default=None),
    action: str | None = Query(default=None),
    actor: str | None = Query(default=None),
    ctx: RequestContext = Depends(require_role(Role.admin)),  # noqa: B008
) -> dict[str, Any]:
    """Retrieve paginated audit log entries for the caller's tenant, newest first."""
    table = _get_audit_table()

    query_params: dict[str, Any] = {
        "KeyConditionExpression": Key("tenant_id").eq(ctx.tenant_id),
        "ScanIndexForward": False,
        "Limit": limit,
    }

    if cursor:
        try:
            seq_val = int(cursor)
            query_params["ExclusiveStartKey"] = {
                "tenant_id": ctx.tenant_id,
                "seq": Decimal(str(seq_val)),
            }
        except ValueError:
            pass

    resp = table.query(**query_params)
    raw_items = [_decimals_to_floats(it) for it in resp.get("Items", [])]

    # In-memory filter for action / actor if specified
    items: list[dict[str, Any]] = []
    for it in raw_items:
        if action and it.get("action") != action:
            continue
        if actor and it.get("actor") != actor:
            continue
        items.append(it)

    last_eval = resp.get("LastEvaluatedKey")
    next_cursor = str(int(last_eval["seq"])) if last_eval and "seq" in last_eval else None

    return {
        "items": items,
        "next_cursor": next_cursor,
    }


@router.get("/verify")
async def verify_audit_chain(
    ctx: RequestContext = Depends(require_role(Role.admin)),  # noqa: B008
) -> dict[str, Any]:
    """Verify cryptographic integrity of the tenant's audit hash chain and record verification."""
    result = verify_chain(ctx.tenant_id)

    # Record the audit_verify action into the chain
    try:
        append_event(
            ctx,
            action="audit_verify",
            outcome="ok" if result["valid"] else "failed",
            details={
                "valid": result["valid"],
                "checked": result["checked"],
                "broken_at_seq": result["broken_at_seq"],
            },
        )
    except Exception as e:
        logger.error("Failed to append audit_verify event: %s", e)

    return result


@router.get("/anchor")
async def get_audit_anchor(
    ctx: RequestContext = Depends(require_role(Role.admin)),  # noqa: B008
) -> dict[str, Any]:
    """Export a signed HMAC-SHA256 anchor of the latest record in the tenant's chain."""
    return export_anchor(ctx.tenant_id)


@router.get("/export")
async def export_audit_csv(
    ctx: RequestContext = Depends(require_role(Role.admin)),  # noqa: B008
) -> Response:
    """Export the entire tenant audit trail as CSV with injection neutralization."""
    table = _get_audit_table()

    items: list[dict[str, Any]] = []
    exclusive_start_key = None

    while True:
        kwargs: dict[str, Any] = {
            "KeyConditionExpression": Key("tenant_id").eq(ctx.tenant_id),
            "ScanIndexForward": True,
        }
        if exclusive_start_key is not None:
            kwargs["ExclusiveStartKey"] = exclusive_start_key

        resp = table.query(**kwargs)
        for it in resp.get("Items", []):
            items.append(_decimals_to_floats(it))

        exclusive_start_key = resp.get("LastEvaluatedKey")
        if not exclusive_start_key:
            break

    # Build CSV output
    headers = [
        "seq",
        "ts",
        "actor",
        "action",
        "resource_id",
        "outcome",
        "hash",
        "prev_hash",
        "details",
    ]

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(headers)

    for it in items:
        row = [
            _sanitize_csv_cell(it.get("seq")),
            _sanitize_csv_cell(it.get("ts")),
            _sanitize_csv_cell(it.get("actor")),
            _sanitize_csv_cell(it.get("action")),
            _sanitize_csv_cell(it.get("resource_id")),
            _sanitize_csv_cell(it.get("outcome")),
            _sanitize_csv_cell(it.get("hash")),
            _sanitize_csv_cell(it.get("prev_hash")),
            _sanitize_csv_cell(it.get("details")),
        ]
        writer.writerow(row)

    csv_data = output.getvalue()
    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=audit.csv"},
    )
