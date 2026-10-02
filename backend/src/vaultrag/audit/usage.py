"""Tenant usage metering, daily query quotas, and rate tracking."""

from __future__ import annotations

import logging
import time
from datetime import UTC, datetime, timedelta
from typing import Any

import boto3
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError

from vaultrag.audit.hashchain import append_event
from vaultrag.clients.dynamo import _decimals_to_floats, _floats_to_decimals
from vaultrag.config import get_settings
from vaultrag.context import RequestContext
from vaultrag.errors import QuotaExceeded

logger = logging.getLogger(__name__)


def _get_usage_table(table_name: str | None = None, dynamodb_resource: Any = None) -> Any:
    settings = get_settings()
    t_name = table_name or settings.usage_table
    if dynamodb_resource is not None:
        return dynamodb_resource.Table(t_name)
    resource = boto3.resource("dynamodb", region_name=settings.aws_region)
    return resource.Table(t_name)


def increment(
    ctx_or_tenant_id: RequestContext | str,
    queries: int = 0,
    chunks: int = 0,
    est_tokens: int = 0,
    cache_hits: int = 0,
    cache_misses: int = 0,
    *,
    table_name: str | None = None,
    dynamodb_resource: Any = None,
) -> None:
    """Increment daily usage counters with 90-day automatic DynamoDB TTL expiration."""
    tenant_id = (
        ctx_or_tenant_id.tenant_id
        if isinstance(ctx_or_tenant_id, RequestContext)
        else str(ctx_or_tenant_id)
    )
    day = datetime.now(UTC).strftime("%Y-%m-%d")
    expires_at = int(time.time()) + 90 * 86400  # 90 days TTL

    table = _get_usage_table(table_name=table_name, dynamodb_resource=dynamodb_resource)

    add_clauses: list[str] = []
    expr_vals: dict[str, Any] = {":exp": expires_at}

    if queries:
        add_clauses.append("queries :q")
        expr_vals[":q"] = queries
    if chunks:
        add_clauses.append("chunks :c")
        expr_vals[":c"] = chunks
    if est_tokens:
        add_clauses.append("est_tokens :t")
        expr_vals[":t"] = est_tokens
    if cache_hits:
        add_clauses.append("cache_hits :ch")
        expr_vals[":ch"] = cache_hits
    if cache_misses:
        add_clauses.append("cache_misses :cm")
        expr_vals[":cm"] = cache_misses

    if add_clauses:
        update_expr = f"ADD {', '.join(add_clauses)} SET expires_at = :exp"
    else:
        update_expr = "SET expires_at = :exp"

    try:
        table.update_item(
            Key={"tenant_id": tenant_id, "day": day},
            UpdateExpression=update_expr,
            ExpressionAttributeValues=_floats_to_decimals(expr_vals),
        )
    except Exception as e:
        logger.error("Failed to increment usage for tenant=%s, day=%s: %s", tenant_id, day, e)


def reserve_query(
    ctx: RequestContext,
    quota: int,
    *,
    table_name: str | None = None,
    dynamodb_resource: Any = None,
) -> None:
    """Atomically reserve 1 query against the tenant's daily quota.

    Condition: attribute_not_exists(queries) OR queries < :quota
    On ConditionalCheckFailed: raises QuotaExceeded (HTTP 429) and records a
    quota_exceeded audit event.
    """
    tenant_id = ctx.tenant_id
    day = datetime.now(UTC).strftime("%Y-%m-%d")
    expires_at = int(time.time()) + 90 * 86400

    table = _get_usage_table(table_name=table_name, dynamodb_resource=dynamodb_resource)

    try:
        table.update_item(
            Key={"tenant_id": tenant_id, "day": day},
            UpdateExpression="ADD queries :one SET expires_at = :exp",
            ConditionExpression="attribute_not_exists(queries) OR queries < :quota",
            ExpressionAttributeValues=_floats_to_decimals(
                {
                    ":one": 1,
                    ":quota": int(quota),
                    ":exp": expires_at,
                }
            ),
        )
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code")
        if code == "ConditionalCheckFailedException":
            logger.warning(
                "Daily query quota exceeded for tenant=%s, user=%s (quota=%d)",
                tenant_id,
                ctx.user_id,
                quota,
            )
            # Record quota_exceeded in the audit hashchain
            try:
                append_event(
                    ctx,
                    action="quota_exceeded",
                    outcome="blocked",
                    details={"quota": int(quota), "queries": int(quota)},
                    dynamodb_resource=dynamodb_resource,
                )
            except Exception as audit_err:
                logger.error("Failed to append quota_exceeded audit record: %s", audit_err)

            raise QuotaExceeded(f"Daily query quota of {quota} exceeded") from e
        raise


def get_usage(
    tenant_id: str,
    days: int = 30,
    *,
    table_name: str | None = None,
    dynamodb_resource: Any = None,
) -> list[dict[str, Any]]:
    """Retrieve usage history for the past *days* for the specified tenant."""
    table = _get_usage_table(table_name=table_name, dynamodb_resource=dynamodb_resource)

    start_day = (datetime.now(UTC) - timedelta(days=days)).strftime("%Y-%m-%d")

    resp = table.query(
        KeyConditionExpression=Key("tenant_id").eq(tenant_id) & Key("day").gte(start_day),
        ScanIndexForward=False,
    )
    items = [_decimals_to_floats(item) for item in resp.get("Items", [])]
    return items
