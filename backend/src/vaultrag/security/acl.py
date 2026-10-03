"""Access-Control Layer: enforces tenant- and document-level access control.

Provides `can_view` for pure-Python evaluation and `build_filter` / `build_doc_filter`
for Qdrant vector retrieval filtering.
"""

from __future__ import annotations

import logging
from typing import Any

from qdrant_client import models

from vaultrag.context import RequestContext

logger = logging.getLogger(__name__)


def can_view(ctx: RequestContext, doc_or_payload: dict[str, Any]) -> bool:
    """Pure-Python ACL decision for a document or Qdrant chunk payload.

    Rules:
      - Tenant mismatch: False.
      - Tenant admin: True.
      - Document owner (owner_user_id == ctx.user_id): True.
      - User in allowed_users: True.
      - Visibility 'tenant': True.
      - Visibility 'roles': True if any role in allowed_roles matches caller's roles.
      - Otherwise: False.
    """
    if not isinstance(doc_or_payload, dict):
        return False

    doc_tenant = doc_or_payload.get("tenant_id")
    if not doc_tenant or doc_tenant != ctx.tenant_id:
        return False

    # Documents in DELETING, DELETE_FAILED, or DELETED are hidden from lists and queries
    status = doc_or_payload.get("status")
    if status in ("DELETING", "DELETE_FAILED", "DELETED"):
        return False

    # Admin of the same tenant has full visibility
    if ctx.is_admin:
        return True

    # Owner always has access
    owner_id = doc_or_payload.get("owner_user_id")
    if owner_id and owner_id == ctx.user_id:
        return True

    # Explicit user grant
    allowed_users = doc_or_payload.get("allowed_users") or []
    if ctx.user_id in allowed_users:
        return True

    # Visibility rules
    visibility = str(doc_or_payload.get("visibility", "tenant")).strip().lower()
    if visibility == "tenant":
        return True

    if visibility == "roles":
        allowed_roles = {
            str(r).strip().lower() for r in (doc_or_payload.get("allowed_roles") or [])
        }
        user_roles = {r.lower() for r in ctx.role_names()}
        if bool(allowed_roles & user_roles):
            return True

    return False


def build_filter(ctx: RequestContext) -> models.Filter:
    """Build a Qdrant Filter that restricts results according to tenant and document ACLs.

    Rules:
      - must: tenant_id == ctx.tenant_id
      - if ctx.is_admin: nothing more.
      - else must (at-least-one-of / should):
          - visibility == 'tenant'
          - allowed_roles any-of ctx.role_names()
          - allowed_users any-of [ctx.user_id]
          - owner_user_id == ctx.user_id

    Fail closed: Any exception returns a filter that matches nothing (tenant_id == '__none__')
    and logs an error event. Never returns an unscoped filter.
    """
    try:
        tenant_id = getattr(ctx, "tenant_id", None)
        if not tenant_id or not isinstance(tenant_id, str):
            raise ValueError(f"Invalid or missing tenant_id on context: {tenant_id}")

        must_conditions: list[Any] = [
            models.FieldCondition(
                key="tenant_id",
                match=models.MatchValue(value=tenant_id),
            )
        ]

        # Admin of the tenant requires no further restriction beyond tenant isolation
        if ctx.is_admin:
            return models.Filter(must=must_conditions)

        # Non-admin callers require at least one visibility / role / user match
        role_names = list(ctx.role_names())
        should_clauses: list[Any] = [
            models.FieldCondition(
                key="visibility",
                match=models.MatchValue(value="tenant"),
            ),
            models.FieldCondition(
                key="allowed_users",
                match=models.MatchAny(any=[ctx.user_id]),
            ),
            models.FieldCondition(
                key="owner_user_id",
                match=models.MatchValue(value=ctx.user_id),
            ),
        ]

        if role_names:
            should_clauses.append(
                models.FieldCondition(
                    key="allowed_roles",
                    match=models.MatchAny(any=role_names),
                )
            )

        must_conditions.append(models.Filter(should=should_clauses))
        return models.Filter(must=must_conditions)

    except Exception as e:
        logger.error(
            "Failed to build ACL filter for tenant=%s user=%s: %s",
            getattr(ctx, "tenant_id", "unknown"),
            getattr(ctx, "user_id", "unknown"),
            type(e).__name__,
        )
        # Fail closed: returns a filter matching nothing, never an unscoped filter
        return models.Filter(
            must=[
                models.FieldCondition(
                    key="tenant_id",
                    match=models.MatchValue(value="__none__"),
                )
            ]
        )


def build_doc_filter(ctx: RequestContext, doc_id: str) -> models.Filter:
    """Build an ACL filter scoped to a specific document ID.

    Calls build_filter(ctx) and appends doc_id == doc_id.
    """
    filt = build_filter(ctx)
    if filt.must is None:
        filt.must = []
    filt.must.append(
        models.FieldCondition(
            key="doc_id",
            match=models.MatchValue(value=doc_id),
        )
    )
    return filt


def build_scoped_filter(ctx: RequestContext, doc_ids: list[str]) -> models.Filter:
    """Build a Qdrant Filter that restricts results to tenant/document ACLs AND the given doc_ids.

    Composes the filter from build_filter(ctx) with doc_id MatchAny(doc_ids).
    Never rebuilds ACL rules. Fails closed if any exception occurs.
    The tenant_id condition remains a top-level must condition.
    """
    try:
        base_filter = build_filter(ctx)
        if not doc_ids:
            return base_filter

        scope_filter = models.Filter(
            must=[
                models.FieldCondition(
                    key="doc_id",
                    match=models.MatchAny(any=list(doc_ids)),
                )
            ]
        )
        must_conditions = list(base_filter.must or [])
        must_conditions.append(scope_filter)
        return models.Filter(must=must_conditions)
    except Exception as e:
        logger.error(
            "Failed to build scoped ACL filter for tenant=%s user=%s: %s",
            getattr(ctx, "tenant_id", "unknown"),
            getattr(ctx, "user_id", "unknown"),
            type(e).__name__,
        )
        return models.Filter(
            must=[
                models.FieldCondition(
                    key="tenant_id",
                    match=models.MatchValue(value="__none__"),
                )
            ]
        )
