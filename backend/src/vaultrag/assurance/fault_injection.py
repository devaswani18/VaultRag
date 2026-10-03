"""Fault injection filters used EXCLUSIVELY by the Assurance Center simulation mode.

WARNING:
These filter builders deliberately introduce controlled security bugs solely to demonstrate
that the Assurance Center's canary matrix detection works and detects leaks.
They must NEVER be imported, referenced, or used in production query routing (api/ or rag/).
Both builders still strictly enforce the tenant_id condition, guaranteeing that simulations
can NEVER cross tenant boundaries or reach customer data.
"""

from __future__ import annotations

from typing import Any

from qdrant_client import models

from vaultrag.context import RequestContext


def build_filter_drop_role_condition(ctx: RequestContext) -> models.Filter:
    """SIMULATION BUG: Ignores allowed_roles condition.

    Causes role-restricted documents (e.g. C2) to leak to any tenant member (e.g. employee, intern),
    while preserving tenant_id isolation.
    """
    tenant_id = ctx.tenant_id
    must_conditions: list[Any] = [
        models.FieldCondition(
            key="tenant_id",
            match=models.MatchValue(value=tenant_id),
        )
    ]

    if ctx.is_admin:
        return models.Filter(must=must_conditions)

    # Bug: unconditionally matches visibility='roles' without validating ctx.role_names()
    should_clauses: list[Any] = [
        models.FieldCondition(key="visibility", match=models.MatchValue(value="tenant")),
        models.FieldCondition(key="visibility", match=models.MatchValue(value="roles")),
        models.FieldCondition(key="allowed_users", match=models.MatchAny(any=[ctx.user_id])),
        models.FieldCondition(key="owner_user_id", match=models.MatchValue(value=ctx.user_id)),
    ]

    must_conditions.append(models.Filter(should=should_clauses))
    return models.Filter(must=must_conditions)


def build_filter_ignore_private(ctx: RequestContext) -> models.Filter:
    """SIMULATION BUG: Treats private documents as visible to all tenant members.

    Causes private documents (C3, C5) to leak to unauthorized users in the tenant,
    while preserving tenant_id isolation.
    """
    tenant_id = ctx.tenant_id
    must_conditions: list[Any] = [
        models.FieldCondition(
            key="tenant_id",
            match=models.MatchValue(value=tenant_id),
        )
    ]

    if ctx.is_admin:
        return models.Filter(must=must_conditions)

    role_names = list(ctx.role_names())
    # Bug: adds visibility='private' to should clauses so any tenant user sees private docs
    should_clauses: list[Any] = [
        models.FieldCondition(key="visibility", match=models.MatchValue(value="tenant")),
        models.FieldCondition(key="visibility", match=models.MatchValue(value="private")),
        models.FieldCondition(key="allowed_users", match=models.MatchAny(any=[ctx.user_id])),
        models.FieldCondition(key="owner_user_id", match=models.MatchValue(value=ctx.user_id)),
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
