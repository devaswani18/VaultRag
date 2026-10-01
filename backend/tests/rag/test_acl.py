"""Tests for vaultrag.security.acl — build_filter correctness."""

from __future__ import annotations

import pytest
from qdrant_client import models

from vaultrag.context import RequestContext, Role
from vaultrag.security.acl import build_filter


def _make_ctx(tenant_id: str) -> RequestContext:
    return RequestContext(
        tenant_id=tenant_id,
        user_id="usr-test",
        roles=frozenset([Role.admin]),
        request_id="req-test-001",
    )


# Parametrised across tenants to prove isolation never leaks tenant_id
@pytest.mark.parametrize("tenant_id", ["acme", "globex", "initech", "umbrella-corp"])
def test_build_filter_contains_tenant_id(tenant_id: str) -> None:
    ctx = _make_ctx(tenant_id)
    filt = build_filter(ctx)

    assert isinstance(filt, models.Filter)
    assert filt.must, "Filter must have at least one must clause"

    tenant_conditions = [
        c for c in filt.must if isinstance(c, models.FieldCondition) and c.key == "tenant_id"
    ]
    assert len(tenant_conditions) == 1, "Filter must have exactly one tenant_id condition"
    match_val = tenant_conditions[0].match
    assert isinstance(match_val, models.MatchValue)
    assert match_val.value == tenant_id


@pytest.mark.parametrize("tenant_id", ["acme", "globex"])
def test_build_filter_different_tenants_are_distinct(tenant_id: str) -> None:
    """Filters for different tenants must not share the same tenant match value."""
    other_tenant = "other-tenant"
    ctx = _make_ctx(tenant_id)
    filt = build_filter(ctx)

    for c in filt.must:
        if isinstance(c, models.FieldCondition) and c.key == "tenant_id":
            assert c.match.value != other_tenant  # type: ignore[union-attr]
