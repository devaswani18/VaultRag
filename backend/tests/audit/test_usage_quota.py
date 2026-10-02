"""Tests for usage metering and atomic query quota enforcement."""

from __future__ import annotations

import concurrent.futures
from typing import Any

from vaultrag.audit.hashchain import verify_chain
from vaultrag.audit.usage import get_usage, increment, reserve_query
from vaultrag.context import RequestContext, Role
from vaultrag.errors import QuotaExceeded


def _make_ctx(tenant_id: str = "tenant-quota", user_id: str = "user-1") -> RequestContext:
    return RequestContext(
        tenant_id=tenant_id,
        user_id=user_id,
        roles=frozenset([Role.employee]),
        request_id="req-quota-123",
    )


def test_quota_atomicity_n_parallel_reserves(mock_audit_dynamo: dict[str, Any]) -> None:
    """N parallel threads attempting to reserve query when quota is Q must allow exactly Q."""
    resource = mock_audit_dynamo["resource"]
    ctx = _make_ctx()
    quota = 5
    n_threads = 20

    success_count = 0
    exceeded_count = 0

    def _reserve_attempt() -> bool:
        try:
            reserve_query(ctx, quota=quota, dynamodb_resource=resource)
            return True
        except QuotaExceeded:
            return False

    with concurrent.futures.ThreadPoolExecutor(max_workers=n_threads) as executor:
        futures = [executor.submit(_reserve_attempt) for _ in range(n_threads)]
        for f in concurrent.futures.as_completed(futures):
            if f.result():
                success_count += 1
            else:
                exceeded_count += 1

    assert success_count == quota
    assert exceeded_count == n_threads - quota

    # Verify that quota_exceeded audit events were recorded in the audit hashchain
    chain_res = verify_chain(ctx.tenant_id, dynamodb_resource=resource)
    assert chain_res["valid"] is True
    assert chain_res["checked"] == exceeded_count


def test_increment_and_get_usage(mock_audit_dynamo: dict[str, Any]) -> None:
    resource = mock_audit_dynamo["resource"]
    ctx = _make_ctx(tenant_id="tenant-usage")

    increment(
        ctx,
        queries=10,
        chunks=50,
        est_tokens=1500,
        cache_hits=2,
        cache_misses=8,
        dynamodb_resource=resource,
    )
    increment(
        ctx,
        queries=5,
        chunks=20,
        est_tokens=800,
        cache_hits=3,
        cache_misses=2,
        dynamodb_resource=resource,
    )

    usage_items = get_usage(ctx.tenant_id, days=7, dynamodb_resource=resource)
    assert len(usage_items) == 1
    item = usage_items[0]
    assert item["queries"] == 15
    assert item["chunks"] == 70
    assert item["est_tokens"] == 2300
    assert item["cache_hits"] == 5
    assert item["cache_misses"] == 10
    assert "expires_at" in item
