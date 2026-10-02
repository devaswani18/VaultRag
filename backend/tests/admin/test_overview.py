from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from vaultrag.api.app import create_app
from vaultrag.auth.dependencies import get_ctx, require_role
from vaultrag.clients.dynamo import DocumentRepo
from vaultrag.context import RequestContext, Role


@pytest.fixture
def admin_ctx() -> RequestContext:
    return RequestContext(
        tenant_id="tenant-a",
        user_id="user-admin",
        roles=frozenset({Role.admin}),
        request_id="req-admin-1",
    )


@pytest.fixture
def non_admin_ctx() -> RequestContext:
    return RequestContext(
        tenant_id="tenant-a",
        user_id="user-employee",
        roles=frozenset({Role.employee}),
        request_id="req-emp-1",
    )


def test_admin_overview_requires_admin_role(
    mock_admin_env: dict[str, Any], non_admin_ctx: RequestContext
) -> None:
    app = create_app()
    app.dependency_overrides[get_ctx] = lambda: non_admin_ctx
    app.dependency_overrides[require_role(Role.admin)] = lambda: non_admin_ctx

    client = TestClient(app)
    resp = client.get("/admin/overview")
    assert resp.status_code == 403


def test_admin_overview_success(mock_admin_env: dict[str, Any], admin_ctx: RequestContext) -> None:
    app = create_app()
    app.dependency_overrides[get_ctx] = lambda: admin_ctx
    app.dependency_overrides[require_role(Role.admin)] = lambda: admin_ctx

    client = TestClient(app)
    resp = client.get("/admin/overview")
    assert resp.status_code == 200
    data = resp.json()

    assert data["tenant_id"] == "tenant-a"
    assert "queries_today" in data
    assert "daily_query_quota" in data
    assert "abstain_rate" in data
    assert "avg_trust_score" in data
    assert "cache_hit_rate" in data
    assert "quarantined_documents_count" in data
    assert "pii_findings_by_type" in data
    assert "audit_chain_status" in data
    assert "valid" in data["audit_chain_status"]


def test_admin_overview_aggregates_data(
    mock_admin_env: dict[str, Any], admin_ctx: RequestContext
) -> None:
    app = create_app()
    app.dependency_overrides[get_ctx] = lambda: admin_ctx
    app.dependency_overrides[require_role(Role.admin)] = lambda: admin_ctx

    # 1. Seed usage
    from vaultrag.audit.usage import increment

    increment(admin_ctx, queries=15, cache_hits=5, cache_misses=5)

    # 2. Seed a quarantined document and PII
    doc_repo = DocumentRepo()
    doc_repo.create(
        tenant_id="tenant-a",
        doc_id="doc-quar-1",
        filename="risky.txt",
        content_type="text/plain",
        size_bytes=100,
        status="QUARANTINED",
        pii_summary={"EMAIL_ADDRESS": 3, "US_SSN": 1},
        quarantine_report=[{"risk": "high", "reasons": ["injection"]}],
    )

    # 3. Seed audit query event
    from vaultrag.audit.hashchain import append_event

    append_event(
        admin_ctx,
        action="query",
        outcome="ok",
        details={
            "trust_score": 0.85,
            "abstained": False,
            "pii_types_in_question": ["EMAIL_ADDRESS"],
        },
    )

    client = TestClient(app)
    resp = client.get("/admin/overview")
    assert resp.status_code == 200
    data = resp.json()

    assert data["quarantined_documents_count"] >= 1
    assert data["pii_findings_by_type"].get("EMAIL_ADDRESS", 0) >= 3
    assert data["avg_trust_score"] > 0
    assert data["cache_hit_rate"] == 0.5


def test_policies_update_llm_judge_enabled(
    mock_admin_env: dict[str, Any], admin_ctx: RequestContext
) -> None:
    app = create_app()
    app.dependency_overrides[get_ctx] = lambda: admin_ctx
    app.dependency_overrides[require_role(Role.admin)] = lambda: admin_ctx

    client = TestClient(app)
    # Check current policies
    resp = client.get("/admin/policies")
    assert resp.status_code == 200
    assert "llm_judge_enabled" in resp.json()

    # Update llm_judge_enabled
    patch_resp = client.patch("/admin/policies", json={"llm_judge_enabled": True})
    assert patch_resp.status_code == 200
    assert patch_resp.json()["llm_judge_enabled"] is True

    # Check invalid value rejected
    bad_resp = client.patch("/admin/policies", json={"llm_judge_enabled": "not-a-bool"})
    assert bad_resp.status_code == 422 or bad_resp.status_code == 400
