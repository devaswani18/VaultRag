from __future__ import annotations

import json
import os
from typing import Any
from unittest.mock import patch

import boto3
import pytest
from fastapi.testclient import TestClient
from moto import mock_aws
from qdrant_client import QdrantClient, models

from vaultrag.admin.assurance import _get_tenants_table
from vaultrag.admin.erasure import verify_signed_payload
from vaultrag.api.app import create_app
from vaultrag.assurance.canaries import EXPECTED_MATRIX
from vaultrag.assurance.models import AssuranceReport
from vaultrag.assurance.runner import run_assurance
from vaultrag.auth.dependencies import get_ctx
from vaultrag.clients.qdrant import ensure_collection, set_client
from vaultrag.config import get_settings
from vaultrag.context import RequestContext, Role


@pytest.fixture
def mock_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AWS_REGION", "ap-south-1")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "ap-south-1")
    monkeypatch.setenv("TENANTS_TABLE", "vaultrag-dev-tenants")
    monkeypatch.setenv("DOCUMENTS_TABLE", "vaultrag-dev-documents")
    monkeypatch.setenv("AUDIT_TABLE", "vaultrag-dev-audit")
    monkeypatch.setenv("USAGE_TABLE", "vaultrag-dev-usage")


@pytest.fixture
def memory_qdrant() -> QdrantClient:
    client = QdrantClient(":memory:")
    set_client(client)
    ensure_collection()
    yield client
    set_client(None)


@pytest.fixture
def mock_dynamodb(mock_env: None):
    with mock_aws():
        dynamodb = boto3.resource("dynamodb", region_name="ap-south-1")

        tenants_table = dynamodb.create_table(
            TableName="vaultrag-dev-tenants",
            KeySchema=[{"AttributeName": "tenant_id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "tenant_id", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )
        tenants_table.put_item(
            Item={
                "tenant_id": "tenant-test",
                "name": "Test Tenant",
                "status": "active",
                "settings": {
                    "pii_mode": "mask",
                    "injection_policy": "quarantine",
                },
            }
        )

        audit_table = dynamodb.create_table(
            TableName="vaultrag-dev-audit",
            KeySchema=[
                {"AttributeName": "tenant_id", "KeyType": "HASH"},
                {"AttributeName": "seq", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "tenant_id", "AttributeType": "S"},
                {"AttributeName": "seq", "AttributeType": "N"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )

        yield {
            "dynamodb": dynamodb,
            "tenants": tenants_table,
            "audit": audit_table,
        }


@pytest.fixture
def admin_ctx() -> RequestContext:
    return RequestContext(
        tenant_id="tenant-test",
        user_id="user-admin",
        roles=frozenset([Role.admin]),
        request_id="req-test-admin",
    )


def test_real_assurance_run_all_18_checks_pass(
    memory_qdrant: QdrantClient,
    mock_dynamodb: dict[str, Any],
    admin_ctx: RequestContext,
) -> None:
    """Test 1: Real run passes all 18 checks and matches literal EXPECTED_MATRIX 100%."""
    report: AssuranceReport = run_assurance(admin_ctx)

    assert report.simulated is False
    assert report.simulated_bug is None
    assert report.tenant_id == "tenant-test"
    assert report.summary["passed"] == 19
    assert report.summary["total"] == 19
    assert report.summary["leaks"] == 0
    assert report.summary["missing"] == 0

    # Verify all 30 cells in the live matrix match EXPECTED_MATRIX
    assert len(report.matrix) == 30
    for cell in report.matrix:
        expected_allowed = EXPECTED_MATRIX[cell.canary][cell.principal]
        assert cell.expected_allowed == expected_allowed
        assert cell.actually_allowed == expected_allowed
        assert cell.state in ("allowed", "blocked")
        assert cell.state not in ("leak", "missing")

    # Verify all 18 check IDs are present and passed
    expected_check_ids = {
        "I1",
        "I2",
        "I3",
        "I4",
        "A1",
        "A2",
        "A3",
        "A4",
        "D1",
        "D2",
        "J1",
        "J2",
        "J3",
        "U1",
        "U2",
        "E1",
        "E2",
        "C1",
        "C2",
    }
    reported_check_ids = {c.id for c in report.checks}
    assert reported_check_ids == expected_check_ids
    for c in report.checks:
        assert c.passed is True, f"Check {c.id} ({c.name}) failed: {c.actual}"

    # Verify signature
    assert report.signature is not None
    assert len(report.signature) == 64
    assert len(report.report_sha256) == 64


def test_simulate_drop_role_condition(
    memory_qdrant: QdrantClient,
    mock_dynamodb: dict[str, Any],
    admin_ctx: RequestContext,
) -> None:
    """Test 2: drop_role_condition simulation detects exact leaks."""
    report: AssuranceReport = run_assurance(admin_ctx, simulate_bug="drop_role_condition")

    assert report.simulated is True
    assert report.simulated_bug == "drop_role_condition"
    assert report.summary["leaks"] == 3
    assert report.summary["missing"] == 0

    # Exact leaks: C2 x A-employee, C2 x A-intern, C4 x A-employee
    leaking_cells = {(c.canary, c.principal) for c in report.matrix if c.state == "leak"}
    assert leaking_cells == {
        ("C2", "A-employee"),
        ("C2", "A-intern"),
        ("C4", "A-employee"),
    }

    # Cross-tenant isolation I1 MUST STILL PASS
    check_i1 = next(c for c in report.checks if c.id == "I1")
    assert check_i1.passed is True

    # Check A4 (matrix exact match) must fail
    check_a4 = next(c for c in report.checks if c.id == "A4")
    assert check_a4.passed is False


def test_simulate_ignore_private(
    memory_qdrant: QdrantClient,
    mock_dynamodb: dict[str, Any],
    admin_ctx: RequestContext,
) -> None:
    """Test 3: ignore_private simulation detects exact private doc leaks."""
    report: AssuranceReport = run_assurance(admin_ctx, simulate_bug="ignore_private")

    assert report.simulated is True
    assert report.simulated_bug == "ignore_private"
    assert report.summary["leaks"] == 5

    # C3 leaks to A-manager, A-employee, A-intern
    # C5 leaks to A-manager, A-employee
    leaking_cells = {(c.canary, c.principal) for c in report.matrix if c.state == "leak"}
    assert leaking_cells == {
        ("C3", "A-manager"),
        ("C3", "A-employee"),
        ("C3", "A-intern"),
        ("C5", "A-manager"),
        ("C5", "A-employee"),
    }

    # Cross-tenant isolation I1 MUST STILL PASS
    check_i1 = next(c for c in report.checks if c.id == "I1")
    assert check_i1.passed is True

    # Check A4 must fail
    check_a4 = next(c for c in report.checks if c.id == "A4")
    assert check_a4.passed is False


def test_tenant_safety_real_tenant_data_untouched(
    memory_qdrant: QdrantClient,
    mock_dynamodb: dict[str, Any],
    admin_ctx: RequestContext,
) -> None:
    """Test 4: Real tenant data is never exposed in queries and never deleted during cleanup."""
    settings = get_settings()

    # Pre-seed a real tenant chunk
    real_point = models.PointStruct(
        id="00000000-0000-0000-0000-000000000099",
        vector=[0.1] * settings.embedding_dim,
        payload={
            "tenant_id": "tenant-test",
            "doc_id": "doc-real-secret",
            "text": "Top secret real customer document data",
            "acl": {"roles": ["admin"], "is_public": False},
        },
    )
    memory_qdrant.upsert(
        collection_name=settings.qdrant_collection,
        points=[real_point],
    )

    # Run assurance suite
    report = run_assurance(admin_ctx)
    assert report.summary["passed"] == 19

    # Assert real point still exists in Qdrant
    res = memory_qdrant.retrieve(
        collection_name=settings.qdrant_collection,
        ids=["00000000-0000-0000-0000-000000000099"],
    )
    assert len(res) == 1
    assert res[0].payload["doc_id"] == "doc-real-secret"


def test_cleanup_on_exception(
    memory_qdrant: QdrantClient,
    mock_dynamodb: dict[str, Any],
    admin_ctx: RequestContext,
) -> None:
    """Test 5: Zero canary points remain even if execution crashes mid-suite."""
    settings = get_settings()

    with (
        patch(
            "vaultrag.assurance.runner.search",
            side_effect=RuntimeError("Simulated crash during query"),
        ),
        pytest.raises(RuntimeError, match="Simulated crash"),
    ):
        run_assurance(admin_ctx)

    # All canary points planted for synthetic tenants must be cleaned up
    count_resp = memory_qdrant.count(
        collection_name=settings.qdrant_collection,
    )
    assert count_resp.count == 0


def test_report_signing_and_tamper_detection(
    memory_qdrant: QdrantClient,
    mock_dynamodb: dict[str, Any],
    admin_ctx: RequestContext,
) -> None:
    """Test 6: HMAC signing and cryptographic tamper detection."""
    report = run_assurance(admin_ctx)
    report_dict = report.to_dict()

    secret = "vaultrag-local-dev-anchor-hmac-secret-key"

    # Authentic report verifies
    assert verify_signed_payload(report_dict, secret) is True

    # Tamper 1: modify summary passed count
    tampered_1 = json.loads(json.dumps(report_dict))
    tampered_1["summary"]["passed"] = 17
    assert verify_signed_payload(tampered_1, secret) is False

    # Tamper 2: flip an access cell state
    tampered_2 = json.loads(json.dumps(report_dict))
    tampered_2["matrix"][0]["state"] = "leak"
    assert verify_signed_payload(tampered_2, secret) is False

    # Tamper 3: modify report_sha256
    tampered_3 = json.loads(json.dumps(report_dict))
    tampered_3["report_sha256"] = "a" * 64
    assert verify_signed_payload(tampered_3, secret) is False

    # Tamper 4: tamper signature
    tampered_4 = json.loads(json.dumps(report_dict))
    tampered_4["signature"] = "b" * 64
    assert verify_signed_payload(tampered_4, secret) is False


def test_api_endpoints_role_enforcement_and_rate_limiting(
    memory_qdrant: QdrantClient,
    mock_dynamodb: dict[str, Any],
) -> None:
    """Test 7: Admin role enforcement, 30s rate limiting, and persistence."""
    app = create_app()
    client = TestClient(app, raise_server_exceptions=False)

    # 1. Non-admin roles receive 403 Forbidden
    for non_admin_role in [Role.intern, Role.employee, Role.manager]:
        user_ctx = RequestContext(
            tenant_id="tenant-test",
            user_id=f"user-{non_admin_role.value}",
            roles=frozenset([non_admin_role]),
            request_id=f"req-test-{non_admin_role.value}",
        )
        app.dependency_overrides[get_ctx] = lambda ctx=user_ctx: ctx
        resp = client.post("/admin/assurance/run", json={})
        assert resp.status_code == 403, f"Role {non_admin_role.value} should get 403"

    admin_ctx = RequestContext(
        tenant_id="tenant-test",
        user_id="user-admin",
        roles=frozenset([Role.admin]),
        request_id="req-test-admin",
    )
    app.dependency_overrides[get_ctx] = lambda: admin_ctx

    # 2. Latest returns 404 before any run
    resp_latest_404 = client.get("/admin/assurance/latest")
    assert resp_latest_404.status_code == 404

    # 3. Successful real run
    resp_run = client.post("/admin/assurance/run", json={})
    assert resp_run.status_code == 200
    data = resp_run.json()
    assert data["summary"]["passed"] == 19
    assert data["simulated"] is False

    # 4. Immediate second run triggered within 30s triggers 429
    resp_rate_limit = client.post("/admin/assurance/run", json={})
    assert resp_rate_limit.status_code == 429
    assert "Rate limit exceeded" in resp_rate_limit.json()["detail"]

    # 5. GET /admin/assurance/latest now returns the signed report
    resp_latest = client.get("/admin/assurance/latest")
    assert resp_latest.status_code == 200
    latest_data = resp_latest.json()
    assert latest_data["run_id"] == data["run_id"]

    # 6. POST /admin/assurance/verify verifies the report
    resp_verify = client.post("/admin/assurance/verify", json=latest_data)
    assert resp_verify.status_code == 200
    assert resp_verify.json() == {"valid": True, "reason": None}

    # 7. POST /admin/assurance/verify rejects report for mismatched tenant
    mismatched_report = json.loads(json.dumps(latest_data))
    mismatched_report["tenant_id"] = "other-tenant"
    resp_mismatch = client.post("/admin/assurance/verify", json=mismatched_report)
    assert resp_mismatch.status_code == 200
    assert resp_mismatch.json()["valid"] is False
    assert "Tenant mismatch" in resp_mismatch.json()["reason"]


def test_simulation_does_not_overwrite_last_assurance(
    memory_qdrant: QdrantClient,
    mock_dynamodb: dict[str, Any],
) -> None:
    """Test 8: Simulated runs record audit event but never overwrite last_assurance."""
    app = create_app()
    client = TestClient(app, raise_server_exceptions=False)

    admin_ctx = RequestContext(
        tenant_id="tenant-test",
        user_id="user-admin",
        roles=frozenset([Role.admin]),
        request_id="req-test-admin",
    )
    app.dependency_overrides[get_ctx] = lambda: admin_ctx

    # Reset rate limit timestamp in DynamoDB so call is permitted
    tenants_table = _get_tenants_table()
    tenants_table.update_item(
        Key={"tenant_id": "tenant-test"},
        UpdateExpression="SET assurance_last_run_ts = :ts",
        ExpressionAttributeValues={":ts": 0},
    )

    resp_sim = client.post(
        "/admin/assurance/run",
        json={"simulate_bug": "drop_role_condition"},
    )
    assert resp_sim.status_code == 200
    sim_data = resp_sim.json()
    assert sim_data["simulated"] is True

    # Check DynamoDB: 'last_assurance' must not be overwritten with the simulated run
    tenant_item = tenants_table.get_item(Key={"tenant_id": "tenant-test"}).get("Item")
    if "last_assurance" in tenant_item:
        assert tenant_item["last_assurance"]["simulated"] is False


def test_no_sensitive_secrets_or_pii_in_report_json(
    memory_qdrant: QdrantClient,
    mock_dynamodb: dict[str, Any],
    admin_ctx: RequestContext,
) -> None:
    """Test 9: Serialized report contains zero PII or raw secrets."""
    report = run_assurance(admin_ctx)
    report_json_str = json.dumps(report.to_dict()).lower()

    # Assert no sensitive keywords or raw secrets
    assert "password" not in report_json_str
    assert "eyjhbgcioij" not in report_json_str
    assert "secret-key" not in report_json_str
    assert "private_key" not in report_json_str


def test_fault_injection_not_imported_in_production_modules() -> None:
    """Test 10: Fault injection module is strictly excluded from api and rag code paths."""
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    api_dir = os.path.join(repo_root, "src", "vaultrag", "api")
    rag_dir = os.path.join(repo_root, "src", "vaultrag", "rag")

    for search_dir in [api_dir, rag_dir]:
        for root, _, files in os.walk(search_dir):
            for file in files:
                if file.endswith(".py"):
                    file_path = os.path.join(root, file)
                    with open(file_path, encoding="utf-8") as f:
                        content = f.read()
                    assert "fault_injection" not in content, (
                        f"Production file {file_path} imports or references fault_injection!"
                    )
