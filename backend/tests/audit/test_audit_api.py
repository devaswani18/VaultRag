"""Integration tests for admin audit and usage endpoints, CSV export, and zero-raw-query assertion."""

from __future__ import annotations

import csv
import io
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from vaultrag.api.app import create_app
from vaultrag.audit.hashchain import append_event
from vaultrag.auth.jwt_verifier import Claims
from vaultrag.context import RequestContext, Role
from vaultrag.rag.retrieve import RetrievedChunk


def _mock_claims(tenant_id: str = "acme", role: Role = Role.admin) -> Claims:
    return Claims(
        sub="user-123",
        email=f"user@{tenant_id}.com",
        tenant_id=tenant_id,
        roles=frozenset([role]),
        token_use="id",
        raw_claims={
            "exp": 1800000000,
            "iat": 1700000000,
            "iss": "https://cognito-idp.ap-south-1.amazonaws.com/test",
            "aud": "test-client",
        },
    )


@pytest.fixture
def client(mock_audit_dynamo: dict[str, Any]) -> TestClient:
    app = create_app()
    return TestClient(app)


def test_admin_audit_list_and_pagination(
    client: TestClient, mock_audit_dynamo: dict[str, Any]
) -> None:
    resource = mock_audit_dynamo["resource"]
    ctx = RequestContext(
        tenant_id="acme",
        user_id="admin-1",
        roles=frozenset([Role.admin]),
        request_id="req-1",
    )

    for i in range(15):
        append_event(
            ctx,
            action="document_create",
            resource_id=f"doc-{i}",
            details={
                "filename": f"f_{i}.txt",
                "content_type": "text/plain",
                "size_bytes": 100,
                "visibility": "tenant",
            },
            dynamodb_resource=resource,
        )

    with patch(
        "vaultrag.auth.dependencies.verify_id_token", return_value=_mock_claims("acme", Role.admin)
    ):
        headers = {"Authorization": "Bearer fake.jwt.token"}
        # Page 1 with limit=5
        r1 = client.get("/admin/audit?limit=5", headers=headers)
        assert r1.status_code == 200
        data1 = r1.json()
        assert len(data1["items"]) == 5
        assert data1["next_cursor"] is not None
        # Newest first: seq 14 down to 10
        assert data1["items"][0]["seq"] == 14

        # Page 2 using cursor
        cursor = data1["next_cursor"]
        r2 = client.get(f"/admin/audit?limit=5&cursor={cursor}", headers=headers)
        assert r2.status_code == 200
        data2 = r2.json()
        assert len(data2["items"]) == 5
        assert data2["items"][0]["seq"] == 9


def test_admin_audit_verify_endpoint(client: TestClient, mock_audit_dynamo: dict[str, Any]) -> None:
    resource = mock_audit_dynamo["resource"]
    ctx = RequestContext(
        tenant_id="acme",
        user_id="admin-1",
        roles=frozenset([Role.admin]),
        request_id="req-1",
    )

    append_event(
        ctx,
        action="policy_change",
        details={"changed_keys": ["min_faithfulness"]},
        dynamodb_resource=resource,
    )

    with patch(
        "vaultrag.auth.dependencies.verify_id_token", return_value=_mock_claims("acme", Role.admin)
    ):
        headers = {"Authorization": "Bearer fake.jwt.token"}
        resp = client.get("/admin/audit/verify", headers=headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["valid"] is True
        assert data["checked"] >= 1


def test_admin_audit_anchor_endpoint(client: TestClient, mock_audit_dynamo: dict[str, Any]) -> None:
    resource = mock_audit_dynamo["resource"]
    ctx = RequestContext(
        tenant_id="acme",
        user_id="admin-1",
        roles=frozenset([Role.admin]),
        request_id="req-1",
    )

    append_event(
        ctx,
        action="document_create",
        resource_id="doc-99",
        details={
            "filename": "doc.pdf",
            "content_type": "application/pdf",
            "size_bytes": 100,
            "visibility": "tenant",
        },
        dynamodb_resource=resource,
    )

    with patch(
        "vaultrag.auth.dependencies.verify_id_token", return_value=_mock_claims("acme", Role.admin)
    ):
        headers = {"Authorization": "Bearer fake.jwt.token"}
        resp = client.get("/admin/audit/anchor", headers=headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["tenant_id"] == "acme"
        assert "signature" in data
        assert "hash" in data


def test_csv_export_neutralizes_injection(
    client: TestClient, mock_audit_dynamo: dict[str, Any]
) -> None:
    resource = mock_audit_dynamo["resource"]
    ctx = RequestContext(
        tenant_id="acme",
        user_id="admin-1",
        roles=frozenset([Role.admin]),
        request_id="req-1",
    )

    # Malicious injection payloads starting with =, +, -, @, \t
    append_event(
        ctx,
        action="document_create",
        resource_id="=cmd|' /C calc'!A0",
        details={
            "filename": "+SUM(1+1)",
            "content_type": "-2+3",
            "size_bytes": 100,
            "visibility": "@malicious",
        },
        dynamodb_resource=resource,
    )

    with patch(
        "vaultrag.auth.dependencies.verify_id_token", return_value=_mock_claims("acme", Role.admin)
    ):
        headers = {"Authorization": "Bearer fake.jwt.token"}
        resp = client.get("/admin/audit/export", headers=headers)
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("text/csv")
        csv_text = resp.text

        reader = csv.reader(io.StringIO(csv_text))
        rows = list(reader)
        assert len(rows) >= 2  # header + 1 data row

        data_row = rows[1]
        # Check that dangerous values were prefixed with single quote
        resource_id_val = data_row[4]
        assert resource_id_val.startswith("'=")

        details_val = data_row[8]
        assert details_val.startswith("{")


def test_raw_question_text_never_appears_in_stored_records(
    client: TestClient,
    mock_audit_dynamo: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Assert that raw question strings never appear anywhere in stored audit DynamoDB items."""
    raw_secret_question = "What is the secret master vault combination for project X?"

    # Setup mocks for query path
    retrieved_chunk = RetrievedChunk(
        chunk_id="chk_1",
        doc_id="doc_1",
        text="The corporate project X vault code is verified and maintained by facilities.",
        score=0.92,
        filename="vault_guide.txt",
        page=1,
    )

    monkeypatch.setattr(
        "vaultrag.api.routers.query.retrieve",
        lambda *args, **kwargs: [retrieved_chunk],
    )

    fake_answer_result = MagicMock()
    fake_answer_result.answer = "The corporate project X vault code is maintained by facilities."
    fake_answer_result.segments = [
        {
            "text": "The corporate project X vault code is maintained by facilities.",
            "citations": ["chk_1"],
        }
    ]
    fake_answer_result.citations = ["chk_1"]
    fake_answer_result.canary = "vr-12345"
    fake_answer_result.invalid = False

    monkeypatch.setattr(
        "vaultrag.api.routers.query.generate_answer",
        lambda *args, **kwargs: fake_answer_result,
    )

    # Mock TenantRepo
    mock_repo = MagicMock()
    mock_repo.get.return_value = {
        "tenant_id": "acme",
        "settings": {
            "daily_query_quota": 50,
            "min_retrieval_score": 0.35,
            "min_faithfulness": 0.6,
            "pii_mode": "redact",
        },
    }
    monkeypatch.setattr("vaultrag.api.routers.query.TenantRepo", lambda: mock_repo)

    with patch(
        "vaultrag.auth.dependencies.verify_id_token",
        return_value=_mock_claims("acme", Role.employee),
    ):
        headers = {"Authorization": "Bearer fake.jwt.token"}
        resp = client.post(
            "/query",
            json={"question": raw_secret_question},
            headers=headers,
        )
        assert resp.status_code == 200

    # Inspect all items written to the audit DynamoDB table
    audit_table = mock_audit_dynamo["audit"]
    items = audit_table.scan().get("Items", [])
    assert len(items) >= 1

    for item in items:
        item_str = str(item)
        assert raw_secret_question not in item_str
        # Verify question_sha256 exists in details
        assert "question_sha256" in item.get("details", {})
