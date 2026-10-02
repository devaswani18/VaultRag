"""Comprehensive tests for Verifiable Document Deletion & Erasure Certificates."""

from __future__ import annotations

import uuid
from typing import Any
from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from qdrant_client import models

from vaultrag.admin.erasure import erase_document, verify_certificate
from vaultrag.api.app import create_app
from vaultrag.auth.dependencies import clear_tenant_cache, get_ctx
from vaultrag.clients.dynamo import DocStatus
from vaultrag.context import RequestContext, Role


def _make_ctx(
    tenant_id: str = "tenant-a",
    user_id: str = "user-alice",
    role: Role = Role.employee,
) -> RequestContext:
    return RequestContext(
        tenant_id=tenant_id,
        user_id=user_id,
        roles=frozenset([role]),
        request_id="req-test-erasure",
    )


def _seed_document_and_assets(
    mock_env: dict[str, Any],
    tenant_id: str = "tenant-a",
    doc_id: str = "doc-1",
    owner_user_id: str = "user-alice",
    filename: str = "confidential_strategy.pdf",
    vector_count: int = 3,
    file_count: int = 2,
) -> None:
    # 1. DynamoDB document
    docs_table = mock_env["docs_table"]
    docs_table.put_item(
        Item={
            "tenant_id": tenant_id,
            "doc_id": doc_id,
            "filename": filename,
            "content_type": "application/pdf",
            "size_bytes": 10240,
            "status": DocStatus.READY.value,
            "visibility": "tenant",
            "allowed_roles": ["employee"],
            "allowed_users": [],
            "owner_user_id": owner_user_id,
            "s3_key": f"uploads/{tenant_id}/{doc_id}/original.pdf",
            "chunk_count": vector_count,
        }
    )

    # 2. Qdrant vectors
    qdrant = mock_env["qdrant"]
    if vector_count > 0:
        points = [
            models.PointStruct(
                id=str(uuid.uuid4()),
                vector=[0.1, 0.2, 0.3, 0.4],
                payload={
                    "tenant_id": tenant_id,
                    "doc_id": doc_id,
                    "chunk_id": f"{doc_id}#c{i}",
                    "text": f"Confidential text segment {i}",
                },
            )
            for i in range(vector_count)
        ]
        qdrant.upsert(collection_name="vaultrag_chunks", points=points)

    # 3. S3 objects
    s3 = mock_env["s3"]
    bucket = "vaultrag-docs-dev"
    if file_count >= 1:
        s3.put_object(
            Bucket=bucket,
            Key=f"uploads/{tenant_id}/{doc_id}/original.pdf",
            Body=b"%PDF-1.4 mock content",
        )
    if file_count >= 2:
        s3.put_object(
            Bucket=bucket,
            Key=f"uploads/{tenant_id}/{doc_id}/extracted.json",
            Body=b'{"chunks": []}',
        )


def test_deletion_leaves_zero_points_and_no_s3_objects(mock_admin_env: dict[str, Any]) -> None:
    """Verifiable deletion must completely wipe Qdrant points and S3 objects for the doc."""
    ctx = _make_ctx(tenant_id="tenant-a", user_id="user-alice", role=Role.employee)
    doc_id = "doc-purge-1"

    _seed_document_and_assets(
        mock_admin_env,
        tenant_id="tenant-a",
        doc_id=doc_id,
        owner_user_id="user-alice",
        vector_count=4,
        file_count=2,
    )
    # Also seed another doc to verify cross-doc isolation
    _seed_document_and_assets(
        mock_admin_env,
        tenant_id="tenant-a",
        doc_id="doc-keep-2",
        owner_user_id="user-alice",
        vector_count=2,
        file_count=1,
    )

    cert = erase_document(
        ctx,
        doc_id=doc_id,
        s3_client=mock_admin_env["s3"],
        qdrant_client=mock_admin_env["qdrant"],
        dynamodb_resource=mock_admin_env["dynamodb"],
    )

    assert cert["version"] == 1
    assert cert["tenant_id"] == "tenant-a"
    assert cert["doc_id"] == doc_id
    assert cert["requested_by"] == "user-alice"
    assert cert["deleted"]["vectors"] == 4
    assert cert["deleted"]["files"] == 2
    assert cert["post_check"]["remaining_vectors"] == 0
    assert cert["post_check"]["remaining_files"] == 0
    assert "signature" in cert

    # Verify Qdrant points for purged doc are 0
    qdrant = mock_admin_env["qdrant"]
    filt_purged = models.Filter(
        must=[
            models.FieldCondition(key="tenant_id", match=models.MatchValue(value="tenant-a")),
            models.FieldCondition(key="doc_id", match=models.MatchValue(value=doc_id)),
        ]
    )
    assert qdrant.count("vaultrag_chunks", count_filter=filt_purged, exact=True).count == 0

    # Verify Qdrant points for kept doc are still intact
    filt_kept = models.Filter(
        must=[
            models.FieldCondition(key="tenant_id", match=models.MatchValue(value="tenant-a")),
            models.FieldCondition(key="doc_id", match=models.MatchValue(value="doc-keep-2")),
        ]
    )
    assert qdrant.count("vaultrag_chunks", count_filter=filt_kept, exact=True).count == 2

    # Verify S3 objects under uploads/tenant-a/doc-purge-1/ are empty
    s3 = mock_admin_env["s3"]
    resp_purged = s3.list_objects_v2(
        Bucket="vaultrag-docs-dev", Prefix=f"uploads/tenant-a/{doc_id}/"
    )
    assert resp_purged.get("KeyCount", 0) == 0

    # Kept document files still exist
    resp_kept = s3.list_objects_v2(
        Bucket="vaultrag-docs-dev", Prefix="uploads/tenant-a/doc-keep-2/"
    )
    assert resp_kept.get("KeyCount", 0) == 1


def test_tombstone_contains_no_filename(mock_admin_env: dict[str, Any]) -> None:
    """The DynamoDB record must be replaced with a tombstone containing NO filename or metadata."""
    ctx = _make_ctx(tenant_id="tenant-a", user_id="user-alice", role=Role.employee)
    doc_id = "doc-tombstone-test"
    _seed_document_and_assets(mock_admin_env, doc_id=doc_id, filename="payroll_secret.pdf")

    _ = erase_document(
        ctx,
        doc_id=doc_id,
        s3_client=mock_admin_env["s3"],
        qdrant_client=mock_admin_env["qdrant"],
        dynamodb_resource=mock_admin_env["dynamodb"],
    )

    docs_table = mock_admin_env["docs_table"]
    stored = docs_table.get_item(Key={"tenant_id": "tenant-a", "doc_id": doc_id}).get("Item")
    assert stored is not None
    assert stored["status"] == "DELETED"
    assert stored["deleted_by"] == "user-alice"
    assert "deleted_at" in stored
    assert stored["certificate_sha256"] != ""

    # Strictly assert no filename or document metadata remains
    assert "filename" not in stored
    assert "content_type" not in stored
    assert "size_bytes" not in stored
    assert "visibility" not in stored
    assert "allowed_roles" not in stored
    assert "allowed_users" not in stored
    assert "owner_user_id" not in stored
    assert "s3_key" not in stored
    assert "chunk_count" not in stored


def test_tampered_certificate_fails_verification(mock_admin_env: dict[str, Any]) -> None:
    """Any alteration to a certificate must fail signature verification."""
    ctx = _make_ctx()
    doc_id = "doc-tamper-check"
    _seed_document_and_assets(mock_admin_env, doc_id=doc_id)

    cert = erase_document(
        ctx,
        doc_id=doc_id,
        s3_client=mock_admin_env["s3"],
        qdrant_client=mock_admin_env["qdrant"],
        dynamodb_resource=mock_admin_env["dynamodb"],
    )

    # 1. Untampered certificate verifies
    res_valid = verify_certificate(cert, caller_tenant_id="tenant-a")
    assert res_valid["valid"] is True
    assert res_valid["reason"] is None

    # 2. Tampering vectors count fails
    tampered_vectors = dict(cert)
    tampered_vectors["deleted"] = dict(cert["deleted"])
    tampered_vectors["deleted"]["vectors"] = 9999
    res_vectors = verify_certificate(tampered_vectors, caller_tenant_id="tenant-a")
    assert res_vectors["valid"] is False
    assert "Signature mismatch" in res_vectors["reason"]

    # 3. Tampering signature directly fails
    tampered_sig = dict(cert)
    tampered_sig["signature"] = "f" * 64
    res_sig = verify_certificate(tampered_sig, caller_tenant_id="tenant-a")
    assert res_sig["valid"] is False
    assert "Signature mismatch" in res_sig["reason"]


def test_certificate_from_another_tenant_fails(mock_admin_env: dict[str, Any]) -> None:
    """A valid certificate presented by a different tenant must be rejected."""
    ctx_b = _make_ctx(tenant_id="tenant-b", user_id="user-bob")
    doc_id = "doc-tenant-b-1"
    _seed_document_and_assets(
        mock_admin_env, tenant_id="tenant-b", doc_id=doc_id, owner_user_id="user-bob"
    )

    cert_b = erase_document(
        ctx_b,
        doc_id=doc_id,
        s3_client=mock_admin_env["s3"],
        qdrant_client=mock_admin_env["qdrant"],
        dynamodb_resource=mock_admin_env["dynamodb"],
    )

    # Attempt verification by tenant-a caller
    res = verify_certificate(cert_b, caller_tenant_id="tenant-a")
    assert res["valid"] is False
    assert "Tenant mismatch" in res["reason"]


def test_non_owner_non_admin_gets_404(mock_admin_env: dict[str, Any]) -> None:
    """Non-owner non-admin caller receives 404 (preventing IDOR existence leak)."""
    doc_id = "doc-priv-123"
    _seed_document_and_assets(
        mock_admin_env,
        tenant_id="tenant-a",
        doc_id=doc_id,
        owner_user_id="user-alice",
    )

    other_user_ctx = _make_ctx(tenant_id="tenant-a", user_id="user-eve", role=Role.employee)

    with pytest.raises(HTTPException) as exc_info:
        erase_document(
            other_user_ctx,
            doc_id=doc_id,
            s3_client=mock_admin_env["s3"],
            qdrant_client=mock_admin_env["qdrant"],
            dynamodb_resource=mock_admin_env["dynamodb"],
        )
    assert exc_info.value.status_code == 404


def test_double_delete_returns_409(mock_admin_env: dict[str, Any]) -> None:
    """Second deletion attempt returns HTTP 409 with the stored certificate_sha256."""
    ctx = _make_ctx(tenant_id="tenant-a", user_id="user-alice", role=Role.employee)
    doc_id = "doc-double-del"
    _seed_document_and_assets(mock_admin_env, doc_id=doc_id)

    _ = erase_document(
        ctx,
        doc_id=doc_id,
        s3_client=mock_admin_env["s3"],
        qdrant_client=mock_admin_env["qdrant"],
        dynamodb_resource=mock_admin_env["dynamodb"],
    )

    with pytest.raises(HTTPException) as exc_info:
        erase_document(
            ctx,
            doc_id=doc_id,
            s3_client=mock_admin_env["s3"],
            qdrant_client=mock_admin_env["qdrant"],
            dynamodb_resource=mock_admin_env["dynamodb"],
        )

    assert exc_info.value.status_code == 409
    detail = exc_info.value.detail
    assert "Document already deleted" in detail["message"]
    assert detail["certificate_sha256"] != ""


def test_failure_in_s3_step_leaves_delete_failed_and_retry_completes(
    mock_admin_env: dict[str, Any],
) -> None:
    """If S3 deletion fails, status is saved as DELETE_FAILED; retrying completes successfully."""
    ctx = _make_ctx(tenant_id="tenant-a", user_id="user-alice")
    doc_id = "doc-fault-injection"
    _seed_document_and_assets(mock_admin_env, doc_id=doc_id)

    docs_table = mock_admin_env["docs_table"]
    mock_failing_s3 = MagicMock()
    mock_failing_s3.get_paginator.side_effect = RuntimeError("Simulated S3 connection loss")

    # 1. First attempt fails in S3 step
    with pytest.raises(HTTPException) as exc_info:
        erase_document(
            ctx,
            doc_id=doc_id,
            s3_client=mock_failing_s3,
            qdrant_client=mock_admin_env["qdrant"],
            dynamodb_resource=mock_admin_env["dynamodb"],
        )
    assert exc_info.value.status_code == 500

    # Verify status in DynamoDB is DELETE_FAILED
    doc_item = docs_table.get_item(Key={"tenant_id": "tenant-a", "doc_id": doc_id}).get("Item")
    assert doc_item["status"] == DocStatus.DELETE_FAILED.value

    # 2. Second attempt (retry) with working S3 completes successfully
    cert = erase_document(
        ctx,
        doc_id=doc_id,
        s3_client=mock_admin_env["s3"],
        qdrant_client=mock_admin_env["qdrant"],
        dynamodb_resource=mock_admin_env["dynamodb"],
    )
    assert cert["version"] == 1
    assert cert["doc_id"] == doc_id

    final_item = docs_table.get_item(Key={"tenant_id": "tenant-a", "doc_id": doc_id}).get("Item")
    assert final_item["status"] == DocStatus.DELETED.value


def test_user_level_erasure_endpoint(mock_admin_env: dict[str, Any]) -> None:
    """Admin can bulk erase all documents owned by a specified user."""
    clear_tenant_cache()
    app = create_app()

    # Seed 3 docs for user-alice and 2 docs for user-bob
    for i in range(3):
        _seed_document_and_assets(
            mock_admin_env, doc_id=f"doc-alice-{i}", owner_user_id="user-alice"
        )
    for j in range(2):
        _seed_document_and_assets(mock_admin_env, doc_id=f"doc-bob-{j}", owner_user_id="user-bob")

    admin_ctx = _make_ctx(tenant_id="tenant-a", user_id="admin-1", role=Role.admin)
    app.dependency_overrides[get_ctx] = lambda: admin_ctx
    client = TestClient(app)

    # 1. Non-confirmed request fails with 400
    res_bad = client.request("DELETE", "/admin/users/user-alice/documents", json={"confirm": False})
    assert res_bad.status_code == 400

    # 2. Non-admin caller receives 403
    employee_ctx = _make_ctx(tenant_id="tenant-a", user_id="emp-1", role=Role.employee)
    app.dependency_overrides[get_ctx] = lambda: employee_ctx
    res_forbidden = client.request(
        "DELETE", "/admin/users/user-alice/documents", json={"confirm": True}
    )
    assert res_forbidden.status_code == 403

    # 3. Valid admin request erases all 3 documents for user-alice
    app.dependency_overrides[get_ctx] = lambda: admin_ctx
    res_ok = client.request("DELETE", "/admin/users/user-alice/documents", json={"confirm": True})
    assert res_ok.status_code == 200
    certs = res_ok.json()
    assert isinstance(certs, list)
    assert len(certs) == 3

    # Verify Alice's docs are all tombstones
    docs_table = mock_admin_env["docs_table"]
    for i in range(3):
        item = docs_table.get_item(Key={"tenant_id": "tenant-a", "doc_id": f"doc-alice-{i}"}).get(
            "Item"
        )
        assert item["status"] == "DELETED"

    # Verify Bob's docs remain active
    for j in range(2):
        item_bob = docs_table.get_item(Key={"tenant_id": "tenant-a", "doc_id": f"doc-bob-{j}"}).get(
            "Item"
        )
        assert item_bob["status"] == DocStatus.READY.value


def test_audit_events_present_on_erasure(mock_admin_env: dict[str, Any]) -> None:
    """Erasure produces start and complete audit records in the cryptographic chain."""
    from vaultrag.audit.hashchain import verify_chain

    ctx = _make_ctx(tenant_id="tenant-a", user_id="user-alice", role=Role.employee)
    doc_id = "doc-audit-chain-check"
    _seed_document_and_assets(mock_admin_env, doc_id=doc_id)

    _ = erase_document(
        ctx,
        doc_id=doc_id,
        s3_client=mock_admin_env["s3"],
        qdrant_client=mock_admin_env["qdrant"],
        dynamodb_resource=mock_admin_env["dynamodb"],
    )

    # Verify audit chain integrity
    res = verify_chain("tenant-a", dynamodb_resource=mock_admin_env["dynamodb"])
    assert res["valid"] is True
    # At least start and complete events were appended
    assert res["checked"] >= 2

    # Query items to verify details
    audit_table = mock_admin_env["audit_table"]
    items = audit_table.query(
        KeyConditionExpression="tenant_id = :t",
        ExpressionAttributeValues={":t": "tenant-a"},
    )["Items"]

    erasure_events = [it for it in items if it.get("action") == "erasure"]
    assert len(erasure_events) == 2
    assert erasure_events[0]["details"]["status"] == "start"
    assert erasure_events[1]["details"]["status"] == "complete"
    assert "certificate_sha256" in erasure_events[1]["details"]


def test_cache_deletion_step(mock_admin_env: dict[str, Any]) -> None:
    """Test asserting semantic query cache invalidation during document erasure."""
    from vaultrag.admin.erasure import invalidate_doc_cache
    from vaultrag.rag.retrieve import RetrievedChunk
    from vaultrag.rag.semantic_cache import store

    ctx = _make_ctx(tenant_id="tenant-a", user_id="user-alice", role=Role.employee)
    doc_id = "doc-test"

    # Seed an entry into the semantic cache referencing doc_id
    q_vec = [0.1] * 768
    chunk = RetrievedChunk(
        chunk_id="chunk-1",
        doc_id=doc_id,
        filename="test.pdf",
        page=1,
        text="Sample text",
        score=0.9,
    )
    resp = {
        "answer": "Cached answer",
        "trust": {"score": 0.95, "abstained": False, "partial": False},
        "sources": [{"doc_id": doc_id}],
    }
    stored = store(
        ctx,
        question_vector=q_vec,
        response=resp,
        source_chunks=[chunk],
        kb_version=1,
        qdrant_client=mock_admin_env["qdrant"],
    )
    assert stored is True

    # Invalidate cache for the doc
    count = invalidate_doc_cache("tenant-a", doc_id, qdrant_client=mock_admin_env["qdrant"])
    assert count == 1
