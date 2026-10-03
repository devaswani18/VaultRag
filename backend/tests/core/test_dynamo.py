from __future__ import annotations

import boto3
import pytest
from moto import mock_aws

from vaultrag.clients.dynamo import DocStatus, DocumentRepo, TenantRepo
from vaultrag.errors import Conflict, NotFound, ValidationFailed


@pytest.fixture
def aws_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AWS_REGION", "ap-south-1")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "ap-south-1")
    monkeypatch.setenv("TENANTS_TABLE", "vaultrag-dev-tenants")
    monkeypatch.setenv("DOCUMENTS_TABLE", "vaultrag-dev-documents")


@pytest.fixture
def mock_dynamodb_tables(aws_env: None):
    with mock_aws():
        dynamodb = boto3.resource("dynamodb", region_name="ap-south-1")

        # Create tenants table (PK: tenant_id)
        tenants_table = dynamodb.create_table(
            TableName="vaultrag-dev-tenants",
            KeySchema=[{"AttributeName": "tenant_id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "tenant_id", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )

        # Create documents table (PK: tenant_id, SK: doc_id)
        documents_table = dynamodb.create_table(
            TableName="vaultrag-dev-documents",
            KeySchema=[
                {"AttributeName": "tenant_id", "KeyType": "HASH"},
                {"AttributeName": "doc_id", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "tenant_id", "AttributeType": "S"},
                {"AttributeName": "doc_id", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )

        yield {"tenants": tenants_table, "documents": documents_table, "resource": dynamodb}


def test_tenant_repo_put_get_and_defaults(mock_dynamodb_tables: dict) -> None:
    repo = TenantRepo(dynamodb_resource=mock_dynamodb_tables["resource"])

    # Missing tenant raises NotFound
    with pytest.raises(NotFound):
        repo.get("tenant-nonexistent")

    # Put tenant with partial custom settings
    created = repo.put(
        tenant_id="tenant-alpha",
        name="Alpha Corp",
        settings={"daily_query_quota": 500},
    )
    assert created["tenant_id"] == "tenant-alpha"
    assert created["settings"]["daily_query_quota"] == 500
    assert created["settings"]["pii_mode"] == "redact"  # Default merged

    # Get tenant and verify defaults
    fetched = repo.get("tenant-alpha")
    assert fetched["name"] == "Alpha Corp"
    assert fetched["settings"]["min_retrieval_score"] == 0.35
    assert fetched["settings"]["min_faithfulness"] == 0.6
    assert fetched["settings"]["cache_enabled"] is True

    # Reserved 'st-' prefix is rejected
    with pytest.raises(ValidationFailed, match="reserved for system assurance"):
        repo.put(tenant_id="st-forbidden-test", name="Forbidden Synthetic Tenant")


def test_document_repo_crud_and_duplicate_conflict(mock_dynamodb_tables: dict) -> None:
    repo = DocumentRepo(dynamodb_resource=mock_dynamodb_tables["resource"])

    # Create document
    doc = repo.create(
        tenant_id="tenant-alpha",
        doc_id="doc-001",
        filename="contract.pdf",
        content_type="application/pdf",
        size_bytes=1024,
    )
    assert doc["tenant_id"] == "tenant-alpha"
    assert doc["doc_id"] == "doc-001"
    assert doc["status"] == DocStatus.PENDING_UPLOAD.value

    # Duplicate create must fail with Conflict
    with pytest.raises(Conflict):
        repo.create(
            tenant_id="tenant-alpha",
            doc_id="doc-001",
            filename="contract.pdf",
            content_type="application/pdf",
            size_bytes=1024,
        )

    # Get created document
    fetched = repo.get("tenant-alpha", "doc-001")
    assert fetched["filename"] == "contract.pdf"
    assert fetched["size_bytes"] == 1024

    # Missing document raises NotFound
    with pytest.raises(NotFound):
        repo.get("tenant-alpha", "doc-missing")


def test_document_repo_tenant_isolation(mock_dynamodb_tables: dict) -> None:
    repo = DocumentRepo(dynamodb_resource=mock_dynamodb_tables["resource"])

    # Create documents under tenant A and tenant B
    repo.create("tenant-aaa", "doc-1", "doc_a1.txt", "text/plain")
    repo.create("tenant-aaa", "doc-2", "doc_a2.txt", "text/plain")
    repo.create("tenant-bbb", "doc-1", "doc_b1.txt", "text/plain")

    # Tenant A list query isolation
    items_a, _ = repo.list_for_tenant("tenant-aaa")
    doc_ids_a = {item["doc_id"] for item in items_a}
    assert doc_ids_a == {"doc-1", "doc-2"}

    # Tenant B list query isolation
    items_b, _ = repo.list_for_tenant("tenant-bbb")
    doc_ids_b = {item["doc_id"] for item in items_b}
    assert doc_ids_b == {"doc-1"}

    # Cross-tenant get isolation: doc-2 exists under tenant-aaa,
    # but asking under tenant-bbb must raise NotFound
    with pytest.raises(NotFound):
        repo.get("tenant-bbb", "doc-2")


def test_document_repo_status_transitions(mock_dynamodb_tables: dict) -> None:
    repo = DocumentRepo(dynamodb_resource=mock_dynamodb_tables["resource"])

    repo.create("tenant-test", "doc-flow", "paper.pdf", "application/pdf")

    # Invalid jump: PENDING_UPLOAD -> READY (must go through PROCESSING)
    with pytest.raises(ValidationFailed) as exc_jump:
        repo.update_status("tenant-test", "doc-flow", DocStatus.READY)
    assert "Invalid status transition" in str(exc_jump.value)

    # Valid: PENDING_UPLOAD -> PROCESSING
    p1 = repo.update_status("tenant-test", "doc-flow", DocStatus.PROCESSING)
    assert p1["status"] == DocStatus.PROCESSING.value

    # Valid: PROCESSING -> READY
    p2 = repo.update_status("tenant-test", "doc-flow", DocStatus.READY)
    assert p2["status"] == DocStatus.READY.value

    # Valid: READY -> DELETED
    p3 = repo.update_status("tenant-test", "doc-flow", DocStatus.DELETED)
    assert p3["status"] == DocStatus.DELETED.value

    # Terminal: DELETED cannot transition to any status
    with pytest.raises(ValidationFailed):
        repo.update_status("tenant-test", "doc-flow", DocStatus.PROCESSING)


def test_document_repo_update_fields_and_delete(mock_dynamodb_tables: dict) -> None:
    repo = DocumentRepo(dynamodb_resource=mock_dynamodb_tables["resource"])

    repo.create("tenant-edit", "doc-x", "sample.txt", "text/plain")

    # Update fields
    updated = repo.update_fields("tenant-edit", "doc-x", {"chunk_count": 12, "visibility": "team"})
    assert updated["chunk_count"] == 12
    assert updated["visibility"] == "team"

    # Delete existing
    repo.delete("tenant-edit", "doc-x")

    # Confirm it is gone
    with pytest.raises(NotFound):
        repo.get("tenant-edit", "doc-x")

    # Delete non-existent raises NotFound
    with pytest.raises(NotFound):
        repo.delete("tenant-edit", "doc-x")
