from __future__ import annotations

import threading
from collections.abc import Generator
from typing import Any

import boto3
import pytest
from moto import mock_aws
from qdrant_client import QdrantClient, models

from vaultrag.clients.qdrant import set_client

_moto_admin_lock = threading.Lock()


def _wrap_table_threadsafe(table: Any) -> Any:
    for m_name in ("put_item", "update_item", "get_item", "delete_item", "query", "scan"):
        if hasattr(table, m_name):
            orig_m = getattr(table, m_name)

            def _make_wrapped(m: Any) -> Any:
                def _locked(*args: Any, **kwargs: Any) -> Any:
                    with _moto_admin_lock:
                        return m(*args, **kwargs)

                return _locked

            setattr(table, m_name, _make_wrapped(orig_m))
    return table


@pytest.fixture
def aws_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AWS_REGION", "ap-south-1")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "ap-south-1")
    monkeypatch.setenv("AUDIT_TABLE", "vaultrag-dev-audit")
    monkeypatch.setenv("USAGE_TABLE", "vaultrag-dev-usage")
    monkeypatch.setenv("TENANTS_TABLE", "vaultrag-dev-tenants")
    monkeypatch.setenv("DOCUMENTS_TABLE", "vaultrag-dev-documents")
    monkeypatch.setenv("DOCS_BUCKET", "vaultrag-docs-dev")
    monkeypatch.setenv("LOCAL_MODE", "true")
    monkeypatch.setenv("VAULTRAG_SECRET_CERT_HMAC_SECRET", "test-secret-cert-hmac-key-12345")
    monkeypatch.setenv("VAULTRAG_SECRET_GEMINI_API_KEY", "test-fake-gemini-api-key")


@pytest.fixture
def mock_admin_env(aws_env: None) -> Generator[dict[str, Any], None, None]:
    with mock_aws():
        dynamodb = boto3.resource("dynamodb", region_name="ap-south-1")
        orig_Table = dynamodb.Table

        def _locked_Table(name: str) -> Any:
            tbl = orig_Table(name)
            return _wrap_table_threadsafe(tbl)

        dynamodb.Table = _locked_Table
        s3 = boto3.client("s3", region_name="ap-south-1")

        # 1. Audit table
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

        # 2. Documents table
        docs_table = dynamodb.create_table(
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

        # 3. Tenants table
        tenants_table = dynamodb.create_table(
            TableName="vaultrag-dev-tenants",
            KeySchema=[{"AttributeName": "tenant_id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "tenant_id", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )
        tenants_table.put_item(
            Item={
                "tenant_id": "tenant-a",
                "name": "Tenant Alpha",
                "status": "active",
                "kb_version": 1,
            }
        )
        tenants_table.put_item(
            Item={
                "tenant_id": "tenant-b",
                "name": "Tenant Beta",
                "status": "active",
                "kb_version": 1,
            }
        )

        # 4. S3 Bucket
        s3.create_bucket(
            Bucket="vaultrag-docs-dev",
            CreateBucketConfiguration={"LocationConstraint": "ap-south-1"},
        )

        # 5. In-memory Qdrant
        qdrant = QdrantClient(":memory:")
        qdrant.create_collection(
            collection_name="vaultrag_chunks",
            vectors_config=models.VectorParams(size=4, distance=models.Distance.COSINE),
        )
        set_client(qdrant)

        yield {
            "dynamodb": dynamodb,
            "s3": s3,
            "qdrant": qdrant,
            "audit_table": audit_table,
            "docs_table": docs_table,
            "tenants_table": tenants_table,
        }

        set_client(None)
