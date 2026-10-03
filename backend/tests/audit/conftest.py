import threading
from collections.abc import Generator
from typing import Any

import boto3
import pytest
from moto import mock_aws

_moto_dynamo_lock = threading.Lock()


def _wrap_table_threadsafe(table: Any) -> Any:
    """Wrap boto3 Table methods with a threading lock to prevent moto concurrency races."""
    for m_name in ("put_item", "update_item", "get_item", "delete_item", "query", "scan"):
        if hasattr(table, m_name):
            orig_m = getattr(table, m_name)

            def _make_wrapped(m: Any) -> Any:
                def _locked(*args: Any, **kwargs: Any) -> Any:
                    with _moto_dynamo_lock:
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
    monkeypatch.setenv("LOCAL_MODE", "true")
    monkeypatch.setenv("VAULTRAG_SECRET_CERT_HMAC_SECRET", "test-secret-cert-hmac-key-12345")
    monkeypatch.setenv("VAULTRAG_SECRET_GEMINI_API_KEY", "test-fake-gemini-api-key")


@pytest.fixture
def mock_audit_dynamo(aws_env: None) -> Generator[dict[str, Any], None, None]:
    with mock_aws():
        dynamodb = boto3.resource("dynamodb", region_name="ap-south-1")
        orig_Table = dynamodb.Table

        def _locked_Table(name: str) -> Any:
            tbl = orig_Table(name)
            return _wrap_table_threadsafe(tbl)

        dynamodb.Table = _locked_Table

        # 1. Audit table (PK: tenant_id S, SK: seq N)
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

        # 2. Usage table (PK: tenant_id S, SK: day S)
        usage_table = dynamodb.create_table(
            TableName="vaultrag-dev-usage",
            KeySchema=[
                {"AttributeName": "tenant_id", "KeyType": "HASH"},
                {"AttributeName": "day", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "tenant_id", "AttributeType": "S"},
                {"AttributeName": "day", "AttributeType": "S"},
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

        # 4. Documents table
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

        # Seed default active tenant
        from vaultrag.clients.dynamo import _floats_to_decimals

        tenants_table.put_item(
            Item=_floats_to_decimals(
                {
                    "tenant_id": "acme",
                    "name": "Acme Corp",
                    "status": "ACTIVE",
                    "settings": {
                        "daily_query_quota": 200,
                        "min_faithfulness": 0.6,
                        "min_retrieval_score": 0.35,
                        "pii_mode": "redact",
                    },
                }
            )
        )

        # 5. Conversations table
        conversations_table = dynamodb.create_table(
            TableName="vaultrag-dev-conversations",
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )

        audit_table = _wrap_table_threadsafe(audit_table)
        usage_table = _wrap_table_threadsafe(usage_table)
        tenants_table = _wrap_table_threadsafe(tenants_table)
        documents_table = _wrap_table_threadsafe(documents_table)
        conversations_table = _wrap_table_threadsafe(conversations_table)

        yield {
            "resource": dynamodb,
            "audit": audit_table,
            "usage": usage_table,
            "tenants": tenants_table,
            "documents": documents_table,
            "conversations": conversations_table,
        }
