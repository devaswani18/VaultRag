"""Tests for knowledge gaps tracking and deterministic Jaccard clustering."""

from __future__ import annotations

import time
from typing import Any

import boto3
import pytest
from fastapi.testclient import TestClient
from moto import mock_aws

from vaultrag.admin.gaps import cluster_gaps, extract_content_tokens, record_knowledge_gap
from vaultrag.api.app import create_app
from vaultrag.auth.dependencies import get_ctx
from vaultrag.context import RequestContext, Role


def _make_ctx(
    tenant_id: str = "tenant-gap",
    user_id: str = "user-1",
    role: Role = Role.admin,
) -> RequestContext:
    return RequestContext(
        request_id="req-gap-1",
        tenant_id=tenant_id,
        user_id=user_id,
        roles=frozenset([role]),
    )


@pytest.fixture
def mock_gaps_dynamo() -> Any:
    with mock_aws():
        dynamodb = boto3.resource("dynamodb", region_name="ap-south-1")
        table = dynamodb.create_table(
            TableName="vaultrag-dev-gaps",
            KeySchema=[
                {"AttributeName": "tenant_id", "KeyType": "HASH"},
                {"AttributeName": "ts_id", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "tenant_id", "AttributeType": "S"},
                {"AttributeName": "ts_id", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )
        yield {"resource": dynamodb, "table": table}


def test_record_knowledge_gap_redacted_preview_and_ttl(mock_gaps_dynamo: Any) -> None:
    """Recorded gap item must contain only redacted preview, content tokens, and 90d TTL."""
    ctx = _make_ctx()
    resource = mock_gaps_dynamo["resource"]
    table = mock_gaps_dynamo["table"]

    # Redacted preview (e.g. Aadhaar masked to [REDACTED])
    redacted_q = "My ID is [REDACTED] and how do I file medical reimbursement claim?"
    top_score = 0.25
    reason = "below_min_retrieval_score"

    item = record_knowledge_gap(
        ctx,
        redacted_question=redacted_q,
        top_score=top_score,
        reason=reason,
        dynamodb_resource=resource,
    )
    assert item is not None
    assert item["tenant_id"] == "tenant-gap"
    assert "ts_id" in item
    assert "[REDACTED]" in item["question_preview"]
    assert "reimbursement" in item["tokens"]
    assert "claim" in item["tokens"]
    # Check max 12 tokens
    assert len(item["tokens"]) <= 12
    # Check TTL is ~90 days in the future
    now = int(time.time())
    assert item["expires_at"] >= now + 89 * 86400

    # Verify item stored in DynamoDB
    stored = table.get_item(Key={"tenant_id": ctx.tenant_id, "ts_id": item["ts_id"]})["Item"]
    assert stored["question_preview"] == redacted_q[:120]
    assert stored["reason"] == reason


def test_token_extraction_filters_stopwords_and_digits() -> None:
    """Content tokens must exclude stopwords, single chars, numbers, and take max 12."""
    text = "What is the policy for 2024 regarding international travel expenses and flight booking?"
    tokens = extract_content_tokens(text, max_tokens=12)

    assert "policy" in tokens
    assert "travel" in tokens
    assert "expenses" in tokens
    assert "flight" in tokens
    assert "booking" in tokens
    assert "what" not in tokens
    assert "is" not in tokens
    assert "the" not in tokens
    assert "2024" not in tokens
    assert len(tokens) <= 12


def test_jaccard_clustering_groups_paraphrases() -> None:
    """Clustering must group paraphrased questions with Jaccard similarity >= 0.6."""
    items = [
        {
            "ts_id": "2026-10-01T10:00:00Z#aaa",
            "question_preview": "How do I claim dental expense refund?",
            "tokens": ["claim", "dental", "expense", "refund"],
            "reason": "no_retrieval_results",
        },
        {
            "ts_id": "2026-10-01T11:00:00Z#bbb",
            "question_preview": "Dental refund claim process",
            "tokens": ["claim", "dental", "process", "refund"],
            "reason": "below_min_retrieval_score",
        },
        {
            "ts_id": "2026-10-01T12:00:00Z#ccc",
            "question_preview": "What is the wifi password for guest lounge?",
            "tokens": ["guest", "lounge", "password", "wifi"],
            "reason": "no_retrieval_results",
        },
    ]

    clusters = cluster_gaps(items, threshold=0.6)

    # Should form 2 clusters: dental (2 questions) and wifi (1 question)
    assert len(clusters) == 2

    top_cluster = clusters[0]
    assert top_cluster["count"] == 2
    assert "dental" in top_cluster["representative_preview"].lower()
    assert sorted(top_cluster["reasons"]) == ["below_min_retrieval_score", "no_retrieval_results"]
    assert top_cluster["first_seen"] == "2026-10-01T10:00:00Z"
    assert top_cluster["last_seen"] == "2026-10-01T11:00:00Z"

    second_cluster = clusters[1]
    assert second_cluster["count"] == 1
    assert "wifi" in second_cluster["representative_preview"].lower()


def test_admin_only_access_to_gaps_endpoint(mock_gaps_dynamo: Any) -> None:
    """Non-admin callers must receive HTTP 403 when requesting knowledge gaps."""
    app = create_app()
    client = TestClient(app, raise_server_exceptions=False)

    # Non-admin context
    employee_ctx = _make_ctx(role=Role.employee)
    app.dependency_overrides[get_ctx] = lambda: employee_ctx

    res_forbidden = client.get("/admin/gaps")
    assert res_forbidden.status_code == 403

    # Admin context
    admin_ctx = _make_ctx(role=Role.admin)
    app.dependency_overrides[get_ctx] = lambda: admin_ctx

    res_ok = client.get("/admin/gaps?days=30")
    assert res_ok.status_code == 200
    assert isinstance(res_ok.json(), list)

    app.dependency_overrides.clear()
