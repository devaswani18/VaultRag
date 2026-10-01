"""Tests for vaultrag.rag.retrieve — verifies ACL filter is always passed."""

from __future__ import annotations

import uuid
from unittest.mock import MagicMock, patch

import pytest
from qdrant_client import models

from vaultrag.context import RequestContext, Role
from vaultrag.rag.retrieve import RetrievedChunk, retrieve


def _make_ctx(tenant_id: str = "acme") -> RequestContext:
    return RequestContext(
        tenant_id=tenant_id,
        user_id="usr-test",
        roles=frozenset([Role.admin]),
        request_id="req-test-001",
    )


def _fake_scored_point(chunk_id: str, doc_id: str, text: str) -> models.ScoredPoint:
    return models.ScoredPoint(
        id=chunk_id,
        version=0,
        score=0.85,
        payload={
            "chunk_id": chunk_id,
            "doc_id": doc_id,
            "filename": "test.txt",
            "page": 1,
            "text": text,
            "tenant_id": "acme",
        },
        vector=None,
    )


@pytest.fixture(autouse=True)
def _mock_embed():
    """Return a deterministic fake embedding vector."""
    with patch("vaultrag.rag.retrieve.gemini_client.embed_texts") as m:
        m.return_value = [[0.1] * 768]
        yield m


@pytest.fixture(autouse=True)
def _mock_qdrant():
    """Return two fake scored points."""
    with patch("vaultrag.rag.retrieve.qdrant_client.search") as m:
        cid1 = str(uuid.uuid5(uuid.NAMESPACE_DNS, "chunk-1"))
        cid2 = str(uuid.uuid5(uuid.NAMESPACE_DNS, "chunk-2"))
        m.return_value = [
            _fake_scored_point(cid1, "doc-1", "Some relevant text about leaves"),
            _fake_scored_point(cid2, "doc-2", "More context about policy"),
        ]
        yield m


# Parametrised across tenants — filter ALWAYS contains the caller's tenant_id
@pytest.mark.parametrize("tenant_id", ["acme", "globex", "initech"])
def test_retrieve_filter_contains_caller_tenant(
    tenant_id: str, _mock_qdrant: MagicMock, _mock_embed: MagicMock
) -> None:
    # Override the qdrant mock per-tenant (autouse fixture already patches it)
    ctx = _make_ctx(tenant_id)
    retrieve(ctx, "What is the leave policy?", top_k=5)

    _mock_qdrant.assert_called_once()
    call_kwargs = _mock_qdrant.call_args.kwargs
    query_filter = call_kwargs.get("query_filter")

    assert query_filter is not None, "qdrant.search must be called with a query_filter"

    # The filter must contain a tenant_id condition matching the caller's tenant
    from vaultrag.clients.qdrant import _has_tenant_condition  # noqa: PLC0415

    assert _has_tenant_condition(query_filter), "ACL filter must contain tenant_id condition"

    # Verify the actual tenant value
    tenant_conds = [
        c
        for c in (query_filter.must or [])
        if isinstance(c, models.FieldCondition) and c.key == "tenant_id"
    ]
    assert len(tenant_conds) == 1
    assert tenant_conds[0].match.value == tenant_id  # type: ignore[union-attr]


def test_retrieve_returns_chunk_list(_mock_qdrant: MagicMock, _mock_embed: MagicMock) -> None:
    ctx = _make_ctx("acme")
    chunks = retrieve(ctx, "Leave policy?", top_k=2)
    assert len(chunks) == 2
    assert all(isinstance(c, RetrievedChunk) for c in chunks)
    assert chunks[0].score == pytest.approx(0.85)
    assert chunks[0].text == "Some relevant text about leaves"


def test_retrieve_empty_when_no_results(_mock_embed: MagicMock) -> None:
    ctx = _make_ctx("acme")
    with patch("vaultrag.rag.retrieve.qdrant_client.search", return_value=[]):
        chunks = retrieve(ctx, "An obscure question", top_k=5)
    assert chunks == []


def test_retrieve_calls_embed_with_query_task_type(
    _mock_embed: MagicMock, _mock_qdrant: MagicMock
) -> None:
    ctx = _make_ctx("acme")
    retrieve(ctx, "My question", top_k=3)
    _mock_embed.assert_called_once_with(["My question"], task_type="RETRIEVAL_QUERY")
