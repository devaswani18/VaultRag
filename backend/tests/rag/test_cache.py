"""Unit and integration tests for semantic query cache layer."""

from __future__ import annotations

import time
from unittest.mock import MagicMock, patch

import pytest
from qdrant_client import QdrantClient

from vaultrag.context import RequestContext, Role
from vaultrag.rag.query_service import execute_query
from vaultrag.rag.retrieve import RetrievedChunk
from vaultrag.rag.semantic_cache import (
    compute_scope_key,
    delete_for_doc,
    lookup,
    store,
)


def _make_ctx(
    tenant_id: str = "tenant-test",
    user_id: str = "user-1",
    role: Role = Role.admin,
) -> RequestContext:
    return RequestContext(
        request_id="req-123",
        tenant_id=tenant_id,
        user_id=user_id,
        roles=frozenset([role]),
    )


@pytest.fixture
def memory_qdrant() -> QdrantClient:
    return QdrantClient(":memory:")


def test_scope_key_generation() -> None:
    """Scope key must be deterministic and include tenant and sorted roles."""
    ctx_admin = _make_ctx(role=Role.admin)
    ctx_intern = _make_ctx(role=Role.intern)

    key_admin = compute_scope_key(ctx_admin)
    key_intern = compute_scope_key(ctx_intern)

    assert key_admin != key_intern
    assert compute_scope_key(ctx_admin) == key_admin


def test_admin_scope_answer_not_served_to_intern(memory_qdrant: QdrantClient) -> None:
    """An answer stored under admin scope must never be served to an intern."""
    ctx_admin = _make_ctx(role=Role.admin)
    ctx_intern = _make_ctx(role=Role.intern)

    vec = [0.5] + [0.0] * 767
    chunk = RetrievedChunk(
        chunk_id="c1",
        doc_id="d1",
        filename="payroll.pdf",
        page=1,
        text="Executive salaries are high",
        score=0.92,
        visibility="tenant",
    )
    resp = {
        "answer": "Executive salaries are high",
        "trust": {"score": 0.95, "abstained": False, "partial": False},
        "sources": [{"doc_id": "d1"}],
    }

    stored = store(
        ctx_admin,
        question_vector=vec,
        response=resp,
        source_chunks=[chunk],
        kb_version=1,
        qdrant_client=memory_qdrant,
    )
    assert stored is True

    # Admin lookup hits
    hit_admin = lookup(
        ctx_admin,
        question_vector=vec,
        kb_version=1,
        qdrant_client=memory_qdrant,
    )
    assert hit_admin is not None
    assert hit_admin["cached"] is True
    assert hit_admin["answer"] == "Executive salaries are high"

    # Intern lookup misses due to scope_key isolation
    hit_intern = lookup(
        ctx_intern,
        question_vector=vec,
        kb_version=1,
        qdrant_client=memory_qdrant,
    )
    assert hit_intern is None


def test_private_or_allowed_users_chunk_never_stored(memory_qdrant: QdrantClient) -> None:
    """Responses synthesized from private or allowed_users chunks must never be cached."""
    ctx = _make_ctx()
    vec = [0.5] + [0.0] * 767
    resp = {
        "answer": "Private data",
        "trust": {"score": 0.95, "abstained": False, "partial": False},
        "sources": [{"doc_id": "d-priv"}],
    }

    # 1. Private visibility chunk
    private_chunk = RetrievedChunk(
        chunk_id="c-priv",
        doc_id="d-priv",
        filename="secret.pdf",
        page=1,
        text="Private data",
        score=0.9,
        visibility="private",
    )
    stored_priv = store(
        ctx,
        question_vector=vec,
        response=resp,
        source_chunks=[private_chunk],
        kb_version=1,
        qdrant_client=memory_qdrant,
    )
    assert stored_priv is False

    # 2. allowed_users restricted chunk
    user_restricted_chunk = RetrievedChunk(
        chunk_id="c-usr",
        doc_id="d-usr",
        filename="restricted.pdf",
        page=1,
        text="Restricted to alice",
        score=0.9,
        visibility="tenant",
        allowed_users=["user-alice"],
    )
    stored_user = store(
        ctx,
        question_vector=vec,
        response=resp,
        source_chunks=[user_restricted_chunk],
        kb_version=1,
        qdrant_client=memory_qdrant,
    )
    assert stored_user is False

    # 3. Quarantined chunk
    quarantined_chunk = RetrievedChunk(
        chunk_id="c-quar",
        doc_id="d-quar",
        filename="quar.pdf",
        page=1,
        text="Quarantined data",
        score=0.9,
        visibility="tenant",
    )
    quarantined_chunk.quarantined = True  # type: ignore[attr-defined]
    stored_quar = store(
        ctx,
        question_vector=vec,
        response=resp,
        source_chunks=[quarantined_chunk],
        kb_version=1,
        qdrant_client=memory_qdrant,
    )
    assert stored_quar is False

    # 4. Flagged injection risk chunk
    flagged_chunk = RetrievedChunk(
        chunk_id="c-flag",
        doc_id="d-flag",
        filename="flag.pdf",
        page=1,
        text="Injection risk chunk",
        score=0.9,
        visibility="tenant",
        injection_risk="high",
    )
    stored_flag = store(
        ctx,
        question_vector=vec,
        response=resp,
        source_chunks=[flagged_chunk],
        kb_version=1,
        qdrant_client=memory_qdrant,
    )
    assert stored_flag is False

    # Verify nothing was added
    assert lookup(ctx, question_vector=vec, kb_version=1, qdrant_client=memory_qdrant) is None


def test_kb_version_bump_invalidates_cache(memory_qdrant: QdrantClient) -> None:
    """Cache entry must become a miss when the tenant's kb_version increments."""
    ctx = _make_ctx()
    vec = [0.2] * 768
    chunk = RetrievedChunk(
        chunk_id="c1",
        doc_id="d1",
        filename="policy.pdf",
        page=1,
        text="Policy text",
        score=0.9,
    )
    resp = {
        "answer": "Policy answer",
        "trust": {"score": 0.9, "abstained": False, "partial": False},
        "sources": [{"doc_id": "d1"}],
    }

    store(
        ctx,
        question_vector=vec,
        response=resp,
        source_chunks=[chunk],
        kb_version=1,
        qdrant_client=memory_qdrant,
    )

    # Hits when kb_version is 1
    assert lookup(ctx, vec, kb_version=1, qdrant_client=memory_qdrant) is not None

    # Misses when kb_version is bumped to 2 (upload, deletion, or ACL mutation)
    assert lookup(ctx, vec, kb_version=2, qdrant_client=memory_qdrant) is None


def test_low_similarity_question_is_a_miss(memory_qdrant: QdrantClient) -> None:
    """Questions with cosine similarity below threshold must miss the cache."""
    ctx = _make_ctx()
    stored_vec = [1.0] + [0.0] * 767
    query_vec = [0.0] * 767 + [1.0]  # Orthogonal vector (cosine sim = 0)

    chunk = RetrievedChunk(
        chunk_id="c1",
        doc_id="d1",
        filename="doc.pdf",
        page=1,
        text="text",
        score=0.9,
    )
    resp = {
        "answer": "Sample answer",
        "trust": {"score": 0.9, "abstained": False, "partial": False},
    }

    store(ctx, stored_vec, resp, [chunk], kb_version=1, qdrant_client=memory_qdrant)

    hit = lookup(
        ctx,
        query_vec,
        kb_version=1,
        qdrant_client=memory_qdrant,
        similarity_threshold=0.95,
    )
    assert hit is None


def test_expired_entry_is_a_miss(
    memory_qdrant: QdrantClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Cache entry past its 24h TTL must be rejected as expired."""
    ctx = _make_ctx()
    vec = [0.3] * 768
    chunk = RetrievedChunk(
        chunk_id="c1",
        doc_id="d1",
        filename="doc.pdf",
        page=1,
        text="text",
        score=0.9,
    )
    resp = {
        "answer": "Timed answer",
        "trust": {"score": 0.9, "abstained": False, "partial": False},
    }

    store(ctx, vec, resp, [chunk], kb_version=1, qdrant_client=memory_qdrant)

    # Fast-forward time past TTL (25 hours later)
    now = time.time()
    monkeypatch.setattr(time, "time", lambda: now + 90000)

    assert lookup(ctx, vec, kb_version=1, qdrant_client=memory_qdrant) is None


def test_abstain_or_partial_not_stored(memory_qdrant: QdrantClient) -> None:
    """Abstained or partial answers must never be written to the cache."""
    ctx = _make_ctx()
    vec = [0.4] * 768
    chunk = RetrievedChunk(
        chunk_id="c1",
        doc_id="d1",
        filename="doc.pdf",
        page=1,
        text="text",
        score=0.5,
    )

    # Abstained response
    abstained_resp = {
        "answer": "I could not find this",
        "trust": {"score": 0.0, "abstained": True, "partial": False},
    }
    assert (
        store(ctx, vec, abstained_resp, [chunk], kb_version=1, qdrant_client=memory_qdrant) is False
    )

    # Partial response
    partial_resp = {
        "answer": "Some partial answer",
        "trust": {"score": 0.5, "abstained": False, "partial": True},
    }
    assert (
        store(ctx, vec, partial_resp, [chunk], kb_version=1, qdrant_client=memory_qdrant) is False
    )


def test_delete_for_doc_removes_entries(memory_qdrant: QdrantClient) -> None:
    """Verifiable erasure helper delete_for_doc must remove all entries referencing the doc."""
    ctx = _make_ctx()
    vec = [0.1] * 768
    doc_id = "doc-to-erase"
    chunk = RetrievedChunk(
        chunk_id="c1",
        doc_id=doc_id,
        filename="secret.pdf",
        page=1,
        text="Confidential",
        score=0.9,
    )
    resp = {
        "answer": "Confidential answer",
        "trust": {"score": 0.9, "abstained": False, "partial": False},
        "sources": [{"doc_id": doc_id}],
    }

    store(ctx, vec, resp, [chunk], kb_version=1, qdrant_client=memory_qdrant)
    assert lookup(ctx, vec, kb_version=1, qdrant_client=memory_qdrant) is not None

    deleted_count = delete_for_doc("tenant-test", doc_id, qdrant_client=memory_qdrant)
    assert deleted_count == 1

    # Now a miss
    assert lookup(ctx, vec, kb_version=1, qdrant_client=memory_qdrant) is None


def test_cache_disabled_by_tenant_setting() -> None:
    """When cache_enabled is False in tenant settings, cache lookup and store are bypassed."""
    ctx = _make_ctx()
    mock_tenant_repo = MagicMock()
    mock_tenant_repo.get.return_value = {
        "tenant_id": ctx.tenant_id,
        "kb_version": 1,
        "settings": {"cache_enabled": False, "min_retrieval_score": 0.1},
    }

    mock_retrieve = MagicMock()
    mock_retrieve.return_value = []

    with (
        patch("vaultrag.rag.query_service.cache_lookup") as mock_lookup,
        patch("vaultrag.rag.query_service.reserve_query"),
        patch("vaultrag.rag.query_service.append_event"),
        patch("vaultrag.rag.query_service.increment"),
    ):
        execute_query(
            ctx,
            "What is our policy?",
            retrieve_fn=mock_retrieve,
            tenant_repo_cls=lambda: mock_tenant_repo,
        )
        mock_lookup.assert_not_called()
