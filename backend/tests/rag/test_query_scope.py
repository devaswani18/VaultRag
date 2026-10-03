"""Comprehensive tests for document-scoped query execution:
- Scope restricts sources to chosen documents
- Scope never reveals forbidden documents (indistinguishable from nonexistent)
- Mixed scope returns only allowed documents
- Scoped queries bypass semantic cache lookup and cache store
- Scoped abstain does not record knowledge gaps
- More than 20 doc IDs returns 422
- Malformed doc ID returns 422
- Cross-tenant document scope returns nothing
- Empty list treated as None (unscoped)
- Duplicate doc IDs are deduplicated
"""

from __future__ import annotations

import uuid
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from qdrant_client import QdrantClient, models

from vaultrag.api.app import create_app
from vaultrag.auth.dependencies import clear_tenant_cache
from vaultrag.auth.jwt_verifier import Claims
from vaultrag.clients.qdrant import set_client
from vaultrag.context import Role
from vaultrag.rag.generate import AnswerResult

COLLECTION_NAME = "vaultrag_chunks"
CACHE_COLLECTION_NAME = "vaultrag_cache"
VECTOR_DIM = 768


@pytest.fixture(autouse=True)
def reset_cache() -> None:
    clear_tenant_cache()
    yield
    clear_tenant_cache()


@pytest.fixture
def memory_qdrant() -> QdrantClient:
    client = QdrantClient(":memory:")
    client.create_collection(
        collection_name=COLLECTION_NAME,
        vectors_config=models.VectorParams(
            size=VECTOR_DIM,
            distance=models.Distance.COSINE,
        ),
    )
    set_client(client)
    yield client
    set_client(None)


@pytest.fixture
def client() -> TestClient:
    app = create_app()
    return TestClient(app, raise_server_exceptions=False)


def _mock_claims(
    sub: str = "usr-test-1",
    tenant_id: str = "tenant-a",
    roles: frozenset[Role] | None = None,
) -> Claims:
    return Claims(
        sub=sub,
        email=f"{sub}@{tenant_id}.com",
        tenant_id=tenant_id,
        roles=roles if roles is not None else frozenset([Role.employee]),
        token_use="id",
        raw_claims={
            "exp": 1800000000,
            "iat": 1700000000,
            "iss": "https://cognito-idp.ap-south-1.amazonaws.com/test",
            "aud": "test-client-id",
        },
    )


def _seed_chunk(
    client: QdrantClient,
    chunk_id: str,
    tenant_id: str,
    doc_id: str,
    visibility: str = "tenant",
    allowed_roles: list[str] | None = None,
    allowed_users: list[str] | None = None,
    filename: str = "doc.txt",
    text: str = "test chunk text",
    vector: list[float] | None = None,
) -> None:
    point = models.PointStruct(
        id=str(uuid.uuid5(uuid.NAMESPACE_DNS, chunk_id)),
        vector=vector or [0.1] * VECTOR_DIM,
        payload={
            "chunk_id": chunk_id,
            "tenant_id": tenant_id,
            "doc_id": doc_id,
            "filename": filename,
            "text": text,
            "visibility": visibility,
            "allowed_roles": allowed_roles or [],
            "allowed_users": allowed_users or [],
            "owner_user_id": "owner-1",
            "page": 1,
            "injection_risk": "low",
        },
    )
    client.upsert(collection_name=COLLECTION_NAME, points=[point])


def _auth_patches(
    mock_verify: MagicMock,
    mock_tenant_cls: MagicMock,
    tenant_id: str = "tenant-a",
    roles: frozenset[Role] | None = None,
    sub: str = "usr-test-1",
) -> None:
    mock_verify.return_value = _mock_claims(sub=sub, tenant_id=tenant_id, roles=roles)
    repo = MagicMock()
    repo.get.return_value = {
        "tenant_id": tenant_id,
        "status": "ACTIVE",
        "settings": {
            "min_retrieval_score": 0.0,
            "min_faithfulness": 0.5,
            "daily_query_quota": 500,
            "cache_enabled": True,
            "pii_mode": "off",
        },
    }
    mock_tenant_cls.return_value = repo


# ── 1. Scope restricts sources to chosen docs ─────────────────────────────────
@patch("vaultrag.rag.query_service.gemini_client.embed_texts")
@patch("vaultrag.api.routers.query.generate_answer")
@patch("vaultrag.auth.dependencies.TenantRepo")
@patch("vaultrag.auth.dependencies.verify_id_token")
def test_scope_restricts_sources_to_chosen_docs(
    mock_verify: MagicMock,
    mock_tenant_cls: MagicMock,
    mock_gen: MagicMock,
    mock_embed: MagicMock,
    client: TestClient,
    memory_qdrant: QdrantClient,
) -> None:
    _auth_patches(mock_verify, mock_tenant_cls, tenant_id="tenant-a")
    mock_embed.return_value = [[0.1] * VECTOR_DIM]
    mock_gen.return_value = AnswerResult(
        answer="First doc content text",
        citations=["chunk-1"],
        canary="canary-1",
        segments=[{"text": "First doc content text", "citations": ["chunk-1"]}],
    )

    _seed_chunk(
        memory_qdrant,
        "chunk-1",
        "tenant-a",
        "doc-1",
        filename="file1.txt",
        text="First doc content text",
    )
    _seed_chunk(
        memory_qdrant,
        "chunk-2",
        "tenant-a",
        "doc-2",
        filename="file2.txt",
        text="Second doc content text",
    )

    resp = client.post(
        "/query",
        json={"question": "What is in doc 1?", "doc_ids": ["doc-1"]},
        headers={"Authorization": "Bearer tok"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["scope"] == {"scoped": True, "n_docs": 1}
    source_docs = {s["doc_id"] for s in data["sources"]}
    assert source_docs == {"doc-1"}
    assert "doc-2" not in source_docs


# ── 2. Scope never reveals forbidden docs (identical response shape and message) ─
@patch("vaultrag.rag.query_service.gemini_client.embed_texts")
@patch("vaultrag.auth.dependencies.TenantRepo")
@patch("vaultrag.auth.dependencies.verify_id_token")
def test_scope_never_reveals_forbidden_docs_identical_to_nonexistent(
    mock_verify: MagicMock,
    mock_tenant_cls: MagicMock,
    mock_embed: MagicMock,
    client: TestClient,
    memory_qdrant: QdrantClient,
) -> None:
    # Caller is an intern
    _auth_patches(
        mock_verify,
        mock_tenant_cls,
        tenant_id="tenant-a",
        roles=frozenset([Role.intern]),
        sub="usr-intern",
    )
    mock_embed.return_value = [[0.1] * VECTOR_DIM]

    # Seed manager-only document
    _seed_chunk(
        memory_qdrant,
        "chunk-mgr",
        "tenant-a",
        "doc-mgr-secret",
        visibility="roles",
        allowed_roles=["manager"],
        text="Executive salaries",
    )

    # 1) Query forbidden doc_id
    resp_forbidden = client.post(
        "/query",
        json={"question": "What are executive salaries?", "doc_ids": ["doc-mgr-secret"]},
        headers={"Authorization": "Bearer tok"},
    )
    assert resp_forbidden.status_code == 200
    data_forbidden = resp_forbidden.json()

    # 2) Query completely nonexistent doc_id
    resp_nonexistent = client.post(
        "/query",
        json={"question": "What are executive salaries?", "doc_ids": ["doc-does-not-exist-xyz"]},
        headers={"Authorization": "Bearer tok"},
    )
    assert resp_nonexistent.status_code == 200
    data_nonexistent = resp_nonexistent.json()

    # Compare response body shape, abstain message, trust structure, and scope
    assert data_forbidden["answer"] == data_nonexistent["answer"]
    assert data_forbidden["answer"] == "I could not find this in the documents you can access."
    assert data_forbidden["trust"]["abstained"] is True
    assert data_nonexistent["trust"]["abstained"] is True
    assert data_forbidden["sources"] == data_nonexistent["sources"] == []
    assert data_forbidden["scope"] == data_nonexistent["scope"] == {"scoped": True, "n_docs": 1}
    # Shapes (keys) match exactly
    assert set(data_forbidden.keys()) == set(data_nonexistent.keys())
    assert set(data_forbidden["trust"].keys()) == set(data_nonexistent["trust"].keys())


# ── 3. Mixed scope: one allowed, one forbidden -> returns only allowed doc ────
@patch("vaultrag.rag.query_service.gemini_client.embed_texts")
@patch("vaultrag.api.routers.query.generate_answer")
@patch("vaultrag.auth.dependencies.TenantRepo")
@patch("vaultrag.auth.dependencies.verify_id_token")
def test_mixed_scope_returns_only_allowed_doc(
    mock_verify: MagicMock,
    mock_tenant_cls: MagicMock,
    mock_gen: MagicMock,
    mock_embed: MagicMock,
    client: TestClient,
    memory_qdrant: QdrantClient,
) -> None:
    # Caller is an intern
    _auth_patches(
        mock_verify,
        mock_tenant_cls,
        tenant_id="tenant-a",
        roles=frozenset([Role.intern]),
        sub="usr-intern",
    )
    mock_embed.return_value = [[0.1] * VECTOR_DIM]
    mock_gen.return_value = AnswerResult(
        answer="Intern guide information",
        citations=["chunk-allowed"],
        canary="canary-mixed",
        segments=[{"text": "Intern guide information", "citations": ["chunk-allowed"]}],
    )

    _seed_chunk(
        memory_qdrant,
        "chunk-allowed",
        "tenant-a",
        "doc-allowed",
        visibility="tenant",
        text="Intern guide information",
    )
    _seed_chunk(
        memory_qdrant,
        "chunk-forbidden",
        "tenant-a",
        "doc-forbidden",
        visibility="roles",
        allowed_roles=["manager"],
        text="Manager secrets",
    )

    resp = client.post(
        "/query",
        json={"question": "Help for interns", "doc_ids": ["doc-allowed", "doc-forbidden"]},
        headers={"Authorization": "Bearer tok"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["trust"]["abstained"] is False
    assert len(data["sources"]) == 1
    assert data["sources"][0]["doc_id"] == "doc-allowed"
    assert data["scope"] == {"scoped": True, "n_docs": 2}


# ── 4. Scoped queries do not read or write the cache ──────────────────────────
@patch("vaultrag.rag.query_service.cache_store")
@patch("vaultrag.rag.query_service.cache_lookup")
@patch("vaultrag.rag.query_service.gemini_client.embed_texts")
@patch("vaultrag.api.routers.query.generate_answer")
@patch("vaultrag.auth.dependencies.TenantRepo")
@patch("vaultrag.auth.dependencies.verify_id_token")
def test_scoped_queries_do_not_read_or_write_cache(
    mock_verify: MagicMock,
    mock_tenant_cls: MagicMock,
    mock_gen: MagicMock,
    mock_embed: MagicMock,
    mock_cache_lookup: MagicMock,
    mock_cache_store: MagicMock,
    client: TestClient,
    memory_qdrant: QdrantClient,
) -> None:
    _auth_patches(mock_verify, mock_tenant_cls, tenant_id="tenant-a")
    mock_embed.return_value = [[0.1] * VECTOR_DIM]
    mock_gen.return_value = AnswerResult(
        answer="Valid answer",
        citations=["chunk-1"],
        canary="canary-1",
        segments=[{"text": "Valid answer", "citations": ["chunk-1"]}],
    )

    _seed_chunk(memory_qdrant, "chunk-1", "tenant-a", "doc-1", text="Chunk data")

    resp = client.post(
        "/query",
        json={"question": "Tell me about doc 1", "doc_ids": ["doc-1"]},
        headers={"Authorization": "Bearer tok"},
    )
    assert resp.status_code == 200

    # Assert cache was never consulted or updated
    mock_cache_lookup.assert_not_called()
    mock_cache_store.assert_not_called()


# ── 5. Scoped abstain does not create a knowledge gap ─────────────────────────
@patch("vaultrag.rag.query_service.record_knowledge_gap")
@patch("vaultrag.rag.query_service.gemini_client.embed_texts")
@patch("vaultrag.auth.dependencies.TenantRepo")
@patch("vaultrag.auth.dependencies.verify_id_token")
def test_scoped_abstain_does_not_create_gap(
    mock_verify: MagicMock,
    mock_tenant_cls: MagicMock,
    mock_embed: MagicMock,
    mock_gap: MagicMock,
    client: TestClient,
    memory_qdrant: QdrantClient,
) -> None:
    _auth_patches(mock_verify, mock_tenant_cls, tenant_id="tenant-a")
    mock_embed.return_value = [[0.1] * VECTOR_DIM]

    resp = client.post(
        "/query",
        json={"question": "Where is the policy?", "doc_ids": ["doc-missing-123"]},
        headers={"Authorization": "Bearer tok"},
    )
    assert resp.status_code == 200
    assert resp.json()["trust"]["abstained"] is True

    # Assert knowledge gap was not recorded
    mock_gap.assert_not_called()


# ── 6. More than 20 doc IDs -> 422 ────────────────────────────────────────────
@patch("vaultrag.auth.dependencies.TenantRepo")
@patch("vaultrag.auth.dependencies.verify_id_token")
def test_more_than_20_doc_ids_returns_422(
    mock_verify: MagicMock,
    mock_tenant_cls: MagicMock,
    client: TestClient,
) -> None:
    _auth_patches(mock_verify, mock_tenant_cls, tenant_id="tenant-a")
    bad_doc_ids = [f"doc_{i}" for i in range(21)]

    resp = client.post(
        "/query",
        json={"question": "Question with 21 docs", "doc_ids": bad_doc_ids},
        headers={"Authorization": "Bearer tok"},
    )
    assert resp.status_code == 422


# ── 7. Malformed doc ID -> 422 ────────────────────────────────────────────────
@patch("vaultrag.auth.dependencies.TenantRepo")
@patch("vaultrag.auth.dependencies.verify_id_token")
def test_malformed_doc_ids_return_422(
    mock_verify: MagicMock,
    mock_tenant_cls: MagicMock,
    client: TestClient,
) -> None:
    _auth_patches(mock_verify, mock_tenant_cls, tenant_id="tenant-a")

    for malformed in ["bad/id", "../doc", "doc!", "doc id", "", "a" * 65]:
        resp = client.post(
            "/query",
            json={"question": "Question with bad doc id", "doc_ids": [malformed]},
            headers={"Authorization": "Bearer tok"},
        )
        assert resp.status_code == 422, f"Expected 422 for malformed id: {malformed}"


# ── 8. Tenant B doc IDs in Tenant A scope return nothing ──────────────────────
@patch("vaultrag.rag.query_service.gemini_client.embed_texts")
@patch("vaultrag.auth.dependencies.TenantRepo")
@patch("vaultrag.auth.dependencies.verify_id_token")
def test_cross_tenant_doc_id_in_scope_returns_nothing(
    mock_verify: MagicMock,
    mock_tenant_cls: MagicMock,
    mock_embed: MagicMock,
    client: TestClient,
    memory_qdrant: QdrantClient,
) -> None:
    # Caller is in Tenant A
    _auth_patches(mock_verify, mock_tenant_cls, tenant_id="tenant-a")
    mock_embed.return_value = [[0.1] * VECTOR_DIM]

    # Seed doc in Tenant B
    _seed_chunk(
        memory_qdrant,
        "chunk-b",
        "tenant-b",
        "doc-tenant-b-secret",
        text="Tenant B secret information",
    )

    resp = client.post(
        "/query",
        json={"question": "What is in Tenant B?", "doc_ids": ["doc-tenant-b-secret"]},
        headers={"Authorization": "Bearer tok"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["trust"]["abstained"] is True
    assert data["sources"] == []


# ── 9. Empty list treated as None / unscoped ──────────────────────────────────
@patch("vaultrag.rag.query_service.gemini_client.embed_texts")
@patch("vaultrag.api.routers.query.generate_answer")
@patch("vaultrag.auth.dependencies.TenantRepo")
@patch("vaultrag.auth.dependencies.verify_id_token")
def test_empty_doc_ids_treated_as_none_unscoped(
    mock_verify: MagicMock,
    mock_tenant_cls: MagicMock,
    mock_gen: MagicMock,
    mock_embed: MagicMock,
    client: TestClient,
    memory_qdrant: QdrantClient,
) -> None:
    _auth_patches(mock_verify, mock_tenant_cls, tenant_id="tenant-a")
    mock_embed.return_value = [[0.1] * VECTOR_DIM]
    mock_gen.return_value = AnswerResult(
        answer="All accessible docs answer",
        citations=["chunk-1"],
        canary="canary-1",
        segments=[{"text": "All accessible docs answer", "citations": ["chunk-1"]}],
    )

    _seed_chunk(memory_qdrant, "chunk-1", "tenant-a", "doc-1", text="Chunk data")

    resp = client.post(
        "/query",
        json={"question": "General question", "doc_ids": []},
        headers={"Authorization": "Bearer tok"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["scope"] == {"scoped": False, "n_docs": 0}


# ── 10. Duplicate doc IDs are deduplicated ────────────────────────────────────
@patch("vaultrag.rag.query_service.gemini_client.embed_texts")
@patch("vaultrag.api.routers.query.generate_answer")
@patch("vaultrag.auth.dependencies.TenantRepo")
@patch("vaultrag.auth.dependencies.verify_id_token")
def test_duplicate_doc_ids_deduplicated(
    mock_verify: MagicMock,
    mock_tenant_cls: MagicMock,
    mock_gen: MagicMock,
    mock_embed: MagicMock,
    client: TestClient,
    memory_qdrant: QdrantClient,
) -> None:
    _auth_patches(mock_verify, mock_tenant_cls, tenant_id="tenant-a")
    mock_embed.return_value = [[0.1] * VECTOR_DIM]
    mock_gen.return_value = AnswerResult(
        answer="Deduplicated answer",
        citations=["chunk-1"],
        canary="canary-1",
        segments=[{"text": "Deduplicated answer", "citations": ["chunk-1"]}],
    )

    _seed_chunk(memory_qdrant, "chunk-1", "tenant-a", "doc-1", text="Chunk data")

    resp = client.post(
        "/query",
        json={"question": "Question with dupes", "doc_ids": ["doc-1", "doc-1", "doc-1"]},
        headers={"Authorization": "Bearer tok"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["scope"] == {"scoped": True, "n_docs": 1}
