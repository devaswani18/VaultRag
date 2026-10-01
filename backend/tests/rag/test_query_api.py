"""Tests for POST /query endpoint — validates auth, question length, empty retrieval,
no chunk text in response, snippet limit, and tenant isolation."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from vaultrag.api.app import create_app
from vaultrag.auth.dependencies import clear_tenant_cache
from vaultrag.auth.jwt_verifier import Claims
from vaultrag.context import Role
from vaultrag.rag.generate import AnswerResult
from vaultrag.rag.retrieve import RetrievedChunk

_SNIPPET_MAX = 200


@pytest.fixture(autouse=True)
def reset_cache() -> None:
    clear_tenant_cache()
    yield
    clear_tenant_cache()


@pytest.fixture
def client() -> TestClient:
    app = create_app()
    return TestClient(app, raise_server_exceptions=False)


def _mock_claims(
    tenant_id: str = "acme",
    sub: str = "usr-test-01",
    roles: frozenset[Role] | None = None,
) -> Claims:
    return Claims(
        sub=sub,
        email=f"user@{tenant_id}.example.com",
        tenant_id=tenant_id,
        roles=roles or frozenset([Role.admin]),
        token_use="id",
        raw_claims={
            "exp": 1800000000,
            "iat": 1700000000,
            "iss": "https://cognito-idp.ap-south-1.amazonaws.com/test",
            "aud": "test-client-id",
        },
    )


def _chunk(
    chunk_id: str = "cid-1", text: str = "chunk text", doc_id: str = "doc-1"
) -> RetrievedChunk:
    return RetrievedChunk(
        chunk_id=chunk_id,
        doc_id=doc_id,
        filename="policy.txt",
        page=1,
        text=text,
        score=0.9,
    )


# ── Helpers ───────────────────────────────────────────────────────────────────
def _auth_patches(
    mock_verify: MagicMock, mock_tenant_cls: MagicMock, tenant_id: str = "acme"
) -> None:
    mock_verify.return_value = _mock_claims(tenant_id=tenant_id)
    repo = MagicMock()
    repo.get.return_value = {"tenant_id": tenant_id, "status": "ACTIVE"}
    mock_tenant_cls.return_value = repo


# ── 1. Unauthenticated request is rejected ────────────────────────────────────
def test_query_requires_auth(client: TestClient) -> None:
    resp = client.post("/query", json={"question": "What is the policy?"})
    assert resp.status_code == 401


# ── 2. Question too short (0 chars) ──────────────────────────────────────────
@patch("vaultrag.auth.dependencies.TenantRepo")
@patch("vaultrag.auth.dependencies.verify_id_token")
def test_query_question_too_short(
    mock_verify: MagicMock,
    mock_tenant_cls: MagicMock,
    client: TestClient,
) -> None:
    _auth_patches(mock_verify, mock_tenant_cls)
    resp = client.post(
        "/query",
        json={"question": ""},
        headers={"Authorization": "Bearer tok"},
    )
    assert resp.status_code == 422


# ── 3. Question too long (> 1000 chars) ───────────────────────────────────────
@patch("vaultrag.auth.dependencies.TenantRepo")
@patch("vaultrag.auth.dependencies.verify_id_token")
def test_query_question_too_long(
    mock_verify: MagicMock,
    mock_tenant_cls: MagicMock,
    client: TestClient,
) -> None:
    _auth_patches(mock_verify, mock_tenant_cls)
    resp = client.post(
        "/query",
        json={"question": "x" * 1001},
        headers={"Authorization": "Bearer tok"},
    )
    assert resp.status_code == 422


# ── 4. top_k out of range ─────────────────────────────────────────────────────
@patch("vaultrag.auth.dependencies.TenantRepo")
@patch("vaultrag.auth.dependencies.verify_id_token")
def test_query_top_k_out_of_range(
    mock_verify: MagicMock,
    mock_tenant_cls: MagicMock,
    client: TestClient,
) -> None:
    _auth_patches(mock_verify, mock_tenant_cls)
    for bad_k in [0, 11]:
        resp = client.post(
            "/query",
            json={"question": "Valid question", "top_k": bad_k},
            headers={"Authorization": "Bearer tok"},
        )
        assert resp.status_code == 422, f"Expected 422 for top_k={bad_k}"


# ── 5. Empty retrieval: no LLM call, canned answer returned ──────────────────
@patch("vaultrag.api.routers.query.generate_answer")
@patch("vaultrag.api.routers.query.retrieve")
@patch("vaultrag.auth.dependencies.TenantRepo")
@patch("vaultrag.auth.dependencies.verify_id_token")
def test_query_empty_retrieval_no_llm_call(
    mock_verify: MagicMock,
    mock_tenant_cls: MagicMock,
    mock_retrieve: MagicMock,
    mock_generate: MagicMock,
    client: TestClient,
) -> None:
    _auth_patches(mock_verify, mock_tenant_cls)
    mock_retrieve.return_value = []

    resp = client.post(
        "/query",
        json={"question": "An obscure question"},
        headers={"Authorization": "Bearer tok"},
    )

    assert resp.status_code == 200
    data = resp.json()
    assert data["sources"] == []
    assert "could not find" in data["answer"].lower()
    mock_generate.assert_not_called()  # LLM must NOT be called


# ── 6. Successful query returns answer and sources ────────────────────────────
@patch("vaultrag.api.routers.query.generate_answer")
@patch("vaultrag.api.routers.query.retrieve")
@patch("vaultrag.auth.dependencies.TenantRepo")
@patch("vaultrag.auth.dependencies.verify_id_token")
def test_query_success_response_shape(
    mock_verify: MagicMock,
    mock_tenant_cls: MagicMock,
    mock_retrieve: MagicMock,
    mock_generate: MagicMock,
    client: TestClient,
) -> None:
    _auth_patches(mock_verify, mock_tenant_cls)
    c = _chunk("cid-1", "The leave policy grants 20 days per year.")
    mock_retrieve.return_value = [c]
    mock_generate.return_value = AnswerResult(answer="20 days per year.", citations=["cid-1"])

    resp = client.post(
        "/query",
        json={"question": "How many leave days?"},
        headers={"Authorization": "Bearer tok"},
    )

    assert resp.status_code == 200
    data = resp.json()
    assert data["answer"] == "20 days per year."
    assert "request_id" in data
    assert len(data["sources"]) >= 1
    src = next(s for s in data["sources"] if s["chunk_id"] == "cid-1")
    assert src["doc_id"] == "doc-1"
    assert src["filename"] == "policy.txt"


# ── 7. Response NEVER contains full chunk text beyond snippet limit ───────────
@patch("vaultrag.api.routers.query.generate_answer")
@patch("vaultrag.api.routers.query.retrieve")
@patch("vaultrag.auth.dependencies.TenantRepo")
@patch("vaultrag.auth.dependencies.verify_id_token")
def test_query_snippet_max_length_enforced(
    mock_verify: MagicMock,
    mock_tenant_cls: MagicMock,
    mock_retrieve: MagicMock,
    mock_generate: MagicMock,
    client: TestClient,
) -> None:
    _auth_patches(mock_verify, mock_tenant_cls)
    long_text = "A" * 500  # well above the 200-char limit
    c = _chunk("cid-long", long_text)
    mock_retrieve.return_value = [c]
    mock_generate.return_value = AnswerResult(answer="Some answer.", citations=["cid-long"])

    resp = client.post(
        "/query",
        json={"question": "Long text question"},
        headers={"Authorization": "Bearer tok"},
    )
    assert resp.status_code == 200
    data = resp.json()

    for src in data["sources"]:
        snippet = src.get("snippet", "")
        assert len(snippet) <= _SNIPPET_MAX, f"Snippet exceeds {_SNIPPET_MAX} chars: {len(snippet)}"
        # Full text must not appear in any string field of the source
        assert long_text not in json.dumps(src), "Full chunk text must not appear in source"


# ── 8. Tenant isolation: retrieve is called with ctx containing correct tenant ─
@patch("vaultrag.api.routers.query.generate_answer")
@patch("vaultrag.api.routers.query.retrieve")
@patch("vaultrag.auth.dependencies.TenantRepo")
@patch("vaultrag.auth.dependencies.verify_id_token")
@pytest.mark.parametrize("tenant_id", ["acme", "globex"])
def test_query_retrieve_receives_correct_tenant(
    mock_verify: MagicMock,
    mock_tenant_cls: MagicMock,
    mock_retrieve: MagicMock,
    mock_generate: MagicMock,
    tenant_id: str,
    client: TestClient,
) -> None:
    _auth_patches(mock_verify, mock_tenant_cls, tenant_id=tenant_id)
    mock_retrieve.return_value = []

    client.post(
        "/query",
        json={"question": "Any question"},
        headers={"Authorization": "Bearer tok"},
    )

    mock_retrieve.assert_called_once()
    ctx_arg = mock_retrieve.call_args.args[0]
    assert ctx_arg.tenant_id == tenant_id
