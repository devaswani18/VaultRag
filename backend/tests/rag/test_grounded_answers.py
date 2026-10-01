from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from vaultrag.api.app import create_app
from vaultrag.auth.dependencies import clear_tenant_cache
from vaultrag.auth.jwt_verifier import Claims
from vaultrag.clients.gemini import GenerationResult
from vaultrag.context import Role
from vaultrag.rag.generate import AnswerResult
from vaultrag.rag.retrieve import RetrievedChunk
from vaultrag.security.pii_guard import generate_verhoeff


@pytest.fixture(autouse=True)
def reset_cache() -> None:
    clear_tenant_cache()
    yield
    clear_tenant_cache()


@pytest.fixture
def client() -> TestClient:
    app = create_app()
    return TestClient(app, raise_server_exceptions=False)


def _mock_claims(tenant_id: str = "acme") -> Claims:
    return Claims(
        sub="user-123",
        email=f"user@{tenant_id}.com",
        tenant_id=tenant_id,
        roles=frozenset([Role.admin]),
        token_use="id",
        raw_claims={
            "exp": 1800000000,
            "iat": 1700000000,
            "iss": "https://cognito-idp.ap-south-1.amazonaws.com/test",
            "aud": "test-client",
        },
    )


def _setup_auth(
    mock_verify: MagicMock,
    mock_auth_repo_cls: MagicMock,
    settings: dict[str, object] | None = None,
) -> None:
    mock_verify.return_value = _mock_claims("acme")
    repo = MagicMock()
    repo.get.return_value = {
        "tenant_id": "acme",
        "status": "ACTIVE",
        "settings": settings or {"min_retrieval_score": 0.35, "min_faithfulness": 0.6},
    }
    mock_auth_repo_cls.return_value = repo


# ── 1. Grounded answer full path ─────────────────────────────────────────────
@patch("vaultrag.api.routers.query.TenantRepo")
@patch("vaultrag.auth.dependencies.TenantRepo")
@patch("vaultrag.auth.dependencies.verify_id_token")
@patch("vaultrag.api.routers.query.retrieve")
@patch("vaultrag.api.routers.query.generate_answer")
def test_grounded_answer_success(
    mock_generate: MagicMock,
    mock_retrieve: MagicMock,
    mock_verify: MagicMock,
    mock_auth_repo: MagicMock,
    mock_query_repo: MagicMock,
    client: TestClient,
) -> None:
    _setup_auth(mock_verify, mock_auth_repo)
    mock_query_repo.return_value = mock_auth_repo.return_value

    chunk = RetrievedChunk(
        chunk_id="c1",
        doc_id="d1",
        filename="leave_policy.pdf",
        page=1,
        text="Full-time employees receive 20 days paid leave per calendar year.",
        score=0.85,
    )
    mock_retrieve.return_value = [chunk]
    mock_generate.return_value = AnswerResult(
        answer="Full-time employees receive 20 days paid leave per calendar year.",
        segments=[
            {
                "text": "Full-time employees receive 20 days paid leave per calendar year.",
                "citations": ["c1"],
            }
        ],
        citations=["c1"],
    )

    resp = client.post(
        "/query",
        json={"question": "What is the annual leave allowance?"},
        headers={"Authorization": "Bearer token"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["trust"]["score"] == 1.0
    assert data["trust"]["grounded"] is True
    assert data["trust"]["abstained"] is False
    assert data["trust"]["partial"] is False
    assert data["answer"] == "Full-time employees receive 20 days paid leave per calendar year."


# ── 2. Out-of-document question abstains without calling LLM ──────────────────
@patch("vaultrag.api.routers.query.TenantRepo")
@patch("vaultrag.auth.dependencies.TenantRepo")
@patch("vaultrag.auth.dependencies.verify_id_token")
@patch("vaultrag.api.routers.query.retrieve")
@patch("vaultrag.api.routers.query.generate_answer")
def test_out_of_document_abstains_without_llm_call(
    mock_generate: MagicMock,
    mock_retrieve: MagicMock,
    mock_verify: MagicMock,
    mock_auth_repo: MagicMock,
    mock_query_repo: MagicMock,
    client: TestClient,
) -> None:
    _setup_auth(mock_verify, mock_auth_repo, {"min_retrieval_score": 0.40})
    mock_query_repo.return_value = mock_auth_repo.return_value

    # Retrieval returns chunks with low scores (< 0.40)
    low_chunk = RetrievedChunk(
        chunk_id="c-low",
        doc_id="d1",
        filename="policy.txt",
        page=1,
        text="Irrelevant text.",
        score=0.22,
    )
    mock_retrieve.return_value = [low_chunk]

    resp = client.post(
        "/query",
        json={"question": "What is the capital of Mars?"},
        headers={"Authorization": "Bearer token"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["trust"]["abstained"] is True
    assert data["trust"]["score"] == 0.0
    assert "below_min_retrieval_score" in data["trust"]["reasons"]
    assert "could not find this in the documents" in data["answer"].lower()

    # CRITICAL: Assert the generative model was NOT called
    mock_generate.assert_not_called()


# ── 3. Partial answer path with visible note ──────────────────────────────────
@patch("vaultrag.api.routers.query.TenantRepo")
@patch("vaultrag.auth.dependencies.TenantRepo")
@patch("vaultrag.auth.dependencies.verify_id_token")
@patch("vaultrag.api.routers.query.retrieve")
@patch("vaultrag.api.routers.query.generate_answer")
def test_partial_answer_drops_unsupported_segments(
    mock_generate: MagicMock,
    mock_retrieve: MagicMock,
    mock_verify: MagicMock,
    mock_auth_repo: MagicMock,
    mock_query_repo: MagicMock,
    client: TestClient,
) -> None:
    _setup_auth(mock_verify, mock_auth_repo, {"min_faithfulness": 0.80})
    mock_query_repo.return_value = mock_auth_repo.return_value

    chunk = RetrievedChunk(
        chunk_id="c1",
        doc_id="d1",
        filename="policy.txt",
        page=1,
        text="The probationary period lasts 90 days for all technical staff.",
        score=0.88,
    )
    mock_retrieve.return_value = [chunk]

    # Model returns 2 segments: 1 supported, 1 hallucinated without citations
    mock_generate.return_value = AnswerResult(
        answer="The probationary period lasts 90 days. Every employee gets a free Tesla.",
        segments=[
            {"text": "The probationary period lasts 90 days.", "citations": ["c1"]},
            {"text": "Every employee gets a free Tesla.", "citations": []},
        ],
        citations=["c1"],
    )

    resp = client.post(
        "/query",
        json={"question": "What are the staff benefits and probation?"},
        headers={"Authorization": "Bearer token"},
    )
    assert resp.status_code == 200
    data = resp.json()

    # Score is 0.5 < 0.80 -> partial answer returned
    assert data["trust"]["partial"] is True
    assert data["trust"]["abstained"] is False
    assert data["trust"]["score"] == 0.5
    assert "The probationary period lasts 90 days." in data["answer"]
    assert "free Tesla" not in data["answer"]
    # Visible note included
    assert "Note: Some unverified statements were removed" in data["answer"]


# ── 4. Invalid JSON retry then abstain ────────────────────────────────────────
@patch("vaultrag.api.routers.query.TenantRepo")
@patch("vaultrag.auth.dependencies.TenantRepo")
@patch("vaultrag.auth.dependencies.verify_id_token")
@patch("vaultrag.api.routers.query.retrieve")
@patch("vaultrag.rag.generate.gemini_client.generate_json")
def test_invalid_json_retry_then_abstain(
    mock_gemini: MagicMock,
    mock_retrieve: MagicMock,
    mock_verify: MagicMock,
    mock_auth_repo: MagicMock,
    mock_query_repo: MagicMock,
    client: TestClient,
) -> None:
    _setup_auth(mock_verify, mock_auth_repo)
    mock_query_repo.return_value = mock_auth_repo.return_value

    chunk = RetrievedChunk(
        chunk_id="c1",
        doc_id="d1",
        filename="doc.txt",
        page=1,
        text="Document information here.",
        score=0.90,
    )
    mock_retrieve.return_value = [chunk]

    # Both LLM generation attempts produce invalid unparseable non-JSON text
    mock_gemini.return_value = GenerationResult(
        text="Sorry, here is plain text not JSON at all.",
        input_tokens=10,
        output_tokens=10,
        model="gemini",
    )

    resp = client.post(
        "/query",
        json={"question": "Test question?"},
        headers={"Authorization": "Bearer token"},
    )
    assert resp.status_code == 200
    data = resp.json()

    # Should retry once (2 calls total) and abstain with model_output_invalid
    assert mock_gemini.call_count == 2
    assert data["trust"]["abstained"] is True
    assert "model_output_invalid" in data["trust"]["reasons"]


# ── 5. Response schema test ───────────────────────────────────────────────────
@patch("vaultrag.api.routers.query.TenantRepo")
@patch("vaultrag.auth.dependencies.TenantRepo")
@patch("vaultrag.auth.dependencies.verify_id_token")
@patch("vaultrag.api.routers.query.retrieve")
@patch("vaultrag.api.routers.query.generate_answer")
def test_query_response_schema_fields(
    mock_generate: MagicMock,
    mock_retrieve: MagicMock,
    mock_verify: MagicMock,
    mock_auth_repo: MagicMock,
    mock_query_repo: MagicMock,
    client: TestClient,
) -> None:
    _setup_auth(mock_verify, mock_auth_repo)
    mock_query_repo.return_value = mock_auth_repo.return_value

    chunk = RetrievedChunk(
        chunk_id="c100",
        doc_id="d100",
        filename="report.pdf",
        page=2,
        text="Annual revenue grew by 15% in FY2025.",
        score=0.88,
    )
    mock_retrieve.return_value = [chunk]
    mock_generate.return_value = AnswerResult(
        answer="Annual revenue grew by 15% in FY2025.",
        segments=[{"text": "Annual revenue grew by 15% in FY2025.", "citations": ["c100"]}],
        citations=["c100"],
    )

    resp = client.post(
        "/query",
        json={"question": "How did revenue grow?"},
        headers={"Authorization": "Bearer token"},
    )
    assert resp.status_code == 200
    data = resp.json()

    # Required top-level keys
    assert "answer" in data
    assert "trust" in data
    assert "sources" in data
    assert "request_id" in data

    # Required trust keys
    trust = data["trust"]
    assert "score" in trust and isinstance(trust["score"], float)
    assert "grounded" in trust and isinstance(trust["grounded"], bool)
    assert "abstained" in trust and isinstance(trust["abstained"], bool)
    assert "partial" in trust and isinstance(trust["partial"], bool)
    assert "reasons" in trust and isinstance(trust["reasons"], list)

    # Required source keys
    assert len(data["sources"]) >= 1
    src = data["sources"][0]
    for key in ("doc_id", "filename", "chunk_id", "page", "score", "snippet"):
        assert key in src


# ── 6. Snippet PII redaction ──────────────────────────────────────────────────
@patch("vaultrag.api.routers.query.TenantRepo")
@patch("vaultrag.auth.dependencies.TenantRepo")
@patch("vaultrag.auth.dependencies.verify_id_token")
@patch("vaultrag.api.routers.query.retrieve")
@patch("vaultrag.api.routers.query.generate_answer")
def test_source_snippet_pii_redaction(
    mock_generate: MagicMock,
    mock_retrieve: MagicMock,
    mock_verify: MagicMock,
    mock_auth_repo: MagicMock,
    mock_query_repo: MagicMock,
    client: TestClient,
) -> None:
    _setup_auth(mock_verify, mock_auth_repo, {"pii_mode": "redact"})
    mock_query_repo.return_value = mock_auth_repo.return_value

    aadhaar = generate_verhoeff("45678901234")
    raw_chunk_text = f"Customer support contact: user@company.com with Aadhaar {aadhaar}."
    chunk = RetrievedChunk(
        chunk_id="c-pii",
        doc_id="d-pii",
        filename="contacts.txt",
        page=1,
        text=raw_chunk_text,
        score=0.88,
    )
    mock_retrieve.return_value = [chunk]
    answer_text = f"Customer support contact is user@company.com with Aadhaar {aadhaar}."
    mock_generate.return_value = AnswerResult(
        answer=answer_text,
        segments=[
            {
                "text": answer_text,
                "citations": ["c-pii"],
            }
        ],
        citations=["c-pii"],
    )

    resp = client.post(
        "/query",
        json={"question": "Who do I contact for customer support?"},
        headers={"Authorization": "Bearer token"},
    )
    assert resp.status_code == 200
    data = resp.json()

    # The snippet in sources MUST have PII redacted
    src = next(s for s in data["sources"] if s["chunk_id"] == "c-pii")
    snippet = src["snippet"]
    assert aadhaar not in snippet
    assert "user@company.com" not in snippet
    assert "[AADHAAR_REDACTED]" in snippet
    assert "[EMAIL_REDACTED]" in snippet
