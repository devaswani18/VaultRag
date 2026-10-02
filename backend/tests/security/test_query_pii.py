"""Tests for PII Guard integration in query and answer pipeline."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from vaultrag.api.app import create_app
from vaultrag.auth.dependencies import clear_tenant_cache
from vaultrag.auth.jwt_verifier import Claims
from vaultrag.context import Role
from vaultrag.rag.generate import AnswerResult
from vaultrag.rag.retrieve import RetrievedChunk
from vaultrag.security.pii_guard import generate_verhoeff


def _valid_aadhaar() -> str:
    return generate_verhoeff("34567890123")


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
        sub="usr-test-01",
        email=f"user@{tenant_id}.example.com",
        tenant_id=tenant_id,
        roles=frozenset([Role.admin]),
        token_use="id",
        raw_claims={
            "exp": 1800000000,
            "iat": 1700000000,
            "iss": "https://cognito-idp.ap-south-1.amazonaws.com/test",
            "aud": "test-client-id",
        },
    )


def _chunk(chunk_id: str = "cid-1", text: str = "sample text") -> RetrievedChunk:
    return RetrievedChunk(
        chunk_id=chunk_id,
        doc_id="doc-1",
        text=text,
        score=0.9,
        page=1,
        filename="policy.pdf",
    )


class TestQueryAnswerPII:
    @patch("vaultrag.api.routers.query.TenantRepo")
    @patch("vaultrag.auth.dependencies.TenantRepo")
    @patch("vaultrag.auth.dependencies.verify_id_token")
    def test_query_block_mode_returns_422_on_pii(
        self,
        mock_verify: MagicMock,
        mock_auth_repo_cls: MagicMock,
        mock_query_repo_cls: MagicMock,
        client: TestClient,
    ) -> None:
        mock_verify.return_value = _mock_claims("acme")
        tenant_data = {"status": "active", "settings": {"pii_mode": "block"}}
        mock_auth_repo = MagicMock()
        mock_auth_repo.get.return_value = tenant_data
        mock_auth_repo_cls.return_value = mock_auth_repo

        mock_query_repo = MagicMock()
        mock_query_repo.get.return_value = tenant_data
        mock_query_repo_cls.return_value = mock_query_repo

        aadhaar = _valid_aadhaar()
        resp = client.post(
            "/query",
            json={"question": f"What is the status of Aadhaar {aadhaar}?"},
            headers={"Authorization": "Bearer valid.token.jwt"},
        )

        assert resp.status_code == 422
        body = resp.json()
        # Safe error message check
        err_msg = body.get("message") or body.get("error", {}).get("message", "")
        assert "Your question appears to contain sensitive identifiers" in err_msg
        assert aadhaar not in resp.text

    @patch("vaultrag.api.routers.query.generate_answer")
    @patch("vaultrag.api.routers.query.retrieve")
    @patch("vaultrag.api.routers.query.TenantRepo")
    @patch("vaultrag.auth.dependencies.TenantRepo")
    @patch("vaultrag.auth.dependencies.verify_id_token")
    def test_query_redact_mode_replaces_question_and_masks_answer(
        self,
        mock_verify: MagicMock,
        mock_auth_repo_cls: MagicMock,
        mock_query_repo_cls: MagicMock,
        mock_retrieve: MagicMock,
        mock_generate: MagicMock,
        client: TestClient,
    ) -> None:
        mock_verify.return_value = _mock_claims("acme")
        tenant_data = {"status": "active", "settings": {"pii_mode": "redact"}}
        mock_auth_repo = MagicMock()
        mock_auth_repo.get.return_value = tenant_data
        mock_auth_repo_cls.return_value = mock_auth_repo

        mock_query_repo = MagicMock()
        mock_query_repo.get.return_value = tenant_data
        mock_query_repo_cls.return_value = mock_query_repo

        aadhaar = _valid_aadhaar()
        mock_retrieve.return_value = [
            _chunk(text=f"The account belongs to citizen with Aadhaar {aadhaar}.")
        ]
        # LLM returns answer containing an Aadhaar number
        mock_generate.return_value = AnswerResult(
            answer=f"The account belongs to citizen with Aadhaar {aadhaar}.",
            citations=["cid-1"],
        )

        resp = client.post(
            "/query",
            json={"question": f"Tell me about email user@example.com and Aadhaar {aadhaar}"},
            headers={"Authorization": "Bearer valid.token.jwt"},
        )

        assert resp.status_code == 200
        data = resp.json()

        # 1. Check retrieve and generate were called with REDACTED question, not original
        retrieve_q = mock_retrieve.call_args[0][1]
        assert aadhaar not in retrieve_q
        assert "user@example.com" not in retrieve_q
        assert "[AADHAAR_REDACTED]" in retrieve_q
        assert "[EMAIL_REDACTED]" in retrieve_q

        generate_q = mock_generate.call_args[0][0]
        assert aadhaar not in generate_q
        assert "[AADHAAR_REDACTED]" in generate_q

        # 2. Check final answer masked the Aadhaar from the LLM
        assert aadhaar not in data["answer"]
        assert "[AADHAAR_REDACTED]" in data["answer"]
        assert data["pii_in_answer"] is True

    @patch("vaultrag.api.routers.query.generate_answer")
    @patch("vaultrag.api.routers.query.retrieve")
    @patch("vaultrag.api.routers.query.TenantRepo")
    @patch("vaultrag.auth.dependencies.TenantRepo")
    @patch("vaultrag.auth.dependencies.verify_id_token")
    def test_clean_answer_without_pii(
        self,
        mock_verify: MagicMock,
        mock_auth_repo_cls: MagicMock,
        mock_query_repo_cls: MagicMock,
        mock_retrieve: MagicMock,
        mock_generate: MagicMock,
        client: TestClient,
    ) -> None:
        mock_verify.return_value = _mock_claims("acme")
        tenant_data = {
            "status": "active",
            "settings": {"pii_mode": "redact", "cache_enabled": False},
        }
        mock_auth_repo = MagicMock()
        mock_auth_repo.get.return_value = tenant_data
        mock_auth_repo_cls.return_value = mock_auth_repo

        mock_query_repo = MagicMock()
        mock_query_repo.get.return_value = tenant_data
        mock_query_repo_cls.return_value = mock_query_repo

        mock_retrieve.return_value = [_chunk(text="The leave policy allows 20 annual days.")]
        mock_generate.return_value = AnswerResult(
            answer="The leave policy allows 20 annual days.",
            citations=["cid-1"],
        )

        resp = client.post(
            "/query",
            json={"question": "What is the annual leave allowance?"},
            headers={"Authorization": "Bearer valid.token.jwt"},
        )

        assert resp.status_code == 200
        data = resp.json()
        assert data["answer"] == "The leave policy allows 20 annual days."
        assert data["pii_in_answer"] is False
