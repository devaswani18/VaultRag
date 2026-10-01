from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from vaultrag.api.app import create_app
from vaultrag.auth.dependencies import clear_tenant_cache
from vaultrag.auth.jwt_verifier import Claims
from vaultrag.context import Role


@pytest.fixture(autouse=True)
def clean_cache() -> None:
    clear_tenant_cache()
    yield
    clear_tenant_cache()


@pytest.fixture
def client() -> TestClient:
    app = create_app()
    return TestClient(app, raise_server_exceptions=False)


def _mock_claims(
    sub: str = "user-1",
    tenant_id: str = "tenant-a",
    roles: frozenset[Role] | None = None,
) -> Claims:
    return Claims(
        sub=sub,
        email="test@example.com",
        tenant_id=tenant_id,
        roles=roles if roles is not None else frozenset([Role.admin]),
        token_use="id",
        raw_claims={
            "exp": 1800000000,
            "iat": 1700000000,
            "iss": "https://cognito-idp.ap-south-1.amazonaws.com/test",
            "aud": "test-client-id",
        },
    )


@patch("vaultrag.admin.quarantine.DocumentRepo")
@patch("vaultrag.auth.dependencies.TenantRepo")
@patch("vaultrag.auth.dependencies.verify_id_token")
def test_admin_can_list_quarantine_without_text(
    mock_verify: MagicMock,
    mock_tenant_repo_cls: MagicMock,
    mock_doc_repo_cls: MagicMock,
    client: TestClient,
) -> None:
    mock_verify.return_value = _mock_claims(roles=frozenset([Role.admin]))
    mock_tenant = MagicMock()
    mock_tenant.get.return_value = {"tenant_id": "tenant-a", "status": "ACTIVE"}
    mock_tenant_repo_cls.return_value = mock_tenant

    mock_doc_repo = MagicMock()
    mock_doc_repo.list_for_tenant.return_value = (
        [
            {
                "doc_id": "doc-q1",
                "filename": "suspicious.pdf",
                "status": "QUARANTINED",
                "created_at": "2026-01-01T00:00:00Z",
                "chunk_count": 0,
                "error": "Quarantined: 2/2 chunks dropped",
                "injection_summary": {"high": 2, "medium": 0, "low": 0},
                "quarantine_report": [
                    {"chunk_index": 0, "page": 1, "risk": "high", "reasons": ["override_phrase"]},
                    {"chunk_index": 1, "page": 1, "risk": "high", "reasons": ["exfiltration"]},
                ],
                "secret_raw_text": "Sensitive confidential text that must never be exposed",
            },
            {
                "doc_id": "doc-clean",
                "filename": "clean.pdf",
                "status": "READY",
                "created_at": "2026-01-01T00:00:00Z",
                "chunk_count": 5,
                "quarantine_report": [],
            },
        ],
        None,
    )
    mock_doc_repo_cls.return_value = mock_doc_repo

    resp = client.get("/admin/quarantine", headers={"Authorization": "Bearer valid-token"})
    assert resp.status_code == 200
    docs = resp.json()

    assert len(docs) == 1
    doc = docs[0]
    assert doc["doc_id"] == "doc-q1"
    assert doc["filename"] == "suspicious.pdf"
    assert doc["status"] == "QUARANTINED"
    assert doc["injection_summary"] == {"high": 2, "medium": 0, "low": 0}
    assert len(doc["quarantine_report"]) == 2

    # Verify ZERO text fields leaked in API response
    raw_json_str = resp.text
    assert "Sensitive confidential text" not in raw_json_str
    assert "secret_raw_text" not in doc
    assert "text" not in doc


@patch("vaultrag.auth.dependencies.TenantRepo")
@patch("vaultrag.auth.dependencies.verify_id_token")
def test_non_admin_cannot_access_quarantine(
    mock_verify: MagicMock,
    mock_tenant_repo_cls: MagicMock,
    client: TestClient,
) -> None:
    # Employee role (not admin)
    mock_verify.return_value = _mock_claims(roles=frozenset([Role.employee]))
    mock_tenant = MagicMock()
    mock_tenant.get.return_value = {"tenant_id": "tenant-a", "status": "ACTIVE"}
    mock_tenant_repo_cls.return_value = mock_tenant

    resp = client.get("/admin/quarantine", headers={"Authorization": "Bearer valid-token"})
    assert resp.status_code == 403
    assert resp.json()["error"]["code"] == "forbidden"
