from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from vaultrag.api.app import create_app
from vaultrag.auth.dependencies import clear_tenant_cache
from vaultrag.auth.jwt_verifier import Claims
from vaultrag.context import Role
from vaultrag.errors import NotFound


@pytest.fixture(autouse=True)
def reset_cache() -> None:
    clear_tenant_cache()
    yield
    clear_tenant_cache()


@pytest.fixture
def client() -> TestClient:
    app = create_app()
    return TestClient(app, raise_server_exceptions=False)


def _mock_auth(
    sub: str = "usr-tester-1",
    tenant_id: str = "acme",
    roles: frozenset[Role] | None = None,
) -> Claims:
    return Claims(
        sub=sub,
        email="user@acme.example.com",
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


# ------------------------------------------------------------------------------
# 1. POST /documents validation & success
# ------------------------------------------------------------------------------
@patch("vaultrag.api.routers.documents.create_presigned_post")
@patch("vaultrag.api.routers.documents.DocumentRepo")
@patch("vaultrag.auth.dependencies.TenantRepo")
@patch("vaultrag.auth.dependencies.verify_id_token")
def test_create_document_success(
    mock_verify: MagicMock,
    mock_tenant_repo_cls: MagicMock,
    mock_doc_repo_cls: MagicMock,
    mock_presigned: MagicMock,
    client: TestClient,
) -> None:
    mock_verify.return_value = _mock_auth()
    mock_tenant_repo = MagicMock()
    mock_tenant_repo.get.return_value = {"tenant_id": "acme", "status": "ACTIVE"}
    mock_tenant_repo_cls.return_value = mock_tenant_repo

    mock_doc_repo = MagicMock()
    mock_doc_repo_cls.return_value = mock_doc_repo

    mock_presigned.return_value = {
        "url": "https://docs-bucket.s3.amazonaws.com",
        "fields": {"key": "uploads/acme/doc_123/original.pdf"},
    }

    body = {
        "filename": "path/to/my_report.pdf",
        "content_type": "application/pdf",
        "size_bytes": 1024,
        "visibility": "tenant",
    }
    response = client.post(
        "/documents",
        json=body,
        headers={"Authorization": "Bearer valid-token"},
    )
    assert response.status_code == 200
    data = response.json()
    assert "doc_id" in data
    assert data["doc_id"].startswith("doc_")
    assert "upload" in data
    assert data["upload"]["url"] == "https://docs-bucket.s3.amazonaws.com"
    assert data["expires_in"] == 300

    # Verify doc repo was called with sanitized filename (path stripped)
    mock_doc_repo.create.assert_called_once()
    create_args = mock_doc_repo.create.call_args[1]
    assert create_args["filename"] == "my_report.pdf"
    assert create_args["content_type"] == "application/pdf"
    assert create_args["owner_user_id"] == "usr-tester-1"
    assert create_args["s3_key"] == f"uploads/acme/{data['doc_id']}/original.pdf"


@patch("vaultrag.auth.dependencies.TenantRepo")
@patch("vaultrag.auth.dependencies.verify_id_token")
def test_create_document_bad_extension(
    mock_verify: MagicMock,
    mock_tenant_repo_cls: MagicMock,
    client: TestClient,
) -> None:
    mock_verify.return_value = _mock_auth()
    mock_tenant_repo = MagicMock()
    mock_tenant_repo.get.return_value = {"tenant_id": "acme", "status": "ACTIVE"}
    mock_tenant_repo_cls.return_value = mock_tenant_repo

    body = {
        "filename": "malicious.exe",
        "content_type": "application/octet-stream",
        "size_bytes": 500,
    }
    response = client.post(
        "/documents",
        json=body,
        headers={"Authorization": "Bearer valid-token"},
    )
    assert response.status_code == 422
    assert "Unsupported file extension" in response.json()["error"]["message"]


@patch("vaultrag.auth.dependencies.TenantRepo")
@patch("vaultrag.auth.dependencies.verify_id_token")
def test_create_document_content_type_mismatch(
    mock_verify: MagicMock,
    mock_tenant_repo_cls: MagicMock,
    client: TestClient,
) -> None:
    mock_verify.return_value = _mock_auth()
    mock_tenant_repo = MagicMock()
    mock_tenant_repo.get.return_value = {"tenant_id": "acme", "status": "ACTIVE"}
    mock_tenant_repo_cls.return_value = mock_tenant_repo

    body = {
        "filename": "document.pdf",
        "content_type": "text/plain",  # Mismatch for .pdf
        "size_bytes": 500,
    }
    response = client.post(
        "/documents",
        json=body,
        headers={"Authorization": "Bearer valid-token"},
    )
    assert response.status_code == 422
    assert "Content-Type" in response.json()["error"]["message"]


@patch("vaultrag.auth.dependencies.TenantRepo")
@patch("vaultrag.auth.dependencies.verify_id_token")
def test_create_document_size_too_large(
    mock_verify: MagicMock,
    mock_tenant_repo_cls: MagicMock,
    client: TestClient,
) -> None:
    mock_verify.return_value = _mock_auth()
    mock_tenant_repo = MagicMock()
    mock_tenant_repo.get.return_value = {"tenant_id": "acme", "status": "ACTIVE"}
    mock_tenant_repo_cls.return_value = mock_tenant_repo

    body = {
        "filename": "big.pdf",
        "content_type": "application/pdf",
        "size_bytes": 50 * 1024 * 1024,  # 50 MB > max_upload_mb (default 10 MB)
    }
    response = client.post(
        "/documents",
        json=body,
        headers={"Authorization": "Bearer valid-token"},
    )
    assert response.status_code == 422
    assert "size_bytes must be between 1 and" in response.json()["error"]["message"]


@patch("vaultrag.auth.dependencies.TenantRepo")
@patch("vaultrag.auth.dependencies.verify_id_token")
def test_create_document_invalid_role(
    mock_verify: MagicMock,
    mock_tenant_repo_cls: MagicMock,
    client: TestClient,
) -> None:
    mock_verify.return_value = _mock_auth()
    mock_tenant_repo = MagicMock()
    mock_tenant_repo.get.return_value = {"tenant_id": "acme", "status": "ACTIVE"}
    mock_tenant_repo_cls.return_value = mock_tenant_repo

    body = {
        "filename": "doc.pdf",
        "content_type": "application/pdf",
        "size_bytes": 100,
        "visibility": "roles",
        "allowed_roles": ["super_hacker"],
    }
    response = client.post(
        "/documents",
        json=body,
        headers={"Authorization": "Bearer valid-token"},
    )
    assert response.status_code == 422
    assert "Invalid role" in response.json()["error"]["message"]


@patch("vaultrag.auth.dependencies.TenantRepo")
@patch("vaultrag.auth.dependencies.verify_id_token")
def test_create_document_roles_visibility_requires_roles(
    mock_verify: MagicMock,
    mock_tenant_repo_cls: MagicMock,
    client: TestClient,
) -> None:
    mock_verify.return_value = _mock_auth()
    mock_tenant_repo = MagicMock()
    mock_tenant_repo.get.return_value = {"tenant_id": "acme", "status": "ACTIVE"}
    mock_tenant_repo_cls.return_value = mock_tenant_repo

    body = {
        "filename": "doc.pdf",
        "content_type": "application/pdf",
        "size_bytes": 100,
        "visibility": "roles",
        "allowed_roles": [],
    }
    response = client.post(
        "/documents",
        json=body,
        headers={"Authorization": "Bearer valid-token"},
    )
    assert response.status_code == 422
    err_msg = response.json()["error"]["message"]
    assert "Visibility 'roles' requires non-empty allowed_roles" in err_msg


# ------------------------------------------------------------------------------
# 2. GET /documents list
# ------------------------------------------------------------------------------
@patch("vaultrag.api.routers.documents.DocumentRepo")
@patch("vaultrag.auth.dependencies.TenantRepo")
@patch("vaultrag.auth.dependencies.verify_id_token")
def test_list_documents(
    mock_verify: MagicMock,
    mock_tenant_repo_cls: MagicMock,
    mock_doc_repo_cls: MagicMock,
    client: TestClient,
) -> None:
    mock_verify.return_value = _mock_auth()
    mock_tenant_repo = MagicMock()
    mock_tenant_repo.get.return_value = {"tenant_id": "acme", "status": "ACTIVE"}
    mock_tenant_repo_cls.return_value = mock_tenant_repo

    mock_doc_repo = MagicMock()
    mock_doc_repo.list_for_tenant.return_value = (
        [
            {
                "tenant_id": "acme",
                "doc_id": "doc-1",
                "filename": "file1.pdf",
                "status": "READY",
                "size_bytes": 1234,
                "created_at": "2026-01-01T00:00:00Z",
                "chunk_count": 5,
            }
        ],
        None,
    )
    mock_doc_repo_cls.return_value = mock_doc_repo

    response = client.get(
        "/documents",
        headers={"Authorization": "Bearer valid-token"},
    )
    assert response.status_code == 200
    docs = response.json()
    assert len(docs) == 1
    assert docs[0]["id"] == "doc-1"
    assert docs[0]["filename"] == "file1.pdf"
    assert docs[0]["status"] == "READY"
    assert docs[0]["chunk_count"] == 5
    mock_doc_repo.list_for_tenant.assert_called_once_with("acme", limit=100)


# ------------------------------------------------------------------------------
# 3. GET /documents/{doc_id} isolation
# ------------------------------------------------------------------------------
@patch("vaultrag.api.routers.documents.DocumentRepo")
@patch("vaultrag.auth.dependencies.TenantRepo")
@patch("vaultrag.auth.dependencies.verify_id_token")
def test_get_document_by_id(
    mock_verify: MagicMock,
    mock_tenant_repo_cls: MagicMock,
    mock_doc_repo_cls: MagicMock,
    client: TestClient,
) -> None:
    mock_verify.return_value = _mock_auth(tenant_id="acme")
    mock_tenant_repo = MagicMock()
    mock_tenant_repo.get.return_value = {"tenant_id": "acme", "status": "ACTIVE"}
    mock_tenant_repo_cls.return_value = mock_tenant_repo

    mock_doc_repo = MagicMock()
    mock_doc_repo.get.return_value = {
        "doc_id": "doc-100",
        "tenant_id": "acme",
        "filename": "report.pdf",
        "status": "READY",
        "size_bytes": 2048,
        "chunk_count": 3,
    }
    mock_doc_repo_cls.return_value = mock_doc_repo

    response = client.get(
        "/documents/doc-100",
        headers={"Authorization": "Bearer valid-token"},
    )
    assert response.status_code == 200
    assert response.json()["id"] == "doc-100"
    mock_doc_repo.get.assert_called_once_with("acme", "doc-100")


@patch("vaultrag.api.routers.documents.DocumentRepo")
@patch("vaultrag.auth.dependencies.TenantRepo")
@patch("vaultrag.auth.dependencies.verify_id_token")
def test_get_document_not_found(
    mock_verify: MagicMock,
    mock_tenant_repo_cls: MagicMock,
    mock_doc_repo_cls: MagicMock,
    client: TestClient,
) -> None:
    mock_verify.return_value = _mock_auth(tenant_id="acme")
    mock_tenant_repo = MagicMock()
    mock_tenant_repo.get.return_value = {"tenant_id": "acme", "status": "ACTIVE"}
    mock_tenant_repo_cls.return_value = mock_tenant_repo

    mock_doc_repo = MagicMock()
    mock_doc_repo.get.side_effect = NotFound("Document 'doc-missing' not found")
    mock_doc_repo_cls.return_value = mock_doc_repo

    response = client.get(
        "/documents/doc-missing",
        headers={"Authorization": "Bearer valid-token"},
    )
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "not_found"
