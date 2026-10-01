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
from vaultrag.context import RequestContext, Role
from vaultrag.security.acl import build_doc_filter, build_filter

COLLECTION_NAME = "vaultrag_chunks"
VECTOR_DIM = 4


@pytest.fixture(autouse=True)
def clean_cache() -> None:
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
    sub: str = "user-1",
    tenant_id: str = "tenant-a",
    roles: frozenset[Role] | None = None,
) -> Claims:
    return Claims(
        sub=sub,
        email="test@example.com",
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
    owner_user_id: str = "owner-1",
    filename: str = "test.pdf",
    text: str = "sample text",
) -> None:
    point = models.PointStruct(
        id=str(uuid.uuid5(uuid.NAMESPACE_DNS, chunk_id)),
        vector=[0.1, 0.2, 0.3, 0.4],
        payload={
            "chunk_id": chunk_id,
            "tenant_id": tenant_id,
            "doc_id": doc_id,
            "filename": filename,
            "text": text,
            "visibility": visibility,
            "allowed_roles": allowed_roles or [],
            "allowed_users": allowed_users or [],
            "owner_user_id": owner_user_id,
        },
    )
    client.upsert(collection_name=COLLECTION_NAME, points=[point])


# ------------------------------------------------------------------------------
# 1. intern cannot retrieve a manager-only doc
# ------------------------------------------------------------------------------
def test_intern_cannot_retrieve_manager_doc(memory_qdrant: QdrantClient) -> None:
    _seed_chunk(
        memory_qdrant,
        chunk_id="chunk_mgr_1",
        tenant_id="tenant-a",
        doc_id="doc_mgr_secret",
        visibility="roles",
        allowed_roles=["manager"],
        owner_user_id="user-manager",
    )

    intern_ctx = RequestContext(
        request_id="req-1",
        tenant_id="tenant-a",
        user_id="user-intern",
        roles=frozenset([Role.intern]),
    )
    filt = build_filter(intern_ctx)
    res = memory_qdrant.query_points(
        collection_name=COLLECTION_NAME,
        query=[0.1, 0.2, 0.3, 0.4],
        query_filter=filt,
    ).points
    assert len(res) == 0

    # But manager CAN retrieve it
    manager_ctx = RequestContext(
        request_id="req-2",
        tenant_id="tenant-a",
        user_id="user-other-mgr",
        roles=frozenset([Role.manager]),
    )
    res_mgr = memory_qdrant.query_points(
        collection_name=COLLECTION_NAME,
        query=[0.1, 0.2, 0.3, 0.4],
        query_filter=build_filter(manager_ctx),
    ).points
    assert len(res_mgr) == 1
    assert res_mgr[0].payload["chunk_id"] == "chunk_mgr_1"


# ------------------------------------------------------------------------------
# 2. tenant B never retrieves tenant A chunks (even identical doc_id and filename)
# ------------------------------------------------------------------------------
def test_cross_tenant_isolation_identical_doc_id(memory_qdrant: QdrantClient) -> None:
    _seed_chunk(
        memory_qdrant,
        chunk_id="chunk_a_1",
        tenant_id="tenant-a",
        doc_id="doc_dup_100",
        filename="financials.pdf",
        visibility="tenant",
    )
    _seed_chunk(
        memory_qdrant,
        chunk_id="chunk_b_1",
        tenant_id="tenant-b",
        doc_id="doc_dup_100",
        filename="financials.pdf",
        visibility="tenant",
    )

    ctx_b = RequestContext(
        request_id="req-b",
        tenant_id="tenant-b",
        user_id="user-b",
        roles=frozenset([Role.admin]),
    )
    res_b = memory_qdrant.query_points(
        collection_name=COLLECTION_NAME,
        query=[0.1, 0.2, 0.3, 0.4],
        query_filter=build_filter(ctx_b),
    ).points

    assert len(res_b) == 1
    assert res_b[0].payload["chunk_id"] == "chunk_b_1"
    assert res_b[0].payload["tenant_id"] == "tenant-b"


# ------------------------------------------------------------------------------
# 3. private doc visible only to owner and admin
# ------------------------------------------------------------------------------
def test_private_doc_visible_only_to_owner_and_admin(memory_qdrant: QdrantClient) -> None:
    _seed_chunk(
        memory_qdrant,
        chunk_id="chunk_priv_1",
        tenant_id="tenant-a",
        doc_id="doc_priv_1",
        visibility="private",
        allowed_roles=[],
        allowed_users=[],
        owner_user_id="user-owner-bob",
    )

    # Bob (owner)
    bob_ctx = RequestContext(
        request_id="req-bob",
        tenant_id="tenant-a",
        user_id="user-owner-bob",
        roles=frozenset([Role.employee]),
    )
    res_bob = memory_qdrant.query_points(
        collection_name=COLLECTION_NAME,
        query=[0.1, 0.2, 0.3, 0.4],
        query_filter=build_filter(bob_ctx),
    ).points
    assert len(res_bob) == 1

    # Tenant Admin
    admin_ctx = RequestContext(
        request_id="req-admin",
        tenant_id="tenant-a",
        user_id="user-admin",
        roles=frozenset([Role.admin]),
    )
    res_admin = memory_qdrant.query_points(
        collection_name=COLLECTION_NAME,
        query=[0.1, 0.2, 0.3, 0.4],
        query_filter=build_filter(admin_ctx),
    ).points
    assert len(res_admin) == 1

    # Another employee (non-owner)
    charlie_ctx = RequestContext(
        request_id="req-charlie",
        tenant_id="tenant-a",
        user_id="user-charlie",
        roles=frozenset([Role.employee]),
    )
    res_charlie = memory_qdrant.query_points(
        collection_name=COLLECTION_NAME,
        query=[0.1, 0.2, 0.3, 0.4],
        query_filter=build_filter(charlie_ctx),
    ).points
    assert len(res_charlie) == 0


# ------------------------------------------------------------------------------
# 4. allowed_users grants access
# ------------------------------------------------------------------------------
def test_allowed_users_grants_access(memory_qdrant: QdrantClient) -> None:
    _seed_chunk(
        memory_qdrant,
        chunk_id="chunk_collab_1",
        tenant_id="tenant-a",
        doc_id="doc_collab_1",
        visibility="private",
        allowed_roles=[],
        allowed_users=["user-invited-dave"],
        owner_user_id="user-alice",
    )

    dave_ctx = RequestContext(
        request_id="req-dave",
        tenant_id="tenant-a",
        user_id="user-invited-dave",
        roles=frozenset([Role.intern]),  # even as an intern
    )
    res = memory_qdrant.query_points(
        collection_name=COLLECTION_NAME,
        query=[0.1, 0.2, 0.3, 0.4],
        query_filter=build_filter(dave_ctx),
    ).points
    assert len(res) == 1
    assert res[0].payload["chunk_id"] == "chunk_collab_1"


# ------------------------------------------------------------------------------
# 5. ACL change takes effect on the very next query
# ------------------------------------------------------------------------------
def test_acl_change_takes_effect_immediately(memory_qdrant: QdrantClient) -> None:
    _seed_chunk(
        memory_qdrant,
        chunk_id="chunk_dynamic_1",
        tenant_id="tenant-a",
        doc_id="doc_dyn_1",
        visibility="private",
        allowed_roles=[],
        allowed_users=[],
        owner_user_id="user-alice",
    )

    bob_ctx = RequestContext(
        request_id="req-bob",
        tenant_id="tenant-a",
        user_id="user-bob",
        roles=frozenset([Role.employee]),
    )

    # 1. Before update: Bob cannot see it
    res1 = memory_qdrant.query_points(
        collection_name=COLLECTION_NAME,
        query=[0.1, 0.2, 0.3, 0.4],
        query_filter=build_filter(bob_ctx),
    ).points
    assert len(res1) == 0

    # 2. Update ACL in Qdrant (simulate PATCH /documents/doc_dyn_1/acl)
    from vaultrag.clients.qdrant import set_payload_by_filter

    doc_filter = models.Filter(
        must=[
            models.FieldCondition(key="tenant_id", match=models.MatchValue(value="tenant-a")),
            models.FieldCondition(key="doc_id", match=models.MatchValue(value="doc_dyn_1")),
        ]
    )
    set_payload_by_filter(
        filter=doc_filter,
        payload={"visibility": "tenant", "allowed_roles": [], "allowed_users": []},
    )

    # 3. Next query immediately retrieves the chunk
    res2 = memory_qdrant.query_points(
        collection_name=COLLECTION_NAME,
        query=[0.1, 0.2, 0.3, 0.4],
        query_filter=build_filter(bob_ctx),
    ).points
    assert len(res2) == 1
    assert res2[0].payload["chunk_id"] == "chunk_dynamic_1"


# ------------------------------------------------------------------------------
# 6. build_filter failure path matches nothing (fail-closed)
# ------------------------------------------------------------------------------
def test_build_filter_failure_path_fail_closed(memory_qdrant: QdrantClient) -> None:
    _seed_chunk(
        memory_qdrant,
        chunk_id="chunk_safe_1",
        tenant_id="tenant-a",
        doc_id="doc_safe_1",
        visibility="tenant",
    )

    # Malformed context with invalid tenant_id
    bad_ctx = MagicMock()
    bad_ctx.tenant_id = None
    bad_ctx.user_id = "user-1"
    bad_ctx.is_admin = False

    filter_fail = build_filter(bad_ctx)
    assert filter_fail.must is not None
    # Tenant must be __none__
    assert any(
        getattr(cond, "key", None) == "tenant_id" and cond.match.value == "__none__"
        for cond in filter_fail.must
    )

    # Searching with this filter returns nothing
    res = memory_qdrant.query_points(
        collection_name=COLLECTION_NAME,
        query=[0.1, 0.2, 0.3, 0.4],
        query_filter=filter_fail,
    ).points
    assert len(res) == 0


# ------------------------------------------------------------------------------
# 7. build_doc_filter restricts to specific doc_id
# ------------------------------------------------------------------------------
def test_build_doc_filter_restricts_to_doc_id(memory_qdrant: QdrantClient) -> None:
    _seed_chunk(
        memory_qdrant,
        chunk_id="chunk_doc_a",
        tenant_id="tenant-a",
        doc_id="doc_a",
        visibility="tenant",
    )
    _seed_chunk(
        memory_qdrant,
        chunk_id="chunk_doc_b",
        tenant_id="tenant-a",
        doc_id="doc_b",
        visibility="tenant",
    )

    ctx = RequestContext(
        request_id="req-1",
        tenant_id="tenant-a",
        user_id="user-1",
        roles=frozenset([Role.employee]),
    )

    filt = build_doc_filter(ctx, "doc_a")
    res = memory_qdrant.query_points(
        collection_name=COLLECTION_NAME,
        query=[0.1, 0.2, 0.3, 0.4],
        query_filter=filt,
    ).points
    assert len(res) == 1
    assert res[0].payload["chunk_id"] == "chunk_doc_a"


# ------------------------------------------------------------------------------
# 8. API ACL: List hides docs, direct fetch 404s, PATCH ACL permissions & unknown fields
# ------------------------------------------------------------------------------
@patch("vaultrag.api.routers.documents.DocumentRepo")
@patch("vaultrag.auth.dependencies.TenantRepo")
@patch("vaultrag.auth.dependencies.verify_id_token")
def test_document_list_hides_inaccessible_docs(
    mock_verify: MagicMock,
    mock_tenant_repo_cls: MagicMock,
    mock_doc_repo_cls: MagicMock,
    client: TestClient,
) -> None:
    mock_verify.return_value = _mock_claims(
        sub="user-bob", tenant_id="tenant-a", roles=frozenset([Role.employee])
    )
    mock_tenant = MagicMock()
    mock_tenant.get.return_value = {"tenant_id": "tenant-a", "status": "ACTIVE"}
    mock_tenant_repo_cls.return_value = mock_tenant

    mock_doc_repo = MagicMock()
    mock_doc_repo.list_for_tenant.return_value = (
        [
            {
                "tenant_id": "tenant-a",
                "doc_id": "doc-public",
                "visibility": "tenant",
                "owner_user_id": "user-alice",
            },
            {
                "tenant_id": "tenant-a",
                "doc_id": "doc-secret",
                "visibility": "private",
                "owner_user_id": "user-alice",  # Bob is not owner/allowed
                "allowed_users": [],
            },
        ],
        None,
    )
    mock_doc_repo_cls.return_value = mock_doc_repo

    resp = client.get("/documents", headers={"Authorization": "Bearer valid-token"})
    assert resp.status_code == 200
    docs = resp.json()
    assert len(docs) == 1
    assert docs[0]["id"] == "doc-public"


@patch("vaultrag.api.routers.documents.DocumentRepo")
@patch("vaultrag.auth.dependencies.TenantRepo")
@patch("vaultrag.auth.dependencies.verify_id_token")
def test_direct_fetch_inaccessible_doc_returns_404(
    mock_verify: MagicMock,
    mock_tenant_repo_cls: MagicMock,
    mock_doc_repo_cls: MagicMock,
    client: TestClient,
) -> None:
    mock_verify.return_value = _mock_claims(
        sub="user-bob", tenant_id="tenant-a", roles=frozenset([Role.employee])
    )
    mock_tenant = MagicMock()
    mock_tenant.get.return_value = {"tenant_id": "tenant-a", "status": "ACTIVE"}
    mock_tenant_repo_cls.return_value = mock_tenant

    mock_doc_repo = MagicMock()
    mock_doc_repo.get.return_value = {
        "tenant_id": "tenant-a",
        "doc_id": "doc-secret",
        "visibility": "private",
        "owner_user_id": "user-alice",
        "allowed_users": [],
    }
    mock_doc_repo_cls.return_value = mock_doc_repo

    resp = client.get("/documents/doc-secret", headers={"Authorization": "Bearer valid-token"})
    assert resp.status_code == 404
    assert resp.json()["error"]["code"] == "not_found"


@patch("vaultrag.api.routers.documents.DocumentRepo")
@patch("vaultrag.auth.dependencies.TenantRepo")
@patch("vaultrag.auth.dependencies.verify_id_token")
def test_non_owner_non_admin_cannot_patch_acl(
    mock_verify: MagicMock,
    mock_tenant_repo_cls: MagicMock,
    mock_doc_repo_cls: MagicMock,
    client: TestClient,
) -> None:
    mock_verify.return_value = _mock_claims(
        sub="user-charlie", tenant_id="tenant-a", roles=frozenset([Role.employee])
    )
    mock_tenant = MagicMock()
    mock_tenant.get.return_value = {"tenant_id": "tenant-a", "status": "ACTIVE"}
    mock_tenant_repo_cls.return_value = mock_tenant

    mock_doc_repo = MagicMock()
    mock_doc_repo.get.return_value = {
        "tenant_id": "tenant-a",
        "doc_id": "doc-alice-file",
        "visibility": "tenant",
        "owner_user_id": "user-alice",
    }
    mock_doc_repo_cls.return_value = mock_doc_repo

    resp = client.patch(
        "/documents/doc-alice-file/acl",
        json={"visibility": "private"},
        headers={"Authorization": "Bearer valid-token"},
    )
    assert resp.status_code == 403
    assert resp.json()["error"]["code"] == "forbidden"


@patch("vaultrag.api.routers.documents.DocumentRepo")
@patch("vaultrag.auth.dependencies.TenantRepo")
@patch("vaultrag.auth.dependencies.verify_id_token")
def test_hidden_document_patch_acl_by_non_owner_returns_404(
    mock_verify: MagicMock,
    mock_tenant_repo_cls: MagicMock,
    mock_doc_repo_cls: MagicMock,
    client: TestClient,
) -> None:
    """Hidden document returns 404, not 403, on PATCH-ACL by non-owners to prevent revealing existence."""
    mock_verify.return_value = _mock_claims(
        sub="user-bob", tenant_id="tenant-a", roles=frozenset([Role.employee])
    )
    mock_tenant = MagicMock()
    mock_tenant.get.return_value = {"tenant_id": "tenant-a", "status": "ACTIVE"}
    mock_tenant_repo_cls.return_value = mock_tenant

    mock_doc_repo = MagicMock()
    mock_doc_repo.get.return_value = {
        "tenant_id": "tenant-a",
        "doc_id": "doc-secret",
        "visibility": "private",
        "owner_user_id": "user-alice",
        "allowed_users": [],
    }
    mock_doc_repo_cls.return_value = mock_doc_repo

    resp = client.patch(
        "/documents/doc-secret/acl",
        json={"visibility": "tenant"},
        headers={"Authorization": "Bearer valid-token"},
    )
    assert resp.status_code == 404
    assert resp.json()["error"]["code"] == "not_found"


@patch("vaultrag.api.routers.documents.TenantRepo")
@patch("vaultrag.api.routers.documents.qdrant_client.set_payload_by_filter")
@patch("vaultrag.api.routers.documents.DocumentRepo")
@patch("vaultrag.auth.dependencies.TenantRepo")
@patch("vaultrag.auth.dependencies.verify_id_token")
def test_owner_can_patch_acl_and_bumps_kb_version(
    mock_verify: MagicMock,
    mock_auth_tenant_repo_cls: MagicMock,
    mock_doc_repo_cls: MagicMock,
    mock_set_payload: MagicMock,
    mock_tenant_repo_cls: MagicMock,
    client: TestClient,
) -> None:
    mock_verify.return_value = _mock_claims(
        sub="user-alice", tenant_id="tenant-a", roles=frozenset([Role.employee])
    )
    mock_auth_tenant = MagicMock()
    mock_auth_tenant.get.return_value = {"tenant_id": "tenant-a", "status": "ACTIVE"}
    mock_auth_tenant_repo_cls.return_value = mock_auth_tenant

    mock_doc_repo = MagicMock()
    mock_doc_repo.get.return_value = {
        "tenant_id": "tenant-a",
        "doc_id": "doc-alice-file",
        "visibility": "tenant",
        "owner_user_id": "user-alice",
    }
    mock_doc_repo.update_acl.return_value = {
        "tenant_id": "tenant-a",
        "doc_id": "doc-alice-file",
        "visibility": "roles",
        "allowed_roles": ["manager"],
        "allowed_users": [],
    }
    mock_doc_repo_cls.return_value = mock_doc_repo

    mock_tenant_repo = MagicMock()
    mock_tenant_repo_cls.return_value = mock_tenant_repo

    resp = client.patch(
        "/documents/doc-alice-file/acl",
        json={"visibility": "roles", "allowed_roles": ["manager"], "allowed_users": []},
        headers={"Authorization": "Bearer valid-token"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["visibility"] == "roles"
    assert data["allowed_roles"] == ["manager"]

    # Verify DynamoDB update_acl called
    mock_doc_repo.update_acl.assert_called_once_with(
        tenant_id="tenant-a",
        doc_id="doc-alice-file",
        visibility="roles",
        allowed_roles=["manager"],
        allowed_users=[],
    )

    # Verify Qdrant payload updated
    mock_set_payload.assert_called_once()
    payload_args = mock_set_payload.call_args[1]
    assert payload_args["payload"] == {
        "visibility": "roles",
        "allowed_roles": ["manager"],
        "allowed_users": [],
    }

    # Verify kb_version bumped
    mock_tenant_repo.bump_kb_version.assert_called_once_with("tenant-a")


@patch("vaultrag.auth.dependencies.TenantRepo")
@patch("vaultrag.auth.dependencies.verify_id_token")
def test_patch_acl_rejects_unknown_fields(
    mock_verify: MagicMock,
    mock_tenant_repo_cls: MagicMock,
    client: TestClient,
) -> None:
    mock_verify.return_value = _mock_claims()
    mock_tenant = MagicMock()
    mock_tenant.get.return_value = {"tenant_id": "tenant-a", "status": "ACTIVE"}
    mock_tenant_repo_cls.return_value = mock_tenant

    resp = client.patch(
        "/documents/doc-1/acl",
        json={"visibility": "tenant", "unknown_field": "injected"},
        headers={"Authorization": "Bearer valid-token"},
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "validation_failed"


@patch("vaultrag.api.routers.documents.create_presigned_post")
@patch("vaultrag.api.routers.documents.DocumentRepo")
@patch("vaultrag.auth.dependencies.TenantRepo")
@patch("vaultrag.auth.dependencies.verify_id_token")
def test_create_private_doc_defaults_allowed_users_to_empty(
    mock_verify: MagicMock,
    mock_tenant_repo_cls: MagicMock,
    mock_doc_repo_cls: MagicMock,
    mock_presigned: MagicMock,
    client: TestClient,
) -> None:
    mock_verify.return_value = _mock_claims(sub="usr-tester", tenant_id="tenant-a")
    mock_tenant = MagicMock()
    mock_tenant.get.return_value = {"tenant_id": "tenant-a", "status": "ACTIVE"}
    mock_tenant_repo_cls.return_value = mock_tenant

    mock_doc_repo = MagicMock()
    mock_doc_repo_cls.return_value = mock_doc_repo

    mock_presigned.return_value = {
        "url": "https://s3.example.com",
        "fields": {"key": "key"},
    }

    resp = client.post(
        "/documents",
        json={
            "filename": "private_note.pdf",
            "content_type": "application/pdf",
            "size_bytes": 100,
            "visibility": "private",
        },
        headers={"Authorization": "Bearer valid-token"},
    )
    assert resp.status_code == 200

    create_args = mock_doc_repo.create.call_args[1]
    assert create_args["visibility"] == "private"
    assert create_args["allowed_users"] == []
