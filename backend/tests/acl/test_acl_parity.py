from __future__ import annotations

import itertools
import uuid

import pytest
from qdrant_client import QdrantClient, models

from vaultrag.context import RequestContext, Role
from vaultrag.security.acl import build_filter, can_view

COLLECTION_NAME = "test_chunks_acl_parity"
VECTOR_DIM = 4


@pytest.fixture(scope="module")
def qdrant_memory() -> tuple[QdrantClient, list[dict]]:
    client = QdrantClient(":memory:")
    client.create_collection(
        collection_name=COLLECTION_NAME,
        vectors_config=models.VectorParams(
            size=VECTOR_DIM,
            distance=models.Distance.COSINE,
        ),
    )

    # Keyword payload indexes
    for field in [
        "tenant_id",
        "doc_id",
        "visibility",
        "allowed_roles",
        "allowed_users",
        "owner_user_id",
    ]:
        client.create_payload_index(
            collection_name=COLLECTION_NAME,
            field_name=field,
            field_schema=models.PayloadSchemaType.KEYWORD,
        )

    # 2 Tenants: tenant_a, tenant_b
    # 3 Visibilities: tenant, roles, private
    # Mixed roles: manager, intern, member
    # Mixed users: user_alice, user_bob, user_charlie
    corpus = [
        # --- Tenant A ---
        # 1. Tenant A - visibility: tenant
        {
            "chunk_id": "c_a_tenant_1",
            "tenant_id": "tenant-a",
            "doc_id": "doc_shared_1",
            "filename": "shared_policy.pdf",
            "visibility": "tenant",
            "allowed_roles": [],
            "allowed_users": [],
            "owner_user_id": "user_alice",
            "text": "Tenant A public policy",
        },
        # 2. Tenant A - visibility: roles (manager)
        {
            "chunk_id": "c_a_roles_manager_1",
            "tenant_id": "tenant-a",
            "doc_id": "doc_manager_review",
            "filename": "manager_notes.pdf",
            "visibility": "roles",
            "allowed_roles": ["manager"],
            "allowed_users": [],
            "owner_user_id": "user_bob",
            "text": "Tenant A manager only review",
        },
        # 3. Tenant A - visibility: roles (intern)
        {
            "chunk_id": "c_a_roles_intern_1",
            "tenant_id": "tenant-a",
            "doc_id": "doc_intern_guide",
            "filename": "intern_guide.pdf",
            "visibility": "roles",
            "allowed_roles": ["intern"],
            "allowed_users": [],
            "owner_user_id": "user_charlie",
            "text": "Tenant A intern orientation",
        },
        # 4. Tenant A - visibility: private (owner: user_alice)
        {
            "chunk_id": "c_a_private_alice",
            "tenant_id": "tenant-a",
            "doc_id": "doc_alice_private",
            "filename": "alice_secret.pdf",
            "visibility": "private",
            "allowed_roles": [],
            "allowed_users": [],
            "owner_user_id": "user_alice",
            "text": "Tenant A Alice private document",
        },
        # 5. Tenant A - visibility: private (owner: user_bob, allowed_users: [user_charlie])
        {
            "chunk_id": "c_a_private_bob_charlie",
            "tenant_id": "tenant-a",
            "doc_id": "doc_bob_collab",
            "filename": "collab_charlie.pdf",
            "visibility": "private",
            "allowed_roles": [],
            "allowed_users": ["user_charlie"],
            "owner_user_id": "user_bob",
            "text": "Tenant A Bob and Charlie collaboration",
        },
        # --- Tenant B ---
        # 6. Tenant B - visibility: tenant (identically named doc_id as in Tenant A)
        {
            "chunk_id": "c_b_tenant_1",
            "tenant_id": "tenant-b",
            "doc_id": "doc_shared_1",
            "filename": "shared_policy.pdf",
            "visibility": "tenant",
            "allowed_roles": [],
            "allowed_users": [],
            "owner_user_id": "user_alice",
            "text": "Tenant B public policy",
        },
        # 7. Tenant B - visibility: roles (manager)
        {
            "chunk_id": "c_b_roles_manager_1",
            "tenant_id": "tenant-b",
            "doc_id": "doc_manager_review",
            "filename": "manager_notes.pdf",
            "visibility": "roles",
            "allowed_roles": ["manager"],
            "allowed_users": [],
            "owner_user_id": "user_bob",
            "text": "Tenant B manager review",
        },
        # 8. Tenant B - visibility: private (owner: user_bob, allowed_users: [])
        {
            "chunk_id": "c_b_private_bob",
            "tenant_id": "tenant-b",
            "doc_id": "doc_b_private",
            "filename": "bob_b_private.pdf",
            "visibility": "private",
            "allowed_roles": [],
            "allowed_users": [],
            "owner_user_id": "user_bob",
            "text": "Tenant B Bob private",
        },
        # 9. Tenant B - visibility: private (owner: user_alice, allowed_users: [user_bob])
        {
            "chunk_id": "c_b_private_alice_bob",
            "tenant_id": "tenant-b",
            "doc_id": "doc_b_alice_bob",
            "filename": "alice_b_collab.pdf",
            "visibility": "private",
            "allowed_roles": [],
            "allowed_users": ["user_bob"],
            "owner_user_id": "user_alice",
            "text": "Tenant B Alice and Bob collaboration",
        },
    ]

    points = [
        models.PointStruct(
            id=str(uuid.uuid5(uuid.NAMESPACE_DNS, item["chunk_id"])),
            vector=[0.1, 0.2, 0.3, 0.4],
            payload=item,
        )
        for item in corpus
    ]
    client.upsert(collection_name=COLLECTION_NAME, points=points)

    return client, corpus


def test_acl_parity_property_test(qdrant_memory: tuple[QdrantClient, list[dict]]) -> None:
    """Property/parity test: for all (tenant, role set, user) combinations,

    asserts that the chunk IDs returned by real Qdrant search with build_filter
    equals the set predicted by pure-Python can_view.
    """
    client, corpus = qdrant_memory

    tenants = ["tenant-a", "tenant-b"]
    role_combinations = [
        frozenset([Role.admin]),
        frozenset([Role.manager]),
        frozenset([Role.intern]),
        frozenset([Role.employee]),
        frozenset([Role.manager, Role.intern]),
        frozenset([Role.employee, Role.intern]),
    ]
    users = ["user_alice", "user_bob", "user_charlie", "user_dave", "user_outsider"]

    total_scenarios = 0
    for tenant_id, roles, user_id in itertools.product(tenants, role_combinations, users):
        ctx = RequestContext(
            request_id=f"req-{total_scenarios}",
            tenant_id=tenant_id,
            user_id=user_id,
            roles=roles,
        )

        # 1. Predict with pure-Python can_view
        expected_chunk_ids = {item["chunk_id"] for item in corpus if can_view(ctx, item)}

        # 2. Query Qdrant with build_filter(ctx)
        qdrant_filter = build_filter(ctx)
        query_res = client.query_points(
            collection_name=COLLECTION_NAME,
            query=[0.1, 0.2, 0.3, 0.4],
            query_filter=qdrant_filter,
            limit=50,
            with_payload=True,
        )
        actual_chunk_ids = {p.payload["chunk_id"] for p in query_res.points}

        assert actual_chunk_ids == expected_chunk_ids, (
            f"Parity mismatch for tenant={tenant_id}, roles={[r.value for r in roles]}, "
            f"user={user_id}. Diff extra in Qdrant: {actual_chunk_ids - expected_chunk_ids}, "
            f"Missing from Qdrant: {expected_chunk_ids - actual_chunk_ids}"
        )
        total_scenarios += 1

    # Ensure a substantial property test space was evaluated
    assert total_scenarios == 2 * len(role_combinations) * len(users)
    assert total_scenarios == 60
