from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from qdrant_client import models

from vaultrag.clients.qdrant import (
    assert_tenant_scoped,
    count_by_filter,
    delete_by_filter,
    ensure_collection,
    search,
    set_client,
    set_payload_by_filter,
    upsert_chunks,
)


@pytest.fixture(autouse=True)
def cleanup_qdrant_client() -> None:
    set_client(None)
    yield
    set_client(None)


def test_assert_tenant_scoped_rejections() -> None:
    # 1. None filter
    with pytest.raises(ValueError, match="Filter is required"):
        assert_tenant_scoped(None)

    # 2. Empty Filter
    with pytest.raises(ValueError, match="must contain a tenant_id condition"):
        assert_tenant_scoped(models.Filter())

    # 3. Filter with only other fields
    unscoped_filter = models.Filter(
        must=[
            models.FieldCondition(
                key="doc_id",
                match=models.MatchValue(value="doc-123"),
            )
        ]
    )
    with pytest.raises(ValueError, match="must contain a tenant_id condition"):
        assert_tenant_scoped(unscoped_filter)

    # 4. Unscoped dict filter
    unscoped_dict = {"must": [{"key": "visibility", "match": {"value": "public"}}]}
    with pytest.raises(ValueError, match="must contain a tenant_id condition"):
        assert_tenant_scoped(unscoped_dict)


def test_assert_tenant_scoped_accepts_valid_filters() -> None:
    # 1. models.Filter with tenant_id in must
    valid_filter = models.Filter(
        must=[
            models.FieldCondition(
                key="tenant_id",
                match=models.MatchValue(value="tenant-alpha"),
            )
        ]
    )
    assert_tenant_scoped(valid_filter)

    # 2. dict filter with tenant_id
    valid_dict = {"must": [{"key": "tenant_id", "match": {"value": "tenant-beta"}}]}
    assert_tenant_scoped(valid_dict)


def test_qdrant_functions_enforce_tenant_scoping() -> None:
    unscoped = models.Filter(
        must=[models.FieldCondition(key="doc_id", match=models.MatchValue(value="d1"))]
    )

    with pytest.raises(ValueError, match="must contain a tenant_id condition"):
        search(vector=[0.1] * 768, query_filter=unscoped)

    with pytest.raises(ValueError, match="must contain a tenant_id condition"):
        delete_by_filter(filter=unscoped)

    with pytest.raises(ValueError, match="must contain a tenant_id condition"):
        count_by_filter(filter=unscoped)

    with pytest.raises(ValueError, match="must contain a tenant_id condition"):
        set_payload_by_filter(filter=unscoped, payload={"visibility": "private"})


def test_ensure_collection_and_payload_indexes() -> None:
    mock_client = MagicMock()
    mock_client.collection_exists.return_value = False
    set_client(mock_client)

    ensure_collection("test-collection")

    mock_client.collection_exists.assert_called_once_with("test-collection")
    mock_client.create_collection.assert_called_once()
    # Verified payload index creations for tenant_id and metadata keys
    assert mock_client.create_payload_index.call_count >= 5


def test_upsert_search_count_delete_with_mock() -> None:
    mock_client = MagicMock()
    set_client(mock_client)

    scoped_filter = models.Filter(
        must=[
            models.FieldCondition(
                key="tenant_id",
                match=models.MatchValue(value="tenant-test"),
            )
        ]
    )

    # 1. Upsert
    pts = [models.PointStruct(id=1, vector=[0.1] * 768, payload={"tenant_id": "tenant-test"})]
    upsert_chunks(pts, collection_name="coll-1")
    mock_client.upsert.assert_called_once_with(collection_name="coll-1", points=pts)

    # 2. Count
    mock_client.count.return_value = MagicMock(count=3)
    c = count_by_filter(scoped_filter, collection_name="coll-1")
    assert c == 3

    # 3. Search
    mock_point = MagicMock(id=1, score=0.95)
    mock_client.query_points.return_value = MagicMock(points=[mock_point])
    hits = search([0.1] * 768, query_filter=scoped_filter, limit=5, collection_name="coll-1")
    assert len(hits) == 1
    assert hits[0].score == 0.95

    # 4. Delete
    mock_client.count.return_value = MagicMock(count=2)
    deleted = delete_by_filter(scoped_filter, collection_name="coll-1")
    assert deleted == 2
    mock_client.delete.assert_called_once_with(
        collection_name="coll-1",
        points_selector=scoped_filter,
    )

    # 5. Set payload
    set_payload_by_filter(scoped_filter, {"status": "indexed"}, collection_name="coll-1")
    mock_client.set_payload.assert_called_once_with(
        collection_name="coll-1",
        payload={"status": "indexed"},
        points=scoped_filter,
    )
