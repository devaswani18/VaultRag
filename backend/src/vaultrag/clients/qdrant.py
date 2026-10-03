from __future__ import annotations

import contextlib
import logging
from collections.abc import Sequence
from typing import Any

from qdrant_client import QdrantClient, models

from vaultrag.config import get_secret, get_settings

_QDRANT_CLIENT: QdrantClient | None = None
logger = logging.getLogger(__name__)


def get_client() -> QdrantClient:
    """Build and cache QdrantClient using secrets (REST only, prefer_grpc=False, timeout 20s)."""
    global _QDRANT_CLIENT
    if _QDRANT_CLIENT is not None:
        return _QDRANT_CLIENT

    url = get_secret("qdrant_url")
    api_key = get_secret("qdrant_api_key")

    _QDRANT_CLIENT = QdrantClient(
        url=url,
        api_key=api_key,
        prefer_grpc=False,
        timeout=20.0,
    )
    return _QDRANT_CLIENT


def set_client(client: QdrantClient | None) -> None:
    """Set or reset QdrantClient instance (used in tests)."""
    global _QDRANT_CLIENT
    _QDRANT_CLIENT = client


def _has_tenant_condition(filter_obj: Any) -> bool:
    """Recursively check if a filter contains a condition on tenant_id."""
    if filter_obj is None:
        return False

    # Check dict structure
    if isinstance(filter_obj, dict):
        if filter_obj.get("key") == "tenant_id":
            return True
        for clause in ("must", "should", "must_not", "min_should"):
            items = filter_obj.get(clause)
            if isinstance(items, list) and any(_has_tenant_condition(item) for item in items):
                return True
        return False

    # Check FieldCondition or object with .key attribute
    if hasattr(filter_obj, "key") and filter_obj.key == "tenant_id":
        return True

    # Check models.Filter clauses
    for clause_name in ("must", "should", "must_not"):
        clause = getattr(filter_obj, clause_name, None)
        if clause and isinstance(clause, list):
            for cond in clause:
                if _has_tenant_condition(cond):
                    return True

    return False


def assert_tenant_scoped(filter_obj: Any) -> None:
    """Validate that query/delete/count/payload filter contains a tenant_id condition.

    Raises ValueError if filter is None or unscoped.
    """
    if filter_obj is None:
        raise ValueError("Filter is required and must contain a tenant_id condition")
    if not _has_tenant_condition(filter_obj):
        raise ValueError("Filter must contain a tenant_id condition for tenant isolation")


def ensure_collection(collection_name: str | None = None) -> None:
    """Idempotently create collection and payload indexes."""
    client = get_client()
    settings = get_settings()
    target_collection = collection_name or settings.qdrant_collection

    if not client.collection_exists(target_collection):
        client.create_collection(
            collection_name=target_collection,
            vectors_config=models.VectorParams(
                size=settings.embedding_dim,
                distance=models.Distance.COSINE,
            ),
        )

    # 1. tenant_id index (with is_tenant=True where supported)
    try:
        client.create_payload_index(
            collection_name=target_collection,
            field_name="tenant_id",
            field_schema=models.KeywordIndexParams(type="keyword", is_tenant=True),
        )
    except Exception:
        with contextlib.suppress(Exception):
            client.create_payload_index(
                collection_name=target_collection,
                field_name="tenant_id",
                field_schema=models.PayloadSchemaType.KEYWORD,
            )

    # 2. Other keyword payload indexes
    keyword_fields = [
        "doc_id",
        "visibility",
        "allowed_roles",
        "allowed_users",
        "owner_user_id",
        "selftest_run_id",
    ]
    for field in keyword_fields:
        with contextlib.suppress(Exception):
            client.create_payload_index(
                collection_name=target_collection,
                field_name=field,
                field_schema=models.PayloadSchemaType.KEYWORD,
            )


def upsert_chunks(
    points: Sequence[models.PointStruct],
    collection_name: str | None = None,
) -> models.UpdateResult:
    """Upsert chunk points into Qdrant."""
    client = get_client()
    settings = get_settings()
    target_collection = collection_name or settings.qdrant_collection
    return client.upsert(collection_name=target_collection, points=points)


def count_by_filter(
    filter: models.Filter | dict[str, Any],
    collection_name: str | None = None,
) -> int:
    """Count points matching a tenant-scoped filter."""
    assert_tenant_scoped(filter)
    client = get_client()
    settings = get_settings()
    target_collection = collection_name or settings.qdrant_collection
    res = client.count(collection_name=target_collection, count_filter=filter, exact=True)
    return res.count


def search(
    vector: list[float],
    query_filter: models.Filter | dict[str, Any],
    limit: int = 10,
    score_threshold: float | None = None,
    collection_name: str | None = None,
) -> list[models.ScoredPoint]:
    """Search points by vector with mandatory tenant-scoped filter."""
    assert_tenant_scoped(query_filter)
    client = get_client()
    settings = get_settings()
    target_collection = collection_name or settings.qdrant_collection

    if hasattr(client, "query_points"):
        res = client.query_points(
            collection_name=target_collection,
            query=vector,
            query_filter=query_filter,
            limit=limit,
            score_threshold=score_threshold,
            with_payload=True,
        )
        return list(res.points)

    return client.search(
        collection_name=target_collection,
        query_vector=vector,
        query_filter=query_filter,
        limit=limit,
        score_threshold=score_threshold,
        with_payload=True,
    )


def delete_by_filter(
    filter: models.Filter | dict[str, Any],
    collection_name: str | None = None,
) -> int:
    """Delete points matching a tenant-scoped filter and return count before delete."""
    assert_tenant_scoped(filter)
    count = count_by_filter(filter, collection_name=collection_name)
    if count > 0:
        client = get_client()
        settings = get_settings()
        target_collection = collection_name or settings.qdrant_collection
        client.delete(collection_name=target_collection, points_selector=filter)
    return count


def set_payload_by_filter(
    filter: models.Filter | dict[str, Any],
    payload: dict[str, Any],
    collection_name: str | None = None,
) -> models.UpdateResult:
    """Set payload on points matching a tenant-scoped filter."""
    assert_tenant_scoped(filter)
    client = get_client()
    settings = get_settings()
    target_collection = collection_name or settings.qdrant_collection
    return client.set_payload(
        collection_name=target_collection,
        payload=payload,
        points=filter,
    )
