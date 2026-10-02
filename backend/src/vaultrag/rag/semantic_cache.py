"""Semantic query caching layer built on Qdrant.

Implements role-scoped, tenant-isolated vector caching for grounded query answers.
Enforces TTL, kb_version cache-busting, zero storage of private/user-restricted chunks,
and document-level eviction for verifiable erasure.
"""

from __future__ import annotations

import contextlib
import copy
import hashlib
import logging
import time
import uuid
from typing import Any

from qdrant_client import QdrantClient, models

from vaultrag.clients.qdrant import get_client
from vaultrag.config import get_settings
from vaultrag.context import RequestContext
from vaultrag.rag.retrieve import RetrievedChunk

logger = logging.getLogger(__name__)


def ensure_cache_collection(client: QdrantClient) -> None:
    """Ensure that the Qdrant semantic cache collection and payload indexes exist."""
    settings = get_settings()
    collection_name = settings.cache_collection
    try:
        existing = [c.name for c in client.get_collections().collections]
    except Exception:
        existing = []

    if collection_name not in existing:
        client.create_collection(
            collection_name=collection_name,
            vectors_config=models.VectorParams(
                size=settings.embedding_dim,
                distance=models.Distance.COSINE,
            ),
        )
        for field in ("tenant_id", "scope_key", "doc_ids"):
            with contextlib.suppress(Exception):
                client.create_payload_index(
                    collection_name=collection_name,
                    field_name=field,
                    field_schema=models.PayloadSchemaType.KEYWORD,
                )


def compute_scope_key(ctx: RequestContext) -> str:
    """Derive deterministic hash representing caller's tenant boundary and role permissions.

    scope_key = sha256(f"{tenant_id}|{','.join(sorted(role_names))}")
    """
    if hasattr(ctx, "roles") and ctx.roles:
        role_names = sorted(r.value for r in ctx.roles)
    elif hasattr(ctx, "role"):
        role_names = [ctx.role.value if hasattr(ctx.role, "value") else str(ctx.role)]
    else:
        role_names = ["employee"]

    raw_scope = f"{ctx.tenant_id}|{','.join(role_names)}"
    return hashlib.sha256(raw_scope.encode("utf-8")).hexdigest()


def lookup(
    ctx: RequestContext,
    question_vector: list[float],
    kb_version: int,
    *,
    qdrant_client: Any = None,
    similarity_threshold: float | None = None,
) -> dict[str, Any] | None:
    """Search semantic cache for an identical/paraphrased answer matching caller's scope.

    Checks:
    - tenant_id AND scope_key exact match
    - similarity >= threshold (default 0.95)
    - entry not expired (TTL)
    - kb_version equality (knowledge base freshness)

    Returns the cached response dict with cached=True, or None on cache miss.
    """
    settings = get_settings()
    threshold = (
        similarity_threshold
        if similarity_threshold is not None
        else settings.cache_similarity_threshold
    )
    client = qdrant_client or get_client()
    ensure_cache_collection(client)

    scope = compute_scope_key(ctx)
    cache_filter = models.Filter(
        must=[
            models.FieldCondition(key="tenant_id", match=models.MatchValue(value=ctx.tenant_id)),
            models.FieldCondition(key="scope_key", match=models.MatchValue(value=scope)),
        ]
    )

    try:
        if hasattr(client, "query_points"):
            res = client.query_points(
                collection_name=settings.cache_collection,
                query=question_vector,
                query_filter=cache_filter,
                limit=1,
                score_threshold=threshold,
                with_payload=True,
            )
            hits = list(res.points)
        else:
            hits = client.search(
                collection_name=settings.cache_collection,
                query_vector=question_vector,
                query_filter=cache_filter,
                limit=1,
                score_threshold=threshold,
            )
    except Exception as e:
        logger.warning("Semantic cache lookup failed: %s", e)
        return None

    if not hits:
        return None

    top_hit = hits[0]
    payload = top_hit.payload or {}

    # 1. TTL Check
    expires_at = int(payload.get("expires_at", 0))
    if expires_at <= int(time.time()):
        logger.info("Semantic cache miss: entry expired for tenant=%s", ctx.tenant_id)
        return None

    # 2. Knowledge base freshness check (kb_version equality)
    entry_kb_version = int(payload.get("kb_version", -1))
    if entry_kb_version != kb_version:
        logger.info(
            "Semantic cache miss: kb_version mismatch (cached=%d, current=%d)",
            entry_kb_version,
            kb_version,
        )
        return None

    cached_response = copy.deepcopy(payload.get("response", {}))
    cached_response["cached"] = True
    cached_response["request_id"] = ctx.request_id
    return cached_response


def store(
    ctx: RequestContext,
    question_vector: list[float],
    response: dict[str, Any],
    source_chunks: list[RetrievedChunk],
    kb_version: int,
    *,
    qdrant_client: Any = None,
) -> bool:
    """Store grounded, non-private query response in the semantic cache.

    Write rules:
    - Never store if response is abstained or partial.
    - Never store if answer used any chunk with visibility='private' or non-empty allowed_users.
    - Store only the PII-redacted response JSON, doc_ids, scope_key, and TTL (24h).
    """
    trust = response.get("trust", {})
    if trust.get("abstained") or trust.get("partial"):
        logger.info("Semantic cache skipping store: response is abstained or partial")
        return False

    # Check chunks for user-level restrictions
    for chunk in source_chunks:
        vis = getattr(chunk, "visibility", "tenant")
        users = getattr(chunk, "allowed_users", [])
        if vis == "private" or bool(users):
            logger.info(
                "Semantic cache skipping store: response contains private or user-restricted chunk"
            )
            return False

    settings = get_settings()
    client = qdrant_client or get_client()
    ensure_cache_collection(client)

    scope = compute_scope_key(ctx)
    expires_at = int(time.time()) + 86400  # 24h TTL

    # Collect unique doc_ids
    doc_ids = sorted(
        {
            str(s.get("doc_id"))
            for s in response.get("sources", [])
            if isinstance(s, dict) and s.get("doc_id")
        }
        or {str(c.doc_id) for c in source_chunks if hasattr(c, "doc_id") and c.doc_id}
    )

    clean_resp = copy.deepcopy(response)
    clean_resp.pop("request_id", None)
    clean_resp["cached"] = True

    payload = {
        "tenant_id": ctx.tenant_id,
        "scope_key": scope,
        "kb_version": kb_version,
        "expires_at": expires_at,
        "doc_ids": doc_ids,
        "response": clean_resp,
    }

    try:
        client.upsert(
            collection_name=settings.cache_collection,
            points=[
                models.PointStruct(
                    id=str(uuid.uuid4()),
                    vector=question_vector,
                    payload=payload,
                )
            ],
        )
        return True
    except Exception as e:
        logger.warning("Semantic cache store failed: %s", e)
        return False


def delete_for_doc(
    tenant_id: str,
    doc_id: str,
    *,
    qdrant_client: Any = None,
) -> int:
    """Evict all semantic cache entries referencing the given doc_id for the tenant.

    Called during verifiable document erasure.
    Returns the count of purged cache points.
    """
    settings = get_settings()
    client = qdrant_client or get_client()
    ensure_cache_collection(client)

    q_filter = models.Filter(
        must=[
            models.FieldCondition(key="tenant_id", match=models.MatchValue(value=tenant_id)),
            models.FieldCondition(key="doc_ids", match=models.MatchValue(value=doc_id)),
        ]
    )

    try:
        count_res = client.count(
            collection_name=settings.cache_collection,
            count_filter=q_filter,
            exact=True,
        )
        count = int(count_res.count)
    except Exception as e:
        logger.warning("Failed to count cache entries for doc %s: %s", doc_id, e)
        count = 0

    if count > 0:
        try:
            client.delete(
                collection_name=settings.cache_collection,
                points_selector=models.FilterSelector(filter=q_filter),
            )
        except Exception as e:
            logger.warning("Failed to delete cache entries for doc %s: %s", doc_id, e)

    return count
