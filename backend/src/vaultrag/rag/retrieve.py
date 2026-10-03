"""RAG retrieval layer: embeds a question and fetches the top-k relevant chunks.

All searches go through ``build_filter`` (security/acl.py) so that results are
always scoped to the caller's tenant.  Stage 12 will extend the filter to
enforce visibility rules.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from vaultrag.clients import gemini as gemini_client
from vaultrag.clients import qdrant as qdrant_client
from vaultrag.context import RequestContext
from vaultrag.security.acl import build_filter, build_scoped_filter

logger = logging.getLogger(__name__)


@dataclass
class RetrievedChunk:
    """A single chunk returned from Qdrant search."""

    chunk_id: str
    doc_id: str
    filename: str
    page: int | None
    text: str
    score: float
    injection_risk: str = "low"
    visibility: str = "tenant"
    allowed_roles: list[str] = field(default_factory=list)
    allowed_users: list[str] = field(default_factory=list)


def retrieve(
    ctx: RequestContext,
    question: str,
    top_k: int = 6,
    *,
    query_vector: list[float] | None = None,
    doc_ids: list[str] | None = None,
) -> list[RetrievedChunk]:
    """Embed *question* (or use precomputed *query_vector*) and return top-*top_k* chunks.

    The Qdrant search is **always** scoped to ``ctx.tenant_id`` via
    :func:`~vaultrag.security.acl.build_filter`.  Never pass ad-hoc filters
    directly to the Qdrant client from this layer.

    Args:
        ctx:          Authenticated request context (provides tenant_id).
        question:     The user's natural-language question.
        top_k:        Maximum number of chunks to return (1-10).
        query_vector: Optional precomputed embedding vector.

    Returns:
        List of :class:`RetrievedChunk` ordered by descending cosine similarity.
        May be empty when no relevant chunks exist in the tenant's collection.
    """
    # 1. Embed question if vector not precomputed
    if query_vector is None:
        vectors = gemini_client.embed_texts([question], task_type="RETRIEVAL_QUERY")
        if not vectors:
            logger.warning("Embedding returned empty result for question (len=%d)", len(question))
            return []
        effective_vector = vectors[0]
    else:
        effective_vector = query_vector

    # 2. Build mandatory tenant-scoped ACL filter
    acl_filter = build_scoped_filter(ctx, doc_ids) if doc_ids else build_filter(ctx)

    # 3. Search Qdrant
    scored_points = qdrant_client.search(
        vector=effective_vector,
        query_filter=acl_filter,
        limit=top_k,
    )

    # 4. Map ScoredPoints -> RetrievedChunk (never log chunk text)
    chunks: list[RetrievedChunk] = []
    for point in scored_points:
        payload = point.payload or {}
        chunk_id = str(point.id)
        if payload.get("chunk_id"):
            chunk_id = str(payload["chunk_id"])

        chunks.append(
            RetrievedChunk(
                chunk_id=chunk_id,
                doc_id=str(payload.get("doc_id", "")),
                filename=str(payload.get("filename", "")),
                page=payload.get("page"),
                text=str(payload.get("text", "")),
                score=float(point.score),
                injection_risk=str(payload.get("injection_risk", "low")),
                visibility=str(payload.get("visibility", "tenant")),
                allowed_roles=list(payload.get("allowed_roles") or []),
                allowed_users=list(payload.get("allowed_users") or []),
            )
        )

    logger.info(
        "retrieval completed tenant=%s top_k=%d returned=%d",
        ctx.tenant_id,
        top_k,
        len(chunks),
    )
    return chunks
