"""Access-Control Layer: builds Qdrant filters that scope every query to a tenant.

Stage 12 will extend ``build_filter`` with visibility rules so that documents
marked ``roles`` or ``private`` are only returned to callers who have the
appropriate roles / user-id match.  Until then the filter enforces **only**
tenant isolation, which is the mandatory baseline for every retrieval call.

Usage::

    from vaultrag.security.acl import build_filter
    from vaultrag.clients import qdrant as qdrant_client

    filt = build_filter(ctx)
    results = qdrant_client.search(vector=embedding, query_filter=filt, limit=top_k)

All retrieval paths MUST call ``build_filter`` and pass the returned filter to
the Qdrant client.  The Qdrant client itself also enforces ``assert_tenant_scoped``
as a defence-in-depth check.
"""

from __future__ import annotations

from qdrant_client import models

from vaultrag.context import RequestContext


def build_filter(ctx: RequestContext) -> models.Filter:
    """Build a Qdrant ``Filter`` that restricts results to *ctx.tenant_id*.

    **Stage 12 note**: this function will be extended to add visibility
    conditions (``tenant`` / ``roles`` / ``private``) so that documents are
    only surfaced to callers authorised by their role-set or user-id.
    All retrieval MUST call this function; do **not** pass raw filters to the
    Qdrant client.

    Args:
        ctx: The authenticated request context carrying ``tenant_id``.

    Returns:
        A ``models.Filter`` with a ``must`` clause ensuring
        ``tenant_id == ctx.tenant_id``.
    """
    return models.Filter(
        must=[
            models.FieldCondition(
                key="tenant_id",
                match=models.MatchValue(value=ctx.tenant_id),
            )
        ]
    )
