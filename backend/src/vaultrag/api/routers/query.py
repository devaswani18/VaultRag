"""Query router: POST /query — RAG question-answering endpoint.

Auth required on all routes. Full chunk text is NEVER returned; only snippets
of at most 200 characters per source are included in the response.
Orchestration is delegated to vaultrag.rag.query_service.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from vaultrag.auth.dependencies import get_ctx
from vaultrag.clients.dynamo import TenantRepo
from vaultrag.context import RequestContext
from vaultrag.rag.generate import answer as generate_answer
from vaultrag.rag.query_service import execute_query
from vaultrag.rag.retrieve import retrieve

__all__ = ["TenantRepo", "generate_answer", "retrieve", "router"]

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/query", tags=["query"])


class QueryRequest(BaseModel):
    question: str = Field(
        ..., min_length=1, max_length=1000, description="Natural-language question"
    )
    top_k: int = Field(6, ge=1, le=10, description="Maximum number of chunks to retrieve (1-10)")


@router.post("")
async def query(
    req: QueryRequest,
    ctx: RequestContext = Depends(get_ctx),  # noqa: B008
) -> dict[str, Any]:
    """Answer a question using the tenant's ingested documents with Trust Layer guards."""
    import vaultrag.api.routers.query as _current_module

    return execute_query(
        ctx,
        req.question,
        top_k=req.top_k,
        retrieve_fn=_current_module.retrieve,
        generate_fn=_current_module.generate_answer,
        tenant_repo_cls=_current_module.TenantRepo,
    )
