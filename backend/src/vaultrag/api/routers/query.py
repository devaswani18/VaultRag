"""Query router: POST /query — RAG question-answering endpoint.

Auth required on all routes.  Full chunk text is NEVER returned; only snippets
of at most 200 characters per source are included in the response.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from vaultrag.auth.dependencies import get_ctx
from vaultrag.clients.dynamo import TenantRepo
from vaultrag.context import RequestContext
from vaultrag.errors import ValidationFailed
from vaultrag.rag.generate import answer as generate_answer
from vaultrag.rag.retrieve import retrieve
from vaultrag.security.pii_guard import apply_policy

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/query", tags=["query"])

_NO_RESULTS_ANSWER = "I could not find relevant information in your documents."
_SNIPPET_MAX_LEN = 200


class QueryRequest(BaseModel):
    question: str = Field(
        ..., min_length=1, max_length=1000, description="Natural-language question"
    )
    top_k: int = Field(6, ge=1, le=10, description="Maximum number of chunks to retrieve (1-10)")


def _make_snippet(text: str) -> str:
    """Return a safe snippet of *text* truncated to ``_SNIPPET_MAX_LEN`` chars."""
    if len(text) <= _SNIPPET_MAX_LEN:
        return text
    return text[:_SNIPPET_MAX_LEN]


@router.post("")
async def query(
    req: QueryRequest,
    ctx: RequestContext = Depends(get_ctx),  # noqa: B008
) -> dict[str, Any]:
    """Answer a question using the tenant's ingested documents.

    If no relevant chunks are found the LLM is **not** called; a canned
    "no information" response is returned instead.
    Full chunk text is NEVER returned to the client.
    """
    # 0. Load tenant settings to inspect PII policy
    tenant_repo = TenantRepo()
    try:
        tenant_rec = tenant_repo.get(ctx.tenant_id)
        pii_mode = str(tenant_rec.get("settings", {}).get("pii_mode", "redact")).strip().lower()
    except Exception:
        pii_mode = "redact"

    # 1. Run guard on question BEFORE embedding or sending to LLM
    q_res = apply_policy(req.question, mode=pii_mode)
    if q_res.blocked:
        raise ValidationFailed("Your question appears to contain sensitive identifiers")

    clean_question = q_res.text if pii_mode == "redact" else req.question

    # 2. Retrieve relevant chunks through the ACL filter using safe question
    chunks = retrieve(ctx, clean_question, top_k=req.top_k)

    # 3. Short-circuit when nothing was found
    if not chunks:
        logger.info(
            "query returned no chunks tenant=%s question_len=%d",
            ctx.tenant_id,
            len(clean_question),
        )
        return {
            "answer": _NO_RESULTS_ANSWER,
            "sources": [],
            "request_id": ctx.request_id,
            "pii_in_answer": False,
        }

    # 4. Generate the answer using safe question
    result = generate_answer(clean_question, chunks)

    # 5. Guard answer: redact in redact mode; track pii_in_answer for audit
    ans_res = apply_policy(result.answer, mode=pii_mode)
    final_answer = ans_res.text if pii_mode == "redact" else result.answer
    pii_in_answer = bool(ans_res.findings_summary) if pii_mode != "off" else False

    # 6. Build cited chunk_id set for fast lookup
    cited_ids: set[str] = set(result.citations)

    # 7. Assemble sources — never expose full text, only snippets <= 200 chars
    chunk_map = {c.chunk_id: c for c in chunks}
    sources: list[dict[str, Any]] = []
    for chunk_id in result.citations:
        chunk = chunk_map.get(chunk_id)
        if chunk is None:
            continue  # citation was already validated in generate layer
        sources.append(
            {
                "doc_id": chunk.doc_id,
                "filename": chunk.filename,
                "chunk_id": chunk.chunk_id,
                "page": chunk.page,
                "score": round(chunk.score, 4),
                "snippet": _make_snippet(chunk.text),
            }
        )

    # Include non-cited retrieved chunks in sources for discovery (without snippet)
    seen_ids = set(result.citations)
    for chunk in chunks:
        if chunk.chunk_id not in seen_ids:
            sources.append(
                {
                    "doc_id": chunk.doc_id,
                    "filename": chunk.filename,
                    "chunk_id": chunk.chunk_id,
                    "page": chunk.page,
                    "score": round(chunk.score, 4),
                    "snippet": _make_snippet(chunk.text),
                }
            )
            seen_ids.add(chunk.chunk_id)

    _ = cited_ids

    return {
        "answer": final_answer,
        "sources": sources,
        "request_id": ctx.request_id,
        "pii_in_answer": pii_in_answer,
    }
