"""Query orchestration service: coordinates retrieval gating, generation, faithfulness scoring,
and Trust Layer guards.
"""

from __future__ import annotations

import logging
from typing import Any

from vaultrag.clients.dynamo import TenantRepo
from vaultrag.context import RequestContext
from vaultrag.errors import ValidationFailed
from vaultrag.rag.faithfulness import check as check_faithfulness
from vaultrag.rag.generate import answer as generate_answer
from vaultrag.rag.output_guard import check_output
from vaultrag.rag.retrieve import RetrievedChunk, retrieve
from vaultrag.security.injection_guard import scan_text
from vaultrag.security.pii_guard import apply_policy

logger = logging.getLogger(__name__)

_ABSTAIN_ANSWER = "I could not find this in the documents you can access."
_SNIPPET_MAX_LEN = 200


def _make_snippet(text: str) -> str:
    """Return a safe snippet of *text* truncated to ``_SNIPPET_MAX_LEN`` chars."""
    if len(text) <= _SNIPPET_MAX_LEN:
        return text
    return text[:_SNIPPET_MAX_LEN]


def _format_sources(
    chunks: list[RetrievedChunk],
    cited_ids: set[str],
    pii_mode: str,
) -> list[dict[str, Any]]:
    """Format retrieval chunks into API source items with PII-redacted snippets."""
    chunk_map = {c.chunk_id: c for c in chunks}
    sources: list[dict[str, Any]] = []

    # First add cited sources in order of citation
    for chunk_id in cited_ids:
        chunk = chunk_map.get(chunk_id)
        if chunk is None:
            continue
        raw_snippet = _make_snippet(chunk.text)
        clean_snippet = (
            apply_policy(raw_snippet, mode=pii_mode).text if pii_mode == "redact" else raw_snippet
        )
        sources.append(
            {
                "doc_id": chunk.doc_id,
                "filename": chunk.filename,
                "chunk_id": chunk.chunk_id,
                "page": chunk.page,
                "score": round(chunk.score, 4),
                "snippet": clean_snippet,
            }
        )

    # Add any remaining uncited chunks for discovery
    seen_ids = set(cited_ids)
    for chunk in chunks:
        if chunk.chunk_id not in seen_ids:
            raw_snippet = _make_snippet(chunk.text)
            clean_snippet = (
                apply_policy(raw_snippet, mode=pii_mode).text
                if pii_mode == "redact"
                else raw_snippet
            )
            sources.append(
                {
                    "doc_id": chunk.doc_id,
                    "filename": chunk.filename,
                    "chunk_id": chunk.chunk_id,
                    "page": chunk.page,
                    "score": round(chunk.score, 4),
                    "snippet": clean_snippet,
                }
            )
            seen_ids.add(chunk.chunk_id)

    return sources


def execute_query(
    ctx: RequestContext,
    question: str,
    top_k: int = 6,
    *,
    retrieve_fn: Any = None,
    generate_fn: Any = None,
    tenant_repo_cls: Any = None,
) -> dict[str, Any]:
    """Execute end-to-end RAG query workflow with retrieval gating and faithfulness scoring."""
    _retrieve = retrieve_fn or retrieve
    _generate = generate_fn or generate_answer
    _repo_cls = tenant_repo_cls or TenantRepo

    # 0. Load tenant settings
    tenant_repo = _repo_cls()
    try:
        tenant_rec = tenant_repo.get(ctx.tenant_id)
        settings = tenant_rec.get("settings", {})
    except Exception:
        settings = {}

    pii_mode = str(settings.get("pii_mode", "redact")).strip().lower()
    min_retrieval_score = float(settings.get("min_retrieval_score", 0.35))
    min_faithfulness = float(settings.get("min_faithfulness", 0.6))

    # 1. Prompt injection detection on question (do NOT refuse; record injection_attempt)
    inj_result = scan_text(question)
    injection_attempt = inj_result.risk == "high"
    if injection_attempt:
        logger.warning(
            "High injection risk detected on question: tenant_id=%s, user_id=%s, reasons=%s",
            ctx.tenant_id,
            ctx.user_id,
            inj_result.reasons,
        )

    # 2. Run PII guard on question BEFORE embedding or sending to LLM
    q_res = apply_policy(question, mode=pii_mode)
    if q_res.blocked:
        raise ValidationFailed("Your question appears to contain sensitive identifiers")

    clean_question = q_res.text if pii_mode == "redact" else question

    # 3. Retrieve top_k chunks through ACL-scoped vector retrieval
    chunks = _retrieve(ctx, clean_question, top_k=top_k)

    # 4. Retrieval Gate: if no results OR best score < min_retrieval_score, abstain immediately
    best_score = max((c.score for c in chunks), default=0.0)
    if not chunks or best_score < min_retrieval_score:
        logger.info(
            "Retrieval gate abstained: tenant=%s, chunks=%d, score=%.4f (min=%.4f)",
            ctx.tenant_id,
            len(chunks),
            best_score,
            min_retrieval_score,
        )
        return {
            "answer": _ABSTAIN_ANSWER,
            "trust": {
                "score": 0.0,
                "grounded": False,
                "abstained": True,
                "partial": False,
                "reasons": ["below_min_retrieval_score"] if chunks else ["no_retrieval_results"],
            },
            "sources": [],
            "request_id": ctx.request_id,
            "pii_in_answer": False,
            "injection_attempt": injection_attempt,
        }

    # 5. Generate structured answer with canary and XML sandboxing
    result = _generate(clean_question, chunks)

    # Handle model output failure / invalid JSON retry failure
    if getattr(result, "invalid", False):
        logger.warning(
            "Model output invalid on query: tenant_id=%s, user_id=%s, reason=%s",
            ctx.tenant_id,
            ctx.user_id,
            getattr(result, "invalid_reason", "model_output_invalid"),
        )
        return {
            "answer": _ABSTAIN_ANSWER,
            "trust": {
                "score": 0.0,
                "grounded": False,
                "abstained": True,
                "partial": False,
                "reasons": [getattr(result, "invalid_reason", "model_output_invalid")],
            },
            "sources": [],
            "request_id": ctx.request_id,
            "pii_in_answer": False,
            "injection_attempt": injection_attempt,
        }

    # 6. Output guard verification (canary leak, untrusted URLs, system prompt leak)
    out_check = check_output(answer=result.answer, chunks=chunks, canary=result.canary)
    if not out_check.ok:
        logger.warning("Output guard blocked answer: reasons=%s", out_check.reasons)
        return {
            "answer": out_check.safe_answer,
            "trust": {
                "score": 0.0,
                "grounded": False,
                "abstained": True,
                "partial": False,
                "reasons": out_check.reasons,
            },
            "sources": [],
            "request_id": ctx.request_id,
            "pii_in_answer": False,
            "injection_attempt": injection_attempt,
        }

    # 7. Check factual faithfulness of answer segments against source chunks
    faith_res = check_faithfulness(result.segments, chunks, tenant_settings=settings)

    # Decision logic
    if faith_res.score >= min_faithfulness:
        final_answer = result.answer
        grounded = True
        abstained = False
        partial = False
        trust_reasons: list[str] = []
    else:
        # Drop unsupported segments
        supported_segments = [
            seg
            for i, seg in enumerate(result.segments)
            if i < len(faith_res.per_segment) and faith_res.per_segment[i]["supported"]
        ]
        if not supported_segments:
            logger.info(
                "Faithfulness score %.4f < %.4f; all segments dropped",
                faith_res.score,
                min_faithfulness,
            )
            return {
                "answer": _ABSTAIN_ANSWER,
                "trust": {
                    "score": round(faith_res.score, 4),
                    "grounded": False,
                    "abstained": True,
                    "partial": False,
                    "reasons": ["insufficient_support"],
                },
                "sources": [],
                "request_id": ctx.request_id,
                "pii_in_answer": False,
                "injection_attempt": injection_attempt,
            }

        reduced_text = " ".join(str(s.get("text", "")).strip() for s in supported_segments)
        final_answer = (
            f"{reduced_text}\n\n[Note: Some unverified statements were removed from this response.]"
        )
        grounded = False
        abstained = False
        partial = True
        trust_reasons = ["partial_support"]

    # 8. Guard answer with PII policy
    ans_res = apply_policy(final_answer, mode=pii_mode)
    masked_answer = ans_res.text if pii_mode == "redact" else final_answer
    pii_in_answer = bool(ans_res.findings_summary) if pii_mode != "off" else False

    # 9. Format sources with PII-guarded snippets
    cited_ids = set(result.citations)
    sources = _format_sources(chunks, cited_ids, pii_mode)

    return {
        "answer": masked_answer,
        "trust": {
            "score": round(faith_res.score, 4),
            "grounded": grounded,
            "abstained": abstained,
            "partial": partial,
            "reasons": trust_reasons,
        },
        "sources": sources,
        "request_id": ctx.request_id,
        "pii_in_answer": pii_in_answer,
        "injection_attempt": injection_attempt,
    }
