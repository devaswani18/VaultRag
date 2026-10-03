"""Query orchestration service: coordinates retrieval gating, generation, faithfulness scoring,
and Trust Layer guards.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
import uuid
from typing import Any

from vaultrag.admin.gaps import record_knowledge_gap
from vaultrag.audit.hashchain import append_event
from vaultrag.audit.usage import increment, reserve_query
from vaultrag.chat.history import ConversationRepo
from vaultrag.clients import gemini as gemini_client
from vaultrag.clients.dynamo import TenantRepo
from vaultrag.context import RequestContext
from vaultrag.errors import QuotaExceeded, ValidationFailed
from vaultrag.rag.faithfulness import check as check_faithfulness
from vaultrag.rag.generate import answer as generate_answer
from vaultrag.rag.output_guard import check_output
from vaultrag.rag.retrieve import RetrievedChunk, retrieve
from vaultrag.rag.semantic_cache import lookup as cache_lookup
from vaultrag.rag.semantic_cache import store as cache_store
from vaultrag.security.injection_guard import scan_text
from vaultrag.security.pii_guard import apply_policy

logger = logging.getLogger(__name__)

_ABSTAIN_ANSWER = "I could not find this in the documents you can access."
_SNIPPET_MAX_LEN = 200

_REWRITE_SYSTEM_PROMPT = (
    "You are a search query reformulator. Given the user's previous questions and "
    "their latest follow-up question, rewrite the latest question into a self-contained, "
    "standalone search query.\n"
    'Do NOT answer the question. Return strictly a JSON object: {"standalone_question": "..."}.'
)


def _rewrite_standalone_question(
    previous_user_questions: list[str],
    current_question: str,
    pii_mode: str,
) -> tuple[str, int]:
    """Rewrite follow-up question using ONLY previous user questions (max 3).

    Returns (rewritten_question, extra_tokens). Falls back to current_question on error.
    """
    last_3 = previous_user_questions[-3:]
    user_prompt = "Previous questions asked by the user:\n"
    for q in last_3:
        user_prompt += f"- {q}\n"
    user_prompt += f"\nCurrent follow-up question: {current_question}\n"
    user_prompt += "Rewrite the current follow-up question into a standalone question."

    try:
        gen_res = gemini_client.generate_json(
            system_prompt=_REWRITE_SYSTEM_PROMPT,
            user_prompt=user_prompt,
        )
        data = json.loads(gen_res.text)
        standalone = str(data.get("standalone_question", "")).strip()
        tokens = (getattr(gen_res, "input_tokens", 0) or 0) + (
            getattr(gen_res, "output_tokens", 0) or 0
        )
        if not standalone:
            return current_question, tokens

        # Run PII guard on the rewritten question
        pii_res = apply_policy(standalone, mode=pii_mode)
        if pii_res.blocked:
            return current_question, tokens
        clean_rewritten = pii_res.text if pii_mode == "redact" else standalone
        return clean_rewritten, tokens
    except Exception as e:
        logger.warning("Failed to rewrite standalone question with Gemini: %s", e)
        return current_question, 0


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


def _finish_and_audit(
    ctx: RequestContext,
    question: str,
    response_dict: dict[str, Any],
    start_time: float,
    q_res: Any = None,
    chunks: list[RetrievedChunk] | None = None,
    *,
    cached: bool = False,
    redacted_question: str | None = None,
    top_score: float = 0.0,
    min_faithfulness: float = 0.6,
    extra_tokens: int = 0,
) -> dict[str, Any]:
    """Record query audit event, increment usage counters, and record knowledge gaps."""
    duration_ms = round((time.monotonic() - start_time) * 1000, 2)
    q_hash = hashlib.sha256(question.encode("utf-8")).hexdigest()

    sources = response_dict.get("sources", [])
    doc_ids = sorted({s["doc_id"] for s in sources if isinstance(s, dict) and "doc_id" in s})
    is_abstained = bool(response_dict.get("trust", {}).get("abstained", False))
    reasons = response_dict.get("trust", {}).get("reasons", [])

    scope_info = response_dict.get("scope", {})
    is_scoped = bool(scope_info.get("scoped", False))
    n_scope_docs = int(scope_info.get("n_docs", 0))

    pii_types_in_q: list[str] = []
    if q_res is not None and hasattr(q_res, "findings"):
        pii_types_in_q = sorted({f.category for f in q_res.findings})
    elif q_res is not None and hasattr(q_res, "findings_summary"):
        pii_types_in_q = sorted(q_res.findings_summary.keys())

    audit_details: dict[str, Any] = {
        "question_sha256": q_hash,
        "trust_score": response_dict.get("trust", {}).get("score", 0.0),
        "abstained": is_abstained,
        "cached": cached,
        "n_sources": len(sources),
        "doc_ids": doc_ids,
        "pii_types_in_question": pii_types_in_q,
        "pii_in_answer": bool(response_dict.get("pii_in_answer", False)),
        "latency_ms": duration_ms,
        "scoped": is_scoped,
        "n_scope_docs": n_scope_docs,
    }
    if is_abstained and reasons:
        audit_details["reason"] = str(reasons[0])

    action = "query_abstain" if is_abstained else "query"

    try:
        append_event(
            ctx,
            action=action,
            outcome="ok",
            details=audit_details,
        )
    except Exception as e:
        logger.error("Failed to append query audit event: %s", e)

    # Meter usage (queries already reserved by reserve_query)
    try:
        est_tokens = (
            (len(question) + len(str(response_dict.get("answer", "")))) // 4
        ) + extra_tokens
        increment(
            ctx,
            queries=0,
            chunks=len(chunks or []),
            est_tokens=est_tokens,
            cache_hits=1 if cached else 0,
            cache_misses=0 if cached else 1,
        )
    except Exception as e:
        logger.error("Failed to increment query usage: %s", e)

    # Record knowledge gap if query abstained or trust score < min_faithfulness
    # (Skip knowledge gap recording for document-scoped queries)
    trust_score = float(response_dict.get("trust", {}).get("score", 0.0))
    if not is_scoped and (is_abstained or trust_score < min_faithfulness) and redacted_question:
        gap_reason = str(reasons[0]) if (is_abstained and reasons) else "insufficient_faithfulness"
        try:
            record_knowledge_gap(
                ctx,
                redacted_question=redacted_question,
                top_score=top_score,
                reason=gap_reason,
            )
        except Exception as gap_err:
            logger.warning("Failed to record knowledge gap: %s", gap_err)

    return response_dict


def execute_query(
    ctx: RequestContext,
    question: str,
    top_k: int = 6,
    *,
    doc_ids: list[str] | None = None,
    conversation_id: str | None = None,
    retrieve_fn: Any = None,
    generate_fn: Any = None,
    tenant_repo_cls: Any = None,
) -> dict[str, Any]:
    """Execute end-to-end RAG query workflow with retrieval gating and faithfulness scoring."""
    start_time = time.monotonic()
    _retrieve = retrieve_fn or retrieve
    _generate = generate_answer if generate_fn is None else generate_fn
    _repo_cls = tenant_repo_cls or TenantRepo

    is_scoped = bool(doc_ids)
    scope_data = {"scoped": is_scoped, "n_docs": len(doc_ids) if doc_ids else 0}

    # 0. Load tenant settings
    tenant_rec: dict[str, Any] = {}
    try:
        tenant_repo = _repo_cls()
        tenant_rec = tenant_repo.get(ctx.tenant_id) or {}
        settings = tenant_rec.get("settings", {})
    except Exception:
        settings = {}

    pii_mode = str(settings.get("pii_mode", "redact")).strip().lower()
    min_retrieval_score = float(settings.get("min_retrieval_score", 0.35))
    min_faithfulness = float(settings.get("min_faithfulness", 0.6))
    daily_query_quota = int(settings.get("daily_query_quota", 200))
    chat_history_days = int(settings.get("chat_history_days", 7))

    # Atomic quota reservation before retrieval/generation
    try:
        reserve_query(ctx, daily_query_quota)
    except QuotaExceeded:
        raise
    except Exception as e:
        logger.warning("Could not reserve query quota in store: %s", e)

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
        try:
            append_event(
                ctx,
                action="injection_attempt",
                outcome="flagged",
                details={"risk": inj_result.risk, "reasons": inj_result.reasons},
            )
        except Exception as audit_err:
            logger.error("Failed to append injection_attempt audit record: %s", audit_err)

    # 2. Run PII guard on question BEFORE embedding or sending to LLM
    q_res = apply_policy(question, mode=pii_mode)
    if q_res.blocked:
        raise ValidationFailed("Your question appears to contain sensitive identifiers")

    clean_question = q_res.text if pii_mode == "redact" else question

    # 2b. Handle conversation history and standalone question rewrite
    active_conversation_id: str | None = None
    rewrite_tokens = 0
    search_question = clean_question

    if chat_history_days > 0:
        conv_repo = ConversationRepo()
        if conversation_id:
            # Caller supplied conversation_id: verify ownership else 404
            conv_repo.get_conversation(ctx.tenant_id, ctx.user_id, conversation_id)
            active_conversation_id = conversation_id
        else:
            # Create a new conversation titled with the first 60 characters of clean_question
            new_id = uuid.uuid4().hex[:16]
            conv_repo.create(
                tenant_id=ctx.tenant_id,
                user_id=ctx.user_id,
                conversation_id=new_id,
                title=clean_question[:60],
                ttl_days=chat_history_days,
            )
            active_conversation_id = new_id

        # Check for previous user questions to potentially rewrite short follow-up questions
        try:
            prev_msgs, _ = conv_repo.get_messages(
                ctx.tenant_id, ctx.user_id, active_conversation_id
            )
            prev_user_questions = [m["text"] for m in prev_msgs if m.get("role") == "user"]
            # If previous user questions exist and new question has <= 12 words, rewrite
            word_count = len(clean_question.split())
            if prev_user_questions and word_count <= 12:
                search_question, rewrite_tokens = _rewrite_standalone_question(
                    prev_user_questions, clean_question, pii_mode=pii_mode
                )
        except Exception as err:
            logger.warning("Error fetching previous messages or rewriting question: %s", err)

    # 3. Embed search_question once for both cache lookup and vector retrieval
    cache_enabled = bool(settings.get("cache_enabled", True))
    cache_similarity_threshold = float(settings.get("cache_similarity_threshold", 0.95))
    kb_version = int(tenant_rec.get("kb_version", 1))

    try:
        vectors = gemini_client.embed_texts([search_question], task_type="RETRIEVAL_QUERY")
        question_vector = vectors[0] if vectors else None
    except Exception as e:
        logger.warning("Failed to embed question: %s", e)
        question_vector = None

    # Helper function to append to conversation history before returning
    def _save_history_and_attach_id(response_payload: dict[str, Any]) -> None:
        if chat_history_days > 0 and active_conversation_id:
            response_payload["conversation_id"] = active_conversation_id
            # PII guard over the assistant text
            asst_text = str(response_payload.get("answer", ""))
            ans_pii = apply_policy(asst_text, mode=pii_mode)
            clean_asst_text = ans_pii.text if pii_mode == "redact" else asst_text

            # Prepare message items: user message (clean_question) + assistant message
            user_msg = {
                "role": "user",
                "text": clean_question,
                "trust": {"score": 1.0, "abstained": False, "partial": False},
                "sources": [],
            }
            asst_msg = {
                "role": "assistant",
                "text": clean_asst_text,
                "trust": response_payload.get("trust", {}),
                "sources": response_payload.get("sources", []),
            }
            try:
                c_repo = ConversationRepo()
                c_repo.append_messages(
                    ctx.tenant_id,
                    ctx.user_id,
                    active_conversation_id,
                    [user_msg, asst_msg],
                    ttl_days=chat_history_days,
                )
            except Exception as hist_err:
                logger.warning("Failed to append messages to conversation history: %s", hist_err)

    # 4. Semantic Cache Lookup (BEFORE retrieval, bypassed if scoped)
    if not is_scoped and cache_enabled and question_vector is not None:
        cached_resp = cache_lookup(
            ctx,
            question_vector=question_vector,
            kb_version=kb_version,
            similarity_threshold=cache_similarity_threshold,
        )
        if cached_resp is not None:
            logger.info("Semantic cache hit for tenant=%s, user=%s", ctx.tenant_id, ctx.user_id)
            cached_resp["scope"] = scope_data
            _save_history_and_attach_id(cached_resp)
            return _finish_and_audit(
                ctx,
                question,
                cached_resp,
                start_time,
                q_res,
                chunks=None,
                cached=True,
                redacted_question=clean_question,
                top_score=1.0,
                min_faithfulness=min_faithfulness,
                extra_tokens=rewrite_tokens,
            )

    # 5. Retrieve top_k chunks through ACL-scoped vector retrieval (reusing question_vector)
    try:
        chunks = _retrieve(
            ctx,
            search_question,
            top_k=top_k,
            query_vector=question_vector,
            doc_ids=doc_ids,
        )
    except TypeError:
        try:
            chunks = _retrieve(ctx, search_question, top_k=top_k, query_vector=question_vector)
        except TypeError:
            chunks = _retrieve(ctx, search_question, top_k=top_k)

    # 6. Retrieval Gate: if no results OR best score < min_retrieval_score, abstain immediately
    best_score = max((c.score for c in chunks), default=0.0)
    if not chunks or best_score < min_retrieval_score:
        logger.info(
            "Retrieval gate abstained: tenant=%s, chunks=%d, score=%.4f (min=%.4f)",
            ctx.tenant_id,
            len(chunks),
            best_score,
            min_retrieval_score,
        )
        resp = {
            "answer": _ABSTAIN_ANSWER,
            "trust": {
                "score": 0.0,
                "grounded": False,
                "abstained": True,
                "partial": False,
                "reasons": ["below_min_retrieval_score"] if chunks else ["no_retrieval_results"],
            },
            "sources": [],
            "scope": scope_data,
            "request_id": ctx.request_id,
            "pii_in_answer": False,
            "injection_attempt": injection_attempt,
        }
        _save_history_and_attach_id(resp)
        return _finish_and_audit(
            ctx,
            question,
            resp,
            start_time,
            q_res,
            chunks,
            cached=False,
            redacted_question=clean_question,
            top_score=best_score,
            min_faithfulness=min_faithfulness,
            extra_tokens=rewrite_tokens,
        )

    # 7. Generate structured answer with canary and XML sandboxing
    result = _generate(clean_question, chunks)

    # Handle model output failure / invalid JSON retry failure
    if getattr(result, "invalid", False):
        logger.warning(
            "Model output invalid on query: tenant_id=%s, user_id=%s, reason=%s",
            ctx.tenant_id,
            ctx.user_id,
            getattr(result, "invalid_reason", "model_output_invalid"),
        )
        resp = {
            "answer": _ABSTAIN_ANSWER,
            "trust": {
                "score": 0.0,
                "grounded": False,
                "abstained": True,
                "partial": False,
                "reasons": [getattr(result, "invalid_reason", "model_output_invalid")],
            },
            "sources": [],
            "scope": scope_data,
            "request_id": ctx.request_id,
            "pii_in_answer": False,
            "injection_attempt": injection_attempt,
        }
        _save_history_and_attach_id(resp)
        return _finish_and_audit(
            ctx,
            question,
            resp,
            start_time,
            q_res,
            chunks,
            cached=False,
            redacted_question=clean_question,
            top_score=best_score,
            min_faithfulness=min_faithfulness,
            extra_tokens=rewrite_tokens,
        )

    # 8. Output guard verification (canary leak, untrusted URLs, system prompt leak)
    out_check = check_output(answer=result.answer, chunks=chunks, canary=result.canary)
    if not out_check.ok:
        logger.warning("Output guard blocked answer: reasons=%s", out_check.reasons)
        resp = {
            "answer": out_check.safe_answer,
            "trust": {
                "score": 0.0,
                "grounded": False,
                "abstained": True,
                "partial": False,
                "reasons": out_check.reasons,
            },
            "sources": [],
            "scope": scope_data,
            "request_id": ctx.request_id,
            "pii_in_answer": False,
            "injection_attempt": injection_attempt,
        }
        _save_history_and_attach_id(resp)
        return _finish_and_audit(
            ctx,
            question,
            resp,
            start_time,
            q_res,
            chunks,
            cached=False,
            redacted_question=clean_question,
            top_score=best_score,
            min_faithfulness=min_faithfulness,
            extra_tokens=rewrite_tokens,
        )

    # 9. Check factual faithfulness of answer segments against source chunks
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
            resp = {
                "answer": _ABSTAIN_ANSWER,
                "trust": {
                    "score": round(faith_res.score, 4),
                    "grounded": False,
                    "abstained": True,
                    "partial": False,
                    "reasons": ["insufficient_support"],
                },
                "sources": [],
                "scope": scope_data,
                "request_id": ctx.request_id,
                "pii_in_answer": False,
                "injection_attempt": injection_attempt,
            }
            _save_history_and_attach_id(resp)
            return _finish_and_audit(
                ctx,
                question,
                resp,
                start_time,
                q_res,
                chunks,
                cached=False,
                redacted_question=clean_question,
                top_score=best_score,
                min_faithfulness=min_faithfulness,
                extra_tokens=rewrite_tokens,
            )

        reduced_text = " ".join(str(s.get("text", "")).strip() for s in supported_segments)
        final_answer = (
            f"{reduced_text}\n\n[Note: Some unverified statements were removed from this response.]"
        )
        grounded = False
        abstained = False
        partial = True
        trust_reasons = ["partial_support"]

    # 10. Guard answer with PII policy
    ans_res = apply_policy(final_answer, mode=pii_mode)
    masked_answer = ans_res.text if pii_mode == "redact" else final_answer
    pii_in_answer = bool(ans_res.findings_summary) if pii_mode != "off" else False

    # 11. Format sources with PII-guarded snippets
    cited_ids = set(result.citations)
    sources = _format_sources(chunks, cited_ids, pii_mode)

    resp = {
        "answer": masked_answer,
        "trust": {
            "score": round(faith_res.score, 4),
            "grounded": grounded,
            "abstained": abstained,
            "partial": partial,
            "reasons": trust_reasons,
        },
        "sources": sources,
        "scope": scope_data,
        "request_id": ctx.request_id,
        "pii_in_answer": pii_in_answer,
        "injection_attempt": injection_attempt,
    }

    # Attach conversation_id and append messages to conversation history
    _save_history_and_attach_id(resp)

    # 12. Store in semantic cache if eligible (grounded, non-abstained, non-partial, and unscoped)
    if (
        not is_scoped
        and cache_enabled
        and question_vector is not None
        and not abstained
        and not partial
    ):
        try:
            cache_store(
                ctx,
                question_vector=question_vector,
                response=resp,
                source_chunks=chunks,
                kb_version=kb_version,
            )
        except Exception as cache_err:
            logger.warning("Failed to store in semantic cache: %s", cache_err)

    return _finish_and_audit(
        ctx,
        question,
        resp,
        start_time,
        q_res,
        chunks,
        cached=False,
        redacted_question=clean_question,
        top_score=best_score,
        min_faithfulness=min_faithfulness,
        extra_tokens=rewrite_tokens,
    )
