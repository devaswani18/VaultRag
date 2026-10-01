"""RAG generation layer: calls Gemini to answer a question from retrieved chunks.

Design principles:
- System prompt instructs the model to answer ONLY from the provided context and
  to respond with JSON ``{"answer": str, "citations": [chunk_id, ...]}``.
- Context is rendered as numbered blocks containing only the chunk_id and text so
  the model can reference back to source chunks.
- Parsing is robust: strips markdown code-fences, retries once on invalid JSON,
  then falls back to a safe answer.
- Citations that are not in the provided chunk set are silently dropped.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field

from vaultrag.clients import gemini as gemini_client
from vaultrag.rag.retrieve import RetrievedChunk

logger = logging.getLogger(__name__)

_CODE_FENCE_RE = re.compile(r"^```(?:json)?\s*|\s*```$", re.MULTILINE)

_SYSTEM_PROMPT = (
    "You answer ONLY using the provided context. "
    "If the context is insufficient to answer the question, say so. "
    "Respond with JSON only. "
    "Your response must be a single JSON object with exactly two keys: "
    '"answer" (a string with your answer) and '
    '"citations" (an array of chunk_id strings from the context that support your answer). '
    "Do not include any text outside the JSON object."
)

_NO_ANSWER = "I could not find relevant information in your documents."

_FALLBACK_RESULT_FACTORY = lambda answer=_NO_ANSWER: AnswerResult(  # noqa: E731
    answer=answer,
    citations=[],
)


@dataclass
class AnswerResult:
    """Structured answer from the generation layer."""

    answer: str
    citations: list[str] = field(default_factory=list)


def _build_context_block(chunks: list[RetrievedChunk]) -> str:
    """Render numbered context blocks from chunks.

    Format::

        [1] chunk_id=<id>
        <text>

        [2] chunk_id=<id>
        <text>

    Chunk text is included here for the LLM call only.  It is never echoed
    back to the API caller (the router enforces a <=200-char snippet limit).
    """
    lines: list[str] = []
    for i, chunk in enumerate(chunks, start=1):
        lines.append(f"[{i}] chunk_id={chunk.chunk_id}")
        lines.append(chunk.text)
        lines.append("")
    return "\n".join(lines)


def _parse_response(raw: str, valid_chunk_ids: set[str]) -> AnswerResult | None:
    """Attempt to parse the model's JSON response.

    Returns ``None`` on failure so the caller can retry or fall back.
    Unknown citations (not in *valid_chunk_ids*) are silently dropped.
    """
    # Strip markdown code fences if the model wrapped the JSON
    cleaned = _CODE_FENCE_RE.sub("", raw).strip()

    try:
        data = json.loads(cleaned)
    except json.JSONDecodeError:
        return None

    if not isinstance(data, dict):
        return None

    answer = data.get("answer", "")
    if not isinstance(answer, str):
        answer = str(answer)

    raw_citations = data.get("citations", [])
    if not isinstance(raw_citations, list):
        raw_citations = []

    # Drop citations that were not in the provided chunk set
    citations = [str(c) for c in raw_citations if str(c) in valid_chunk_ids]

    return AnswerResult(answer=answer.strip(), citations=citations)


def answer(question: str, chunks: list[RetrievedChunk]) -> AnswerResult:
    """Generate a grounded answer using Gemini.

    Args:
        question: The user's natural-language question.
        chunks:   Retrieved chunks from :mod:`~vaultrag.rag.retrieve`.

    Returns:
        An :class:`AnswerResult` with the model's answer and validated
        citation chunk_ids.  On persistent parse failure a safe fallback
        answer is returned so the API never surfaces a 500 to the client.
    """
    valid_chunk_ids: set[str] = {c.chunk_id for c in chunks}
    context_block = _build_context_block(chunks)

    user_prompt = f"Context:\n{context_block}\nQuestion: {question}\n\nAnswer (JSON only):"

    # First attempt
    try:
        result = gemini_client.generate_json(
            system_prompt=_SYSTEM_PROMPT,
            user_prompt=user_prompt,
        )
        parsed = _parse_response(str(result), valid_chunk_ids)
        if parsed is not None:
            return parsed
    except Exception:
        logger.exception("Gemini generate_json failed on first attempt")

    # Single retry
    logger.warning("First generation attempt produced invalid JSON; retrying once")
    try:
        result = gemini_client.generate_json(
            system_prompt=_SYSTEM_PROMPT,
            user_prompt=user_prompt,
        )
        parsed = _parse_response(str(result), valid_chunk_ids)
        if parsed is not None:
            return parsed
    except Exception:
        logger.exception("Gemini generate_json failed on retry attempt")

    # Safe fallback – never raise here so the API always returns a response
    logger.error("Both generation attempts failed; returning safe fallback answer")
    return _FALLBACK_RESULT_FACTORY()
