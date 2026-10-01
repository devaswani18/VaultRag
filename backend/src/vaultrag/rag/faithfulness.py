"""Faithfulness checking: validates generated answer segments against retrieved chunks.

Evaluates:
  (a) Presence of citations (has >= 1 citation)
  (b) Citation validity (every citation ID exists in the retrieved set)
  (c) Lexical support (fraction of content tokens in cited chunks >= 0.5)
  (d) Numeric/date consistency (all numbers and dates in segment appear in cited chunks)

Scoring:
  Score = supported_segments / total_segments, minus 0.2 per invalid citation
  (floor 0.0, max 1.0).
  Optional LLM judge used when 0.4 <= score < min_faithfulness
  (behind tenant setting llm_judge_enabled).
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Protocol

from vaultrag.rag.retrieve import RetrievedChunk

logger = logging.getLogger(__name__)

STOPWORDS = frozenset(
    {
        "a",
        "about",
        "above",
        "after",
        "again",
        "against",
        "all",
        "am",
        "an",
        "and",
        "any",
        "are",
        "aren't",
        "as",
        "at",
        "be",
        "because",
        "been",
        "before",
        "being",
        "below",
        "between",
        "both",
        "but",
        "by",
        "can't",
        "cannot",
        "could",
        "couldn't",
        "did",
        "didn't",
        "do",
        "does",
        "doesn't",
        "doing",
        "don't",
        "down",
        "during",
        "each",
        "few",
        "for",
        "from",
        "further",
        "had",
        "hadn't",
        "has",
        "hasn't",
        "have",
        "haven't",
        "having",
        "he",
        "he'd",
        "he'll",
        "he's",
        "her",
        "here",
        "here's",
        "hers",
        "herself",
        "him",
        "himself",
        "his",
        "how",
        "how's",
        "i",
        "i'd",
        "i'll",
        "i'm",
        "i've",
        "if",
        "in",
        "into",
        "is",
        "isn't",
        "it",
        "it's",
        "its",
        "itself",
        "let's",
        "me",
        "more",
        "most",
        "mustn't",
        "my",
        "myself",
        "no",
        "nor",
        "not",
        "of",
        "off",
        "on",
        "once",
        "only",
        "or",
        "other",
        "ought",
        "our",
        "ours",
        "ourselves",
        "out",
        "over",
        "own",
        "same",
        "shan't",
        "she",
        "she'd",
        "she'll",
        "she's",
        "should",
        "shouldn't",
        "so",
        "some",
        "such",
        "than",
        "that",
        "that's",
        "the",
        "their",
        "theirs",
        "them",
        "themselves",
        "then",
        "there",
        "there's",
        "these",
        "they",
        "they'd",
        "they'll",
        "they're",
        "they've",
        "this",
        "those",
        "through",
        "to",
        "too",
        "under",
        "until",
        "up",
        "very",
        "was",
        "wasn't",
        "we",
        "we'd",
        "we'll",
        "we're",
        "we've",
        "were",
        "weren't",
        "what",
        "what's",
        "when",
        "when's",
        "where",
        "where's",
        "which",
        "while",
        "who",
        "who's",
        "whom",
        "why",
        "why's",
        "with",
        "won't",
        "would",
        "wouldn't",
        "you",
        "you'd",
        "you'll",
        "you're",
        "you've",
        "your",
        "yours",
        "yourself",
        "yourselves",
    }
)

TOKEN_RE = re.compile(r"\b[a-zA-Z0-9_-]+\b")
NUMBER_RE = re.compile(r"\b\d+(?:[.,]\d+)?\b")
DATE_WORDS_RE = re.compile(
    r"\b(?:january|february|march|april|may|june|july|august|september|october|november|december|"
    r"jan|feb|mar|apr|jun|jul|aug|sep|sept|oct|nov|dec)\b",
    re.IGNORECASE,
)
DATE_FORMAT_RE = re.compile(r"\b\d{1,4}[-/]\d{1,2}[-/]\d{1,4}\b")


@dataclass(frozen=True)
class SegmentCheck:
    """Individual segment evaluation result."""

    index: int
    supported: bool
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "supported": self.supported,
            "reasons": list(self.reasons),
        }


@dataclass(frozen=True)
class FaithfulnessResult:
    """Overall answer faithfulness result."""

    score: float
    per_segment: list[dict[str, Any]]
    invalid_citations: list[str] = field(default_factory=list)


class LLMJudge(Protocol):
    """Protocol for borderline faithfulness evaluation."""

    def evaluate(self, segment_text: str, context_text: str) -> bool: ...


class GeminiLLMJudge:
    """Default LLM judge using Gemini for borderline verification."""

    def evaluate(self, segment_text: str, context_text: str) -> bool:
        from vaultrag.clients import gemini as gemini_client

        system_prompt = (
            "You are a factual consistency evaluator. Determine if the Statement is directly "
            'supported by the Context. Respond with JSON only: {"supported": true} or '
            '{"supported": false}.'
        )
        user_prompt = f"Context:\n{context_text}\n\nStatement:\n{segment_text}"
        try:
            raw = gemini_client.generate_json(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
            )
            data = json.loads(str(raw))
            return bool(data.get("supported", False))
        except Exception:
            logger.exception("LLMJudge call failed")
            return False


def _extract_content_tokens(text: str) -> list[str]:
    """Tokenize text and strip common English stopwords."""
    tokens = TOKEN_RE.findall(text.lower())
    return [t for t in tokens if t not in STOPWORDS]


def _extract_numeric_and_dates(text: str) -> set[str]:
    """Extract numbers and date identifiers from text."""
    entities: set[str] = set()
    for m in NUMBER_RE.finditer(text):
        entities.add(m.group(0).lower())
    for m in DATE_WORDS_RE.finditer(text):
        entities.add(m.group(0).lower())
    for m in DATE_FORMAT_RE.finditer(text):
        entities.add(m.group(0).lower())
    return entities


def check(
    segments: list[dict[str, Any]],
    retrieved_chunks: list[RetrievedChunk],
    *,
    tenant_settings: dict[str, Any] | None = None,
    judge: LLMJudge | None = None,
) -> FaithfulnessResult:
    """Check factual faithfulness of answer segments against retrieved chunks."""
    if not segments:
        return FaithfulnessResult(score=0.0, per_segment=[], invalid_citations=[])

    settings = tenant_settings or {}
    min_faithfulness = float(settings.get("min_faithfulness", 0.6))
    llm_judge_enabled = bool(settings.get("llm_judge_enabled", False))

    chunk_map: dict[str, str] = {c.chunk_id: c.text for c in retrieved_chunks}
    valid_chunk_ids = set(chunk_map.keys())

    all_invalid_citations: set[str] = set()
    per_segment_checks: list[dict[str, Any]] = []
    supported_count = 0

    for idx, seg in enumerate(segments):
        text = str(seg.get("text", "")).strip()
        citations = [str(c) for c in seg.get("citations", []) if str(c)]
        reasons: list[str] = []

        # Rule (a): has >= 1 citation
        if not citations:
            reasons.append("no_citations")

        # Rule (b): every citation id exists in the retrieved set
        valid_citations = [c for c in citations if c in valid_chunk_ids]
        invalid_in_seg = [c for c in citations if c not in valid_chunk_ids]
        if invalid_in_seg:
            reasons.append("invalid_citation")
            all_invalid_citations.update(invalid_in_seg)

        # Context text from valid citations
        cited_text = " ".join(chunk_map[cid] for cid in valid_citations)
        cited_text_lower = cited_text.lower()
        cited_token_set = set(TOKEN_RE.findall(cited_text_lower))

        # Rule (c): lexical support: fraction of content tokens present in cited chunk text >= 0.5
        content_tokens = _extract_content_tokens(text)
        if content_tokens:
            matching_tokens = [t for t in content_tokens if t in cited_token_set]
            overlap = len(matching_tokens) / len(content_tokens)
            if overlap < 0.5:
                reasons.append("insufficient_lexical_support")

        # Rule (d): numeric/date consistency
        seg_nums_and_dates = _extract_numeric_and_dates(text)
        for val in seg_nums_and_dates:
            # Check exact occurrence in cited chunk text (case-insensitive)
            if val not in cited_text_lower:
                reasons.append("numeric_date_mismatch")
                break

        is_supported = len(reasons) == 0
        if is_supported:
            supported_count += 1

        per_segment_checks.append(
            SegmentCheck(index=idx, supported=is_supported, reasons=reasons).to_dict()
        )

    # Compute base score: supported segments / total segments - 0.2 per invalid citation
    total_segments = len(segments)
    raw_ratio = supported_count / total_segments if total_segments > 0 else 0.0
    penalty = 0.2 * len(all_invalid_citations)
    final_score = max(0.0, min(1.0, raw_ratio - penalty))

    # Optional LLM Judge when 0.4 <= score < min_faithfulness
    if llm_judge_enabled and 0.4 <= final_score < min_faithfulness:
        evaluator = judge or GeminiLLMJudge()
        rescued = 0
        all_chunk_text = "\n".join(c.text for c in retrieved_chunks)

        for seg_idx, chk in enumerate(per_segment_checks):
            if not chk["supported"] and "invalid_citation" not in chk["reasons"]:
                seg_text = str(segments[seg_idx].get("text", ""))
                try:
                    if evaluator.evaluate(seg_text, all_chunk_text):
                        chk["supported"] = True
                        chk["reasons"] = []
                        rescued += 1
                except Exception:
                    logger.debug("Judge evaluation failed for segment %d", seg_idx)

        if rescued > 0:
            supported_count += rescued
            raw_ratio = supported_count / total_segments
            final_score = max(0.0, min(1.0, raw_ratio - penalty))

    return FaithfulnessResult(
        score=round(final_score, 4),
        per_segment=per_segment_checks,
        invalid_citations=sorted(all_invalid_citations),
    )
