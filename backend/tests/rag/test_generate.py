"""Tests for vaultrag.rag.generate — robust JSON parsing and citation filtering."""

from __future__ import annotations

import json
from unittest.mock import patch

from vaultrag.clients.gemini import GenerationResult
from vaultrag.rag.generate import AnswerResult, answer
from vaultrag.rag.retrieve import RetrievedChunk


def _make_chunk(chunk_id: str, text: str = "Some chunk text") -> RetrievedChunk:
    return RetrievedChunk(
        chunk_id=chunk_id,
        doc_id="doc-1",
        filename="test.txt",
        page=1,
        text=text,
        score=0.9,
    )


def _gen_result(text: str) -> GenerationResult:
    return GenerationResult(text=text, input_tokens=10, output_tokens=20, model="test-model")


# ── 1. Valid JSON answer ──────────────────────────────────────────────────────
def test_answer_valid_json() -> None:
    chunk = _make_chunk("chunk-abc")
    payload = json.dumps({"answer": "You get 20 days.", "citations": ["chunk-abc"]})

    with patch(
        "vaultrag.rag.generate.gemini_client.generate_json", return_value=_gen_result(payload)
    ):
        result = answer("How many leave days?", [chunk])

    assert isinstance(result, AnswerResult)
    assert result.answer == "You get 20 days."
    assert result.citations == ["chunk-abc"]


# ── 2. JSON wrapped in code fences is handled ─────────────────────────────────
def test_answer_strips_code_fences() -> None:
    chunk = _make_chunk("chunk-xyz")
    raw = (
        "```json\n" + json.dumps({"answer": "Policy answer.", "citations": ["chunk-xyz"]}) + "\n```"
    )

    with patch("vaultrag.rag.generate.gemini_client.generate_json", return_value=_gen_result(raw)):
        result = answer("Policy?", [chunk])

    assert result.answer == "Policy answer."
    assert "chunk-xyz" in result.citations


# ── 3. Unknown citations are dropped ─────────────────────────────────────────
def test_answer_drops_unknown_citations() -> None:
    chunk = _make_chunk("chunk-known")
    payload = json.dumps(
        {
            "answer": "Mixed answer.",
            "citations": ["chunk-known", "chunk-DOES-NOT-EXIST", "chunk-GHOST"],
        }
    )

    with patch(
        "vaultrag.rag.generate.gemini_client.generate_json", return_value=_gen_result(payload)
    ):
        result = answer("Question?", [chunk])

    assert result.citations == ["chunk-known"]


# ── 4. Invalid JSON on first attempt triggers retry; second attempt succeeds ──
def test_answer_retries_on_invalid_json() -> None:
    chunk = _make_chunk("chunk-retry")
    valid_payload = json.dumps({"answer": "Retry worked.", "citations": ["chunk-retry"]})
    call_count = 0

    def _side_effect(*_a, **_kw) -> GenerationResult:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return _gen_result("this is NOT json }{")
        return _gen_result(valid_payload)

    with patch("vaultrag.rag.generate.gemini_client.generate_json", side_effect=_side_effect):
        result = answer("Retry test?", [chunk])

    assert call_count == 2, "Should have called generate_json exactly twice"
    assert result.answer == "Retry worked."


# ── 5. Both attempts return invalid JSON → safe fallback ─────────────────────
def test_answer_fallback_on_persistent_invalid_json() -> None:
    chunk = _make_chunk("chunk-fallback")

    with patch(
        "vaultrag.rag.generate.gemini_client.generate_json",
        return_value=_gen_result("{not valid json"),
    ):
        result = answer("Will fail?", [chunk])

    # Must return a safe fallback, not raise
    assert isinstance(result, AnswerResult)
    assert result.citations == []
    assert len(result.answer) > 0  # non-empty fallback message


# ── 6. Exception in generate_json → safe fallback ────────────────────────────
def test_answer_fallback_on_exception() -> None:
    chunk = _make_chunk("chunk-exc")

    with patch(
        "vaultrag.rag.generate.gemini_client.generate_json",
        side_effect=RuntimeError("Gemini down"),
    ):
        result = answer("Will except?", [chunk])

    assert isinstance(result, AnswerResult)
    assert result.citations == []
