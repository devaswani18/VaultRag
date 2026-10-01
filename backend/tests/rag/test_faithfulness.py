from __future__ import annotations

from vaultrag.rag.faithfulness import check
from vaultrag.rag.retrieve import RetrievedChunk


def _make_chunk(chunk_id: str, text: str) -> RetrievedChunk:
    return RetrievedChunk(
        chunk_id=chunk_id,
        doc_id="doc-1",
        filename="policy.pdf",
        page=1,
        text=text,
        score=0.9,
    )


def test_grounded_answer_all_supported() -> None:
    chunk = _make_chunk(
        "c1", "Employees receive 20 days of annual leave and 10 days of sick leave."
    )
    segments = [
        {"text": "Employees receive 20 days of annual leave.", "citations": ["c1"]},
        {"text": "Employees get 10 days of sick leave.", "citations": ["c1"]},
    ]

    res = check(segments, [chunk])
    assert res.score == 1.0
    assert len(res.invalid_citations) == 0
    assert all(chk["supported"] for chk in res.per_segment)


def test_segment_without_citation_is_unsupported() -> None:
    chunk = _make_chunk("c1", "All employees receive 20 days leave.")
    segments = [
        {"text": "All employees receive 20 days leave.", "citations": ["c1"]},
        {"text": "Also free coffee is provided in the breakroom.", "citations": []},
    ]

    res = check(segments, [chunk])
    assert res.per_segment[0]["supported"] is True
    assert res.per_segment[1]["supported"] is False
    assert "no_citations" in res.per_segment[1]["reasons"]
    assert res.score == 0.5


def test_fabricated_citation_id_is_caught_and_lowers_score() -> None:
    chunk = _make_chunk("c1", "All employees receive 20 days leave.")
    # Cites c1 (valid) and c-fake (hallucinated)
    segments = [
        {"text": "All employees receive 20 days leave.", "citations": ["c1"]},
        {"text": "Remote work is permitted.", "citations": ["c-ghost"]},
    ]

    res = check(segments, [chunk])
    assert "c-ghost" in res.invalid_citations
    assert res.per_segment[1]["supported"] is False
    assert "invalid_citation" in res.per_segment[1]["reasons"]
    # Raw ratio = 1/2 = 0.5; minus 0.2 penalty = 0.3
    assert res.score == 0.3


def test_numeric_mismatch_is_caught() -> None:
    # Cited chunk says 15 days; segment claims 30 days
    chunk = _make_chunk("c1", "The review period is 15 days from submission.")
    segments = [{"text": "The review period is 30 days from submission.", "citations": ["c1"]}]

    res = check(segments, [chunk])
    assert res.score == 0.0
    assert res.per_segment[0]["supported"] is False
    assert "numeric_date_mismatch" in res.per_segment[0]["reasons"]


def test_lexical_support_threshold() -> None:
    chunk = _make_chunk("c1", "The sky is blue over the mountains.")
    # Content tokens completely unrelated to chunk text
    segments = [
        {
            "text": "Quantum entanglement requires ultra-cold vacuum chambers.",
            "citations": ["c1"],
        }
    ]

    res = check(segments, [chunk])
    assert res.score == 0.0
    assert res.per_segment[0]["supported"] is False
    assert "insufficient_lexical_support" in res.per_segment[0]["reasons"]


def test_llm_judge_rescues_borderline_score() -> None:
    chunk = _make_chunk("c1", "The policy was enacted on January 15th 2024.")
    segments = [
        {"text": "The policy was enacted on January 15th 2024.", "citations": ["c1"]},
        {"text": "It remains currently operational across teams.", "citations": ["c1"]},
    ]

    class FakeJudge:
        def evaluate(self, segment_text: str, context_text: str) -> bool:
            return True

    # Without judge, segment 2 might fail lexical check (raw score 0.5)
    res_no_judge = check(segments, [chunk], tenant_settings={"llm_judge_enabled": False})
    assert res_no_judge.score == 0.5

    # With judge enabled, score in [0.4, 0.6) gets evaluated by judge
    res_judge = check(
        segments,
        [chunk],
        tenant_settings={"llm_judge_enabled": True, "min_faithfulness": 0.6},
        judge=FakeJudge(),
    )
    assert res_judge.score == 1.0
    assert res_judge.per_segment[1]["supported"] is True
