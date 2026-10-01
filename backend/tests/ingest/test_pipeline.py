from __future__ import annotations

from typing import Any

import pytest

from vaultrag.ingest.chunker import Chunk
from vaultrag.ingest.pipeline import ChunkContext, DocumentBlocked, run_hooks


def _sample_chunks() -> list[Chunk]:
    return [
        Chunk(
            index=0,
            text="First chunk content",
            page=1,
            char_start=0,
            char_end=19,
            chunk_id="c0",
        ),
        Chunk(
            index=1,
            text="Second chunk content",
            page=1,
            char_start=20,
            char_end=40,
            chunk_id="c1",
        ),
    ]


def test_pipeline_execution_order() -> None:
    order_trail: list[str] = []

    def hook_a(ctx: ChunkContext, settings: dict[str, Any]) -> None:
        order_trail.append(f"A-{ctx.chunk.index}")
        ctx.payload["step_a"] = True

    def hook_b(ctx: ChunkContext, settings: dict[str, Any]) -> None:
        order_trail.append(f"B-{ctx.chunk.index}")
        ctx.payload["step_b"] = True

    chunks = _sample_chunks()
    contexts = run_hooks(chunks, [hook_a, hook_b], {"mode": "test"})

    assert len(contexts) == 2
    # Hook A runs for all chunks first, then Hook B
    assert order_trail == ["A-0", "A-1", "B-0", "B-1"]
    assert contexts[0].payload["step_a"] is True
    assert contexts[0].payload["step_b"] is True


def test_pipeline_drop_chunk() -> None:
    def drop_first_hook(ctx: ChunkContext, settings: dict[str, Any]) -> None:
        if ctx.chunk.index == 0:
            ctx.is_dropped = True

    def second_hook(ctx: ChunkContext, settings: dict[str, Any]) -> None:
        ctx.payload["reached_second"] = True

    chunks = _sample_chunks()
    contexts = run_hooks(chunks, [drop_first_hook, second_hook], {})

    assert contexts[0].is_dropped is True
    assert "reached_second" not in contexts[0].payload
    assert contexts[1].is_dropped is False
    assert contexts[1].payload.get("reached_second") is True


def test_pipeline_document_blocked_quarantines() -> None:
    def malicious_block_hook(ctx: ChunkContext, settings: dict[str, Any]) -> None:
        if "First" in ctx.text:
            raise DocumentBlocked("Severe prompt injection detected", rule="injection_guard")

    chunks = _sample_chunks()
    with pytest.raises(DocumentBlocked) as exc_info:
        run_hooks(chunks, [malicious_block_hook], {})

    assert exc_info.value.message == "Severe prompt injection detected"
    assert exc_info.value.details.get("rule") == "injection_guard"
