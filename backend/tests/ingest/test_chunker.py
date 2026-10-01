from __future__ import annotations

import uuid

from vaultrag.ingest.chunker import Chunk, chunk_document


def test_chunker_basic_splitting() -> None:
    text = (
        "This is paragraph one of the document. It contains text for basic chunking.\n\n"
        "This is paragraph two. It also has plenty of characters to see chunker behavior.\n\n"
        "This is paragraph three, concluding our test document."
    )
    pages = [(1, text)]
    chunks = chunk_document(pages, tenant_id="tenant-a", doc_id="doc-123", target_size=100)

    assert len(chunks) > 1
    for chunk in chunks:
        assert isinstance(chunk, Chunk)
        assert chunk.index >= 0
        assert chunk.page == 1
        assert len(chunk.text) > 0
        assert chunk.char_end > chunk.char_start
        assert isinstance(uuid.UUID(chunk.chunk_id), uuid.UUID)


def test_chunker_overlap_present() -> None:
    # A text with multiple sentences that will be split across multiple chunks
    sentences = [
        f"Sentence number {i} with some descriptive words to take up space in the chunk."
        for i in range(20)
    ]
    long_text = " ".join(sentences)
    pages = [(1, long_text)]

    chunks = chunk_document(
        pages,
        tenant_id="tenant-a",
        doc_id="doc-123",
        target_size=200,
        overlap=50,
        min_size=40,
    )

    assert len(chunks) >= 2
    # Verify that consecutive chunks share overlap text
    for i in range(len(chunks) - 1):
        c1 = chunks[i]
        c2 = chunks[i + 1]
        words_c1 = c1.text.split()[-3:]
        # At least one trailing word of c1 should appear in c2
        assert any(w in c2.text for w in words_c1)


def test_chunker_determinism() -> None:
    pages = [(1, "Deterministic chunking content repeated for testing consistency.")]
    chunks1 = chunk_document(pages, tenant_id="tenant-acme", doc_id="doc-999")
    chunks2 = chunk_document(pages, tenant_id="tenant-acme", doc_id="doc-999")

    assert len(chunks1) == len(chunks2)
    for c1, c2 in zip(chunks1, chunks2, strict=True):
        assert c1.chunk_id == c2.chunk_id
        assert c1.text == c2.text
        assert c1.char_start == c2.char_start
        assert c1.char_end == c2.char_end

    # Different tenant produces different chunk_id
    chunks_diff_tenant = chunk_document(pages, tenant_id="tenant-other", doc_id="doc-999")
    assert chunks1[0].chunk_id != chunks_diff_tenant[0].chunk_id

    # Different doc_id produces different chunk_id
    chunks_diff_doc = chunk_document(pages, tenant_id="tenant-acme", doc_id="doc-other")
    assert chunks1[0].chunk_id != chunks_diff_doc[0].chunk_id


def test_chunker_multiple_pages() -> None:
    pages = [
        (1, "Page 1 content with first page statements."),
        (2, "Page 2 content with second page statements."),
    ]
    chunks = chunk_document(pages, tenant_id="tenant-a", doc_id="doc-multi")
    assert len(chunks) == 2
    assert chunks[0].page == 1
    assert chunks[1].page == 2
    assert chunks[0].index == 0
    assert chunks[1].index == 1
