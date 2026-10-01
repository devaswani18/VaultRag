from __future__ import annotations

import uuid
from dataclasses import dataclass

DEFAULT_TARGET_CHARS = 1000
DEFAULT_OVERLAP_CHARS = 150
DEFAULT_MIN_CHARS = 100


@dataclass(frozen=True)
class Chunk:
    """Represents an extracted document text chunk with lineage and deterministic ID."""

    index: int
    text: str
    page: int
    char_start: int
    char_end: int
    chunk_id: str


def _split_text_recursive(
    text: str,
    separators: list[str],
    target_size: int,
    overlap: int,
) -> list[str]:
    """Recursively split text using hierarchy of separators (paragraphs -> sentences -> words)."""
    text = text.strip()
    if not text:
        return []

    if len(text) <= target_size:
        return [text]

    # Find the first separator present in the text
    sep = None
    remaining_seps = []
    for idx, s in enumerate(separators):
        if s in text:
            sep = s
            remaining_seps = separators[idx + 1 :]
            break

    if sep is None or not sep:
        # Fallback: slice directly if no separator matches
        parts = []
        step = max(1, target_size - overlap)
        for i in range(0, len(text), step):
            part = text[i : i + target_size].strip()
            if part:
                parts.append(part)
        return parts

    raw_splits = text.split(sep)
    sub_chunks: list[str] = []
    current_chunk: list[str] = []
    current_len = 0

    for split in raw_splits:
        split_stripped = split.strip()
        if not split_stripped:
            continue

        split_len = len(split_stripped)

        # If a single split is already larger than target_size, split it with remaining separators
        if split_len > target_size and remaining_seps:
            deeper_splits = _split_text_recursive(
                split_stripped, remaining_seps, target_size, overlap
            )
            for ds in deeper_splits:
                if current_len + len(ds) + len(sep) <= target_size:
                    current_chunk.append(ds)
                    current_len += len(ds) + len(sep)
                else:
                    if current_chunk:
                        sub_chunks.append(sep.join(current_chunk).strip())
                    current_chunk = [ds]
                    current_len = len(ds)
        elif current_len + split_len + (len(sep) if current_chunk else 0) <= target_size:
            current_chunk.append(split_stripped)
            current_len += split_len + (len(sep) if len(current_chunk) > 1 else 0)
        else:
            if current_chunk:
                sub_chunks.append(sep.join(current_chunk).strip())
            current_chunk = [split_stripped]
            current_len = split_len

    if current_chunk:
        sub_chunks.append(sep.join(current_chunk).strip())

    return sub_chunks


def chunk_document(
    pages: list[tuple[int, str]],
    tenant_id: str,
    doc_id: str,
    target_size: int = DEFAULT_TARGET_CHARS,
    overlap: int = DEFAULT_OVERLAP_CHARS,
    min_size: int = DEFAULT_MIN_CHARS,
) -> list[Chunk]:
    """Chunk document pages recursively on paragraphs, sentences, and words with overlap.

    Generates deterministic UUID5 chunk_ids = uuid5(NAMESPACE_DNS, f"{tenant_id}:{doc_id}:{index}")
    to guarantee idempotent overwrite on reprocessing.
    """
    separators = ["\n\n", "\n", ". ", "? ", "! ", " ", ""]
    chunks: list[Chunk] = []
    chunk_index = 0
    doc_offset = 0

    for page_num, page_text in pages:
        page_clean = page_text.strip()
        if not page_clean:
            continue

        raw_pieces = _split_text_recursive(page_clean, separators, target_size, overlap)
        if not raw_pieces:
            continue

        # Build chunks with overlap
        merged_pieces: list[str] = []
        for i, piece in enumerate(raw_pieces):
            if not piece.strip():
                continue
            if not merged_pieces:
                merged_pieces.append(piece)
                continue

            # Check if this trailing piece is too small and can be merged into previous
            if len(piece) < min_size and i == len(raw_pieces) - 1 and merged_pieces:
                candidate = merged_pieces[-1] + "\n\n" + piece
                if len(candidate) <= target_size + overlap:
                    merged_pieces[-1] = candidate
                    continue

            # Add overlap from tail of previous piece if needed
            prev_piece = merged_pieces[-1]
            if overlap > 0 and len(prev_piece) > overlap:
                overlap_text = prev_piece[-overlap:].strip()
                # Find clean boundary in overlap text
                space_idx = overlap_text.find(" ")
                if space_idx != -1 and space_idx < len(overlap_text) - 10:
                    overlap_text = overlap_text[space_idx + 1 :]
                if overlap_text and not piece.startswith(overlap_text):
                    piece = f"{overlap_text} {piece}"

            merged_pieces.append(piece)

        # Create Chunk instances with char offsets and deterministic IDs
        for piece in merged_pieces:
            piece_text = piece.strip()
            if not piece_text:
                continue

            # Find or track char offsets in the document
            pos = page_clean.find(piece_text)
            char_start = doc_offset + (pos if pos != -1 else 0)
            char_end = char_start + len(piece_text)

            chunk_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{tenant_id}:{doc_id}:{chunk_index}"))

            chunks.append(
                Chunk(
                    index=chunk_index,
                    text=piece_text,
                    page=page_num,
                    char_start=char_start,
                    char_end=char_end,
                    chunk_id=chunk_id,
                )
            )
            chunk_index += 1

        doc_offset += len(page_clean) + 2

    return chunks
