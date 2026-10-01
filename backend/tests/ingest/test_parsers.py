from __future__ import annotations

import pytest

from tests.fixtures.make_fixtures import (
    get_corrupt_pdf,
    get_fake_pdf,
    get_tiny_docx,
    get_tiny_md,
    get_tiny_pdf,
    get_tiny_txt,
    get_zipbomb_docx,
)
from vaultrag.errors import ValidationFailed
from vaultrag.ingest.handler import parse_document


def test_parse_valid_pdf() -> None:
    data = get_tiny_pdf()
    pages = parse_document(data, "pdf")
    assert len(pages) >= 1
    assert pages[0][0] == 1
    assert "VaultRAG tiny test PDF" in pages[0][1]


def test_parse_valid_docx() -> None:
    data = get_tiny_docx()
    pages = parse_document(data, "docx")
    assert len(pages) == 1
    assert "VaultRAG tiny test DOCX" in pages[0][1]
    assert "Header Col A" in pages[0][1]


def test_parse_valid_txt() -> None:
    data = get_tiny_txt()
    pages = parse_document(data, "txt")
    assert len(pages) == 1
    assert "VaultRAG tiny test TXT" in pages[0][1]


def test_parse_valid_md() -> None:
    data = get_tiny_md()
    pages = parse_document(data, "md")
    assert len(pages) == 1
    assert "# VaultRAG Markdown" in pages[0][1]


def test_magic_byte_rejection_fake_pdf() -> None:
    fake_pdf = get_fake_pdf()
    with pytest.raises(ValidationFailed) as exc_info:
        parse_document(fake_pdf, "pdf")
    assert "missing %PDF header" in exc_info.value.message


def test_corrupt_pdf_fails_safely() -> None:
    corrupt_pdf = get_corrupt_pdf()
    with pytest.raises(ValidationFailed) as exc_info:
        parse_document(corrupt_pdf, "pdf")
    assert "Corrupt or invalid PDF file" in exc_info.value.message


def test_docx_zip_bomb_guard() -> None:
    zipbomb = get_zipbomb_docx()
    with pytest.raises(ValidationFailed) as exc_info:
        parse_document(zipbomb, "docx")
    assert "50 MB limit" in exc_info.value.message
    assert "zip-bomb guard" in exc_info.value.message


def test_invalid_utf8_rejection() -> None:
    # 20 invalid bytes in a 30-byte stream -> ~66% valid, triggers < 99% threshold
    bad_data = b"Hello world! " + b"\xff\xfe\xfa\xfb\xfc" * 4
    with pytest.raises(ValidationFailed) as exc_info:
        parse_document(bad_data, "txt")
    assert "File is not valid UTF-8 text" in exc_info.value.message


def test_unsupported_extension_rejection() -> None:
    with pytest.raises(ValidationFailed) as exc_info:
        parse_document(b"hello world", "exe")
    assert "Unsupported document extension" in exc_info.value.message
