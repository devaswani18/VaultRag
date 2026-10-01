"""Tests for PII Hook in the ingestion pipeline."""

from __future__ import annotations

import logging
from unittest.mock import MagicMock, patch

import pytest

from vaultrag.clients.dynamo import DocStatus
from vaultrag.ingest.chunker import Chunk
from vaultrag.ingest.handler import process_record
from vaultrag.ingest.hooks.pii_hook import PIIHook
from vaultrag.ingest.pipeline import ChunkContext, DocumentBlocked
from vaultrag.security.pii_guard import generate_verhoeff


def _valid_aadhaar() -> str:
    return generate_verhoeff("34567890123")


def _make_chunk(chunk_id: str, text: str, index: int = 0) -> Chunk:
    return Chunk(
        index=index,
        text=text,
        page=1,
        char_start=0,
        char_end=len(text),
        chunk_id=chunk_id,
    )


class TestPIIHookUnit:
    def test_hook_redact_mode(self) -> None:
        hook = PIIHook()
        aadhaar = _valid_aadhaar()
        raw_text = f"Citizen ID is {aadhaar} and email is test@example.com"
        chunk = _make_chunk("chk_001", raw_text)
        ctx = ChunkContext(chunk=chunk, text=chunk.text, tenant_id="acme", doc_id="doc_1")

        hook(ctx, {"pii_mode": "redact"})

        assert ctx.payload["pii_found"] is True
        assert sorted(ctx.payload["pii_types"]) == ["AADHAAR", "EMAIL"]
        assert aadhaar not in ctx.text
        assert "[AADHAAR_REDACTED]" in ctx.text
        assert "[EMAIL_REDACTED]" in ctx.text

    def test_hook_flag_mode(self) -> None:
        hook = PIIHook()
        aadhaar = _valid_aadhaar()
        raw_text = f"Citizen ID is {aadhaar}"
        chunk = _make_chunk("chk_002", raw_text)
        ctx = ChunkContext(chunk=chunk, text=raw_text)

        hook(ctx, {"pii_mode": "flag"})

        assert ctx.payload["pii_found"] is True
        assert ctx.payload["pii_types"] == ["AADHAAR"]
        assert ctx.text == raw_text  # Kept unchanged

    def test_hook_block_mode_raises_document_blocked(self) -> None:
        hook = PIIHook()
        aadhaar = _valid_aadhaar()
        chunk = _make_chunk("chk_003", f"Secret: {aadhaar}")
        ctx = ChunkContext(chunk=chunk, text=chunk.text)

        with pytest.raises(DocumentBlocked) as exc_info:
            hook(ctx, {"pii_mode": "block"})

        assert "blocked by PII policy" in str(exc_info.value)
        assert exc_info.value.details.get("rule") == "pii_policy"

    def test_hook_off_mode_passthrough(self) -> None:
        hook = PIIHook()
        raw_text = f"Citizen ID is {_valid_aadhaar()}"
        chunk = _make_chunk("chk_004", raw_text)
        ctx = ChunkContext(chunk=chunk, text=raw_text)

        hook(ctx, {"pii_mode": "off"})

        assert ctx.payload["pii_found"] is False
        assert ctx.payload["pii_types"] == []
        assert ctx.text == raw_text


class TestIngestionPipelineIntegration:
    @patch("vaultrag.ingest.handler.delete_object")
    @patch("vaultrag.ingest.handler.upsert_chunks")
    @patch("vaultrag.ingest.handler.embed_texts")
    @patch("vaultrag.ingest.handler.download_bytes")
    @patch("vaultrag.ingest.handler.TenantRepo")
    @patch("vaultrag.ingest.handler.DocumentRepo")
    def test_redact_mode_aggregates_pii_summary_in_document(
        self,
        mock_doc_repo_cls: MagicMock,
        mock_tenant_repo_cls: MagicMock,
        mock_download: MagicMock,
        mock_embed: MagicMock,
        mock_upsert: MagicMock,
        mock_delete_obj: MagicMock,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        aadhaar = _valid_aadhaar()
        raw_content = (
            f"Sensitive document content with Aadhaar {aadhaar} and email hr@acme.com.".encode()
        )
        mock_download.return_value = raw_content

        mock_tenant_repo = MagicMock()
        mock_tenant_repo.get.return_value = {
            "settings": {"pii_mode": "redact", "retain_original_files": False}
        }
        mock_tenant_repo_cls.return_value = mock_tenant_repo

        mock_doc_repo = MagicMock()
        mock_doc_repo.get.return_value = {
            "tenant_id": "acme",
            "doc_id": "doc_100",
            "filename": "confidential.txt",
            "status": "PENDING_UPLOAD",
        }
        mock_doc_repo_cls.return_value = mock_doc_repo

        mock_embed.return_value = [[0.1] * 768]

        record = {
            "s3": {
                "object": {"key": "uploads/acme/doc_100/original.txt"},
                "bucket": {"name": "vaultrag-docs-test"},
            }
        }

        with caplog.at_level(logging.INFO):
            process_record(record)

        # Document updated first to PROCESSING, then to READY with pii_summary
        assert mock_doc_repo.update_status.call_count == 2
        # Check second call (READY)
        ready_call = mock_doc_repo.update_status.call_args_list[1]
        assert ready_call[0][0] == "acme"
        assert ready_call[0][1] == "doc_100"
        assert ready_call[0][2] == DocStatus.READY
        extra_fields = ready_call[1]["extra_fields"]
        assert extra_fields["pii_summary"]["AADHAAR"] == 1
        assert extra_fields["pii_summary"]["EMAIL"] == 1

        # S3 original deleted because retain_original_files=False
        mock_delete_obj.assert_called_once_with("uploads/acme/doc_100/original.txt")

        # Verify Qdrant points received redacted text and PII payload flags
        upserted_points = mock_upsert.call_args[0][0]
        assert len(upserted_points) >= 1
        payload = upserted_points[0].payload
        assert payload["pii_found"] is True
        assert "AADHAAR" in payload["pii_types"]
        assert aadhaar not in payload["text"]
        assert "[AADHAAR_REDACTED]" in payload["text"]

        # LOG CAPTURE TEST: Raw sensitive Aadhaar/email values must NEVER appear in logs
        for record_log in caplog.records:
            assert aadhaar not in record_log.message
            assert "hr@acme.com" not in record_log.message

    @patch("vaultrag.ingest.handler.upsert_chunks")
    @patch("vaultrag.ingest.handler.embed_texts")
    @patch("vaultrag.ingest.handler.download_bytes")
    @patch("vaultrag.ingest.handler.TenantRepo")
    @patch("vaultrag.ingest.handler.DocumentRepo")
    def test_block_mode_quarantines_and_indexes_nothing(
        self,
        mock_doc_repo_cls: MagicMock,
        mock_tenant_repo_cls: MagicMock,
        mock_download: MagicMock,
        mock_embed: MagicMock,
        mock_upsert: MagicMock,
    ) -> None:
        aadhaar = _valid_aadhaar()
        raw_content = f"Disallowed content with Aadhaar {aadhaar}".encode()
        mock_download.return_value = raw_content

        mock_tenant_repo = MagicMock()
        mock_tenant_repo.get.return_value = {"settings": {"pii_mode": "block"}}
        mock_tenant_repo_cls.return_value = mock_tenant_repo

        mock_doc_repo = MagicMock()
        mock_doc_repo.get.return_value = {
            "tenant_id": "acme",
            "doc_id": "doc_200",
            "filename": "blocked.txt",
            "status": "PENDING_UPLOAD",
        }
        mock_doc_repo_cls.return_value = mock_doc_repo

        record = {
            "s3": {
                "object": {"key": "uploads/acme/doc_200/original.txt"},
                "bucket": {"name": "vaultrag-docs-test"},
            }
        }

        process_record(record)

        # Nothing indexed to Qdrant or embedded
        mock_embed.assert_not_called()
        mock_upsert.assert_not_called()

        # Document transitioned to PROCESSING, then to QUARANTINED with safe reason
        assert mock_doc_repo.update_status.call_count == 2
        quarantine_call = mock_doc_repo.update_status.call_args_list[1]
        assert quarantine_call[0] == ("acme", "doc_200", DocStatus.QUARANTINED)
        assert quarantine_call[1]["error"] == "blocked by PII policy"
