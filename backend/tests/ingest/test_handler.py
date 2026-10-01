from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

from tests.fixtures.make_fixtures import get_corrupt_pdf, get_tiny_pdf, get_tiny_txt
from vaultrag.clients.dynamo import DocumentStatus
from vaultrag.ingest.handler import handler, process_record
from vaultrag.ingest.pipeline import DocumentBlocked


def _make_s3_record(bucket: str, key: str) -> dict[str, Any]:
    return {
        "s3": {
            "bucket": {"name": bucket},
            "object": {"key": key, "size": 100},
        }
    }


# ------------------------------------------------------------------------------
# 1. Key parsing rejection test
# ------------------------------------------------------------------------------
def test_handler_ignores_invalid_s3_keys() -> None:
    # Invalid structure, path traversal, missing original prefix
    invalid_keys = [
        "uploads/invalid-traversal/../doc1/original.pdf",
        "random-prefix/tenant-a/doc-1/original.pdf",
        "uploads/tenant-a/doc-1/extra/original.pdf",
        "uploads/tenant-a/doc-1/not_original.pdf",
    ]
    for key in invalid_keys:
        record = _make_s3_record("test-bucket", key)
        # Should not raise exception; ignored gracefully
        process_record(record)


# ------------------------------------------------------------------------------
# 2. Missing document in DynamoDB ignored
# ------------------------------------------------------------------------------
@patch("vaultrag.ingest.handler.DocumentRepo")
def test_handler_ignores_missing_document(mock_repo_cls: MagicMock) -> None:
    from vaultrag.errors import NotFound

    mock_repo = MagicMock()
    mock_repo.get.side_effect = NotFound("Document not found")
    mock_repo_cls.return_value = mock_repo

    record = _make_s3_record("test-bucket", "uploads/acme/doc-123/original.pdf")
    process_record(record)

    mock_repo.get.assert_called_once_with("acme", "doc-123")
    mock_repo.update_status.assert_not_called()


# ------------------------------------------------------------------------------
# 3. Handler idempotency (second event does nothing)
# ------------------------------------------------------------------------------
@patch("vaultrag.ingest.handler.DocumentRepo")
def test_handler_idempotency_skips_non_pending(mock_repo_cls: MagicMock) -> None:
    mock_repo = MagicMock()
    # Status is already READY
    mock_repo.get.return_value = {
        "tenant_id": "acme",
        "doc_id": "doc-123",
        "status": DocumentStatus.READY.value,
    }
    mock_repo_cls.return_value = mock_repo

    record = _make_s3_record("test-bucket", "uploads/acme/doc-123/original.pdf")
    process_record(record)

    mock_repo.get.assert_called_once_with("acme", "doc-123")
    mock_repo.update_status.assert_not_called()


# ------------------------------------------------------------------------------
# 4. Corrupt file failure with safe message
# ------------------------------------------------------------------------------
@patch("vaultrag.ingest.handler.download_bytes")
@patch("vaultrag.ingest.handler.DocumentRepo")
def test_handler_corrupt_file_fails_safely(
    mock_repo_cls: MagicMock,
    mock_download: MagicMock,
) -> None:
    corrupt_bytes = get_corrupt_pdf()
    mock_download.return_value = corrupt_bytes

    mock_repo = MagicMock()
    mock_repo.get.return_value = {
        "tenant_id": "acme",
        "doc_id": "doc-123",
        "status": DocumentStatus.PENDING_UPLOAD.value,
        "size_bytes": len(corrupt_bytes),
    }
    mock_repo_cls.return_value = mock_repo

    record = _make_s3_record("test-bucket", "uploads/acme/doc-123/original.pdf")
    process_record(record)

    # Status updated to PROCESSING first
    assert mock_repo.update_status.call_args_list[0][0] == (
        "acme",
        "doc-123",
        DocumentStatus.PROCESSING,
    )
    # Then updated to FAILED with safe message
    failed_call = mock_repo.update_status.call_args_list[1]
    assert failed_call[0] == ("acme", "doc-123", DocumentStatus.FAILED)
    err_msg = failed_call[1].get("error", "")
    assert "Corrupt or invalid PDF file" in err_msg
    # Ensure no document content is present in the error message
    assert "GARBAGE_NOT_A_VALID_PDF" not in err_msg


# ------------------------------------------------------------------------------
# 5. Scanned document failure (text < 20 chars)
# ------------------------------------------------------------------------------
@patch("vaultrag.ingest.handler.download_bytes")
@patch("vaultrag.ingest.handler.DocumentRepo")
def test_handler_scanned_doc_rejection(
    mock_repo_cls: MagicMock,
    mock_download: MagicMock,
) -> None:
    tiny_text = b"short"  # < 20 chars
    mock_download.return_value = tiny_text

    mock_repo = MagicMock()
    mock_repo.get.return_value = {
        "tenant_id": "acme",
        "doc_id": "doc-short",
        "status": DocumentStatus.PENDING_UPLOAD.value,
        "size_bytes": len(tiny_text),
    }
    mock_repo_cls.return_value = mock_repo

    record = _make_s3_record("test-bucket", "uploads/acme/doc-short/original.txt")
    process_record(record)

    failed_call = mock_repo.update_status.call_args_list[1]
    assert failed_call[0] == ("acme", "doc-short", DocumentStatus.FAILED)
    assert "no extractable text (scanned documents are not supported yet)" in failed_call[1].get(
        "error", ""
    )


# ------------------------------------------------------------------------------
# 6. Hook pipeline DocumentBlocked sets QUARANTINED
# ------------------------------------------------------------------------------
@patch("vaultrag.ingest.handler.run_hooks")
@patch("vaultrag.ingest.handler.download_bytes")
@patch("vaultrag.ingest.handler.DocumentRepo")
def test_handler_document_blocked_quarantines(
    mock_repo_cls: MagicMock,
    mock_download: MagicMock,
    mock_run_hooks: MagicMock,
) -> None:
    valid_pdf = get_tiny_pdf()
    mock_download.return_value = valid_pdf
    mock_run_hooks.side_effect = DocumentBlocked("Blocked by security guard", rule="test")

    mock_repo = MagicMock()
    mock_repo.get.return_value = {
        "tenant_id": "acme",
        "doc_id": "doc-blocked",
        "status": DocumentStatus.PENDING_UPLOAD.value,
        "size_bytes": len(valid_pdf),
    }
    mock_repo_cls.return_value = mock_repo

    record = _make_s3_record("test-bucket", "uploads/acme/doc-blocked/original.pdf")
    process_record(record)

    quarantine_call = mock_repo.update_status.call_args_list[1]
    assert quarantine_call[0] == ("acme", "doc-blocked", DocumentStatus.QUARANTINED)
    assert quarantine_call[1].get("error") == "Blocked by security guard"


# ------------------------------------------------------------------------------
# 7. Successful ingestion: embeddings, Qdrant payload verification, READY status
# ------------------------------------------------------------------------------
@patch("vaultrag.ingest.handler.upsert_chunks")
@patch("vaultrag.ingest.handler.embed_texts")
@patch("vaultrag.ingest.handler.download_bytes")
@patch("vaultrag.ingest.handler.DocumentRepo")
def test_handler_successful_ingestion_payload_verification(
    mock_repo_cls: MagicMock,
    mock_download: MagicMock,
    mock_embed: MagicMock,
    mock_upsert: MagicMock,
) -> None:
    valid_txt = get_tiny_txt()
    mock_download.return_value = valid_txt
    mock_embed.return_value = [[0.1] * 768]

    mock_repo = MagicMock()
    mock_repo.get.return_value = {
        "tenant_id": "acme",
        "doc_id": "doc-ok",
        "status": DocumentStatus.PENDING_UPLOAD.value,
        "size_bytes": len(valid_txt),
        "filename": "tiny.txt",
        "visibility": "roles",
        "allowed_roles": ["employee"],
        "allowed_users": [],
        "owner_user_id": "usr-123",
    }
    mock_repo_cls.return_value = mock_repo

    record = _make_s3_record("test-bucket", "uploads/acme/doc-ok/original.txt")
    process_record(record)

    # 1. Check Qdrant upsert points
    mock_upsert.assert_called_once()
    points = mock_upsert.call_args[0][0]
    assert len(points) == 1
    point = points[0]

    # Verify payload schema per requirement 9:
    # tenant_id, doc_id, chunk_index, text, filename, page, visibility,
    # allowed_roles, allowed_users, owner_user_id, pii_found=false,
    # pii_types=[], injection_risk="low", created_at
    payload = point.payload
    assert payload["tenant_id"] == "acme"
    assert payload["doc_id"] == "doc-ok"
    assert payload["chunk_index"] == 0
    assert payload["filename"] == "tiny.txt"
    assert payload["page"] == 1
    assert payload["visibility"] == "roles"
    assert payload["allowed_roles"] == ["employee"]
    assert payload["allowed_users"] == []
    assert payload["owner_user_id"] == "usr-123"
    assert payload["pii_found"] is False
    assert payload["pii_types"] == []
    assert payload["injection_risk"] == "low"
    assert "created_at" in payload
    assert len(point.vector) == 768

    # 2. Check document updated to READY with chunk_count
    ready_call = mock_repo.update_status.call_args_list[1]
    assert ready_call[0] == ("acme", "doc-ok", DocumentStatus.READY)
    assert ready_call[1].get("extra_fields", {}).get("chunk_count") == 1


# ------------------------------------------------------------------------------
# 8. Lambda entry point returns 200 OK
# ------------------------------------------------------------------------------
@patch("vaultrag.ingest.handler.process_record")
def test_handler_lambda_entry_point(mock_process: MagicMock) -> None:
    event = {
        "Records": [
            _make_s3_record("bucket-1", "uploads/acme/doc-1/original.pdf"),
            _make_s3_record("bucket-1", "uploads/acme/doc-2/original.pdf"),
        ]
    }
    res = handler(event)
    assert res == {"statusCode": 200, "body": "OK"}
    assert mock_process.call_count == 2
