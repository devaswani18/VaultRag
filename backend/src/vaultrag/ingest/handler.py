from __future__ import annotations

import logging
import urllib.parse
from datetime import UTC, datetime
from typing import Any

from qdrant_client import models

from vaultrag.audit.hashchain import append_event
from vaultrag.clients.dynamo import DocumentRepo, DocumentStatus, TenantRepo
from vaultrag.clients.gemini import embed_texts
from vaultrag.clients.qdrant import upsert_chunks
from vaultrag.clients.s3 import delete_object, download_bytes, parse_object_key
from vaultrag.config import get_settings
from vaultrag.errors import NotFound, ValidationFailed
from vaultrag.ingest.chunker import chunk_document
from vaultrag.ingest.parsers import parse_document
from vaultrag.ingest.pipeline import ChunkContext, DocumentBlocked, get_default_hooks, run_hooks

logger = logging.getLogger(__name__)


def _safe_error_message(exc: Exception) -> str:
    """Return safe user-facing error message without raw document or prompt text."""
    if isinstance(exc, (ValidationFailed, DocumentBlocked)):
        return exc.message
    return f"Processing failed: {type(exc).__name__}"


def process_record(record: dict[str, Any]) -> None:
    """Process a single S3 ObjectCreated event record."""
    s3_info = record.get("s3", {})
    raw_key = s3_info.get("object", {}).get("key", "")
    if not raw_key:
        logger.warning("Record missing s3.object.key, skipping")
        return

    # S3 event object keys are URL-encoded
    key = urllib.parse.unquote_plus(raw_key)

    # 1. Parse object key (tenant_id, doc_id, ext). Ignore and log any non-matching keys.
    try:
        tenant_id, doc_id, ext = parse_object_key(key)
    except ValidationFailed:
        logger.warning("Ignoring S3 object with invalid key structure: %s", key)
        return

    # 2. Load document record by (tenant_id, doc_id). If missing: ignore and log.
    repo = DocumentRepo()
    try:
        doc = repo.get(tenant_id, doc_id)
    except NotFound:
        logger.warning(
            "Document record not found for tenant_id=%s, doc_id=%s. Ignoring event.",
            tenant_id,
            doc_id,
        )
        return
    except Exception as e:
        logger.error(
            "Unexpected error loading document doc_id=%s for tenant_id=%s: %s",
            doc_id,
            tenant_id,
            type(e).__name__,
        )
        return

    # Idempotency check: if status != PENDING_UPLOAD, skip duplicate event
    curr_status = doc.get("status")
    if curr_status != DocumentStatus.PENDING_UPLOAD.value:
        logger.info(
            "Document doc_id=%s status is '%s' (not PENDING_UPLOAD). Skipping duplicate event.",
            doc_id,
            curr_status,
        )
        return

    # 3-10. Processing pipeline with safe exception handling
    try:
        # 3. Set PROCESSING and verify size constraints
        repo.update_status(tenant_id, doc_id, DocumentStatus.PROCESSING)

        settings = get_settings()
        max_bytes = settings.max_upload_mb * 1024 * 1024
        declared_size = int(doc.get("size_bytes", 0))

        # 4. Download bytes (bounded) and validate magic bytes
        bucket = s3_info.get("bucket", {}).get("name")
        data = download_bytes(key, max_bytes=max_bytes, bucket=bucket)
        actual_size = len(data)

        if actual_size <= 0:
            raise ValidationFailed("Uploaded object is empty")
        if actual_size > max_bytes:
            raise ValidationFailed(
                f"Uploaded object size {actual_size} exceeds max {max_bytes} bytes"
            )

        # Verify object matches declared size within tolerance
        tolerance = max(1024, int(declared_size * 0.05))
        if abs(actual_size - declared_size) > tolerance:
            raise ValidationFailed("Uploaded size does not match declared size within tolerance")

        # 5. Parse -> list of (page, text)
        pages = parse_document(data, ext)

        total_text_len = sum(len(text.strip()) for _, text in pages)
        if total_text_len < 20:
            raise ValidationFailed("no extractable text (scanned documents are not supported yet)")

        # 6. Chunk recursively (target 1000, overlap 150, min 100, deterministic uuid5 IDs)
        chunks = chunk_document(
            pages=pages,
            tenant_id=tenant_id,
            doc_id=doc_id,
            target_size=1000,
            overlap=150,
            min_size=100,
        )
        if not chunks:
            raise ValidationFailed("no extractable text (scanned documents are not supported yet)")

        # 7. Run hook pipeline
        tenant_repo = TenantRepo()
        try:
            tenant_record = tenant_repo.get(tenant_id)
            tenant_settings = tenant_record.get("settings", {})
        except Exception:
            tenant_settings = {}

        hooks = get_default_hooks()
        chunk_contexts = [
            ChunkContext(
                chunk=c,
                text=c.text,
                tenant_id=tenant_id,
                doc_id=doc_id,
                filename=doc.get("filename", ""),
            )
            for c in chunks
        ]
        contexts = run_hooks(chunk_contexts, hooks, tenant_settings)
        active_contexts = [ctx for ctx in contexts if not ctx.is_dropped and ctx.text.strip()]

        # 8. Aggregate security summaries and reports (NO raw text)
        doc_pii_summary: dict[str, int] = {}
        injection_summary: dict[str, int] = {"low": 0, "medium": 0, "high": 0}
        quarantine_report: list[dict[str, Any]] = []

        for ctx in contexts:
            # PII summary
            for ptype, pcount in ctx.payload.get("pii_summary", {}).items():
                doc_pii_summary[ptype] = doc_pii_summary.get(ptype, 0) + pcount

            # Injection summary & quarantine report
            irisk = ctx.payload.get("injection_risk", "low")
            injection_summary[irisk] = injection_summary.get(irisk, 0) + 1
            if irisk in ("medium", "high") or ctx.is_dropped:
                quarantine_report.append(
                    {
                        "chunk_index": ctx.chunk.index if ctx.chunk else 0,
                        "page": ctx.chunk.page if ctx.chunk else None,
                        "risk": irisk,
                        "reasons": ctx.payload.get("injection_reasons", []),
                    }
                )

        total_chunks = len(contexts)
        dropped_chunks = len([c for c in contexts if c.is_dropped])
        drop_ratio = (dropped_chunks / total_chunks) if total_chunks > 0 else 0.0

        # If > 30% of chunks are dropped or all chunks dropped, quarantine whole document
        if drop_ratio > 0.30 or not active_contexts:
            logger.warning(
                "Document quarantined: tenant=%s, doc=%s, dropped=%d/%d (%.1f%%)",
                tenant_id,
                doc_id,
                dropped_chunks,
                total_chunks,
                drop_ratio * 100,
            )
            err_msg = (
                f"Quarantined: {dropped_chunks}/{total_chunks} chunks dropped by security policy"
            )
            repo.update_status(
                tenant_id,
                doc_id,
                DocumentStatus.QUARANTINED,
                error=err_msg,
                extra_fields={
                    "chunk_count": 0,
                    "pii_summary": doc_pii_summary,
                    "injection_summary": injection_summary,
                    "quarantine_report": quarantine_report,
                },
            )
            try:
                append_event(
                    "system:ingest",
                    action="document_quarantined",
                    resource_id=doc_id,
                    outcome="quarantined",
                    details={
                        "risk": "high" if drop_ratio > 0.30 else "medium",
                        "reasons": [f"dropped_{dropped_chunks}_of_{total_chunks}"],
                    },
                    tenant_id=tenant_id,
                )
            except Exception as audit_err:
                logger.error("Failed to append document_quarantined audit record: %s", audit_err)
            return

        # 9. Embed all remaining active chunks (RETRIEVAL_DOCUMENT) in batches
        texts_to_embed = [ctx.text for ctx in active_contexts]
        embeddings = embed_texts(texts_to_embed, task_type="RETRIEVAL_DOCUMENT")

        # 10. Upsert to Qdrant with complete schema payload
        now_iso = datetime.now(UTC).isoformat()
        points: list[models.PointStruct] = []
        for ctx, emb in zip(active_contexts, embeddings, strict=True):
            payload = {
                "tenant_id": tenant_id,
                "doc_id": doc_id,
                "chunk_index": ctx.chunk.index,
                "text": ctx.text,
                "filename": doc.get("filename", ""),
                "page": ctx.chunk.page,
                "visibility": doc.get("visibility", "tenant"),
                "allowed_roles": doc.get("allowed_roles", []),
                "allowed_users": doc.get("allowed_users", []),
                "owner_user_id": doc.get("owner_user_id", ""),
                "pii_found": False,
                "pii_types": [],
                "injection_risk": "low",
                "created_at": now_iso,
            }
            if ctx.payload:
                payload.update(ctx.payload)

            points.append(
                models.PointStruct(
                    id=ctx.chunk.chunk_id,
                    vector=emb,
                    payload=payload,
                )
            )

        upsert_chunks(points)

        # 11. Update document to READY with security summaries
        repo.update_status(
            tenant_id,
            doc_id,
            DocumentStatus.READY,
            extra_fields={
                "chunk_count": len(points),
                "pii_summary": doc_pii_summary,
                "injection_summary": injection_summary,
                "quarantine_report": quarantine_report,
            },
        )
        try:
            append_event(
                "system:ingest",
                action="document_ready",
                resource_id=doc_id,
                outcome="ok",
                details={"chunk_count": len(points)},
                tenant_id=tenant_id,
            )
        except Exception as audit_err:
            logger.error("Failed to append document_ready audit record: %s", audit_err)

        logger.info(
            "Document ingestion completed: tenant_id=%s, doc_id=%s, chunk_count=%d",
            tenant_id,
            doc_id,
            len(points),
        )

        # 12. Handle retain_original_files policy
        if not tenant_settings.get("retain_original_files", True):
            try:
                delete_object(key)
                logger.info("Deleted original S3 object per retain_original_files=False: %s", key)
            except Exception:
                logger.exception("Failed to delete original S3 object: %s", key)

    except DocumentBlocked as e:
        # Quarantine blocked document
        logger.warning(
            "Document blocked by security policy: tenant_id=%s, doc_id=%s",
            tenant_id,
            doc_id,
        )
        safe_msg = _safe_error_message(e)
        inj_sum = injection_summary if "injection_summary" in locals() else {}
        quar_rep = quarantine_report if "quarantine_report" in locals() else []
        try:
            repo.update_status(
                tenant_id,
                doc_id,
                DocumentStatus.QUARANTINED,
                error=safe_msg,
                extra_fields={
                    "chunk_count": 0,
                    "pii_summary": doc_pii_summary if "doc_pii_summary" in locals() else {},
                    "injection_summary": inj_sum,
                    "quarantine_report": quar_rep,
                },
            )
            try:
                append_event(
                    "system:ingest",
                    action="document_quarantined",
                    resource_id=doc_id,
                    outcome="quarantined",
                    details={
                        "risk": "high",
                        "reasons": getattr(e, "reasons", ["document_blocked"]),
                    },
                    tenant_id=tenant_id,
                )
            except Exception as audit_err:
                logger.error("Failed to append document_quarantined audit record: %s", audit_err)
        except Exception:
            logger.exception(
                "Failed to update document to QUARANTINED for tenant_id=%s, doc_id=%s",
                tenant_id,
                doc_id,
            )
    except Exception as e:
        # Safe short error string, log exception type only (NEVER log document text)
        logger.error(
            "Document ingestion failed: tenant_id=%s, doc_id=%s, error_type=%s",
            tenant_id,
            doc_id,
            type(e).__name__,
        )
        safe_msg = _safe_error_message(e)
        try:
            repo.update_status(tenant_id, doc_id, DocumentStatus.FAILED, error=safe_msg)
        except Exception:
            logger.exception(
                "Failed to update document to FAILED for tenant_id=%s, doc_id=%s",
                tenant_id,
                doc_id,
            )


def handler(event: dict[str, Any], context: Any = None) -> dict[str, Any]:
    """AWS Lambda entry point for S3 ObjectCreated events."""
    records = event.get("Records", [])
    logger.info("Ingest handler received %d S3 record(s)", len(records))

    for record in records:
        process_record(record)

    return {"statusCode": 200, "body": "OK"}
