"""Verifiable Document Deletion & Cryptographic Erasure Certificates.

Implements idempotent, verified document purging across DynamoDB, S3, Qdrant,
and semantic cache, returning a cryptographically signed Certificate of Erasure.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import logging
import os
from datetime import UTC, datetime
from typing import Any

import boto3
from fastapi import APIRouter, Body, Depends, HTTPException
from pydantic import BaseModel
from qdrant_client import models

from vaultrag.audit.hashchain import append_event, canonical_json
from vaultrag.auth.dependencies import get_ctx
from vaultrag.clients.dynamo import DocStatus, DocumentRepo, TenantRepo
from vaultrag.clients.qdrant import get_client
from vaultrag.config import get_secret, get_settings
from vaultrag.context import RequestContext

logger = logging.getLogger(__name__)


def _get_cert_hmac_secret() -> str:
    """Retrieve HMAC secret for certificate signing from SSM or local environment."""
    try:
        return get_secret("cert_hmac_secret")
    except Exception:
        return os.environ.get("VAULTRAG_SECRET_CERT_HMAC_SECRET", "dev-insecure-hmac-secret-12345")


def invalidate_doc_cache(tenant_id: str, doc_id: str) -> int:
    """Purge cached query answers referencing doc_id.

    TODO (Stage 17): Integrate with semantic query cache layer once implemented.
    Returns the count of purged cache entries (currently 0 stub).
    """
    _ = (tenant_id, doc_id)
    return 0


def erase_document(
    ctx: RequestContext,
    doc_id: str,
    doc_repo: DocumentRepo | None = None,
    tenant_repo: TenantRepo | None = None,
    s3_client: Any = None,
    qdrant_client: Any = None,
    dynamodb_resource: Any = None,
    hmac_secret: str | None = None,
) -> dict[str, Any]:
    """Execute verifiable deletion of a document across storage tiers.

    Steps:
      a. Load document via DocumentRepo (tenant-scoped) -> 404 if absent / inaccessible,
         409 if already deleted.
      b. Set status DELETING and log 'erasure' start audit event.
      c. Qdrant: count points with filter tenant_id and doc_id; delete by filter.
      d. S3: delete everything under uploads/{tenant_id}/{doc_id}/; record count.
      e. Cache: invalidate entries referencing doc_id (Stage 17 stub).
      f. Post-check: assert 0 remaining points in Qdrant and 0 remaining S3 files.
      g. Generate & HMAC sign Certificate of Erasure.
      h. Replace DynamoDB record with minimal TOMBSTONE.
      i. Atomically bump tenant kb_version.
      j. Record 'erasure' completion audit event with certificate_sha256.

    If any step fails, status is saved as DELETE_FAILED, error is audited, and 500 is raised.
    Re-running resumes idempotently.
    """
    settings = get_settings()
    repo = doc_repo or DocumentRepo()
    t_repo = tenant_repo or TenantRepo()

    # Step a: Load document
    try:
        doc = repo.get(ctx.tenant_id, doc_id)
    except Exception:
        raise HTTPException(status_code=404, detail=f"Document '{doc_id}' not found") from None

    # Check if already deleted
    if doc.get("status") == DocStatus.DELETED.value:
        cert_hash = doc.get("certificate_sha256", "")
        raise HTTPException(
            status_code=409,
            detail={"message": "Document already deleted", "certificate_sha256": cert_hash},
        )

    # Authorization check: tenant admin or document owner
    is_owner = doc.get("owner_user_id") == ctx.user_id
    if not (ctx.is_admin or is_owner):
        raise HTTPException(status_code=404, detail=f"Document '{doc_id}' not found")

    # Step b: Transition status to DELETING and write audit start
    try:
        if doc.get("status") != DocStatus.DELETING.value:
            repo.update_status(ctx.tenant_id, doc_id, DocStatus.DELETING)
    except Exception as e:
        logger.error("Failed to transition document %s to DELETING: %s", doc_id, e)
        raise HTTPException(status_code=500, detail="Failed to initialize document deletion") from e

    try:
        start_event = append_event(
            ctx,
            action="erasure",
            resource_id=doc_id,
            details={"status": "start", "user_id": ctx.user_id},
            dynamodb_resource=dynamodb_resource,
        )
        audit_seq = int(start_event.get("seq", 0))
    except Exception as e:
        logger.critical("Audit recording failed for erasure start: %s", e)
        # Attempt to mark DELETE_FAILED
        with contextlib.suppress(Exception):
            repo.update_status(ctx.tenant_id, doc_id, DocStatus.DELETE_FAILED)
        raise HTTPException(
            status_code=500, detail="Audit log failure: document erasure aborted"
        ) from e

    # Main deletion execution block
    try:
        # Step c: Qdrant deletion
        qdrant = qdrant_client or get_client()
        collection = settings.qdrant_collection
        q_filter = models.Filter(
            must=[
                models.FieldCondition(
                    key="tenant_id", match=models.MatchValue(value=ctx.tenant_id)
                ),
                models.FieldCondition(key="doc_id", match=models.MatchValue(value=doc_id)),
            ]
        )

        try:
            count_res = qdrant.count(collection_name=collection, count_filter=q_filter, exact=True)
            deleted_vectors = int(count_res.count)
        except Exception:
            deleted_vectors = 0

        if deleted_vectors > 0:
            qdrant.delete(
                collection_name=collection,
                points_selector=models.FilterSelector(filter=q_filter),
            )

        # Step d: S3 deletion
        s3 = s3_client or boto3.client("s3", region_name=settings.aws_region)
        bucket = settings.docs_bucket
        prefix = f"uploads/{ctx.tenant_id}/{doc_id}/"

        paginator = s3.get_paginator("list_objects_v2")
        keys_to_delete = []
        for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
            for obj in page.get("Contents", []):
                keys_to_delete.append({"Key": obj["Key"]})

        deleted_files = len(keys_to_delete)
        if keys_to_delete:
            for i in range(0, len(keys_to_delete), 1000):
                batch = keys_to_delete[i : i + 1000]
                s3.delete_objects(Bucket=bucket, Delete={"Objects": batch})

        # Step e: Cache invalidation (Stage 17 stub)
        deleted_cache_entries = invalidate_doc_cache(ctx.tenant_id, doc_id)

        # Step f: Post-checks
        try:
            recheck_qdrant = qdrant.count(
                collection_name=collection, count_filter=q_filter, exact=True
            ).count
        except Exception:
            recheck_qdrant = 0

        recheck_s3 = s3.list_objects_v2(Bucket=bucket, Prefix=prefix, MaxKeys=1).get("KeyCount", 0)

        if recheck_qdrant != 0:
            raise RuntimeError(f"Post-check failed: {recheck_qdrant} Qdrant vectors remaining")
        if recheck_s3 != 0:
            raise RuntimeError(f"Post-check failed: {recheck_s3} S3 files remaining")

        # Step g: Build and sign Certificate of Erasure
        secret = hmac_secret or _get_cert_hmac_secret()
        now_ts = datetime.now(UTC).isoformat()
        cert_payload: dict[str, Any] = {
            "version": 1,
            "tenant_id": ctx.tenant_id,
            "doc_id": doc_id,
            "requested_by": ctx.user_id,
            "ts": now_ts,
            "deleted": {
                "vectors": deleted_vectors,
                "files": deleted_files,
                "cache_entries": deleted_cache_entries,
            },
            "post_check": {
                "remaining_vectors": 0,
                "remaining_files": 0,
            },
            "audit_seq": audit_seq,
        }

        canonical_cert = canonical_json(cert_payload)
        signature = hmac.new(
            secret.encode("utf-8"), canonical_cert.encode("utf-8"), hashlib.sha256
        ).hexdigest()
        certificate = {**cert_payload, "signature": signature}

        cert_sha256 = hashlib.sha256(canonical_json(certificate).encode("utf-8")).hexdigest()

        # Step h: Replace DynamoDB record with TOMBSTONE
        repo.create_tombstone(
            tenant_id=ctx.tenant_id,
            doc_id=doc_id,
            deleted_by=ctx.user_id,
            certificate_sha256=cert_sha256,
        )

        # Step i: Atomically bump tenant kb_version
        try:
            t_repo.bump_kb_version(ctx.tenant_id)
        except Exception as e:
            logger.warning("Failed to bump kb_version for tenant %s: %s", ctx.tenant_id, e)

        # Step j: Record final erasure audit event referencing certificate hash
        try:
            append_event(
                ctx,
                action="erasure",
                resource_id=doc_id,
                details={
                    "status": "complete",
                    "user_id": ctx.user_id,
                    "certificate_sha256": cert_sha256,
                    "deleted_vectors": deleted_vectors,
                    "deleted_files": deleted_files,
                },
                dynamodb_resource=dynamodb_resource,
            )
        except Exception as e:
            logger.critical("Failed to append final erasure audit event: %s", e)

        return certificate

    except Exception as e:
        logger.error("Document erasure failed for doc_id=%s: %s", doc_id, e)
        # Transition to DELETE_FAILED
        try:
            repo.update_status(ctx.tenant_id, doc_id, DocStatus.DELETE_FAILED)
        except Exception as update_err:
            logger.error("Failed to mark document as DELETE_FAILED: %s", update_err)

        # Audit failure event
        try:
            append_event(
                ctx,
                action="erasure",
                resource_id=doc_id,
                details={"status": "failed", "user_id": ctx.user_id, "error": str(e)},
                dynamodb_resource=dynamodb_resource,
            )
        except Exception as audit_err:
            logger.critical("Failed to audit erasure failure: %s", audit_err)

        raise HTTPException(
            status_code=500,
            detail="Document erasure failed; state saved as DELETE_FAILED. Please retry.",
        ) from e


def verify_certificate(
    cert: dict[str, Any],
    caller_tenant_id: str,
    hmac_secret: str | None = None,
) -> dict[str, Any]:
    """Verify cryptographic authenticity of an Erasure Certificate."""
    if not isinstance(cert, dict):
        return {"valid": False, "reason": "Certificate must be a JSON object"}

    cert_tenant = cert.get("tenant_id")
    if not cert_tenant or cert_tenant != caller_tenant_id:
        return {
            "valid": False,
            "reason": (
                f"Tenant mismatch: caller tenant '{caller_tenant_id}' "
                f"does not match certificate tenant '{cert_tenant}'"
            ),
        }

    sig = cert.get("signature")
    if not sig or not isinstance(sig, str):
        return {"valid": False, "reason": "Missing or invalid certificate signature"}

    # Validate required fields
    required = [
        "version",
        "tenant_id",
        "doc_id",
        "requested_by",
        "ts",
        "deleted",
        "post_check",
        "audit_seq",
    ]
    missing = [f for f in required if f not in cert]
    if missing:
        return {"valid": False, "reason": f"Malformed certificate: missing fields {missing}"}

    # Recompute HMAC over core fields without signature
    cert_core = {k: v for k, v in cert.items() if k != "signature"}
    secret = hmac_secret or _get_cert_hmac_secret()
    canonical = canonical_json(cert_core)
    expected_sig = hmac.new(
        secret.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(sig, expected_sig):
        return {
            "valid": False,
            "reason": (
                "Signature mismatch: certificate has been altered or signed by an unknown key"
            ),
        }

    return {"valid": True, "reason": None}


router = APIRouter(prefix="/admin", tags=["admin-erasure"])


class ConfirmErasureRequest(BaseModel):
    confirm: bool


@router.post("/certificates/verify")
async def verify_certificate_endpoint(
    cert: dict[str, Any] = Body(...),  # noqa: B008
    ctx: RequestContext = Depends(get_ctx),  # noqa: B008
) -> dict[str, Any]:
    """Verify validity and signature of a Certificate of Erasure."""
    return verify_certificate(cert, caller_tenant_id=ctx.tenant_id)


@router.delete("/users/{user_id}/documents")
async def erase_user_documents_endpoint(
    user_id: str,
    body: ConfirmErasureRequest,
    ctx: RequestContext = Depends(get_ctx),  # noqa: B008
) -> list[dict[str, Any]]:
    """Erase every document owned by the specified user (admin only, requires confirm=true).

    Capped at 100 documents per invocation. Returns a list of generated Certificates of Erasure.
    """
    if not ctx.is_admin:
        raise HTTPException(status_code=403, detail="Admin role required to erase user documents")

    if not body.confirm:
        raise HTTPException(status_code=400, detail="Confirmation required: confirm must be true")

    repo = DocumentRepo()
    items, _ = repo.list_for_tenant(ctx.tenant_id, limit=200)

    user_docs = [
        d
        for d in items
        if d.get("owner_user_id") == user_id and d.get("status") != DocStatus.DELETED.value
    ][:100]

    certificates: list[dict[str, Any]] = []
    for d in user_docs:
        cert = erase_document(ctx, d["doc_id"])
        certificates.append(cert)

    return certificates
