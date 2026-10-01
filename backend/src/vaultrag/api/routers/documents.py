from __future__ import annotations

import time
import uuid
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from vaultrag.auth.dependencies import get_ctx
from vaultrag.clients.dynamo import DocumentRepo
from vaultrag.clients.s3 import build_object_key, create_presigned_post
from vaultrag.config import get_settings
from vaultrag.context import RequestContext, Role
from vaultrag.errors import ValidationFailed

router = APIRouter(prefix="/documents", tags=["documents"])

ALLOWED_CONTENT_TYPES: dict[str, set[str]] = {
    "pdf": {"application/pdf"},
    "docx": {
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "application/docx",
    },
    "txt": {"text/plain"},
    "md": {"text/markdown", "text/plain", "text/x-markdown"},
}


class CreateDocumentRequest(BaseModel):
    filename: str = Field(..., description="Original name of the file to upload")
    content_type: str = Field(..., description="MIME type of the file")
    size_bytes: int = Field(..., description="File size in bytes")
    visibility: str = Field("tenant", description="Document visibility: tenant | roles | private")
    allowed_roles: list[str] | None = Field(
        None, description="Permitted roles if visibility is roles"
    )
    allowed_users: list[str] | None = Field(None, description="Permitted user sub IDs")


def _generate_time_sortable_doc_id() -> str:
    """Generate lexicographically time-sortable document ID."""
    timestamp_ms = int(time.time() * 1000)
    random_suffix = uuid.uuid4().hex[:12]
    return f"doc_{timestamp_ms:013d}_{random_suffix}"


@router.post("")
async def create_document(
    req: CreateDocumentRequest,
    ctx: RequestContext = Depends(get_ctx),  # noqa: B008
) -> dict[str, Any]:
    """Initiate document upload, create PENDING_UPLOAD record, and return presigned S3 POST URL."""
    settings = get_settings()

    # 1. Sanitise and validate filename
    sanitized_filename = Path(req.filename).name.strip()
    if not sanitized_filename or sanitized_filename in (".", ".."):
        raise ValidationFailed("Invalid or empty filename")
    if len(sanitized_filename) > 120:
        raise ValidationFailed("Filename exceeds maximum length of 120 characters")

    # 2. Validate file extension
    ext = Path(sanitized_filename).suffix.lstrip(".").lower()
    if not ext or ext not in ALLOWED_CONTENT_TYPES:
        raise ValidationFailed(
            f"Unsupported file extension '.{ext}'. Supported extensions: pdf, docx, txt, md"
        )

    # 3. Validate content-type against extension
    base_ct = req.content_type.split(";")[0].strip().lower()
    if base_ct not in ALLOWED_CONTENT_TYPES[ext]:
        raise ValidationFailed(
            f"Content-Type '{req.content_type}' does not match extension '.{ext}'"
        )

    # 4. Validate file size constraints
    max_bytes = settings.max_upload_mb * 1024 * 1024
    if req.size_bytes <= 0 or req.size_bytes > max_bytes:
        msg = (
            f"size_bytes must be between 1 and {max_bytes} bytes "
            f"({settings.max_upload_mb} MB limit)"
        )
        raise ValidationFailed(msg)

    # 5. Validate visibility and role constraints
    visibility = req.visibility.lower()
    if visibility not in ("tenant", "roles", "private"):
        raise ValidationFailed("Invalid visibility. Must be one of: 'tenant', 'roles', 'private'")

    allowed_roles: list[str] = []
    if req.allowed_roles is not None:
        valid_roles = {r.value for r in Role}
        for r in req.allowed_roles:
            r_clean = r.strip().lower()
            if r_clean not in valid_roles:
                raise ValidationFailed(
                    f"Invalid role '{r}' in allowed_roles. Allowed: {sorted(valid_roles)}"
                )
            allowed_roles.append(r_clean)

    if visibility == "roles" and not allowed_roles:
        raise ValidationFailed("Visibility 'roles' requires non-empty allowed_roles")

    allowed_users: list[str] = req.allowed_users or []
    if visibility == "private" and not allowed_users:
        allowed_users = [ctx.user_id]

    # 6. Generate time-sortable doc_id and deterministic S3 key
    doc_id = _generate_time_sortable_doc_id()
    s3_key = build_object_key(ctx.tenant_id, doc_id, ext)

    # 7. Create DynamoDB document record with PENDING_UPLOAD status
    repo = DocumentRepo()
    repo.create(
        tenant_id=ctx.tenant_id,
        doc_id=doc_id,
        filename=sanitized_filename,
        content_type=base_ct,
        size_bytes=req.size_bytes,
        visibility=visibility,
        allowed_roles=allowed_roles,
        allowed_users=allowed_users,
        owner_user_id=ctx.user_id,
        s3_key=s3_key,
        chunk_count=0,
    )

    # 8. Generate presigned S3 POST data
    presigned = create_presigned_post(
        key=s3_key,
        content_type=base_ct,
        max_bytes=max_bytes,
        expires=300,
    )

    return {
        "doc_id": doc_id,
        "upload": {
            "url": presigned["url"],
            "fields": presigned["fields"],
        },
        "expires_in": 300,
    }


@router.get("")
async def list_documents(
    ctx: RequestContext = Depends(get_ctx),  # noqa: B008
) -> list[dict[str, Any]]:
    """List documents for the current tenant."""
    repo = DocumentRepo()
    items, _ = repo.list_for_tenant(ctx.tenant_id, limit=100)

    return [
        {
            "id": d["doc_id"],
            "doc_id": d["doc_id"],
            "filename": d.get("filename", ""),
            "status": d.get("status", ""),
            "size": d.get("size_bytes", 0),
            "created_at": d.get("created_at", ""),
            "chunk_count": d.get("chunk_count", 0),
        }
        for d in items
    ]


@router.get("/{doc_id}")
async def get_document(
    doc_id: str,
    ctx: RequestContext = Depends(get_ctx),  # noqa: B008
) -> dict[str, Any]:
    """Retrieve document details by doc_id (strictly scoped to the caller's tenant)."""
    repo = DocumentRepo()
    doc = repo.get(ctx.tenant_id, doc_id)

    return {
        "id": doc["doc_id"],
        "doc_id": doc["doc_id"],
        "filename": doc.get("filename", ""),
        "status": doc.get("status", ""),
        "size": doc.get("size_bytes", 0),
        "created_at": doc.get("created_at", ""),
        "chunk_count": doc.get("chunk_count", 0),
        "visibility": doc.get("visibility", "tenant"),
        "allowed_roles": doc.get("allowed_roles", []),
        "allowed_users": doc.get("allowed_users", []),
        "owner_user_id": doc.get("owner_user_id", ""),
    }
