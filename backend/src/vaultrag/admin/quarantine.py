"""Admin quarantine router: GET /admin/quarantine.

Restricted strictly to callers with the 'admin' role.
Lists quarantined documents and prompt injection reports without revealing document text.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends

from vaultrag.auth.dependencies import require_role
from vaultrag.clients.dynamo import DocumentRepo
from vaultrag.context import RequestContext, Role

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/admin/quarantine", tags=["admin-quarantine"])


@router.get("")
async def list_quarantined_documents(
    ctx: RequestContext = Depends(require_role(Role.admin)),  # noqa: B008
) -> list[dict[str, Any]]:
    """List documents with quarantine_report or QUARANTINED status (admin only, NO text)."""
    repo = DocumentRepo()
    items, _ = repo.list_for_tenant(ctx.tenant_id, limit=100)

    quarantined_docs: list[dict[str, Any]] = []
    for d in items:
        status = d.get("status", "")
        quarantine_report = d.get("quarantine_report") or []
        has_quarantine_entries = bool(quarantine_report)

        if status == "QUARANTINED" or has_quarantine_entries:
            # Exclude any document or chunk text to prevent confidential data leakage
            quarantined_docs.append(
                {
                    "doc_id": d.get("doc_id", ""),
                    "filename": d.get("filename", ""),
                    "status": status,
                    "created_at": d.get("created_at", ""),
                    "chunk_count": d.get("chunk_count", 0),
                    "error": d.get("error"),
                    "injection_summary": d.get("injection_summary", {}),
                    "quarantine_report": quarantine_report,
                }
            )

    return quarantined_docs
