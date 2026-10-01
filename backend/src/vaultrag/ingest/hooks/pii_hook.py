"""PII Inspection & Redaction Hook for Document Ingestion Pipeline."""

from __future__ import annotations

import logging
from typing import Any

from vaultrag.ingest.pipeline import ChunkContext, DocumentBlocked
from vaultrag.security.pii_guard import apply_policy

logger = logging.getLogger(__name__)


class PIIHook:
    """Document ingestion hook that enforces tenant PII policy on chunk text."""

    def __call__(self, ctx: ChunkContext, settings: dict[str, Any]) -> None:
        """Inspect chunk text, redact or block per tenant policy, and set chunk metadata."""
        pii_mode = str(settings.get("pii_mode", "redact")).strip().lower()

        # Apply guard policy
        result = apply_policy(ctx.text, mode=pii_mode)

        if result.blocked:
            logger.warning(
                "Document blocked by PII policy: tenant_id=%s, doc_id=%s, chunk_index=%d",
                ctx.tenant_id,
                ctx.doc_id,
                ctx.chunk.index if ctx.chunk else -1,
            )
            raise DocumentBlocked(
                reason="blocked by PII policy",
                rule="pii_policy",
                details={"findings_summary": result.findings_summary},
            )

        if pii_mode == "redact":
            ctx.text = result.text

        # Record chunk-level PII metadata into payload
        ctx.payload["pii_found"] = bool(result.findings_summary)
        ctx.payload["pii_types"] = sorted(result.findings_summary.keys())
        ctx.payload["pii_summary"] = result.findings_summary
