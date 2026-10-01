"""Prompt Injection Inspection Hook for Document Ingestion Pipeline."""

from __future__ import annotations

import logging
from typing import Any

from vaultrag.ingest.pipeline import ChunkContext
from vaultrag.security.injection_guard import scan_text

logger = logging.getLogger(__name__)


class InjectionHook:
    """Document ingestion hook that enforces tenant injection_policy on chunk text."""

    def __call__(self, ctx: ChunkContext, settings: dict[str, Any]) -> None:
        """Inspect chunk text, flag or drop per tenant injection_policy."""
        policy = str(settings.get("injection_policy", "quarantine_high")).strip().lower()

        if policy == "off":
            ctx.payload["injection_risk"] = "low"
            ctx.payload["injection_reasons"] = []
            return

        result = scan_text(ctx.text)
        chunk_idx = ctx.chunk.index if ctx.chunk else 0

        # Always record risk and reasons into chunk payload
        ctx.payload["injection_risk"] = result.risk
        ctx.payload["injection_reasons"] = result.reasons

        # Track on context for document-level report aggregation
        if result.risk == "high" and policy == "quarantine_high":
            ctx.is_dropped = True
            logger.warning(
                "Chunk dropped for injection risk: tenant=%s doc=%s chunk=%d reasons=%s",
                ctx.tenant_id,
                ctx.doc_id,
                chunk_idx,
                result.reasons,
            )
