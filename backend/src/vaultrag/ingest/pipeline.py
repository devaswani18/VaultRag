from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

from vaultrag.errors import AppError
from vaultrag.ingest.chunker import Chunk


class DocumentBlocked(AppError):
    """Raised by a security hook to halt document ingestion and quarantine the document."""

    default_status = 400
    default_code = "document_blocked"
    default_message = "Document ingestion was blocked by security policy"

    def __init__(
        self,
        reason: str,
        *,
        rule: str = "security_policy",
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            status=self.default_status,
            code=self.default_code,
            message=reason,
            details={"rule": rule, **(details or {})},
        )


@dataclass
class ChunkContext:
    """Mutable context wrapping a chunk through the ingestion hook pipeline."""

    chunk: Chunk
    text: str = ""
    payload: dict[str, Any] = field(default_factory=dict)
    is_dropped: bool = False
    tenant_id: str = ""
    doc_id: str = ""
    filename: str = ""

    def __post_init__(self) -> None:
        if not self.text and self.chunk:
            self.text = self.chunk.text


class Hook(Protocol):
    """Protocol for document ingestion inspection/transformation hooks."""

    def __call__(self, ctx: ChunkContext, settings: dict[str, Any]) -> None:
        """Inspect or mutate the chunk context.

        May modify ctx.text, append to ctx.payload, set ctx.is_dropped = True,
        or raise DocumentBlocked to halt ingestion and quarantine the document.
        """
        ...


def get_default_hooks() -> list[Hook]:
    """Return the ordered list of registered ingestion hooks."""
    from vaultrag.ingest.hooks.pii_hook import PIIHook

    return [
        PIIHook(),
    ]


def run_hooks(
    chunks: list[ChunkContext] | list[Chunk],
    hooks: list[Hook],
    tenant_settings: dict[str, Any] | None = None,
) -> list[ChunkContext]:
    """Execute all registered hooks sequentially on each document chunk.

    Raises DocumentBlocked if any hook flags a catastrophic security violation.
    Returns the processed list of ChunkContext objects.
    """
    settings = tenant_settings or {}
    contexts: list[ChunkContext] = []
    for c in chunks:
        if isinstance(c, ChunkContext):
            contexts.append(c)
        else:
            contexts.append(ChunkContext(chunk=c, text=c.text))

    for hook in hooks:
        for ctx in contexts:
            if ctx.is_dropped:
                continue
            hook(ctx, settings)

    return contexts
