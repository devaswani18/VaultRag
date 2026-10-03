"""Chat conversations router: endpoints for privacy-preserving user conversation history.

Strictly authenticated; scoped exclusively to caller's own conversations
(ctx.tenant_id, ctx.user_id). No admin route exists to read or list other users' conversations.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field

from vaultrag.audit.hashchain import append_event
from vaultrag.auth.dependencies import get_ctx
from vaultrag.chat.history import ConversationRepo
from vaultrag.context import RequestContext
from vaultrag.errors import ValidationFailed

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/chat/conversations", tags=["chat-conversations"])


class ClearConversationsRequest(BaseModel):
    confirm: bool = Field(..., description="Must be true to clear all conversations")


@router.get("")
async def list_conversations(
    limit: int = Query(50, ge=1, le=50),
    next_token: str | None = Query(None),
    ctx: RequestContext = Depends(get_ctx),  # noqa: B008
) -> dict[str, Any]:
    """List the caller's own conversations, newest first (max 50)."""
    repo = ConversationRepo()
    items, token_out = repo.list(ctx.tenant_id, ctx.user_id, limit=limit, next_token=next_token)
    return {
        "conversations": items,
        "next_token": token_out,
    }


@router.get("/{conversation_id}")
async def get_conversation_messages(
    conversation_id: str,
    limit: int = Query(100, ge=1, le=200),
    next_token: str | None = Query(None),
    ctx: RequestContext = Depends(get_ctx),  # noqa: B008
) -> dict[str, Any]:
    """Retrieve messages for a specific conversation belonging to caller."""
    repo = ConversationRepo()
    conv = repo.get_conversation(ctx.tenant_id, ctx.user_id, conversation_id)
    messages, token_out = repo.get_messages(
        ctx.tenant_id, ctx.user_id, conversation_id, limit=limit, next_token=next_token
    )
    return {
        "conversation": conv,
        "messages": messages,
        "next_token": token_out,
    }


@router.delete("/{conversation_id}")
async def delete_conversation(
    conversation_id: str,
    ctx: RequestContext = Depends(get_ctx),  # noqa: B008
) -> dict[str, Any]:
    """Delete a single conversation and its messages belonging to caller."""
    repo = ConversationRepo()
    msgs_deleted = repo.delete_one(ctx.tenant_id, ctx.user_id, conversation_id)

    # Cryptographic audit event with counts only (no title, no text)
    append_event(
        ctx,
        action="conversation_deleted",
        details={
            "conversation_id": conversation_id,
            "messages_deleted": msgs_deleted,
        },
    )

    return {
        "status": "deleted",
        "conversation_id": conversation_id,
        "messages_deleted": msgs_deleted,
    }


@router.delete("")
async def clear_all_conversations(
    req: ClearConversationsRequest,
    ctx: RequestContext = Depends(get_ctx),  # noqa: B008
) -> dict[str, Any]:
    """Clear all conversations and messages for the caller."""
    if not req.confirm:
        raise ValidationFailed("Confirmation required to clear all conversations")

    repo = ConversationRepo()
    convs_deleted, msgs_deleted = repo.delete_all(ctx.tenant_id, ctx.user_id)

    # Cryptographic audit event with counts only (no title, no text)
    append_event(
        ctx,
        action="conversations_cleared",
        details={
            "conversations_deleted": convs_deleted,
            "messages_deleted": msgs_deleted,
        },
    )

    return {
        "status": "cleared",
        "conversations_deleted": convs_deleted,
        "messages_deleted": msgs_deleted,
    }
