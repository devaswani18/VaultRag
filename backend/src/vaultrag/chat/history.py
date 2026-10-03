"""Privacy-preserving conversation history repository.

All operations strictly require (tenant_id, user_id) first.
The partition key `pk` is ALWAYS constructed as `<tenant_id>#<user_id>`.
It is never accepted from user input.

Caps enforced:
- Maximum 50 conversations per user (evict oldest conversation + messages when creating beyond 50)
- Maximum 200 messages per conversation (Conflict 409 beyond 200)

Item schema in DynamoDB:
- pk: "<tenant_id>#<user_id>"
- sk: "C#<conversation_id>" (conversation metadata)
      Attributes: conversation_id, title, created_at, updated_at, message_count, expires_at
- sk: "M#<conversation_id>#<zero-padded-seq>" (message)
      Attributes: conversation_id, seq, role ("user" | "assistant"), text,
                  trust ({score, abstained, partial}),
                  sources ([{doc_id, filename, chunk_id, page}] - NO snippets),
                  created_at, expires_at
"""

from __future__ import annotations

import base64
import json
import logging
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

import boto3
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError

from vaultrag.config import get_settings
from vaultrag.errors import Conflict, NotFound, ValidationFailed

logger = logging.getLogger(__name__)

MAX_CONVERSATIONS_PER_USER = 50
MAX_MESSAGES_PER_CONVERSATION = 200


def _floats_to_decimals(val: Any) -> Any:
    """Convert float values to Decimal for DynamoDB storage."""
    if isinstance(val, float):
        return Decimal(str(val))
    elif isinstance(val, dict):
        return {k: _floats_to_decimals(v) for k, v in val.items()}
    elif isinstance(val, list):
        return [_floats_to_decimals(item) for item in val]
    return val


def _decimals_to_floats(val: Any) -> Any:
    """Convert Decimal values to float/int for Python consumers."""
    if isinstance(val, Decimal):
        if val % 1 == 0:
            return int(val)
        return float(val)
    elif isinstance(val, dict):
        return {k: _decimals_to_floats(v) for k, v in val.items()}
    elif isinstance(val, list):
        return [_decimals_to_floats(item) for item in val]
    return val


class ConversationRepo:
    """Repository for user conversation history.

    Never accepts pk from callers. All methods take (tenant_id, user_id) as leading arguments.
    Never implements scan().
    """

    def __init__(self, table_name: str | None = None, dynamodb_resource: Any = None) -> None:
        settings = get_settings()
        self.table_name = table_name or getattr(
            settings, "conversations_table", "vaultrag-dev-conversations"
        )
        if dynamodb_resource is not None:
            self.dynamodb = dynamodb_resource
        else:
            self.dynamodb = boto3.resource("dynamodb", region_name=settings.aws_region)
        self.table = self.dynamodb.Table(self.table_name)

    @staticmethod
    def _build_pk(tenant_id: str, user_id: str) -> str:
        if not tenant_id or not user_id:
            raise ValidationFailed("tenant_id and user_id must be non-empty strings")
        return f"{tenant_id}#{user_id}"

    def create(
        self,
        tenant_id: str,
        user_id: str,
        conversation_id: str,
        title: str,
        ttl_days: int = 7,
    ) -> dict[str, Any]:
        """Create a new conversation record, evicting the oldest if limit of 50 is reached."""
        pk = self._build_pk(tenant_id, user_id)
        now = datetime.now(UTC)
        now_iso = now.isoformat()
        expires_at = int(now.timestamp()) + (ttl_days * 86400) if ttl_days > 0 else 0

        # Truncate title to 60 chars max
        safe_title = (title[:60] if title else "New Conversation").strip()

        # Check existing conversation count to enforce cap of 50
        existing_convs, _ = self.list(tenant_id, user_id, limit=MAX_CONVERSATIONS_PER_USER + 5)
        if len(existing_convs) >= MAX_CONVERSATIONS_PER_USER:
            # Sort by created_at ascending (oldest first) and evict
            sorted_by_age = sorted(existing_convs, key=lambda c: str(c.get("created_at", "")))
            # Evict enough to bring count below 50
            num_to_evict = len(existing_convs) - MAX_CONVERSATIONS_PER_USER + 1
            for i in range(num_to_evict):
                oldest_id = sorted_by_age[i]["conversation_id"]
                try:
                    self.delete_one(tenant_id, user_id, oldest_id)
                except Exception as e:
                    logger.warning("Failed to evict oldest conversation %s: %s", oldest_id, e)

        item: dict[str, Any] = {
            "pk": pk,
            "sk": f"C#{conversation_id}",
            "conversation_id": conversation_id,
            "title": safe_title,
            "created_at": now_iso,
            "updated_at": now_iso,
            "message_count": 0,
        }
        if expires_at > 0:
            item["expires_at"] = expires_at

        db_item = _floats_to_decimals(item)
        try:
            self.table.put_item(
                Item=db_item,
                ConditionExpression="attribute_not_exists(pk) AND attribute_not_exists(sk)",
            )
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
                raise Conflict(f"Conversation '{conversation_id}' already exists") from e
            raise

        return item

    def get_conversation(
        self,
        tenant_id: str,
        user_id: str,
        conversation_id: str,
    ) -> dict[str, Any]:
        """Get conversation metadata by owner. Returns 404 if not found or owned by someone else."""
        pk = self._build_pk(tenant_id, user_id)
        try:
            resp = self.table.get_item(Key={"pk": pk, "sk": f"C#{conversation_id}"})
        except ClientError as e:
            raise ValidationFailed(f"DynamoDB error: {e}") from e

        item = resp.get("Item")
        if not item:
            raise NotFound(f"Conversation '{conversation_id}' not found")

        return _decimals_to_floats(item)

    def list(
        self,
        tenant_id: str,
        user_id: str,
        limit: int = 50,
        next_token: str | None = None,
    ) -> tuple[list[dict[str, Any]], str | None]:
        """List caller's conversations (sk begins with 'C#'), newest first, max 50."""
        pk = self._build_pk(tenant_id, user_id)
        query_limit = min(limit, MAX_CONVERSATIONS_PER_USER)

        kwargs: dict[str, Any] = {
            "KeyConditionExpression": Key("pk").eq(pk) & Key("sk").begins_with("C#"),
            "Limit": query_limit,
        }

        if next_token:
            try:
                decoded = json.loads(base64.urlsafe_b64decode(next_token.encode()).decode())
                kwargs["ExclusiveStartKey"] = decoded
            except Exception as e:
                raise ValidationFailed(f"Invalid pagination token: {e}") from e

        try:
            response = self.table.query(**kwargs)
        except ClientError as e:
            raise ValidationFailed(f"DynamoDB query error: {e}") from e

        items = [_decimals_to_floats(i) for i in response.get("Items", [])]
        # Sort newest first by created_at / updated_at descending
        items.sort(key=lambda x: str(x.get("updated_at", x.get("created_at", ""))), reverse=True)

        last_key = response.get("LastEvaluatedKey")
        token_out = None
        if last_key:
            token_bytes = json.dumps(last_key, default=str).encode()
            token_out = base64.urlsafe_b64encode(token_bytes).decode()

        return items, token_out

    def get_messages(
        self,
        tenant_id: str,
        user_id: str,
        conversation_id: str,
        limit: int = 100,
        next_token: str | None = None,
    ) -> tuple[list[dict[str, Any]], str | None]:
        """Get messages for a conversation in sequence order (sk prefix M#<conversation_id>#)."""
        # Ensure conversation exists and is owned by caller
        self.get_conversation(tenant_id, user_id, conversation_id)

        pk = self._build_pk(tenant_id, user_id)
        sk_prefix = f"M#{conversation_id}#"

        kwargs: dict[str, Any] = {
            "KeyConditionExpression": Key("pk").eq(pk) & Key("sk").begins_with(sk_prefix),
            "Limit": limit,
            "ScanIndexForward": True,  # Chronological order
        }

        if next_token:
            try:
                decoded = json.loads(base64.urlsafe_b64decode(next_token.encode()).decode())
                kwargs["ExclusiveStartKey"] = decoded
            except Exception as e:
                raise ValidationFailed(f"Invalid pagination token: {e}") from e

        try:
            response = self.table.query(**kwargs)
        except ClientError as e:
            raise ValidationFailed(f"DynamoDB query error: {e}") from e

        items = [_decimals_to_floats(i) for i in response.get("Items", [])]

        last_key = response.get("LastEvaluatedKey")
        token_out = None
        if last_key:
            token_bytes = json.dumps(last_key, default=str).encode()
            token_out = base64.urlsafe_b64encode(token_bytes).decode()

        return items, token_out

    def append_messages(
        self,
        tenant_id: str,
        user_id: str,
        conversation_id: str,
        new_messages: list[dict[str, Any]],
        ttl_days: int = 7,
    ) -> list[dict[str, Any]]:
        """Append messages to a conversation and atomically update message_count.

        Enforces 200 message limit. If adding exceeds 200, raises Conflict 409.
        """
        if not new_messages:
            return []

        conv = self.get_conversation(tenant_id, user_id, conversation_id)
        current_count = int(conv.get("message_count", 0))

        if current_count + len(new_messages) > MAX_MESSAGES_PER_CONVERSATION:
            raise Conflict(f"Conversation message limit ({MAX_MESSAGES_PER_CONVERSATION}) exceeded")

        pk = self._build_pk(tenant_id, user_id)
        now = datetime.now(UTC)
        now_iso = now.isoformat()
        expires_at = int(now.timestamp()) + (ttl_days * 86400) if ttl_days > 0 else 0

        stored: list[dict[str, Any]] = []

        # Store each message
        seq = current_count
        for msg in new_messages:
            seq += 1
            sk = f"M#{conversation_id}#{seq:04d}"

            # Sanitize sources: strictly [{doc_id, filename, chunk_id, page}], NO snippets
            clean_sources = []
            for src in msg.get("sources", []):
                if isinstance(src, dict):
                    clean_sources.append(
                        {
                            "doc_id": src.get("doc_id", ""),
                            "filename": src.get("filename", ""),
                            "chunk_id": src.get("chunk_id", ""),
                            "page": src.get("page"),
                        }
                    )

            trust_val = msg.get("trust", {})
            trust_dict = trust_val if isinstance(trust_val, dict) else {}
            clean_trust = {
                "score": float(trust_dict.get("score", 0.0)),
                "abstained": bool(trust_dict.get("abstained", False)),
                "partial": bool(trust_dict.get("partial", False)),
            }

            msg_item: dict[str, Any] = {
                "pk": pk,
                "sk": sk,
                "conversation_id": conversation_id,
                "seq": seq,
                "role": msg.get("role", "user"),
                "text": msg.get("text", ""),
                "trust": clean_trust,
                "sources": clean_sources,
                "created_at": msg.get("created_at") or now_iso,
            }
            if expires_at > 0:
                msg_item["expires_at"] = expires_at

            db_item = _floats_to_decimals(msg_item)
            self.table.put_item(Item=db_item)
            stored.append(msg_item)

        # Update conversation metadata: updated_at, message_count, and optionally refresh expires_at
        update_expr = "SET #cnt = :cnt, #upd = :upd"
        expr_names = {"#cnt": "message_count", "#upd": "updated_at"}
        expr_vals: dict[str, Any] = {
            ":cnt": seq,
            ":upd": now_iso,
        }
        if expires_at > 0:
            update_expr += ", #exp = :exp"
            expr_names["#exp"] = "expires_at"
            expr_vals[":exp"] = expires_at

        try:
            self.table.update_item(
                Key={"pk": pk, "sk": f"C#{conversation_id}"},
                UpdateExpression=update_expr,
                ConditionExpression="attribute_exists(pk) AND attribute_exists(sk)",
                ExpressionAttributeNames=expr_names,
                ExpressionAttributeValues=_floats_to_decimals(expr_vals),
            )
        except ClientError as e:
            logger.warning("Failed to update conversation count: %s", e)

        return stored

    def delete_one(
        self,
        tenant_id: str,
        user_id: str,
        conversation_id: str,
    ) -> int:
        """Delete a single conversation and all its messages. Returns number of messages deleted."""
        # Check ownership first; raises NotFound 404 if missing or not owner
        self.get_conversation(tenant_id, user_id, conversation_id)

        pk = self._build_pk(tenant_id, user_id)
        sk_prefix = f"M#{conversation_id}#"

        # Query all messages
        resp = self.table.query(
            KeyConditionExpression=Key("pk").eq(pk) & Key("sk").begins_with(sk_prefix),
        )
        msg_items = resp.get("Items", [])
        msgs_deleted = 0

        # Delete each message item
        for item in msg_items:
            self.table.delete_item(Key={"pk": pk, "sk": item["sk"]})
            msgs_deleted += 1

        # Delete conversation item
        self.table.delete_item(Key={"pk": pk, "sk": f"C#{conversation_id}"})
        return msgs_deleted

    def delete_all(
        self,
        tenant_id: str,
        user_id: str,
    ) -> tuple[int, int]:
        """Delete all conversations and messages. Returns (convs_deleted, msgs_deleted)."""
        pk = self._build_pk(tenant_id, user_id)

        # Query all items for this user (both C# and M#)
        resp = self.table.query(
            KeyConditionExpression=Key("pk").eq(pk),
        )
        all_items = resp.get("Items", [])

        convs_deleted = 0
        msgs_deleted = 0

        for item in all_items:
            sk = str(item.get("sk", ""))
            if sk.startswith("C#"):
                convs_deleted += 1
            elif sk.startswith("M#"):
                msgs_deleted += 1
            self.table.delete_item(Key={"pk": pk, "sk": sk})

        return convs_deleted, msgs_deleted
