"""Audit hash chain: append-only cryptographically linked audit log for compliance."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import random
import time
from datetime import UTC, datetime
from typing import Any

import boto3
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError

from vaultrag.clients.dynamo import _decimals_to_floats, _floats_to_decimals
from vaultrag.config import get_secret, get_settings
from vaultrag.context import RequestContext
from vaultrag.errors import AppError, Conflict, NotFound

logger = logging.getLogger(__name__)

GENESIS_PREV_HASH = "0" * 64

# Strict whitelist of allowed detail keys per audit action
ALLOWED_DETAIL_KEYS: dict[str, frozenset[str]] = {
    "document_create": frozenset({"filename", "content_type", "size_bytes", "visibility"}),
    "document_ready": frozenset({"chunk_count"}),
    "document_quarantined": frozenset({"risk", "reasons"}),
    "document_delete": frozenset({"deleted"}),
    "acl_change": frozenset({"visibility", "allowed_roles", "allowed_users"}),
    "policy_change": frozenset({"changed_keys"}),
    "query": frozenset(
        {
            "question_sha256",
            "trust_score",
            "abstained",
            "cached",
            "n_sources",
            "doc_ids",
            "pii_types_in_question",
            "pii_in_answer",
            "latency_ms",
            "scoped",
            "n_scope_docs",
        }
    ),
    "query_abstain": frozenset(
        {
            "question_sha256",
            "trust_score",
            "abstained",
            "cached",
            "n_sources",
            "doc_ids",
            "pii_types_in_question",
            "pii_in_answer",
            "latency_ms",
            "reason",
            "scoped",
            "n_scope_docs",
        }
    ),
    "injection_attempt": frozenset({"risk", "reasons"}),
    "quota_exceeded": frozenset({"quota", "queries"}),
    "erasure": frozenset(
        {
            "doc_id",
            "user_id",
            "status",
            "certificate_sha256",
            "deleted_vectors",
            "deleted_files",
            "error",
        }
    ),
    "audit_verify": frozenset({"valid", "checked", "broken_at_seq"}),
}


def canonical_json(obj: Any) -> str:
    """Serialize object to canonical JSON string (sorted keys, compact separators, UTF-8)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _get_audit_table(table_name: str | None = None, dynamodb_resource: Any = None) -> Any:
    settings = get_settings()
    t_name = table_name or settings.audit_table
    if dynamodb_resource is not None:
        return dynamodb_resource.Table(t_name)
    resource = boto3.resource("dynamodb", region_name=settings.aws_region)
    return resource.Table(t_name)


def append_event(
    ctx_or_system_actor: RequestContext | tuple[str, str] | str,
    action: str,
    resource_id: str | None = None,
    outcome: str = "ok",
    details: dict[str, Any] | None = None,
    *,
    tenant_id: str | None = None,
    table_name: str | None = None,
    dynamodb_resource: Any = None,
) -> dict[str, Any]:
    """Append a cryptographically linked event to the tenant's audit hash chain.

    Retries with exponential jitter on sequence conflict up to 5 times.
    """
    if isinstance(ctx_or_system_actor, RequestContext):
        t_id = ctx_or_system_actor.tenant_id
        actor = ctx_or_system_actor.user_id
    elif isinstance(ctx_or_system_actor, tuple) and len(ctx_or_system_actor) == 2:
        t_id, actor = ctx_or_system_actor
    elif isinstance(ctx_or_system_actor, str):
        actor = ctx_or_system_actor
        t_id = tenant_id or (details.get("tenant_id") if isinstance(details, dict) else None)
        if not t_id:
            raise ValueError("tenant_id must be provided when actor is a string")
    else:
        raise ValueError(f"Unsupported actor/context type: {type(ctx_or_system_actor)}")

    table = _get_audit_table(table_name=table_name, dynamodb_resource=dynamodb_resource)

    # Filter details strictly according to the whitelist for this action
    allowed_keys = ALLOWED_DETAIL_KEYS.get(action, frozenset())
    filtered_details = {k: v for k, v in (details or {}).items() if k in allowed_keys}

    # Retry loop for optimistic concurrency conflict resolution
    max_retries = 30
    for attempt in range(max_retries):
        # 1. Read latest record for tenant (ConsistentRead=True to guarantee monotonic seq)
        resp = table.query(
            KeyConditionExpression=Key("tenant_id").eq(t_id),
            ScanIndexForward=False,
            Limit=1,
            ConsistentRead=True,
        )
        items = resp.get("Items", [])
        if items:
            latest = _decimals_to_floats(items[0])
            seq = int(latest["seq"]) + 1
            prev_hash = str(latest["hash"])
        else:
            seq = 0
            prev_hash = GENESIS_PREV_HASH

        # 2. Build record dictionary without the hash
        now_ts = datetime.now(UTC).isoformat()
        record_core = {
            "action": action,
            "actor": actor,
            "details": filtered_details,
            "outcome": outcome,
            "prev_hash": prev_hash,
            "resource_id": resource_id,
            "seq": seq,
            "tenant_id": t_id,
            "ts": now_ts,
        }
        # Normalize numbers to match exact DynamoDB roundtrip representation
        record_core = _decimals_to_floats(_floats_to_decimals(record_core))

        # 3. Compute entry hash = sha256(prev_hash + canonical_json(record_core))
        hash_input = prev_hash + canonical_json(record_core)
        entry_hash = hashlib.sha256(hash_input.encode("utf-8")).hexdigest()

        # 4. Construct final item with hash
        item = dict(record_core)
        item["hash"] = entry_hash

        # 5. Atomic conditional PutItem
        try:
            table.put_item(
                Item=_floats_to_decimals(item),
                ConditionExpression="attribute_not_exists(seq)",
            )
            return item
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
                if attempt == max_retries - 1:
                    logger.error(
                        "Audit append conflict retry exhausted: tenant=%s, seq=%d", t_id, seq
                    )
                    raise Conflict(
                        f"Audit append conflict after {max_retries} retries for tenant {t_id}"
                    ) from e
                # Jittered backoff before re-reading latest
                sleep_time = min(0.25, random.uniform(0.01, 0.04) * (1.12**attempt))  # noqa: S311
                time.sleep(sleep_time)
                continue
            raise

    raise Conflict(f"Failed to append audit record for tenant {t_id}")


def verify_chain(
    tenant_id: str,
    *,
    table_name: str | None = None,
    dynamodb_resource: Any = None,
) -> dict[str, Any]:
    """Verify hash chain integrity for tenant.

    Pages through all records, recomputes hashes, verifies sequential continuity
    and prev_hash linkage.
    """
    table = _get_audit_table(table_name=table_name, dynamodb_resource=dynamodb_resource)

    items: list[dict[str, Any]] = []
    exclusive_start_key = None

    while True:
        kwargs: dict[str, Any] = {
            "KeyConditionExpression": Key("tenant_id").eq(tenant_id),
            "ScanIndexForward": True,
            "ConsistentRead": True,
        }
        if exclusive_start_key is not None:
            kwargs["ExclusiveStartKey"] = exclusive_start_key

        resp = table.query(**kwargs)
        for it in resp.get("Items", []):
            items.append(_decimals_to_floats(it))

        exclusive_start_key = resp.get("LastEvaluatedKey")
        if not exclusive_start_key:
            break

    if not items:
        return {"valid": True, "checked": 0, "broken_at_seq": None, "reason": None}

    expected_prev_hash = GENESIS_PREV_HASH
    checked_count = 0

    for expected_seq, record in enumerate(items):
        actual_seq = int(record.get("seq", -1))
        # 1. Continuity check
        if actual_seq != expected_seq:
            return {
                "valid": False,
                "checked": checked_count,
                "broken_at_seq": actual_seq if actual_seq >= 0 else expected_seq,
                "reason": f"Sequence gap: expected {expected_seq}, found {actual_seq}",
            }

        # 2. Previous hash linkage check
        actual_prev_hash = record.get("prev_hash")
        if actual_prev_hash != expected_prev_hash:
            reason = (
                f"Previous hash mismatch at seq {actual_seq}: "
                f"expected {expected_prev_hash}, got {actual_prev_hash}"
            )
            return {
                "valid": False,
                "checked": checked_count,
                "broken_at_seq": actual_seq,
                "reason": reason,
            }

        # 3. Hash integrity check
        record_core = {k: v for k, v in record.items() if k != "hash"}
        hash_input = expected_prev_hash + canonical_json(record_core)
        expected_hash = hashlib.sha256(hash_input.encode("utf-8")).hexdigest()

        if record.get("hash") != expected_hash:
            reason = (
                f"Hash mismatch at seq {actual_seq}: "
                f"computed {expected_hash}, recorded {record.get('hash')}"
            )
            return {
                "valid": False,
                "checked": checked_count,
                "broken_at_seq": actual_seq,
                "reason": reason,
            }

        expected_prev_hash = record["hash"]
        checked_count += 1

    return {"valid": True, "checked": checked_count, "broken_at_seq": None, "reason": None}


def export_anchor(
    tenant_id: str,
    *,
    table_name: str | None = None,
    dynamodb_resource: Any = None,
    hmac_secret: str | None = None,
) -> dict[str, Any]:
    """Export a signed cryptographic anchor of the latest record in the tenant's chain.

    The signature is HMAC-SHA256 over canonical_json of (tenant_id, seq, hash, ts)
    using SSM secret 'cert_hmac_secret'.
    """
    table = _get_audit_table(table_name=table_name, dynamodb_resource=dynamodb_resource)

    resp = table.query(
        KeyConditionExpression=Key("tenant_id").eq(tenant_id),
        ScanIndexForward=False,
        Limit=1,
        ConsistentRead=True,
    )
    items = resp.get("Items", [])
    if not items:
        raise NotFound(f"No audit records found for tenant '{tenant_id}'")

    latest = _decimals_to_floats(items[0])

    anchor_data = {
        "hash": latest["hash"],
        "seq": int(latest["seq"]),
        "tenant_id": tenant_id,
        "ts": datetime.now(UTC).isoformat(),
    }

    # Fetch secret
    if hmac_secret is not None:
        secret = hmac_secret
    else:
        try:
            secret = get_secret("cert_hmac_secret")
        except AppError:
            secret = "vaultrag-local-dev-anchor-hmac-secret-key"  # noqa: S105

    anchor_payload = canonical_json(anchor_data)
    signature = hmac.new(
        secret.encode("utf-8"),
        anchor_payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    return {**anchor_data, "signature": signature}


def verify_anchor(anchor: dict[str, Any], *, hmac_secret: str | None = None) -> bool:
    """Verify an exported anchor signature."""
    if "signature" not in anchor:
        return False

    sig = anchor["signature"]
    anchor_core = {k: v for k, v in anchor.items() if k != "signature"}

    if hmac_secret is not None:
        secret = hmac_secret
    else:
        try:
            secret = get_secret("cert_hmac_secret")
        except AppError:
            secret = "vaultrag-local-dev-anchor-hmac-secret-key"  # noqa: S105

    anchor_payload = canonical_json(anchor_core)
    expected_sig = hmac.new(
        secret.encode("utf-8"),
        anchor_payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    return hmac.compare_digest(sig, expected_sig)
