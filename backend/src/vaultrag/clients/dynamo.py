from __future__ import annotations

import base64
import json
from datetime import UTC, datetime
from decimal import Decimal
from enum import StrEnum
from typing import Any

import boto3
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError

from vaultrag.config import get_settings
from vaultrag.errors import Conflict, NotFound, ValidationFailed

DEFAULT_TENANT_SETTINGS: dict[str, Any] = {
    "pii_mode": "redact",
    "injection_policy": "quarantine_high",
    "min_retrieval_score": 0.35,
    "min_faithfulness": 0.6,
    "daily_query_quota": 200,
    "cache_enabled": True,
    "retain_original_files": True,
    "llm_judge_enabled": False,
    "settings_version": 1,
}


class DocStatus(StrEnum):
    PENDING_UPLOAD = "PENDING_UPLOAD"
    PROCESSING = "PROCESSING"
    READY = "READY"
    QUARANTINED = "QUARANTINED"
    FAILED = "FAILED"
    DELETING = "DELETING"
    DELETE_FAILED = "DELETE_FAILED"
    DELETED = "DELETED"


# Alias for readability and specification consistency
DocumentStatus = DocStatus


# Allowed status transitions
VALID_STATUS_TRANSITIONS: dict[DocStatus, set[DocStatus]] = {
    DocStatus.PENDING_UPLOAD: {
        DocStatus.PROCESSING,
        DocStatus.FAILED,
        DocStatus.DELETING,
        DocStatus.DELETED,
    },
    DocStatus.PROCESSING: {
        DocStatus.READY,
        DocStatus.QUARANTINED,
        DocStatus.FAILED,
        DocStatus.DELETING,
        DocStatus.DELETED,
    },
    DocStatus.READY: {
        DocStatus.PROCESSING,
        DocStatus.QUARANTINED,
        DocStatus.DELETING,
        DocStatus.DELETED,
    },
    DocStatus.QUARANTINED: {DocStatus.PROCESSING, DocStatus.DELETING, DocStatus.DELETED},
    DocStatus.FAILED: {DocStatus.PROCESSING, DocStatus.DELETING, DocStatus.DELETED},
    DocStatus.DELETING: {DocStatus.DELETING, DocStatus.DELETED, DocStatus.DELETE_FAILED},
    DocStatus.DELETE_FAILED: {DocStatus.DELETING, DocStatus.DELETED},
    DocStatus.DELETED: set(),  # Terminal state
}


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


class TenantRepo:
    """Repository for tenant configuration and default settings."""

    def __init__(self, table_name: str | None = None, dynamodb_resource: Any = None) -> None:
        settings = get_settings()
        self.table_name = table_name or settings.tenants_table
        if dynamodb_resource is not None:
            self.dynamodb = dynamodb_resource
        else:
            self.dynamodb = boto3.resource("dynamodb", region_name=settings.aws_region)
        self.table = self.dynamodb.Table(self.table_name)

    def get(self, tenant_id: str) -> dict[str, Any]:
        """Retrieve tenant with merged default settings. Raises NotFound if missing."""
        try:
            response = self.table.get_item(Key={"tenant_id": tenant_id})
        except ClientError as e:
            raise ValidationFailed(f"DynamoDB error: {e}") from e

        item = response.get("Item")
        if not item:
            raise NotFound(f"Tenant '{tenant_id}' not found")

        item = _decimals_to_floats(item)
        stored_settings = item.get("settings", {})
        merged_settings = {**DEFAULT_TENANT_SETTINGS, **stored_settings}
        item["settings"] = merged_settings
        return item

    def put(
        self,
        tenant_id: str,
        name: str,
        settings: dict[str, Any] | None = None,
        status: str = "ACTIVE",
    ) -> dict[str, Any]:
        """Create or replace tenant configuration with default settings merged."""
        merged_settings = {**DEFAULT_TENANT_SETTINGS, **(settings or {})}
        now = datetime.now(UTC).isoformat()
        item: dict[str, Any] = {
            "tenant_id": tenant_id,
            "name": name,
            "status": status,
            "settings": merged_settings,
            "created_at": now,
            "updated_at": now,
        }
        db_item = _floats_to_decimals(item)
        self.table.put_item(Item=db_item)
        return item

    def update_settings(self, tenant_id: str, patch: dict[str, Any]) -> dict[str, Any]:
        """Atomically update tenant settings with a conditional update and bump settings_version."""
        item = self.get(tenant_id)
        current_settings = item.get("settings", {})
        new_settings = {**DEFAULT_TENANT_SETTINGS, **current_settings, **patch}
        current_version = int(new_settings.get("settings_version", 1))
        new_settings["settings_version"] = current_version + 1

        now = datetime.now(UTC).isoformat()
        db_settings = _floats_to_decimals(new_settings)

        try:
            response = self.table.update_item(
                Key={"tenant_id": tenant_id},
                UpdateExpression="SET #settings = :new_settings, #updated_at = :now",
                ConditionExpression="attribute_exists(tenant_id)",
                ExpressionAttributeNames={
                    "#settings": "settings",
                    "#updated_at": "updated_at",
                },
                ExpressionAttributeValues={
                    ":new_settings": db_settings,
                    ":now": now,
                },
                ReturnValues="ALL_NEW",
            )
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
                raise NotFound(f"Tenant '{tenant_id}' not found") from e
            raise ValidationFailed(f"DynamoDB update error: {e}") from e

        updated_item = _decimals_to_floats(response["Attributes"])
        return updated_item.get("settings", new_settings)

    def bump_kb_version(self, tenant_id: str) -> int:
        """Atomically bump the tenant's kb_version counter using ADD.

        Returns the new kb_version integer.
        """
        now = datetime.now(UTC).isoformat()
        try:
            response = self.table.update_item(
                Key={"tenant_id": tenant_id},
                UpdateExpression="ADD #kb_ver :one SET #updated_at = :now",
                ConditionExpression="attribute_exists(tenant_id)",
                ExpressionAttributeNames={
                    "#kb_ver": "kb_version",
                    "#updated_at": "updated_at",
                },
                ExpressionAttributeValues={
                    ":one": Decimal("1"),
                    ":now": now,
                },
                ReturnValues="ALL_NEW",
            )
            item = _decimals_to_floats(response["Attributes"])
            return int(item.get("kb_version", 1))
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
                raise NotFound(f"Tenant '{tenant_id}' not found") from e
            raise ValidationFailed(f"DynamoDB update error: {e}") from e


class DocumentRepo:
    """Repository for documents. All operations strictly require tenant_id as first argument.

    Never implements scan(). Enforces atomic create constraints and valid status transitions.
    """

    def __init__(self, table_name: str | None = None, dynamodb_resource: Any = None) -> None:
        settings = get_settings()
        self.table_name = table_name or settings.documents_table
        if dynamodb_resource is not None:
            self.dynamodb = dynamodb_resource
        else:
            self.dynamodb = boto3.resource("dynamodb", region_name=settings.aws_region)
        self.table = self.dynamodb.Table(self.table_name)

    def create(
        self,
        tenant_id: str,
        doc_id: str,
        filename: str,
        content_type: str,
        size_bytes: int = 0,
        **extra: Any,
    ) -> dict[str, Any]:
        """Create a new document item. Fails if the document already exists."""
        now = datetime.now(UTC).isoformat()
        item: dict[str, Any] = {
            "tenant_id": tenant_id,
            "doc_id": doc_id,
            "filename": filename,
            "content_type": content_type,
            "size_bytes": size_bytes,
            "status": DocStatus.PENDING_UPLOAD.value,
            "created_at": now,
            "updated_at": now,
            **extra,
        }
        db_item = _floats_to_decimals(item)
        try:
            self.table.put_item(
                Item=db_item,
                ConditionExpression=(
                    "attribute_not_exists(tenant_id) AND attribute_not_exists(doc_id)"
                ),
            )
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
                raise Conflict(
                    f"Document '{doc_id}' already exists for tenant '{tenant_id}'"
                ) from e
            raise

        return item

    def get(self, tenant_id: str, doc_id: str) -> dict[str, Any]:
        """Retrieve document item by PK (tenant_id) and SK (doc_id). Raises NotFound if missing."""
        response = self.table.get_item(Key={"tenant_id": tenant_id, "doc_id": doc_id})
        item = response.get("Item")
        if not item:
            raise NotFound(f"Document '{doc_id}' not found for tenant '{tenant_id}'")
        return _decimals_to_floats(item)

    def list_for_tenant(
        self,
        tenant_id: str,
        limit: int = 50,
        next_token: str | None = None,
    ) -> tuple[list[dict[str, Any]], str | None]:
        """Query documents strictly for a single tenant with pagination. Never uses scan()."""
        kwargs: dict[str, Any] = {
            "KeyConditionExpression": Key("tenant_id").eq(tenant_id),
            "Limit": limit,
        }

        if next_token:
            try:
                decoded = json.loads(base64.urlsafe_b64decode(next_token.encode()).decode())
                kwargs["ExclusiveStartKey"] = decoded
            except Exception as e:
                raise ValidationFailed(f"Invalid pagination token: {e}") from e

        response = self.table.query(**kwargs)
        items = [_decimals_to_floats(i) for i in response.get("Items", [])]

        last_key = response.get("LastEvaluatedKey")
        token_out = None
        if last_key:
            token_bytes = json.dumps(last_key, default=str).encode()
            token_out = base64.urlsafe_b64encode(token_bytes).decode()

        return items, token_out

    def update_status(
        self,
        tenant_id: str,
        doc_id: str,
        new_status: DocStatus | str,
        error: str | None = None,
        extra_fields: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Enforce atomic valid status transition via ConditionExpression.

        Raises NotFound if document does not exist, or ValidationFailed if transition is invalid.
        """
        if isinstance(new_status, str):
            try:
                target_status = DocStatus(new_status)
            except ValueError:
                raise ValidationFailed(f"Invalid document status '{new_status}'") from None
        else:
            target_status = new_status

        # Find allowed previous statuses for this target
        allowed_prev = [
            src.value for src, dests in VALID_STATUS_TRANSITIONS.items() if target_status in dests
        ]

        if not allowed_prev:
            raise ValidationFailed(f"No valid transitions allowed into '{target_status.value}'")

        now = datetime.now(UTC).isoformat()

        # Build condition: attribute_exists AND status IN (:p0, :p1, ...)
        cond_clauses = ["attribute_exists(tenant_id)", "attribute_exists(doc_id)"]
        expr_names = {"#st": "status"}
        expr_vals: dict[str, Any] = {
            ":new_st": target_status.value,
            ":now": now,
        }

        in_placeholders = []
        for idx, prev in enumerate(allowed_prev):
            p = f":p{idx}"
            in_placeholders.append(p)
            expr_vals[p] = prev

        cond_clauses.append(f"#st IN ({', '.join(in_placeholders)})")
        condition_expr = " AND ".join(cond_clauses)

        update_expr = "SET #st = :new_st, updated_at = :now"
        if error is not None:
            update_expr += ", #err = :err"
            expr_names["#err"] = "error"
            expr_vals[":err"] = error
        if extra_fields:
            for idx, (k, v) in enumerate(extra_fields.items()):
                if k in ("tenant_id", "doc_id", "status", "error", "updated_at"):
                    continue
                attr_name = f"#ef{idx}"
                attr_val = f":ef{idx}"
                update_expr += f", {attr_name} = {attr_val}"
                expr_names[attr_name] = k
                expr_vals[attr_val] = v

        try:
            response = self.table.update_item(
                Key={"tenant_id": tenant_id, "doc_id": doc_id},
                UpdateExpression=update_expr,
                ConditionExpression=condition_expr,
                ExpressionAttributeNames=expr_names,
                ExpressionAttributeValues=_floats_to_decimals(expr_vals),
                ReturnValues="ALL_NEW",
            )
            return _decimals_to_floats(response["Attributes"])
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
                # Check whether document exists or the status transition failed
                existing = self.table.get_item(Key={"tenant_id": tenant_id, "doc_id": doc_id}).get(
                    "Item"
                )
                if not existing:
                    raise NotFound(f"Document '{doc_id}' not found for tenant '{tenant_id}'") from e
                curr = existing.get("status")
                raise ValidationFailed(
                    f"Invalid status transition from '{curr}' to '{target_status.value}'"
                ) from e
            raise

    def update_fields(
        self,
        tenant_id: str,
        doc_id: str,
        fields: dict[str, Any],
    ) -> dict[str, Any]:
        """Update arbitrary document fields with existence check. Rejects PK/SK mutation."""
        safe_fields = {k: v for k, v in fields.items() if k not in ("tenant_id", "doc_id")}
        if not safe_fields:
            return self.get(tenant_id, doc_id)

        now = datetime.now(UTC).isoformat()
        safe_fields["updated_at"] = now

        set_clauses = []
        expr_names = {}
        expr_vals = {}

        for idx, (k, v) in enumerate(safe_fields.items()):
            attr_name = f"#k{idx}"
            attr_val = f":v{idx}"
            set_clauses.append(f"{attr_name} = {attr_val}")
            expr_names[attr_name] = k
            expr_vals[attr_val] = _floats_to_decimals(v)

        update_expr = f"SET {', '.join(set_clauses)}"

        try:
            response = self.table.update_item(
                Key={"tenant_id": tenant_id, "doc_id": doc_id},
                UpdateExpression=update_expr,
                ConditionExpression="attribute_exists(tenant_id) AND attribute_exists(doc_id)",
                ExpressionAttributeNames=expr_names,
                ExpressionAttributeValues=expr_vals,
                ReturnValues="ALL_NEW",
            )
            return _decimals_to_floats(response["Attributes"])
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
                raise NotFound(f"Document '{doc_id}' not found for tenant '{tenant_id}'") from e
            raise

    def update_acl(
        self,
        tenant_id: str,
        doc_id: str,
        visibility: str,
        allowed_roles: list[str],
        allowed_users: list[str],
    ) -> dict[str, Any]:
        """Atomically update document ACL fields conditional on tenant_id and doc_id existing."""
        return self.update_fields(
            tenant_id=tenant_id,
            doc_id=doc_id,
            fields={
                "visibility": visibility,
                "allowed_roles": allowed_roles,
                "allowed_users": allowed_users,
            },
        )

    def create_tombstone(
        self,
        tenant_id: str,
        doc_id: str,
        deleted_by: str,
        certificate_sha256: str,
    ) -> dict[str, Any]:
        """Replace the document record with a minimal tombstone, removing all metadata.

        Retains strictly: tenant_id, doc_id, status: DELETED, deleted_at, deleted_by,
        and certificate_sha256.
        """
        now = datetime.now(UTC).isoformat()
        tombstone = {
            "tenant_id": tenant_id,
            "doc_id": doc_id,
            "status": DocStatus.DELETED.value,
            "deleted_at": now,
            "deleted_by": deleted_by,
            "certificate_sha256": certificate_sha256,
        }
        self.table.put_item(Item=_floats_to_decimals(tombstone))
        return tombstone

    def delete(self, tenant_id: str, doc_id: str) -> None:
        """Delete document by PK and SK. Raises NotFound if item does not exist."""
        try:
            self.table.delete_item(
                Key={"tenant_id": tenant_id, "doc_id": doc_id},
                ConditionExpression="attribute_exists(tenant_id) AND attribute_exists(doc_id)",
            )
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
                raise NotFound(f"Document '{doc_id}' not found for tenant '{tenant_id}'") from e
            raise
