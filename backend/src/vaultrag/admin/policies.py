"""Tenant policies administration router: GET /admin/policies and PATCH /admin/policies.

Restricted strictly to callers with the 'admin' role.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, Request

from vaultrag.audit.hashchain import append_event
from vaultrag.auth.dependencies import require_role
from vaultrag.clients.dynamo import TenantRepo
from vaultrag.context import RequestContext, Role
from vaultrag.errors import ValidationFailed

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/admin/policies", tags=["admin-policies"])

ALLOWED_SETTINGS_KEYS = frozenset(
    {
        "pii_mode",
        "injection_policy",
        "min_retrieval_score",
        "min_faithfulness",
        "daily_query_quota",
        "cache_enabled",
        "retain_original_files",
        "llm_judge_enabled",
        "chat_history_days",
    }
)

VALID_PII_MODES = frozenset({"off", "flag", "redact", "block"})
VALID_INJECTION_POLICIES = frozenset({"off", "flag_only", "quarantine_high"})


def _validate_patch_payload(body: dict[str, Any]) -> dict[str, Any]:
    """Validate partial policies patch payload strictly.

    Rejects unknown keys and out-of-range values.
    """
    if not isinstance(body, dict):
        raise ValidationFailed("Request body must be a JSON object")

    if not body:
        raise ValidationFailed("Patch payload cannot be empty")

    # Reject any unknown keys
    unknown_keys = sorted(set(body.keys()) - ALLOWED_SETTINGS_KEYS)
    if unknown_keys:
        raise ValidationFailed(f"Unknown settings key(s): {', '.join(unknown_keys)}")

    cleaned: dict[str, Any] = {}

    # 1. pii_mode
    if "pii_mode" in body:
        val = body["pii_mode"]
        if not isinstance(val, str) or val.strip().lower() not in VALID_PII_MODES:
            raise ValidationFailed(
                f"Invalid pii_mode '{val}'. Must be one of: {sorted(VALID_PII_MODES)}"
            )
        cleaned["pii_mode"] = val.strip().lower()

    # 2. injection_policy
    if "injection_policy" in body:
        val = body["injection_policy"]
        if not isinstance(val, str) or val.strip().lower() not in VALID_INJECTION_POLICIES:
            valid_policies = sorted(VALID_INJECTION_POLICIES)
            raise ValidationFailed(
                f"Invalid injection_policy '{val}'. Must be one of: {valid_policies}"
            )
        cleaned["injection_policy"] = val.strip().lower()

    # 3. min_retrieval_score
    if "min_retrieval_score" in body:
        val = body["min_retrieval_score"]
        if isinstance(val, bool) or not isinstance(val, (int, float)):
            raise ValidationFailed("min_retrieval_score must be a float between 0.0 and 1.0")
        score = float(val)
        if not (0.0 <= score <= 1.0):
            raise ValidationFailed("min_retrieval_score must be between 0.0 and 1.0")
        cleaned["min_retrieval_score"] = score

    # 4. min_faithfulness
    if "min_faithfulness" in body:
        val = body["min_faithfulness"]
        if isinstance(val, bool) or not isinstance(val, (int, float)):
            raise ValidationFailed("min_faithfulness must be a float between 0.0 and 1.0")
        score = float(val)
        if not (0.0 <= score <= 1.0):
            raise ValidationFailed("min_faithfulness must be between 0.0 and 1.0")
        cleaned["min_faithfulness"] = score

    # 5. daily_query_quota
    if "daily_query_quota" in body:
        val = body["daily_query_quota"]
        if isinstance(val, bool) or not isinstance(val, int):
            raise ValidationFailed("daily_query_quota must be an integer between 1 and 10000")
        if not (1 <= val <= 10000):
            raise ValidationFailed("daily_query_quota must be an integer between 1 and 10000")
        cleaned["daily_query_quota"] = val

    # 6. cache_enabled
    if "cache_enabled" in body:
        val = body["cache_enabled"]
        if not isinstance(val, bool):
            raise ValidationFailed("cache_enabled must be a boolean")
        cleaned["cache_enabled"] = val

    # 7. retain_original_files
    if "retain_original_files" in body:
        val = body["retain_original_files"]
        if not isinstance(val, bool):
            raise ValidationFailed("retain_original_files must be a boolean")
        cleaned["retain_original_files"] = val

    # 8. llm_judge_enabled
    if "llm_judge_enabled" in body:
        val = body["llm_judge_enabled"]
        if not isinstance(val, bool):
            raise ValidationFailed("llm_judge_enabled must be a boolean")
        cleaned["llm_judge_enabled"] = val

    # 9. chat_history_days (int 0..30)
    if "chat_history_days" in body:
        val = body["chat_history_days"]
        if isinstance(val, bool) or not isinstance(val, int):
            raise ValidationFailed("chat_history_days must be an integer between 0 and 30")
        if not (0 <= val <= 30):
            raise ValidationFailed("chat_history_days must be an integer between 0 and 30")
        cleaned["chat_history_days"] = val

    return cleaned


@router.get("")
async def get_policies(
    ctx: RequestContext = Depends(require_role(Role.admin)),  # noqa: B008
) -> dict[str, Any]:
    """Retrieve the caller's tenant security and operational policies (admin only)."""
    repo = TenantRepo()
    tenant = repo.get(ctx.tenant_id)
    return tenant.get("settings", {})


@router.patch("")
async def update_policies(
    request: Request,
    ctx: RequestContext = Depends(require_role(Role.admin)),  # noqa: B008
) -> dict[str, Any]:
    """Update caller's tenant policies with strict validation and version bump (admin only)."""
    try:
        raw_body = await request.json()
    except Exception:
        raise ValidationFailed("Request body must be valid JSON") from None

    cleaned_patch = _validate_patch_payload(raw_body)
    repo = TenantRepo()
    updated_settings = repo.update_settings(ctx.tenant_id, cleaned_patch)

    logger.info(
        "Tenant policies updated: tenant_id=%s, settings_version=%s, updated_keys=%s",
        ctx.tenant_id,
        updated_settings.get("settings_version"),
        sorted(cleaned_patch.keys()),
    )
    # Append cryptographic audit event (security mutation must fail if audit fails)
    append_event(
        ctx,
        action="policy_change",
        details={"changed_keys": sorted(cleaned_patch.keys())},
    )

    return updated_settings
