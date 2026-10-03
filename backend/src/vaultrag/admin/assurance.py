"""Admin Assurance Center Router.

Provides endpoints for running security assurance self-tests, retrieving the latest
attestation report, and verifying signed assurance reports.
Restricted strictly to callers with the 'admin' role.
"""

from __future__ import annotations

import logging
import time
from decimal import Decimal
from typing import Any

import boto3
from botocore.exceptions import ClientError
from fastapi import APIRouter, Body, Depends, HTTPException
from pydantic import BaseModel, field_validator

from vaultrag.admin.erasure import verify_signed_payload
from vaultrag.assurance.models import AssuranceReport
from vaultrag.assurance.runner import run_assurance
from vaultrag.audit.hashchain import append_event
from vaultrag.auth.dependencies import require_role
from vaultrag.clients.dynamo import _decimals_to_floats, _floats_to_decimals
from vaultrag.config import get_secret, get_settings
from vaultrag.context import RequestContext, Role
from vaultrag.errors import ValidationFailed

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/admin/assurance", tags=["admin-assurance"])

ALLOWED_SIMULATED_BUGS = frozenset({"drop_role_condition", "ignore_private"})


class RunAssuranceRequest(BaseModel):
    simulate_bug: str | None = None

    @field_validator("simulate_bug")
    @classmethod
    def validate_simulate_bug(cls, v: str | None) -> str | None:
        if v is not None and v not in ALLOWED_SIMULATED_BUGS:
            raise ValueError(
                f"Invalid simulate_bug '{v}'. Must be one of: "
                f"{sorted(ALLOWED_SIMULATED_BUGS)} or null"
            )
        return v


def _get_tenants_table(dynamodb_resource: Any = None) -> Any:
    settings = get_settings()
    if dynamodb_resource is not None:
        return dynamodb_resource.Table(settings.tenants_table)
    resource = boto3.resource("dynamodb", region_name=settings.aws_region)
    return resource.Table(settings.tenants_table)


def _enforce_rate_limit(tenant_id: str, table: Any, now_ts: int) -> None:
    """Enforce 1 run per 30 seconds rate limit per tenant via DynamoDB conditional update."""
    min_allowed = now_ts - 30
    try:
        table.update_item(
            Key={"tenant_id": tenant_id},
            UpdateExpression="SET assurance_last_run_ts = :now",
            ConditionExpression=(
                "attribute_not_exists(assurance_last_run_ts) OR "
                "assurance_last_run_ts <= :min_allowed"
            ),
            ExpressionAttributeValues={
                ":now": Decimal(now_ts),
                ":min_allowed": Decimal(min_allowed),
            },
        )
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code")
        if code == "ConditionalCheckFailedException":
            raise HTTPException(
                status_code=429,
                detail=(
                    "Rate limit exceeded: only one assurance run is permitted "
                    "every 30 seconds per tenant"
                ),
            ) from e
        raise


@router.post("/run")
async def run_assurance_endpoint(
    body: RunAssuranceRequest = Body(...),  # noqa: B008
    ctx: RequestContext = Depends(require_role(Role.admin)),  # noqa: B008
) -> dict[str, Any]:
    """Execute the full Assurance Center security self-test suite.

    Rate limited to one run per 30 seconds per tenant.
    Real runs persist the attestation to 'last_assurance' and record an
    'assurance_run' audit event.
    Simulated runs never overwrite 'last_assurance' and record an
    'assurance_run_simulated' audit event.
    """
    tenants_table = _get_tenants_table()
    now_ts = int(time.time())

    # 1. Enforce 30s rate limit
    _enforce_rate_limit(ctx.tenant_id, tenants_table, now_ts)

    # 2. Execute self-test suite
    try:
        report: AssuranceReport = run_assurance(ctx, simulate_bug=body.simulate_bug)
    except Exception as e:
        logger.error("Assurance self-test runner failed for tenant %s: %s", ctx.tenant_id, e)
        raise HTTPException(
            status_code=500, detail=f"Assurance self-test failed to execute: {e}"
        ) from e

    report_dict = report.to_dict()

    # 3. Security-relevant audit logging (must fail closed if auditing fails)
    try:
        if body.simulate_bug is None:
            append_event(
                ctx,
                action="assurance_run",
                details={
                    "run_id": report.run_id,
                    "passed": report.summary["passed"],
                    "total": report.summary["total"],
                    "leaks": report.summary["leaks"],
                    "report_sha256": report.report_sha256,
                },
            )
        else:
            append_event(
                ctx,
                action="assurance_run_simulated",
                details={
                    "run_id": report.run_id,
                    "simulated_bug": report.simulated_bug,
                    "leaks": report.summary["leaks"],
                },
            )
    except Exception as e:
        logger.error(
            "Audit logging failed during assurance run for tenant %s: %s", ctx.tenant_id, e
        )
        raise HTTPException(
            status_code=500, detail="Security audit event creation failed during assurance run"
        ) from e

    # 4. Save to tenant item if real run
    if body.simulate_bug is None:
        try:
            tenants_table.update_item(
                Key={"tenant_id": ctx.tenant_id},
                UpdateExpression="SET last_assurance = :rep",
                ExpressionAttributeValues={":rep": _floats_to_decimals(report_dict)},
            )
        except Exception as e:
            logger.error("Failed to store last_assurance for tenant %s: %s", ctx.tenant_id, e)

    return report_dict


@router.get("/latest")
async def get_latest_assurance_endpoint(
    ctx: RequestContext = Depends(require_role(Role.admin)),  # noqa: B008
) -> dict[str, Any]:
    """Retrieve the latest real signed Assurance Report for the tenant."""
    tenants_table = _get_tenants_table()
    try:
        resp = tenants_table.get_item(Key={"tenant_id": ctx.tenant_id})
    except ClientError as e:
        raise HTTPException(status_code=500, detail=f"DynamoDB error: {e}") from e

    item = resp.get("Item")
    if not item or "last_assurance" not in item:
        raise HTTPException(
            status_code=404, detail=f"No assurance report found for tenant '{ctx.tenant_id}'"
        )

    return _decimals_to_floats(item["last_assurance"])


@router.post("/verify")
async def verify_assurance_endpoint(
    report: dict[str, Any] = Body(...),  # noqa: B008
    ctx: RequestContext = Depends(require_role(Role.admin)),  # noqa: B008
) -> dict[str, Any]:
    """Verify an Assurance Report's signature and tenant scoping."""
    if not isinstance(report, dict):
        raise ValidationFailed("Report must be a JSON object")

    report_tenant = report.get("tenant_id")
    if not report_tenant or report_tenant != ctx.tenant_id:
        return {
            "valid": False,
            "reason": (
                f"Tenant mismatch: report is for tenant '{report_tenant}', "
                f"but authenticated tenant is '{ctx.tenant_id}'"
            ),
        }

    try:
        secret = get_secret("cert_hmac_secret")
    except Exception:
        secret = "vaultrag-local-dev-anchor-hmac-secret-key"  # noqa: S105

    if not verify_signed_payload(report, secret):
        return {
            "valid": False,
            "reason": (
                "Cryptographic signature mismatch: report has been modified "
                "or signed with an unknown secret"
            ),
        }

    return {"valid": True, "reason": None}
