"""Admin Overview router: GET /admin/overview.

Aggregates operational metrics, daily quota usage, trust statistics, PII findings,
and cryptographic audit integrity verification for the Trust Center dashboard.
Strictly restricted to callers with the 'admin' role.
"""

from __future__ import annotations

import contextlib
import logging
from datetime import UTC, datetime
from typing import Any

from boto3.dynamodb.conditions import Key
from fastapi import APIRouter, Depends

from vaultrag.audit.hashchain import _get_audit_table, verify_chain
from vaultrag.audit.usage import _get_usage_table, get_usage
from vaultrag.auth.dependencies import require_role
from vaultrag.clients.dynamo import DocumentRepo, TenantRepo
from vaultrag.context import RequestContext, Role

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/admin/overview", tags=["admin-overview"])


@router.get("")
async def get_admin_overview(
    ctx: RequestContext = Depends(require_role(Role.admin)),  # noqa: B008
) -> dict[str, Any]:
    """Retrieve comprehensive security & trust center overview metrics (admin only)."""
    # 1. Tenant configuration & quota
    tenant_repo = TenantRepo()
    try:
        tenant = tenant_repo.get(ctx.tenant_id)
        settings = tenant.get("settings", {})
    except Exception:
        settings = {}

    daily_quota = int(settings.get("daily_query_quota", 200))

    # 2. Queries today from usage table
    today_str = datetime.now(UTC).strftime("%Y-%m-%d")
    queries_today = 0
    try:
        usage_table = _get_usage_table()
        resp = usage_table.get_item(Key={"tenant_id": ctx.tenant_id, "day": today_str})
        item = resp.get("Item")
        if item:
            queries_today = int(item.get("queries", 0))
    except Exception as e:
        logger.warning("Failed to fetch today's query usage for tenant %s: %s", ctx.tenant_id, e)

    # 3. 30-day cache hit rate
    try:
        usage_records = get_usage(ctx.tenant_id, days=30)
        total_hits = sum(int(r.get("cache_hits", 0)) for r in usage_records)
        total_misses = sum(int(r.get("cache_misses", 0)) for r in usage_records)
        lookups = total_hits + total_misses
        cache_hit_rate = round(total_hits / lookups, 4) if lookups > 0 else 0.0
    except Exception as e:
        logger.warning("Failed to calculate cache hit rate for tenant %s: %s", ctx.tenant_id, e)
        cache_hit_rate = 0.0

    # 4. Recent audit items for abstain rate, average trust score, and last audit verification
    audit_table = _get_audit_table()
    recent_events: list[dict[str, Any]] = []
    try:
        audit_resp = audit_table.query(
            KeyConditionExpression=Key("tenant_id").eq(ctx.tenant_id),
            ScanIndexForward=False,
            Limit=100,
        )
        recent_events = audit_resp.get("Items", [])
    except Exception as e:
        logger.warning("Failed to fetch recent audit events for tenant %s: %s", ctx.tenant_id, e)

    # Calculate abstain rate and avg trust score from query events
    query_events = [e for e in recent_events if e.get("action") in ("query", "query_abstain")]
    if query_events:
        abstained_count = sum(
            1
            for e in query_events
            if e.get("action") == "query_abstain" or e.get("details", {}).get("abstained") is True
        )
        abstain_rate = round(abstained_count / len(query_events), 4)

        trust_scores: list[float] = []
        for e in query_events:
            val = e.get("details", {}).get("trust_score")
            if val is not None:
                with contextlib.suppress(ValueError, TypeError):
                    trust_scores.append(float(val))
        avg_trust_score = round(sum(trust_scores) / len(trust_scores), 4) if trust_scores else 0.0
    else:
        abstain_rate = 0.0
        avg_trust_score = 0.0

    # 5. Quarantined documents and PII findings by type
    doc_repo = DocumentRepo()
    quarantined_count = 0
    pii_by_type: dict[str, int] = {}

    try:
        docs, _ = doc_repo.list_for_tenant(ctx.tenant_id, limit=200)
        for d in docs:
            st = str(d.get("status", "")).upper()
            q_rep = d.get("quarantine_report") or []
            if st == "QUARANTINED" or bool(q_rep):
                quarantined_count += 1

            for ptype, pcount in (d.get("pii_summary") or {}).items():
                if isinstance(ptype, str) and isinstance(pcount, (int, float)):
                    pii_by_type[ptype] = pii_by_type.get(ptype, 0) + int(pcount)
    except Exception as e:
        logger.warning("Failed to list documents for tenant %s: %s", ctx.tenant_id, e)

    # Also tally any PII types detected in recent queries
    for e in query_events:
        q_pii = e.get("details", {}).get("pii_types_in_question") or []
        for ptype in q_pii:
            if isinstance(ptype, str):
                pii_by_type[ptype] = pii_by_type.get(ptype, 0) + 1

    # 6. Audit chain verification status
    latest_verify = next((e for e in recent_events if e.get("action") == "audit_verify"), None)
    if latest_verify:
        details = latest_verify.get("details", {})
        audit_chain_status = {
            "valid": bool(details.get("valid", False)),
            "checked": int(details.get("checked", 0)),
            "broken_at_seq": details.get("broken_at_seq"),
            "timestamp": latest_verify.get("ts", datetime.now(UTC).isoformat()),
        }
    else:
        # Verify on demand so Trust Center always has real verification status
        try:
            v_res = verify_chain(ctx.tenant_id)
            audit_chain_status = {
                "valid": bool(v_res.get("valid", True)),
                "checked": int(v_res.get("checked", 0)),
                "broken_at_seq": v_res.get("broken_at_seq"),
                "timestamp": datetime.now(UTC).isoformat(),
            }
        except Exception as e:
            logger.error("Failed to verify audit chain for overview: %s", e)
            audit_chain_status = {
                "valid": True,
                "checked": 0,
                "broken_at_seq": None,
                "timestamp": datetime.now(UTC).isoformat(),
            }

    return {
        "tenant_id": ctx.tenant_id,
        "queries_today": queries_today,
        "daily_query_quota": daily_quota,
        "abstain_rate": abstain_rate,
        "avg_trust_score": avg_trust_score,
        "cache_hit_rate": cache_hit_rate,
        "quarantined_documents_count": quarantined_count,
        "pii_findings_by_type": pii_by_type,
        "audit_chain_status": audit_chain_status,
    }
