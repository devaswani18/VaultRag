"""Assurance Center self-test execution engine.

Coordinates synthetic canary placement, multi-principal vector search evaluations,
security checks execution, clean teardown, and cryptographic report signing.
"""

from __future__ import annotations

import hashlib
import logging
import secrets
import uuid
from datetime import UTC, datetime
from typing import Any

from qdrant_client import models

from vaultrag.admin.erasure import sign_payload
from vaultrag.assurance.canaries import (
    CANARY_DESCRIPTORS,
    CANARY_KEYS,
    EXPECTED_MATRIX,
    PRINCIPAL_KEYS,
    create_synthetic_principals,
    get_fixed_vector,
)
from vaultrag.assurance.checks import (
    check_a1_role_restricted_canary,
    check_a2_private_canaries,
    check_a3_user_grant_canary,
    check_a4_full_matrix,
    check_c1_payload_indexes,
    check_c2_tenant_security_policies,
    check_d1_pii_guard,
    check_d2_log_redaction,
    check_e1_sign_and_verify_certificate,
    check_e2_zero_canary_points_remain,
    check_i1_tenant_a_never_receives_c6,
    check_i2_tenant_b_never_receives_c1_c5,
    check_i3_unscoped_query_refused,
    check_i4_builder_fails_closed,
    check_j1_known_direct_injection,
    check_j2_benign_lookalike,
    check_j3_delimiter_breakout,
    check_u1_calling_tenant_audit_chain,
    check_u2_audit_tamper_detection,
)
from vaultrag.assurance.fault_injection import (
    build_filter_drop_role_condition,
    build_filter_ignore_private,
)
from vaultrag.assurance.models import AssuranceReport, CheckResult, MatrixCell
from vaultrag.audit.hashchain import canonical_json
from vaultrag.clients.qdrant import (
    assert_tenant_scoped,
    delete_by_filter,
    ensure_collection,
    search,
    upsert_chunks,
)
from vaultrag.config import get_secret
from vaultrag.context import RequestContext
from vaultrag.security.acl import build_filter

logger = logging.getLogger(__name__)


def run_assurance(
    ctx: RequestContext,
    simulate_bug: str | None = None,
) -> AssuranceReport:
    """Run the complete Assurance Center self-test suite.

    Guarantees:
      1. Zero Gemini/LLM calls.
      2. Strictly isolated synthetic canary tenants ('st-<run_id>-a' & 'st-<run_id>-b').
      3. Guaranteed teardown of all synthetic data in a finally block.
      4. Constant-time cryptographically signed report.
    """
    ensure_collection()

    run_id = secrets.token_hex(4)  # 8 random hex chars
    tenant_a = f"st-{run_id}-a"
    tenant_b = f"st-{run_id}-b"
    now_ts = datetime.now(UTC).isoformat()
    fixed_vector = get_fixed_vector()

    # 1. Upsert the six canary points into Qdrant
    points: list[models.PointStruct] = []
    for c in CANARY_DESCRIPTORS:
        c_tenant = tenant_a if c.tenant_key == "a" else tenant_b
        marker = f"CANARY-{secrets.token_hex(4)}-{c.label}"
        point_id = str(uuid.uuid5(uuid.NAMESPACE_OID, f"{run_id}-{c.label}"))

        payload: dict[str, Any] = {
            "tenant_id": c_tenant,
            "doc_id": f"doc-st-{run_id}-{c.label.lower()}",
            "chunk_id": f"chk-st-{run_id}-{c.label.lower()}",
            "canary_label": c.label,
            "canary_name": c.name,
            "text": f"{marker}: Internal confidential verification text for {c.name}.",
            "visibility": c.visibility,
            "allowed_roles": c.allowed_roles,
            "allowed_users": c.allowed_users,
            "owner_user_id": c.owner_user_id,
            "selftest_run_id": run_id,
            "pii_found": False,
            "injection_risk": "low",
        }

        points.append(
            models.PointStruct(
                id=point_id,
                vector=fixed_vector,
                payload=payload,
            )
        )

    upsert_chunks(points)

    matrix: list[MatrixCell] = []
    checks: list[CheckResult] = []

    try:
        # 2. Select filter builder based on simulation mode
        if simulate_bug == "drop_role_condition":
            builder = build_filter_drop_role_condition
        elif simulate_bug == "ignore_private":
            builder = build_filter_ignore_private
        else:
            builder = build_filter

        principals = create_synthetic_principals(tenant_a, tenant_b, run_id)

        # 3. Query as each synthetic principal and evaluate retrieved canaries
        for p_name in PRINCIPAL_KEYS:
            p_ctx = principals[p_name]
            builder_filter = builder(p_ctx)

            # Safety check: builder's own filter MUST be properly tenant-scoped
            assert_tenant_scoped(builder_filter)

            # Wrap with hard selftest_run_id isolation
            final_filter = models.Filter(
                must=[
                    models.FieldCondition(
                        key="selftest_run_id",
                        match=models.MatchValue(value=run_id),
                    ),
                    builder_filter,
                ]
            )

            results = search(
                vector=fixed_vector,
                query_filter=final_filter,
                limit=50,
            )

            retrieved_labels = {
                r.payload.get("canary_label")
                for r in results
                if r.payload and "canary_label" in r.payload
            }

            for c_label in CANARY_KEYS:
                actually_allowed = c_label in retrieved_labels
                expected_allowed = EXPECTED_MATRIX[c_label][p_name]

                if expected_allowed and actually_allowed:
                    state = "allowed"
                elif not expected_allowed and not actually_allowed:
                    state = "blocked"
                elif not expected_allowed and actually_allowed:
                    state = "leak"
                else:
                    state = "missing"

                matrix.append(
                    MatrixCell(
                        canary=c_label,
                        principal=p_name,
                        expected_allowed=expected_allowed,
                        actually_allowed=actually_allowed,
                        state=state,
                    )
                )

        # 4. Run Security Checks
        # Isolation
        checks.append(check_i1_tenant_a_never_receives_c6(matrix))
        checks.append(check_i2_tenant_b_never_receives_c1_c5(matrix))
        checks.append(check_i3_unscoped_query_refused())
        checks.append(check_i4_builder_fails_closed())

        # Access Control
        checks.append(check_a1_role_restricted_canary(matrix))
        checks.append(check_a2_private_canaries(matrix))
        checks.append(check_a3_user_grant_canary(matrix))
        checks.append(check_a4_full_matrix(matrix))

        # Data Protection
        checks.append(check_d1_pii_guard())
        checks.append(check_d2_log_redaction())

        # Injection Defence
        checks.append(check_j1_known_direct_injection())
        checks.append(check_j2_benign_lookalike())
        checks.append(check_j3_delimiter_breakout())

        # Audit Integrity
        checks.append(check_u1_calling_tenant_audit_chain(ctx))
        checks.append(check_u2_audit_tamper_detection(ctx))

        # Cryptography
        checks.append(check_e1_sign_and_verify_certificate())

        # Configuration Posture
        checks.append(check_c1_payload_indexes())
        checks.append(check_c2_tenant_security_policies(ctx))

    finally:
        # 5. Clean up canary points from Qdrant in finally block
        filt_del_a = models.Filter(
            must=[
                models.FieldCondition(key="tenant_id", match=models.MatchValue(value=tenant_a)),
                models.FieldCondition(key="selftest_run_id", match=models.MatchValue(value=run_id)),
            ]
        )
        filt_del_b = models.Filter(
            must=[
                models.FieldCondition(key="tenant_id", match=models.MatchValue(value=tenant_b)),
                models.FieldCondition(key="selftest_run_id", match=models.MatchValue(value=run_id)),
            ]
        )

        try:
            delete_by_filter(filt_del_a)
            delete_by_filter(filt_del_b)
        except Exception as e:
            logger.error("Error during canary point cleanup: %s", e)

        # Check E2: Verify zero canary points remain
        checks.append(check_e2_zero_canary_points_remain(tenant_a, tenant_b, run_id))

    # 6. Compute summary
    passed_count = sum(1 for c in checks if c.passed)
    total_count = len(checks)
    leaks_count = sum(1 for m in matrix if m.state == "leak")
    missing_count = sum(1 for m in matrix if m.state == "missing")

    summary = {
        "passed": passed_count,
        "total": total_count,
        "leaks": leaks_count,
        "missing": missing_count,
    }

    report_payload: dict[str, Any] = {
        "run_id": run_id,
        "tenant_id": ctx.tenant_id,
        "ts": now_ts,
        "version": 1,
        "simulated": simulate_bug is not None,
        "simulated_bug": simulate_bug,
        "summary": summary,
        "matrix": [m.to_dict() for m in matrix],
        "checks": [c.to_dict() for c in checks],
    }

    # 7. Compute SHA256 of canonical report JSON and sign with secret
    canonical_body = canonical_json(report_payload)
    report_sha256 = hashlib.sha256(canonical_body.encode("utf-8")).hexdigest()

    try:
        secret = get_secret("cert_hmac_secret")
    except Exception:
        secret = "vaultrag-local-dev-anchor-hmac-secret-key"  # noqa: S105

    signed_report = sign_payload({**report_payload, "report_sha256": report_sha256}, secret)

    return AssuranceReport(
        run_id=run_id,
        tenant_id=ctx.tenant_id,
        ts=now_ts,
        version=1,
        simulated=simulate_bug is not None,
        simulated_bug=simulate_bug,
        summary=summary,
        matrix=matrix,
        checks=checks,
        report_sha256=report_sha256,
        signature=signed_report["signature"],
    )
