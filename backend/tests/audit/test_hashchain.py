"""Tests for the cryptographic audit hashchain."""

from __future__ import annotations

import concurrent.futures
from decimal import Decimal
from typing import Any

from vaultrag.audit.hashchain import (
    append_event,
    export_anchor,
    verify_anchor,
    verify_chain,
)
from vaultrag.context import RequestContext, Role


def _make_ctx(tenant_id: str = "tenant-acme", user_id: str = "user-1") -> RequestContext:
    return RequestContext(
        tenant_id=tenant_id,
        user_id=user_id,
        roles=frozenset([Role.admin]),
        request_id="req-test-123",
    )


def test_chain_verifies_after_n_appends(mock_audit_dynamo: dict[str, Any]) -> None:
    resource = mock_audit_dynamo["resource"]
    ctx = _make_ctx()

    actions = [
        (
            "document_create",
            {
                "filename": "doc1.pdf",
                "content_type": "application/pdf",
                "size_bytes": 1024,
                "visibility": "tenant",
            },
        ),
        ("document_ready", {"chunk_count": 5}),
        ("query", {"question_sha256": "abc123hash", "trust_score": 0.95, "abstained": False}),
        ("acl_change", {"visibility": "roles", "allowed_roles": ["manager"]}),
        ("policy_change", {"changed_keys": ["min_faithfulness"]}),
        ("document_delete", {"deleted": True}),
        (
            "query_abstain",
            {
                "question_sha256": "def456hash",
                "trust_score": 0.0,
                "abstained": True,
                "reason": "below_min_retrieval_score",
            },
        ),
        ("injection_attempt", {"risk": "high", "reasons": ["jailbreak"]}),
    ]

    for action, details in actions:
        append_event(
            ctx,
            action=action,
            details=details,
            dynamodb_resource=resource,
        )

    res = verify_chain(ctx.tenant_id, dynamodb_resource=resource)
    assert res["valid"] is True
    assert res["checked"] == len(actions)
    assert res["broken_at_seq"] is None
    assert res["reason"] is None


def test_editing_stored_field_reports_exact_broken_seq(mock_audit_dynamo: dict[str, Any]) -> None:
    resource = mock_audit_dynamo["resource"]
    table = mock_audit_dynamo["audit"]
    ctx = _make_ctx()

    for i in range(5):
        append_event(
            ctx,
            action="document_create",
            resource_id=f"doc-{i}",
            details={
                "filename": f"file_{i}.txt",
                "content_type": "text/plain",
                "size_bytes": 100,
                "visibility": "tenant",
            },
            dynamodb_resource=resource,
        )

    # Tamper with stored field at seq = 2
    table.update_item(
        Key={"tenant_id": ctx.tenant_id, "seq": Decimal("2")},
        UpdateExpression="SET #act = :new_act",
        ExpressionAttributeNames={"#act": "action"},
        ExpressionAttributeValues={":new_act": "erasure"},
    )

    res = verify_chain(ctx.tenant_id, dynamodb_resource=resource)
    assert res["valid"] is False
    assert res["broken_at_seq"] == 2
    assert "Hash mismatch at seq 2" in res["reason"]


def test_deleting_middle_record_detected_as_seq_gap(mock_audit_dynamo: dict[str, Any]) -> None:
    resource = mock_audit_dynamo["resource"]
    table = mock_audit_dynamo["audit"]
    ctx = _make_ctx()

    for i in range(5):
        append_event(
            ctx,
            action="document_ready",
            details={"chunk_count": i + 1},
            dynamodb_resource=resource,
        )

    # Delete middle record (seq = 2)
    table.delete_item(Key={"tenant_id": ctx.tenant_id, "seq": Decimal("2")})

    res = verify_chain(ctx.tenant_id, dynamodb_resource=resource)
    assert res["valid"] is False
    assert res["broken_at_seq"] == 3
    assert "Sequence gap" in res["reason"]


def test_reordering_records_detected_as_broken_chain(mock_audit_dynamo: dict[str, Any]) -> None:
    resource = mock_audit_dynamo["resource"]
    table = mock_audit_dynamo["audit"]
    ctx = _make_ctx()

    for i in range(4):
        append_event(
            ctx,
            action="document_ready",
            details={"chunk_count": i + 1},
            dynamodb_resource=resource,
        )

    # Swap payloads of seq=1 and seq=2 (keeping seq key, but swapping action/details/hashes)
    item_1 = table.get_item(Key={"tenant_id": ctx.tenant_id, "seq": Decimal("1")})["Item"]
    item_2 = table.get_item(Key={"tenant_id": ctx.tenant_id, "seq": Decimal("2")})["Item"]

    # Reorder items
    swapped_1 = dict(item_2)
    swapped_1["seq"] = Decimal("1")
    swapped_2 = dict(item_1)
    swapped_2["seq"] = Decimal("2")

    table.put_item(Item=swapped_1)
    table.put_item(Item=swapped_2)

    res = verify_chain(ctx.tenant_id, dynamodb_resource=resource)
    assert res["valid"] is False
    assert res["broken_at_seq"] is not None
    assert "mismatch" in res["reason"].lower()


def test_concurrent_appends_do_not_fork(mock_audit_dynamo: dict[str, Any]) -> None:
    resource = mock_audit_dynamo["resource"]
    ctx = _make_ctx()
    n_workers = 12

    def _worker(worker_id: int) -> dict[str, Any]:
        return append_event(
            ctx,
            action="query",
            details={
                "question_sha256": f"q_hash_{worker_id}",
                "trust_score": 0.85,
                "abstained": False,
                "cached": False,
            },
            dynamodb_resource=resource,
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=n_workers) as executor:
        futures = [executor.submit(_worker, i) for i in range(n_workers)]
        results = [f.result() for f in concurrent.futures.as_completed(futures)]

    # All seq numbers must be uniquely 0 .. n_workers - 1
    seqs = sorted(r["seq"] for r in results)
    assert seqs == list(range(n_workers))

    # Verify the entire chain is unbroken and valid
    verify_res = verify_chain(ctx.tenant_id, dynamodb_resource=resource)
    assert verify_res["valid"] is True
    assert verify_res["checked"] == n_workers
    assert verify_res["broken_at_seq"] is None


def test_whitelist_drops_disallowed_keys(mock_audit_dynamo: dict[str, Any]) -> None:
    resource = mock_audit_dynamo["resource"]
    table = mock_audit_dynamo["audit"]
    ctx = _make_ctx()

    append_event(
        ctx,
        action="policy_change",
        details={
            "changed_keys": ["pii_mode"],
            "raw_user_prompt": "DROP TABLE students;",
            "internal_secret": "my-secret-key",
            "forbidden_extra": 12345,
        },
        dynamodb_resource=resource,
    )

    resp = table.get_item(Key={"tenant_id": ctx.tenant_id, "seq": Decimal("0")})
    stored_item = resp["Item"]
    stored_details = stored_item["details"]

    assert "changed_keys" in stored_details
    assert "raw_user_prompt" not in stored_details
    assert "internal_secret" not in stored_details
    assert "forbidden_extra" not in stored_details


def test_anchor_signature_verifies_and_fails_when_altered(
    mock_audit_dynamo: dict[str, Any],
) -> None:
    resource = mock_audit_dynamo["resource"]
    ctx = _make_ctx()

    append_event(
        ctx,
        action="document_create",
        resource_id="doc-123",
        details={
            "filename": "test.pdf",
            "content_type": "application/pdf",
            "size_bytes": 500,
            "visibility": "tenant",
        },
        dynamodb_resource=resource,
    )

    secret = "test-custom-hmac-secret-xyz"
    anchor = export_anchor(
        ctx.tenant_id,
        dynamodb_resource=resource,
        hmac_secret=secret,
    )

    assert "signature" in anchor
    assert anchor["seq"] == 0
    assert anchor["tenant_id"] == ctx.tenant_id

    # Signature must verify correctly
    assert verify_anchor(anchor, hmac_secret=secret) is True

    # Tampering with sequence must fail
    tampered_seq = dict(anchor)
    tampered_seq["seq"] = 999
    assert verify_anchor(tampered_seq, hmac_secret=secret) is False

    # Tampering with hash must fail
    tampered_hash = dict(anchor)
    tampered_hash["hash"] = "0" * 64
    assert verify_anchor(tampered_hash, hmac_secret=secret) is False

    # Tampering with signature must fail
    tampered_sig = dict(anchor)
    tampered_sig["signature"] = "deadbeef" * 8
    assert verify_anchor(tampered_sig, hmac_secret=secret) is False
