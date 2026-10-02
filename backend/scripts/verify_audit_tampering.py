"""Demonstration of Audit Hash Chain verification and tamper detection.

1. Runs a few queries and document events.
2. Calls /admin/audit/verify -> reports valid=True.
3. Modifies one 'outcome' field in DynamoDB (simulating tampering in DynamoDB console).
4. Calls /admin/audit/verify again -> reports valid=False, broken_at_seq=1.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import boto3
from fastapi.testclient import TestClient
from moto import mock_aws

from vaultrag.api.app import create_app
from vaultrag.audit.hashchain import append_event
from vaultrag.auth.dependencies import get_ctx
from vaultrag.context import RequestContext, Role


def run_demo() -> None:
    with mock_aws():
        # Setup DynamoDB tables
        dynamodb = boto3.resource("dynamodb", region_name="ap-south-1")
        audit_table = dynamodb.create_table(
            TableName="vaultrag-dev-audit",
            KeySchema=[
                {"AttributeName": "tenant_id", "KeyType": "HASH"},
                {"AttributeName": "seq", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "tenant_id", "AttributeType": "S"},
                {"AttributeName": "seq", "AttributeType": "N"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )
        _ = dynamodb.create_table(
            TableName="vaultrag-dev-usage",
            KeySchema=[
                {"AttributeName": "tenant_id", "KeyType": "HASH"},
                {"AttributeName": "day", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "tenant_id", "AttributeType": "S"},
                {"AttributeName": "day", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )
        tenants_table = dynamodb.create_table(
            TableName="vaultrag-dev-tenants",
            KeySchema=[{"AttributeName": "tenant_id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "tenant_id", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )
        tenants_table.put_item(
            Item={
                "tenant_id": "tenant-corp",
                "name": "Acme Corp",
                "status": "active",
                "tier": "enterprise",
                "settings": {"daily_query_quota": 500},
            }
        )

        app = create_app()
        ctx = RequestContext(
            tenant_id="tenant-corp",
            user_id="admin-user",
            roles=frozenset([Role.admin]),
            request_id="req-demo-1",
        )
        app.dependency_overrides[get_ctx] = lambda: ctx
        client = TestClient(app)

        print("\n=== STEP 1: Appending query & system events to the hashchain ===")
        events = [
            ("document_create", "doc-1", {"filename": "handbook.pdf", "size_bytes": 45000}),
            (
                "query",
                None,
                {"question_sha256": "3a4f89d5...", "trust_score": 0.94, "abstained": False},
            ),
            (
                "query",
                None,
                {"question_sha256": "7b8e12a4...", "trust_score": 0.88, "abstained": False},
            ),
            (
                "query_abstain",
                None,
                {
                    "question_sha256": "9c1d33e1...",
                    "trust_score": 0.0,
                    "abstained": True,
                    "reason": "no_results",
                },
            ),
        ]

        for action, res_id, details in events:
            rec = append_event(
                ctx,
                action=action,
                resource_id=res_id,
                details=details,
                dynamodb_resource=dynamodb,
            )
            print(
                f"  [+] Appended seq={rec['seq']} action={rec['action']} outcome={rec['outcome']} hash={rec['hash'][:16]}... prev_hash={rec['prev_hash'][:16]}..."
            )

        print("\n=== STEP 2: Calling /admin/audit/verify (chain intact) ===")
        res1 = client.get("/admin/audit/verify")
        print(f"HTTP Status: {res1.status_code}")
        print("Response JSON:", res1.json())
        assert res1.json()["valid"] is True
        assert res1.json()["checked"] == 4
        print("  -> Chain verification PASSED (valid: True, checked: 4, broken_at_seq: None)")

        print("\n=== STEP 3: Changing one outcome value in DynamoDB (tampering at seq=1) ===")
        print("  DynamoDB UpdateItem on seq=1: outcome 'ok' -> 'tampered'")
        audit_table.update_item(
            Key={"tenant_id": "tenant-corp", "seq": 1},
            UpdateExpression="SET #out = :t",
            ExpressionAttributeNames={"#out": "outcome"},
            ExpressionAttributeValues={":t": "tampered"},
        )

        print("\n=== STEP 4: Calling /admin/audit/verify again (tampered chain) ===")
        res2 = client.get("/admin/audit/verify")
        print(f"HTTP Status: {res2.status_code}")
        print("Response JSON:", res2.json())
        assert res2.json()["valid"] is False
        assert res2.json()["broken_at_seq"] == 1
        print("\n SUCCESS: Chain tampering detected immediately! Broken at seq: 1.")


if __name__ == "__main__":
    run_demo()
