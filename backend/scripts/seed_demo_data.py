# ruff: noqa: E402
from __future__ import annotations

import contextlib
import json
import os
import secrets
import string
import sys
from pathlib import Path
from typing import Any

# Add backend/src to path
SRC_PATH = Path(__file__).resolve().parent.parent / "src"
if str(SRC_PATH) not in sys.path:
    sys.path.insert(0, str(SRC_PATH))

import boto3
from botocore.exceptions import ClientError

from vaultrag.clients.dynamo import TenantRepo
from vaultrag.config import get_settings

TENANTS = ["acme", "globex"]
ROLES = ["admin", "manager", "employee", "intern"]


def _generate_strong_password(length: int = 16) -> str:
    """Generate a random password meeting Cognito policy (min 12, upper, lower, num, symbol)."""
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    while True:
        pwd = "".join(secrets.choice(alphabet) for _ in range(length))
        if (
            any(c in string.ascii_uppercase for c in pwd)
            and any(c in string.ascii_lowercase for c in pwd)
            and any(c in string.digits for c in pwd)
            and any(c in "!@#$%^&*()-_=+" for c in pwd)
        ):
            return pwd


def _get_user_pool_id(settings: Any, cognito_client: Any) -> str:
    """Resolve Cognito User Pool ID from settings or by prefix search."""
    if settings.cognito_user_pool_id:
        return settings.cognito_user_pool_id

    # Fallback: look up pool by name
    expected_name = f"{settings.tenants_table.replace('-tenants', '')}-users"
    resp = cognito_client.list_user_pools(MaxResults=20)
    for pool in resp.get("UserPools", []):
        if pool.get("Name") == expected_name or "vaultrag" in pool.get("Name", ""):
            return pool["Id"]

    raise ValueError(
        f"Cognito User Pool ID not configured and no pool matching '{expected_name}' found."
    )


def seed() -> None:
    settings = get_settings()
    cognito = boto3.client("cognito-idp", region_name=settings.aws_region)
    tenant_repo = TenantRepo()

    print("=" * 60)
    print(" VaultRAG Demo Data Seeder")
    print(f" Environment: {settings.env} | Region: {settings.aws_region}")
    print("=" * 60)

    # 1. Seed Tenants
    print("\n[1/2] Seeding Demo Tenants in DynamoDB...")
    for t in TENANTS:
        tenant_repo.put(
            tenant_id=t,
            name=f"{t.capitalize()} Corporation",
            status="ACTIVE",
        )
        print(f"  --> Seeded tenant '{t}' (status: ACTIVE)")

    # 2. Seed Cognito Users
    print("\n[2/2] Seeding Demo Users in Cognito...")
    try:
        user_pool_id = _get_user_pool_id(settings, cognito)
        print(f"  --> Using User Pool: {user_pool_id}")
    except Exception as e:
        print(f"  --> [WARN] Skipping Cognito user seeding (User Pool not active yet): {e}")
        return

    # Determine credential file path at repository root
    repo_root = Path(__file__).resolve().parent.parent.parent
    cred_file = repo_root / ".demo-credentials.json"

    existing_creds: dict[str, Any] = {}
    if cred_file.exists():
        try:
            with open(cred_file, encoding="utf-8") as f:
                existing_creds = json.load(f)
        except Exception:
            existing_creds = {}

    credentials_saved: list[dict[str, str]] = existing_creds.get("users", [])

    for tenant in TENANTS:
        for role in ROLES:
            email = f"{role}@{tenant}.example.com"
            user_exists = False

            try:
                cognito.admin_get_user(UserPoolId=user_pool_id, Username=email)
                user_exists = True
                print(f"  --> User '{email}' already exists in Cognito (skipped creation)")
            except ClientError as e:
                if e.response.get("Error", {}).get("Code") != "UserNotFoundException":
                    print(f"  --> [ERROR] Checking user '{email}': {e}")
                    continue

            password = None
            if not user_exists:
                password = _generate_strong_password(16)
                try:
                    cognito.admin_create_user(
                        UserPoolId=user_pool_id,
                        Username=email,
                        UserAttributes=[
                            {"Name": "email", "Value": email},
                            {"Name": "email_verified", "Value": "true"},
                            {"Name": "custom:tenant_id", "Value": tenant},
                        ],
                        MessageAction="SUPPRESS",
                    )
                    cognito.admin_set_user_password(
                        UserPoolId=user_pool_id,
                        Username=email,
                        Password=password,
                        Permanent=True,
                    )
                    print(f"  --> Created user '{email}' for tenant '{tenant}' with role '{role}'")
                except ClientError as e:
                    print(f"  --> [ERROR] Creating user '{email}': {e}")
                    continue

            # Ensure group membership
            try:
                cognito.admin_add_user_to_group(
                    UserPoolId=user_pool_id,
                    Username=email,
                    GroupName=role,
                )
            except ClientError as e:
                print(f"  --> [WARN] Group assignment for '{email}': {e}")

            if password:
                # Update saved credentials record
                # Remove prior entry if present
                credentials_saved = [u for u in credentials_saved if u.get("email") != email]
                credentials_saved.append(
                    {
                        "tenant_id": tenant,
                        "role": role,
                        "email": email,
                        "password": password,
                    }
                )

    # Write credentials to .demo-credentials.json with chmod 600
    if credentials_saved:
        payload = {
            "user_pool_id": user_pool_id,
            "users": credentials_saved,
        }
        with open(cred_file, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)

        with contextlib.suppress(OSError):
            os.chmod(cred_file, 0o600)

        print(f"\n[INFO] Credentials saved to private file: {cred_file} (chmod 600)")
        print("[INFO] Passwords were NEVER printed to the terminal.")


def seed_demo_content(tenant_id: str = "acme") -> None:
    """Upload and ingest eval corpus into tenant 'acme' so screenshots have rich data."""
    import uuid
    from datetime import UTC, datetime, timedelta
    from decimal import Decimal

    import yaml

    from vaultrag.audit.hashchain import append_event, verify_chain
    from vaultrag.clients.dynamo import DocumentRepo
    from vaultrag.clients.s3 import build_object_key
    from vaultrag.context import RequestContext, Role
    from vaultrag.ingest.handler import process_record

    settings = get_settings()
    repo_root = Path(__file__).resolve().parent.parent.parent
    manifest_path = repo_root / "eval" / "corpus" / "manifest.yaml"

    print(f"\n[3/3] Uploading eval corpus into tenant '{tenant_id}' (--demo-content)...")
    if not manifest_path.exists():
        print(f"  --> [WARN] Manifest not found at {manifest_path}")
        return

    with open(manifest_path, encoding="utf-8") as f:
        manifest = yaml.safe_load(f)

    doc_repo = DocumentRepo()
    s3 = boto3.client("s3", region_name=settings.aws_region)
    admin_ctx = RequestContext(
        tenant_id=tenant_id,
        user_id="user-admin",
        roles=frozenset({Role.admin}),
        request_id=f"seed-{uuid.uuid4().hex[:8]}",
    )

    docs = manifest.get("documents", [])
    ingested_count = 0
    for doc in docs:
        doc_id = doc["id"]
        filename = doc["filename"]
        file_path = repo_root / "eval" / "corpus" / filename

        if not file_path.exists():
            continue

        with open(file_path, "rb") as f:
            content = f.read()

        size_bytes = len(content)
        content_type = "text/markdown" if filename.endswith(".md") else "text/plain"
        ext = filename.rsplit(".", 1)[-1]

        with contextlib.suppress(Exception):
            doc_repo.create(
                tenant_id=tenant_id,
                doc_id=doc_id,
                filename=filename,
                content_type=content_type,
                size_bytes=size_bytes,
                owner_user_id=doc.get("owner", "user-admin"),
                visibility=doc.get("visibility", "tenant"),
                allowed_roles=doc.get("allowed_roles", []),
                allowed_users=doc.get("allowed_users", []),
            )

        key = build_object_key(tenant_id, doc_id, ext)
        try:
            s3.put_object(
                Bucket=settings.docs_bucket,
                Key=key,
                Body=content,
                ContentType=content_type,
            )
            s3_record = {
                "s3": {
                    "bucket": {"name": settings.docs_bucket},
                    "object": {"key": key},
                }
            }
            process_record(s3_record)
            ingested_count += 1
            print(f"  --> Ingested {filename} ({doc_id})")
        except Exception as e:
            print(f"  --> [WARN] Failed ingesting {filename}: {e}")

    # Seed 30-day usage metrics
    print(f"  --> Seeding 30-day usage history for tenant '{tenant_id}'...")
    now = datetime.now(UTC)
    dynamodb = boto3.resource("dynamodb", region_name=settings.aws_region)
    usage_table = dynamodb.Table(settings.usage_table)
    for days_ago in range(30, -1, -1):
        day_date = now - timedelta(days=days_ago)
        day_str = day_date.strftime("%Y-%m-%d")
        weekday = day_date.weekday()
        base_queries = 28 if weekday < 5 else 8
        queries = base_queries + (days_ago % 5) * 4
        cache_hits = int(queries * 0.4)
        cache_misses = queries - cache_hits
        with contextlib.suppress(Exception):
            usage_table.put_item(
                Item={
                    "tenant_id": tenant_id,
                    "day": day_str,
                    "queries": queries,
                    "cache_hits": cache_hits,
                    "cache_misses": cache_misses,
                    "chunks": queries * 4,
                    "est_tokens": queries * 400,
                    "expires_at": int(now.timestamp()) + 90 * 86400,
                }
            )

    # Seed sample audit events
    print(f"  --> Seeding audit records and verifying chain for '{tenant_id}'...")
    try:
        append_event(
            admin_ctx,
            action="policy_change",
            outcome="ok",
            details={"changed_keys": ["pii_mode", "daily_query_quota"]},
        )
        append_event(
            admin_ctx,
            action="query",
            outcome="ok",
            details={
                "question_sha256": "4b281f9a",
                "trust_score": 0.92,
                "abstained": False,
                "cached": True,
                "pii_types_in_question": ["EMAIL_ADDRESS"],
            },
        )
        append_event(
            admin_ctx,
            action="query_abstain",
            outcome="ok",
            details={
                "question_sha256": "81c039ab",
                "trust_score": 0.20,
                "abstained": True,
                "reason": "insufficient_support",
            },
        )
        verify_chain(tenant_id)
        append_event(
            admin_ctx,
            action="audit_verify",
            outcome="ok",
            details={"valid": True, "checked": 15, "broken_at_seq": None},
        )
    except Exception as e:
        print(f"  --> [WARN] Audit event seeding: {e}")

    # Seed knowledge gaps
    print(f"  --> Seeding clustered knowledge gaps for '{tenant_id}'...")
    try:
        gaps_table = dynamodb.Table(settings.gaps_table)
        sample_gaps = [
            (
                "What is our Q4 enterprise pricing and volume discount table?",
                ["pricing", "discount", "enterprise"],
                "insufficient_faithfulness",
            ),
            (
                "How do we configure Kubernetes cluster SSO with Okta?",
                ["kubernetes", "sso", "staging"],
                "no_relevant_sources",
            ),
            (
                "Where can I submit employee wellness gym reimbursement receipts?",
                ["wellness", "gym", "receipts"],
                "insufficient_faithfulness",
            ),
        ]
        for preview, tokens, reason in sample_gaps:
            now_iso = datetime.now(UTC).isoformat()
            ts_id = f"{now_iso}#{uuid.uuid4().hex[:8]}"
            gaps_table.put_item(
                Item={
                    "tenant_id": tenant_id,
                    "ts_id": ts_id,
                    "question_preview": preview,
                    "tokens": tokens,
                    "top_score": Decimal("0.25"),
                    "reason": reason,
                    "expires_at": int(now.timestamp()) + 90 * 86400,
                }
            )
    except Exception as e:
        print(f"  --> [WARN] Gaps seeding: {e}")

    print(f"  --> Done! Ingested {ingested_count} documents with full demo telemetry.")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="VaultRAG Demo Data Seeder")
    parser.add_argument(
        "--demo-content",
        action="store_true",
        help="Upload eval corpus into tenant 'acme' and generate 30-day telemetry for screenshots",
    )
    parser.add_argument(
        "--tenant",
        default="acme",
        help="Target tenant (default: acme)",
    )
    args = parser.parse_args()

    seed()
    if args.demo_content:
        seed_demo_content(tenant_id=args.tenant)
