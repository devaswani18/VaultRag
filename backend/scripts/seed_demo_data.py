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


if __name__ == "__main__":
    seed()
