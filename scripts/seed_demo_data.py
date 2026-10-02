# ruff: noqa: BLE001
"""Demo data seed script for VaultRAG.

Sets up demonstration tenant ("acme") and optionally uploads eval corpus
and generates realistic usage, audit, gaps, and quarantine data for UI exploration and screenshots.

Usage:
    python scripts/seed_demo_data.py [--demo-content] [--tenant acme]
"""

from __future__ import annotations

import argparse
import logging
import sys
import uuid
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path

# Add backend/src to path
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "backend" / "src"))

import boto3
import yaml
from vaultrag.audit.hashchain import append_event, verify_chain
from vaultrag.clients.dynamo import DocumentRepo, TenantRepo
from vaultrag.clients.s3 import build_object_key
from vaultrag.config import get_settings
from vaultrag.context import RequestContext, Role
from vaultrag.ingest.handler import process_record

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger("seed_demo_data")


def seed_tenant(tenant_id: str = "acme") -> None:
    """Ensure the target tenant exists with operational settings."""
    tenant_repo = TenantRepo()
    try:
        tenant_repo.get(tenant_id)
        logger.info("Tenant '%s' already exists.", tenant_id)
    except Exception:
        logger.info("Creating demo tenant '%s'...", tenant_id)
        tenant_repo.create(
            tenant_id=tenant_id,
            name="Acme Corporation",
            settings={
                "pii_mode": "redact",
                "injection_policy": "quarantine_high",
                "min_retrieval_score": 0.35,
                "min_faithfulness": 0.60,
                "daily_query_quota": 500,
                "cache_enabled": True,
                "retain_original_files": True,
                "llm_judge_enabled": False,
            },
        )
        logger.info("Tenant '%s' created successfully.", tenant_id)


def seed_demo_content(tenant_id: str = "acme") -> None:
    """Upload and ingest eval corpus into the specified tenant."""
    manifest_path = REPO_ROOT / "eval" / "corpus" / "manifest.yaml"
    if not manifest_path.exists():
        logger.error("Manifest not found at %s", manifest_path)
        return

    with open(manifest_path, encoding="utf-8") as f:
        manifest = yaml.safe_load(f)

    doc_repo = DocumentRepo()
    settings = get_settings()
    s3 = boto3.client("s3", region_name=settings.aws_region)

    admin_ctx = RequestContext(
        tenant_id=tenant_id,
        user_id="user-admin",
        roles=frozenset({Role.admin}),
        request_id=f"seed-{uuid.uuid4().hex[:8]}",
    )

    documents = manifest.get("documents", [])
    logger.info(
        "Ingesting %d corpus documents into tenant '%s'...", len(documents), tenant_id
    )

    ingested_count = 0
    for doc in documents:
        doc_id = doc["id"]
        filename = doc["filename"]
        file_path = REPO_ROOT / "eval" / "corpus" / filename

        if not file_path.exists():
            logger.warning("Corpus file %s does not exist, skipping.", file_path)
            continue

        with open(file_path, "rb") as f:
            content = f.read()

        size_bytes = len(content)
        content_type = "text/markdown" if filename.endswith(".md") else "text/plain"
        ext = filename.rsplit(".", 1)[-1]

        # 1. Create document entry
        try:
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
        except Exception:
            logger.debug("Doc %s may already exist, proceeding to upload.", doc_id)

        # 2. Upload to S3
        key = build_object_key(tenant_id, doc_id, ext)
        try:
            s3.put_object(
                Bucket=settings.docs_bucket,
                Key=key,
                Body=content,
                ContentType=content_type,
            )

            # 3. Process ingestion
            s3_record = {
                "s3": {
                    "bucket": {"name": settings.docs_bucket},
                    "object": {"key": key},
                }
            }
            process_record(s3_record)
            ingested_count += 1
        except Exception as e:
            logger.warning("Failed processing %s: %s", filename, e)

    logger.info(
        "Ingested %d/%d documents successfully.", ingested_count, len(documents)
    )

    # 4. Seed realistic usage history across 30 days
    logger.info("Seeding 30-day usage and query history...")
    now = datetime.now(UTC)
    for days_ago in range(30, -1, -1):
        day_date = now - timedelta(days=days_ago)
        day_str = day_date.strftime("%Y-%m-%d")

        # Create varied, realistic patterns (more queries on weekdays, weekend dips)
        weekday = day_date.weekday()
        base_queries = 25 if weekday < 5 else 6
        queries = base_queries + (days_ago % 7) * 3
        cache_hits = int(queries * 0.35)
        cache_misses = queries - cache_hits
        chunks = queries * 4
        tokens = queries * 450

        # Direct table write for historical days
        try:
            table = boto3.resource("dynamodb", region_name=settings.aws_region).Table(
                settings.usage_table
            )
            table.put_item(
                Item={
                    "tenant_id": tenant_id,
                    "day": day_str,
                    "queries": queries,
                    "cache_hits": cache_hits,
                    "cache_misses": cache_misses,
                    "chunks": chunks,
                    "est_tokens": tokens,
                    "expires_at": int(now.timestamp()) + 90 * 86400,
                }
            )
        except Exception as e:
            logger.debug("Usage seeding warning for %s: %s", day_str, e)

    # 5. Seed sample audit events
    logger.info("Seeding cryptographic audit events...")
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
                "question_sha256": "3a8712e5",
                "trust_score": 0.94,
                "abstained": False,
                "cached": True,
                "n_sources": 3,
                "pii_types_in_question": ["EMAIL_ADDRESS"],
            },
        )
        append_event(
            admin_ctx,
            action="query_abstain",
            outcome="ok",
            details={
                "question_sha256": "89b72f10",
                "trust_score": 0.22,
                "abstained": True,
                "cached": False,
                "reason": "insufficient_support",
            },
        )
        # Verify chain so audit status badge shows intact
        verify_chain(tenant_id)
        append_event(
            admin_ctx,
            action="audit_verify",
            outcome="ok",
            details={"valid": True, "checked": 10, "broken_at_seq": None},
        )
    except Exception as e:
        logger.warning("Audit seeding warning: %s", e)

    # 6. Seed sample knowledge gaps
    logger.info("Seeding knowledge gap clusters...")
    try:
        gaps_table = boto3.resource("dynamodb", region_name=settings.aws_region).Table(
            settings.gaps_table
        )
        sample_gaps = [
            (
                "What is our Q4 2027 enterprise pricing discount policy?",
                ["pricing", "discount", "enterprise"],
                "insufficient_faithfulness",
            ),
            (
                "How do we configure Kubernetes SSO with Okta in staging?",
                ["kubernetes", "sso", "staging"],
                "no_relevant_sources",
            ),
            (
                "Where can I find the company wellness budget reimbursement form?",
                ["wellness", "reimbursement", "budget"],
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
                    "top_score": Decimal("0.24"),
                    "reason": reason,
                    "expires_at": int(now.timestamp()) + 90 * 86400,
                }
            )
    except Exception as e:
        logger.warning("Knowledge gaps seeding warning: %s", e)

    logger.info("Demo data seeding complete for tenant '%s'!", tenant_id)


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed VaultRAG demo data")
    parser.add_argument(
        "--demo-content",
        action="store_true",
        help="Upload eval corpus and generate 30-day metrics for screenshots and testing",
    )
    parser.add_argument(
        "--tenant",
        default="acme",
        help="Target tenant ID (default: acme)",
    )
    args = parser.parse_args()

    seed_tenant(tenant_id=args.tenant)
    if args.demo_content:
        seed_demo_content(tenant_id=args.tenant)


if __name__ == "__main__":
    main()
