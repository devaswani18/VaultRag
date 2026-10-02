"""Knowledge Gaps Tracking & Clustering for Unanswered Queries.

Records queries that abstain or fall below the faithfulness threshold into DynamoDB,
extracting content tokens and providing deterministic greedy Jaccard clustering
for administrative gap analysis.
"""

from __future__ import annotations

import logging
import re
import time
import uuid
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any

import boto3
from boto3.dynamodb.conditions import Key
from fastapi import APIRouter, Depends, HTTPException, Query

from vaultrag.auth.dependencies import get_ctx
from vaultrag.config import get_settings
from vaultrag.context import RequestContext

logger = logging.getLogger(__name__)

STOPWORDS = frozenset(
    {
        "a",
        "about",
        "above",
        "after",
        "again",
        "against",
        "all",
        "am",
        "an",
        "and",
        "any",
        "are",
        "aren't",
        "as",
        "at",
        "be",
        "because",
        "been",
        "before",
        "being",
        "below",
        "between",
        "both",
        "but",
        "by",
        "can",
        "can't",
        "cannot",
        "could",
        "couldn't",
        "did",
        "didn't",
        "do",
        "does",
        "doesn't",
        "doing",
        "don't",
        "down",
        "during",
        "each",
        "few",
        "for",
        "from",
        "further",
        "had",
        "hadn't",
        "has",
        "hasn't",
        "have",
        "haven't",
        "having",
        "he",
        "he'd",
        "he'll",
        "he's",
        "her",
        "here",
        "here's",
        "hers",
        "herself",
        "him",
        "himself",
        "his",
        "how",
        "how's",
        "i",
        "i'd",
        "i'll",
        "i'm",
        "i've",
        "if",
        "in",
        "into",
        "is",
        "isn't",
        "it",
        "it's",
        "its",
        "itself",
        "let's",
        "me",
        "more",
        "most",
        "mustn't",
        "my",
        "myself",
        "no",
        "nor",
        "not",
        "of",
        "off",
        "on",
        "once",
        "only",
        "or",
        "other",
        "ought",
        "our",
        "ours",
        "ourselves",
        "out",
        "over",
        "own",
        "same",
        "shan't",
        "she",
        "she'd",
        "she'll",
        "she's",
        "should",
        "shouldn't",
        "so",
        "some",
        "such",
        "than",
        "that",
        "that's",
        "the",
        "their",
        "theirs",
        "them",
        "themselves",
        "then",
        "there",
        "there's",
        "these",
        "they",
        "they'd",
        "they'll",
        "they're",
        "they've",
        "this",
        "those",
        "through",
        "to",
        "too",
        "under",
        "until",
        "up",
        "very",
        "was",
        "wasn't",
        "we",
        "we'd",
        "we'll",
        "we're",
        "we've",
        "were",
        "weren't",
        "what",
        "what's",
        "when",
        "when's",
        "where",
        "where's",
        "which",
        "while",
        "who",
        "who's",
        "whom",
        "why",
        "why's",
        "with",
        "won't",
        "would",
        "wouldn't",
        "you",
        "you'd",
        "you'll",
        "you're",
        "you've",
        "your",
        "yours",
        "yourself",
        "yourselves",
    }
)


def extract_content_tokens(text: str, max_tokens: int = 12) -> list[str]:
    """Extract up to *max_tokens* unique content tokens, sorted alphabetically."""
    raw_words = re.findall(r"\b[a-zA-Z0-9_-]+\b", text.lower())
    content = {w for w in raw_words if len(w) > 1 and w not in STOPWORDS and not w.isdigit()}
    return sorted(content)[:max_tokens]


def record_knowledge_gap(
    ctx: RequestContext,
    redacted_question: str,
    top_score: float,
    reason: str,
    *,
    table_name: str | None = None,
    dynamodb_resource: Any = None,
) -> dict[str, Any] | None:
    """Record an unanswerable or sub-faithfulness query to the DynamoDB gaps table.

    Never stores the original/unredacted question.
    """
    settings = get_settings()
    t_name = table_name or settings.gaps_table
    now_ts = datetime.now(UTC).isoformat()
    short_id = uuid.uuid4().hex[:8]
    ts_id = f"{now_ts}#{short_id}"

    # Truncate to 120 chars
    preview = redacted_question[:120]
    tokens = extract_content_tokens(preview, max_tokens=12)
    expires_at = int(time.time()) + 90 * 86400  # 90 days TTL

    item: dict[str, Any] = {
        "tenant_id": ctx.tenant_id,
        "ts_id": ts_id,
        "question_preview": preview,
        "tokens": tokens,
        "top_score": Decimal(str(round(top_score, 4))),
        "reason": reason,
        "expires_at": expires_at,
    }

    try:
        if dynamodb_resource is not None:
            table = dynamodb_resource.Table(t_name)
        else:
            resource = boto3.resource("dynamodb", region_name=settings.aws_region)
            table = resource.Table(t_name)
        table.put_item(Item=item)
        return item
    except Exception as e:
        logger.error("Failed to record knowledge gap: %s", e)
        return None


def jaccard_similarity(tokens_a: set[str], tokens_b: set[str]) -> float:
    """Compute Jaccard similarity between two token sets."""
    if not tokens_a and not tokens_b:
        return 1.0
    if not tokens_a or not tokens_b:
        return 0.0
    intersection = len(tokens_a & tokens_b)
    union = len(tokens_a | tokens_b)
    return intersection / union if union > 0 else 0.0


def cluster_gaps(items: list[dict[str, Any]], threshold: float = 0.6) -> list[dict[str, Any]]:
    """Group gap records by token-set Jaccard similarity >= threshold.

    Deterministic greedy clustering:
    - Sorts records by ts_id ascending.
    - Each record joins the first existing cluster with Jaccard similarity >= threshold.
    - If no cluster matches, a new cluster is created with this item as representative.
    - Returns clusters sorted by cluster size (count) descending.
    """
    clusters: list[dict[str, Any]] = []

    # Deterministic chronological order
    sorted_items = sorted(items, key=lambda x: str(x.get("ts_id", "")))

    for item in sorted_items:
        tokens_set = set(item.get("tokens", []))
        ts_full = str(item.get("ts_id", ""))
        ts_part = ts_full.split("#")[0] if "#" in ts_full else ts_full
        reason = str(item.get("reason", ""))
        preview = str(item.get("question_preview", ""))

        best_cluster = None
        best_sim = -1.0

        for cluster in clusters:
            sim = jaccard_similarity(tokens_set, cluster["_tokens"])
            if sim >= threshold and sim > best_sim:
                best_sim = sim
                best_cluster = cluster

        if best_cluster is not None:
            best_cluster["count"] += 1
            best_cluster["_tokens"].update(tokens_set)
            if reason:
                best_cluster["_reasons"].add(reason)
            if ts_part:
                if not best_cluster["first_seen"] or ts_part < best_cluster["first_seen"]:
                    best_cluster["first_seen"] = ts_part
                if not best_cluster["last_seen"] or ts_part > best_cluster["last_seen"]:
                    best_cluster["last_seen"] = ts_part
        else:
            reasons_set = {reason} if reason else set()
            clusters.append(
                {
                    "representative_preview": preview,
                    "count": 1,
                    "first_seen": ts_part,
                    "last_seen": ts_part,
                    "_tokens": set(tokens_set),
                    "_reasons": reasons_set,
                }
            )

    result = []
    for c in clusters:
        result.append(
            {
                "representative_preview": c["representative_preview"],
                "count": c["count"],
                "first_seen": c["first_seen"],
                "last_seen": c["last_seen"],
                "reasons": sorted(c["_reasons"]),
            }
        )

    # Sort clusters by count descending, then by first_seen
    result.sort(key=lambda x: (-x["count"], x["first_seen"]))
    return result


router = APIRouter(prefix="/admin", tags=["admin-gaps"])


@router.get("/gaps")
async def get_knowledge_gaps(
    days: int = Query(30, ge=1, le=90),
    ctx: RequestContext = Depends(get_ctx),  # noqa: B008
) -> list[dict[str, Any]]:
    """Retrieve clustered knowledge gaps for the tenant over the given time window (admin only)."""
    if not ctx.is_admin:
        raise HTTPException(status_code=403, detail="Admin role required to view knowledge gaps")

    settings = get_settings()
    cutoff_ts = (datetime.now(UTC) - timedelta(days=days)).isoformat()

    resource = boto3.resource("dynamodb", region_name=settings.aws_region)
    table = resource.Table(settings.gaps_table)

    try:
        resp = table.query(
            KeyConditionExpression=Key("tenant_id").eq(ctx.tenant_id) & Key("ts_id").gte(cutoff_ts),
            Limit=500,
        )
        items = resp.get("Items", [])
    except Exception as e:
        logger.error("Failed to query gaps table for tenant %s: %s", ctx.tenant_id, e)
        items = []

    return cluster_gaps(items, threshold=0.6)
