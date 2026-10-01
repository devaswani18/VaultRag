# ruff: noqa: E402
from __future__ import annotations

import sys
import uuid
from pathlib import Path

# Add backend/src to path for direct script invocation
SRC_PATH = Path(__file__).resolve().parent.parent / "src"
if str(SRC_PATH) not in sys.path:
    sys.path.insert(0, str(SRC_PATH))

from qdrant_client import models

from vaultrag.clients.gemini import embed_texts
from vaultrag.clients.qdrant import (
    delete_by_filter,
    ensure_collection,
    search,
    upsert_chunks,
)
from vaultrag.config import get_settings


def run_checks() -> bool:
    settings = get_settings()
    print("=" * 60)
    print(" VaultRAG External Services Connectivity Check")
    print(f" Environment: {settings.env} | Region: {settings.aws_region}")
    print(f" Collection:  {settings.qdrant_collection} | Dim: {settings.embedding_dim}")
    print("=" * 60)

    all_passed = True

    # 1. Gemini Embedding
    vector = None
    try:
        print("\n[1/5] Testing Gemini Embeddings API...")
        vecs = embed_texts(["connectivity check"], task_type="RETRIEVAL_DOCUMENT")
        if vecs and len(vecs) == 1:
            vector = vecs[0]
            print(f"  --> [PASS] Gemini Embed: generated vector of length {len(vector)}")
        else:
            print("  --> [FAIL] Gemini Embed: empty response")
            all_passed = False
    except Exception as e:
        print(f"  --> [FAIL] Gemini Embed error: {type(e).__name__} - {e}")
        all_passed = False

    if vector is None:
        # Fallback dummy vector to continue testing Qdrant if Gemini had quota issues
        vector = [0.01] * settings.embedding_dim

    # 2. Qdrant Ensure Collection
    try:
        print("\n[2/5] Testing Qdrant Collection Initialization...")
        ensure_collection()
        print(
            f"  --> [PASS] Qdrant Collection: '{settings.qdrant_collection}' "
            "ensured with payload indexes"
        )
    except Exception as e:
        print(f"  --> [FAIL] Qdrant Collection error: {type(e).__name__} - {e}")
        all_passed = False
        return False

    # 3. Qdrant Upsert
    test_id = str(uuid.uuid4())
    tenant_id = "connectivity-test"
    try:
        print("\n[3/5] Testing Qdrant Upsert (tenant-scoped)...")
        point = models.PointStruct(
            id=test_id,
            vector=vector,
            payload={
                "tenant_id": tenant_id,
                "doc_id": "doc-conn-1",
                "visibility": "team",
                "allowed_roles": ["admin"],
                "allowed_users": ["test-user"],
                "owner_user_id": "test-user",
            },
        )
        upsert_chunks([point])
        print(f"  --> [PASS] Qdrant Upsert: point {test_id} upserted with tenant_id='{tenant_id}'")
    except Exception as e:
        print(f"  --> [FAIL] Qdrant Upsert error: {type(e).__name__} - {e}")
        all_passed = False

    # 4. Qdrant Search (with mandatory tenant filter)
    q_filter = models.Filter(
        must=[
            models.FieldCondition(
                key="tenant_id",
                match=models.MatchValue(value=tenant_id),
            )
        ]
    )
    try:
        print("\n[4/5] Testing Qdrant Search with tenant-scoped filter...")
        hits = search(vector=vector, query_filter=q_filter, limit=5)
        found = any(hit.id == test_id for hit in hits)
        if found:
            top_hit = next(hit for hit in hits if hit.id == test_id)
            print(f"  --> [PASS] Qdrant Search: retrieved test point (score: {top_hit.score:.4f})")
        else:
            print(f"  --> [FAIL] Qdrant Search: test point {test_id} not in search results: {hits}")
            all_passed = False
    except Exception as e:
        print(f"  --> [FAIL] Qdrant Search error: {type(e).__name__} - {e}")
        all_passed = False

    # 5. Qdrant Delete by Filter
    try:
        print("\n[5/5] Testing Qdrant Delete by tenant filter...")
        deleted = delete_by_filter(q_filter)
        print(f"  --> [PASS] Qdrant Delete: deleted {deleted} point(s) matching tenant filter")
    except Exception as e:
        print(f"  --> [FAIL] Qdrant Delete error: {type(e).__name__} - {e}")
        all_passed = False

    print("\n" + "=" * 60)
    if all_passed:
        print(" ALL CONNECTIVITY CHECKS PASSED SUCCESSFULLY!")
    else:
        print(" SOME CONNECTIVITY CHECKS FAILED - Check errors above.")
    print("=" * 60)
    return all_passed


if __name__ == "__main__":
    success = run_checks()
    sys.exit(0 if success else 1)
