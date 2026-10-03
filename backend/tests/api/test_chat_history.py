from __future__ import annotations

from unittest.mock import MagicMock, patch

import boto3
import pytest
from fastapi.testclient import TestClient
from moto import mock_aws

from vaultrag.api.app import create_app
from vaultrag.auth.dependencies import clear_tenant_cache
from vaultrag.auth.jwt_verifier import Claims
from vaultrag.chat.history import ConversationRepo
from vaultrag.context import RequestContext, Role
from vaultrag.errors import Conflict, NotFound
from vaultrag.rag.query_service import execute_query
from vaultrag.rag.retrieve import RetrievedChunk


@pytest.fixture(autouse=True)
def _reset():
    clear_tenant_cache()
    yield
    clear_tenant_cache()


@pytest.fixture
def mock_dynamodb():
    with mock_aws():
        dynamodb = boto3.resource("dynamodb", region_name="ap-south-1")
        # Create conversations table
        dynamodb.create_table(
            TableName="vaultrag-dev-conversations",
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )
        # Create tenants table
        tenants_table = dynamodb.create_table(
            TableName="vaultrag-dev-tenants",
            KeySchema=[{"AttributeName": "tenant_id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "tenant_id", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )
        tenants_table.put_item(
            Item={
                "tenant_id": "tenant-a",
                "name": "Tenant A",
                "status": "active",
                "settings": {"chat_history_days": 7, "pii_mode": "redact"},
            }
        )
        # Create usage table
        dynamodb.create_table(
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
        # Create audit table
        dynamodb.create_table(
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
        yield dynamodb


# ------------------------------------------------------------------------------
# 8. Owner-only: 404 for other users, admin, other tenants; no admin route
# ------------------------------------------------------------------------------


def test_no_admin_route_reads_conversations():
    """Verify via route-table inspection that NO admin route reads or touches conversations."""
    app = create_app()
    admin_routes = [
        route.path
        for route in app.routes
        if hasattr(route, "path") and route.path.startswith("/admin")
    ]
    for r in admin_routes:
        assert "conversation" not in r.lower(), f"Forbidden admin route found: {r}"


def test_conversation_repo_owner_only_isolation(mock_dynamodb):
    repo = ConversationRepo(dynamodb_resource=mock_dynamodb)
    # User 1 in Tenant A creates a conversation
    repo.create("tenant-a", "user-1", "conv-101", "Confidential Discussion")
    repo.append_messages(
        "tenant-a",
        "user-1",
        "conv-101",
        [{"role": "user", "text": "secret prompt"}],
    )

    # User 1 can read it
    conv = repo.get_conversation("tenant-a", "user-1", "conv-101")
    assert conv["title"] == "Confidential Discussion"
    msgs, _ = repo.get_messages("tenant-a", "user-1", "conv-101")
    assert len(msgs) == 1

    # User 2 in same Tenant A gets 404 NotFound
    with pytest.raises(NotFound):
        repo.get_conversation("tenant-a", "user-2", "conv-101")
    with pytest.raises(NotFound):
        repo.get_messages("tenant-a", "user-2", "conv-101")

    # Tenant Admin in same Tenant A gets 404 NotFound
    with pytest.raises(NotFound):
        repo.get_conversation("tenant-a", "admin-user", "conv-101")
    with pytest.raises(NotFound):
        repo.get_messages("tenant-a", "admin-user", "conv-101")

    # User in Tenant B gets 404 NotFound
    with pytest.raises(NotFound):
        repo.get_conversation("tenant-b", "user-1", "conv-101")
    with pytest.raises(NotFound):
        repo.get_messages("tenant-b", "user-1", "conv-101")


def test_api_chat_endpoints_owner_only(mock_dynamodb):
    app = create_app()
    client = TestClient(app)

    repo = ConversationRepo(dynamodb_resource=mock_dynamodb)
    repo.create("tenant-a", "user-1", "conv-101", "User 1 Chat")

    # Authenticate as user-2 in tenant-a
    with patch("vaultrag.auth.dependencies.verify_id_token") as mock_verify:
        mock_verify.return_value = Claims(
            sub="user-2",
            email="user2@example.com",
            tenant_id="tenant-a",
            roles=frozenset([Role.employee]),
            token_use="id",
            raw_claims={},
        )
        resp = client.get(
            "/chat/conversations/conv-101",
            headers={"Authorization": "Bearer mock-token"},
        )
        assert resp.status_code == 404

        # Delete by other user also returns 404
        del_resp = client.delete(
            "/chat/conversations/conv-101",
            headers={"Authorization": "Bearer mock-token"},
        )
        assert del_resp.status_code == 404

    # Authenticate as admin in tenant-a (still 404)
    with patch("vaultrag.auth.dependencies.verify_id_token") as mock_verify:
        mock_verify.return_value = Claims(
            sub="admin-user",
            email="admin@example.com",
            tenant_id="tenant-a",
            roles=frozenset([Role.admin]),
            token_use="id",
            raw_claims={},
        )
        resp = client.get(
            "/chat/conversations/conv-101",
            headers={"Authorization": "Bearer mock-token"},
        )
        assert resp.status_code == 404


# ------------------------------------------------------------------------------
# 9. TTL attribute set from setting; disabled mode stores nothing; caps enforced
# ------------------------------------------------------------------------------


def test_conversation_ttl_and_caps(mock_dynamodb):
    repo = ConversationRepo(dynamodb_resource=mock_dynamodb)

    # 1. TTL attribute set
    created = repo.create("tenant-a", "user-1", "conv-1", "Title 1", ttl_days=14)
    assert "expires_at" in created
    assert created["expires_at"] > 0

    # 2. Message limit: 200 max. Adding beyond 200 raises Conflict 409
    msgs = [{"role": "user", "text": f"msg {i}"} for i in range(200)]
    repo.append_messages("tenant-a", "user-1", "conv-1", msgs, ttl_days=14)

    with pytest.raises(Conflict):
        repo.append_messages(
            "tenant-a",
            "user-1",
            "conv-1",
            [{"role": "user", "text": "overflow"}],
            ttl_days=14,
        )

    # 3. Conversation cap: 50 max per user. Creating 51 evicts the oldest
    for i in range(2, 52):
        repo.create("tenant-a", "user-1", f"conv-{i}", f"Title {i}", ttl_days=14)

    convs, _ = repo.list("tenant-a", "user-1", limit=50)
    assert len(convs) <= 50
    # Oldest conv-1 was evicted
    conv_ids = [c["conversation_id"] for c in convs]
    assert "conv-1" not in conv_ids


def test_disabled_history_stores_nothing(mock_dynamodb):
    ctx = RequestContext(
        tenant_id="tenant-a",
        user_id="user-1",
        roles=frozenset([Role.employee]),
        request_id="req-123",
    )

    class MockTenantRepo:
        def get(self, tenant_id):
            return {
                "tenant_id": tenant_id,
                "settings": {"chat_history_days": 0},
            }

    fake_chunk = RetrievedChunk(
        chunk_id="c1",
        doc_id="d1",
        text="Sample document text.",
        score=0.9,
        filename="doc.txt",
        page=1,
    )

    resp = execute_query(
        ctx,
        "What is in the document?",
        retrieve_fn=lambda *args, **kwargs: [fake_chunk],
        generate_fn=lambda *args, **kwargs: MagicMock(
            answer="Sample answer",
            segments=[{"text": "Sample answer", "citations": ["c1"]}],
            citations=["c1"],
            canary="canary-123",
        ),
        tenant_repo_cls=MockTenantRepo,
    )

    # With chat_history_days = 0, no conversation_id is returned
    assert "conversation_id" not in resp or resp.get("conversation_id") is None

    # Nothing should be stored in conversations table
    table = mock_dynamodb.Table("vaultrag-dev-conversations")
    scan_resp = table.scan()
    assert scan_resp.get("Count", 0) == 0


# ------------------------------------------------------------------------------
# 10. PII redaction: synthetic card number redacted in stored items
# ------------------------------------------------------------------------------


def test_pii_redacted_in_stored_items(mock_dynamodb):
    ctx = RequestContext(
        tenant_id="tenant-a",
        user_id="user-1",
        roles=frozenset([Role.employee]),
        request_id="req-123",
    )

    class MockTenantRepo:
        def get(self, tenant_id):
            return {
                "tenant_id": tenant_id,
                "settings": {"chat_history_days": 7, "pii_mode": "redact"},
            }

    fake_chunk = RetrievedChunk(
        chunk_id="c1",
        doc_id="d1",
        text="Support details.",
        score=0.95,
        filename="support.txt",
        page=1,
    )

    raw_card = "4532751234567896"  # Valid Luhn card number
    q = f"My credit card is {raw_card}, can you help?"

    resp = execute_query(
        ctx,
        q,
        retrieve_fn=lambda *args, **kwargs: [fake_chunk],
        generate_fn=lambda *args, **kwargs: MagicMock(
            answer=f"Received card {raw_card} securely.",
            segments=[{"text": "Received card securely.", "citations": ["c1"]}],
            citations=["c1"],
            canary="canary-123",
        ),
        tenant_repo_cls=MockTenantRepo,
    )

    conv_id = resp["conversation_id"]
    assert conv_id

    # Scan the DynamoDB table and assert raw credit card number NEVER appears anywhere in any item
    table = mock_dynamodb.Table("vaultrag-dev-conversations")
    scan_resp = table.scan()
    items = scan_resp["Items"]
    assert len(items) >= 2  # Conversation metadata + messages

    for item in items:
        item_str = str(item)
        assert raw_card not in item_str, f"Raw PII card leaked in stored item: {item}"
        if item["sk"].startswith("M#") and item.get("role") == "user":
            assert "[CREDIT_CARD_REDACTED]" in item["text"]


# ------------------------------------------------------------------------------
# 11. Rewrite prompt contains only previous USER questions
# ------------------------------------------------------------------------------


def test_rewrite_prompt_isolation_and_pii(mock_dynamodb):
    ctx = RequestContext(
        tenant_id="tenant-a",
        user_id="user-1",
        roles=frozenset([Role.employee]),
        request_id="req-123",
    )

    class MockTenantRepo:
        def get(self, tenant_id):
            return {
                "tenant_id": tenant_id,
                "settings": {"chat_history_days": 7, "pii_mode": "redact"},
            }

    repo = ConversationRepo(dynamodb_resource=mock_dynamodb)
    repo.create("tenant-a", "user-1", "conv-followup", "Initial topic")
    repo.append_messages(
        "tenant-a",
        "user-1",
        "conv-followup",
        [
            {"role": "user", "text": "What is the capital of France?"},
            {
                "role": "assistant",
                "text": "The capital is Paris with confidential doc snippet XYZ.",
                "sources": [{"doc_id": "d1", "filename": "f.txt", "chunk_id": "c1", "page": 1}],
            },
        ],
    )

    captured_user_prompts = []

    def mock_generate_json(system_prompt, user_prompt):
        captured_user_prompts.append(user_prompt)
        return MagicMock(
            text='{"standalone_question": "What is the population of Paris?"}',
            input_tokens=15,
            output_tokens=8,
        )

    fake_chunk = RetrievedChunk(
        chunk_id="c2",
        doc_id="d2",
        text="Paris population is 2 million.",
        score=0.9,
        filename="geo.txt",
        page=1,
    )

    with patch("vaultrag.clients.gemini.generate_json", side_effect=mock_generate_json):
        _ = execute_query(
            ctx,
            "What is its population?",  # 4 words <= 12 words
            conversation_id="conv-followup",
            retrieve_fn=lambda *args, **kwargs: [fake_chunk],
            generate_fn=lambda *args, **kwargs: MagicMock(
                answer="Paris has about 2 million people.",
                segments=[{"text": "Paris has about 2 million people.", "citations": ["c2"]}],
                citations=["c2"],
                canary="canary-123",
            ),
            tenant_repo_cls=MockTenantRepo,
        )

    assert len(captured_user_prompts) == 1
    prompt = captured_user_prompts[0]
    # Assert ONLY previous user question is in prompt
    assert "What is the capital of France?" in prompt
    assert "What is its population?" in prompt
    # Assert NO assistant text or chunk snippet is present
    assert "confidential doc snippet XYZ" not in prompt
    assert "Paris population is 2 million" not in prompt


def test_rewrite_failure_falls_back(mock_dynamodb):
    ctx = RequestContext(
        tenant_id="tenant-a",
        user_id="user-1",
        roles=frozenset([Role.employee]),
        request_id="req-123",
    )

    class MockTenantRepo:
        def get(self, tenant_id):
            return {
                "tenant_id": tenant_id,
                "settings": {"chat_history_days": 7, "pii_mode": "redact"},
            }

    repo = ConversationRepo(dynamodb_resource=mock_dynamodb)
    repo.create("tenant-a", "user-1", "conv-fallback", "Topic")
    repo.append_messages(
        "tenant-a",
        "user-1",
        "conv-fallback",
        [{"role": "user", "text": "Tell me about Q3 earnings."}],
    )

    retrieved_questions = []

    def mock_retrieve(ctx, query_text, **kwargs):
        retrieved_questions.append(query_text)
        return [
            RetrievedChunk(
                chunk_id="c1",
                doc_id="d1",
                text="Q3 revenue was $10M.",
                score=0.9,
                filename="fin.txt",
                page=1,
            )
        ]

    # Gemini raises exception during rewrite
    with patch("vaultrag.clients.gemini.generate_json", side_effect=RuntimeError("Gemini 500")):
        _ = execute_query(
            ctx,
            "What about Q4?",
            conversation_id="conv-fallback",
            retrieve_fn=mock_retrieve,
            generate_fn=lambda *args, **kwargs: MagicMock(
                answer="Q4 info.",
                segments=[{"text": "Q4 info.", "citations": ["c1"]}],
                citations=["c1"],
                canary="canary-123",
            ),
            tenant_repo_cls=MockTenantRepo,
        )

    # Retrieval fell back to original question
    assert retrieved_questions[0] == "What about Q4?"


# ------------------------------------------------------------------------------
# 12. Audit events carry counts only (no titles or questions)
# ------------------------------------------------------------------------------


def test_audit_events_carry_counts_only(mock_dynamodb):
    app = create_app()
    client = TestClient(app)

    repo = ConversationRepo(dynamodb_resource=mock_dynamodb)
    repo.create("tenant-a", "user-1", "conv-audit", "Sensitive Mergers & Acquisitions")
    repo.append_messages(
        "tenant-a",
        "user-1",
        "conv-audit",
        [{"role": "user", "text": "Secret acquisition target"}] * 3,
    )

    recorded_events = []

    def mock_append(ctx, action, outcome="ok", details=None):
        recorded_events.append({"action": action, "details": details or {}})

    with (
        patch("vaultrag.api.routers.chat.append_event", side_effect=mock_append),
        patch("vaultrag.auth.dependencies.verify_id_token") as mock_verify,
    ):
        mock_verify.return_value = Claims(
            sub="user-1",
            email="u1@example.com",
            tenant_id="tenant-a",
            roles=frozenset([Role.employee]),
            token_use="id",
            raw_claims={},
        )

        # Delete one conversation
        del_resp = client.delete(
            "/chat/conversations/conv-audit",
            headers={"Authorization": "Bearer mock-token"},
        )
        assert del_resp.status_code == 200

        # Clear all conversations
        clear_resp = client.request(
            "DELETE",
            "/chat/conversations",
            json={"confirm": True},
            headers={"Authorization": "Bearer mock-token"},
        )
        assert clear_resp.status_code == 200

    assert len(recorded_events) == 2
    del_event = recorded_events[0]
    assert del_event["action"] == "conversation_deleted"
    assert "messages_deleted" in del_event["details"]
    # Verify no title or text leaked in details
    assert "Sensitive" not in str(del_event["details"])
    assert "acquisition" not in str(del_event["details"])

    clear_event = recorded_events[1]
    assert clear_event["action"] == "conversations_cleared"
    assert "conversations_deleted" in clear_event["details"]
    assert "messages_deleted" in clear_event["details"]
    assert "Sensitive" not in str(clear_event["details"])
