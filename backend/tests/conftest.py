from __future__ import annotations

import os
from collections.abc import Generator
from unittest.mock import patch

import pytest

# Ensure dummy AWS credentials are set for all pytest executions (avoids NoCredentialsError in CI)
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
os.environ.setdefault("AWS_SECURITY_TOKEN", "testing")
os.environ.setdefault("AWS_SESSION_TOKEN", "testing")
os.environ.setdefault("AWS_DEFAULT_REGION", "ap-south-1")
os.environ.setdefault("AWS_REGION", "ap-south-1")


@pytest.fixture(autouse=True)
def _auto_mock_audit_for_unit_tests(request: pytest.FixtureRequest) -> Generator[None, None, None]:
    """Auto-mock append_event for unit tests outside tests/audit.

    Unit tests (e.g. tests/acl, tests/api, tests/security) mock repositories and do not
    set up real/moto DynamoDB tables for the cryptographic audit chain.
    """
    test_path = str(request.fspath).replace("\\", "/")
    if "tests/audit" in test_path:
        yield
        return

    mock_rec = {
        "tenant_id": "test-tenant",
        "seq": 0,
        "ts": "2026-10-02T00:00:00Z",
        "actor": "user-1",
        "action": "mock",
        "resource_id": None,
        "outcome": "ok",
        "details": {},
        "prev_hash": "0" * 64,
        "hash": "1" * 64,
    }

    with (
        patch("vaultrag.api.routers.documents.append_event", return_value=mock_rec),
        patch("vaultrag.admin.policies.append_event", return_value=mock_rec),
    ):
        yield
