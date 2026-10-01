from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from vaultrag.api.app import create_app
from vaultrag.auth.dependencies import clear_tenant_cache
from vaultrag.auth.jwt_verifier import Claims
from vaultrag.context import Role
from vaultrag.errors import NotFound


@pytest.fixture(autouse=True)
def reset_cache() -> None:
    clear_tenant_cache()
    yield
    clear_tenant_cache()


@pytest.fixture
def client() -> TestClient:
    app = create_app()

    # Add a route to test custom AppError
    @app.get("/test-not-found")
    async def not_found_route() -> None:
        raise NotFound("Document doc-123 was not found")

    # Add a route to test unhandled exception
    @app.get("/test-error")
    async def crash_route() -> None:
        raise RuntimeError("Database connection suddenly dropped")

    # Add a route to test validation error
    @app.post("/test-validate")
    async def validate_route(payload: dict[str, int]) -> dict[str, int]:
        return payload

    return TestClient(app, raise_server_exceptions=False)


# ------------------------------------------------------------------------------
# 1. /health endpoint tests
# ------------------------------------------------------------------------------
def test_health_check(client: TestClient) -> None:
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert "version" in data


# ------------------------------------------------------------------------------
# 2. Security headers tests
# ------------------------------------------------------------------------------
def test_security_headers_present(client: TestClient) -> None:
    response = client.get("/health")
    assert response.headers.get("X-Content-Type-Options") == "nosniff"
    assert response.headers.get("Cache-Control") == "no-store"
    assert response.headers.get("Referrer-Policy") == "no-referrer"
    assert "X-Request-Id" in response.headers


# ------------------------------------------------------------------------------
# 3. Request-ID propagation tests
# ------------------------------------------------------------------------------
def test_request_id_custom_valid_propagation(client: TestClient) -> None:
    custom_id = "custom-req-id-12345"
    response = client.get("/health", headers={"X-Request-Id": custom_id})
    assert response.status_code == 200
    assert response.headers["X-Request-Id"] == custom_id


def test_request_id_invalid_generates_uuid(client: TestClient) -> None:
    invalid_id = "bad$id"
    response = client.get("/health", headers={"X-Request-Id": invalid_id})
    assert response.status_code == 200
    generated_id = response.headers["X-Request-Id"]
    assert generated_id != invalid_id
    assert len(generated_id) >= 8


# ------------------------------------------------------------------------------
# 4. /me endpoint tests (Patched verifier)
# ------------------------------------------------------------------------------
@patch("vaultrag.auth.dependencies.TenantRepo")
@patch("vaultrag.auth.dependencies.verify_id_token")
def test_get_me_valid_token(
    mock_verify: MagicMock,
    mock_repo_cls: MagicMock,
    client: TestClient,
) -> None:
    mock_verify.return_value = Claims(
        sub="usr-123",
        email="admin@acme.example.com",
        tenant_id="acme",
        roles=frozenset([Role.admin, Role.manager]),
        token_use="id",
        raw_claims={
            "exp": 1800000000,
            "iat": 1700000000,
            "iss": "https://cognito-idp.ap-south-1.amazonaws.com/test",
            "aud": "test-client-id",
        },
    )
    mock_repo = MagicMock()
    mock_repo.get.return_value = {"tenant_id": "acme", "status": "ACTIVE"}
    mock_repo_cls.return_value = mock_repo

    response = client.get(
        "/me",
        headers={
            "Authorization": "Bearer mock-token-123",
            "X-Request-Id": "req-auth-valid-99",
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["tenant_id"] == "acme"
    assert data["user_id"] == "usr-123"
    assert sorted(data["roles"]) == ["admin", "manager"]
    assert data["request_id"] == "req-auth-valid-99"
    assert response.headers["X-Request-Id"] == "req-auth-valid-99"


def test_get_me_missing_authorization(client: TestClient) -> None:
    response = client.get("/me")
    assert response.status_code == 401
    data = response.json()
    assert "error" in data
    assert data["error"]["code"] == "unauthorized"
    assert (
        "Authentication required" in data["error"]["message"]
        or "Missing Authorization header" in data["error"]["message"]
    )
    assert "request_id" in data["error"]


def test_get_me_malformed_authorization(client: TestClient) -> None:
    response = client.get("/me", headers={"Authorization": "Basic dXNlcjpwYXNz"})
    assert response.status_code == 401
    data = response.json()
    assert data["error"]["code"] == "unauthorized"
    assert "request_id" in data["error"]


# ------------------------------------------------------------------------------
# 5. Error envelope structure tests
# ------------------------------------------------------------------------------
def test_app_error_envelope(client: TestClient) -> None:
    response = client.get("/test-not-found", headers={"X-Request-Id": "req-not-found-1"})
    assert response.status_code == 404
    data = response.json()
    assert "error" in data
    assert data["error"]["code"] == "not_found"
    assert data["error"]["message"] == "Document doc-123 was not found"
    assert data["error"]["request_id"] == "req-not-found-1"
    assert response.headers["X-Content-Type-Options"] == "nosniff"


def test_validation_error_envelope(client: TestClient) -> None:
    response = client.post("/test-validate", json={"count": "not-an-int"})
    assert response.status_code == 422
    data = response.json()
    assert "error" in data
    assert data["error"]["code"] == "validation_failed"
    assert "request_id" in data["error"]
    assert "details" in data["error"]
    assert len(data["error"]["details"]) > 0


def test_unhandled_exception_envelope(client: TestClient) -> None:
    response = client.get("/test-error")
    assert response.status_code == 500
    data = response.json()
    assert "error" in data
    assert data["error"]["code"] == "internal_error"
    assert data["error"]["message"] == "An unexpected error occurred"
    assert "request_id" in data["error"]
    # Internal crash message must NOT leak to client
    assert "Database connection suddenly dropped" not in str(data)


# ------------------------------------------------------------------------------
# 6. Access logging tests
# ------------------------------------------------------------------------------
@patch("vaultrag.api.app.log_event")
def test_access_logging_emitted(mock_log: MagicMock, client: TestClient) -> None:
    response = client.get("/health?token=secret123&pass=confidential")
    assert response.status_code == 200

    # Ensure log_event was called for http_access
    mock_log.assert_called()
    call_args = [c for c in mock_log.call_args_list if c[0][0] == "http_access"]
    assert len(call_args) >= 1

    event_name, kwargs = call_args[0][0][0], call_args[0][1]
    assert event_name == "http_access"
    assert kwargs["method"] == "GET"
    assert kwargs["path"] == "/health"
    assert kwargs["status"] == 200
    assert "duration_ms" in kwargs

    # Verify query strings or secret parameters are NEVER logged
    for val in kwargs.values():
        val_str = str(val)
        assert "secret123" not in val_str
        assert "confidential" not in val_str
