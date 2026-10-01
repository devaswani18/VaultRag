from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from starlette.requests import Request

from vaultrag.auth.dependencies import clear_tenant_cache, get_ctx, require_role
from vaultrag.auth.jwt_verifier import Claims
from vaultrag.context import RequestContext, Role
from vaultrag.errors import Forbidden, NotFound, Unauthorized
from vaultrag.logging_utils import request_id_var, tenant_id_var, user_id_var


def _build_fake_request(auth_header: str | None = None, req_id: str | None = None) -> Request:
    headers = []
    if auth_header:
        headers.append((b"authorization", auth_header.encode("utf-8")))
    if req_id:
        headers.append((b"x-request-id", req_id.encode("utf-8")))

    scope = {
        "type": "http",
        "method": "GET",
        "headers": headers,
    }
    return Request(scope)


@pytest.fixture(autouse=True)
def cleanup() -> None:
    clear_tenant_cache()
    yield
    clear_tenant_cache()


def test_get_ctx_missing_header() -> None:
    req = _build_fake_request(auth_header=None)
    with pytest.raises(Unauthorized, match="Missing Authorization header"):
        get_ctx(req)


def test_get_ctx_invalid_header_scheme() -> None:
    req = _build_fake_request(auth_header="Basic dXNlcjpwYXNz")
    with pytest.raises(Unauthorized, match="Expected 'Bearer <token>'"):
        get_ctx(req)


@patch("vaultrag.auth.dependencies.TenantRepo")
@patch("vaultrag.auth.dependencies.verify_id_token")
def test_get_ctx_valid_token_and_active_tenant(
    mock_verify: MagicMock,
    mock_repo_cls: MagicMock,
) -> None:
    mock_claims = Claims(
        sub="usr-999",
        email="alice@acme.com",
        tenant_id="acme-test",
        roles=frozenset([Role.manager]),
        token_use="id",
        raw_claims={},
    )
    mock_verify.return_value = mock_claims

    mock_repo = MagicMock()
    mock_repo.get.return_value = {"tenant_id": "acme-test", "status": "ACTIVE"}
    mock_repo_cls.return_value = mock_repo

    req = _build_fake_request(auth_header="Bearer fake.jwt.token", req_id="req-custom-123")
    ctx = get_ctx(req)

    assert ctx.tenant_id == "acme-test"
    assert ctx.user_id == "usr-999"
    assert ctx.has_role(Role.manager)
    assert ctx.request_id == "req-custom-123"

    # Contextvars check
    assert tenant_id_var.get() == "acme-test"
    assert user_id_var.get() == "usr-999"
    assert request_id_var.get() == "req-custom-123"


@patch("vaultrag.auth.dependencies.TenantRepo")
@patch("vaultrag.auth.dependencies.verify_id_token")
def test_get_ctx_tenant_inactive_raises_forbidden(
    mock_verify: MagicMock,
    mock_repo_cls: MagicMock,
) -> None:
    mock_claims = Claims(
        sub="usr-1",
        email="user@dormant.com",
        tenant_id="tenant-dormant",
        roles=frozenset([Role.employee]),
        token_use="id",
        raw_claims={},
    )
    mock_verify.return_value = mock_claims

    mock_repo = MagicMock()
    mock_repo.get.return_value = {"tenant_id": "tenant-dormant", "status": "SUSPENDED"}
    mock_repo_cls.return_value = mock_repo

    req = _build_fake_request(auth_header="Bearer valid.jwt.token")
    with pytest.raises(Forbidden, match="is inactive"):
        get_ctx(req)


@patch("vaultrag.auth.dependencies.TenantRepo")
@patch("vaultrag.auth.dependencies.verify_id_token")
def test_get_ctx_tenant_not_found_raises_forbidden(
    mock_verify: MagicMock,
    mock_repo_cls: MagicMock,
) -> None:
    mock_claims = Claims(
        sub="usr-1",
        email="user@unknown.com",
        tenant_id="tenant-missing",
        roles=frozenset([Role.employee]),
        token_use="id",
        raw_claims={},
    )
    mock_verify.return_value = mock_claims

    mock_repo = MagicMock()
    mock_repo.get.side_effect = NotFound("Tenant not found")
    mock_repo_cls.return_value = mock_repo

    req = _build_fake_request(auth_header="Bearer valid.jwt.token")
    with pytest.raises(Forbidden, match="not found"):
        get_ctx(req)


def test_require_role_behavior() -> None:
    # 1. Admin context
    admin_ctx = RequestContext(
        tenant_id="tenant-alpha",
        user_id="usr-admin",
        roles=frozenset([Role.admin]),
        request_id="req-1",
    )

    # Admin passes any requirement
    checker_employee = require_role(Role.employee)
    assert checker_employee(admin_ctx) is admin_ctx

    checker_manager = require_role("manager")
    assert checker_manager(admin_ctx) is admin_ctx

    # 2. Employee context
    emp_ctx = RequestContext(
        tenant_id="tenant-alpha",
        user_id="usr-emp",
        roles=frozenset([Role.employee]),
        request_id="req-2",
    )

    # Employee passes employee check
    assert checker_employee(emp_ctx) is emp_ctx

    # Employee fails manager check
    with pytest.raises(Forbidden, match="Insufficient permissions"):
        checker_manager(emp_ctx)

    # Multiple roles allowed
    checker_multi = require_role("manager", "employee")
    assert checker_multi(emp_ctx) is emp_ctx
