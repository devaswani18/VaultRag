from __future__ import annotations

import pytest

from vaultrag.context import RequestContext, Role
from vaultrag.errors import ValidationFailed


def test_valid_request_context() -> None:
    ctx = RequestContext(
        tenant_id="tenant-123",
        user_id="usr-abc",
        roles=frozenset([Role.admin, Role.employee]),
        request_id="req-123",
    )
    assert ctx.tenant_id == "tenant-123"
    assert ctx.user_id == "usr-abc"
    assert ctx.has_role(Role.admin) is True
    assert ctx.has_role("admin") is True
    assert ctx.has_role("manager") is False
    assert ctx.is_admin is not False
    assert bool(ctx.is_admin) is True
    assert ctx.is_admin() is True
    assert ctx.role_names() == ["admin", "employee"]


def test_non_admin_request_context() -> None:
    ctx = RequestContext(
        tenant_id="tenant-alpha",
        user_id="usr-xyz",
        roles=frozenset([Role.intern]),
        request_id="req-456",
    )
    assert bool(ctx.is_admin) is False
    assert ctx.is_admin() is False
    assert ctx.has_role(Role.admin) is False
    assert ctx.role_names() == ["intern"]


@pytest.mark.parametrize(
    "bad_tenant_id",
    [
        "../x",  # Path traversal attempt
        "TENANT-123",  # Uppercase characters forbidden
        "a",  # Too short (pattern requires start char + 1 to 30 chars, min len 2)
        "",  # Empty string
        "-tenant",  # Cannot start with hyphen
        "tenant_123",  # Underscores forbidden
        "tenant.123",  # Dots forbidden
        "tenant/123",  # Slashes forbidden
        "a" * 32,  # Too long (> 31 characters)
        "tenant@domain",  # Special characters forbidden
        "tenant\x00x",  # Null byte forbidden
    ],
)
def test_invalid_tenant_id_rejected(bad_tenant_id: str) -> None:
    with pytest.raises(ValidationFailed):
        RequestContext(
            tenant_id=bad_tenant_id,
            user_id="user-1",
            roles=frozenset([Role.employee]),
            request_id="req-1",
        )
