"""Canary universe, hand-written expected access matrix, and synthetic principals."""

from __future__ import annotations

import math
from dataclasses import dataclass

from vaultrag.config import get_settings
from vaultrag.context import RequestContext, Role


@dataclass(frozen=True)
class CanaryDescriptor:
    label: str  # "C1", "C2", etc.
    name: str  # "Tenant-wide document"
    tenant_key: str  # "a" or "b"
    visibility: str  # "tenant", "roles", "private"
    allowed_roles: list[str]
    allowed_users: list[str]
    owner_user_id: str


CANARY_DESCRIPTORS: list[CanaryDescriptor] = [
    CanaryDescriptor(
        label="C1",
        name="Tenant-wide document",
        tenant_key="a",
        visibility="tenant",
        allowed_roles=[],
        allowed_users=[],
        owner_user_id="u-admin",
    ),
    CanaryDescriptor(
        label="C2",
        name="Manager-only document",
        tenant_key="a",
        visibility="roles",
        allowed_roles=["manager"],
        allowed_users=[],
        owner_user_id="u-admin",
    ),
    CanaryDescriptor(
        label="C3",
        name="Admin-private document",
        tenant_key="a",
        visibility="private",
        allowed_roles=[],
        allowed_users=[],
        owner_user_id="u-admin",
    ),
    CanaryDescriptor(
        label="C4",
        name="User-granted document",
        tenant_key="a",
        visibility="roles",
        allowed_roles=["manager"],
        allowed_users=["u-intern"],
        owner_user_id="u-admin",
    ),
    CanaryDescriptor(
        label="C5",
        name="Intern-private document",
        tenant_key="a",
        visibility="private",
        allowed_roles=[],
        allowed_users=[],
        owner_user_id="u-intern",
    ),
    CanaryDescriptor(
        label="C6",
        name="Foreign-tenant document",
        tenant_key="b",
        visibility="tenant",
        allowed_roles=[],
        allowed_users=[],
        owner_user_id="u-b-admin",
    ),
]

# HAND-WRITTEN literal expected matrix.
# CRITICAL SAFETY & CORRECTNESS REQUIREMENT:
# This matrix is explicitly hard-coded as a literal constant and is NOT derived
# from can_view(), build_filter(), or any runtime policy helper.
# Deriving it dynamically from existing code would make the self-test circular
# (a bug in can_view or policy logic would simply redefine the expected answer).
# The self-test must evaluate live Qdrant vector retrieval against this immutable ground truth.
EXPECTED_MATRIX: dict[str, dict[str, bool]] = {
    # C1: tenant-wide in Tenant A -> Accessible to all Tenant A principals, blocked for Tenant B
    "C1": {
        "A-admin": True,
        "A-manager": True,
        "A-employee": True,
        "A-intern": True,
        "B-admin": False,
    },
    # C2: roles=[manager] in Tenant A -> Accessible to Admin and Manager only
    "C2": {
        "A-admin": True,
        "A-manager": True,
        "A-employee": False,
        "A-intern": False,
        "B-admin": False,
    },
    # C3: private (owner=u-admin) in Tenant A -> Accessible to Admin only
    "C3": {
        "A-admin": True,
        "A-manager": False,
        "A-employee": False,
        "A-intern": False,
        "B-admin": False,
    },
    # C4: roles=[manager], users=[u-intern] -> Accessible to Admin, Manager, and granted Intern
    "C4": {
        "A-admin": True,
        "A-manager": True,
        "A-employee": False,
        "A-intern": True,
        "B-admin": False,
    },
    # C5: private (owner=u-intern) -> Accessible to Admin and Owner (Intern)
    "C5": {
        "A-admin": True,
        "A-manager": False,
        "A-employee": False,
        "A-intern": True,
        "B-admin": False,
    },
    # C6: tenant-wide in Tenant B -> Blocked for all Tenant A principals, accessible to B-admin
    "C6": {
        "A-admin": False,
        "A-manager": False,
        "A-employee": False,
        "A-intern": False,
        "B-admin": True,
    },
}

PRINCIPAL_KEYS: list[str] = ["A-admin", "A-manager", "A-employee", "A-intern", "B-admin"]
CANARY_KEYS: list[str] = ["C1", "C2", "C3", "C4", "C5", "C6"]


def get_fixed_vector(dim: int | None = None) -> list[float]:
    """Return a normalized fixed unit vector V of dimension `dim`."""
    target_dim = dim or get_settings().embedding_dim
    # Normalized unit vector so cosine similarity is exactly 1.0
    val = 1.0 / math.sqrt(target_dim)
    return [val] * target_dim


def create_synthetic_principals(
    tenant_a: str, tenant_b: str, run_id: str
) -> dict[str, RequestContext]:
    """Instantiate the five synthetic principals as RequestContext objects."""
    return {
        "A-admin": RequestContext(
            tenant_id=tenant_a,
            user_id="u-admin",
            roles=frozenset({Role.admin}),
            request_id=f"req-st-{run_id}-a-admin",
        ),
        "A-manager": RequestContext(
            tenant_id=tenant_a,
            user_id="u-manager",
            roles=frozenset({Role.manager}),
            request_id=f"req-st-{run_id}-a-mgr",
        ),
        "A-employee": RequestContext(
            tenant_id=tenant_a,
            user_id="u-employee",
            roles=frozenset({Role.employee}),
            request_id=f"req-st-{run_id}-a-emp",
        ),
        "A-intern": RequestContext(
            tenant_id=tenant_a,
            user_id="u-intern",
            roles=frozenset({Role.intern}),
            request_id=f"req-st-{run_id}-a-intern",
        ),
        "B-admin": RequestContext(
            tenant_id=tenant_b,
            user_id="u-b-admin",
            roles=frozenset({Role.admin}),
            request_id=f"req-st-{run_id}-b-admin",
        ),
    }
