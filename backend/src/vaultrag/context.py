from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum

from vaultrag.errors import ValidationFailed

TENANT_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{1,30}$")


class Role(StrEnum):
    admin = "admin"
    manager = "manager"
    employee = "employee"
    intern = "intern"


class _AdminCheck(int):
    """Boolean flag that also allows being invoked as a method `ctx.is_admin()`."""

    def __call__(self) -> bool:
        return bool(int(self))

    def __bool__(self) -> bool:
        return bool(int(self))


@dataclass(frozen=True)
class RequestContext:
    tenant_id: str
    user_id: str
    roles: frozenset[Role]
    request_id: str

    def __post_init__(self) -> None:
        if not isinstance(self.tenant_id, str) or not TENANT_ID_PATTERN.match(self.tenant_id):
            raise ValidationFailed(
                f"Invalid tenant_id '{self.tenant_id}'. "
                "Must match pattern ^[a-z0-9][a-z0-9-]{1,30}$"
            )

        # Normalize roles into frozenset[Role] if a set/list was passed
        if not isinstance(self.roles, frozenset):
            normalized_roles = set()
            for r in self.roles:
                if isinstance(r, Role):
                    normalized_roles.add(r)
                elif isinstance(r, str):
                    try:
                        normalized_roles.add(Role(r.lower()))
                    except ValueError:
                        raise ValidationFailed(f"Invalid role '{r}'") from None
                else:
                    raise ValidationFailed(f"Invalid role type {type(r)}")
            object.__setattr__(self, "roles", frozenset(normalized_roles))

    def has_role(self, role: Role | str) -> bool:
        if isinstance(role, str):
            try:
                role = Role(role.lower())
            except ValueError:
                return False
        return role in self.roles

    @property
    def is_admin(self) -> _AdminCheck:
        return _AdminCheck(1 if Role.admin in self.roles else 0)

    def role_names(self) -> list[str]:
        return sorted(r.value for r in self.roles)
