"""Identities and the role ladder.

Roles are ordered rather than a permission matrix: this system has one privileged
action, approving a change, and inventing a policy engine for it would be more
machinery than the problem deserves.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class Role(StrEnum):
    VIEWER = "viewer"
    OPERATOR = "operator"
    APPROVER = "approver"
    ADMIN = "admin"

    @property
    def rank(self) -> int:
        return _RANKS[self]

    def can(self, required: Role) -> bool:
        return self.rank >= required.rank


_RANKS = {
    Role.VIEWER: 0,
    Role.OPERATOR: 1,
    Role.APPROVER: 2,
    Role.ADMIN: 3,
}


@dataclass(frozen=True)
class Principal:
    subject: str
    role: Role
    kind: str = "user"
    # Whether this session was established with a second factor, and the value
    # a cookie session must echo back to prove the request came from our page.
    mfa: bool = False
    csrf: str = ""

    @property
    def is_service(self) -> bool:
        return self.kind == "service"
