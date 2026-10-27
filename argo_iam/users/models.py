"""User domain model: profile, base role and account status."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Optional


class Role(str, Enum):
    """Base roles, ordered from least to most privileged."""

    VIEWER = "viewer"
    OPERATOR = "operator"
    ADMIN = "admin"

    @property
    def rank(self) -> int:
        return _ROLE_RANK[self]

    @property
    def label(self) -> str:
        return self.value.capitalize()

    def outranks(self, other: "Role") -> bool:
        return self.rank > other.rank


_ROLE_RANK = {Role.VIEWER: 0, Role.OPERATOR: 1, Role.ADMIN: 2}


class AccountStatus(str, Enum):
    ACTIVE = "active"
    DISABLED = "disabled"


@dataclass
class User:
    id: Optional[int]
    username: str
    display_name: str
    email: str
    password_hash: str
    role: Role
    status: AccountStatus
    created_at: datetime
    mfa_secret: Optional[str] = None
    mfa_enabled: bool = False
    mfa_last_step: int = 0
    failed_attempts: int = 0
    locked_until: Optional[datetime] = None
    last_login_at: Optional[datetime] = None

    @property
    def is_active(self) -> bool:
        return self.status is AccountStatus.ACTIVE

    def is_locked(self, now: datetime) -> bool:
        return self.locked_until is not None and self.locked_until > now
