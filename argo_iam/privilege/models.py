"""Temporary privilege (just-in-time elevation) request model.

Lifecycle::

    PENDING --approve--> ACTIVE --time passes--> EXPIRED
       |                   |
       |                   +--revoke--> REVOKED
       +--reject--> REJECTED
       +--cancel--> CANCELLED
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Optional

from argo_iam.users.models import Role


class RequestStatus(str, Enum):
    PENDING = "pending"
    ACTIVE = "active"
    REJECTED = "rejected"
    CANCELLED = "cancelled"
    EXPIRED = "expired"
    REVOKED = "revoked"

    @property
    def is_open(self) -> bool:
        return self in (RequestStatus.PENDING, RequestStatus.ACTIVE)


@dataclass
class PrivilegeRequest:
    id: Optional[int]
    requester_id: int
    base_role: Role
    requested_role: Role
    justification: str
    duration_minutes: int
    status: RequestStatus
    created_at: datetime
    decided_at: Optional[datetime] = None
    decided_by: Optional[int] = None
    decision_note: Optional[str] = None
    activated_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    ended_at: Optional[datetime] = None

    def is_effective(self, now: datetime) -> bool:
        """True while the grant confers the requested role."""
        return (
            self.status is RequestStatus.ACTIVE
            and self.expires_at is not None
            and now < self.expires_at
        )

    def remaining_seconds(self, now: datetime) -> int:
        if not self.is_effective(now):
            return 0
        return int((self.expires_at - now).total_seconds())
