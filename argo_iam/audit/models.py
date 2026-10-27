"""Audit event model."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, Optional


class EventType(str, Enum):
    # Authentication
    LOGIN_SUCCEEDED = "auth.login.succeeded"
    LOGIN_FAILED = "auth.login.failed"
    LOGIN_BLOCKED = "auth.login.blocked"
    ACCOUNT_LOCKED = "auth.account.locked"
    LOGOUT = "auth.logout"
    MFA_CHALLENGE_ISSUED = "auth.mfa.challenge_issued"
    MFA_SUCCEEDED = "auth.mfa.succeeded"
    MFA_FAILED = "auth.mfa.failed"
    MFA_ENROLLED = "auth.mfa.enrolled"
    MFA_RESET = "auth.mfa.reset"
    # Sessions
    SESSION_CREATED = "session.created"
    SESSION_EXPIRED = "session.expired"
    SESSION_REVOKED = "session.revoked"
    # Users and roles
    USER_CREATED = "user.created"
    USER_DISABLED = "user.disabled"
    USER_ENABLED = "user.enabled"
    USER_UNLOCKED = "user.unlocked"
    ROLE_CHANGED = "user.role_changed"
    # Authorization
    ACCESS_DENIED = "authz.denied"
    # Privilege elevation
    PRIVILEGE_REQUESTED = "privilege.requested"
    PRIVILEGE_APPROVED = "privilege.approved"
    PRIVILEGE_REJECTED = "privilege.rejected"
    PRIVILEGE_CANCELLED = "privilege.cancelled"
    PRIVILEGE_REVOKED = "privilege.revoked"
    PRIVILEGE_EXPIRED = "privilege.expired"
    # Argo CD operations performed through the adapter
    ARGOCD_SYNC = "argocd.application.sync"
    ARGOCD_REFRESH = "argocd.application.refresh"
    ARGOCD_PROJECT_UPDATE = "argocd.project.update"

    @property
    def category(self) -> str:
        return self.value.split(".", 1)[0]


class Outcome(str, Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    DENIED = "denied"
    INFO = "info"


@dataclass
class AuditEvent:
    id: Optional[int]
    occurred_at: datetime
    event_type: EventType
    outcome: Outcome
    actor_id: Optional[int]
    actor_username: Optional[str]
    target: Optional[str]
    ip: str
    channel: str
    details: Dict[str, Any] = field(default_factory=dict)
    prev_hash: str = ""
    hash: str = ""


@dataclass(frozen=True)
class AuditQuery:
    event_type: Optional[str] = None  # exact type or a category prefix such as "auth"
    username: Optional[str] = None
    outcome: Optional[str] = None
    limit: int = 200
