"""Session domain model."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Optional


class EndReason(str, Enum):
    LOGOUT = "logout"
    REVOKED = "revoked"
    IDLE_TIMEOUT = "idle_timeout"
    ABSOLUTE_TIMEOUT = "absolute_timeout"
    ACCOUNT_CHANGED = "account_changed"


@dataclass
class Session:
    id: str  # public identifier, safe to show in the UI
    token_hash: str  # SHA-256 of the bearer token; the token itself is never stored
    user_id: int
    created_at: datetime
    last_seen_at: datetime
    expires_at: datetime
    ip: str
    user_agent: str
    channel: str
    ended_at: Optional[datetime] = None
    end_reason: Optional[EndReason] = None
    ended_by: Optional[str] = None

    @property
    def is_ended(self) -> bool:
        return self.ended_at is not None
