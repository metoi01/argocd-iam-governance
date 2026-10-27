"""Time source abstraction.

Every expiry rule (sessions, MFA challenges, lockouts, temporary privileges)
reads time through a Clock so tests can move time forward deterministically.
"""

from __future__ import annotations

import threading
from datetime import datetime, timedelta, timezone
from typing import Optional


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Clock:
    def now(self) -> datetime:  # pragma: no cover - interface
        raise NotImplementedError


class SystemClock(Clock):
    def now(self) -> datetime:
        return utcnow()


class ManualClock(Clock):
    """A clock that only moves when told to. Used by tests and demos."""

    def __init__(self, start: Optional[datetime] = None):
        self._now = start or datetime(2026, 1, 15, 9, 0, tzinfo=timezone.utc)
        self._lock = threading.Lock()

    def now(self) -> datetime:
        with self._lock:
            return self._now

    def advance(self, **kwargs) -> datetime:
        with self._lock:
            self._now = self._now + timedelta(**kwargs)
            return self._now


def to_iso(value: Optional[datetime]) -> Optional[str]:
    if value is None:
        return None
    # Fixed width so that ISO strings compare correctly inside SQL.
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds")


def from_iso(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    return datetime.fromisoformat(value)
