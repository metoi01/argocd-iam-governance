"""Audit Service: records security events into a hash-chained log.

Each event stores the hash of the previous event, so editing or deleting a
row breaks the chain and ``verify_chain`` reports where.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from argo_iam.audit.models import AuditEvent, AuditQuery, EventType, Outcome
from argo_iam.audit.repository import GENESIS_HASH, AuditRepository
from argo_iam.clock import Clock, to_iso
from argo_iam.common import RequestContext, SYSTEM_CONTEXT


def compute_hash(event: AuditEvent) -> str:
    payload = {
        "occurred_at": to_iso(event.occurred_at),
        "event_type": event.event_type.value,
        "outcome": event.outcome.value,
        "actor_id": event.actor_id,
        "actor_username": event.actor_username,
        "target": event.target,
        "ip": event.ip,
        "channel": event.channel,
        "details": event.details,
        "prev_hash": event.prev_hash,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ChainVerification:
    valid: bool
    checked: int
    broken_at: Optional[int] = None


class AuditService:
    def __init__(self, repository: AuditRepository, clock: Clock):
        self._repo = repository
        self._clock = clock

    def record(
        self,
        event_type: EventType,
        outcome: Outcome = Outcome.SUCCESS,
        *,
        actor=None,
        actor_username: Optional[str] = None,
        target: Optional[str] = None,
        ctx: RequestContext = SYSTEM_CONTEXT,
        details: Optional[Dict[str, Any]] = None,
    ) -> AuditEvent:
        """Append one event. ``actor`` is a User (or None for anonymous/system)."""
        with self._repo.transaction():
            event = AuditEvent(
                id=None,
                occurred_at=self._clock.now(),
                event_type=event_type,
                outcome=outcome,
                actor_id=getattr(actor, "id", None),
                actor_username=getattr(actor, "username", None) or actor_username,
                target=target,
                ip=ctx.ip,
                channel=ctx.channel,
                details=dict(details or {}),
                prev_hash=self._repo.last_hash(),
            )
            event.hash = compute_hash(event)
            return self._repo.append(event)

    def query(self, q: AuditQuery = AuditQuery()) -> List[AuditEvent]:
        return self._repo.query(q)

    def count(self, event_type: Optional[EventType] = None) -> int:
        return self._repo.count(event_type)

    def verify_chain(self) -> ChainVerification:
        expected_prev = GENESIS_HASH
        checked = 0
        for event in self._repo.iter_all():
            if event.prev_hash != expected_prev or compute_hash(event) != event.hash:
                return ChainVerification(valid=False, checked=checked, broken_at=event.id)
            expected_prev = event.hash
            checked += 1
        return ChainVerification(valid=True, checked=checked)
