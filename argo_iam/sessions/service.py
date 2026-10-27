"""Session Manager: creation, idle/absolute expiration and revocation."""

from __future__ import annotations

import hashlib
import secrets
from datetime import timedelta
from typing import List, Optional, Tuple

from argo_iam.audit.models import EventType, Outcome
from argo_iam.audit.service import AuditService
from argo_iam.authorization.permissions import Permission
from argo_iam.authorization.service import AuthorizationService
from argo_iam.clock import Clock
from argo_iam.common import NotFoundError, PermissionDenied, RequestContext, SYSTEM_CONTEXT
from argo_iam.config import Settings
from argo_iam.sessions.models import EndReason, Session
from argo_iam.sessions.repository import SessionRepository
from argo_iam.users.models import User

# last_seen_at is written at most this often to avoid a write per request.
_TOUCH_INTERVAL = timedelta(seconds=30)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class SessionManager:
    def __init__(
        self,
        repository: SessionRepository,
        authorization: AuthorizationService,
        audit: AuditService,
        clock: Clock,
        settings: Settings,
    ):
        self._repo = repository
        self._authz = authorization
        self._audit = audit
        self._clock = clock
        self._settings = settings

    # -- lifecycle -----------------------------------------------------------

    def create(self, user: User, ctx: RequestContext) -> Tuple[Session, str]:
        """Start a session after successful authentication. Returns (session, token)."""
        now = self._clock.now()
        token = secrets.token_urlsafe(32)
        session = Session(
            id=secrets.token_hex(8),
            token_hash=hash_token(token),
            user_id=user.id,
            created_at=now,
            last_seen_at=now,
            expires_at=now + self._settings.session_absolute_timeout,
            ip=ctx.ip,
            user_agent=ctx.user_agent[:200],
            channel=ctx.channel,
        )
        self._repo.add(session)
        self._audit.record(
            EventType.SESSION_CREATED, actor=user, target=f"session:{session.id}", ctx=ctx,
            details={"expires_at": session.expires_at.isoformat()},
        )
        return session, token

    def resolve(self, token: Optional[str]) -> Optional[Session]:
        """Return the live session for a bearer token, expiring it if it is stale."""
        if not token:
            return None
        session = self._repo.get_by_token_hash(hash_token(token))
        if session is None or session.is_ended:
            return None
        now = self._clock.now()
        reason = None
        if now >= session.expires_at:
            reason = EndReason.ABSOLUTE_TIMEOUT
        elif now - session.last_seen_at >= self._settings.session_idle_timeout:
            reason = EndReason.IDLE_TIMEOUT
        if reason is not None:
            self._repo.end(session.id, now, reason, by="system")
            self._audit.record(
                EventType.SESSION_EXPIRED, Outcome.INFO, actor_username=None,
                target=f"session:{session.id}",
                details={"user_id": session.user_id, "reason": reason.value},
            )
            return None
        if now - session.last_seen_at >= _TOUCH_INTERVAL:
            self._repo.touch(session.id, now)
            session.last_seen_at = now
        return session

    def logout(self, session: Session, user: User, ctx: RequestContext) -> None:
        self._repo.end(session.id, self._clock.now(), EndReason.LOGOUT, by=user.username)
        self._audit.record(
            EventType.LOGOUT, actor=user, target=f"session:{session.id}", ctx=ctx
        )

    def revoke(self, actor: User, session_id: str, ctx: RequestContext) -> Session:
        """Revoke one session: users may revoke their own, managers any session."""
        session = self._repo.get(session_id)
        if session is None:
            raise NotFoundError("Session not found.")
        if session.user_id != actor.id:
            self._authz.require(
                actor, Permission.SESSIONS_MANAGE, ctx, target=f"session:{session_id}"
            )
        if session.is_ended:
            return session
        self._repo.end(session.id, self._clock.now(), EndReason.REVOKED, by=actor.username)
        self._audit.record(
            EventType.SESSION_REVOKED, actor=actor, target=f"session:{session.id}", ctx=ctx,
            details={"session_user_id": session.user_id},
        )
        return self._repo.get(session.id)

    def revoke_all_for_user(
        self, user_id: int, by: str, reason: EndReason = EndReason.ACCOUNT_CHANGED,
        ctx: RequestContext = SYSTEM_CONTEXT, except_session: Optional[str] = None,
    ) -> int:
        """End every open session of a user (used on disable, role or MFA change)."""
        count = 0
        for s in self._repo.list_for_user(user_id):
            if s.id == except_session:
                continue
            self._repo.end(s.id, self._clock.now(), reason, by=by)
            count += 1
        if count:
            self._audit.record(
                EventType.SESSION_REVOKED, actor_username=by, target=f"user:{user_id}",
                ctx=ctx, details={"sessions": count, "reason": reason.value},
            )
        return count

    # -- queries -------------------------------------------------------------

    def list_for_user(self, user_id: int, include_ended: bool = False) -> List[Session]:
        return self._repo.list_for_user(user_id, include_ended)

    def list_open(self, actor: User) -> List[Session]:
        if not self._authz.has(actor, Permission.SESSIONS_MANAGE):
            raise PermissionDenied("Managing sessions requires the admin role.")
        return self._repo.list_open()
