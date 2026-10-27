"""User administration: accounts, permanent roles and account status."""

from __future__ import annotations

import re
from typing import List, Optional

from argo_iam.audit.models import EventType
from argo_iam.audit.service import AuditService
from argo_iam.auth.passwords import PasswordHasher
from argo_iam.authorization.permissions import Permission
from argo_iam.authorization.service import AuthorizationService
from argo_iam.clock import Clock
from argo_iam.common import (
    SYSTEM_CONTEXT,
    ConflictError,
    NotFoundError,
    RequestContext,
    ValidationError,
)
from argo_iam.config import Settings
from argo_iam.privilege.service import PrivilegeService
from argo_iam.sessions.models import EndReason
from argo_iam.sessions.service import SessionManager
from argo_iam.users.models import AccountStatus, Role, User
from argo_iam.users.repository import UserRepository

_USERNAME = re.compile(r"^[a-z][a-z0-9._-]{2,31}$")
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def check_password_policy(password: str, settings: Settings) -> None:
    if len(password) < settings.min_password_length:
        raise ValidationError(
            f"Password must be at least {settings.min_password_length} characters."
        )
    classes = sum(
        [
            any(c.islower() for c in password),
            any(c.isupper() for c in password),
            any(c.isdigit() for c in password),
            any(not c.isalnum() for c in password),
        ]
    )
    if classes < 3:
        raise ValidationError(
            "Password must mix at least three of: lower case, upper case, digits, symbols."
        )


class UserService:
    def __init__(
        self,
        repository: UserRepository,
        hasher: PasswordHasher,
        authorization: AuthorizationService,
        sessions: SessionManager,
        privileges: PrivilegeService,
        audit: AuditService,
        clock: Clock,
        settings: Settings,
    ):
        self._repo = repository
        self._hasher = hasher
        self._authz = authorization
        self._sessions = sessions
        self._privileges = privileges
        self._audit = audit
        self._clock = clock
        self._settings = settings

    # -- queries -------------------------------------------------------------

    def get(self, user_id: int) -> User:
        user = self._repo.get(user_id)
        if user is None:
            raise NotFoundError("User not found.")
        return user

    def list_users(self) -> List[User]:
        return self._repo.list_all()

    # -- administration ------------------------------------------------------

    def create_user(
        self,
        actor: User,
        username: str,
        display_name: str,
        email: str,
        password: str,
        role: Role,
        ctx: RequestContext,
    ) -> User:
        self._authz.require(actor, Permission.USERS_MANAGE, ctx, target="user:new")
        return self.provision(username, display_name, email, password, role, actor, ctx)

    def provision(
        self,
        username: str,
        display_name: str,
        email: str,
        password: str,
        role: Role,
        actor=None,
        ctx: Optional[RequestContext] = None,
    ) -> User:
        """Create a user without a permission check (bootstrap / seeding)."""
        username = (username or "").strip().lower()
        email = (email or "").strip()
        if not _USERNAME.match(username):
            raise ValidationError(
                "Username must be 3-32 characters: lower-case letters, digits, '.', '_' or '-'."
            )
        if not _EMAIL.match(email):
            raise ValidationError("Enter a valid e-mail address.")
        check_password_policy(password, self._settings)
        if self._repo.get_by_username(username) is not None:
            raise ConflictError(f"User '{username}' already exists.")
        user = self._repo.add(
            User(
                id=None,
                username=username,
                display_name=(display_name or username).strip()[:80],
                email=email,
                password_hash=self._hasher.hash(password),
                role=role,
                status=AccountStatus.ACTIVE,
                created_at=self._clock.now(),
            )
        )
        self._audit.record(
            EventType.USER_CREATED,
            actor=actor,
            actor_username=None if actor else "system",
            target=f"user:{user.username}",
            ctx=ctx or SYSTEM_CONTEXT,
            details={"role": role.value},
        )
        return user

    def change_role(self, actor: User, user_id: int, role: Role, ctx: RequestContext) -> User:
        self._authz.require(actor, Permission.USERS_MANAGE, ctx, target=f"user:{user_id}")
        user = self.get(user_id)
        if user.role is role:
            return user
        if user.role is Role.ADMIN:
            self._guard_last_admin(user)
        previous = user.role
        user.role = role
        self._repo.save(user)
        self._privileges.end_open_requests_for_user(user.id)
        self._sessions.revoke_all_for_user(user.id, by=actor.username, ctx=ctx)
        self._audit.record(
            EventType.ROLE_CHANGED, actor=actor, target=f"user:{user.username}", ctx=ctx,
            details={"from": previous.value, "to": role.value},
        )
        return user

    def set_status(
        self, actor: User, user_id: int, status: AccountStatus, ctx: RequestContext
    ) -> User:
        self._authz.require(actor, Permission.USERS_MANAGE, ctx, target=f"user:{user_id}")
        user = self.get(user_id)
        if user.status is status:
            return user
        if status is AccountStatus.DISABLED:
            if user.id == actor.id:
                raise ConflictError("You cannot disable your own account.")
            if user.role is Role.ADMIN:
                self._guard_last_admin(user)
        user.status = status
        self._repo.save(user)
        if status is AccountStatus.DISABLED:
            self._privileges.end_open_requests_for_user(user.id)
            self._sessions.revoke_all_for_user(user.id, by=actor.username, ctx=ctx)
            event = EventType.USER_DISABLED
        else:
            event = EventType.USER_ENABLED
        self._audit.record(event, actor=actor, target=f"user:{user.username}", ctx=ctx)
        return user

    def unlock(self, actor: User, user_id: int, ctx: RequestContext) -> User:
        self._authz.require(actor, Permission.USERS_MANAGE, ctx, target=f"user:{user_id}")
        user = self.get(user_id)
        user.failed_attempts = 0
        user.locked_until = None
        self._repo.save(user)
        self._audit.record(
            EventType.USER_UNLOCKED, actor=actor, target=f"user:{user.username}", ctx=ctx
        )
        return user

    def reset_mfa(self, actor: User, user_id: int, ctx: RequestContext) -> User:
        """Clear a user's authenticator; they must enrol again at next login."""
        self._authz.require(actor, Permission.USERS_MANAGE, ctx, target=f"user:{user_id}")
        user = self.get(user_id)
        user.mfa_secret = None
        user.mfa_enabled = False
        user.mfa_last_step = 0
        self._repo.save(user)
        self._sessions.revoke_all_for_user(
            user.id, by=actor.username, reason=EndReason.ACCOUNT_CHANGED, ctx=ctx
        )
        self._audit.record(
            EventType.MFA_RESET, actor=actor, target=f"user:{user.username}", ctx=ctx
        )
        return user

    def _guard_last_admin(self, user: User) -> None:
        if user.is_active and self._repo.count_active_admins() <= 1:
            raise ConflictError("At least one active administrator must remain.")
