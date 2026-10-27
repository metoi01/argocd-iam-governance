"""Authorization Service: role-aware permission checks.

A user's effective permissions are those of their permanent role plus the
Argo CD permissions of an approved, unexpired temporary grant. Expiry is
evaluated against the clock on every check, so a grant stops working the
moment it expires even before the expiry sweep updates its status.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import FrozenSet, Optional

from argo_iam.audit.models import EventType, Outcome
from argo_iam.audit.service import AuditService
from argo_iam.authorization.permissions import (
    Permission,
    elevatable_permissions,
    permissions_for_role,
)
from argo_iam.clock import Clock
from argo_iam.common import PermissionDenied, RequestContext
from argo_iam.privilege.models import PrivilegeRequest
from argo_iam.privilege.repository import PrivilegeRepository
from argo_iam.users.models import Role, User


@dataclass(frozen=True)
class AccessProfile:
    """Snapshot of what a user may do right now."""

    base_role: Role
    effective_role: Role
    permissions: FrozenSet[Permission]
    grant: Optional[PrivilegeRequest]

    @property
    def is_elevated(self) -> bool:
        return self.grant is not None


class AuthorizationService:
    def __init__(self, grants: PrivilegeRepository, audit: AuditService, clock: Clock):
        self._grants = grants
        self._audit = audit
        self._clock = clock

    def profile(self, user: User) -> AccessProfile:
        permissions = set(permissions_for_role(user.role))
        effective = user.role
        grant = None
        if user.is_active:
            grant = self._grants.active_grant_for_user(user.id, self._clock.now())
            if grant is not None and grant.requested_role.outranks(user.role):
                permissions |= elevatable_permissions(grant.requested_role)
                effective = grant.requested_role
            else:
                grant = None
        else:
            permissions = set()
        return AccessProfile(
            base_role=user.role,
            effective_role=effective,
            permissions=frozenset(permissions),
            grant=grant,
        )

    def has(self, user: User, permission: Permission) -> bool:
        return permission in self.profile(user).permissions

    def require(
        self,
        user: User,
        permission: Permission,
        ctx: RequestContext,
        target: Optional[str] = None,
    ) -> None:
        """Raise PermissionDenied (and audit the denial) unless ``user`` may act."""
        profile = self.profile(user)
        if permission in profile.permissions:
            return
        self._audit.record(
            EventType.ACCESS_DENIED,
            Outcome.DENIED,
            actor=user,
            target=target,
            ctx=ctx,
            details={
                "permission": permission.value,
                "base_role": profile.base_role.value,
                "effective_role": profile.effective_role.value,
            },
        )
        raise PermissionDenied(
            f"Your current role ({profile.effective_role.label}) does not allow "
            f"'{permission.value}'."
        )
