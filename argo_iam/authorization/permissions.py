"""Permission catalogue and role-to-permission mapping (RBAC).

Permissions come in two families:

* Argo CD permissions are about delivery operations and are what a temporary
  privilege grant can confer.
* IAM governance permissions (approving elevation, managing users, sessions and
  audit) are only ever given by a user's *permanent* role. A temporarily
  elevated user therefore cannot approve requests or make themselves a
  permanent admin, which keeps elevation and its approval separated.
"""

from __future__ import annotations

from enum import Enum
from typing import Dict, FrozenSet

from argo_iam.users.models import Role


class Permission(str, Enum):
    # Argo CD side
    APP_VIEW = "applications:get"
    APP_REFRESH = "applications:refresh"
    APP_SYNC = "applications:sync"
    APP_SYNC_PRODUCTION = "applications:sync:production"
    PROJECT_VIEW = "projects:get"
    PROJECT_UPDATE = "projects:update"
    # IAM governance side
    PRIVILEGE_REQUEST = "iam:privilege:request"
    PRIVILEGE_APPROVE = "iam:privilege:approve"
    USERS_MANAGE = "iam:users:manage"
    SESSIONS_MANAGE = "iam:sessions:manage"
    AUDIT_READ = "iam:audit:read"

    @property
    def is_argocd(self) -> bool:
        return not self.value.startswith("iam:")


ARGOCD_PERMISSIONS: Dict[Role, FrozenSet[Permission]] = {
    Role.VIEWER: frozenset({Permission.APP_VIEW, Permission.PROJECT_VIEW}),
    Role.OPERATOR: frozenset(
        {
            Permission.APP_VIEW,
            Permission.PROJECT_VIEW,
            Permission.APP_REFRESH,
            Permission.APP_SYNC,
        }
    ),
    Role.ADMIN: frozenset(p for p in Permission if p.is_argocd),
}

GOVERNANCE_PERMISSIONS: Dict[Role, FrozenSet[Permission]] = {
    Role.VIEWER: frozenset({Permission.PRIVILEGE_REQUEST}),
    Role.OPERATOR: frozenset({Permission.PRIVILEGE_REQUEST}),
    Role.ADMIN: frozenset(
        {
            Permission.PRIVILEGE_APPROVE,
            Permission.USERS_MANAGE,
            Permission.SESSIONS_MANAGE,
            Permission.AUDIT_READ,
        }
    ),
}


def permissions_for_role(role: Role) -> FrozenSet[Permission]:
    """All permissions of a permanent role."""
    return ARGOCD_PERMISSIONS[role] | GOVERNANCE_PERMISSIONS[role]


def elevatable_permissions(role: Role) -> FrozenSet[Permission]:
    """Permissions a temporary grant of ``role`` confers (Argo CD side only)."""
    return ARGOCD_PERMISSIONS[role]
