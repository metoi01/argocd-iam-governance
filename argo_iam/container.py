"""Composition root: builds and wires every service exactly once.

Nothing else in the code base constructs services, so swapping an
implementation (another clock, the HTTP adapter, an in-memory database)
happens here only.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from argo_iam.argocd_adapter import build_adapter
from argo_iam.argocd_adapter.base import ArgoCDAdapter
from argo_iam.argocd_adapter.governed import GovernedArgoCD
from argo_iam.audit.repository import AuditRepository
from argo_iam.audit.service import AuditService
from argo_iam.auth.passwords import PasswordHasher
from argo_iam.auth.repository import ChallengeRepository
from argo_iam.auth.service import AuthenticationService
from argo_iam.auth.totp import TOTP
from argo_iam.authorization.service import AuthorizationService
from argo_iam.clock import Clock, SystemClock
from argo_iam.config import Settings
from argo_iam.db import Database
from argo_iam.privilege.repository import PrivilegeRepository
from argo_iam.privilege.service import PrivilegeService
from argo_iam.sessions.repository import SessionRepository
from argo_iam.sessions.service import SessionManager
from argo_iam.users.repository import UserRepository
from argo_iam.users.service import UserService


@dataclass
class Container:
    settings: Settings
    clock: Clock
    db: Database
    users_repo: UserRepository
    hasher: PasswordHasher
    totp: TOTP
    audit: AuditService
    authorization: AuthorizationService
    sessions: SessionManager
    privileges: PrivilegeService
    users: UserService
    auth: AuthenticationService
    argocd: GovernedArgoCD


def build_container(
    settings: Optional[Settings] = None,
    clock: Optional[Clock] = None,
    adapter: Optional[ArgoCDAdapter] = None,
    hasher: Optional[PasswordHasher] = None,
) -> Container:
    settings = settings or Settings.from_env()
    clock = clock or SystemClock()
    db = Database(settings.database_path)

    users_repo = UserRepository(db)
    privilege_repo = PrivilegeRepository(db)
    hasher = hasher or PasswordHasher()
    totp = TOTP()

    audit = AuditService(AuditRepository(db), clock)
    authorization = AuthorizationService(privilege_repo, audit, clock)
    sessions = SessionManager(SessionRepository(db), authorization, audit, clock, settings)
    privileges = PrivilegeService(
        privilege_repo, users_repo, authorization, audit, clock, settings
    )
    users = UserService(
        users_repo, hasher, authorization, sessions, privileges, audit, clock, settings
    )
    auth = AuthenticationService(
        users_repo, ChallengeRepository(db), hasher, totp, sessions, audit, clock, settings
    )
    argocd = GovernedArgoCD(adapter or build_adapter(settings, clock), authorization, audit)

    return Container(
        settings=settings, clock=clock, db=db, users_repo=users_repo, hasher=hasher,
        totp=totp, audit=audit, authorization=authorization, sessions=sessions,
        privileges=privileges, users=users, auth=auth, argocd=argocd,
    )
