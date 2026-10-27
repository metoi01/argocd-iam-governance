"""Governed access to Argo CD: every operation passes authorization and audit.

This is the only path from the IAM layer's UI/API to the adapter:

    caller -> GovernedArgoCD -> AuthorizationService -> ArgoCDAdapter
                             -> AuditService
"""

from __future__ import annotations

from typing import List, Optional

from argo_iam.argocd_adapter.base import (
    ArgoApplication,
    ArgoCDAdapter,
    ArgoCDError,
    ArgoProject,
    SyncResult,
)
from argo_iam.audit.models import EventType, Outcome
from argo_iam.audit.service import AuditService
from argo_iam.authorization.permissions import Permission
from argo_iam.authorization.service import AuthorizationService
from argo_iam.common import RequestContext, ValidationError
from argo_iam.users.models import User


def required_sync_permission(app: ArgoApplication) -> Permission:
    return Permission.APP_SYNC_PRODUCTION if app.is_production else Permission.APP_SYNC


class GovernedArgoCD:
    def __init__(
        self, adapter: ArgoCDAdapter, authorization: AuthorizationService, audit: AuditService
    ):
        self.adapter = adapter
        self._authz = authorization
        self._audit = audit

    def list_applications(self, user: User, ctx: RequestContext) -> List[ArgoApplication]:
        self._authz.require(user, Permission.APP_VIEW, ctx, target="applications")
        return self.adapter.list_applications()

    def get_application(self, user: User, name: str, ctx: RequestContext) -> ArgoApplication:
        self._authz.require(user, Permission.APP_VIEW, ctx, target=f"application:{name}")
        return self.adapter.get_application(name)

    def sync(
        self, user: User, name: str, ctx: RequestContext, *,
        revision: Optional[str] = None, dry_run: bool = False,
    ) -> SyncResult:
        app = self.get_application(user, name, ctx)
        permission = required_sync_permission(app)
        self._authz.require(user, permission, ctx, target=f"application:{name}")
        profile = self._authz.profile(user)
        details = {
            "project": app.project,
            "environment": app.environment,
            "permission": permission.value,
            "effective_role": profile.effective_role.value,
            "elevated": profile.is_elevated,
            "dry_run": dry_run,
        }
        if profile.grant is not None:
            details["privilege_request"] = profile.grant.id
        try:
            result = self.adapter.sync_application(
                name, initiated_by=user.username, revision=revision, dry_run=dry_run
            )
        except ArgoCDError as e:
            details["error"] = str(e)
            self._audit.record(
                EventType.ARGOCD_SYNC, Outcome.FAILURE, actor=user,
                target=f"application:{name}", ctx=ctx, details=details,
            )
            raise
        details.update(revision=result.revision, phase=result.phase)
        self._audit.record(
            EventType.ARGOCD_SYNC, actor=user, target=f"application:{name}", ctx=ctx,
            details=details,
        )
        return result

    def refresh(self, user: User, name: str, ctx: RequestContext) -> ArgoApplication:
        self._authz.require(user, Permission.APP_REFRESH, ctx, target=f"application:{name}")
        app = self.adapter.refresh_application(name)
        self._audit.record(
            EventType.ARGOCD_REFRESH, actor=user, target=f"application:{name}", ctx=ctx
        )
        return app

    def list_projects(self, user: User, ctx: RequestContext) -> List[ArgoProject]:
        self._authz.require(user, Permission.PROJECT_VIEW, ctx, target="projects")
        return self.adapter.list_projects()

    def update_project_source_repos(
        self, user: User, name: str, source_repos: List[str], ctx: RequestContext
    ) -> ArgoProject:
        self._authz.require(user, Permission.PROJECT_UPDATE, ctx, target=f"project:{name}")
        repos = [r.strip() for r in source_repos if r.strip()]
        if not repos:
            raise ValidationError("A project needs at least one source repository.")
        for repo in repos:
            if repo != "*" and not repo.startswith(("https://", "git@", "ssh://", "oci://")):
                raise ValidationError(f"'{repo}' is not a repository URL.")
        project = self.adapter.update_project_source_repos(name, repos)
        self._audit.record(
            EventType.ARGOCD_PROJECT_UPDATE, actor=user, target=f"project:{name}", ctx=ctx,
            details={"source_repos": repos},
        )
        return project
