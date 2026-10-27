"""In-memory stand-in for an Argo CD API server, used for demos and tests."""

from __future__ import annotations

import copy
import hashlib
import threading
from typing import Dict, List, Optional

from argo_iam.argocd_adapter.base import (
    ApplicationNotFound,
    ArgoApplication,
    ArgoCDAdapter,
    ArgoCDError,
    ArgoProject,
    SyncResult,
)
from argo_iam.clock import Clock, SystemClock

_IN_CLUSTER = "https://kubernetes.default.svc"
_PROD_CLUSTER = "https://prod-eu-1.k8s.example.com"


def _seed_applications() -> List[ArgoApplication]:
    def app(name, project, env, path, server, ns, sync, health, rev):
        return ArgoApplication(
            name=name, project=project, environment=env,
            repo_url=f"https://github.com/example-org/{project}-deploy.git",
            path=path, target_revision="HEAD", destination_server=server,
            destination_namespace=ns, sync_status=sync, health_status=health,
            revision=rev,
        )

    return [
        app("guestbook-dev", "guestbook", "development", "overlays/dev", _IN_CLUSTER,
            "guestbook-dev", "Synced", "Healthy", "4f2c1a9"),
        app("guestbook-staging", "guestbook", "staging", "overlays/staging", _IN_CLUSTER,
            "guestbook-staging", "OutOfSync", "Healthy", "4f2c1a9"),
        app("guestbook-prod", "guestbook", "production", "overlays/prod", _PROD_CLUSTER,
            "guestbook", "OutOfSync", "Healthy", "1b7e3d0"),
        app("payments-api-dev", "payments", "development", "k8s/dev", _IN_CLUSTER,
            "payments-dev", "OutOfSync", "Progressing", "9ac44e2"),
        app("payments-api-prod", "payments", "production", "k8s/prod", _PROD_CLUSTER,
            "payments", "Synced", "Healthy", "77d0b15"),
        app("monitoring-stack-prod", "platform", "production", "monitoring", _PROD_CLUSTER,
            "monitoring", "OutOfSync", "Degraded", "c03f8e1"),
    ]


def _seed_projects() -> List[ArgoProject]:
    return [
        ArgoProject("guestbook", "Sample guestbook web application",
                    ["https://github.com/example-org/guestbook-deploy.git"],
                    [f"{_IN_CLUSTER}/guestbook-*", f"{_PROD_CLUSTER}/guestbook"]),
        ArgoProject("payments", "Payment processing services",
                    ["https://github.com/example-org/payments-deploy.git"],
                    [f"{_IN_CLUSTER}/payments-*", f"{_PROD_CLUSTER}/payments"]),
        ArgoProject("platform", "Shared platform services (monitoring, ingress)",
                    ["https://github.com/example-org/platform-deploy.git"],
                    [f"{_PROD_CLUSTER}/*"]),
    ]


class MockArgoCDAdapter(ArgoCDAdapter):
    def __init__(self, clock: Optional[Clock] = None):
        self._clock = clock or SystemClock()
        self._lock = threading.Lock()
        self._apps: Dict[str, ArgoApplication] = {a.name: a for a in _seed_applications()}
        self._projects: Dict[str, ArgoProject] = {p.name: p for p in _seed_projects()}
        self.sync_history: List[SyncResult] = []

    def describe(self) -> str:
        return "Mock Argo CD (in-memory)"

    def list_applications(self) -> List[ArgoApplication]:
        with self._lock:
            return [copy.copy(a) for a in sorted(self._apps.values(), key=lambda a: a.name)]

    def get_application(self, name: str) -> ArgoApplication:
        with self._lock:
            return copy.copy(self._get(name))

    def sync_application(
        self, name: str, *, initiated_by: str, revision: Optional[str] = None,
        dry_run: bool = False,
    ) -> SyncResult:
        with self._lock:
            app = self._get(name)
            if app.health_status == "Missing":
                raise ArgoCDError(f"Application '{name}' has missing resources.")
            now = self._clock.now()
            new_rev = revision or hashlib.sha1(
                f"{name}{now.isoformat()}".encode()
            ).hexdigest()[:7]
            if not dry_run:
                app.revision = new_rev
                app.sync_status = "Synced"
                app.health_status = "Healthy"
                app.last_synced_at = now
                app.last_synced_by = initiated_by
            result = SyncResult(
                application=name, revision=new_rev, phase="Succeeded",
                message="dry run: no changes applied" if dry_run else "successfully synced",
                dry_run=dry_run,
            )
            self.sync_history.append(result)
            return result

    def refresh_application(self, name: str) -> ArgoApplication:
        with self._lock:
            return copy.copy(self._get(name))

    def list_projects(self) -> List[ArgoProject]:
        with self._lock:
            return [copy.deepcopy(p) for p in sorted(self._projects.values(), key=lambda p: p.name)]

    def update_project_source_repos(self, name: str, source_repos: List[str]) -> ArgoProject:
        with self._lock:
            project = self._projects.get(name)
            if project is None:
                raise ArgoCDError(f"Project '{name}' not found.")
            project.source_repos = list(source_repos)
            return copy.deepcopy(project)

    def _get(self, name: str) -> ArgoApplication:
        app = self._apps.get(name)
        if app is None:
            raise ApplicationNotFound(f"Application '{name}' not found.")
        return app
