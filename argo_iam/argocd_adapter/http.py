"""Adapter for a real Argo CD API server (REST gateway of the gRPC API).

Uses an Argo CD account token (``argocd account generate-token``) as a bearer
token. Only the endpoints the IAM layer needs are wrapped:

* ``GET  /api/v1/applications``
* ``GET  /api/v1/applications/{name}`` (``?refresh=normal`` to refresh)
* ``POST /api/v1/applications/{name}/sync``
* ``GET  /api/v1/projects`` / ``GET`` + ``PUT /api/v1/projects/{name}``
"""

from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import quote

from argo_iam.argocd_adapter.base import (
    ApplicationNotFound,
    ArgoApplication,
    ArgoCDAdapter,
    ArgoCDError,
    ArgoProject,
    SyncResult,
    infer_environment,
)

# (method, url, headers, body) -> (status, parsed JSON body)
Transport = Callable[[str, str, Dict[str, str], Optional[bytes]], Tuple[int, Any]]


def _parse_time(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def application_from_json(item: Dict[str, Any]) -> ArgoApplication:
    meta = item.get("metadata", {})
    spec = item.get("spec", {})
    status = item.get("status", {})
    source = spec.get("source") or (spec.get("sources") or [{}])[0]
    destination = spec.get("destination", {})
    operation = status.get("operationState") or {}
    sync_result = operation.get("syncResult") or {}
    initiated = (operation.get("operation") or {}).get("initiatedBy") or {}
    name = meta.get("name", "")
    return ArgoApplication(
        name=name,
        project=spec.get("project", "default"),
        environment=infer_environment(name, meta.get("labels")),
        repo_url=source.get("repoURL", ""),
        path=source.get("path", source.get("chart", "")),
        target_revision=source.get("targetRevision", "HEAD"),
        destination_server=destination.get("server", destination.get("name", "")),
        destination_namespace=destination.get("namespace", ""),
        sync_status=(status.get("sync") or {}).get("status", "Unknown"),
        health_status=(status.get("health") or {}).get("status", "Unknown"),
        revision=((status.get("sync") or {}).get("revision") or sync_result.get("revision") or "")[:7],
        last_synced_at=_parse_time(operation.get("finishedAt")),
        last_synced_by=initiated.get("username"),
    )


def project_from_json(item: Dict[str, Any]) -> ArgoProject:
    spec = item.get("spec", {})
    return ArgoProject(
        name=item.get("metadata", {}).get("name", ""),
        description=spec.get("description", ""),
        source_repos=list(spec.get("sourceRepos") or []),
        destinations=[
            f"{d.get('server', d.get('name', '*'))}/{d.get('namespace', '*')}"
            for d in spec.get("destinations") or []
        ],
    )


class ArgoCDHttpAdapter(ArgoCDAdapter):
    def __init__(
        self,
        base_url: str,
        token: str,
        verify_tls: bool = True,
        timeout: float = 10.0,
        transport: Optional[Transport] = None,
    ):
        if not base_url:
            raise ValueError("ARGOCD_SERVER_URL is required for the HTTP adapter.")
        self._base = base_url.rstrip("/")
        self._token = token
        self._timeout = timeout
        self._ssl = None if verify_tls else ssl._create_unverified_context()
        self._transport = transport or self._urllib_transport

    def describe(self) -> str:
        return f"Argo CD API at {self._base}"

    # -- applications --------------------------------------------------------

    def list_applications(self) -> List[ArgoApplication]:
        body = self._call("GET", "/api/v1/applications")
        return sorted(
            (application_from_json(i) for i in (body.get("items") or [])),
            key=lambda a: a.name,
        )

    def get_application(self, name: str) -> ArgoApplication:
        return application_from_json(self._call("GET", f"/api/v1/applications/{quote(name)}"))

    def refresh_application(self, name: str) -> ArgoApplication:
        return application_from_json(
            self._call("GET", f"/api/v1/applications/{quote(name)}?refresh=normal")
        )

    def sync_application(
        self, name: str, *, initiated_by: str, revision: Optional[str] = None,
        dry_run: bool = False,
    ) -> SyncResult:
        payload: Dict[str, Any] = {"name": name, "dryRun": dry_run, "prune": False}
        if revision:
            payload["revision"] = revision
        body = self._call("POST", f"/api/v1/applications/{quote(name)}/sync", payload)
        operation = (body.get("status") or {}).get("operationState") or {}
        return SyncResult(
            application=name,
            revision=((operation.get("syncResult") or {}).get("revision") or revision or "")[:7],
            phase=operation.get("phase", "Running"),
            message=operation.get("message", "sync requested"),
            dry_run=dry_run,
        )

    # -- projects ------------------------------------------------------------

    def list_projects(self) -> List[ArgoProject]:
        body = self._call("GET", "/api/v1/projects")
        return sorted(
            (project_from_json(i) for i in (body.get("items") or [])), key=lambda p: p.name
        )

    def update_project_source_repos(self, name: str, source_repos: List[str]) -> ArgoProject:
        current = self._call("GET", f"/api/v1/projects/{quote(name)}")
        current.setdefault("spec", {})["sourceRepos"] = list(source_repos)
        updated = self._call("PUT", f"/api/v1/projects/{quote(name)}", {"project": current})
        return project_from_json(updated)

    # -- transport -----------------------------------------------------------

    def _call(self, method: str, path: str, payload: Optional[dict] = None) -> Dict[str, Any]:
        headers = {"Authorization": f"Bearer {self._token}", "Accept": "application/json"}
        data = None
        if payload is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(payload).encode("utf-8")
        status, body = self._transport(method, self._base + path, headers, data)
        if status == 404:
            raise ApplicationNotFound(f"Not found: {path}")
        if status in (401, 403):
            raise ArgoCDError("Argo CD rejected the IAM gateway's service token.")
        if status >= 400:
            message = body.get("message") if isinstance(body, dict) else None
            raise ArgoCDError(f"Argo CD returned HTTP {status}: {message or 'error'}")
        return body if isinstance(body, dict) else {}

    def _urllib_transport(
        self, method: str, url: str, headers: Dict[str, str], data: Optional[bytes]
    ) -> Tuple[int, Any]:
        request = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=self._timeout, context=self._ssl) as r:
                raw = r.read()
                return r.status, json.loads(raw) if raw else {}
        except urllib.error.HTTPError as e:
            raw = e.read()
            try:
                return e.code, json.loads(raw) if raw else {}
            except ValueError:
                return e.code, {"message": raw.decode("utf-8", "replace")[:200]}
        except (urllib.error.URLError, OSError) as e:
            raise ArgoCDError(f"Cannot reach Argo CD: {e}") from e
