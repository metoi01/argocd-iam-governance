"""The port the IAM layer uses to reach Argo CD (Adapter pattern).

The rest of the system depends only on this interface and on the plain data
classes below, never on Argo CD's wire format. ``MockArgoCDAdapter`` and
``ArgoCDHttpAdapter`` are interchangeable implementations.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional

PRODUCTION = "production"


class ArgoCDError(Exception):
    """Argo CD could not be reached or rejected the operation."""


class ApplicationNotFound(ArgoCDError):
    pass


@dataclass
class ArgoApplication:
    name: str
    project: str
    environment: str
    repo_url: str
    path: str
    target_revision: str
    destination_server: str
    destination_namespace: str
    sync_status: str  # Synced | OutOfSync | Unknown
    health_status: str  # Healthy | Progressing | Degraded | Missing | Unknown
    revision: str = ""
    last_synced_at: Optional[datetime] = None
    last_synced_by: Optional[str] = None

    @property
    def is_production(self) -> bool:
        return self.environment == PRODUCTION


@dataclass
class ArgoProject:
    name: str
    description: str
    source_repos: List[str] = field(default_factory=list)
    destinations: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class SyncResult:
    application: str
    revision: str
    phase: str  # Succeeded | Running | Failed
    message: str
    dry_run: bool = False


class ArgoCDAdapter(ABC):
    @abstractmethod
    def list_applications(self) -> List[ArgoApplication]: ...

    @abstractmethod
    def get_application(self, name: str) -> ArgoApplication: ...

    @abstractmethod
    def sync_application(
        self, name: str, *, initiated_by: str, revision: Optional[str] = None,
        dry_run: bool = False,
    ) -> SyncResult: ...

    @abstractmethod
    def refresh_application(self, name: str) -> ArgoApplication: ...

    @abstractmethod
    def list_projects(self) -> List[ArgoProject]: ...

    @abstractmethod
    def update_project_source_repos(self, name: str, source_repos: List[str]) -> ArgoProject: ...

    def describe(self) -> str:
        return self.__class__.__name__


def infer_environment(name: str, labels: Optional[dict] = None) -> str:
    """Environment from an ``environment`` label, else from the name suffix."""
    labels = labels or {}
    if labels.get("environment"):
        return str(labels["environment"])
    lowered = name.lower()
    if lowered.endswith(("-prod", "-production")):
        return PRODUCTION
    if lowered.endswith(("-stage", "-staging")):
        return "staging"
    if lowered.endswith("-dev"):
        return "development"
    return "unknown"
