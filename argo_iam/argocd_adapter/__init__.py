"""Isolates interaction with the real or simulated Argo CD API."""

from argo_iam.argocd_adapter.base import ArgoCDAdapter
from argo_iam.argocd_adapter.http import ArgoCDHttpAdapter
from argo_iam.argocd_adapter.mock import MockArgoCDAdapter


def build_adapter(settings, clock=None) -> ArgoCDAdapter:
    if settings.argocd_mode == "http":
        return ArgoCDHttpAdapter(
            settings.argocd_url, settings.argocd_token, settings.argocd_verify_tls
        )
    return MockArgoCDAdapter(clock)


__all__ = ["ArgoCDAdapter", "ArgoCDHttpAdapter", "MockArgoCDAdapter", "build_adapter"]
