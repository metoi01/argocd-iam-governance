"""Architecture conformance tests: the module rules in docs/ARCHITECTURE.md.

They parse imports statically, so a violation fails the build rather than
silently eroding the layering.
"""

import ast
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent / "argo_iam"
DOMAIN_MODULES = ["auth", "users", "sessions", "authorization", "privilege", "audit"]


def imports_of(package: str):
    found = set()
    for path in (ROOT / package).rglob("*.py"):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                found.update((path.name, a.name) for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                found.add((path.name, node.module))
    return found


@pytest.mark.parametrize("package", DOMAIN_MODULES + ["argocd_adapter"])
def test_service_modules_do_not_depend_on_the_web_layer(package):
    for filename, module in imports_of(package):
        assert not module.startswith(("flask", "werkzeug", "argo_iam.web")), (filename, module)


@pytest.mark.parametrize("package", DOMAIN_MODULES)
def test_domain_modules_do_not_touch_argocd(package):
    for filename, module in imports_of(package):
        assert not module.startswith("argo_iam.argocd_adapter"), (filename, module)


@pytest.mark.parametrize("package", DOMAIN_MODULES)
def test_only_repositories_use_the_database(package):
    for filename, module in imports_of(package):
        if module in ("argo_iam.db", "sqlite3"):
            assert filename == "repository.py", (package, filename, module)


def test_only_the_http_adapter_does_network_io():
    for path in ROOT.rglob("*.py"):
        text = path.read_text()
        if "urllib.request" in text or "import requests" in text:
            assert path.name == "http.py", path


def test_web_reaches_argocd_only_through_governed_facade():
    for filename, module in imports_of("web"):
        if module.startswith("argo_iam.argocd_adapter"):
            assert module in {
                "argo_iam.argocd_adapter.base",
                "argo_iam.argocd_adapter.governed",
                "argo_iam.argocd_adapter.policy",
            }, (filename, module)
    source = "".join(p.read_text() for p in (ROOT / "web").rglob("*.py"))
    assert ".adapter.sync_application" not in source
