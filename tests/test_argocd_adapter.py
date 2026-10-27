import json

import pytest

from argo_iam.argocd_adapter.base import ApplicationNotFound, ArgoCDError, infer_environment
from argo_iam.argocd_adapter.http import ArgoCDHttpAdapter
from argo_iam.argocd_adapter.mock import MockArgoCDAdapter
from argo_iam.argocd_adapter.policy import policy_rules, render_policy_csv
from argo_iam.audit.models import AuditQuery, EventType, Outcome
from argo_iam.common import PermissionDenied, ValidationError
from argo_iam.users.models import Role

from conftest import CTX

# -- mock adapter ---------------------------------------------------------------------


def test_mock_adapter_sync_updates_state(clock):
    adapter = MockArgoCDAdapter(clock)
    assert adapter.get_application("guestbook-staging").sync_status == "OutOfSync"
    result = adapter.sync_application("guestbook-staging", initiated_by="oscar")
    app = adapter.get_application("guestbook-staging")
    assert result.phase == "Succeeded" and app.sync_status == "Synced"
    assert app.last_synced_by == "oscar" and app.revision == result.revision


def test_mock_adapter_dry_run_changes_nothing(clock):
    adapter = MockArgoCDAdapter(clock)
    adapter.sync_application("guestbook-staging", initiated_by="x", dry_run=True)
    assert adapter.get_application("guestbook-staging").sync_status == "OutOfSync"


def test_mock_adapter_unknown_application(clock):
    with pytest.raises(ApplicationNotFound):
        MockArgoCDAdapter(clock).get_application("nope")


def test_environment_inference():
    assert infer_environment("api-prod") == "production"
    assert infer_environment("api", {"environment": "qa"}) == "qa"
    assert infer_environment("api-staging") == "staging"
    assert infer_environment("api") == "unknown"


# -- governed access -------------------------------------------------------------------


def test_viewer_can_list_but_not_sync(c, user):
    assert c.argocd.list_applications(user("vera"), CTX)
    with pytest.raises(PermissionDenied):
        c.argocd.sync(user("vera"), "guestbook-dev", CTX)


def test_operator_syncs_non_production_only(c, user):
    result = c.argocd.sync(user("oscar"), "guestbook-staging", CTX)
    assert result.phase == "Succeeded"
    with pytest.raises(PermissionDenied):
        c.argocd.sync(user("oscar"), "guestbook-prod", CTX)
    denied = c.audit.query(AuditQuery(event_type=EventType.ACCESS_DENIED.value))[0]
    assert denied.target == "application:guestbook-prod"
    assert denied.details["permission"] == "applications:sync:production"


def test_elevated_operator_syncs_production_and_audit_links_grant(c, user):
    oscar = user("oscar")
    req = c.privileges.request(oscar, Role.ADMIN, "Ship fix for INC-1042 to production", 30, CTX)
    c.privileges.approve(user("alice"), req.id, "", CTX)
    c.argocd.sync(oscar, "guestbook-prod", CTX)
    event = c.audit.query(AuditQuery(event_type=EventType.ARGOCD_SYNC.value))[0]
    assert event.details["elevated"] is True
    assert event.details["privilege_request"] == req.id
    assert c.argocd.adapter.get_application("guestbook-prod").last_synced_by == "oscar"
    c.clock.advance(minutes=31)
    with pytest.raises(PermissionDenied):
        c.argocd.sync(oscar, "guestbook-prod", CTX)


def test_adapter_failure_is_audited(c, user):
    c.argocd.adapter._apps["guestbook-dev"].health_status = "Missing"
    with pytest.raises(ArgoCDError):
        c.argocd.sync(user("oscar"), "guestbook-dev", CTX)
    event = c.audit.query(AuditQuery(event_type=EventType.ARGOCD_SYNC.value))[0]
    assert event.outcome is Outcome.FAILURE and "error" in event.details


def test_project_update_requires_admin_and_validates(c, user):
    with pytest.raises(PermissionDenied):
        c.argocd.update_project_source_repos(user("oscar"), "guestbook", ["https://x/y.git"], CTX)
    with pytest.raises(ValidationError):
        c.argocd.update_project_source_repos(user("alice"), "guestbook", ["ftp://bad"], CTX)
    p = c.argocd.update_project_source_repos(
        user("alice"), "guestbook", ["https://github.com/example-org/guestbook-deploy.git",
                                     "https://github.com/example-org/shared.git"], CTX)
    assert len(p.source_repos) == 2


# -- HTTP adapter against a fake Argo CD -------------------------------------------------


APP_JSON = {
    "metadata": {"name": "web-prod", "labels": {}},
    "spec": {"project": "web", "source": {"repoURL": "https://git/x.git", "path": "k8s",
                                          "targetRevision": "main"},
             "destination": {"server": "https://k8s", "namespace": "web"}},
    "status": {"sync": {"status": "OutOfSync", "revision": "abcdef123456"},
               "health": {"status": "Healthy"},
               "operationState": {"finishedAt": "2026-01-01T10:00:00Z",
                                  "operation": {"initiatedBy": {"username": "admin"}}}},
}


class FakeArgo:
    def __init__(self):
        self.calls = []

    def __call__(self, method, url, headers, body):
        self.calls.append((method, url, headers, json.loads(body) if body else None))
        if headers.get("Authorization") != "Bearer svc-token":
            return 401, {"message": "unauthorized"}
        if url.endswith("/api/v1/applications"):
            return 200, {"items": [APP_JSON]}
        if "/api/v1/applications/web-prod/sync" in url:
            return 200, {"status": {"operationState": {"phase": "Running", "message": "ok",
                                                       "syncResult": {"revision": "fedcba987"}}}}
        if "/api/v1/applications/web-prod" in url:
            return 200, APP_JSON
        if "/api/v1/projects/web" in url and method == "GET":
            return 200, {"metadata": {"name": "web"}, "spec": {"sourceRepos": ["a"]}}
        if "/api/v1/projects/web" in url and method == "PUT":
            sent = json.loads(body)["project"]
            return 200, sent
        return 404, {"message": "not found"}


def test_http_adapter_maps_argocd_json():
    fake = FakeArgo()
    adapter = ArgoCDHttpAdapter("https://argocd.example.com/", "svc-token", transport=fake)
    [app] = adapter.list_applications()
    assert (app.name, app.environment, app.sync_status, app.revision) == \
        ("web-prod", "production", "OutOfSync", "abcdef1")
    assert app.last_synced_by == "admin" and app.destination_namespace == "web"
    assert fake.calls[0][1] == "https://argocd.example.com/api/v1/applications"


def test_http_adapter_sync_and_project_update():
    fake = FakeArgo()
    adapter = ArgoCDHttpAdapter("https://argocd", "svc-token", transport=fake)
    result = adapter.sync_application("web-prod", initiated_by="oscar", dry_run=True)
    assert result.phase == "Running" and result.revision == "fedcba9"
    method, _, _, body = fake.calls[-1]
    assert method == "POST" and body["dryRun"] is True and body["prune"] is False
    project = adapter.update_project_source_repos("web", ["https://git/a.git"])
    assert project.source_repos == ["https://git/a.git"]


def test_http_adapter_errors():
    adapter = ArgoCDHttpAdapter("https://argocd", "wrong", transport=FakeArgo())
    with pytest.raises(ArgoCDError):
        adapter.list_applications()
    adapter = ArgoCDHttpAdapter("https://argocd", "svc-token", transport=FakeArgo())
    with pytest.raises(ApplicationNotFound):
        adapter.get_application("missing")
    with pytest.raises(ValueError):
        ArgoCDHttpAdapter("", "t")


# -- RBAC translation ---------------------------------------------------------------------


def test_policy_translation():
    operator = policy_rules(Role.OPERATOR)
    assert ("applications", "sync", "*/*", "allow") in operator
    assert ("applications", "sync", "*/*-prod", "deny") in operator
    assert ("applications", "sync", "*/*-prod", "allow") in policy_rules(Role.ADMIN)
    assert all(action == "get" for _, action, _, _ in policy_rules(Role.VIEWER))
    csv = render_policy_csv()
    assert "p, role:iam-admin, projects, update, *, allow" in csv
    assert "g, argo-iam-operators, role:iam-operator" in csv
