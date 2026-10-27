"""Regression tests for the end-to-end QA findings."""

import csv
import io

import pytest

from argo_iam.audit.models import EventType, Outcome
from argo_iam.seed import DEMO_PASSWORD
from argo_iam.web.security import safe_next

from conftest import CTX, csrf_from
from test_api import api_login  # noqa: F401  (fixture)


# -- B1 / B2: login redirect target ------------------------------------------------

@pytest.mark.parametrize("target", [
    "/\t/evil.com", "/\r/evil.com", "/\n/evil.com", "/\r\nSet-Cookie: x=1",
    "/a\x00b", "/a\x1fb", "/a\x7fb", "//evil.com", "/\\evil.com", "evil.com", "",
])
def test_safe_next_rejects_unsafe_targets(target):
    assert safe_next(target) is None


@pytest.mark.parametrize("target", ["/applications", "/admin/audit?type=auth", "/access"])
def test_safe_next_keeps_local_paths(target):
    assert safe_next(target) == target


def test_safe_next_none():
    assert safe_next(None) is None


@pytest.mark.parametrize("next_param", ["/%09/evil.com", "/%0d%0aX-Evil:%201", "/%0a/evil.com"])
def test_login_redirect_ignores_control_characters(app, c, user, next_param):
    client = app.test_client()
    client.get(f"/login?next={next_param}")
    token = csrf_from(client.get("/login").get_data(as_text=True))
    client.post("/login", data={"username": "vera", "password": DEMO_PASSWORD,
                                "csrf_token": token})
    r = client.post("/login/mfa", data={"code": c.auth.current_code(user("vera")),
                                        "csrf_token": token})
    assert r.status_code == 302, r.status_code
    assert r.location.endswith("/applications"), r.location


# -- B4: audit limit ------------------------------------------------------------------

@pytest.mark.parametrize("value", ["abc", "", "1.5", "0", "-1", "1001", "99999999999"])
def test_api_audit_rejects_bad_limit(api_login, value):  # noqa: F811
    client, auth = api_login("alice")
    r = client.get(f"/api/v1/audit?limit={value}", headers=auth)
    assert r.status_code == 400, r.status_code
    assert r.json["error"] and r.json["message"]


def test_api_audit_limit_valid_and_default(api_login):  # noqa: F811
    client, auth = api_login("alice")
    r = client.get("/api/v1/audit?limit=1", headers=auth)
    assert r.status_code == 200 and len(r.json["items"]) == 1
    assert client.get("/api/v1/audit?limit=1000", headers=auth).status_code == 200
    assert client.get("/api/v1/audit", headers=auth).status_code == 200


# -- B5: CSV formula injection --------------------------------------------------------

def test_audit_csv_neutralises_formulas(web_login, c, user):
    payloads = ["=1+1", "+1", "-1", "@SUM(A1)", "\tx", "\rx"]
    for p in payloads:
        c.audit.record(EventType.LOGIN_FAILED, Outcome.FAILURE, actor_username=p,
                       target=p, ctx=CTX)
    client, _ = web_login("alice")
    body = client.get("/admin/audit.csv?limit=500").get_data(as_text=True)
    rows = list(csv.DictReader(io.StringIO(body, newline="")))
    for p in payloads:
        assert any(r["target"] == "'" + p and r["actor"] == "'" + p for r in rows), p
    for r in rows:
        for cell in r.values():
            assert not cell.startswith(("=", "+", "-", "@", "\t", "\r")), cell
    # the stored events and the hash chain are untouched
    assert c.audit.verify_chain().valid
    stored = {e.target for e in c.audit.query()}
    assert set(payloads) <= stored


# -- B7: privilege request duration ---------------------------------------------------

@pytest.mark.parametrize("duration", [None, 30.5, 30.0, "30", "abc", True, False, [30]])
def test_api_privilege_request_rejects_non_integer_duration(api_login, duration):  # noqa: F811
    client, auth = api_login("oscar")
    r = client.post("/api/v1/privilege-requests", headers=auth, json={
        "role": "admin", "duration_minutes": duration,
        "justification": "Pipeline needs to ship hotfix for INC-7"})
    assert r.status_code == 400, r.status_code
    assert r.json["error"]


def test_api_privilege_request_keeps_range_message(api_login):  # noqa: F811
    client, auth = api_login("oscar")
    r = client.post("/api/v1/privilege-requests", headers=auth, json={
        "role": "admin", "duration_minutes": 5,
        "justification": "Pipeline needs to ship hotfix for INC-7"})
    assert r.status_code == 400 and "between" in r.json["message"]


# -- B8: sync dry_run -----------------------------------------------------------------

@pytest.mark.parametrize("value", ["false", "true", 0, 1, None, [], {}, "yes"])
def test_api_sync_rejects_non_boolean_dry_run(api_login, value):  # noqa: F811
    client, auth = api_login("oscar")
    r = client.post("/api/v1/applications/guestbook-dev/sync", headers=auth,
                    json={"dry_run": value})
    assert r.status_code == 400, r.status_code
    assert r.json["error"]


def test_api_sync_accepts_boolean_or_missing_dry_run(api_login):  # noqa: F811
    client, auth = api_login("oscar")
    r = client.post("/api/v1/applications/guestbook-dev/sync", headers=auth,
                    json={"dry_run": True})
    assert r.status_code == 200 and r.json["dry_run"] is True
    r = client.post("/api/v1/applications/guestbook-dev/sync", headers=auth,
                    json={"dry_run": False})
    assert r.status_code == 200 and r.json["dry_run"] is False
    r = client.post("/api/v1/applications/guestbook-dev/sync", headers=auth, json={})
    assert r.status_code == 200
