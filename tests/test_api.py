import pytest

from argo_iam.seed import DEMO_PASSWORD


@pytest.fixture
def api_login(app, c, user):
    def _login(name):
        client = app.test_client()
        r = client.post("/api/v1/auth/login", json={"username": name, "password": DEMO_PASSWORD})
        assert r.status_code == 200, r.json
        c.clock.advance(seconds=30)
        r = client.post("/api/v1/auth/mfa", json={
            "challenge_token": r.json["challenge_token"],
            "code": c.auth.current_code(user(name))})
        assert r.status_code == 200, r.json
        return client, {"Authorization": f"Bearer {r.json['session_token']}"}

    return _login


def test_api_requires_bearer_token(app):
    r = app.test_client().get("/api/v1/me")
    assert r.status_code == 401 and r.json["error"] == "authentication_required"


def test_api_login_errors(app):
    client = app.test_client()
    assert client.post("/api/v1/auth/login", json={"username": "oscar",
                                                   "password": "x"}).status_code == 401
    r = client.post("/api/v1/auth/login", json={"username": "nina", "password": DEMO_PASSWORD})
    assert r.status_code == 403 and r.json["status"] == "mfa_enrollment_required"
    r = client.post("/api/v1/auth/mfa", json={"challenge_token": "bogus", "code": "123456"})
    assert r.status_code == 401
    assert client.post("/api/v1/auth/login", data="not json").status_code == 400


def test_api_me_and_applications(api_login):
    client, auth = api_login("oscar")
    me = client.get("/api/v1/me", headers=auth).json
    assert me["effective_role"] == "operator" and "applications:sync" in me["permissions"]
    apps = client.get("/api/v1/applications", headers=auth).json["items"]
    assert {a["name"] for a in apps} >= {"guestbook-dev", "guestbook-prod"}


def test_api_jit_flow(api_login, c):
    oscar, oscar_auth = api_login("oscar")
    r = oscar.post("/api/v1/applications/guestbook-prod/sync", headers=oscar_auth, json={})
    assert r.status_code == 403
    r = oscar.post("/api/v1/privilege-requests", headers=oscar_auth, json={
        "role": "admin", "duration_minutes": 30,
        "justification": "Pipeline needs to ship hotfix for INC-7"})
    assert r.status_code == 201
    request_id = r.json["id"]

    alice, alice_auth = api_login("alice")
    pending = alice.get("/api/v1/privilege-requests?status=pending", headers=alice_auth).json
    assert [p["id"] for p in pending["items"]] == [request_id]
    assert oscar.get("/api/v1/privilege-requests?status=pending",
                     headers=oscar_auth).status_code == 403
    r = alice.post(f"/api/v1/privilege-requests/{request_id}/approve", headers=alice_auth,
                   json={"note": "ok"})
    assert r.json["status"] == "active"

    r = oscar.post("/api/v1/applications/guestbook-prod/sync", headers=oscar_auth,
                   json={"dry_run": True})
    assert r.status_code == 200 and r.json["dry_run"] is True
    assert oscar.get("/api/v1/me", headers=oscar_auth).json["elevation"]["id"] == request_id


def test_api_audit_for_admins_only(api_login):
    oscar, oscar_auth = api_login("oscar")
    assert oscar.get("/api/v1/audit", headers=oscar_auth).status_code == 403
    alice, alice_auth = api_login("alice")
    body = alice.get("/api/v1/audit?type=auth", headers=alice_auth).json
    assert body["chain"]["valid"] and body["items"]
    assert all(i["type"].startswith("auth.") for i in body["items"])


def test_api_logout_invalidates_token(api_login):
    client, auth = api_login("vera")
    assert client.post("/api/v1/auth/logout", headers=auth).status_code == 200
    assert client.get("/api/v1/me", headers=auth).status_code == 401


def test_api_validation_errors(api_login):
    client, auth = api_login("oscar")
    r = client.post("/api/v1/privilege-requests", headers=auth,
                    json={"role": "superuser", "duration_minutes": 30})
    assert r.status_code == 400
    r = client.post("/api/v1/applications/does-not-exist/sync", headers=auth, json={})
    assert r.status_code == 404
