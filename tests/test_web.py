from argo_iam.seed import DEMO_PASSWORD

from conftest import csrf_from


def test_pages_require_login(app):
    client = app.test_client()
    for path in ["/applications", "/access", "/admin/", "/admin/audit"]:
        r = client.get(path)
        assert r.status_code == 302 and "/login" in r.location


def test_login_page_and_security_headers(app):
    r = app.test_client().get("/login")
    assert r.status_code == 200
    assert "default-src 'self'" in r.headers["Content-Security-Policy"]
    assert r.headers["X-Frame-Options"] == "DENY"


def test_post_without_csrf_token_is_rejected(app):
    r = app.test_client().post("/login", data={"username": "oscar", "password": DEMO_PASSWORD})
    assert r.status_code == 400


def test_wrong_password_shows_generic_error(app):
    client = app.test_client()
    token = csrf_from(client.get("/login").get_data(as_text=True))
    r = client.post("/login", data={"username": "oscar", "password": "bad", "csrf_token": token})
    assert r.status_code == 401 and "Invalid username or password" in r.get_data(as_text=True)


def test_mfa_page_without_challenge_redirects(app):
    r = app.test_client().get("/login/mfa")
    assert r.status_code == 302 and r.location.endswith("/login")


def test_full_login_sets_hardened_cookie(app, c, user):
    client = app.test_client()
    token = csrf_from(client.get("/login").get_data(as_text=True))
    client.post("/login", data={"username": "oscar", "password": DEMO_PASSWORD,
                                "csrf_token": token})
    r = client.post("/login/mfa", data={"code": c.auth.current_code(user("oscar")),
                                        "csrf_token": token})
    cookie = r.headers["Set-Cookie"]
    assert c.settings.session_cookie_name in cookie
    assert "HttpOnly" in cookie and "SameSite=Lax" in cookie


def test_operator_dashboard_and_forbidden_admin(web_login):
    client, _ = web_login("oscar")
    page = client.get("/applications").get_data(as_text=True)
    assert "guestbook-prod" in page and "Admin only" in page
    assert client.get("/admin/users").status_code == 403


def test_production_sync_denied_for_operator_via_web(web_login):
    client, csrf = web_login("oscar")
    r = client.post("/applications/guestbook-prod/sync", data={"csrf_token": csrf})
    assert r.status_code == 403


def test_jit_flow_through_the_web_ui(web_login, c):
    oscar, oscar_csrf = web_login("oscar")
    r = oscar.post("/access/requests", data={
        "csrf_token": oscar_csrf, "role": "admin", "duration": "30",
        "justification": "Deploy hotfix for INC-1042 to guestbook-prod"})
    assert r.status_code == 302
    [pending] = c.privileges.list_pending()

    alice, alice_csrf = web_login("alice")
    assert "INC-1042" in alice.get("/admin/privileges").get_data(as_text=True)
    r = alice.post(f"/admin/privileges/{pending.id}/approve",
                   data={"csrf_token": alice_csrf, "note": "approved"})
    assert r.status_code == 302

    page = oscar.get("/applications").get_data(as_text=True)
    assert "(temporary)" in page
    r = oscar.post("/applications/guestbook-prod/sync", data={"csrf_token": oscar_csrf})
    assert r.status_code == 302
    assert c.argocd.adapter.get_application("guestbook-prod").sync_status == "Synced"

    # Keep the session alive (idle timeout is 30 min) while the 30 min grant runs out.
    c.clock.advance(minutes=20)
    assert oscar.get("/access").status_code == 200
    c.clock.advance(minutes=11)
    r = oscar.post("/applications/payments-api-prod/sync", data={"csrf_token": oscar_csrf})
    assert r.status_code == 403
    assert "(temporary)" not in oscar.get("/applications").get_data(as_text=True)


def test_idle_session_redirects_to_login(web_login, c):
    client, _ = web_login("vera")
    c.clock.advance(minutes=31)
    r = client.get("/applications")
    assert r.status_code == 302 and "/login" in r.location


def test_admin_pages_render(web_login):
    client, _ = web_login("alice")
    for path in ["/admin/", "/admin/users", "/admin/privileges", "/admin/sessions",
                 "/admin/audit", "/admin/audit?type=auth&outcome=success",
                 "/admin/argocd-policy", "/projects", "/account/sessions", "/access"]:
        assert client.get(path).status_code == 200, path
    r = client.get("/admin/audit.csv")
    assert r.mimetype == "text/csv" and "auth.login.succeeded" in r.get_data(as_text=True)


def test_admin_user_management_via_web(web_login, c, user):
    client, csrf = web_login("alice")
    r = client.post("/admin/users", data={
        "csrf_token": csrf, "username": "dana", "display_name": "Dana", "email": "d@example.com",
        "password": "Very-Strong-Pass1", "role": "viewer"})
    assert r.status_code == 302 and user("dana") is not None
    client.post(f"/admin/users/{user('dana').id}/role", data={"csrf_token": csrf,
                                                              "role": "operator"})
    assert user("dana").role.value == "operator"
    client.post(f"/admin/users/{user('dana').id}/status", data={"csrf_token": csrf,
                                                                "status": "disabled"})
    assert not user("dana").is_active


def test_revoked_session_is_logged_out(web_login, c, user):
    oscar, _ = web_login("oscar")
    alice, csrf = web_login("alice")
    [s] = c.sessions.list_for_user(user("oscar").id)
    alice.post(f"/admin/sessions/{s.id}/revoke", data={"csrf_token": csrf})
    r = oscar.get("/applications")
    assert r.status_code == 302 and "/login" in r.location


def test_logout(web_login):
    client, csrf = web_login("vera")
    client.post("/logout", data={"csrf_token": csrf})
    assert client.get("/applications").status_code == 302


def test_enrolment_page_shows_qr_code(app):
    client = app.test_client()
    token = csrf_from(client.get("/login").get_data(as_text=True))
    r = client.post("/login", data={"username": "nina", "password": DEMO_PASSWORD,
                                    "csrf_token": token})
    assert r.location.endswith("/login/mfa/enroll")
    page = client.get("/login/mfa/enroll").get_data(as_text=True)
    assert "<svg" in page and "Set up your authenticator" in page


def test_open_redirect_is_blocked(app, c, user):
    client = app.test_client()
    client.get("/login?next=//evil.example.com")
    token = csrf_from(client.get("/login").get_data(as_text=True))
    client.post("/login", data={"username": "vera", "password": DEMO_PASSWORD,
                                "csrf_token": token})
    r = client.post("/login/mfa", data={"code": c.auth.current_code(user("vera")),
                                        "csrf_token": token})
    assert "evil" not in r.location
