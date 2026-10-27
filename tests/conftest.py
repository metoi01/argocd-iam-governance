from __future__ import annotations

import re

import pytest

from argo_iam.auth.passwords import PasswordHasher
from argo_iam.clock import ManualClock
from argo_iam.common import RequestContext
from argo_iam.config import Settings
from argo_iam.container import build_container
from argo_iam.seed import DEMO_PASSWORD, seed_demo_users

CTX = RequestContext(ip="10.0.0.5", user_agent="pytest", channel="web")


@pytest.fixture
def clock():
    return ManualClock()


@pytest.fixture
def settings(tmp_path):
    return Settings(database_path=str(tmp_path / "iam.sqlite3"), secret_key="test-secret")


@pytest.fixture
def c(settings, clock):
    """A fully wired container with the demo users (fast hashing for tests)."""
    container = build_container(settings, clock, hasher=PasswordHasher(n=2**10))
    seed_demo_users(container)
    yield container
    container.db.close()


@pytest.fixture
def user(c):
    return lambda name: c.users_repo.get_by_username(name)


@pytest.fixture
def login(c, user):
    """Log a user in through the service layer; returns (session, token)."""

    def _login(name: str):
        outcome = c.auth.begin_login(name, DEMO_PASSWORD, CTX)
        assert outcome.challenge_token, outcome
        c.clock.advance(seconds=30)  # never reuse the previous TOTP step
        result = c.auth.verify_mfa(outcome.challenge_token, c.auth.current_code(user(name)), CTX)
        assert result.success, result.message
        return result.session, result.session_token

    return _login


@pytest.fixture
def app(c):
    from argo_iam.web import create_app

    application = create_app(c)
    application.config["TESTING"] = True
    return application


def csrf_from(html: str) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert match, "no CSRF token in page"
    return match.group(1)


@pytest.fixture
def web_login(app, c, user):
    """Log in through the HTML forms; returns (client, csrf_token)."""

    def _login(name: str):
        client = app.test_client()
        token = csrf_from(client.get("/login").get_data(as_text=True))
        r = client.post("/login", data={"username": name, "password": DEMO_PASSWORD,
                                         "csrf_token": token})
        assert r.status_code == 302 and r.location.endswith("/login/mfa"), r.location
        c.clock.advance(seconds=30)
        r = client.post("/login/mfa", data={"code": c.auth.current_code(user(name)),
                                            "csrf_token": token})
        assert r.status_code == 302, r.get_data(as_text=True)
        page = client.get("/applications").get_data(as_text=True)
        return client, csrf_from(page)

    return _login
