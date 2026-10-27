"""Request-level security for the web and API layers.

* resolves the caller's session (cookie for the UI, bearer token for the API);
* sweeps expired privilege grants;
* CSRF protection for HTML form posts;
* ``login_required`` / ``permission_required`` view decorators;
* hardening response headers.
"""

from __future__ import annotations

import hmac
import secrets
from functools import wraps
from typing import Optional

from flask import Flask, abort, current_app, g, jsonify, redirect, request, session, url_for

from argo_iam.authorization.permissions import Permission
from argo_iam.common import RequestContext
from argo_iam.container import Container

CHALLENGE_KEY = "mfa_challenge"


def container() -> Container:
    return current_app.extensions["argo_iam"]


def is_api_request() -> bool:
    return request.path.startswith("/api/")


def request_context() -> RequestContext:
    return RequestContext(
        ip=request.remote_addr or "-",
        user_agent=(request.headers.get("User-Agent") or "-")[:200],
        channel="api" if is_api_request() else "web",
    )


def _bearer_token() -> Optional[str]:
    header = request.headers.get("Authorization", "")
    if header.lower().startswith("bearer "):
        return header[7:].strip() or None
    return None


def load_identity() -> None:
    c = container()
    c.privileges.expire_due()
    g.user = g.session = g.access = None
    token = _bearer_token() if is_api_request() else request.cookies.get(
        c.settings.session_cookie_name
    )
    s = c.sessions.resolve(token)
    if s is None:
        return
    user = c.users_repo.get(s.user_id)
    if user is None or not user.is_active:
        return
    g.user, g.session = user, s
    g.access = c.authorization.profile(user)


def csrf_token() -> str:
    token = session.get("csrf")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf"] = token
    return token


def rotate_csrf_token() -> None:
    session["csrf"] = secrets.token_urlsafe(32)


def verify_csrf() -> None:
    if request.method != "POST" or is_api_request():
        return
    expected = session.get("csrf")
    submitted = request.form.get("csrf_token", "")
    if not expected or not hmac.compare_digest(expected, submitted):
        abort(400, description="The form expired. Reload the page and try again.")


def set_security_headers(response):
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
        "frame-ancestors 'none'; form-action 'self'; base-uri 'none'",
    )
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    if getattr(g, "user", None) is not None or request.endpoint in (
        "auth.mfa", "auth.enroll",
    ):
        response.headers["Cache-Control"] = "no-store"
    return response


def safe_next(target: Optional[str]) -> Optional[str]:
    """Only allow local absolute paths as post-login redirects."""
    if (
        target
        and target.startswith("/")
        and not target.startswith("//")
        and "\\" not in target
        and not any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in target)
    ):
        return target
    return None


def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if g.user is None:
            if is_api_request():
                return jsonify(error="authentication_required",
                               message="A valid session token is required."), 401
            return redirect(url_for("auth.login", next=request.path))
        return view(*args, **kwargs)

    return wrapper


def permission_required(permission: Permission):
    def decorator(view):
        @wraps(view)
        @login_required
        def wrapper(*args, **kwargs):
            container().authorization.require(
                g.user, permission, request_context(), target=request.path
            )
            return view(*args, **kwargs)

        return wrapper

    return decorator


def install(app: Flask) -> None:
    app.before_request(load_identity)
    app.before_request(verify_csrf)
    app.after_request(set_security_headers)
    app.jinja_env.globals["csrf_token"] = csrf_token
