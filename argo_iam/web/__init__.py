"""Web layer: login interface, user dashboard, admin dashboard and JSON API."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from flask import Flask, g, jsonify, render_template
from werkzeug.exceptions import HTTPException

from argo_iam.argocd_adapter.base import ApplicationNotFound, ArgoCDError
from argo_iam.authorization.permissions import Permission
from argo_iam.common import IAMError
from argo_iam.container import Container, build_container
from argo_iam.web import admin_views, api, app_views, auth_views, security


def _fmt_dt(value: Optional[datetime]) -> str:
    if value is None:
        return "—"
    return value.strftime("%Y-%m-%d %H:%M:%S UTC")


def _fmt_remaining(seconds: int) -> str:
    seconds = max(0, int(seconds))
    hours, rest = divmod(seconds, 3600)
    minutes, secs = divmod(rest, 60)
    return f"{hours}h {minutes:02d}m" if hours else f"{minutes}m {secs:02d}s"


def create_app(container: Optional[Container] = None) -> Flask:
    c = container or build_container()
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=c.settings.secret_key,
        SESSION_COOKIE_NAME="argo_iam_flow",
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=c.settings.cookie_secure,
        MAX_CONTENT_LENGTH=64 * 1024,
    )
    app.extensions["argo_iam"] = c

    security.install(app)
    for blueprint in (auth_views.bp, app_views.bp, admin_views.bp, api.bp):
        app.register_blueprint(blueprint)

    app.jinja_env.filters["dt"] = _fmt_dt
    app.jinja_env.filters["remaining"] = _fmt_remaining

    @app.context_processor
    def inject_globals():
        user = getattr(g, "user", None)
        access = getattr(g, "access", None)
        ctx = {"current_user": user, "access": access, "now": c.clock.now()}
        if user is not None and access is not None:
            ctx["pending_count"] = (
                len(c.privileges.list_pending())
                if Permission.PRIVILEGE_APPROVE in access.permissions else 0
            )
            ctx["P"] = Permission
        return ctx

    def _error(status: int, message: str, code: str):
        if security.is_api_request():
            return jsonify(error=code, message=message), status
        return render_template("error.html", status=status, message=message), status

    @app.errorhandler(IAMError)
    def handle_iam_error(e: IAMError):
        return _error(e.status_code, e.message, e.__class__.__name__)

    @app.errorhandler(ApplicationNotFound)
    def handle_app_not_found(e):
        return _error(404, str(e), "not_found")

    @app.errorhandler(ArgoCDError)
    def handle_argocd_error(e):
        return _error(502, f"Argo CD error: {e}", "argocd_error")

    @app.errorhandler(HTTPException)
    def handle_http_error(e: HTTPException):
        return _error(e.code or 500, e.description or e.name, e.name.lower().replace(" ", "_"))

    @app.route("/healthz")
    def healthz():
        return jsonify(status="ok", argocd=c.argocd.adapter.describe())

    return app
