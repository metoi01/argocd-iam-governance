"""User dashboard: applications, projects, own access and own sessions."""

from __future__ import annotations

from flask import Blueprint, flash, g, redirect, render_template, request, url_for

from argo_iam.argocd_adapter.base import ArgoCDError
from argo_iam.argocd_adapter.governed import required_sync_permission
from argo_iam.authorization.permissions import Permission
from argo_iam.common import IAMError
from argo_iam.users.models import Role
from argo_iam.web.security import (
    container,
    login_required,
    permission_required,
    request_context,
)

bp = Blueprint("apps", __name__)

DURATION_CHOICES = [15, 30, 60, 120, 240]


@bp.route("/")
@login_required
def index():
    return redirect(url_for("apps.applications"))


@bp.route("/applications")
@permission_required(Permission.APP_VIEW)
def applications():
    c = container()
    apps = c.argocd.list_applications(g.user, request_context())
    perms = g.access.permissions
    rows = [
        {"app": a, "can_sync": required_sync_permission(a) in perms,
         "needs": required_sync_permission(a)}
        for a in apps
    ]
    env = request.args.get("env")
    if env:
        rows = [r for r in rows if r["app"].environment == env]
    summary = {
        "total": len(apps),
        "out_of_sync": sum(1 for a in apps if a.sync_status != "Synced"),
        "degraded": sum(1 for a in apps if a.health_status not in ("Healthy",)),
    }
    return render_template(
        "apps/applications.html", rows=rows, summary=summary, env=env,
        environments=sorted({a.environment for a in apps}),
        can_refresh=Permission.APP_REFRESH in perms,
        backend=c.argocd.adapter.describe(),
    )


@bp.route("/applications/<name>/sync", methods=["POST"])
@login_required
def sync(name):
    try:
        result = container().argocd.sync(
            g.user, name, request_context(), dry_run=request.form.get("dry_run") == "1"
        )
        flash(f"{name}: {result.message} (revision {result.revision}).", "success")
    except ArgoCDError as e:
        flash(f"Argo CD error: {e}", "error")
    return redirect(url_for("apps.applications"))


@bp.route("/applications/<name>/refresh", methods=["POST"])
@login_required
def refresh(name):
    try:
        container().argocd.refresh(g.user, name, request_context())
        flash(f"{name} refreshed.", "info")
    except ArgoCDError as e:
        flash(f"Argo CD error: {e}", "error")
    return redirect(url_for("apps.applications"))


@bp.route("/projects")
@permission_required(Permission.PROJECT_VIEW)
def projects():
    c = container()
    return render_template(
        "apps/projects.html",
        projects=c.argocd.list_projects(g.user, request_context()),
        can_edit=Permission.PROJECT_UPDATE in g.access.permissions,
    )


@bp.route("/projects/<name>", methods=["POST"])
@login_required
def update_project(name):
    repos = request.form.get("source_repos", "").splitlines()
    try:
        container().argocd.update_project_source_repos(g.user, name, repos, request_context())
        flash(f"Project {name} updated.", "success")
    except ArgoCDError as e:
        flash(f"Argo CD error: {e}", "error")
    return redirect(url_for("apps.projects"))


@bp.route("/access")
@login_required
def access():
    c = container()
    requestable = [r for r in Role if r.outranks(g.user.role)]
    return render_template(
        "account/access.html",
        requests=c.privileges.list_for_user(g.user.id),
        open_request=c.privileges.open_request(g.user.id),
        requestable=requestable,
        durations=[d for d in DURATION_CHOICES if d <= c.settings.max_privilege_minutes],
        users_by_id={u.id: u for u in c.users.list_users()},
        all_permissions=list(Permission),
        min_justification=c.settings.min_justification_length,
    )


@bp.route("/access/requests", methods=["POST"])
@login_required
def request_privilege():
    try:
        role = Role(request.form.get("role", ""))
        duration = int(request.form.get("duration", "0"))
    except ValueError:
        flash("Choose a role and a duration.", "error")
        return redirect(url_for("apps.access"))
    try:
        req = container().privileges.request(
            g.user, role, request.form.get("justification", ""), duration, request_context()
        )
        flash(f"Request #{req.id} for temporary {role.label} access sent for approval.",
              "success")
    except IAMError as e:
        flash(e.message, "error")
    return redirect(url_for("apps.access"))


@bp.route("/access/requests/<int:request_id>/cancel", methods=["POST"])
@login_required
def cancel_request(request_id):
    try:
        container().privileges.cancel(g.user, request_id, request_context())
        flash(f"Request #{request_id} cancelled.", "info")
    except IAMError as e:
        flash(e.message, "error")
    return redirect(url_for("apps.access"))


@bp.route("/account/sessions")
@login_required
def my_sessions():
    c = container()
    sessions = c.sessions.list_for_user(g.user.id, include_ended=True)[:25]
    idle = int(c.settings.session_idle_timeout.total_seconds() // 60)
    return render_template("account/sessions.html", sessions=sessions, idle_minutes=idle)


@bp.route("/account/sessions/<session_id>/revoke", methods=["POST"])
@login_required
def revoke_my_session(session_id):
    container().sessions.revoke(g.user, session_id, request_context())
    if session_id == g.session.id:
        flash("This session was revoked. Please sign in again.", "info")
        return redirect(url_for("auth.login"))
    flash("Session revoked.", "success")
    return redirect(url_for("apps.my_sessions"))
