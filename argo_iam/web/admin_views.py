"""Administrative IAM dashboard."""

from __future__ import annotations

import csv
import io
import json

from flask import Blueprint, Response, flash, g, redirect, render_template, request, url_for

from argo_iam.argocd_adapter.policy import render_policy_csv
from argo_iam.audit.models import AuditQuery, EventType, Outcome
from argo_iam.authorization.permissions import (
    ARGOCD_PERMISSIONS,
    Permission,
    permissions_for_role,
)
from argo_iam.common import IAMError
from argo_iam.users.models import AccountStatus, Role
from argo_iam.web.security import container, permission_required, request_context

bp = Blueprint("admin", __name__, url_prefix="/admin")


def _users_by_id():
    return {u.id: u for u in container().users.list_users()}


def _run(action, success_message):
    try:
        action()
        flash(success_message, "success")
    except IAMError as e:
        flash(e.message, "error")


@bp.route("/")
@permission_required(Permission.AUDIT_READ)
def overview():
    c = container()
    users = c.users.list_users()
    now = c.clock.now()
    stats = {
        "users": len(users),
        "disabled": sum(1 for u in users if not u.is_active),
        "locked": sum(1 for u in users if u.is_locked(now)),
        "without_mfa": sum(1 for u in users if not u.mfa_enabled),
        "sessions": len(c.sessions.list_open(g.user)),
        "pending": len(c.privileges.list_pending()),
        "active_grants": len(c.privileges.list_active()),
        "failed_logins": c.audit.count(EventType.LOGIN_FAILED)
        + c.audit.count(EventType.MFA_FAILED),
        "denied": c.audit.count(EventType.ACCESS_DENIED),
    }
    return render_template(
        "admin/overview.html", stats=stats, chain=c.audit.verify_chain(),
        recent=c.audit.query(AuditQuery(limit=12)),
    )


# -- users -----------------------------------------------------------------------

@bp.route("/users")
@permission_required(Permission.USERS_MANAGE)
def users():
    c = container()
    return render_template(
        "admin/users.html", users=c.users.list_users(), roles=list(Role), now=c.clock.now()
    )


@bp.route("/users", methods=["POST"])
@permission_required(Permission.USERS_MANAGE)
def create_user():
    f = request.form
    try:
        role = Role(f.get("role", "viewer"))
        user = container().users.create_user(
            g.user, f.get("username", ""), f.get("display_name", ""), f.get("email", ""),
            f.get("password", ""), role, request_context(),
        )
        flash(f"User {user.username} created. They will enrol MFA at first sign-in.",
              "success")
    except (IAMError, ValueError) as e:
        flash(getattr(e, "message", str(e)), "error")
    return redirect(url_for("admin.users"))


@bp.route("/users/<int:user_id>/role", methods=["POST"])
@permission_required(Permission.USERS_MANAGE)
def change_role(user_id):
    try:
        role = Role(request.form.get("role", ""))
    except ValueError:
        flash("Unknown role.", "error")
        return redirect(url_for("admin.users"))
    _run(lambda: container().users.change_role(g.user, user_id, role, request_context()),
         f"Role changed to {role.label}; the user's sessions were ended.")
    return redirect(url_for("admin.users"))


@bp.route("/users/<int:user_id>/status", methods=["POST"])
@permission_required(Permission.USERS_MANAGE)
def change_status(user_id):
    status = AccountStatus.DISABLED if request.form.get("status") == "disabled" \
        else AccountStatus.ACTIVE
    _run(lambda: container().users.set_status(g.user, user_id, status, request_context()),
         f"Account {status.value}.")
    return redirect(url_for("admin.users"))


@bp.route("/users/<int:user_id>/unlock", methods=["POST"])
@permission_required(Permission.USERS_MANAGE)
def unlock(user_id):
    _run(lambda: container().users.unlock(g.user, user_id, request_context()),
         "Account unlocked.")
    return redirect(url_for("admin.users"))


@bp.route("/users/<int:user_id>/reset-mfa", methods=["POST"])
@permission_required(Permission.USERS_MANAGE)
def reset_mfa(user_id):
    _run(lambda: container().users.reset_mfa(g.user, user_id, request_context()),
         "MFA reset. The user will enrol a new authenticator at next sign-in.")
    return redirect(url_for("admin.users"))


# -- privilege requests --------------------------------------------------------------

@bp.route("/privileges")
@permission_required(Permission.PRIVILEGE_APPROVE)
def privileges():
    c = container()
    return render_template(
        "admin/privileges.html",
        pending=c.privileges.list_pending(),
        active=c.privileges.list_active(),
        history=c.privileges.list_all(limit=50),
        users_by_id=_users_by_id(),
    )


@bp.route("/privileges/<int:request_id>/<decision>", methods=["POST"])
@permission_required(Permission.PRIVILEGE_APPROVE)
def decide(request_id, decision):
    c, ctx, note = container(), request_context(), request.form.get("note", "")
    actions = {
        "approve": (lambda: c.privileges.approve(g.user, request_id, note, ctx),
                    f"Request #{request_id} approved; temporary access is active."),
        "reject": (lambda: c.privileges.reject(g.user, request_id, note, ctx),
                   f"Request #{request_id} rejected."),
        "revoke": (lambda: c.privileges.revoke(g.user, request_id, note, ctx),
                   f"Temporary access from request #{request_id} revoked."),
    }
    if decision not in actions:
        flash("Unknown action.", "error")
    else:
        _run(*actions[decision])
    return redirect(url_for("admin.privileges"))


# -- sessions --------------------------------------------------------------------

@bp.route("/sessions")
@permission_required(Permission.SESSIONS_MANAGE)
def sessions():
    return render_template(
        "admin/sessions.html", sessions=container().sessions.list_open(g.user),
        users_by_id=_users_by_id(),
    )


@bp.route("/sessions/<session_id>/revoke", methods=["POST"])
@permission_required(Permission.SESSIONS_MANAGE)
def revoke_session(session_id):
    _run(lambda: container().sessions.revoke(g.user, session_id, request_context()),
         "Session revoked.")
    return redirect(url_for("admin.sessions"))


# -- audit -----------------------------------------------------------------------

def _audit_query() -> AuditQuery:
    a = request.args
    return AuditQuery(
        event_type=a.get("type") or None,
        username=a.get("user") or None,
        outcome=a.get("outcome") or None,
        limit=int(a.get("limit", 200)) if a.get("limit", "").isdigit() else 200,
    )


@bp.route("/audit")
@permission_required(Permission.AUDIT_READ)
def audit():
    c = container()
    return render_template(
        "admin/audit.html", events=c.audit.query(_audit_query()), chain=c.audit.verify_chain(),
        event_types=list(EventType), outcomes=list(Outcome),
        categories=sorted({e.category for e in EventType}), filters=request.args,
    )


def _csv_safe(value):
    """Stop spreadsheets from evaluating a cell as a formula (CSV output only)."""
    if isinstance(value, str) and value.startswith(("=", "+", "-", "@", "\t", "\r")):
        return "'" + value
    return value


@bp.route("/audit.csv")
@permission_required(Permission.AUDIT_READ)
def audit_csv():
    events = container().audit.query(_audit_query())
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["id", "occurred_at", "event_type", "outcome", "actor", "target", "ip",
                     "channel", "details", "hash"])
    for e in events:
        writer.writerow([_csv_safe(v) for v in (
            e.id, e.occurred_at.isoformat(), e.event_type.value, e.outcome.value,
            e.actor_username or "", e.target or "", e.ip, e.channel,
            json.dumps(e.details, sort_keys=True), e.hash)])
    return Response(out.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=audit.csv"})


# -- Argo CD RBAC translation ---------------------------------------------------------

@bp.route("/argocd-policy")
@permission_required(Permission.AUDIT_READ)
def argocd_policy():
    matrix = [
        (p, [p in permissions_for_role(r) for r in Role],
         [p in ARGOCD_PERMISSIONS[r] for r in Role])
        for p in Permission
    ]
    return render_template(
        "admin/policy.html", policy_csv=render_policy_csv(), roles=list(Role), matrix=matrix
    )
