"""IAM Gateway JSON API (``/api/v1``) for the CLI, CI systems and scripts.

Authentication uses the same two steps as the UI and returns a bearer token:

    POST /api/v1/auth/login   {"username", "password"} -> {"challenge_token"}
    POST /api/v1/auth/mfa     {"challenge_token", "code"} -> {"session_token"}
    then: Authorization: Bearer <session_token>
"""

from __future__ import annotations

from flask import Blueprint, g, jsonify, request

from argo_iam.argocd_adapter.base import ArgoApplication
from argo_iam.audit.models import AuditEvent, AuditQuery
from argo_iam.auth.service import LoginStatus
from argo_iam.authorization.permissions import Permission
from argo_iam.common import ValidationError
from argo_iam.privilege.models import PrivilegeRequest
from argo_iam.users.models import Role
from argo_iam.web.security import container, login_required, permission_required, request_context

bp = Blueprint("api", __name__, url_prefix="/api/v1")


def _body() -> dict:
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        raise ValidationError("Send a JSON object body.")
    return data


def _app_json(a: ArgoApplication) -> dict:
    return {
        "name": a.name, "project": a.project, "environment": a.environment,
        "sync_status": a.sync_status, "health_status": a.health_status,
        "revision": a.revision, "repo_url": a.repo_url, "path": a.path,
        "destination": f"{a.destination_server}/{a.destination_namespace}",
        "last_synced_at": a.last_synced_at.isoformat() if a.last_synced_at else None,
        "last_synced_by": a.last_synced_by,
    }


def _request_json(r: PrivilegeRequest) -> dict:
    iso = lambda d: d.isoformat() if d else None  # noqa: E731
    return {
        "id": r.id, "requester_id": r.requester_id, "base_role": r.base_role.value,
        "requested_role": r.requested_role.value, "justification": r.justification,
        "duration_minutes": r.duration_minutes, "status": r.status.value,
        "created_at": iso(r.created_at), "decided_at": iso(r.decided_at),
        "decided_by": r.decided_by, "decision_note": r.decision_note,
        "activated_at": iso(r.activated_at), "expires_at": iso(r.expires_at),
    }


def _event_json(e: AuditEvent) -> dict:
    return {
        "id": e.id, "occurred_at": e.occurred_at.isoformat(), "type": e.event_type.value,
        "outcome": e.outcome.value, "actor": e.actor_username, "target": e.target,
        "ip": e.ip, "channel": e.channel, "details": e.details, "hash": e.hash,
    }


# -- authentication -------------------------------------------------------------

@bp.route("/auth/login", methods=["POST"])
def login():
    data = _body()
    outcome = container().auth.begin_login(
        str(data.get("username", "")), str(data.get("password", "")), request_context()
    )
    if outcome.status is LoginStatus.MFA_REQUIRED:
        return jsonify(status=outcome.status.value, challenge_token=outcome.challenge_token)
    if outcome.status is LoginStatus.ENROLLMENT_REQUIRED:
        return jsonify(status=outcome.status.value,
                       message="Sign in once through the web UI to enrol an authenticator."), 403
    return jsonify(status=outcome.status.value, message=outcome.message), 401


@bp.route("/auth/mfa", methods=["POST"])
def mfa():
    data = _body()
    c = container()
    token = str(data.get("challenge_token", ""))
    challenge = c.auth.challenge(token)
    if challenge is None or challenge.purpose != "verify":
        return jsonify(status="challenge_invalid",
                       message="The challenge expired or is invalid."), 401
    outcome = c.auth.verify_mfa(token, str(data.get("code", "")), request_context())
    if not outcome.success:
        return jsonify(status="mfa_failed", message=outcome.message,
                       restart=outcome.restart), 401
    return jsonify(
        status="authenticated", session_token=outcome.session_token,
        session_id=outcome.session.id, expires_at=outcome.session.expires_at.isoformat(),
    )


@bp.route("/auth/logout", methods=["POST"])
@login_required
def logout():
    container().sessions.logout(g.session, g.user, request_context())
    return jsonify(status="logged_out")


@bp.route("/me")
@login_required
def me():
    a = g.access
    return jsonify(
        username=g.user.username, display_name=g.user.display_name,
        base_role=a.base_role.value, effective_role=a.effective_role.value,
        permissions=sorted(p.value for p in a.permissions),
        elevation=_request_json(a.grant) if a.grant else None,
        session={"id": g.session.id, "expires_at": g.session.expires_at.isoformat()},
    )


# -- Argo CD operations -------------------------------------------------------------

@bp.route("/applications")
@login_required
def applications():
    apps = container().argocd.list_applications(g.user, request_context())
    return jsonify(items=[_app_json(a) for a in apps])


@bp.route("/applications/<name>/sync", methods=["POST"])
@login_required
def sync(name):
    data = request.get_json(silent=True) or {}
    result = container().argocd.sync(
        g.user, name, request_context(), revision=data.get("revision"),
        dry_run=bool(data.get("dry_run", False)),
    )
    return jsonify(application=result.application, revision=result.revision,
                   phase=result.phase, message=result.message, dry_run=result.dry_run)


# -- privilege elevation ------------------------------------------------------------

@bp.route("/privilege-requests", methods=["GET"])
@login_required
def list_requests():
    c = container()
    if request.args.get("status") == "pending":
        c.authorization.require(g.user, Permission.PRIVILEGE_APPROVE, request_context())
        items = c.privileges.list_pending()
    else:
        items = c.privileges.list_for_user(g.user.id)
    return jsonify(items=[_request_json(r) for r in items])


@bp.route("/privilege-requests", methods=["POST"])
@login_required
def create_request():
    data = _body()
    try:
        role = Role(str(data.get("role", "")))
        duration = int(data.get("duration_minutes", 0))
    except ValueError:
        raise ValidationError("'role' must be viewer/operator/admin and "
                              "'duration_minutes' an integer.")
    req = container().privileges.request(
        g.user, role, str(data.get("justification", "")), duration, request_context()
    )
    return jsonify(_request_json(req)), 201


@bp.route("/privilege-requests/<int:request_id>/<decision>", methods=["POST"])
@login_required
def decide(request_id, decision):
    c, ctx = container(), request_context()
    note = str((request.get_json(silent=True) or {}).get("note", ""))
    if decision == "approve":
        req = c.privileges.approve(g.user, request_id, note, ctx)
    elif decision == "reject":
        req = c.privileges.reject(g.user, request_id, note, ctx)
    elif decision == "revoke":
        req = c.privileges.revoke(g.user, request_id, note, ctx)
    elif decision == "cancel":
        req = c.privileges.cancel(g.user, request_id, ctx)
    else:
        raise ValidationError("Unknown decision.")
    return jsonify(_request_json(req))


# -- audit --------------------------------------------------------------------------

@bp.route("/audit")
@permission_required(Permission.AUDIT_READ)
def audit():
    a = request.args
    q = AuditQuery(event_type=a.get("type"), username=a.get("user"),
                   outcome=a.get("outcome"), limit=int(a.get("limit", 100)))
    c = container()
    chain = c.audit.verify_chain()
    return jsonify(
        chain={"valid": chain.valid, "checked": chain.checked, "broken_at": chain.broken_at},
        items=[_event_json(e) for e in c.audit.query(q)],
    )
