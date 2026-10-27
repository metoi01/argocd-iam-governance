"""Login UI: password step, TOTP step, first-login enrolment, logout."""

from __future__ import annotations

import io

from flask import (
    Blueprint,
    flash,
    g,
    make_response,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from argo_iam.auth.service import LoginStatus
from argo_iam.web.security import (
    CHALLENGE_KEY,
    container,
    request_context,
    rotate_csrf_token,
    safe_next,
)

bp = Blueprint("auth", __name__)


def _qr_svg(uri: str) -> str:
    try:
        import segno
    except ImportError:  # optional dependency
        return ""
    out = io.BytesIO()
    segno.make(uri, error="m").save(out, kind="svg", scale=5, border=2, xmldecl=False,
                                    svgns=True, dark="#0d2738", light="#ffffff")
    return out.getvalue().decode("utf-8")


def _finish_login(outcome):
    c = container()
    session.pop(CHALLENGE_KEY, None)
    target = safe_next(session.pop("next", None)) or url_for("apps.applications")
    rotate_csrf_token()  # new anonymous->authenticated boundary
    response = make_response(redirect(target))
    response.set_cookie(
        c.settings.session_cookie_name,
        outcome.session_token,
        max_age=int(c.settings.session_absolute_timeout.total_seconds()),
        httponly=True,
        secure=c.settings.cookie_secure,
        samesite="Lax",
    )
    flash(f"Welcome back, {outcome.user.display_name}.", "success")
    return response


@bp.route("/login", methods=["GET", "POST"])
def login():
    if g.user is not None:
        return redirect(url_for("apps.applications"))
    if request.method == "GET":
        if request.args.get("next"):
            session["next"] = safe_next(request.args.get("next"))
        return render_template("auth/login.html")

    outcome = container().auth.begin_login(
        request.form.get("username", ""), request.form.get("password", ""), request_context()
    )
    if outcome.needs_mfa:
        session[CHALLENGE_KEY] = outcome.challenge_token
        if outcome.status is LoginStatus.ENROLLMENT_REQUIRED:
            return redirect(url_for("auth.enroll"))
        return redirect(url_for("auth.mfa"))
    return render_template(
        "auth/login.html", error=outcome.message, username=request.form.get("username", "")
    ), 401


@bp.route("/login/mfa", methods=["GET", "POST"])
def mfa():
    c = container()
    token = session.get(CHALLENGE_KEY)
    challenge = c.auth.challenge(token)
    if challenge is None or challenge.purpose != "verify":
        session.pop(CHALLENGE_KEY, None)
        flash("Your sign-in attempt expired. Please log in again.", "warning")
        return redirect(url_for("auth.login"))
    user = c.users_repo.get(challenge.user_id)
    if request.method == "GET":
        return render_template("auth/mfa.html", user=user)

    outcome = c.auth.verify_mfa(token, request.form.get("code", ""), request_context())
    if outcome.success:
        return _finish_login(outcome)
    if outcome.restart:
        session.pop(CHALLENGE_KEY, None)
        flash(outcome.message, "error")
        return redirect(url_for("auth.login"))
    return render_template("auth/mfa.html", user=user, error=outcome.message), 401


@bp.route("/login/mfa/enroll", methods=["GET", "POST"])
def enroll():
    c = container()
    token = session.get(CHALLENGE_KEY)
    details = c.auth.enrollment_details(token)
    if details is None:
        session.pop(CHALLENGE_KEY, None)
        flash("Your sign-in attempt expired. Please log in again.", "warning")
        return redirect(url_for("auth.login"))
    secret, uri, user = details
    context = dict(
        user=user, secret=" ".join(secret[i:i + 4] for i in range(0, len(secret), 4)),
        uri=uri, qr_svg=_qr_svg(uri),
    )
    if request.method == "GET":
        return render_template("auth/enroll.html", **context)

    outcome = c.auth.verify_mfa(token, request.form.get("code", ""), request_context())
    if outcome.success:
        flash("Authenticator enrolled. Use it every time you sign in.", "success")
        return _finish_login(outcome)
    if outcome.restart:
        session.pop(CHALLENGE_KEY, None)
        flash(outcome.message, "error")
        return redirect(url_for("auth.login"))
    return render_template("auth/enroll.html", error=outcome.message, **context), 401


@bp.route("/logout", methods=["POST"])
def logout():
    c = container()
    if g.user is not None:
        c.sessions.logout(g.session, g.user, request_context())
    session.clear()
    response = make_response(redirect(url_for("auth.login")))
    response.delete_cookie(c.settings.session_cookie_name)
    flash("You have been signed out.", "info")
    return response
