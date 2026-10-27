from argo_iam.audit.models import AuditQuery, EventType
from argo_iam.auth.service import GENERIC_FAILURE, LoginStatus
from argo_iam.common import RequestContext
from argo_iam.seed import DEMO_PASSWORD
from argo_iam.users.models import AccountStatus

from conftest import CTX


def types(c, n=50):
    return [e.event_type for e in c.audit.query(AuditQuery(limit=n))]


def test_successful_two_step_login(c, user):
    outcome = c.auth.begin_login("oscar", DEMO_PASSWORD, CTX)
    assert outcome.status is LoginStatus.MFA_REQUIRED
    result = c.auth.verify_mfa(outcome.challenge_token, c.auth.current_code(user("oscar")), CTX)
    assert result.success and result.session_token
    assert c.sessions.resolve(result.session_token).user_id == user("oscar").id
    recorded = types(c)
    assert EventType.LOGIN_SUCCEEDED in recorded and EventType.MFA_SUCCEEDED in recorded


def test_password_alone_never_creates_a_session(c):
    c.auth.begin_login("oscar", DEMO_PASSWORD, CTX)
    assert c.sessions.list_for_user(c.users_repo.get_by_username("oscar").id) == []


def test_unknown_user_and_wrong_password_look_identical(c):
    unknown = c.auth.begin_login("mallory", "whatever", CTX)
    wrong = c.auth.begin_login("oscar", "wrong-password", CTX)
    assert unknown.status is wrong.status is LoginStatus.INVALID
    assert unknown.message == wrong.message == GENERIC_FAILURE
    failed = c.audit.query(AuditQuery(event_type=EventType.LOGIN_FAILED.value))
    assert {e.details["reason"] for e in failed} == {"unknown_user", "bad_password"}


def test_lockout_after_repeated_failures_and_expiry(c, user):
    for _ in range(c.settings.max_failed_logins - 1):
        assert c.auth.begin_login("oscar", "nope", CTX).status is LoginStatus.INVALID
    assert c.auth.begin_login("oscar", "nope", CTX).status is LoginStatus.LOCKED
    # even the right password is refused while locked
    assert c.auth.begin_login("oscar", DEMO_PASSWORD, CTX).status is LoginStatus.LOCKED
    assert EventType.ACCOUNT_LOCKED in types(c)
    assert EventType.LOGIN_BLOCKED in types(c)
    c.clock.advance(minutes=16)
    assert c.auth.begin_login("oscar", DEMO_PASSWORD, CTX).status is LoginStatus.MFA_REQUIRED


def test_wrong_totp_codes_count_towards_lockout(c, user):
    outcome = c.auth.begin_login("oscar", DEMO_PASSWORD, CTX)
    for _ in range(c.settings.mfa_challenge_max_attempts - 1):
        result = c.auth.verify_mfa(outcome.challenge_token, "000000", CTX)
        assert not result.success and not result.restart
    result = c.auth.verify_mfa(outcome.challenge_token, "000000", CTX)
    assert result.restart  # fifth failure locks the account
    assert user("oscar").is_locked(c.clock.now())
    assert EventType.MFA_FAILED in types(c)


def test_totp_code_cannot_be_replayed(c, user):
    first = c.auth.begin_login("oscar", DEMO_PASSWORD, CTX)
    code = c.auth.current_code(user("oscar"))
    assert c.auth.verify_mfa(first.challenge_token, code, CTX).success
    second = c.auth.begin_login("oscar", DEMO_PASSWORD, CTX)
    assert not c.auth.verify_mfa(second.challenge_token, code, CTX).success


def test_mfa_challenge_expires(c, user):
    outcome = c.auth.begin_login("oscar", DEMO_PASSWORD, CTX)
    c.clock.advance(minutes=6)
    result = c.auth.verify_mfa(outcome.challenge_token, c.auth.current_code(user("oscar")), CTX)
    assert not result.success and result.restart


def test_disabled_account_cannot_log_in(c, user):
    u = user("vera")
    u.status = AccountStatus.DISABLED
    c.users_repo.save(u)
    assert c.auth.begin_login("vera", DEMO_PASSWORD, CTX).status is LoginStatus.DISABLED


def test_first_login_enrols_authenticator(c, user):
    outcome = c.auth.begin_login("nina", DEMO_PASSWORD, CTX)
    assert outcome.status is LoginStatus.ENROLLMENT_REQUIRED
    secret, uri, nina = c.auth.enrollment_details(outcome.challenge_token)
    assert uri.startswith("otpauth://totp/") and nina.username == "nina"
    code = c.totp.code_at(secret, c.clock.now())
    result = c.auth.verify_mfa(outcome.challenge_token, code, CTX)
    assert result.success
    assert user("nina").mfa_enabled and user("nina").mfa_secret == secret
    assert EventType.MFA_ENROLLED in types(c)


def test_audit_records_request_origin(c):
    c.auth.begin_login("oscar", "bad", RequestContext(ip="192.0.2.7", user_agent="x",
                                                       channel="api"))
    event = c.audit.query(AuditQuery(event_type=EventType.LOGIN_FAILED.value))[0]
    assert (event.ip, event.channel) == ("192.0.2.7", "api")
