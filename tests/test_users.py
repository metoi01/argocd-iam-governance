import pytest

from argo_iam.audit.models import AuditQuery, EventType
from argo_iam.common import ConflictError, PermissionDenied, ValidationError
from argo_iam.users.models import AccountStatus, Role

from conftest import CTX


def test_admin_creates_user_who_must_enrol_mfa(c, user):
    created = c.users.create_user(user("alice"), "dana", "Dana Dev", "dana@example.com",
                                  "Very-Strong-Pass1", Role.VIEWER, CTX)
    assert created.role is Role.VIEWER and not created.mfa_enabled
    assert created.password_hash.startswith("scrypt$")
    assert c.audit.query(AuditQuery(event_type=EventType.USER_CREATED.value))


def test_non_admin_cannot_manage_users(c, user):
    with pytest.raises(PermissionDenied):
        c.users.create_user(user("oscar"), "dana", "Dana", "dana@example.com",
                            "Very-Strong-Pass1", Role.ADMIN, CTX)


@pytest.mark.parametrize("password", ["short1!A", "alllowercaseletters", "NoDigitsOrSymbols"])
def test_password_policy(c, user, password):
    with pytest.raises(ValidationError):
        c.users.create_user(user("alice"), "dana", "Dana", "dana@example.com", password,
                            Role.VIEWER, CTX)


def test_duplicate_and_invalid_usernames(c, user):
    with pytest.raises(ConflictError):
        c.users.create_user(user("alice"), "oscar", "x", "o@example.com",
                            "Very-Strong-Pass1", Role.VIEWER, CTX)
    with pytest.raises(ValidationError):
        c.users.create_user(user("alice"), "Bad Name", "x", "b@example.com",
                            "Very-Strong-Pass1", Role.VIEWER, CTX)


def test_role_change_ends_sessions_and_is_audited(c, user, login):
    _, token = login("vera")
    c.users.change_role(user("alice"), user("vera").id, Role.OPERATOR, CTX)
    assert user("vera").role is Role.OPERATOR
    assert c.sessions.resolve(token) is None
    event = c.audit.query(AuditQuery(event_type=EventType.ROLE_CHANGED.value))[0]
    assert event.details == {"from": "viewer", "to": "operator"}


def test_disable_ends_sessions_and_grants(c, user, login):
    _, token = login("oscar")
    req = c.privileges.request(user("oscar"), Role.ADMIN, "Production rollout for INC-9", 30, CTX)
    c.privileges.approve(user("alice"), req.id, "", CTX)
    c.users.set_status(user("alice"), user("oscar").id, AccountStatus.DISABLED, CTX)
    assert c.sessions.resolve(token) is None
    assert c.privileges.open_request(user("oscar").id) is None


def test_last_admin_and_self_protection(c, user):
    alice, sam = user("alice"), user("sam")
    with pytest.raises(ConflictError):
        c.users.set_status(alice, alice.id, AccountStatus.DISABLED, CTX)
    c.users.change_role(alice, sam.id, Role.OPERATOR, CTX)
    with pytest.raises(ConflictError):
        c.users.change_role(alice, alice.id, Role.VIEWER, CTX)


def test_unlock_and_reset_mfa(c, user):
    from argo_iam.seed import DEMO_PASSWORD

    for _ in range(c.settings.max_failed_logins):
        c.auth.begin_login("vera", "wrong", CTX)
    assert user("vera").is_locked(c.clock.now())
    c.users.unlock(user("alice"), user("vera").id, CTX)
    assert not user("vera").is_locked(c.clock.now())
    c.users.reset_mfa(user("alice"), user("vera").id, CTX)
    assert not user("vera").mfa_enabled
    assert c.auth.begin_login("vera", DEMO_PASSWORD, CTX).status.value == \
        "mfa_enrollment_required"
