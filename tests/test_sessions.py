import pytest

from argo_iam.audit.models import AuditQuery, EventType
from argo_iam.common import PermissionDenied
from argo_iam.sessions.models import EndReason

from conftest import CTX


def test_session_token_is_stored_hashed(c, login):
    session, token = login("oscar")
    assert session.token_hash != token and len(session.token_hash) == 64
    row = c.db.query_one("SELECT * FROM sessions WHERE id = ?", (session.id,))
    assert token not in tuple(row)


def test_idle_timeout(c, login):
    _, token = login("oscar")
    c.clock.advance(minutes=29)
    assert c.sessions.resolve(token) is not None  # activity refreshes last_seen
    c.clock.advance(minutes=29)
    assert c.sessions.resolve(token) is not None
    c.clock.advance(minutes=31)
    assert c.sessions.resolve(token) is None
    ended = c.sessions.list_for_user(c.users_repo.get_by_username("oscar").id, True)[0]
    assert ended.end_reason is EndReason.IDLE_TIMEOUT
    assert c.audit.query(AuditQuery(event_type=EventType.SESSION_EXPIRED.value))


def test_absolute_timeout_even_when_active(c, login):
    _, token = login("oscar")
    for _ in range(17):  # 17 x 29 min ≈ 8.2 h of continuous activity
        c.clock.advance(minutes=29)
        c.sessions.resolve(token)
    assert c.sessions.resolve(token) is None


def test_user_can_revoke_own_session_but_not_others(c, login, user):
    oscar_session, oscar_token = login("oscar")
    vera_session, _ = login("vera")
    c.sessions.revoke(user("oscar"), oscar_session.id, CTX)
    assert c.sessions.resolve(oscar_token) is None
    with pytest.raises(PermissionDenied):
        c.sessions.revoke(user("oscar"), vera_session.id, CTX)


def test_admin_can_list_and_revoke_any_session(c, login, user):
    vera_session, vera_token = login("vera")
    assert any(s.id == vera_session.id for s in c.sessions.list_open(user("alice")))
    c.sessions.revoke(user("alice"), vera_session.id, CTX)
    assert c.sessions.resolve(vera_token) is None
    with pytest.raises(PermissionDenied):
        c.sessions.list_open(user("oscar"))


def test_logout_ends_session(c, login, user):
    session, token = login("oscar")
    c.sessions.logout(session, user("oscar"), CTX)
    assert c.sessions.resolve(token) is None
    assert c.audit.query(AuditQuery(event_type=EventType.LOGOUT.value))


def test_garbage_tokens_resolve_to_nothing(c):
    assert c.sessions.resolve(None) is None
    assert c.sessions.resolve("not-a-token") is None
