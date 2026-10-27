from argo_iam.audit.models import AuditQuery, EventType, Outcome

from conftest import CTX


def test_hash_chain_is_valid_after_normal_activity(c, login):
    login("oscar")
    result = c.audit.verify_chain()
    assert result.valid and result.checked == c.audit.count() > 0


def test_tampering_is_detected(c, login):
    login("oscar")
    target = c.audit.query(AuditQuery(event_type=EventType.LOGIN_SUCCEEDED.value))[0]
    c.db.execute("UPDATE audit_events SET actor_username = 'mallory' WHERE id = ?", (target.id,))
    result = c.audit.verify_chain()
    assert not result.valid and result.broken_at == target.id


def test_deletion_is_detected(c, login):
    login("oscar")
    c.db.execute("DELETE FROM audit_events WHERE id = 3")
    assert not c.audit.verify_chain().valid


def test_query_filters(c, user):
    c.audit.record(EventType.ACCESS_DENIED, Outcome.DENIED, actor=user("vera"), ctx=CTX)
    c.audit.record(EventType.LOGIN_FAILED, Outcome.FAILURE, actor_username="ghost", ctx=CTX)
    assert {e.event_type for e in c.audit.query(AuditQuery(event_type="authz"))} == \
        {EventType.ACCESS_DENIED}
    assert [e.actor_username for e in c.audit.query(AuditQuery(username="ghost"))] == ["ghost"]
    assert all(e.outcome is Outcome.DENIED for e in c.audit.query(AuditQuery(outcome="denied")))


def test_repository_is_append_only():
    from argo_iam.audit.repository import AuditRepository

    public = {name for name in dir(AuditRepository) if not name.startswith("_")}
    assert not public & {"update", "delete", "save", "remove"}
