import pytest

from argo_iam.audit.models import AuditQuery, EventType
from argo_iam.common import ConflictError, PermissionDenied, ValidationError
from argo_iam.privilege.models import RequestStatus
from argo_iam.users.models import Role

from conftest import CTX

WHY = "Deploy hotfix 2.4.1 to guestbook-prod (INC-1042)"


def test_full_jit_lifecycle(c, user):
    oscar, alice = user("oscar"), user("alice")
    req = c.privileges.request(oscar, Role.ADMIN, WHY, 60, CTX)
    assert req.status is RequestStatus.PENDING
    assert [r.id for r in c.privileges.list_pending()] == [req.id]

    approved = c.privileges.approve(alice, req.id, "OK for the incident", CTX)
    assert approved.status is RequestStatus.ACTIVE
    assert approved.decided_by == alice.id
    assert (approved.expires_at - approved.activated_at).total_seconds() == 3600

    c.clock.advance(minutes=59)
    assert c.privileges.expire_due() == 0
    c.clock.advance(minutes=2)
    assert c.privileges.expire_due() == 1
    assert c.privileges.get(req.id).status is RequestStatus.EXPIRED
    expired = c.audit.query(AuditQuery(event_type=EventType.PRIVILEGE_EXPIRED.value))[0]
    assert expired.details["restored_role"] == "operator"


def test_request_validation(c, user):
    oscar = user("oscar")
    with pytest.raises(ValidationError):
        c.privileges.request(oscar, Role.OPERATOR, WHY, 60, CTX)  # not higher
    with pytest.raises(ValidationError):
        c.privileges.request(oscar, Role.VIEWER, WHY, 60, CTX)  # lower
    with pytest.raises(ValidationError):
        c.privileges.request(oscar, Role.ADMIN, "because", 60, CTX)  # short reason
    with pytest.raises(ValidationError):
        c.privileges.request(oscar, Role.ADMIN, WHY, 5, CTX)  # too short
    with pytest.raises(ValidationError):
        c.privileges.request(oscar, Role.ADMIN, WHY, 600, CTX)  # too long


def test_only_one_open_request(c, user):
    c.privileges.request(user("oscar"), Role.ADMIN, WHY, 30, CTX)
    with pytest.raises(ConflictError):
        c.privileges.request(user("oscar"), Role.ADMIN, WHY, 30, CTX)


def test_viewer_can_request_operator(c, user):
    req = c.privileges.request(user("vera"), Role.OPERATOR, WHY, 30, CTX)
    c.privileges.approve(user("alice"), req.id, "", CTX)
    assert c.authorization.profile(user("vera")).effective_role is Role.OPERATOR


def test_non_admin_cannot_approve(c, user):
    req = c.privileges.request(user("vera"), Role.OPERATOR, WHY, 30, CTX)
    with pytest.raises(PermissionDenied):
        c.privileges.approve(user("oscar"), req.id, "", CTX)


def test_temporarily_elevated_admin_cannot_approve(c, user):
    req = c.privileges.request(user("oscar"), Role.ADMIN, WHY, 30, CTX)
    c.privileges.approve(user("alice"), req.id, "", CTX)
    other = c.privileges.request(user("vera"), Role.OPERATOR, WHY, 30, CTX)
    with pytest.raises(PermissionDenied):
        c.privileges.approve(user("oscar"), other.id, "", CTX)


def test_self_approval_is_blocked(c, user):
    # Simulate an admin-requested elevation by inserting via the repository.
    from argo_iam.privilege.models import PrivilegeRequest

    alice = user("alice")
    req = c.privileges._repo.add(PrivilegeRequest(
        id=None, requester_id=alice.id, base_role=Role.OPERATOR, requested_role=Role.ADMIN,
        justification=WHY, duration_minutes=30, status=RequestStatus.PENDING,
        created_at=c.clock.now()))
    with pytest.raises(PermissionDenied):
        c.privileges.approve(alice, req.id, "", CTX)


def test_reject_requires_reason_and_closes_request(c, user):
    req = c.privileges.request(user("oscar"), Role.ADMIN, WHY, 30, CTX)
    with pytest.raises(ValidationError):
        c.privileges.reject(user("alice"), req.id, "  ", CTX)
    rejected = c.privileges.reject(user("alice"), req.id, "Use the change window", CTX)
    assert rejected.status is RequestStatus.REJECTED
    with pytest.raises(ConflictError):
        c.privileges.approve(user("sam"), req.id, "", CTX)
    # a new request is allowed after rejection
    c.privileges.request(user("oscar"), Role.ADMIN, WHY, 30, CTX)


def test_cancel_by_requester_only(c, user):
    req = c.privileges.request(user("oscar"), Role.ADMIN, WHY, 30, CTX)
    with pytest.raises(PermissionDenied):
        c.privileges.cancel(user("vera"), req.id, CTX)
    assert c.privileges.cancel(user("oscar"), req.id, CTX).status is RequestStatus.CANCELLED


def test_revoke_active_grant(c, user):
    req = c.privileges.request(user("oscar"), Role.ADMIN, WHY, 120, CTX)
    c.privileges.approve(user("alice"), req.id, "", CTX)
    c.privileges.revoke(user("sam"), req.id, "Incident closed", CTX)
    assert c.authorization.profile(user("oscar")).effective_role is Role.OPERATOR
    assert c.privileges.get(req.id).status is RequestStatus.REVOKED


def test_role_change_after_request_blocks_approval(c, user):
    req = c.privileges.request(user("vera"), Role.ADMIN, WHY, 30, CTX)
    c.users.change_role(user("alice"), user("vera").id, Role.OPERATOR, CTX)
    # role change closes open requests
    assert c.privileges.get(req.id).status is RequestStatus.CANCELLED
