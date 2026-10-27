import pytest

from argo_iam.audit.models import AuditQuery, EventType
from argo_iam.authorization.permissions import (
    Permission,
    elevatable_permissions,
    permissions_for_role,
)
from argo_iam.common import PermissionDenied
from argo_iam.users.models import Role

from conftest import CTX


def test_role_hierarchy_is_cumulative_for_argocd_permissions():
    viewer = elevatable_permissions(Role.VIEWER)
    operator = elevatable_permissions(Role.OPERATOR)
    admin = elevatable_permissions(Role.ADMIN)
    assert viewer < operator < admin


def test_role_permission_mapping():
    assert Permission.APP_VIEW in permissions_for_role(Role.VIEWER)
    assert Permission.APP_SYNC not in permissions_for_role(Role.VIEWER)
    assert Permission.APP_SYNC in permissions_for_role(Role.OPERATOR)
    assert Permission.APP_SYNC_PRODUCTION not in permissions_for_role(Role.OPERATOR)
    assert Permission.APP_SYNC_PRODUCTION in permissions_for_role(Role.ADMIN)
    assert Permission.PRIVILEGE_APPROVE in permissions_for_role(Role.ADMIN)


def test_temporary_grants_never_include_governance_permissions():
    assert not any(not p.is_argocd for p in elevatable_permissions(Role.ADMIN))


def test_require_denies_and_audits(c, user):
    with pytest.raises(PermissionDenied):
        c.authorization.require(user("vera"), Permission.APP_SYNC, CTX, target="application:x")
    event = c.audit.query(AuditQuery(event_type=EventType.ACCESS_DENIED.value))[0]
    assert event.actor_username == "vera"
    assert event.details["permission"] == "applications:sync"


def test_disabled_users_have_no_permissions(c, user):
    from argo_iam.users.models import AccountStatus

    u = user("alice")
    u.status = AccountStatus.DISABLED
    assert c.authorization.profile(u).permissions == frozenset()


def test_effective_role_follows_active_grant(c, user):
    oscar, alice = user("oscar"), user("alice")
    req = c.privileges.request(oscar, Role.ADMIN, "Production hotfix INC-77 rollout", 30, CTX)
    assert c.authorization.profile(oscar).effective_role is Role.OPERATOR
    c.privileges.approve(alice, req.id, "", CTX)
    profile = c.authorization.profile(oscar)
    assert profile.effective_role is Role.ADMIN and profile.is_elevated
    assert Permission.APP_SYNC_PRODUCTION in profile.permissions
    assert Permission.PRIVILEGE_APPROVE not in profile.permissions
    assert Permission.USERS_MANAGE not in profile.permissions
    c.clock.advance(minutes=30)
    # expiry is enforced at check time, before any sweep runs
    assert c.authorization.profile(oscar).effective_role is Role.OPERATOR
