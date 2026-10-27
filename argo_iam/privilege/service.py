"""Privilege Service: just-in-time elevation with approval and expiry.

Rules enforced here:

* only a role above the requester's permanent role can be requested;
* a user has at most one open (pending or active) request at a time;
* duration is bounded by configuration and a justification is mandatory;
* approvers need the permanent ``iam:privilege:approve`` permission and may not
  approve their own request (four-eyes principle);
* an approved grant becomes active immediately and ends automatically.
"""

from __future__ import annotations

from datetime import timedelta
from typing import List, Optional

from argo_iam.audit.models import EventType, Outcome
from argo_iam.audit.service import AuditService
from argo_iam.authorization.permissions import Permission
from argo_iam.authorization.service import AuthorizationService
from argo_iam.clock import Clock
from argo_iam.common import (
    ConflictError,
    NotFoundError,
    PermissionDenied,
    RequestContext,
    SYSTEM_CONTEXT,
    ValidationError,
)
from argo_iam.config import Settings
from argo_iam.privilege.models import PrivilegeRequest, RequestStatus
from argo_iam.privilege.repository import PrivilegeRepository
from argo_iam.users.models import Role, User
from argo_iam.users.repository import UserRepository


class PrivilegeService:
    def __init__(
        self,
        repository: PrivilegeRepository,
        users: UserRepository,
        authorization: AuthorizationService,
        audit: AuditService,
        clock: Clock,
        settings: Settings,
    ):
        self._repo = repository
        self._users = users
        self._authz = authorization
        self._audit = audit
        self._clock = clock
        self._settings = settings

    # -- requester actions ---------------------------------------------------

    def request(
        self,
        user: User,
        requested_role: Role,
        justification: str,
        duration_minutes: int,
        ctx: RequestContext,
    ) -> PrivilegeRequest:
        self._authz.require(user, Permission.PRIVILEGE_REQUEST, ctx, target="privilege")
        justification = (justification or "").strip()
        s = self._settings
        if not requested_role.outranks(user.role):
            raise ValidationError(
                f"You already hold {user.role.label}; request a higher role."
            )
        if len(justification) < s.min_justification_length:
            raise ValidationError(
                f"Justification must be at least {s.min_justification_length} characters."
            )
        if not s.min_privilege_minutes <= duration_minutes <= s.max_privilege_minutes:
            raise ValidationError(
                f"Duration must be between {s.min_privilege_minutes} and "
                f"{s.max_privilege_minutes} minutes."
            )
        with self._repo.transaction():
            if self._repo.open_request_for_user(user.id) is not None:
                raise ConflictError(
                    "You already have a pending or active elevation request."
                )
            req = self._repo.add(
                PrivilegeRequest(
                    id=None,
                    requester_id=user.id,
                    base_role=user.role,
                    requested_role=requested_role,
                    justification=justification[:1000],
                    duration_minutes=duration_minutes,
                    status=RequestStatus.PENDING,
                    created_at=self._clock.now(),
                )
            )
        self._audit.record(
            EventType.PRIVILEGE_REQUESTED, actor=user, target=f"privilege:{req.id}",
            ctx=ctx,
            details={
                "requested_role": requested_role.value,
                "duration_minutes": duration_minutes,
                "justification": req.justification,
            },
        )
        return req

    def cancel(self, user: User, request_id: int, ctx: RequestContext) -> PrivilegeRequest:
        req = self._get(request_id)
        if req.requester_id != user.id:
            raise PermissionDenied("You can only cancel your own requests.")
        if req.status is not RequestStatus.PENDING:
            raise ConflictError("Only pending requests can be cancelled.")
        req.status = RequestStatus.CANCELLED
        req.ended_at = self._clock.now()
        self._repo.save(req)
        self._audit.record(
            EventType.PRIVILEGE_CANCELLED, actor=user, target=f"privilege:{req.id}", ctx=ctx
        )
        return req

    # -- approver actions ----------------------------------------------------

    def approve(
        self, approver: User, request_id: int, note: str, ctx: RequestContext
    ) -> PrivilegeRequest:
        req = self._decidable(approver, request_id, ctx)
        requester = self._users.get(req.requester_id)
        if requester is None or not requester.is_active:
            raise ConflictError("The requester's account is not active.")
        if requester.role is not req.base_role:
            raise ConflictError(
                "The requester's permanent role changed since the request was made."
            )
        now = self._clock.now()
        req.status = RequestStatus.ACTIVE
        req.decided_at = now
        req.decided_by = approver.id
        req.decision_note = (note or "").strip()[:500] or None
        req.activated_at = now
        req.expires_at = now + timedelta(minutes=req.duration_minutes)
        self._repo.save(req)
        self._audit.record(
            EventType.PRIVILEGE_APPROVED, actor=approver, target=f"privilege:{req.id}",
            ctx=ctx,
            details={
                "requester": requester.username,
                "granted_role": req.requested_role.value,
                "expires_at": req.expires_at.isoformat(),
                "note": req.decision_note,
            },
        )
        return req

    def reject(
        self, approver: User, request_id: int, note: str, ctx: RequestContext
    ) -> PrivilegeRequest:
        req = self._decidable(approver, request_id, ctx)
        note = (note or "").strip()
        if not note:
            raise ValidationError("Give a reason when rejecting a request.")
        now = self._clock.now()
        req.status = RequestStatus.REJECTED
        req.decided_at = now
        req.decided_by = approver.id
        req.decision_note = note[:500]
        req.ended_at = now
        self._repo.save(req)
        self._audit.record(
            EventType.PRIVILEGE_REJECTED, actor=approver, target=f"privilege:{req.id}",
            ctx=ctx, details={"note": req.decision_note},
        )
        return req

    def revoke(
        self, approver: User, request_id: int, reason: str, ctx: RequestContext
    ) -> PrivilegeRequest:
        self._authz.require(
            approver, Permission.PRIVILEGE_APPROVE, ctx, target=f"privilege:{request_id}"
        )
        req = self._get(request_id)
        if req.status is not RequestStatus.ACTIVE:
            raise ConflictError("Only active grants can be revoked.")
        req.status = RequestStatus.REVOKED
        req.ended_at = self._clock.now()
        req.decision_note = (reason or "").strip()[:500] or req.decision_note
        self._repo.save(req)
        self._audit.record(
            EventType.PRIVILEGE_REVOKED, actor=approver, target=f"privilege:{req.id}",
            ctx=ctx, details={"reason": reason},
        )
        return req

    # -- system --------------------------------------------------------------

    def expire_due(self) -> int:
        """Close grants whose time is up. Safe to call on every request."""
        now = self._clock.now()
        expired = 0
        with self._repo.transaction():
            for req in self._repo.due_for_expiry(now):
                req.status = RequestStatus.EXPIRED
                req.ended_at = req.expires_at
                self._repo.save(req)
                requester = self._users.get(req.requester_id)
                self._audit.record(
                    EventType.PRIVILEGE_EXPIRED, Outcome.INFO,
                    actor_username="system", target=f"privilege:{req.id}",
                    ctx=SYSTEM_CONTEXT,
                    details={
                        "requester": requester.username if requester else None,
                        "role": req.requested_role.value,
                        "restored_role": req.base_role.value,
                    },
                )
                expired += 1
        return expired

    def end_open_requests_for_user(self, user_id: int) -> None:
        """Called when an account is disabled or its role changes."""
        now = self._clock.now()
        open_req = self._repo.open_request_for_user(user_id)
        if open_req is None:
            return
        if open_req.status is RequestStatus.PENDING:
            open_req.status = RequestStatus.CANCELLED
        else:
            open_req.status = RequestStatus.REVOKED
        open_req.ended_at = now
        open_req.decision_note = "Closed because the account changed."
        self._repo.save(open_req)

    # -- queries -------------------------------------------------------------

    def get(self, request_id: int) -> PrivilegeRequest:
        return self._get(request_id)

    def list_for_user(self, user_id: int) -> List[PrivilegeRequest]:
        return self._repo.list_for_user(user_id)

    def list_pending(self) -> List[PrivilegeRequest]:
        return self._repo.list_by_status(RequestStatus.PENDING)

    def list_active(self) -> List[PrivilegeRequest]:
        now = self._clock.now()
        return [
            r for r in self._repo.list_by_status(RequestStatus.ACTIVE) if r.is_effective(now)
        ]

    def list_all(self, limit: int = 200) -> List[PrivilegeRequest]:
        return self._repo.list_all(limit)

    def open_request(self, user_id: int) -> Optional[PrivilegeRequest]:
        return self._repo.open_request_for_user(user_id)

    # -- helpers -------------------------------------------------------------

    def _get(self, request_id: int) -> PrivilegeRequest:
        req = self._repo.get(request_id)
        if req is None:
            raise NotFoundError("Privilege request not found.")
        return req

    def _decidable(self, approver: User, request_id: int, ctx: RequestContext) -> PrivilegeRequest:
        self._authz.require(
            approver, Permission.PRIVILEGE_APPROVE, ctx, target=f"privilege:{request_id}"
        )
        req = self._get(request_id)
        if req.requester_id == approver.id:
            self._audit.record(
                EventType.ACCESS_DENIED, Outcome.DENIED, actor=approver,
                target=f"privilege:{req.id}", ctx=ctx,
                details={"reason": "self_approval"},
            )
            raise PermissionDenied("You cannot decide on your own elevation request.")
        if req.status is not RequestStatus.PENDING:
            raise ConflictError(f"This request is already {req.status.value}.")
        return req
