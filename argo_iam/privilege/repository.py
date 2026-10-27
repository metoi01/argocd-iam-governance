"""Persistence for privilege requests (Repository pattern)."""

from __future__ import annotations

import sqlite3
from datetime import datetime
from typing import List, Optional

from argo_iam.clock import from_iso, to_iso
from argo_iam.db import Database
from argo_iam.privilege.models import PrivilegeRequest, RequestStatus
from argo_iam.users.models import Role


def _row_to_request(row: sqlite3.Row) -> PrivilegeRequest:
    return PrivilegeRequest(
        id=row["id"],
        requester_id=row["requester_id"],
        base_role=Role(row["base_role"]),
        requested_role=Role(row["requested_role"]),
        justification=row["justification"],
        duration_minutes=row["duration_minutes"],
        status=RequestStatus(row["status"]),
        created_at=from_iso(row["created_at"]),
        decided_at=from_iso(row["decided_at"]),
        decided_by=row["decided_by"],
        decision_note=row["decision_note"],
        activated_at=from_iso(row["activated_at"]),
        expires_at=from_iso(row["expires_at"]),
        ended_at=from_iso(row["ended_at"]),
    )


class PrivilegeRepository:
    def __init__(self, db: Database):
        self._db = db

    def transaction(self):
        return self._db.transaction()

    def add(self, r: PrivilegeRequest) -> PrivilegeRequest:
        cursor = self._db.execute(
            """INSERT INTO privilege_requests (requester_id, base_role, requested_role,
                   justification, duration_minutes, status, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                r.requester_id, r.base_role.value, r.requested_role.value,
                r.justification, r.duration_minutes, r.status.value, to_iso(r.created_at),
            ),
        )
        r.id = cursor.lastrowid
        return r

    def save(self, r: PrivilegeRequest) -> PrivilegeRequest:
        self._db.execute(
            """UPDATE privilege_requests SET status = ?, decided_at = ?, decided_by = ?,
                   decision_note = ?, activated_at = ?, expires_at = ?, ended_at = ?
               WHERE id = ?""",
            (
                r.status.value, to_iso(r.decided_at), r.decided_by, r.decision_note,
                to_iso(r.activated_at), to_iso(r.expires_at), to_iso(r.ended_at), r.id,
            ),
        )
        return r

    def get(self, request_id: int) -> Optional[PrivilegeRequest]:
        row = self._db.query_one(
            "SELECT * FROM privilege_requests WHERE id = ?", (request_id,)
        )
        return _row_to_request(row) if row else None

    def list_for_user(self, user_id: int) -> List[PrivilegeRequest]:
        rows = self._db.query_all(
            "SELECT * FROM privilege_requests WHERE requester_id = ? ORDER BY id DESC",
            (user_id,),
        )
        return [_row_to_request(r) for r in rows]

    def list_by_status(self, *statuses: RequestStatus) -> List[PrivilegeRequest]:
        marks = ",".join("?" for _ in statuses)
        rows = self._db.query_all(
            f"SELECT * FROM privilege_requests WHERE status IN ({marks}) ORDER BY id DESC",
            [s.value for s in statuses],
        )
        return [_row_to_request(r) for r in rows]

    def list_all(self, limit: int = 200) -> List[PrivilegeRequest]:
        rows = self._db.query_all(
            "SELECT * FROM privilege_requests ORDER BY id DESC LIMIT ?", (limit,)
        )
        return [_row_to_request(r) for r in rows]

    def open_request_for_user(self, user_id: int) -> Optional[PrivilegeRequest]:
        row = self._db.query_one(
            """SELECT * FROM privilege_requests
               WHERE requester_id = ? AND status IN (?, ?) ORDER BY id DESC LIMIT 1""",
            (user_id, RequestStatus.PENDING.value, RequestStatus.ACTIVE.value),
        )
        return _row_to_request(row) if row else None

    def active_grant_for_user(self, user_id: int, now: datetime) -> Optional[PrivilegeRequest]:
        row = self._db.query_one(
            """SELECT * FROM privilege_requests
               WHERE requester_id = ? AND status = ? AND expires_at > ?
               ORDER BY expires_at DESC LIMIT 1""",
            (user_id, RequestStatus.ACTIVE.value, to_iso(now)),
        )
        return _row_to_request(row) if row else None

    def due_for_expiry(self, now: datetime) -> List[PrivilegeRequest]:
        rows = self._db.query_all(
            "SELECT * FROM privilege_requests WHERE status = ? AND expires_at <= ?",
            (RequestStatus.ACTIVE.value, to_iso(now)),
        )
        return [_row_to_request(r) for r in rows]
