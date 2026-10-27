"""Persistence for users (Repository pattern)."""

from __future__ import annotations

import sqlite3
from typing import List, Optional

from argo_iam.clock import from_iso, to_iso
from argo_iam.db import Database
from argo_iam.users.models import AccountStatus, Role, User


def _row_to_user(row: sqlite3.Row) -> User:
    return User(
        id=row["id"],
        username=row["username"],
        display_name=row["display_name"],
        email=row["email"],
        password_hash=row["password_hash"],
        role=Role(row["role"]),
        status=AccountStatus(row["status"]),
        created_at=from_iso(row["created_at"]),
        mfa_secret=row["mfa_secret"],
        mfa_enabled=bool(row["mfa_enabled"]),
        mfa_last_step=row["mfa_last_step"],
        failed_attempts=row["failed_attempts"],
        locked_until=from_iso(row["locked_until"]),
        last_login_at=from_iso(row["last_login_at"]),
    )


class UserRepository:
    def __init__(self, db: Database):
        self._db = db

    def get(self, user_id: int) -> Optional[User]:
        row = self._db.query_one("SELECT * FROM users WHERE id = ?", (user_id,))
        return _row_to_user(row) if row else None

    def get_by_username(self, username: str) -> Optional[User]:
        row = self._db.query_one(
            "SELECT * FROM users WHERE username = ? COLLATE NOCASE", (username,)
        )
        return _row_to_user(row) if row else None

    def list_all(self) -> List[User]:
        rows = self._db.query_all("SELECT * FROM users ORDER BY username")
        return [_row_to_user(r) for r in rows]

    def count_active_admins(self) -> int:
        row = self._db.query_one(
            "SELECT COUNT(*) AS n FROM users WHERE role = ? AND status = ?",
            (Role.ADMIN.value, AccountStatus.ACTIVE.value),
        )
        return int(row["n"])

    def add(self, user: User) -> User:
        cursor = self._db.execute(
            """INSERT INTO users (username, display_name, email, password_hash, role,
                   status, mfa_secret, mfa_enabled, mfa_last_step, failed_attempts,
                   locked_until, created_at, last_login_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                user.username,
                user.display_name,
                user.email,
                user.password_hash,
                user.role.value,
                user.status.value,
                user.mfa_secret,
                int(user.mfa_enabled),
                user.mfa_last_step,
                user.failed_attempts,
                to_iso(user.locked_until),
                to_iso(user.created_at),
                to_iso(user.last_login_at),
            ),
        )
        user.id = cursor.lastrowid
        return user

    def save(self, user: User) -> User:
        self._db.execute(
            """UPDATE users SET display_name = ?, email = ?, password_hash = ?, role = ?,
                   status = ?, mfa_secret = ?, mfa_enabled = ?, mfa_last_step = ?,
                   failed_attempts = ?, locked_until = ?, last_login_at = ?
               WHERE id = ?""",
            (
                user.display_name,
                user.email,
                user.password_hash,
                user.role.value,
                user.status.value,
                user.mfa_secret,
                int(user.mfa_enabled),
                user.mfa_last_step,
                user.failed_attempts,
                to_iso(user.locked_until),
                to_iso(user.last_login_at),
                user.id,
            ),
        )
        return user
