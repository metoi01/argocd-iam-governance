"""Persistence for sessions (Repository pattern)."""

from __future__ import annotations

import sqlite3
from datetime import datetime
from typing import List, Optional

from argo_iam.clock import from_iso, to_iso
from argo_iam.db import Database
from argo_iam.sessions.models import EndReason, Session


def _row_to_session(row: sqlite3.Row) -> Session:
    return Session(
        id=row["id"],
        token_hash=row["token_hash"],
        user_id=row["user_id"],
        created_at=from_iso(row["created_at"]),
        last_seen_at=from_iso(row["last_seen_at"]),
        expires_at=from_iso(row["expires_at"]),
        ip=row["ip"],
        user_agent=row["user_agent"],
        channel=row["channel"],
        ended_at=from_iso(row["ended_at"]),
        end_reason=EndReason(row["end_reason"]) if row["end_reason"] else None,
        ended_by=row["ended_by"],
    )


class SessionRepository:
    def __init__(self, db: Database):
        self._db = db

    def add(self, s: Session) -> Session:
        self._db.execute(
            """INSERT INTO sessions (id, token_hash, user_id, created_at, last_seen_at,
                   expires_at, ip, user_agent, channel)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                s.id, s.token_hash, s.user_id, to_iso(s.created_at),
                to_iso(s.last_seen_at), to_iso(s.expires_at), s.ip, s.user_agent,
                s.channel,
            ),
        )
        return s

    def get(self, session_id: str) -> Optional[Session]:
        row = self._db.query_one("SELECT * FROM sessions WHERE id = ?", (session_id,))
        return _row_to_session(row) if row else None

    def get_by_token_hash(self, token_hash: str) -> Optional[Session]:
        row = self._db.query_one(
            "SELECT * FROM sessions WHERE token_hash = ?", (token_hash,)
        )
        return _row_to_session(row) if row else None

    def list_for_user(self, user_id: int, include_ended: bool = False) -> List[Session]:
        sql = "SELECT * FROM sessions WHERE user_id = ?"
        if not include_ended:
            sql += " AND ended_at IS NULL"
        rows = self._db.query_all(sql + " ORDER BY created_at DESC", (user_id,))
        return [_row_to_session(r) for r in rows]

    def list_open(self) -> List[Session]:
        rows = self._db.query_all(
            "SELECT * FROM sessions WHERE ended_at IS NULL ORDER BY last_seen_at DESC"
        )
        return [_row_to_session(r) for r in rows]

    def touch(self, session_id: str, at: datetime) -> None:
        self._db.execute(
            "UPDATE sessions SET last_seen_at = ? WHERE id = ?", (to_iso(at), session_id)
        )

    def end(self, session_id: str, at: datetime, reason: EndReason, by: Optional[str]) -> None:
        self._db.execute(
            """UPDATE sessions SET ended_at = ?, end_reason = ?, ended_by = ?
               WHERE id = ? AND ended_at IS NULL""",
            (to_iso(at), reason.value, by, session_id),
        )
