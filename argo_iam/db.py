"""SQLite persistence shared by the repositories.

Only repository classes talk to this module; services never write SQL.
"""

from __future__ import annotations

import os
import sqlite3
import threading
from contextlib import contextmanager
from typing import Any, Iterable, Iterator, List, Optional

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT    NOT NULL UNIQUE,
    display_name    TEXT    NOT NULL,
    email           TEXT    NOT NULL,
    password_hash   TEXT    NOT NULL,
    role            TEXT    NOT NULL,
    status          TEXT    NOT NULL,
    mfa_secret      TEXT,
    mfa_enabled     INTEGER NOT NULL DEFAULT 0,
    mfa_last_step   INTEGER NOT NULL DEFAULT 0,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until    TEXT,
    created_at      TEXT    NOT NULL,
    last_login_at   TEXT
);

CREATE TABLE IF NOT EXISTS mfa_challenges (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash     TEXT    NOT NULL UNIQUE,
    user_id        INTEGER NOT NULL REFERENCES users(id),
    purpose        TEXT    NOT NULL,
    pending_secret TEXT,
    created_at     TEXT    NOT NULL,
    expires_at     TEXT    NOT NULL,
    attempts       INTEGER NOT NULL DEFAULT 0,
    consumed       INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS sessions (
    id           TEXT    PRIMARY KEY,
    token_hash   TEXT    NOT NULL UNIQUE,
    user_id      INTEGER NOT NULL REFERENCES users(id),
    created_at   TEXT    NOT NULL,
    last_seen_at TEXT    NOT NULL,
    expires_at   TEXT    NOT NULL,
    ended_at     TEXT,
    end_reason   TEXT,
    ended_by     TEXT,
    ip           TEXT    NOT NULL,
    user_agent   TEXT    NOT NULL,
    channel      TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

CREATE TABLE IF NOT EXISTS privilege_requests (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    requester_id     INTEGER NOT NULL REFERENCES users(id),
    base_role        TEXT    NOT NULL,
    requested_role   TEXT    NOT NULL,
    justification    TEXT    NOT NULL,
    duration_minutes INTEGER NOT NULL,
    status           TEXT    NOT NULL,
    created_at       TEXT    NOT NULL,
    decided_at       TEXT,
    decided_by       INTEGER REFERENCES users(id),
    decision_note    TEXT,
    activated_at     TEXT,
    expires_at       TEXT,
    ended_at         TEXT
);
CREATE INDEX IF NOT EXISTS idx_privilege_requester ON privilege_requests(requester_id);

CREATE TABLE IF NOT EXISTS audit_events (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    occurred_at    TEXT NOT NULL,
    event_type     TEXT NOT NULL,
    outcome        TEXT NOT NULL,
    actor_id       INTEGER,
    actor_username TEXT,
    target         TEXT,
    ip             TEXT NOT NULL,
    channel        TEXT NOT NULL,
    details        TEXT NOT NULL,
    prev_hash      TEXT NOT NULL,
    hash           TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_type ON audit_events(event_type);
"""


class Database:
    """A single SQLite connection guarded by a re-entrant lock.

    A prototype serves a handful of users, so serialising access is simpler
    and safer than a pool. ``transaction()`` groups writes atomically.
    """

    def __init__(self, path: str):
        self.path = path
        if path != ":memory:":
            directory = os.path.dirname(os.path.abspath(path))
            os.makedirs(directory, exist_ok=True)
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._lock = threading.RLock()
        self._depth = 0
        with self._lock:
            self._conn.executescript(SCHEMA)
            self._conn.commit()

    @contextmanager
    def transaction(self) -> Iterator["Database"]:
        with self._lock:
            self._depth += 1
            try:
                yield self
                if self._depth == 1:
                    self._conn.commit()
            except BaseException:
                if self._depth == 1:
                    self._conn.rollback()
                raise
            finally:
                self._depth -= 1

    def execute(self, sql: str, params: Iterable[Any] = ()) -> sqlite3.Cursor:
        with self.transaction():
            return self._conn.execute(sql, tuple(params))

    def query_one(self, sql: str, params: Iterable[Any] = ()) -> Optional[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(sql, tuple(params)).fetchone()

    def query_all(self, sql: str, params: Iterable[Any] = ()) -> List[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(sql, tuple(params)).fetchall()

    def close(self) -> None:
        with self._lock:
            self._conn.close()
