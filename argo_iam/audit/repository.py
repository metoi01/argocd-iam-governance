"""Append-only audit store (Repository pattern).

The repository intentionally offers no update or delete operation.
"""

from __future__ import annotations

import json
import sqlite3
from typing import Iterator, List, Optional

from argo_iam.audit.models import AuditEvent, AuditQuery, EventType, Outcome
from argo_iam.clock import from_iso, to_iso
from argo_iam.db import Database

GENESIS_HASH = "0" * 64


def _row_to_event(row: sqlite3.Row) -> AuditEvent:
    return AuditEvent(
        id=row["id"],
        occurred_at=from_iso(row["occurred_at"]),
        event_type=EventType(row["event_type"]),
        outcome=Outcome(row["outcome"]),
        actor_id=row["actor_id"],
        actor_username=row["actor_username"],
        target=row["target"],
        ip=row["ip"],
        channel=row["channel"],
        details=json.loads(row["details"]),
        prev_hash=row["prev_hash"],
        hash=row["hash"],
    )


class AuditRepository:
    def __init__(self, db: Database):
        self._db = db

    def transaction(self):
        return self._db.transaction()

    def last_hash(self) -> str:
        row = self._db.query_one("SELECT hash FROM audit_events ORDER BY id DESC LIMIT 1")
        return row["hash"] if row else GENESIS_HASH

    def append(self, event: AuditEvent) -> AuditEvent:
        cursor = self._db.execute(
            """INSERT INTO audit_events (occurred_at, event_type, outcome, actor_id,
                   actor_username, target, ip, channel, details, prev_hash, hash)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                to_iso(event.occurred_at),
                event.event_type.value,
                event.outcome.value,
                event.actor_id,
                event.actor_username,
                event.target,
                event.ip,
                event.channel,
                json.dumps(event.details, sort_keys=True),
                event.prev_hash,
                event.hash,
            ),
        )
        event.id = cursor.lastrowid
        return event

    def query(self, q: AuditQuery) -> List[AuditEvent]:
        clauses, params = [], []
        if q.event_type:
            if "." in q.event_type:
                clauses.append("event_type = ?")
                params.append(q.event_type)
            else:
                clauses.append("event_type LIKE ?")
                params.append(q.event_type + ".%")
        if q.username:
            clauses.append("actor_username = ? COLLATE NOCASE")
            params.append(q.username)
        if q.outcome:
            clauses.append("outcome = ?")
            params.append(q.outcome)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        rows = self._db.query_all(
            f"SELECT * FROM audit_events {where} ORDER BY id DESC LIMIT ?",
            (*params, max(1, min(q.limit, 5000))),
        )
        return [_row_to_event(r) for r in rows]

    def iter_all(self) -> Iterator[AuditEvent]:
        for row in self._db.query_all("SELECT * FROM audit_events ORDER BY id ASC"):
            yield _row_to_event(row)

    def count(self, event_type: Optional[EventType] = None) -> int:
        if event_type is None:
            row = self._db.query_one("SELECT COUNT(*) AS n FROM audit_events")
        else:
            row = self._db.query_one(
                "SELECT COUNT(*) AS n FROM audit_events WHERE event_type = ?",
                (event_type.value,),
            )
        return int(row["n"])
