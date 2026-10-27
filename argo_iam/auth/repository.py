"""Persistence for MFA challenges issued between the password and TOTP steps."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from argo_iam.clock import from_iso, to_iso
from argo_iam.db import Database


@dataclass
class MfaChallenge:
    id: Optional[int]
    token_hash: str
    user_id: int
    purpose: str  # "verify" (has an authenticator) or "enroll" (must set one up)
    created_at: datetime
    expires_at: datetime
    pending_secret: Optional[str] = None
    attempts: int = 0
    consumed: bool = False


def _row_to_challenge(row: sqlite3.Row) -> MfaChallenge:
    return MfaChallenge(
        id=row["id"],
        token_hash=row["token_hash"],
        user_id=row["user_id"],
        purpose=row["purpose"],
        created_at=from_iso(row["created_at"]),
        expires_at=from_iso(row["expires_at"]),
        pending_secret=row["pending_secret"],
        attempts=row["attempts"],
        consumed=bool(row["consumed"]),
    )


class ChallengeRepository:
    def __init__(self, db: Database):
        self._db = db

    def add(self, c: MfaChallenge) -> MfaChallenge:
        cursor = self._db.execute(
            """INSERT INTO mfa_challenges (token_hash, user_id, purpose, pending_secret,
                   created_at, expires_at, attempts, consumed)
               VALUES (?, ?, ?, ?, ?, ?, 0, 0)""",
            (
                c.token_hash, c.user_id, c.purpose, c.pending_secret,
                to_iso(c.created_at), to_iso(c.expires_at),
            ),
        )
        c.id = cursor.lastrowid
        return c

    def get_by_token_hash(self, token_hash: str) -> Optional[MfaChallenge]:
        row = self._db.query_one(
            "SELECT * FROM mfa_challenges WHERE token_hash = ?", (token_hash,)
        )
        return _row_to_challenge(row) if row else None

    def record_attempt(self, challenge_id: int) -> None:
        self._db.execute(
            "UPDATE mfa_challenges SET attempts = attempts + 1 WHERE id = ?", (challenge_id,)
        )

    def consume(self, challenge_id: int) -> None:
        self._db.execute(
            "UPDATE mfa_challenges SET consumed = 1 WHERE id = ?", (challenge_id,)
        )

    def consume_all_for_user(self, user_id: int) -> None:
        self._db.execute(
            "UPDATE mfa_challenges SET consumed = 1 WHERE user_id = ? AND consumed = 0",
            (user_id,),
        )
