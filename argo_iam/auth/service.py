"""Authentication Service: two-step login (password, then TOTP) with lockout.

Step 1 checks the password and, on success, issues a short-lived MFA
challenge. Step 2 checks a TOTP code against the challenge and only then asks
the Session Manager for a session. Users without an authenticator receive an
*enrolment* challenge and set one up as part of their first login.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from enum import Enum
from typing import Optional, Tuple

from argo_iam.audit.models import EventType, Outcome
from argo_iam.audit.service import AuditService
from argo_iam.auth.passwords import PasswordHasher
from argo_iam.auth.repository import ChallengeRepository, MfaChallenge
from argo_iam.auth.totp import TOTP
from argo_iam.clock import Clock
from argo_iam.common import RequestContext
from argo_iam.config import Settings
from argo_iam.sessions.models import Session
from argo_iam.sessions.service import SessionManager
from argo_iam.users.models import User
from argo_iam.users.repository import UserRepository

GENERIC_FAILURE = "Invalid username or password."
LOCKED_MESSAGE = "Too many failed attempts. The account is temporarily locked."


class LoginStatus(str, Enum):
    MFA_REQUIRED = "mfa_required"
    ENROLLMENT_REQUIRED = "mfa_enrollment_required"
    INVALID = "invalid_credentials"
    LOCKED = "locked"
    DISABLED = "disabled"


@dataclass(frozen=True)
class LoginOutcome:
    status: LoginStatus
    message: str = ""
    challenge_token: Optional[str] = None

    @property
    def needs_mfa(self) -> bool:
        return self.status in (LoginStatus.MFA_REQUIRED, LoginStatus.ENROLLMENT_REQUIRED)


@dataclass(frozen=True)
class MfaOutcome:
    success: bool
    message: str = ""
    session: Optional[Session] = None
    session_token: Optional[str] = None
    user: Optional[User] = None
    restart: bool = False  # the challenge is no longer usable; log in again


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class AuthenticationService:
    def __init__(
        self,
        users: UserRepository,
        challenges: ChallengeRepository,
        hasher: PasswordHasher,
        totp: TOTP,
        sessions: SessionManager,
        audit: AuditService,
        clock: Clock,
        settings: Settings,
    ):
        self._users = users
        self._challenges = challenges
        self._hasher = hasher
        self._totp = totp
        self._sessions = sessions
        self._audit = audit
        self._clock = clock
        self._settings = settings

    # -- step 1: password ----------------------------------------------------

    def begin_login(self, username: str, password: str, ctx: RequestContext) -> LoginOutcome:
        username = (username or "").strip()
        user = self._users.get_by_username(username) if username else None
        if user is None:
            self._hasher.verify_dummy(password or "")
            self._audit.record(
                EventType.LOGIN_FAILED, Outcome.FAILURE, actor_username=username[:64] or None,
                target="auth", ctx=ctx, details={"reason": "unknown_user"},
            )
            return LoginOutcome(LoginStatus.INVALID, GENERIC_FAILURE)

        now = self._clock.now()
        if user.is_locked(now):
            self._audit.record(
                EventType.LOGIN_BLOCKED, Outcome.DENIED, actor=user, target="auth", ctx=ctx,
                details={"reason": "locked", "locked_until": user.locked_until.isoformat()},
            )
            return LoginOutcome(LoginStatus.LOCKED, LOCKED_MESSAGE)

        if not self._hasher.verify(password or "", user.password_hash):
            return self._register_failure(user, ctx, stage="password")

        if not user.is_active:
            self._audit.record(
                EventType.LOGIN_BLOCKED, Outcome.DENIED, actor=user, target="auth", ctx=ctx,
                details={"reason": "disabled"},
            )
            return LoginOutcome(LoginStatus.DISABLED, "This account is disabled.")

        if self._hasher.needs_rehash(user.password_hash):
            user.password_hash = self._hasher.hash(password)
            self._users.save(user)

        enrol = not (user.mfa_enabled and user.mfa_secret)
        token = secrets.token_urlsafe(32)
        self._challenges.consume_all_for_user(user.id)
        self._challenges.add(
            MfaChallenge(
                id=None,
                token_hash=_hash(token),
                user_id=user.id,
                purpose="enroll" if enrol else "verify",
                pending_secret=TOTP.generate_secret() if enrol else None,
                created_at=now,
                expires_at=now + self._settings.mfa_challenge_ttl,
            )
        )
        self._audit.record(
            EventType.MFA_CHALLENGE_ISSUED, Outcome.INFO, actor=user, target="auth", ctx=ctx,
            details={"purpose": "enroll" if enrol else "verify"},
        )
        status = LoginStatus.ENROLLMENT_REQUIRED if enrol else LoginStatus.MFA_REQUIRED
        return LoginOutcome(status, challenge_token=token)

    # -- step 2: TOTP --------------------------------------------------------

    def challenge(self, token: Optional[str]) -> Optional[MfaChallenge]:
        """Return a still-usable challenge for ``token``."""
        if not token:
            return None
        c = self._challenges.get_by_token_hash(_hash(token))
        if (
            c is None
            or c.consumed
            or self._clock.now() >= c.expires_at
            or c.attempts >= self._settings.mfa_challenge_max_attempts
        ):
            return None
        return c

    def enrollment_details(self, token: str) -> Optional[Tuple[str, str, User]]:
        """(secret, otpauth URI, user) for an enrolment challenge."""
        c = self.challenge(token)
        if c is None or c.purpose != "enroll":
            return None
        user = self._users.get(c.user_id)
        uri = self._totp.provisioning_uri(
            c.pending_secret, user.username, self._settings.totp_issuer
        )
        return c.pending_secret, uri, user

    def verify_mfa(self, token: str, code: str, ctx: RequestContext) -> MfaOutcome:
        c = self.challenge(token)
        if c is None:
            return MfaOutcome(False, "Your sign-in attempt expired. Please log in again.",
                              restart=True)
        user = self._users.get(c.user_id)
        now = self._clock.now()
        if user is None or not user.is_active or user.is_locked(now):
            self._challenges.consume(c.id)
            return MfaOutcome(False, LOCKED_MESSAGE if user and user.is_locked(now)
                              else GENERIC_FAILURE, restart=True)

        enrolling = c.purpose == "enroll"
        secret = c.pending_secret if enrolling else user.mfa_secret
        step = self._totp.verify(secret, code, now, 0 if enrolling else user.mfa_last_step)
        if step is None:
            self._challenges.record_attempt(c.id)
            outcome = self._register_failure(user, ctx, stage="mfa")
            exhausted = c.attempts + 1 >= self._settings.mfa_challenge_max_attempts
            if outcome.status is LoginStatus.LOCKED or exhausted:
                self._challenges.consume(c.id)
                return MfaOutcome(False, outcome.message if outcome.status is LoginStatus.LOCKED
                                  else "Too many incorrect codes. Please log in again.",
                                  restart=True)
            return MfaOutcome(False, "That code is not valid. Check your authenticator and try again.")

        self._challenges.consume(c.id)
        if enrolling:
            user.mfa_secret = c.pending_secret
            user.mfa_enabled = True
            self._audit.record(EventType.MFA_ENROLLED, actor=user, target="auth", ctx=ctx)
        user.mfa_last_step = step
        user.failed_attempts = 0
        user.locked_until = None
        user.last_login_at = now
        self._users.save(user)
        self._audit.record(EventType.MFA_SUCCEEDED, actor=user, target="auth", ctx=ctx)
        session, session_token = self._sessions.create(user, ctx)
        self._audit.record(
            EventType.LOGIN_SUCCEEDED, actor=user, target=f"session:{session.id}", ctx=ctx,
            details={"factors": ["password", "totp"]},
        )
        return MfaOutcome(True, session=session, session_token=session_token, user=user)

    # -- helpers -------------------------------------------------------------

    def _register_failure(self, user: User, ctx: RequestContext, stage: str) -> LoginOutcome:
        now = self._clock.now()
        user.failed_attempts += 1
        event = EventType.LOGIN_FAILED if stage == "password" else EventType.MFA_FAILED
        self._audit.record(
            event, Outcome.FAILURE, actor=user, target="auth", ctx=ctx,
            details={"reason": f"bad_{stage}", "failed_attempts": user.failed_attempts},
        )
        if user.failed_attempts >= self._settings.max_failed_logins:
            user.failed_attempts = 0
            user.locked_until = now + self._settings.lockout_duration
            self._users.save(user)
            self._challenges.consume_all_for_user(user.id)
            self._audit.record(
                EventType.ACCOUNT_LOCKED, Outcome.DENIED, actor=user, target="auth", ctx=ctx,
                details={"locked_until": user.locked_until.isoformat()},
            )
            return LoginOutcome(LoginStatus.LOCKED, LOCKED_MESSAGE)
        self._users.save(user)
        return LoginOutcome(LoginStatus.INVALID, GENERIC_FAILURE)

    def current_code(self, user: User) -> Optional[str]:
        """Demo helper: the code an authenticator would show right now."""
        if not user.mfa_secret:
            return None
        return self._totp.code_at(user.mfa_secret, self._clock.now())
