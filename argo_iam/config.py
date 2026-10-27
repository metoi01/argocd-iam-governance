"""Runtime settings, read from environment variables with safe defaults."""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field
from datetime import timedelta


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    return int(raw) if raw else default


@dataclass(frozen=True)
class Settings:
    database_path: str = "instance/argo_iam.sqlite3"
    secret_key: str = field(default_factory=lambda: secrets.token_hex(32))

    # Sessions
    session_idle_timeout: timedelta = timedelta(minutes=30)
    session_absolute_timeout: timedelta = timedelta(hours=8)
    session_cookie_name: str = "argo_iam_session"
    cookie_secure: bool = False

    # Authentication
    mfa_challenge_ttl: timedelta = timedelta(minutes=5)
    mfa_challenge_max_attempts: int = 5
    max_failed_logins: int = 5
    lockout_duration: timedelta = timedelta(minutes=15)
    min_password_length: int = 12
    totp_issuer: str = "Argo IAM Governance"

    # Privilege elevation
    min_privilege_minutes: int = 15
    max_privilege_minutes: int = 240
    min_justification_length: int = 15

    # Argo CD integration
    argocd_mode: str = "mock"  # "mock" or "http"
    argocd_url: str = ""
    argocd_token: str = ""
    argocd_verify_tls: bool = True

    # Enables demo helpers such as printing the current TOTP code of a seeded user.
    demo_mode: bool = True

    @classmethod
    def from_env(cls) -> "Settings":
        defaults = cls()
        return cls(
            database_path=os.environ.get("ARGO_IAM_DB", defaults.database_path),
            secret_key=os.environ.get("ARGO_IAM_SECRET_KEY") or defaults.secret_key,
            session_idle_timeout=timedelta(
                minutes=_env_int("ARGO_IAM_SESSION_IDLE_MINUTES", 30)
            ),
            session_absolute_timeout=timedelta(
                minutes=_env_int("ARGO_IAM_SESSION_ABSOLUTE_MINUTES", 480)
            ),
            cookie_secure=_env_bool("ARGO_IAM_COOKIE_SECURE", False),
            max_failed_logins=_env_int("ARGO_IAM_MAX_FAILED_LOGINS", 5),
            lockout_duration=timedelta(
                minutes=_env_int("ARGO_IAM_LOCKOUT_MINUTES", 15)
            ),
            max_privilege_minutes=_env_int("ARGO_IAM_MAX_PRIVILEGE_MINUTES", 240),
            argocd_mode=os.environ.get("ARGO_IAM_ARGOCD_MODE", "mock"),
            argocd_url=os.environ.get("ARGOCD_SERVER_URL", ""),
            argocd_token=os.environ.get("ARGOCD_AUTH_TOKEN", ""),
            argocd_verify_tls=_env_bool("ARGOCD_VERIFY_TLS", True),
            demo_mode=_env_bool("ARGO_IAM_DEMO_MODE", True),
        )
