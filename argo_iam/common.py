"""Types shared by every module: request context and the error hierarchy."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RequestContext:
    """Where a request came from. Recorded with audit events."""

    ip: str = "-"
    user_agent: str = "-"
    channel: str = "web"  # "web", "api" or "cli"


SYSTEM_CONTEXT = RequestContext(ip="-", user_agent="system", channel="system")


class IAMError(Exception):
    """Base class for errors the service layer reports to callers."""

    status_code = 400

    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


class ValidationError(IAMError):
    status_code = 400


class NotFoundError(IAMError):
    status_code = 404


class ConflictError(IAMError):
    status_code = 409


class PermissionDenied(IAMError):
    status_code = 403


class AuthenticationRequired(IAMError):
    status_code = 401
