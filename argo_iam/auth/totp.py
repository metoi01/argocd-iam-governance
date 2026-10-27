"""Time-based one-time passwords (RFC 6238 over RFC 4226 HOTP).

Compatible with Google Authenticator, Microsoft Authenticator, 1Password etc.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
from datetime import datetime
from typing import Optional
from urllib.parse import quote, urlencode


class TOTP:
    def __init__(self, digits: int = 6, period: int = 30, window: int = 1):
        self.digits = digits
        self.period = period
        # Number of 30-second steps accepted either side of "now" (clock drift).
        self.window = window

    @staticmethod
    def generate_secret() -> str:
        return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")

    def time_step(self, at: datetime) -> int:
        return int(at.timestamp()) // self.period

    def code_at_step(self, secret: str, step: int) -> str:
        key = _decode_secret(secret)
        digest = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
        offset = digest[-1] & 0x0F
        value = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
        return str(value % (10**self.digits)).zfill(self.digits)

    def code_at(self, secret: str, at: datetime) -> str:
        return self.code_at_step(secret, self.time_step(at))

    def verify(
        self, secret: str, code: str, at: datetime, last_used_step: int = 0
    ) -> Optional[int]:
        """Return the matched time step, or None.

        Steps at or before ``last_used_step`` are rejected so a code cannot be
        replayed within its validity window.
        """
        code = (code or "").strip().replace(" ", "")
        if len(code) != self.digits or not code.isdigit():
            return None
        current = self.time_step(at)
        for step in range(current - self.window, current + self.window + 1):
            if step <= last_used_step:
                continue
            if hmac.compare_digest(self.code_at_step(secret, step), code):
                return step
        return None

    def provisioning_uri(self, secret: str, account: str, issuer: str) -> str:
        label = quote(f"{issuer}:{account}")
        query = urlencode(
            {
                "secret": secret,
                "issuer": issuer,
                "algorithm": "SHA1",
                "digits": self.digits,
                "period": self.period,
            }
        )
        return f"otpauth://totp/{label}?{query}"


def _decode_secret(secret: str) -> bytes:
    cleaned = secret.strip().replace(" ", "").upper()
    padding = "=" * (-len(cleaned) % 8)
    return base64.b32decode(cleaned + padding)
