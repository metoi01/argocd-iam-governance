"""Password hashing with scrypt (memory-hard, standard library only).

Stored format: ``scrypt$<n>$<r>$<p>$<salt b64>$<hash b64>`` so parameters can
be raised later and old hashes still verify (and are flagged for rehash).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os


class PasswordHasher:
    def __init__(self, n: int = 2**14, r: int = 8, p: int = 1, dklen: int = 64):
        self.n, self.r, self.p, self.dklen = n, r, p, dklen
        # Verified when a username does not exist so that response time does not
        # reveal which usernames are real.
        self._dummy_hash = self.hash("dummy-password-for-timing")

    def hash(self, password: str) -> str:
        salt = os.urandom(16)
        digest = self._derive(password, salt, self.n, self.r, self.p, self.dklen)
        return "scrypt${}${}${}${}${}".format(
            self.n,
            self.r,
            self.p,
            base64.b64encode(salt).decode("ascii"),
            base64.b64encode(digest).decode("ascii"),
        )

    def verify(self, password: str, stored: str) -> bool:
        try:
            scheme, n, r, p, salt_b64, hash_b64 = stored.split("$")
            if scheme != "scrypt":
                return False
            salt = base64.b64decode(salt_b64)
            expected = base64.b64decode(hash_b64)
            actual = self._derive(password, salt, int(n), int(r), int(p), len(expected))
        except (ValueError, TypeError):
            return False
        return hmac.compare_digest(actual, expected)

    def verify_dummy(self, password: str) -> None:
        self.verify(password, self._dummy_hash)

    def needs_rehash(self, stored: str) -> bool:
        try:
            scheme, n, r, p, _, _ = stored.split("$")
        except ValueError:
            return True
        return scheme != "scrypt" or (int(n), int(r), int(p)) != (self.n, self.r, self.p)

    @staticmethod
    def _derive(password: str, salt: bytes, n: int, r: int, p: int, dklen: int) -> bytes:
        return hashlib.scrypt(
            password.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=dklen,
            maxmem=128 * r * (n + p + 2) + 1024 * 1024,
        )
