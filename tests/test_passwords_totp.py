from datetime import datetime, timezone

from argo_iam.auth.passwords import PasswordHasher
from argo_iam.auth.totp import TOTP

# RFC 6238 Appendix B shared secret "12345678901234567890" in base32.
RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"


def test_password_hash_roundtrip_and_salting():
    h = PasswordHasher(n=2**10)
    a, b = h.hash("Correct-Horse-1"), h.hash("Correct-Horse-1")
    assert a != b  # random salt
    assert h.verify("Correct-Horse-1", a)
    assert not h.verify("correct-horse-1", a)
    assert not h.verify("anything", "not-a-hash")


def test_password_rehash_detection():
    old = PasswordHasher(n=2**10).hash("pw-Value-123")
    assert PasswordHasher(n=2**11).needs_rehash(old)
    assert not PasswordHasher(n=2**10).needs_rehash(old)


def test_totp_matches_rfc6238_vectors():
    totp8 = TOTP(digits=8)
    vectors = {59: "94287082", 1111111109: "07081804", 1234567890: "89005924",
               2000000000: "69279037"}
    for ts, expected in vectors.items():
        at = datetime.fromtimestamp(ts, tz=timezone.utc)
        assert totp8.code_at(RFC_SECRET, at) == expected


def test_totp_verify_window_and_replay_protection():
    totp = TOTP()
    secret = TOTP.generate_secret()
    now = datetime(2026, 3, 1, 12, 0, 0, tzinfo=timezone.utc)
    code = totp.code_at(secret, now)
    step = totp.verify(secret, code, now)
    assert step == totp.time_step(now)
    # one step of clock drift is tolerated
    assert totp.verify(secret, code, now.replace(second=29)) is not None
    # replaying the same step is rejected
    assert totp.verify(secret, code, now, last_used_step=step) is None
    # wrong shape / wrong code
    assert totp.verify(secret, "12345", now) is None
    assert totp.verify(secret, "abcdef", now) is None


def test_provisioning_uri_is_authenticator_compatible():
    uri = TOTP().provisioning_uri("JBSWY3DPEHPK3PXP", "alice", "Argo IAM")
    assert uri.startswith("otpauth://totp/Argo%20IAM%3Aalice?")
    assert "secret=JBSWY3DPEHPK3PXP" in uri and "issuer=Argo+IAM" in uri
