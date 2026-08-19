"""TOTP, checked against the RFC 6238 test vectors."""

from app.auth import totp

# RFC 6238 appendix B, SHA-1 seed "12345678901234567890" in base32.
RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
VECTORS = {
    59: "287082",
    1111111109: "081804",
    1111111111: "050471",
    1234567890: "005924",
    2000000000: "279037",
    20000000000: "353130",
}


def test_codes_match_the_published_vectors():
    for timestamp, expected in VECTORS.items():
        assert totp.code_at(RFC_SECRET, timestamp) == expected


def test_a_code_verifies_within_the_drift_window():
    now = 1111111109
    code = totp.code_at(RFC_SECRET, now)
    assert totp.verify(RFC_SECRET, code, now) is True
    # One step either side, for a phone whose clock is slightly off.
    assert totp.verify(RFC_SECRET, code, now + totp.PERIOD) is True
    assert totp.verify(RFC_SECRET, code, now - totp.PERIOD) is True


def test_a_stale_code_is_refused():
    now = 1111111109
    code = totp.code_at(RFC_SECRET, now)
    assert totp.verify(RFC_SECRET, code, now + 5 * totp.PERIOD) is False


def test_malformed_codes_are_refused_without_raising():
    for candidate in ("", "12345", "abcdef", "1234567", None):
        assert totp.verify(RFC_SECRET, candidate) is False


def test_generated_secrets_are_usable_base32():
    secret = totp.generate_secret()
    assert totp.verify(secret, totp.code_at(secret)) is True


def test_the_provisioning_uri_carries_the_account_and_parameters():
    uri = totp.provisioning_uri("ABCDEFGH", "alice@example.com")
    assert uri.startswith("otpauth://totp/ZeroNode:alice%40example.com?")
    assert "secret=ABCDEFGH" in uri
    assert "digits=6" in uri and "period=30" in uri
