import time

import jwt
import pytest

from app.auth.models import Principal, Role
from app.auth.passwords import hash_password, verify_password
from app.auth.tokens import TokenError, decode_token, issue_token

SECRET = "test-secret-value"


def test_role_ladder():
    assert Role.APPROVER.can(Role.VIEWER)
    assert Role.ADMIN.can(Role.APPROVER)
    assert not Role.OPERATOR.can(Role.APPROVER)
    assert not Role.VIEWER.can(Role.OPERATOR)


def test_password_round_trip():
    hashed = hash_password("correct horse battery staple")
    assert verify_password(hashed, "correct horse battery staple")
    assert not verify_password(hashed, "wrong password")
    assert not verify_password("not-a-hash", "anything")


def test_token_round_trip():
    principal = Principal(subject="alice@example.com", role=Role.APPROVER)
    token, expires_in = issue_token(principal, SECRET, 60)
    decoded = decode_token(token, SECRET)
    assert decoded == principal
    assert expires_in == 3600


def test_token_signed_with_another_secret_is_rejected():
    token, _ = issue_token(Principal("alice@example.com", Role.ADMIN), SECRET, 60)
    with pytest.raises(TokenError):
        decode_token(token, "different-secret")


def test_expired_token_is_rejected():
    now = int(time.time())
    token = jwt.encode(
        {
            "sub": "alice@example.com",
            "role": "admin",
            "iss": "zeronode",
            "iat": now - 7200,
            "exp": now - 3600,
        },
        SECRET,
        algorithm="HS256",
    )
    with pytest.raises(TokenError):
        decode_token(token, SECRET)


def test_role_cannot_be_escalated_by_editing_the_payload():
    token, _ = issue_token(Principal("bob@example.com", Role.VIEWER), SECRET, 60)
    header, payload, signature = token.split(".")
    forged_payload = (
        jwt.encode({"sub": "bob@example.com", "role": "admin", "iss": "zeronode"}, "x")
        .split(".")[1]
    )
    with pytest.raises(TokenError):
        decode_token(f"{header}.{forged_payload}.{signature}", SECRET)


def test_token_without_a_role_is_rejected():
    token = jwt.encode({"sub": "alice@example.com", "iss": "zeronode"}, SECRET, algorithm="HS256")
    with pytest.raises(TokenError):
        decode_token(token, SECRET)
