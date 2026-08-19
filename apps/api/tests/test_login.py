"""Login: throttling, lockout, second factor and cookie issuance."""

from contextlib import asynccontextmanager

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.auth import store as user_store
from app.auth import totp
from app.auth.passwords import hash_password
from app.auth.ratelimit import SlidingWindow
from app.auth.sessions import CSRF_COOKIE, SESSION_COOKIE
from app.auth.tokens import decode_token
from app.routers.auth import router as auth_router

SECRET = "a-test-secret-that-is-long-enough"
PASSWORD = "correct-horse-battery"


class FakePool:
    @asynccontextmanager
    async def connection(self):
        yield None


class Users:
    """Stands in for the users table, with the same call surface the router uses."""

    def __init__(self, **overrides):
        self.row = {
            "email": "alice@example.com",
            "password_hash": hash_password(PASSWORD),
            "role": "approver",
            "active": True,
            "totp_secret": "",
            "totp_enabled": False,
            "failed_attempts": 0,
            "locked_until": None,
            **overrides,
        }
        self.failures = 0
        self.cleared = 0

    def install(self, monkeypatch):
        async def ensure(_conn):
            return None

        async def get_user(_conn, email):
            return self.row if email.lower() == self.row["email"] else None

        async def register_failure(_conn, _email, _threshold, _minutes):
            self.failures += 1
            return self.failures

        async def clear_failures(_conn, _email):
            self.cleared += 1

        async def set_totp_secret(_conn, _email, secret):
            self.row["totp_secret"] = secret
            self.row["totp_enabled"] = False

        async def set_totp_enabled(_conn, _email, enabled):
            self.row["totp_enabled"] = enabled

        for name, function in {
            "ensure_users_table": ensure,
            "get_user": get_user,
            "register_failure": register_failure,
            "clear_failures": clear_failures,
            "set_totp_secret": set_totp_secret,
            "set_totp_enabled": set_totp_enabled,
        }.items():
            monkeypatch.setattr(user_store, name, function)
        return self


@pytest.fixture
def app_client():
    app = FastAPI()
    app.include_router(auth_router)
    app.state.pool = FakePool()
    app.state.auth_enabled = True
    app.state.jwt_secret = SECRET
    app.state.jwt_ttl_minutes = 60
    app.state.service_token = ""
    app.state.mfa_required_for_approvers = True
    app.state.login_limiter = SlidingWindow(limit=5, window_seconds=60)
    with TestClient(app) as client:
        yield client


def login(client, **body):
    payload = {"email": "alice@example.com", "password": PASSWORD}
    payload.update(body)
    return client.post("/api/v1/auth/login", json=payload)


def test_a_good_login_sets_an_httponly_cookie_and_returns_no_token(monkeypatch, app_client):
    Users().install(monkeypatch)
    response = login(app_client)

    assert response.status_code == 200
    assert "access_token" not in response.json()
    session_cookie = response.cookies.get(SESSION_COOKIE)
    assert session_cookie
    assert "httponly" in response.headers["set-cookie"].lower()
    # The CSRF value is deliberately readable, and must match the session token.
    assert decode_token(session_cookie, SECRET).csrf == response.cookies.get(CSRF_COOKIE)


def test_a_wrong_password_counts_towards_lockout(monkeypatch, app_client):
    users = Users().install(monkeypatch)
    response = login(app_client, password="wrong")
    assert response.status_code == 401
    assert users.failures == 1


def test_an_unknown_address_does_not_reveal_itself(monkeypatch, app_client):
    users = Users().install(monkeypatch)
    response = login(app_client, email="nobody@example.com", password="wrong")
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid credentials"
    assert users.failures == 0


def test_a_locked_account_is_refused_even_with_the_right_password(monkeypatch, app_client):
    from datetime import UTC, datetime, timedelta

    Users(locked_until=datetime.now(UTC) + timedelta(minutes=5)).install(monkeypatch)
    response = login(app_client)
    assert response.status_code == 423
    assert "locked" in response.json()["detail"]


def test_repeated_attempts_are_throttled_before_they_reach_the_password_check(
    monkeypatch, app_client
):
    users = Users().install(monkeypatch)
    codes = [login(app_client, password="wrong").status_code for _ in range(7)]
    assert codes[:5] == [401] * 5
    assert codes[5:] == [429, 429]
    # The throttled attempts never became failed-attempt counts.
    assert users.failures == 5


def test_an_mfa_user_must_supply_a_code(monkeypatch, app_client):
    secret = totp.generate_secret()
    Users(totp_enabled=True, totp_secret=secret).install(monkeypatch)

    assert login(app_client).json()["detail"] == "mfa_required"
    assert login(app_client, totp_code="000000").status_code == 401

    response = login(app_client, totp_code=totp.code_at(secret))
    assert response.status_code == 200
    assert response.json()["mfa"] is True
    assert decode_token(response.cookies.get(SESSION_COOKIE), SECRET).mfa is True


def test_a_session_without_mfa_is_not_marked_as_such(monkeypatch, app_client):
    Users().install(monkeypatch)
    response = login(app_client)
    assert response.json()["mfa"] is False
    assert decode_token(response.cookies.get(SESSION_COOKIE), SECRET).mfa is False


def test_enrolment_needs_confirmation_before_it_counts(monkeypatch, app_client):
    users = Users().install(monkeypatch)
    csrf = {"x-csrf-token": login(app_client).json()["csrf_token"]}

    enrol = app_client.post("/api/v1/auth/mfa/enrol", headers=csrf)
    assert enrol.status_code == 200
    secret = enrol.json()["secret"]
    assert users.row["totp_enabled"] is False

    assert (
        app_client.post(
            "/api/v1/auth/mfa/activate", json={"totp_code": "000000"}, headers=csrf
        ).status_code
        == 400
    )
    activated = app_client.post(
        "/api/v1/auth/mfa/activate", json={"totp_code": totp.code_at(secret)}, headers=csrf
    )
    assert activated.status_code == 200
    assert activated.json()["reauthenticate"] is True
    assert users.row["totp_enabled"] is True


def test_enrolment_from_another_site_is_blocked_by_csrf(monkeypatch, app_client):
    Users().install(monkeypatch)
    login(app_client)
    assert app_client.post("/api/v1/auth/mfa/enrol").status_code == 403


def test_logout_clears_the_session(monkeypatch, app_client):
    Users().install(monkeypatch)
    login(app_client)
    assert app_client.get("/api/v1/auth/me").status_code == 200

    app_client.post("/api/v1/auth/logout")
    assert app_client.get("/api/v1/auth/me").status_code == 401


def test_me_reports_whether_this_session_may_approve(monkeypatch, app_client):
    secret = totp.generate_secret()
    Users(totp_enabled=True, totp_secret=secret).install(monkeypatch)

    login(app_client)  # no code: rejected, so still anonymous
    assert app_client.get("/api/v1/auth/me").status_code == 401

    login(app_client, totp_code=totp.code_at(secret))
    body = app_client.get("/api/v1/auth/me").json()
    assert body["can_approve"] is True
    assert body["mfa"] is True
