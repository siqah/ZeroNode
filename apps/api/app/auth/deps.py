"""Request-level authentication and role checks."""

from __future__ import annotations

import hmac
from collections.abc import Callable

from fastapi import HTTPException, Request, status

from app.auth.models import Principal, Role
from app.auth.sessions import CSRF_HEADER, SESSION_COOKIE, UNSAFE_METHODS
from app.auth.tokens import TokenError, decode_token

ANONYMOUS = Principal(subject="auth-disabled", role=Role.ADMIN, kind="anonymous")


def _bearer(request: Request) -> str | None:
    header = request.headers.get("authorization") or ""
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        return None
    return token.strip()


def _unauthorised(detail: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


def current_principal(request: Request) -> Principal:
    state = request.app.state
    if not getattr(state, "auth_enabled", True):
        return ANONYMOUS

    bearer = _bearer(request)
    if bearer:
        service_token = getattr(state, "service_token", "") or ""
        if service_token and hmac.compare_digest(bearer, service_token):
            return Principal(subject="service-token", role=Role.OPERATOR, kind="service")
        return _decode(bearer, state.jwt_secret)

    cookie = request.cookies.get(SESSION_COOKIE)
    if not cookie:
        raise _unauthorised("Not authenticated")

    principal = _decode(cookie, state.jwt_secret)
    _check_csrf(request, principal)
    return principal


def _decode(token: str, secret: str) -> Principal:
    try:
        return decode_token(token, secret)
    except TokenError as exc:
        raise _unauthorised(f"Invalid token: {exc}") from exc


def _check_csrf(request: Request, principal: Principal) -> None:
    """A cookie is attached by the browser to any request, including one made by
    another site. The header cannot be, so requiring it proves our page made the
    call. The expected value is carried in the session token itself, which means
    a stale or swapped cookie fails too."""
    if request.method.upper() not in UNSAFE_METHODS:
        return
    if not principal.csrf:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Session predates CSRF protection; sign in again",
        )
    supplied = request.headers.get(CSRF_HEADER, "")
    if not supplied or not hmac.compare_digest(supplied, principal.csrf):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Missing or invalid CSRF token",
        )


def require_role(
    required: Role, *, human_only: bool = False, mfa: bool = False
) -> Callable[..., Principal]:
    def dependency(request: Request) -> Principal:
        principal = current_principal(request)
        if not principal.role.can(required):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{principal.role.value}' cannot perform this action; "
                f"'{required.value}' or higher is required",
            )
        # An approval has to belong to a person. A machine credential must never be
        # able to sign one, whatever role it was granted.
        if human_only and principal.is_service:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="This action requires an authenticated human, not a machine credential",
            )
        if (
            mfa
            and principal.kind == "user"
            and getattr(request.app.state, "mfa_required_for_approvers", True)
            and not principal.mfa
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    "This action requires a second factor. Enrol at "
                    "/api/v1/auth/mfa/enrol and sign in again with your code."
                ),
            )
        return principal

    return dependency
