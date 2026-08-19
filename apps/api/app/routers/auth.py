from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, EmailStr, Field

from app.auth import store as user_store
from app.auth import totp
from app.auth.deps import current_principal, require_role
from app.auth.models import Principal, Role
from app.auth.passwords import hash_password, verify_password
from app.auth.sessions import clear_session_cookies, new_csrf_token, set_session_cookies
from app.auth.tokens import issue_token
from app.config import settings

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


class LoginBody(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1)
    totp_code: str = ""


class CreateUserBody(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12)
    role: Role = Role.VIEWER


class CodeBody(BaseModel):
    totp_code: str = Field(min_length=6, max_length=8)


def _pool_or_503(request: Request):
    pool = getattr(request.app.state, "pool", None)
    if pool is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="User store unavailable: the API has no database connection",
        )
    return pool


def _throttle(request: Request, email: str) -> None:
    limiter = getattr(request.app.state, "login_limiter", None)
    if limiter is None:
        return
    client = request.client.host if request.client else "unknown"
    for key in (f"ip:{client}", f"user:{email.lower()}"):
        allowed, retry_after = limiter.check(key)
        if not allowed:
            logger.warning("login throttled for %s", key)
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many login attempts; try again shortly",
                headers={"Retry-After": str(retry_after)},
            )


def _locked(user: dict) -> bool:
    locked_until = user.get("locked_until")
    return bool(locked_until and locked_until > datetime.now(UTC))


@router.post("/login")
async def login(body: LoginBody, request: Request, response: Response):
    pool = _pool_or_503(request)
    _throttle(request, body.email)

    async with pool.connection() as conn:
        await user_store.ensure_users_table(conn)
        user = await user_store.get_user(conn, body.email)

        # Hash even when the user is unknown, so a missing account and a wrong
        # password take the same time to answer.
        stored = user["password_hash"] if user else hash_password("timing-equaliser")
        valid = await asyncio.to_thread(verify_password, stored, body.password)

        if user and _locked(user):
            logger.warning("login attempt on locked account %s", body.email)
            raise HTTPException(
                status_code=status.HTTP_423_LOCKED,
                detail="Account is temporarily locked after repeated failures",
            )

        if not user or not valid or not user["active"]:
            if user:
                count = await user_store.register_failure(
                    conn,
                    body.email,
                    settings.login_lock_threshold,
                    settings.login_lock_minutes,
                )
                logger.warning("failed login for %s (%d consecutive)", body.email, count)
            else:
                logger.warning("failed login for unknown address %s", body.email)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials"
            )

        if user["totp_enabled"]:
            if not body.totp_code:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="mfa_required",
                )
            if not totp.verify(user["totp_secret"], body.totp_code):
                await user_store.register_failure(
                    conn,
                    body.email,
                    settings.login_lock_threshold,
                    settings.login_lock_minutes,
                )
                logger.warning("failed second factor for %s", body.email)
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials"
                )

        await user_store.clear_failures(conn, body.email)

    principal = Principal(subject=user["email"], role=Role(user["role"]))
    csrf = new_csrf_token()
    token, expires_in = issue_token(
        principal,
        request.app.state.jwt_secret,
        request.app.state.jwt_ttl_minutes,
        csrf=csrf,
        mfa=bool(user["totp_enabled"]),
    )
    set_session_cookies(response, token, csrf, expires_in, settings.cookie_secure)

    # The token is not returned to the browser: it lives in an httpOnly cookie so
    # that page script cannot read it. Machine clients use SERVICE_TOKEN instead.
    return {
        "email": principal.subject,
        "role": principal.role.value,
        "expires_in": expires_in,
        "csrf_token": csrf,
        "mfa": bool(user["totp_enabled"]),
    }


@router.post("/logout")
async def logout(response: Response):
    clear_session_cookies(response)
    return {"ok": True}


@router.get("/me")
async def me(request: Request, principal: Principal = Depends(current_principal)):
    mfa_required = getattr(request.app.state, "mfa_required_for_approvers", True)
    can_approve = (
        principal.role.can(Role.APPROVER)
        and principal.kind != "service"
        and (principal.mfa or not mfa_required or principal.kind == "anonymous")
    )
    return {
        "email": principal.subject,
        "role": principal.role.value,
        "kind": principal.kind,
        "mfa": principal.mfa,
        "mfa_required_to_approve": mfa_required,
        "can_approve": can_approve,
    }


@router.post("/mfa/enrol")
async def enrol_mfa(request: Request, principal: Principal = Depends(current_principal)):
    """Issue a secret. It only becomes usable once a code from it is confirmed."""
    if principal.kind != "user":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only a signed-in person can enrol a second factor",
        )
    pool = _pool_or_503(request)
    secret = totp.generate_secret()
    async with pool.connection() as conn:
        await user_store.ensure_users_table(conn)
        await user_store.set_totp_secret(conn, principal.subject, secret)
    return {
        "secret": secret,
        "otpauth_uri": totp.provisioning_uri(secret, principal.subject),
    }


@router.post("/mfa/activate")
async def activate_mfa(
    body: CodeBody, request: Request, principal: Principal = Depends(current_principal)
):
    pool = _pool_or_503(request)
    async with pool.connection() as conn:
        await user_store.ensure_users_table(conn)
        user = await user_store.get_user(conn, principal.subject)
        if not user or not user["totp_secret"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="Enrol before activating"
            )
        if not totp.verify(user["totp_secret"], body.totp_code):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="That code is not valid"
            )
        await user_store.set_totp_enabled(conn, principal.subject, True)

    logger.info("second factor activated for %s", principal.subject)
    # The current session predates the second factor, so it must be re-established
    # before it counts as MFA-backed.
    return {"ok": True, "reauthenticate": True}


@router.post("/mfa/disable")
async def disable_mfa(
    body: CodeBody, request: Request, principal: Principal = Depends(current_principal)
):
    pool = _pool_or_503(request)
    async with pool.connection() as conn:
        await user_store.ensure_users_table(conn)
        user = await user_store.get_user(conn, principal.subject)
        if not user or not user["totp_enabled"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="No second factor is active"
            )
        if not totp.verify(user["totp_secret"], body.totp_code):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="That code is not valid"
            )
        await user_store.set_totp_enabled(conn, principal.subject, False)
    logger.warning("second factor removed for %s", principal.subject)
    return {"ok": True}


@router.get("/users")
async def list_users(request: Request, _: Principal = Depends(require_role(Role.ADMIN))):
    pool = _pool_or_503(request)
    async with pool.connection() as conn:
        await user_store.ensure_users_table(conn)
        return {"users": await user_store.list_users(conn)}


@router.post("/users", status_code=status.HTTP_201_CREATED)
async def create_user(
    body: CreateUserBody,
    request: Request,
    admin: Principal = Depends(require_role(Role.ADMIN)),
):
    pool = _pool_or_503(request)
    password_hash = await asyncio.to_thread(hash_password, body.password)
    async with pool.connection() as conn:
        await user_store.ensure_users_table(conn)
        created = await user_store.create_if_absent(conn, body.email, password_hash, body.role)
    if not created:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="User exists")
    logger.info("user %s created by %s", body.email, admin.subject)
    return {"email": body.email, "role": body.role.value}


@router.post("/users/{email}/unlock")
async def unlock_user(
    email: str, request: Request, admin: Principal = Depends(require_role(Role.ADMIN))
):
    pool = _pool_or_503(request)
    async with pool.connection() as conn:
        await user_store.ensure_users_table(conn)
        await user_store.clear_failures(conn, email)
    logger.info("account %s unlocked by %s", email, admin.subject)
    return {"ok": True}
