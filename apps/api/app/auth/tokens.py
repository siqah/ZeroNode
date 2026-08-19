from __future__ import annotations

from datetime import UTC, datetime, timedelta

import jwt

from app.auth.models import Principal, Role

ALGORITHM = "HS256"
ISSUER = "zeronode"


class TokenError(Exception):
    pass


def issue_token(
    principal: Principal,
    secret: str,
    ttl_minutes: int,
    *,
    csrf: str = "",
    mfa: bool = False,
) -> tuple[str, int]:
    """Return (token, expires_in_seconds).

    `csrf` binds a cookie session to a value the browser must echo in a header;
    `mfa` records that this session was established with a second factor, so a
    later approval can require one without re-prompting.
    """
    now = datetime.now(UTC)
    expires = now + timedelta(minutes=ttl_minutes)
    payload = {
        "sub": principal.subject,
        "role": principal.role.value,
        "kind": principal.kind,
        "iss": ISSUER,
        "iat": int(now.timestamp()),
        "exp": int(expires.timestamp()),
        "mfa": mfa,
    }
    if csrf:
        payload["csrf"] = csrf
    return jwt.encode(payload, secret, algorithm=ALGORITHM), ttl_minutes * 60


def decode_token(token: str, secret: str) -> Principal:
    try:
        payload = jwt.decode(token, secret, algorithms=[ALGORITHM], issuer=ISSUER)
    except jwt.PyJWTError as exc:
        raise TokenError(str(exc)) from exc

    try:
        role = Role(payload["role"])
    except (KeyError, ValueError) as exc:
        raise TokenError("token carries no usable role") from exc

    subject = payload.get("sub")
    if not subject:
        raise TokenError("token carries no subject")
    return Principal(
        subject=subject,
        role=role,
        kind=payload.get("kind", "user"),
        mfa=bool(payload.get("mfa", False)),
        csrf=str(payload.get("csrf", "")),
    )
