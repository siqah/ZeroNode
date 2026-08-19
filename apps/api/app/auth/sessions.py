"""Browser sessions.

The session token lives in an httpOnly cookie, so script running in the page
cannot read it; an XSS bug can then abuse a session but cannot steal one. That
trade brings CSRF back, which is handled by binding a random value to the
session token and requiring it in a header on every state-changing request.
Machines keep using bearer tokens, which are not cookies and so are not exposed
to either problem.
"""

from __future__ import annotations

import secrets

from fastapi import Response

SESSION_COOKIE = "zn_session"
CSRF_COOKIE = "zn_csrf"
CSRF_HEADER = "x-csrf-token"
UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def new_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def set_session_cookies(
    response: Response, token: str, csrf: str, max_age: int, secure: bool
) -> None:
    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=max_age,
        httponly=True,
        secure=secure,
        samesite="lax",
        path="/",
    )
    # Readable by the dashboard so it can echo the value back in a header.
    response.set_cookie(
        CSRF_COOKIE,
        csrf,
        max_age=max_age,
        httponly=False,
        secure=secure,
        samesite="lax",
        path="/",
    )


def clear_session_cookies(response: Response) -> None:
    response.delete_cookie(SESSION_COOKIE, path="/")
    response.delete_cookie(CSRF_COOKIE, path="/")
