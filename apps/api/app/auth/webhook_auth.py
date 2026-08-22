from __future__ import annotations

from fastapi import HTTPException, Request, status

from app.auth.deps import current_principal
from app.auth.models import Principal, Role
from app.auth.ratelimit import SlidingWindow
from app.ingress.pagerduty import verify_pagerduty_signature


def _client_key(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request.client and request.client.host:
        return request.client.host
    return "unknown"


def require_webhook_principal(request: Request) -> Principal:
    principal = current_principal(request)
    if not principal.role.can(Role.OPERATOR):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Role '{principal.role.value}' cannot perform this action; "
            f"'{Role.OPERATOR.value}' or higher is required",
        )
    limiter: SlidingWindow | None = getattr(request.app.state, "webhook_limiter", None)
    if limiter is not None:
        allowed, retry_after = limiter.check(_client_key(request))
        if not allowed:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Webhook rate limit exceeded; retry in {retry_after}s",
                headers={"Retry-After": str(retry_after)},
            )
    return principal


async def verify_pagerduty_request(request: Request) -> Principal:
    settings = request.app.state.settings
    secret = getattr(settings, "pagerduty_webhook_secret", "") or ""
    signature = request.headers.get("x-pagerduty-signature", "")
    timestamp = request.headers.get("x-pagerduty-timestamp", "")
    body = await request.body()
    if secret and signature and timestamp:
        if not verify_pagerduty_signature(
            secret, body=body, timestamp=timestamp, signature=signature
        ):
            raise HTTPException(status_code=401, detail="Invalid PagerDuty webhook signature")
        request.state.raw_body = body
        return require_webhook_principal(request)
    return require_webhook_principal(request)
