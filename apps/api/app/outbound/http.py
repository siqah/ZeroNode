"""Outbound HTTP that can never take an incident down with it.

Ticketing and chat are conveniences around the workflow, not part of it. If
ServiceNow is down, the investigation still runs and the approval is still
sealed; the only thing lost is the notification, and that loss is logged rather
than raised.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

logger = logging.getLogger(__name__)

TIMEOUT = 8.0


async def post_json(
    url: str,
    payload: dict[str, Any],
    *,
    headers: dict[str, str] | None = None,
    max_retries: int | None = None,
    retry_backoff_seconds: float | None = None,
) -> bool:
    """Returns whether it worked. Never raises, never logs the headers."""
    from app.config import settings

    retry_limit = settings.outbound_max_retries if max_retries is None else max_retries
    attempts = max(int(retry_limit), 0)
    backoff = float(
        retry_backoff_seconds
        if retry_backoff_seconds is not None
        else settings.outbound_retry_backoff_seconds
    )
    host = _safe(url)

    for attempt in range(attempts + 1):
        try:
            import httpx

            async with httpx.AsyncClient(timeout=TIMEOUT) as client:
                response = await client.post(url, json=payload, headers=headers or {})
            if response.status_code < 400:
                if attempt:
                    logger.info("outbound POST to %s succeeded on retry %s", host, attempt)
                return True
            if response.status_code < 500 or attempt >= attempts:
                logger.warning(
                    "outbound POST to %s returned %s", host, response.status_code
                )
                return False
            logger.warning(
                "outbound POST to %s returned %s; retrying (%s/%s)",
                host,
                response.status_code,
                attempt + 1,
                attempts,
            )
        except Exception as exc:  # noqa: BLE001 - an outbound failure is never fatal here
            if attempt >= attempts:
                logger.warning("outbound POST to %s failed: %s", host, exc)
                return False
            logger.warning(
                "outbound POST to %s failed: %s; retrying (%s/%s)",
                host,
                exc,
                attempt + 1,
                attempts,
            )

        await asyncio.sleep(backoff * (2**attempt))

    return False


def _safe(url: str) -> str:
    """Webhook URLs are themselves credentials, so only the host is logged."""
    without_scheme = url.split("://", 1)[-1]
    return without_scheme.split("/", 1)[0] or "(unknown host)"
