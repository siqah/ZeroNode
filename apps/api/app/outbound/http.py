"""Outbound HTTP that can never take an incident down with it.

Ticketing and chat are conveniences around the workflow, not part of it. If
ServiceNow is down, the investigation still runs and the approval is still
sealed; the only thing lost is the notification, and that loss is logged rather
than raised.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

TIMEOUT = 8.0


async def post_json(
    url: str, payload: dict[str, Any], *, headers: dict[str, str] | None = None
) -> bool:
    """Returns whether it worked. Never raises, never logs the headers."""
    try:
        import httpx

        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            response = await client.post(url, json=payload, headers=headers or {})
        if response.status_code >= 400:
            logger.warning("outbound POST to %s returned %s", _safe(url), response.status_code)
            return False
        return True
    except Exception as exc:  # noqa: BLE001 - an outbound failure is never fatal here
        logger.warning("outbound POST to %s failed: %s", _safe(url), exc)
        return False


def _safe(url: str) -> str:
    """Webhook URLs are themselves credentials, so only the host is logged."""
    without_scheme = url.split("://", 1)[-1]
    return without_scheme.split("/", 1)[0] or "(unknown host)"
