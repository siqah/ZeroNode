"""Putting changes where the organisation already tracks them.

Deliberately a webhook rather than a ServiceNow or Jira client. Both expose a
JSON API that accepts a POST, both are usually fronted by an integration layer
anyway, and a vendor SDK per tool would be more code to maintain than the
feature is worth at this stage. The interface is what matters; a native client
can implement it later without anything else changing.
"""

from __future__ import annotations

import logging
from typing import Any, Protocol

from app.outbound.http import post_json

logger = logging.getLogger(__name__)


class TicketSink(Protocol):
    def describe(self) -> str: ...

    async def opened(self, thread_id: str, description: str, severity: str) -> None: ...

    async def commented(self, thread_id: str, text: str, context: dict[str, Any]) -> None: ...

    async def closed(self, thread_id: str, summary: str) -> None: ...


class NullTicketSink:
    """No ticketing. The incident still exists in the ledger and the dashboard."""

    def describe(self) -> str:
        return "none (changes are not recorded in a ticket system)"

    async def opened(self, thread_id: str, description: str, severity: str) -> None:
        logger.debug("ticket: would open %s", thread_id)

    async def commented(self, thread_id: str, text: str, context: dict[str, Any]) -> None:
        logger.debug("ticket: would comment on %s", thread_id)

    async def closed(self, thread_id: str, summary: str) -> None:
        logger.debug("ticket: would close %s", thread_id)


class WebhookTicketSink:
    def __init__(self, url: str, token: str = "", dashboard_url: str = "") -> None:
        self.url = url
        self.token = token
        self.dashboard_url = dashboard_url.rstrip("/")

    def describe(self) -> str:
        host = self.url.split("://", 1)[-1].split("/", 1)[0]
        return f"webhook to {host}"

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token}"} if self.token else {}

    def _link(self, thread_id: str) -> str:
        return f"{self.dashboard_url}/incidents/{thread_id}" if self.dashboard_url else ""

    async def opened(self, thread_id: str, description: str, severity: str) -> None:
        await post_json(
            self.url,
            {
                "event": "incident.opened",
                "incident": thread_id,
                "severity": severity,
                "summary": description,
                "url": self._link(thread_id),
            },
            headers=self._headers(),
        )

    async def commented(self, thread_id: str, text: str, context: dict[str, Any]) -> None:
        await post_json(
            self.url,
            {
                "event": "incident.updated",
                "incident": thread_id,
                "comment": text,
                "url": self._link(thread_id),
                **context,
            },
            headers=self._headers(),
        )

    async def closed(self, thread_id: str, summary: str) -> None:
        await post_json(
            self.url,
            {
                "event": "incident.closed",
                "incident": thread_id,
                "resolution": summary,
                "url": self._link(thread_id),
            },
            headers=self._headers(),
        )
