"""Telling someone a change is waiting for them.

Nobody watches a dashboard, so an approval gate with no notification is a
system that stops at the gate. The payload uses `text`, which Slack, Mattermost
and Teams all accept, and includes a direct link because an alert that makes
someone go looking is an alert that gets read later.
"""

from __future__ import annotations

import logging
from typing import Any, Protocol

from app.outbound.http import post_json

logger = logging.getLogger(__name__)


class Notifier(Protocol):
    def describe(self) -> str: ...

    async def send(self, text: str, context: dict[str, Any] | None = None) -> None: ...


class NullNotifier:
    def describe(self) -> str:
        return "none (pending approvals are only visible in the dashboard)"

    async def send(self, text: str, context: dict[str, Any] | None = None) -> None:
        logger.info("notification (not delivered, no webhook configured): %s", text)


class WebhookNotifier:
    def __init__(self, url: str, token: str = "") -> None:
        self.url = url
        self.token = token

    def describe(self) -> str:
        host = self.url.split("://", 1)[-1].split("/", 1)[0]
        return f"webhook to {host}"

    async def send(self, text: str, context: dict[str, Any] | None = None) -> None:
        headers = {"Authorization": f"Bearer {self.token}"} if self.token else {}
        await post_json(self.url, {"text": text, **(context or {})}, headers=headers)


def pending_approval_message(
    thread_id: str,
    actions: list[dict[str, Any]],
    dashboard_url: str,
    window_reason: str = "",
    alert_flags: list[str] | None = None,
) -> str:
    """Everything needed to decide whether to get out of bed, in one message."""
    command = next((str(a.get("command", "")) for a in actions if a.get("command")), "(none)")
    device = next((str(a.get("device", "")) for a in actions if a.get("device")), "?")
    verified = all(a.get("verified") for a in actions) if actions else False

    parts = [
        f"ZeroNode {thread_id}: a change on {device} is waiting for approval.",
        f"Proposed: {command}",
        "Simulation: passed" if verified else "Simulation: DID NOT PASS - review carefully",
    ]
    if window_reason:
        parts.append(f"Change window: {window_reason}")
    if alert_flags:
        parts.append(f"The alert text was flagged: {', '.join(alert_flags)}")
    if dashboard_url:
        parts.append(f"{dashboard_url.rstrip('/')}/incidents/{thread_id}")
    return "\n".join(parts)
