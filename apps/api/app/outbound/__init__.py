"""Outbound integrations: ticketing and notifications."""

from __future__ import annotations

from app.config import settings
from app.outbound.notify import (
    Notifier,
    NullNotifier,
    WebhookNotifier,
    pending_approval_message,
)
from app.outbound.tickets import NullTicketSink, TicketSink, WebhookTicketSink
from app.secretref import SecretResolver

__all__ = [
    "Notifier",
    "NullNotifier",
    "NullTicketSink",
    "TicketSink",
    "WebhookNotifier",
    "WebhookTicketSink",
    "make_notifier",
    "make_ticket_sink",
    "pending_approval_message",
]


def _resolver() -> SecretResolver:
    return SecretResolver(
        ttl_seconds=settings.secret_cache_seconds,
        vault_addr=settings.vault_addr,
        vault_token=settings.vault_token,
    )


def make_ticket_sink() -> TicketSink:
    if not settings.ticket_webhook_url:
        return NullTicketSink()
    return WebhookTicketSink(
        settings.ticket_webhook_url,
        _resolver().resolve(settings.ticket_webhook_token),
        settings.dashboard_url,
    )


def make_notifier() -> Notifier:
    if not settings.notify_webhook_url:
        return NullNotifier()
    return WebhookNotifier(
        settings.notify_webhook_url,
        _resolver().resolve(settings.notify_webhook_token),
    )
