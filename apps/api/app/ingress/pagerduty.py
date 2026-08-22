from __future__ import annotations

import hashlib
import hmac
import re
from typing import Any

from pydantic import BaseModel, Field

from app.ingress.models import NormalizedIncidentTrigger, Severity

PRIORITY_MAP = {
    "P1": "critical",
    "P2": "high",
    "P3": "medium",
    "P4": "low",
    "P5": "low",
}


class PagerDutyData(BaseModel):
    id: str = ""
    number: int | None = None
    title: str = ""
    body: dict[str, Any] = Field(default_factory=dict)
    urgency: str = ""
    priority: dict[str, Any] | None = None
    service: dict[str, Any] | None = None
    custom_details: dict[str, Any] | None = None


class PagerDutyEvent(BaseModel):
    event_type: str = ""
    resource_type: str = ""
    data: PagerDutyData = Field(default_factory=PagerDutyData)


class PagerDutyWebhookBody(BaseModel):
    event: PagerDutyEvent = Field(default_factory=PagerDutyEvent)


def _sanitize_thread_id(value: str, *, prefix: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._:-]", "-", value.strip())
    cleaned = cleaned.strip("-._:")
    if not cleaned:
        cleaned = hashlib.sha256(value.encode()).hexdigest()[:12]
    if not cleaned[0].isalnum():
        cleaned = f"{prefix}{cleaned}"
    return cleaned[:128]


def _severity(data: PagerDutyData) -> Severity:
    priority = (data.priority or {}).get("summary") or (data.priority or {}).get("name") or ""
    priority = str(priority).strip().upper()
    if priority in PRIORITY_MAP:
        return PRIORITY_MAP[priority]  # type: ignore[return-value]
    urgency = (data.urgency or "").strip().lower()
    if urgency == "high":
        return "high"
    if urgency == "low":
        return "low"
    return "high"


def _site(data: PagerDutyData) -> str:
    custom = data.custom_details or {}
    for key in ("site", "topology_site", "location"):
        value = str(custom.get(key, "")).strip()
        if value:
            return value[:128]
    service = data.service or {}
    summary = str(service.get("summary") or service.get("name") or "").strip()
    return summary[:128]


def _description(data: PagerDutyData) -> str:
    title = (data.title or "PagerDuty incident").strip()
    details = data.body.get("details")
    if isinstance(details, dict):
        detail_text = ", ".join(f"{key}={value}" for key, value in sorted(details.items()))
    elif isinstance(details, str):
        detail_text = details.strip()
    else:
        detail_text = ""
    if detail_text and detail_text != title:
        return f"{title}\n{detail_text}"
    return title


def verify_pagerduty_signature(
    secret: str,
    *,
    body: bytes,
    timestamp: str,
    signature: str,
) -> bool:
    if not secret or not signature or not timestamp:
        return False
    payload = f"{timestamp}.{body.decode('utf-8')}".encode()
    expected = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    provided = signature.removeprefix("v1=")
    return hmac.compare_digest(expected, provided)


def normalize_pagerduty(
    body: PagerDutyWebhookBody,
    *,
    prefix: str = "PD",
) -> NormalizedIncidentTrigger:
    event_type = body.event.event_type.strip().lower()
    data = body.event.data
    if data.number is not None:
        thread_id = _sanitize_thread_id(f"{prefix}-{data.number}", prefix=prefix)
    elif data.id:
        thread_id = _sanitize_thread_id(f"{prefix}-{data.id}", prefix=prefix)
    else:
        thread_id = _sanitize_thread_id(f"{prefix}-unknown", prefix=prefix)

    if event_type in {"incident.resolved", "incident.acknowledged"}:
        return NormalizedIncidentTrigger(
            thread_id=thread_id,
            description=_description(data),
            severity=_severity(data),
            site=_site(data),
            source="pagerduty",
            external_id=data.id,
            action="ignore",
            ignore_reason=event_type.replace("incident.", ""),
            metadata={"event_type": event_type},
        )

    if event_type != "incident.triggered":
        raise ValueError(f"unsupported PagerDuty event type: {event_type or 'unknown'}")

    return NormalizedIncidentTrigger(
        thread_id=thread_id,
        description=_description(data),
        severity=_severity(data),
        site=_site(data),
        source="pagerduty",
        external_id=data.id,
        metadata={"event_type": event_type},
    )
