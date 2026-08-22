from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

from app.ingress.models import NormalizedIncidentTrigger

SeverityLiteral = Literal["low", "medium", "high", "critical"]


class GenericWebhookBody(BaseModel):
    ticket_id: str = Field(pattern=r"^[A-Za-z0-9._:-]+$", min_length=1)
    description: str = Field(min_length=1)
    severity: SeverityLiteral = "high"
    site: str = Field(default="", max_length=128)
    external_id: str = Field(default="", max_length=256)
    source: str = Field(default="generic", max_length=64)


class GenericMirrorBody(BaseModel):
    event: str = Field(default="incident.opened")
    incident: str = Field(pattern=r"^[A-Za-z0-9._:-]+$", min_length=1)
    summary: str = Field(min_length=1)
    severity: SeverityLiteral = "high"
    site: str = Field(default="", max_length=128)
    external_id: str = Field(default="", max_length=256)


def normalize_generic(body: GenericWebhookBody) -> NormalizedIncidentTrigger:
    return NormalizedIncidentTrigger(
        thread_id=body.ticket_id,
        description=body.description,
        severity=body.severity,
        site=body.site.strip(),
        source="generic",
        external_id=body.external_id.strip(),
        metadata={"source_label": body.source.strip()},
    )


def normalize_mirror(body: GenericMirrorBody) -> NormalizedIncidentTrigger:
    return NormalizedIncidentTrigger(
        thread_id=body.incident,
        description=body.summary,
        severity=body.severity,
        site=body.site.strip(),
        source="generic",
        external_id=body.external_id.strip(),
        metadata={"event": body.event},
    )


def normalize_generic_payload(payload: dict[str, Any]) -> NormalizedIncidentTrigger:
    if payload.get("event") == "incident.opened" and payload.get("incident"):
        return normalize_mirror(GenericMirrorBody.model_validate(payload))
    return normalize_generic(GenericWebhookBody.model_validate(payload))
