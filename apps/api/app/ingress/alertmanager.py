from __future__ import annotations

import hashlib
import re
from typing import Literal

from pydantic import BaseModel, Field

from app.ingress.models import NormalizedIncidentTrigger, Severity

SeverityLiteral = Literal["low", "medium", "high", "critical"]


class AlertmanagerAlert(BaseModel):
    status: str = "firing"
    labels: dict[str, str] = Field(default_factory=dict)
    annotations: dict[str, str] = Field(default_factory=dict)
    fingerprint: str = ""


class AlertmanagerWebhookBody(BaseModel):
    version: str = "4"
    status: str = "firing"
    groupLabels: dict[str, str] = Field(default_factory=dict)
    commonLabels: dict[str, str] = Field(default_factory=dict)
    commonAnnotations: dict[str, str] = Field(default_factory=dict)
    alerts: list[AlertmanagerAlert] = Field(default_factory=list)


SEVERITY_MAP = {
    "critical": "critical",
    "crit": "critical",
    "p1": "critical",
    "high": "high",
    "warning": "high",
    "warn": "high",
    "p2": "high",
    "medium": "medium",
    "p3": "medium",
    "low": "low",
    "info": "low",
    "p4": "low",
    "p5": "low",
}


def _sanitize_thread_id(value: str, *, prefix: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._:-]", "-", value.strip())
    cleaned = cleaned.strip("-._:")
    if not cleaned:
        cleaned = hashlib.sha256(value.encode()).hexdigest()[:12]
    if not cleaned[0].isalnum():
        cleaned = f"{prefix}{cleaned}"
    return cleaned[:128]


def _severity(labels: dict[str, str]) -> Severity:
    for key in ("severity", "priority", "alert_level"):
        raw = labels.get(key, "").strip().lower()
        if raw in SEVERITY_MAP:
            return SEVERITY_MAP[raw]  # type: ignore[return-value]
    return "high"


def _site(labels: dict[str, str], default_site: str = "") -> str:
    for key in ("site", "topology_site", "cluster", "location"):
        value = labels.get(key, "").strip()
        if value:
            return value[:128]
    return default_site[:128]


def _description(alert: AlertmanagerAlert, common_annotations: dict[str, str]) -> str:
    labels = {**alert.labels}
    summary = (
        alert.annotations.get("summary")
        or common_annotations.get("summary")
        or labels.get("alertname")
        or "Alertmanager notification"
    )
    description = alert.annotations.get("description") or common_annotations.get("description")
    parts = [summary.strip()]
    if description and description.strip() != summary.strip():
        parts.append(description.strip())
    label_bits = [
        f"{key}={value}"
        for key, value in sorted(labels.items())
        if key in {"alertname", "instance", "job", "service", "namespace"}
    ]
    if label_bits:
        parts.append("Labels: " + ", ".join(label_bits))
    return "\n".join(part for part in parts if part)


def normalize_alertmanager(
    body: AlertmanagerWebhookBody,
    *,
    prefix: str = "AM",
    default_site: str = "",
) -> NormalizedIncidentTrigger:
    if body.status == "resolved":
        alert = body.alerts[0] if body.alerts else AlertmanagerAlert(status="resolved")
        labels = {**body.commonLabels, **alert.labels}
        thread_id = labels.get("ticket_id") or labels.get("incident")
        if not thread_id:
            fingerprint = alert.fingerprint or hashlib.sha256(
                repr(sorted(labels.items())).encode()
            ).hexdigest()[:12]
            thread_id = _sanitize_thread_id(f"{prefix}-{fingerprint}", prefix=prefix)
        return NormalizedIncidentTrigger(
            thread_id=_sanitize_thread_id(thread_id, prefix=prefix),
            description=_description(alert, body.commonAnnotations),
            severity=_severity(labels),
            site=_site(labels, default_site),
            source="alertmanager",
            external_id=alert.fingerprint,
            action="ignore",
            ignore_reason="alert resolved",
            metadata={"status": body.status},
        )

    if not body.alerts:
        raise ValueError("Alertmanager payload has no alerts")

    alert = next((item for item in body.alerts if item.status == "firing"), body.alerts[0])
    labels = {**body.commonLabels, **body.groupLabels, **alert.labels}
    thread_id = labels.get("ticket_id") or labels.get("incident")
    if not thread_id:
        fingerprint = alert.fingerprint or hashlib.sha256(
            repr(sorted(labels.items())).encode()
        ).hexdigest()[:12]
        thread_id = _sanitize_thread_id(f"{prefix}-{fingerprint}", prefix=prefix)
    else:
        thread_id = _sanitize_thread_id(thread_id, prefix=prefix)

    return NormalizedIncidentTrigger(
        thread_id=thread_id,
        description=_description(alert, body.commonAnnotations),
        severity=_severity(labels),
        site=_site(labels, default_site),
        source="alertmanager",
        external_id=alert.fingerprint,
        metadata={"status": alert.status, "labels": labels},
    )
