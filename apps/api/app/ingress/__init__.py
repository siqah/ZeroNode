"""Inbound alert normalization and shared incident trigger service."""

from app.ingress.models import NormalizedIncidentTrigger, TriggerResult
from app.ingress.trigger import trigger_incident

__all__ = ["NormalizedIncidentTrigger", "TriggerResult", "trigger_incident"]
