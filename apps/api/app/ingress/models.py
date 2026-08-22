from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

Severity = Literal["low", "medium", "high", "critical"]
TriggerSource = Literal["api", "generic", "alertmanager", "pagerduty"]
TriggerAction = Literal["open", "ignore"]


@dataclass(frozen=True)
class NormalizedIncidentTrigger:
    thread_id: str
    description: str
    severity: Severity = "high"
    site: str = ""
    source: TriggerSource = "api"
    external_id: str = ""
    action: TriggerAction = "open"
    ignore_reason: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class TriggerResult:
    status: str
    thread_id: str
    job_id: int | None = None
    deduped: bool = False
    source: str = "api"
    ignore_reason: str = ""
