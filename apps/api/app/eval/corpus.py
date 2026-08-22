"""Load golden incidents from the eval corpus."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

CORPUS_DIR = Path(__file__).resolve().parent / "corpus"


@dataclass(frozen=True)
class IncidentSpec:
    id: str
    ticket_id: str
    alert: str
    scripted_responses: list[str]
    expect: dict[str, Any]
    topology: str = "lab"
    topology_site: str = ""
    firewall: str = "lab"

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> IncidentSpec:
        return cls(
            id=str(payload["id"]),
            ticket_id=str(payload["ticket_id"]),
            alert=str(payload["alert"]),
            scripted_responses=[str(item) for item in payload["scripted_responses"]],
            expect=dict(payload.get("expect") or {}),
            topology=str(payload.get("topology") or "lab"),
            topology_site=str(payload.get("topology_site") or ""),
            firewall=str(payload.get("firewall") or "lab"),
        )


def load_incident(incident_id: str) -> IncidentSpec:
    path = CORPUS_DIR / f"{incident_id}.json"
    if not path.exists():
        raise FileNotFoundError(f"unknown incident {incident_id!r} (missing {path})")
    return IncidentSpec.from_dict(json.loads(path.read_text()))


def load_corpus() -> list[IncidentSpec]:
    incidents: list[IncidentSpec] = []
    for path in sorted(CORPUS_DIR.glob("*.json")):
        incidents.append(IncidentSpec.from_dict(json.loads(path.read_text())))
    return incidents
