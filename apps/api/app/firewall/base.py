"""The contract every firewall backend implements.

Deliberately read-only. Nothing in this interface can change a device; proposed
changes go to a human and are only ever simulated against the policy returned
by `acl_policy`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from app.firewall.nat import NatAssessment
from app.firewall.policy import AclRule


@dataclass(frozen=True)
class FlowQuery:
    source_device: str
    source_ip: str
    target_device: str
    target_ip: str
    port: int = 443
    proto: str = "tcp"


class FirewallStore(Protocol):
    def describe(self) -> str:
        """Human-readable backend identity, recorded in the audit trail."""
        ...

    def acl_policy(self, device_id: str) -> list[AclRule]:
        """Ordered rules for the device, lowest line first."""
        ...

    def denied_flows(self, query: FlowQuery) -> list[dict[str, Any]]:
        """Deny records for the flow described by the alert."""
        ...

    def acl_hits(self, device_id: str, rule_id: str | None = None) -> list[dict[str, Any]]:
        """Rule hit counters, optionally filtered to one rule."""
        ...

    def refresh(self, device_id: str) -> None:
        """Drop any cached policy for the device.

        Post-change verification is worthless against a cached read, so a
        backend that caches must be able to forget on demand.
        """
        ...

    def nat_assessment(self, device_id: str, addresses: list[str]) -> NatAssessment:
        """Whether address translation could apply to the given addresses.

        A simulation run against the wrong side of a translation is worse than
        no simulation, so backends report what they cannot rule out.
        """
        ...
