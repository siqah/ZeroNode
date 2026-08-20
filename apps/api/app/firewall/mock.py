"""Fixture-backed firewall for tests, CI and demos without hardware.

Mirrors the shape of a real ASA response so swapping backends changes nothing
downstream.
"""

from __future__ import annotations

from typing import Any

from app.firewall.base import FlowQuery
from app.firewall.nat import NatAssessment
from app.firewall.policy import AclRule
from app.minify import minify_payload

DENIED_FLOWS: list[dict[str, Any]] = [
    {
        "src": "10.10.1.10",
        "src_device": "Web_App",
        "dst": "10.20.1.50",
        "dst_device": "DB_Primary",
        "port": 443,
        "proto": "tcp",
        "action": "deny",
        "rule_id": "ACL-DMZ-47",
        "hits": 1284,
        "last_seen": "2026-08-17T09:14:00Z",
    }
]

ACL_HITS: list[dict[str, Any]] = [
    {
        "device": "FW_Edge",
        "rule_id": "ACL-DMZ-10",
        "acl": "DMZ_TO_TRUST",
        "line": 10,
        "action": "permit",
        "proto": "tcp",
        "src": "10.10.1.0/24",
        "dst": "10.20.1.0/24",
        "port": 80,
        "hits": 42,
    },
    {
        "device": "FW_Edge",
        "rule_id": "ACL-DMZ-47",
        "acl": "DMZ_TO_TRUST",
        "line": 40,
        "action": "deny",
        "proto": "tcp",
        "src": "10.10.1.0/24",
        "dst": "10.20.1.50",
        "port": 443,
        "hits": 1284,
    },
]


class MockFirewall:
    """Static lab policy. The one piece of the system that is not real."""

    def describe(self) -> str:
        return "mock fixtures (no device contacted)"

    def refresh(self, device_id: str) -> None:
        """Fixtures are read fresh every time."""

    def acl_policy(self, device_id: str) -> list[AclRule]:
        rules = [
            AclRule(
                line=int(row["line"]),
                action=str(row["action"]),
                proto=str(row.get("proto", "tcp")),
                src=str(row["src"]),
                dst=str(row["dst"]),
                port=row.get("port"),
                rule_id=str(row["rule_id"]),
                hits=int(row.get("hits", 0)),
                acl=str(row.get("acl", "")),
            )
            for row in ACL_HITS
            if row["device"] == device_id
        ]
        return sorted(rules, key=lambda rule: rule.line)

    def denied_flows(self, query: FlowQuery) -> list[dict[str, Any]]:
        rows = [
            row
            for row in DENIED_FLOWS
            if row["src_device"] == query.source_device
            and row["dst_device"] == query.target_device
        ]
        return [minify_payload(row) for row in rows]

    def nat_assessment(self, device_id: str, addresses: list[str]) -> NatAssessment:
        """The lab topology is routed, not translated."""
        return NatAssessment()

    def acl_hits(self, device_id: str, rule_id: str | None = None) -> list[dict[str, Any]]:
        rows = [row for row in ACL_HITS if row["device"] == device_id]
        if rule_id:
            rows = [row for row in rows if row["rule_id"] == rule_id]
        return [minify_payload(row) for row in rows]
