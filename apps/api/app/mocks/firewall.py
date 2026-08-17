from __future__ import annotations

from typing import Any

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
        "syslog_href": None,
        "unused_counters": {},
    }
]

ACL_HITS: list[dict[str, Any]] = [
    {
        "device": "FW_Edge",
        "rule_id": "ACL-DMZ-47",
        "acl": "DMZ_TO_TRUST",
        "line": 40,
        "action": "deny",
        "src": "10.10.1.0/24",
        "dst": "10.20.1.50",
        "port": 443,
        "hits": 1284,
        "remark": None,
    },
    {
        "device": "FW_Edge",
        "rule_id": "ACL-DMZ-10",
        "acl": "DMZ_TO_TRUST",
        "line": 10,
        "action": "permit",
        "src": "10.10.1.0/24",
        "dst": "10.20.1.0/24",
        "port": 80,
        "hits": 42,
    },
]


def denied_flows(source_device: str, target_device: str) -> list[dict[str, Any]]:
    rows = [
        row
        for row in DENIED_FLOWS
        if row["src_device"] == source_device and row["dst_device"] == target_device
    ]
    return [minify_payload(row) for row in rows]


def acl_hits(device_id: str, rule_id: str | None = None) -> list[dict[str, Any]]:
    rows = [row for row in ACL_HITS if row["device"] == device_id]
    if rule_id:
        rows = [row for row in rows if row["rule_id"] == rule_id]
    return [minify_payload(row) for row in rows]
