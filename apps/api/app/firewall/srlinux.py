"""Read-only Nokia SR Linux ACL backend.

SR Linux is the public, vendor-supported NOS used by the hardware-free L4
validation rung. Reads use its operational ``show acl`` report so the common
SSH guard can continue enforcing that every investigation command starts with
``show``. Configuration remains isolated in the execution layer.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from app.firewall.asa import AclParseResult
from app.firewall.base import FlowQuery
from app.firewall.nat import NatAssessment
from app.firewall.policy import AclRule, evaluate_flow
from app.firewall.ssh import Credential, SshDevice

logger = logging.getLogger(__name__)

ENTRY_RE = re.compile(r"^\s*Entry\s+(?P<line>\d+)\s*$", re.IGNORECASE)
MATCH_RE = re.compile(
    r"protocol=(?P<proto>[^,\s]+)\s*,\s*"
    r"(?P<src>[^\s(]*)(?:\((?P<src_port>[^)]*)\))?\s*->\s*"
    r"(?P<dst>[^\s(]*)(?:\((?P<dst_port>[^)]*)\))?",
    re.IGNORECASE,
)
ACTION_RE = re.compile(r"^\s*Action\s*:\s*(?P<action>\S+)", re.IGNORECASE)
HITS_RE = re.compile(
    r"^\s*(?:Input )?Match Packets\s*:\s*(?P<hits>\d+)", re.IGNORECASE
)


def _exact_port(text: str | None) -> int | None:
    if not text:
        return None
    values = [int(value) for value in re.findall(r"\d+", text)]
    if len(values) == 1:
        return values[0]
    if len(values) >= 2 and values[0] == values[1]:
        return values[0]
    return None


def parse_show_acl(output: str, acl_name: str) -> AclParseResult:
    """Parse ``show acl ipv4-filter`` while preserving entry order."""
    rules: list[AclRule] = []
    current: dict[str, Any] | None = None

    def finish() -> None:
        nonlocal current
        if current is None:
            return
        action = current.get("action", "")
        match = current.get("match")
        if action not in ("accept", "drop") or match is None:
            rules.append(
                AclRule(
                    line=current["line"],
                    action="unparsed",
                    proto="",
                    src="",
                    dst="",
                    port=None,
                    acl=acl_name,
                    raw="\n".join(current["raw"]),
                )
            )
        else:
            rules.append(
                AclRule(
                    line=current["line"],
                    action="permit" if action == "accept" else "deny",
                    proto=(
                        "ip"
                        if match.group("proto").lower() == "<undefined>"
                        else match.group("proto").lower()
                    ),
                    src=match.group("src") or "any",
                    dst=match.group("dst") or "any",
                    port=_exact_port(match.group("dst_port")),
                    rule_id=f"{acl_name}-{current['line']}",
                    hits=current.get("hits", 0),
                    acl=acl_name,
                    raw="\n".join(current["raw"]),
                )
            )
        current = None

    for raw in (output or "").splitlines():
        entry = ENTRY_RE.match(raw)
        if entry:
            finish()
            current = {"line": int(entry.group("line")), "raw": [raw.strip()]}
            continue
        if current is None:
            continue
        current["raw"].append(raw.strip())
        acl_match = MATCH_RE.search(raw)
        if acl_match:
            current["match"] = acl_match
        action = ACTION_RE.match(raw)
        if action:
            current["action"] = action.group("action").lower()
        hits = HITS_RE.match(raw)
        if hits:
            current["hits"] = int(hits.group("hits"))
    finish()
    return AclParseResult(rules=rules)


class NokiaSrlinuxFirewall(SshDevice):
    """Read-only SR Linux backend; only operational ``show`` reaches the NOS."""

    device_type = "nokia_srl"

    def __init__(
        self,
        host: str,
        username: str,
        password: Credential = "",
        *,
        acl_name: str | None = None,
        device_id: str = "FW_Edge",
        port: int = 22,
        timeout: int = 30,
        secret: Credential = "",
    ) -> None:
        super().__init__(
            host,
            username,
            password,
            device_id=device_id,
            port=port,
            timeout=timeout,
            secret=secret,
        )
        self.acl_name = acl_name or "DMZ_TO_TRUST"
        self._cache: dict[str, AclParseResult] = {}

    def describe(self) -> str:
        return f"nokia-srlinux {self.host} (read-only)"

    def refresh(self, device_id: str) -> None:
        self._cache.pop(device_id, None)

    def _policy_result(self, device_id: str) -> AclParseResult:
        if device_id not in self._cache:
            output = self._send(
                f"show acl acl-filter {self.acl_name} type ipv4"
            )
            parsed = parse_show_acl(output, self.acl_name)
            if parsed.unparsed:
                logger.warning(
                    "%s: %d SR Linux ACL entries could not be modelled: %s",
                    device_id,
                    len(parsed.unparsed),
                    [rule.raw for rule in parsed.unparsed],
                )
            self._cache[device_id] = parsed
        return self._cache[device_id]

    def acl_policy(self, device_id: str) -> list[AclRule]:
        return list(self._policy_result(device_id).rules)

    def denied_flows(self, query: FlowQuery) -> list[dict[str, Any]]:
        action, hit = evaluate_flow(
            self.acl_policy(self.device_id),
            query.source_ip,
            query.target_ip,
            query.port,
            query.proto,
        )
        if action != "deny" or hit is None:
            return []
        return [
            {
                "src": query.source_ip,
                "dst": query.target_ip,
                "port": query.port,
                "proto": query.proto,
                "action": "deny",
                "rule_id": hit.rule_id,
                "device": self.device_id,
                "source_device": query.source_device,
                "target_device": query.target_device,
            }
        ]

    def acl_hits(
        self, device_id: str, rule_id: str | None = None
    ) -> list[dict[str, Any]]:
        rules = self.acl_policy(device_id)
        if rule_id:
            rules = [rule for rule in rules if rule.rule_id == rule_id]
        return [
            {
                "rule_id": rule.rule_id,
                "line": rule.line,
                "action": rule.action,
                "hits": rule.hits,
                "acl": rule.acl,
            }
            for rule in rules
        ]

    def nat_assessment(self, device_id: str, addresses: list[str]) -> NatAssessment:
        return NatAssessment(
            translated=False,
            notes=["NAT is not configured or modelled on the SR Linux lab backend"],
        )
