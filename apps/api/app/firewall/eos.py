"""Read-only Arista EOS backend.

Its reason for existing is practical rather than architectural: EOS is the only
credible network OS with a container image anyone can obtain without a hardware
or simulator licence, which makes it the only way to run this code against a
real CLI in a lab. The ACL model is close enough to IOS to reuse the rule
semantics and different enough in its output that reusing the IOS parser would
quietly mis-read it.

Where IOS writes:

    Extended IP access list DMZ_TO_TRUST
        10 permit tcp host 10.10.1.10 host 10.20.1.50 eq 443 (42 matches)

EOS writes:

    IP Access List DMZ_TO_TRUST
        10 permit tcp host 10.10.1.10 host 10.20.1.50 eq https [match 42, 0:02:11 ago]
"""

from __future__ import annotations

import logging
import re
from ipaddress import ip_network
from typing import Any

from app.firewall.asa import AclParseResult
from app.firewall.base import FlowQuery
from app.firewall.ios import _endpoint, _port, _strip_trailing
from app.firewall.nat import NatAssessment
from app.firewall.policy import AclRule, evaluate_flow
from app.firewall.ssh import Credential, SshDevice

logger = logging.getLogger(__name__)

HEADER_RE = re.compile(r"^(?:IPv6 )?IP Access List (?P<name>\S+)", re.IGNORECASE)
ENTRY_RE = re.compile(
    r"^\s*(?P<seq>\d+)\s+(?P<action>permit|deny)\s+(?P<body>.+?)"
    r"(?:\s*\[match(?:es)?\s+(?P<hits>\d+).*?\])?\s*$",
    re.IGNORECASE,
)
# EOS reports counters as a trailing bracket; IOS uses parentheses.
COUNTER_RE = re.compile(r"\s*\[.*?\]\s*$")


def _eos_endpoint(tokens: list[str], index: int) -> tuple[str | None, int]:
    """EOS prints prefixes where IOS prints wildcard masks.

    Handing `10.10.1.0/24` to the IOS reader gets it read as a bare host
    address, which silently narrows the rule to one address. Everything else
    falls through to the shared reader.
    """
    token = tokens[index]
    if "/" in token:
        try:
            ip_network(token, strict=False)
        except ValueError:
            return None, index + 1
        return token, index + 1
    return _endpoint(tokens, index)


def _unmodelled(sequence: int, proto: str, raw: str) -> AclRule:
    """Kept, but marked: a rule nobody can reason about must not read as absent."""
    return AclRule(
        line=sequence, action="unparsed", proto=proto, src="", dst="", port=None, raw=raw
    )


def _rule(acl: str, sequence: int, action: str, body: str, hits: int, raw: str) -> AclRule:
    tokens = _strip_trailing(COUNTER_RE.sub("", body).split())
    if not tokens:
        return _unmodelled(sequence, "", raw)

    proto = tokens[0].lower()
    index = 1

    try:
        src, index = _eos_endpoint(tokens, index)
        src_port, index, src_modelled = _port(tokens, index)
        dst, index = _eos_endpoint(tokens, index)
        dst_port, index, dst_modelled = _port(tokens, index)
    except IndexError:
        return _unmodelled(sequence, proto, raw)

    if src is None or dst is None or not (src_modelled and dst_modelled):
        return _unmodelled(sequence, proto, raw)

    # A qualifier we do not model could narrow the rule, which would make
    # treating it as a plain five-tuple match too generous.
    if tokens[index:]:
        return _unmodelled(sequence, proto, raw)

    return AclRule(
        line=sequence,
        action=action.lower(),
        proto=proto,
        src=src,
        dst=dst,
        port=dst_port if dst_port is not None else src_port,
        rule_id=f"{acl}-{sequence}",
        hits=hits,
        acl=acl,
        raw=raw,
    )


def parse_show_ip_access_lists(output: str) -> AclParseResult:
    # Unparsed rules stay in the ordered list. Dropping them would lose the
    # position of something that might match the flow first, and a simulation
    # that cannot see a rule cannot know it is wrong.
    rules: list[AclRule] = []
    acl = ""

    for raw_line in (output or "").splitlines():
        line = raw_line.rstrip()
        if not line.strip():
            continue

        header = HEADER_RE.match(line.strip())
        if header:
            acl = header.group("name")
            continue

        entry = ENTRY_RE.match(line)
        if not entry or not acl:
            continue

        rule = _rule(
            acl,
            int(entry.group("seq")),
            entry.group("action"),
            entry.group("body"),
            int(entry.group("hits") or 0),
            line.strip(),
        )
        rules.append(rule)

    return AclParseResult(rules=rules)


class AristaEosFirewall(SshDevice):
    """Read-only EOS backend. Only `show` commands ever reach the device."""

    device_type = "arista_eos"

    def __init__(
        self,
        host: str,
        username: str,
        password: Credential = "",
        *,
        acl_name: str | None = None,
        device_id: str = "FW_Edge",
        port: int = 22,
        timeout: int = 20,
        secret: Credential = "",
    ) -> None:
        super().__init__(
            host, username, password, device_id=device_id, port=port, timeout=timeout, secret=secret
        )
        self.acl_name = acl_name
        self._cache: dict[str, AclParseResult] = {}

    def describe(self) -> str:
        return f"arista-eos {self.host} (read-only)"

    def refresh(self, device_id: str) -> None:
        self._cache.pop(device_id, None)

    def _policy_result(self, device_id: str, refresh: bool = False) -> AclParseResult:
        if refresh or device_id not in self._cache:
            command = "show ip access-lists"
            if self.acl_name:
                command = f"show ip access-lists {self.acl_name}"
            parsed = parse_show_ip_access_lists(self._send(command))
            if parsed.unparsed:
                logger.warning(
                    "%s: %d ACL lines could not be modelled: %s",
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

    def acl_hits(self, device_id: str, rule_id: str | None = None) -> list[dict[str, Any]]:
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
        """EOS in a lab has no NAT worth modelling; say so rather than imply none."""
        return NatAssessment(translated=False, notes=["NAT is not read on EOS backends"])
