"""Read-only Cisco ASA backend.

Two independent pieces: parsers for `show access-list` and `show object-group`,
which are pure and fully testable against captured text, and an SSH transport
that can only issue `show` commands. There is no code path here that writes to a
device.

On object-groups the ASA does most of the work itself: `show access-list` prints
the summary rule followed by indented, fully expanded elements. Those are
preferred when present, since the device's own expansion is authoritative.
`show object-group` is only used to resolve rules that arrive unexpanded.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from itertools import product
from typing import Any

from app.firewall.base import FlowQuery
from app.firewall.nat import NatAssessment, NatRule, assess_flow, parse_show_nat
from app.firewall.objectgroup import (
    ObjectGroup,
    expand_group,
    expand_object,
    expand_range,
    parse_show_object_groups,
    parse_show_objects,
    port_value,
)
from app.firewall.policy import AclRule, evaluate_flow, parse_endpoint
from app.firewall.ssh import Credential, ReadOnlyViolation, SshDevice

logger = logging.getLogger(__name__)

ACL_LINE_RE = re.compile(
    r"^access-list\s+(?P<acl>\S+)\s+line\s+(?P<line>\d+)\s+(?P<body>.*)$",
    re.IGNORECASE,
)
HITCNT_RE = re.compile(r"\(hitcnt=(\d+)\)", re.IGNORECASE)
HEADER_RE = re.compile(r"^access-list\s+\S+;", re.IGNORECASE)
GROUP_KEYWORDS = ("object-group", "object", "interface")
# Guards against a rule whose object-groups expand into an unusable number of rules.
MAX_EXPANSION = 2048


@dataclass
class AclParseResult:
    rules: list[AclRule] = field(default_factory=list)

    @property
    def unparsed(self) -> list[AclRule]:
        return [rule for rule in self.rules if rule.action == "unparsed"]


@dataclass
class _Entry:
    acl: str
    line: int
    body: str
    raw: str
    expanded: bool


def _clean_body(body: str) -> list[str]:
    body = HITCNT_RE.sub(" ", body)
    body = re.sub(r"0x[0-9a-f]+", " ", body, flags=re.IGNORECASE)
    return [token.lower() for token in body.split()]


def _group_kind(
    name: str, groups: dict[str, ObjectGroup], objects: dict[str, ObjectGroup] | None = None
) -> str | None:
    entry = groups.get(name.lower()) or (objects or {}).get(name.lower())
    return entry.kind if entry else None


def _resolve_endpoint(
    tokens: list[str],
    index: int,
    groups: dict[str, ObjectGroup],
    objects: dict[str, ObjectGroup],
) -> tuple[list[str], int, bool]:
    keyword = tokens[index]
    if keyword in ("object-group", "object"):
        if index + 1 >= len(tokens):
            return [], index + 1, False
        expansion = (
            expand_group(tokens[index + 1], groups, objects)
            if keyword == "object-group"
            else expand_object(tokens[index + 1], objects)
        )
        if not expansion.complete or not expansion.networks:
            return [], index + 2, False
        return expansion.networks, index + 2, True
    if keyword == "interface":
        return [], index + 1, False
    spec, next_index = parse_endpoint(tokens, index)
    return [spec], next_index, True


def _resolve_ports(
    tokens: list[str],
    index: int,
    groups: dict[str, ObjectGroup],
    objects: dict[str, ObjectGroup],
) -> tuple[list[int | None], int, bool]:
    """Return (ports, next_index, understood). `[None]` means no port constraint."""
    if index >= len(tokens):
        return [None], index, True

    token = tokens[index]
    if token == "eq" and index + 1 < len(tokens):
        port = port_value(tokens[index + 1])
        return [port], index + 2, port is not None
    if token == "range" and index + 2 < len(tokens):
        expanded = expand_range(tokens[index + 1], tokens[index + 2])
        if expanded is None:
            return [None], index + 3, False
        return list(expanded), index + 3, True
    if token in ("object-group", "object") and index + 1 < len(tokens):
        kind = _group_kind(tokens[index + 1], groups, objects)
        if kind in ("service", "protocol"):
            expansion = (
                expand_group(tokens[index + 1], groups, objects)
                if token == "object-group"
                else expand_object(tokens[index + 1], objects)
            )
            if not expansion.complete:
                return [None], index + 2, False
            if expansion.ports:
                return list(expansion.ports), index + 2, True
            return [None], index + 2, True
        # A network group here belongs to the next endpoint, not to a port.
        return [None], index, True
    return [None], index, True


def _rules_from_tokens(
    tokens: list[str],
    entry: _Entry,
    rule_id: str,
    hits: int,
    groups: dict[str, ObjectGroup],
    objects: dict[str, ObjectGroup],
) -> list[AclRule] | None:
    action_index = next(
        (i for i, token in enumerate(tokens) if token in ("permit", "deny")), None
    )
    if action_index is None:
        return None
    action = tokens[action_index]
    index = action_index + 1
    if index >= len(tokens):
        return None

    protocols: list[str] = ["ip"]
    group_ports: list[int | None] = [None]
    if tokens[index] in ("tcp", "udp", "ip", "icmp"):
        protocols = [tokens[index]]
        index += 1
    elif tokens[index] in ("object-group", "object") and index + 1 < len(tokens):
        # `permit object-group SVC_GRP <src> <dst>`: the group carries protocol and ports.
        if _group_kind(tokens[index + 1], groups, objects) not in ("service", "protocol"):
            return None
        expansion = (
            expand_group(tokens[index + 1], groups, objects)
            if tokens[index] == "object-group"
            else expand_object(tokens[index + 1], objects)
        )
        if not expansion.complete or not expansion.protocols:
            return None
        protocols = list(dict.fromkeys(expansion.protocols))
        group_ports = list(expansion.ports) or [None]
        index += 2

    try:
        sources, index, ok = _resolve_endpoint(tokens, index, groups, objects)
        if not ok:
            return None
        source_ports, index, ok = _resolve_ports(tokens, index, groups, objects)
        if not ok:
            return None
        destinations, index, ok = _resolve_endpoint(tokens, index, groups, objects)
        if not ok:
            return None
    except IndexError:
        return None

    dest_ports, _, ok = _resolve_ports(tokens, index, groups, objects)
    if not ok:
        return None

    ports: list[int | None] = [port for port in dest_ports if port is not None] or [
        port for port in source_ports if port is not None
    ] or [port for port in group_ports if port is not None] or [None]

    if len(protocols) * len(sources) * len(destinations) * len(ports) > MAX_EXPANSION:
        return None

    return [
        AclRule(
            line=entry.line,
            action=action,
            proto=proto,
            src=src,
            dst=dst,
            port=port,
            rule_id=rule_id,
            hits=hits,
            acl=entry.acl,
            raw=entry.raw if not entry.expanded else "",
        )
        for proto, src, dst, port in product(protocols, sources, destinations, ports)
    ]


def _collect_entries(output: str) -> list[_Entry]:
    entries: list[_Entry] = []
    for raw_line in (output or "").splitlines():
        line = raw_line.strip()
        if not line or HEADER_RE.match(line) or line.lower().startswith("access-list cached"):
            continue
        match = ACL_LINE_RE.match(line)
        if not match or " remark " in f" {line.lower()} ":
            continue
        entries.append(
            _Entry(
                acl=match.group("acl"),
                line=int(match.group("line")),
                body=match.group("body"),
                raw=line,
                # The ASA indents the elements it expanded from an object-group.
                expanded=raw_line[:1].isspace(),
            )
        )
    return entries


def parse_show_access_list(
    output: str,
    groups: dict[str, ObjectGroup] | None = None,
    objects: dict[str, ObjectGroup] | None = None,
) -> AclParseResult:
    """Parse ASA `show access-list` text into ordered rules.

    Anything not understood is kept as an `unparsed` rule rather than dropped, so
    a partially understood policy can never be mistaken for a complete one.
    """
    groups = groups or {}
    objects = objects or {}
    result = AclParseResult()

    grouped: dict[tuple[str, int], list[_Entry]] = {}
    for entry in _collect_entries(output):
        grouped.setdefault((entry.acl, entry.line), []).append(entry)

    for (acl, line_no), entries in grouped.items():
        expanded = [entry for entry in entries if entry.expanded]
        # The device already did the expansion; its output beats our own.
        chosen = expanded or entries
        rule_id = f"{acl}-{line_no}"

        for entry in chosen:
            hits_match = HITCNT_RE.search(entry.body)
            hits = int(hits_match.group(1)) if hits_match else 0
            rules = _rules_from_tokens(
                _clean_body(entry.body), entry, rule_id, hits, groups, objects
            )
            if rules is None:
                result.rules.append(
                    AclRule(
                        line=line_no,
                        action="unparsed",
                        proto="ip",
                        src="any",
                        dst="any",
                        port=None,
                        rule_id=rule_id,
                        hits=hits,
                        acl=acl,
                        raw=entry.raw,
                    )
                )
                continue
            result.rules.extend(rules)

    result.rules.sort(key=lambda item: item.line)
    return result


class CiscoAsaFirewall(SshDevice):
    """Live ASA over SSH, restricted to `show` commands.

    Requires the `devices` extra (`pip install -e ".[devices]"`).
    """

    device_type = "cisco_asa"

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
            host,
            username,
            password,
            device_id=device_id,
            port=port,
            timeout=timeout,
            secret=secret,
        )
        self.acl_name = acl_name
        self._cache: dict[str, AclParseResult] = {}
        self._nat: list[NatRule] | None = None
        self._defs: tuple[dict[str, ObjectGroup], dict[str, ObjectGroup]] | None = None

    def describe(self) -> str:
        return f"cisco-asa {self.host} (read-only)"

    def _definitions(self) -> tuple[dict[str, ObjectGroup], dict[str, ObjectGroup]]:
        """Object-groups and named objects. Either failing is survivable: the
        affected rules stay unmodelled rather than being guessed at."""
        if self._defs is not None:
            return self._defs
        groups: dict[str, ObjectGroup] = {}
        objects: dict[str, ObjectGroup] = {}
        try:
            groups = parse_show_object_groups(self._send("show object-group"))
        except Exception:  # noqa: BLE001
            logger.warning("%s: could not read object-groups", self.device_id)
        try:
            objects = parse_show_objects(self._send("show running-config object"))
        except Exception:  # noqa: BLE001
            logger.warning("%s: could not read named objects", self.device_id)
        self._defs = (groups, objects)
        return self._defs

    def refresh(self, device_id: str) -> None:
        self._cache.pop(device_id, None)
        self._defs = None

    def _policy_result(self, device_id: str, refresh: bool = False) -> AclParseResult:
        if refresh or device_id not in self._cache:
            command = "show access-list"
            if self.acl_name:
                command = f"show access-list {self.acl_name}"
            output = self._send(command)
            parsed = parse_show_access_list(output)
            # Only pay for a second round trip if something failed to parse; when
            # the device expanded its own object-groups, nothing will have.
            if parsed.unparsed:
                groups, objects = self._definitions()
                if groups or objects:
                    parsed = parse_show_access_list(output, groups, objects)
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
        rules = self.acl_policy(self.device_id)
        action, hit = evaluate_flow(
            rules, query.source_ip, query.target_ip, query.port, query.proto
        )
        if action != "deny":
            return []
        return [
            {
                "src": query.source_ip,
                "src_device": query.source_device,
                "dst": query.target_ip,
                "dst_device": query.target_device,
                "port": query.port,
                "proto": query.proto,
                "action": "deny",
                "rule_id": hit.rule_id if hit else "implicit-deny",
                "hits": hit.hits if hit else 0,
                "source": self.describe(),
            }
        ]

    def nat_assessment(self, device_id: str, addresses: list[str]) -> NatAssessment:
        if self._nat is None:
            try:
                self._nat = parse_show_nat(self._send("show nat"))
            except Exception:  # noqa: BLE001 - no NAT view is itself worth reporting
                logger.warning("%s: could not read NAT policy", device_id)
                self._nat = []
                return NatAssessment(unresolved=["NAT policy could not be read from the device"])
        _, objects = self._definitions() if self._nat else ({}, {})
        return assess_flow(self._nat, addresses, objects)

    def acl_hits(self, device_id: str, rule_id: str | None = None) -> list[dict[str, Any]]:
        """One row per ACL line. Expanded object-group members are summarised."""
        by_rule: dict[str, list[AclRule]] = {}
        for rule in self.acl_policy(device_id):
            if rule.action in ("permit", "deny"):
                by_rule.setdefault(rule.rule_id, []).append(rule)

        rows: list[dict[str, Any]] = []
        for rid, rules in by_rule.items():
            head = rules[0]
            many = len(rules) > 1
            rows.append(
                {
                    "device": device_id,
                    "rule_id": rid,
                    "acl": head.acl,
                    "line": head.line,
                    "action": head.action,
                    "proto": head.proto,
                    "src": f"{len({r.src for r in rules})} networks" if many else head.src,
                    "dst": f"{len({r.dst for r in rules})} networks" if many else head.dst,
                    "port": head.port,
                    "hits": max(rule.hits for rule in rules),
                }
            )
        if rule_id:
            rows = [row for row in rows if row["rule_id"] == rule_id]
        return sorted(rows, key=lambda row: row["line"])


# `parse_acl_command` handles single proposed rules; re-exported for callers that
# only import this module.
__all__ = [
    "AclParseResult",
    "CiscoAsaFirewall",
    "ReadOnlyViolation",
    "SshDevice",
    "parse_show_access_list",
    "parse_show_object_groups",
]
