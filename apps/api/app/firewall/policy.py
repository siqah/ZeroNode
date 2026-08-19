"""ACL rule model, CLI parsing and first-match evaluation.

Kept free of any data source so the same semantics apply to a fixture, a live
device, and a rule the model has only proposed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from ipaddress import IPv4Network, ip_address, ip_network

PORT_ALIASES = {
    "https": 443,
    "http": 80,
    "www": 80,
    "ssh": 22,
    "domain": 53,
    "telnet": 23,
    "smtp": 25,
}
LINE_RE = re.compile(r"\bline\s+(\d+)\b", re.IGNORECASE)
LEADING_SEQ_RE = re.compile(r"^\s*(\d+)\s+")


@dataclass
class AclRule:
    line: int
    action: str
    proto: str
    src: str
    dst: str
    port: int | None
    rule_id: str = "proposed"
    hits: int = 0
    acl: str = ""
    raw: str = ""

    def matches(self, src_ip: str, dst_ip: str, port: int, proto: str) -> bool:
        if self.action not in ("permit", "deny"):
            return False
        if self.proto not in ("ip", "any", proto):
            return False
        if self.port is not None and self.port != port:
            return False
        return contains(self.src, src_ip) and contains(self.dst, dst_ip)


def as_network(spec: str) -> IPv4Network:
    """Accept CIDR, dotted mask, wildcard mask or a bare host address."""
    if "/" in spec:
        return ip_network(spec, strict=False)
    return ip_network(f"{spec}/32", strict=False)


def contains(spec: str, addr: str) -> bool:
    if spec in ("any", "any4", "*"):
        return True
    try:
        return ip_address(addr) in as_network(spec)
    except ValueError:
        return False


def breadth(spec: str) -> int:
    """Usable host count, excluding network and broadcast for real subnets."""
    if spec in ("any", "any4", "*"):
        return 2**32
    try:
        network = as_network(spec)
    except ValueError:
        return 2**32
    if network.prefixlen >= 31:
        return network.num_addresses
    return network.num_addresses - 2


def parse_port(tokens: list[str], index: int) -> int | None:
    if index < len(tokens) and tokens[index] == "eq" and index + 1 < len(tokens):
        raw = tokens[index + 1]
        if raw.isdigit():
            return int(raw)
        return PORT_ALIASES.get(raw)
    return None


def parse_endpoint(tokens: list[str], index: int) -> tuple[str, int]:
    """Return (spec, next_index) for `host X`, CIDR, dotted mask or `any`."""
    token = tokens[index]
    if token == "host" and index + 1 < len(tokens):
        return tokens[index + 1], index + 2
    if token in ("any", "any4"):
        return "any", index + 1
    if index + 1 < len(tokens) and re.fullmatch(r"\d+\.\d+\.\d+\.\d+", tokens[index + 1]):
        return f"{token}/{tokens[index + 1]}", index + 2
    return token, index + 1


def parse_acl_command(command: str) -> AclRule | None:
    """Parse a single permit/deny line into a rule, ignoring platform noise."""
    text = command.strip()
    if not text:
        return None
    line_match = LINE_RE.search(text) or LEADING_SEQ_RE.match(text)
    stated_line = int(line_match.group(1)) if line_match else None
    text = LINE_RE.sub(" ", text)
    tokens = [token.lower() for token in text.replace("\t", " ").split()]

    action_index = next(
        (i for i, token in enumerate(tokens) if token in ("permit", "deny")), None
    )
    if action_index is None:
        return None
    action = tokens[action_index]

    index = action_index + 1
    proto = "ip"
    if index < len(tokens) and tokens[index] in ("tcp", "udp", "ip", "icmp"):
        proto = tokens[index]
        index += 1

    try:
        src, index = parse_endpoint(tokens, index)
        port = parse_port(tokens, index)
        if port is not None:
            index += 2
        dst, index = parse_endpoint(tokens, index)
    except IndexError:
        return None

    dst_port = parse_port(tokens, index)
    return AclRule(
        line=stated_line if stated_line is not None else -1,
        action=action,
        proto=proto,
        src=src,
        dst=dst,
        port=dst_port if dst_port is not None else port,
    )


def evaluate_flow(
    rules: list[AclRule], src_ip: str, dst_ip: str, port: int, proto: str = "tcp"
) -> tuple[str, AclRule | None]:
    """First match wins; an unmatched flow hits the implicit deny."""
    for rule in sorted(rules, key=lambda item: item.line):
        if rule.matches(src_ip, dst_ip, port, proto):
            return rule.action, rule
    return "deny", None
