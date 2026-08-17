"""Post-change verification for proposed firewall policy.

A proposal is only useful if the flow it targets would actually pass afterwards.
This module rebuilds the device ACL, splices the proposed rule in at its stated
position, and re-evaluates the denied flow with first-match semantics. Order
matters: a permit appended below an existing deny is shadowed and changes
nothing, which is the mistake this check exists to catch.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from ipaddress import IPv4Network, ip_address, ip_network
from typing import Any

from app.mocks.firewall import ACL_HITS

PORT_ALIASES = {"https": 443, "http": 80, "ssh": 22, "domain": 53}
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

    def matches(self, src_ip: str, dst_ip: str, port: int, proto: str) -> bool:
        if self.proto not in ("ip", "any", proto):
            return False
        if self.port is not None and self.port != port:
            return False
        return _contains(self.src, src_ip) and _contains(self.dst, dst_ip)


@dataclass
class VerificationReport:
    ok: bool
    lines: list[str]
    remediation: str = ""


def _contains(spec: str, addr: str) -> bool:
    if spec in ("any", "any4", "*"):
        return True
    try:
        return ip_address(addr) in _as_network(spec)
    except ValueError:
        return False


def _as_network(spec: str) -> IPv4Network:
    return ip_network(spec if "/" in spec else f"{spec}/32", strict=False)


def _parse_port(tokens: list[str], index: int) -> int | None:
    if index < len(tokens) and tokens[index] == "eq" and index + 1 < len(tokens):
        raw = tokens[index + 1]
        if raw.isdigit():
            return int(raw)
        return PORT_ALIASES.get(raw)
    return None


def _parse_endpoint(tokens: list[str], index: int) -> tuple[str, int]:
    """Return (spec, next_index) for host X | CIDR | dotted mask | any."""
    token = tokens[index]
    if token == "host" and index + 1 < len(tokens):
        return tokens[index + 1], index + 2
    if token in ("any", "any4"):
        return "any", index + 1
    if index + 1 < len(tokens) and re.fullmatch(r"\d+\.\d+\.\d+\.\d+", tokens[index + 1]):
        # "10.10.1.0 255.255.255.0" style
        return f"{token}/{tokens[index + 1]}", index + 2
    return token, index + 1


def parse_acl_command(command: str) -> AclRule | None:
    text = command.strip()
    if not text:
        return None
    line_match = LINE_RE.search(text) or LEADING_SEQ_RE.match(text)
    stated_line = int(line_match.group(1)) if line_match else None
    text = LINE_RE.sub(" ", text)
    tokens = text.replace("\t", " ").split()
    tokens = [token.lower() for token in tokens]

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
        src, index = _parse_endpoint(tokens, index)
        port = _parse_port(tokens, index)
        if port is not None:
            index += 2
        dst, index = _parse_endpoint(tokens, index)
    except IndexError:
        return None

    dst_port = _parse_port(tokens, index)
    return AclRule(
        line=stated_line if stated_line is not None else -1,
        action=action,
        proto=proto,
        src=src,
        dst=dst,
        port=dst_port if dst_port is not None else port,
    )


def device_policy(device_id: str) -> list[AclRule]:
    rules: list[AclRule] = []
    for row in ACL_HITS:
        if row.get("device") != device_id:
            continue
        rules.append(
            AclRule(
                line=int(row.get("line", 0)),
                action=str(row.get("action", "deny")),
                proto=str(row.get("proto", "tcp")),
                src=str(row.get("src", "any")),
                dst=str(row.get("dst", "any")),
                port=row.get("port"),
                rule_id=str(row.get("rule_id", "unknown")),
            )
        )
    return sorted(rules, key=lambda rule: rule.line)


def evaluate_flow(
    rules: list[AclRule], src_ip: str, dst_ip: str, port: int, proto: str = "tcp"
) -> tuple[str, AclRule | None]:
    for rule in sorted(rules, key=lambda item: item.line):
        if rule.matches(src_ip, dst_ip, port, proto):
            return rule.action, rule
    return "deny", None


def _breadth(spec: str) -> int:
    """Usable host count, excluding network and broadcast for real subnets."""
    if spec in ("any", "any4", "*"):
        return 2**32
    try:
        network = _as_network(spec)
    except ValueError:
        return 2**32
    if network.prefixlen >= 31:
        return network.num_addresses
    return network.num_addresses - 2


def scope_findings(
    rule: AclRule, flows: list[dict[str, Any]]
) -> tuple[list[str], str]:
    """Flag a permit that opens far more than the evidence justifies.

    Widening a single blocked flow into subnet-to-subnet access is the quiet way
    segmentation dies, and it reads as reasonable in a change ticket.
    """
    srcs = sorted({str(flow.get("src", "")) for flow in flows if flow.get("src")})
    dsts = sorted({str(flow.get("dst", "")) for flow in flows if flow.get("dst")})
    if not srcs or not dsts:
        return [], ""

    permitted = _breadth(rule.src) * _breadth(rule.dst)
    needed = len(srcs) * len(dsts)
    lines: list[str] = []
    remediation = ""

    if rule.port is None:
        lines.append("SCOPE the rule matches every port, not just the blocked one.")
    if permitted > needed:
        lines.append(
            f"SCOPE the rule permits {permitted:,} host pairs but only {needed:,} "
            f"{'is' if needed == 1 else 'are'} evidenced ({', '.join(srcs)} -> "
            f"{', '.join(dsts)})."
        )

    if lines:
        port = rule.port or "<port>"
        remediation = (
            "Narrow the change to the flow that was actually blocked: "
            f"'permit tcp host {srcs[0]} host {dsts[0]} eq {port}'. "
            "Keep the same position argument."
        )
    return lines, remediation


def verify_change(
    actions: list[dict[str, Any]], flows: list[dict[str, Any]]
) -> VerificationReport:
    if not actions:
        return VerificationReport(False, ["No proposed action to verify."])
    if not flows:
        return VerificationReport(
            False, ["No observed denied flow to verify the change against."]
        )

    lines: list[str] = []
    ok = True
    remediation = ""

    for action in actions:
        device = str(action.get("device", ""))
        command = str(action.get("command", ""))
        rule = parse_acl_command(command)
        if rule is None:
            ok = False
            lines.append(f"{device}: could not parse '{command}' as an ACL rule.")
            remediation = (
                "The proposed command could not be parsed. Re-issue it as "
                "'permit tcp host <src> host <dst> eq <port>'."
            )
            continue

        base = device_policy(device)
        position = action.get("position")
        if rule.line < 0 and position is not None:
            rule.line = int(position)
            lines.append(f"{device}: inserting at line {rule.line}.")
        elif rule.line < 0:
            rule.line = max((item.line for item in base), default=0) + 10
            lines.append(
                f"{device}: no position given, simulating append at line {rule.line}."
            )

        matched_proposal = False
        for flow in flows:
            src_ip = str(flow.get("src", ""))
            dst_ip = str(flow.get("dst", ""))
            port = int(flow.get("port", 0) or 0)
            proto = str(flow.get("proto", "tcp"))
            action_result, hit = evaluate_flow(base + [rule], src_ip, dst_ip, port, proto)
            flow_text = f"{src_ip} -> {dst_ip}:{port}/{proto}"
            if action_result == "permit" and hit is rule:
                lines.append(f"PASS {flow_text} now permitted by the proposed rule.")
                matched_proposal = True
            elif action_result == "permit":
                lines.append(
                    f"PASS {flow_text} permitted, but by existing rule "
                    f"{hit.rule_id if hit else 'unknown'}, not the proposal."
                )
            else:
                ok = False
                blocker = hit.rule_id if hit else "implicit deny"
                blocker_line = hit.line if hit else "end of list"
                lines.append(
                    f"FAIL {flow_text} still denied by {blocker} at line {blocker_line}; "
                    f"the proposed rule at line {rule.line} is shadowed."
                )
                if hit is not None:
                    remediation = (
                        f"The permit is evaluated after {blocker} at line {blocker_line}, "
                        f"so it never takes effect. Call propose_policy_change again with "
                        f"the same command and position={max(hit.line - 1, 1)}. The position "
                        f"belongs in the position argument, not in the rationale text."
                    )

        # Only judge breadth once the rule is known to actually carry the flow;
        # a shadowed rule has a more urgent problem than being too wide.
        if matched_proposal:
            scope_lines, scope_fix = scope_findings(rule, flows)
            if scope_lines:
                ok = False
                lines.extend(scope_lines)
                remediation = scope_fix

    return VerificationReport(ok=ok, lines=lines, remediation=remediation)
