"""NAT detection.

On ASA 8.3 and later an ACL is matched against the real address of a host, not
the translated one. Our evidence comes from deny logs and from whatever the
operator typed, either of which may be the mapped side. Simulating an ACL
against the wrong side of a translation produces a confident, wrong answer.

We therefore do not attempt to model NAT. We detect whether any translation
could touch the flow and, if it can, decline to give a verdict. Identity NAT is
excluded because it leaves addresses unchanged.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from ipaddress import ip_address, ip_network

from app.firewall.objectgroup import ObjectGroup, expand_object

NAT_LINE_RE = re.compile(
    r"^\s*\d+\s+\(([^)]+)\)\s+to\s+\(([^)]+)\)\s+source\s+(.*)$", re.IGNORECASE
)
CONFIG_NAT_RE = re.compile(
    r"^\s*nat\s+\(([^)]+),\s*([^)]+)\)\s+(?:\d+\s+)?source\s+(.*)$", re.IGNORECASE
)


@dataclass
class NatRule:
    raw: str
    from_zone: str
    to_zone: str
    kind: str  # static, dynamic
    identity: bool
    operands: list[str] = field(default_factory=list)


@dataclass
class NatAssessment:
    translated: list[str] = field(default_factory=list)
    unresolved: list[str] = field(default_factory=list)

    @property
    def applies(self) -> bool:
        return bool(self.translated)


def parse_show_nat(output: str) -> list[NatRule]:
    """Parse `show nat` or `show running-config nat`.

    Only enough structure is extracted to answer "could this touch the flow".
    """
    rules: list[NatRule] = []
    for raw_line in (output or "").splitlines():
        line = raw_line.rstrip()
        if not line.strip() or line.lstrip().lower().startswith("translate_hits"):
            continue

        match = NAT_LINE_RE.match(line)
        if match:
            from_zone, to_zone, body = match.group(1), match.group(2), match.group(3)
        else:
            config = CONFIG_NAT_RE.match(line)
            if not config:
                continue
            from_zone, to_zone, body = config.group(1), config.group(2), config.group(3)

        rules.extend(_rules_from_body(line, from_zone.strip(), to_zone.strip(), body))
    return rules


def _rules_from_body(raw: str, from_zone: str, to_zone: str, body: str) -> list[NatRule]:
    tokens = body.split()
    rules: list[NatRule] = []
    index = 0
    section = "source"

    while index < len(tokens):
        token = tokens[index].lower()
        if token == "destination":
            section = "destination"
            index += 1
            continue
        if token in ("static", "dynamic"):
            operands = _operands(tokens, index + 1)
            if not operands:
                index += 1
                continue
            identity = token == "static" and len(operands) >= 2 and operands[0] == operands[1]
            rules.append(
                NatRule(
                    raw=raw.strip(),
                    from_zone=from_zone,
                    to_zone=to_zone,
                    kind=token,
                    identity=identity,
                    # The real address is the first operand for a source rule and
                    # the second for a destination rule.
                    operands=operands[:2] if section == "source" else list(reversed(operands[:2])),
                )
            )
            index += 1 + len(operands)
            continue
        index += 1

    return rules


STOP_WORDS = {"destination", "service", "description", "inactive", "unidirectional", "no-proxy-arp"}


def _operands(tokens: list[str], start: int) -> list[str]:
    operands: list[str] = []
    for token in tokens[start:]:
        if token.lower() in STOP_WORDS:
            break
        operands.append(token)
        if len(operands) == 2:
            break
    return operands


def _covers(operand: str, address: str, objects: dict[str, ObjectGroup]) -> bool | None:
    """True/False if we can tell, None if the operand is not resolvable."""
    if operand.lower() in ("any", "any4", "any6", "interface"):
        # `interface` is PAT to the outside address; `any` in a NAT operand is
        # broad enough that pretending it does not match would be dishonest.
        return operand.lower() != "interface"

    candidates: list[str] = []
    named = objects.get(operand.lower())
    if named is not None:
        expansion = expand_object(operand, objects)
        if not expansion.complete and not expansion.networks:
            return None
        candidates = expansion.networks
    else:
        candidates = [operand]

    try:
        target = ip_address(address)
    except ValueError:
        return None

    resolved_any = False
    for candidate in candidates:
        network = _as_network(candidate)
        if network is None:
            continue
        resolved_any = True
        if target in network:
            return True
    return False if resolved_any else None


def _as_network(spec: str):
    text = spec.strip()
    if "/" in text:
        try:
            return ip_network(text, strict=False)
        except ValueError:
            return None
    try:
        return ip_network(f"{text}/32", strict=False)
    except ValueError:
        return None


def assess_flow(
    rules: list[NatRule],
    addresses: list[str],
    objects: dict[str, ObjectGroup] | None = None,
) -> NatAssessment:
    """Decide whether any translation could apply to the addresses in the flow."""
    objects = objects or {}
    assessment = NatAssessment()

    for rule in rules:
        if rule.identity:
            continue
        unresolved = False
        for operand in rule.operands:
            for address in addresses:
                verdict = _covers(operand, address, objects)
                if verdict is True:
                    if rule.raw not in assessment.translated:
                        assessment.translated.append(rule.raw)
                    break
                if verdict is None:
                    unresolved = True
            else:
                continue
            break
        else:
            if unresolved and rule.raw not in assessment.unresolved:
                assessment.unresolved.append(rule.raw)

    return assessment
