"""Cisco ASA object-group parsing and expansion.

Real policies are written against object-groups, so a simulator that cannot
resolve them is a simulator that cannot judge real change requests. Expansion is
deliberately conservative: any member this parser does not understand marks the
whole group incomplete, and an incomplete group makes the rule unmodellable
rather than quietly narrower than it really is.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from app.firewall.policy import PORT_ALIASES

GROUP_HEADER_RE = re.compile(
    r"^object-group\s+(?P<kind>network|service|protocol|icmp-type)\s+(?P<name>\S+)"
    r"(?:\s+(?P<proto>tcp|udp|tcp-udp))?\s*$",
    re.IGNORECASE,
)
# A range wider than this is treated as unmodellable rather than expanded.
MAX_PORT_RANGE = 64


@dataclass
class ObjectGroup:
    name: str
    kind: str
    networks: list[str] = field(default_factory=list)
    ports: list[int] = field(default_factory=list)
    protocols: list[str] = field(default_factory=list)
    members: list[str] = field(default_factory=list)
    object_refs: list[str] = field(default_factory=list)
    complete: bool = True


def port_value(token: str) -> int | None:
    if token.isdigit():
        return int(token)
    return PORT_ALIASES.get(token)


def expand_range(low: str, high: str) -> list[int] | None:
    start, end = port_value(low), port_value(high)
    if start is None or end is None or end < start:
        return None
    if end - start + 1 > MAX_PORT_RANGE:
        return None
    return list(range(start, end + 1))


def _network_member(tokens: list[str]) -> str | None:
    """`host X`, `A.B.C.D MASK`, or a bare address."""
    if not tokens:
        return None
    if tokens[0] == "host" and len(tokens) > 1:
        return tokens[1]
    if tokens[0] in ("any", "any4"):
        return "any"
    if len(tokens) > 1 and re.fullmatch(r"\d+\.\d+\.\d+\.\d+", tokens[1]):
        return f"{tokens[0]}/{tokens[1]}"
    if re.match(r"^\d+\.\d+\.\d+\.\d+(/\d+)?$", tokens[0]):
        return tokens[0]
    return None


def parse_show_object_groups(output: str) -> dict[str, ObjectGroup]:
    """Parse `show object-group` output, keyed by lowercased group name."""
    groups: dict[str, ObjectGroup] = {}
    current: ObjectGroup | None = None

    for raw_line in (output or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue

        header = GROUP_HEADER_RE.match(line)
        if header:
            current = ObjectGroup(
                name=header.group("name"),
                kind=header.group("kind").lower(),
            )
            if header.group("proto"):
                current.protocols.append(header.group("proto").lower())
            groups[current.name.lower()] = current
            continue

        if current is None or line.lower().startswith("description"):
            continue

        tokens = line.lower().split()
        keyword, rest = tokens[0], tokens[1:]

        if keyword == "group-object" and rest:
            current.members.append(rest[0])
        elif keyword == "network-object":
            if rest[:1] == ["object"] and len(rest) > 1:
                current.object_refs.append(rest[1])
                continue
            member = _network_member(rest)
            if member is None:
                current.complete = False
            else:
                current.networks.append(member)
        elif keyword == "port-object":
            if rest[:1] == ["eq"] and len(rest) > 1:
                port = port_value(rest[1])
                if port is None:
                    current.complete = False
                else:
                    current.ports.append(port)
            elif rest[:1] == ["range"] and len(rest) > 2:
                expanded = expand_range(rest[1], rest[2])
                if expanded is None:
                    current.complete = False
                else:
                    current.ports.extend(expanded)
            else:
                current.complete = False
        elif keyword == "protocol-object" and rest:
            current.protocols.append(rest[0])
        elif keyword == "service-object":
            _absorb_service_object(current, rest)
        elif keyword.endswith("-object"):
            current.complete = False

    return groups


def _absorb_service_object(group: ObjectGroup, rest: list[str]) -> None:
    """Handle `service-object tcp destination eq 8443` and its simpler forms."""
    if not rest:
        group.complete = False
        return
    if rest[0] == "object":
        if len(rest) > 1:
            group.object_refs.append(rest[1])
        else:
            group.complete = False
        return
    group.protocols.append(rest[0])
    if "eq" in rest:
        index = rest.index("eq")
        port = port_value(rest[index + 1]) if index + 1 < len(rest) else None
        if port is None:
            group.complete = False
        else:
            group.ports.append(port)
    elif "range" in rest:
        index = rest.index("range")
        expanded = (
            expand_range(rest[index + 1], rest[index + 2])
            if index + 2 < len(rest)
            else None
        )
        if expanded is None:
            group.complete = False
        else:
            group.ports.extend(expanded)
    elif len(rest) > 1:
        # Anything else carries a qualifier we are not modelling.
        group.complete = False


@dataclass
class Expansion:
    networks: list[str] = field(default_factory=list)
    ports: list[int] = field(default_factory=list)
    protocols: list[str] = field(default_factory=list)
    complete: bool = True


def expand_group(
    name: str,
    groups: dict[str, ObjectGroup],
    objects: dict[str, ObjectGroup] | None = None,
    _seen: set[str] | None = None,
) -> Expansion:
    """Flatten a group, its nested groups and any named objects it references.

    Unknown members, unreadable members and cycles all make the result
    incomplete, which stops a caller treating a partial expansion as the whole
    rule.
    """
    return _expand(name, groups, objects or {}, _seen if _seen is not None else set(), "group")


def expand_object(
    name: str, objects: dict[str, ObjectGroup], _seen: set[str] | None = None
) -> Expansion:
    return _expand(name, {}, objects, _seen if _seen is not None else set(), "object")


def _expand(
    name: str,
    groups: dict[str, ObjectGroup],
    objects: dict[str, ObjectGroup],
    seen: set[str],
    kind: str,
) -> Expansion:
    key = f"{kind}:{name.lower()}"
    if key in seen:
        return Expansion(complete=False)
    seen.add(key)

    registry = groups if kind == "group" else objects
    entry = registry.get(name.lower())
    if entry is None:
        return Expansion(complete=False)

    result = Expansion(
        networks=list(entry.networks),
        ports=list(entry.ports),
        protocols=list(entry.protocols),
        complete=entry.complete,
    )
    for member in entry.members:
        nested = _expand(member, groups, objects, seen, "group")
        result.networks.extend(nested.networks)
        result.ports.extend(nested.ports)
        result.protocols.extend(nested.protocols)
        result.complete = result.complete and nested.complete
    for ref in entry.object_refs:
        nested = _expand(ref, groups, objects, seen, "object")
        result.networks.extend(nested.networks)
        result.ports.extend(nested.ports)
        result.protocols.extend(nested.protocols)
        result.complete = result.complete and nested.complete
    return result


OBJECT_HEADER_RE = re.compile(
    r"^object\s+(?P<kind>network|service)\s+(?P<name>\S+)\s*$", re.IGNORECASE
)


def parse_show_objects(output: str) -> dict[str, ObjectGroup]:
    """Parse `show running-config object` into named objects, keyed lowercase."""
    objects: dict[str, ObjectGroup] = {}
    current: ObjectGroup | None = None

    for raw_line in (output or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue

        header = OBJECT_HEADER_RE.match(line)
        if header:
            current = ObjectGroup(name=header.group("name"), kind=header.group("kind").lower())
            objects[current.name.lower()] = current
            continue

        if current is None or line.lower().startswith("description"):
            continue

        tokens = line.lower().split()
        keyword, rest = tokens[0], tokens[1:]

        if keyword == "host" and rest:
            current.networks.append(rest[0])
        elif keyword == "subnet" and len(rest) > 1:
            current.networks.append(f"{rest[0]}/{rest[1]}")
        elif keyword == "range" and len(rest) > 1:
            expanded = _summarise_range(rest[0], rest[1])
            if expanded is None:
                current.complete = False
            else:
                current.networks.extend(expanded)
        elif keyword == "service":
            _absorb_service_object(current, rest)
        else:
            # fqdn, nat and anything else we do not model
            current.complete = False

    return objects


def _summarise_range(low: str, high: str) -> list[str] | None:
    from ipaddress import ip_address, summarize_address_range

    try:
        networks = list(summarize_address_range(ip_address(low), ip_address(high)))
    except (ValueError, TypeError):
        return None
    if len(networks) > 16:
        return None
    return [str(network) for network in networks]
