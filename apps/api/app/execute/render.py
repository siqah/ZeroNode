"""Turning an approved action into the exact lines a device is sent.

The simulator splices a proposed rule in at a stated position and judges the
result. If the command actually sent does not carry that position, the device
appends the rule instead, the deny that prompted the change still shadows it,
and a change that simulated clean does nothing. The two must agree, so the
position is materialised into the command here rather than left implied.
"""

from __future__ import annotations

import re
from ipaddress import ip_network
from typing import Any

from app.firewall.policy import parse_acl_command

# `access-list NAME [line N] [extended] permit ...`
ASA_RE = re.compile(
    r"^(?P<head>access-list\s+(?P<acl>\S+))\s+(?P<rest>(?:line\s+\d+\s+)?.*)$",
    re.IGNORECASE,
)
HAS_LINE = re.compile(r"^line\s+\d+\b", re.IGNORECASE)
IOS_ACL_RE = re.compile(
    r"^ip\s+access-list\s+(?:extended|standard)\s+(?P<acl>\S+)\s+(?P<body>.+)$", re.IGNORECASE
)
EOS_ACL_RE = re.compile(
    r"^ip\s+access-list\s+(?:(?:extended|standard)\s+)?"
    r"(?P<acl>\S+)\s+(?P<body>.+)$",
    re.IGNORECASE,
)


def asa_command(command: str, position: int | None) -> str:
    """`access-list X extended permit ...` -> `access-list X line N extended permit ...`"""
    match = ASA_RE.match(command.strip())
    if match is None or position is None:
        return command.strip()

    rest = match.group("rest").strip()
    if HAS_LINE.match(rest):
        return command.strip()
    return f"{match.group('head')} line {int(position)} {rest}"


def ios_commands(command: str, position: int | None) -> list[str]:
    """IOS sequences a rule inside the named ACL, not on the `ip access-list` line."""
    text = command.strip()
    match = IOS_ACL_RE.match(text)
    if match is None:
        return [text]

    body = match.group("body").strip()
    entry = f"{int(position)} {body}" if position is not None else body
    return [f"ip access-list extended {match.group('acl')}", entry]


def eos_commands(
    command: str, position: int | None, *, removal: bool = False
) -> list[str]:
    """EOS uses IOS-style ACL mode without the `extended` keyword."""
    match = EOS_ACL_RE.match(command.strip())
    if match is None:
        return [f"no {command.strip()}" if removal else command.strip()]

    context = f"ip access-list {match.group('acl')}"
    if removal and position is not None:
        # EOS removes a sequenced ACE by sequence number. Repeating the whole
        # ACE after `no` is accepted by IOS but not consistently by EOS.
        return [context, f"no {int(position)}"]

    body = match.group("body").strip()
    entry = f"{int(position)} {body}" if position is not None else body
    return [context, f"no {entry}" if removal else entry]


def _srl_prefix(value: str) -> str:
    if value in ("any", "any4", "*"):
        return "0.0.0.0/0"
    return str(ip_network(value if "/" in value else f"{value}/32", strict=False))


def srlinux_commands(
    command: str, position: int | None, *, removal: bool = False
) -> list[str]:
    """Render one modelled ACE as flat SR Linux candidate commands."""
    match = IOS_ACL_RE.match(command.strip())
    if match is None or position is None:
        return [command.strip()]

    base = (
        f"/ acl acl-filter {match.group('acl')} type ipv4 "
        f"entry {int(position)}"
    )
    if removal:
        return [f"delete {base}"]

    rule = parse_acl_command(command)
    if rule is None:
        return [command.strip()]

    action = "accept" if rule.action == "permit" else "drop"
    commands = [
        f"set {base} match ipv4 protocol {rule.proto}",
        f"set {base} match ipv4 source-ip prefix {_srl_prefix(rule.src)}",
        f"set {base} match ipv4 destination-ip prefix {_srl_prefix(rule.dst)}",
    ]
    if rule.port is not None:
        commands.append(
            f"set {base} match transport destination-port value {rule.port}"
        )
    commands.append(f"set {base} action {action}")
    return commands


def device_commands(command: str, position: int | None, platform: str) -> list[str]:
    """The literal lines to send, in order."""
    text = (command or "").strip()
    if not text:
        return []

    removal = text.lower().startswith("no ")
    body = text[3:].strip() if removal else text

    if platform == "nokia_srl":
        return srlinux_commands(body, position, removal=removal)

    if platform == "arista_eos":
        return eos_commands(body, position, removal=removal)

    if platform == "cisco_ios":
        lines = ios_commands(body, position)
        # On IOS the removal applies to the entry, not the ACL it lives in.
        return [lines[0], f"no {lines[1]}"] if removal and len(lines) > 1 else (
            [f"no {lines[0]}"] if removal else lines
        )

    rendered = asa_command(body, position)
    return [f"no {rendered}" if removal else rendered]


def rendered_for(action: dict[str, Any], platform: str, *, rollback: bool = False) -> list[str]:
    key = "rollback" if rollback else "command"
    position = action.get("position")
    return device_commands(str(action.get(key, "")), position, platform)
