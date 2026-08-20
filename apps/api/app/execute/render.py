"""Turning an approved action into the exact lines a device is sent.

The simulator splices a proposed rule in at a stated position and judges the
result. If the command actually sent does not carry that position, the device
appends the rule instead, the deny that prompted the change still shadows it,
and a change that simulated clean does nothing. The two must agree, so the
position is materialised into the command here rather than left implied.
"""

from __future__ import annotations

import re
from typing import Any

# `access-list NAME [line N] [extended] permit ...`
ASA_RE = re.compile(
    r"^(?P<head>access-list\s+(?P<acl>\S+))\s+(?P<rest>(?:line\s+\d+\s+)?.*)$",
    re.IGNORECASE,
)
HAS_LINE = re.compile(r"^line\s+\d+\b", re.IGNORECASE)
IOS_ACL_RE = re.compile(
    r"^ip\s+access-list\s+(?:extended|standard)\s+(?P<acl>\S+)\s+(?P<body>.+)$", re.IGNORECASE
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


def device_commands(command: str, position: int | None, platform: str) -> list[str]:
    """The literal lines to send, in order."""
    text = (command or "").strip()
    if not text:
        return []

    removal = text.lower().startswith("no ")
    body = text[3:].strip() if removal else text

    # EOS sequences entries inside the ACL exactly as IOS does.
    if platform in ("cisco_ios", "arista_eos"):
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
