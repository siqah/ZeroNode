"""Vendor ACL command normalisation into the shared policy model."""

from __future__ import annotations

import re

from app.firewall.policy import AclRule, parse_acl_command

VENDOR_ALIASES = {
    "cisco": "cisco_asa",
    "asa": "cisco_asa",
    "ios": "cisco_ios",
    "eos": "arista_eos",
    "arista": "arista_eos",
    "srl": "nokia_srl",
    "nokia": "nokia_srl",
    "nokia_srl": "nokia_srl",
    "cisco_asa": "cisco_asa",
    "cisco_ios": "cisco_ios",
    "arista_eos": "arista_eos",
}

IOS_ACL_RE = re.compile(
    r"^ip\s+access-list\s+(?:extended|standard)\s+\S+\s+(?P<body>.+)$",
    re.IGNORECASE,
)
EOS_ACL_RE = re.compile(
    r"^ip\s+access-list\s+(?:(?:extended|standard)\s+)?\S+\s+(?P<body>.+)$",
    re.IGNORECASE,
)


def normalise_vendor(vendor: str) -> str:
    key = (vendor or "").strip().lower().replace("-", "_")
    return VENDOR_ALIASES.get(key, key)


def acl_command_body(vendor: str, command: str) -> str:
    """Strip vendor-specific ACL wrappers so the shared parser can read the ACE."""
    text = (command or "").strip()
    key = normalise_vendor(vendor)
    if key == "cisco_ios":
        match = IOS_ACL_RE.match(text)
        return match.group("body").strip() if match else text
    if key == "arista_eos":
        match = EOS_ACL_RE.match(text)
        return match.group("body").strip() if match else text
    return text


def parse_vendor_acl(vendor: str, command: str) -> AclRule:
    """Parse a vendor CLI line into the shared ``AclRule`` representation."""
    body = acl_command_body(vendor, command)
    rule = parse_acl_command(body)
    if rule is None:
        rule = parse_acl_command(command)
    if rule is None:
        raise ValueError(f"could not parse ACL command for {vendor!r}: {command!r}")
    return rule


def parse_proposed_acl(command: str, *, vendor: str = "") -> AclRule | None:
    """Parse a proposed change, using vendor dispatch when the platform is known."""
    text = (command or "").strip()
    if not text:
        return None
    if vendor:
        try:
            return parse_vendor_acl(vendor, text)
        except ValueError:
            return None
    return parse_acl_command(text)
