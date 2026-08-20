"""Read-only Cisco IOS backend.

IOS differs from ASA in three ways that matter to the simulator: addresses are
matched with wildcard bits rather than netmasks, hit counters are printed as
`(N matches)` on the entry itself, and access lists are grouped under a header
instead of repeating the list name per line. Everything downstream of the parser
is shared, so a second vendor changes only how text becomes `AclRule`.
"""

from __future__ import annotations

import logging
import re
from ipaddress import IPv4Address, ip_address
from typing import Any

from app.firewall.asa import AclParseResult
from app.firewall.base import FlowQuery
from app.firewall.nat import NatAssessment
from app.firewall.objectgroup import port_value
from app.firewall.policy import AclRule, evaluate_flow
from app.firewall.ssh import Credential, SshDevice

logger = logging.getLogger(__name__)

HEADER_RE = re.compile(
    r"^(?:(?P<kind>Standard|Extended)\s+IP\s+access\s+list\s+(?P<name>\S+)"
    r"|IP\s+access\s+list\s+(?P<kind2>standard|extended)\s+(?P<name2>\S+))\s*$",
    re.IGNORECASE,
)
MATCHES_RE = re.compile(r"\((\d+)\s+matches?\)", re.IGNORECASE)
SEQ_RE = re.compile(r"^(\d+)\s+(.*)$")
PORT_OPS = ("eq", "range", "gt", "lt", "neq")


def wildcard_to_prefix(address: str, wildcard: str) -> str | None:
    """`10.10.1.0 0.0.0.255` -> `10.10.1.0/255.255.255.0`.

    Non-contiguous wildcards are legal on IOS and cannot be expressed as a
    prefix; those return None so the rule is left unmodelled rather than
    silently widened.
    """
    try:
        host = ip_address(address)
        bits = int(IPv4Address(wildcard))
    except ValueError:
        return None
    if not isinstance(host, IPv4Address):
        return None

    netmask = (~bits) & 0xFFFFFFFF
    inverted = bits + 1
    if inverted & bits:  # not a run of low bits, so not contiguous
        return None
    return f"{host}/{IPv4Address(netmask)}"


def _endpoint(tokens: list[str], index: int) -> tuple[str | None, int]:
    token = tokens[index]
    if token == "any":
        return "any", index + 1
    if token == "host":
        return tokens[index + 1], index + 2
    if token in ("object-group", "addrgroup"):
        return None, index + 2
    if index + 1 < len(tokens):
        spec = wildcard_to_prefix(token, tokens[index + 1])
        if spec is not None:
            return spec, index + 2
    # A bare address with no wildcard is a host on IOS.
    try:
        ip_address(token)
    except ValueError:
        return None, index + 1
    return token, index + 1


def _port(tokens: list[str], index: int) -> tuple[int | None, int, bool]:
    """Returns (port, next index, modelled). `gt`/`lt`/`neq` are not modelled."""
    if index >= len(tokens) or tokens[index] not in PORT_OPS:
        return None, index, True
    operator = tokens[index]
    if operator == "eq" and index + 1 < len(tokens):
        return port_value(tokens[index + 1]), index + 2, True
    return None, index + 2, False


def _strip_trailing(tokens: list[str]) -> list[str]:
    keep: list[str] = []
    for token in tokens:
        if token in ("log", "log-input", "established", "fragments", "time-range"):
            break
        keep.append(token)
    return keep


def parse_show_ip_access_lists(output: str) -> AclParseResult:
    """Parse `show ip access-lists` into ordered rules."""
    result = AclParseResult()
    acl = ""
    extended = True
    fallback_line = 0

    for raw_line in (output or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue

        header = HEADER_RE.match(line)
        if header:
            acl = header.group("name") or header.group("name2") or ""
            kind = (header.group("kind") or header.group("kind2") or "extended").lower()
            extended = kind == "extended"
            fallback_line = 0
            continue

        if not acl or line.lower().startswith("remark"):
            continue

        hits_match = MATCHES_RE.search(line)
        hits = int(hits_match.group(1)) if hits_match else 0
        body = MATCHES_RE.sub("", line).strip()

        seq = SEQ_RE.match(body)
        if seq:
            number = int(seq.group(1))
            body = seq.group(2).strip()
        else:
            fallback_line += 10
            number = fallback_line

        rule = _rule_from_entry(body, acl, number, hits, extended)
        result.rules.append(rule)

    result.rules.sort(key=lambda item: item.line)
    return result


def _unparsed(acl: str, number: int, raw: str) -> AclRule:
    return AclRule(
        line=number,
        action="unparsed",
        proto="",
        src="",
        dst="",
        port=None,
        rule_id=f"{acl}-{number}",
        acl=acl,
        raw=raw,
    )


def _rule_from_entry(body: str, acl: str, number: int, hits: int, extended: bool) -> AclRule:
    tokens = _strip_trailing(body.replace(",", " ").split())
    if not tokens or tokens[0] not in ("permit", "deny"):
        return _unparsed(acl, number, body)

    action = tokens[0]
    rule_id = f"{acl}-{number}"

    if not extended:
        # `permit 10.10.1.0, wildcard bits 0.0.0.255`
        cleaned = [token for token in tokens[1:] if token not in ("wildcard", "bits")]
        source, _ = _endpoint(cleaned, 0) if cleaned else (None, 0)
        if source is None:
            return _unparsed(acl, number, body)
        return AclRule(
            line=number,
            action=action,
            proto="ip",
            src=source,
            dst="any",
            port=None,
            rule_id=rule_id,
            hits=hits,
            acl=acl,
            raw=body,
        )

    if len(tokens) < 4:
        return _unparsed(acl, number, body)

    proto = tokens[1]
    index = 2
    try:
        source, index = _endpoint(tokens, index)
        if source is None:
            return _unparsed(acl, number, body)
        _, index, source_port_ok = _port(tokens, index)
        destination, index = _endpoint(tokens, index)
        if destination is None:
            return _unparsed(acl, number, body)
        port, _, dest_port_ok = _port(tokens, index)
    except IndexError:
        return _unparsed(acl, number, body)

    if not source_port_ok or not dest_port_ok:
        return _unparsed(acl, number, body)

    return AclRule(
        line=number,
        action=action,
        proto=proto,
        src=source,
        dst=destination,
        port=port,
        rule_id=rule_id,
        hits=hits,
        acl=acl,
        raw=body,
    )


NAT_TRANSLATION_RE = re.compile(
    r"^(?P<proto>\S+)\s+(?P<inside_global>\S+)\s+(?P<inside_local>\S+)\s+", re.IGNORECASE
)


def parse_show_ip_nat_translations(output: str) -> list[tuple[str, str]]:
    """Pairs of (inside global, inside local) with ports stripped."""
    pairs: list[tuple[str, str]] = []
    for raw_line in (output or "").splitlines():
        line = raw_line.strip()
        if not line or line.lower().startswith("pro "):
            continue
        match = NAT_TRANSLATION_RE.match(line)
        if not match:
            continue
        globally = match.group("inside_global").split(":")[0]
        locally = match.group("inside_local").split(":")[0]
        if globally == "---" or locally == "---":
            continue
        if globally != locally:
            pairs.append((globally, locally))
    return pairs


class CiscoIosFirewall(SshDevice):
    """Live IOS router or switch over SSH, restricted to `show` commands."""

    device_type = "cisco_ios"

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

    def describe(self) -> str:
        return f"cisco-ios {self.host} (read-only)"

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

    def acl_hits(self, device_id: str, rule_id: str | None = None) -> list[dict[str, Any]]:
        rows = [
            {
                "device": device_id,
                "rule_id": rule.rule_id,
                "acl": rule.acl,
                "line": rule.line,
                "action": rule.action,
                "proto": rule.proto,
                "src": rule.src,
                "dst": rule.dst,
                "port": rule.port,
                "hits": rule.hits,
            }
            for rule in self.acl_policy(device_id)
            if rule.action in ("permit", "deny")
        ]
        if rule_id:
            rows = [row for row in rows if row["rule_id"] == rule_id]
        return sorted(rows, key=lambda row: row["line"])

    def nat_assessment(self, device_id: str, addresses: list[str]) -> NatAssessment:
        """IOS reports live translations rather than a policy we can evaluate.

        An address that appears on either side of an active translation makes the
        simulation untrustworthy; an empty table only means nothing is translated
        right now, which we say rather than treating as proof.
        """
        try:
            pairs = parse_show_ip_nat_translations(self._send("show ip nat translations"))
        except Exception:  # noqa: BLE001
            logger.warning("%s: could not read NAT translations", device_id)
            return NatAssessment(unresolved=["NAT table could not be read from the device"])

        wanted = set(addresses)
        translated = [
            f"{globally} <-> {locally}"
            for globally, locally in pairs
            if globally in wanted or locally in wanted
        ]
        return NatAssessment(translated=translated)
