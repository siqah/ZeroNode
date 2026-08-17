from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

TOOL_CALL_RE = re.compile(r"<tool_call>\s*(.*?)\s*</tool_call>", re.DOTALL | re.IGNORECASE)
UNCLOSED_TOOL_RE = re.compile(r"<tool_call>\s*(\{.*)", re.DOTALL | re.IGNORECASE)
THINKING_RE = re.compile(r"<thinking>\s*(.*?)\s*(?:</thinking>|$)", re.DOTALL | re.IGNORECASE)
FENCE_RE = re.compile(r"^```(?:json)?\s*|\s*```$", re.IGNORECASE)
ALERT_ENDPOINTS_RE = re.compile(
    r"([A-Za-z][A-Za-z0-9_-]*)\s+cannot reach\s+([A-Za-z][A-Za-z0-9_-]*)",
    re.IGNORECASE,
)
PATH_RE = re.compile(r"Traffic flows through:\s*(.+)", re.IGNORECASE)

DENY_LINE_RE = re.compile(r"'line':\s*(\d+)")


@dataclass(frozen=True)
class ParsedToolCall:
    name: str
    arguments: dict[str, Any]


def message_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for block in content:
            if isinstance(block, str):
                parts.append(block)
            elif isinstance(block, dict) and "text" in block:
                parts.append(str(block["text"]))
        return "".join(parts)
    return str(content)


def extract_thinking(text: str) -> str:
    match = THINKING_RE.search(text or "")
    return match.group(1).strip() if match else ""


def _candidate_json_blobs(text: str) -> list[str]:
    blobs: list[str] = []
    closed = TOOL_CALL_RE.search(text or "")
    if closed:
        blobs.append(closed.group(1).strip())
    unclosed = UNCLOSED_TOOL_RE.search(text or "")
    if unclosed:
        blobs.append(unclosed.group(1).strip())
    i = 0
    while True:
        start = (text or "").find("{", i)
        if start < 0:
            break
        depth = 0
        end = None
        for j, char in enumerate(text[start:], start):
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    end = j + 1
                    break
        if end is None:
            break
        blobs.append(text[start:end])
        i = start + 1
    return blobs


def _payload_to_call(raw: str) -> ParsedToolCall | None:
    cleaned = FENCE_RE.sub("", raw.strip())
    try:
        payload = json.loads(cleaned)
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None
    name = payload.get("name")
    arguments = payload.get("arguments", {})
    if not isinstance(name, str) or not name:
        return None
    if arguments is None:
        arguments = {}
    if not isinstance(arguments, dict):
        return None
    return ParsedToolCall(name=name, arguments=arguments)


def parse_tool_call(text: str) -> ParsedToolCall | None:
    for blob in _candidate_json_blobs(text or ""):
        parsed = _payload_to_call(blob)
        if parsed:
            return parsed
    return None


def path_hops(topology_context: str) -> list[str]:
    match = PATH_RE.search(topology_context or "")
    if not match:
        return []
    return [hop.strip() for hop in match.group(1).split("->") if hop.strip()]


def alert_endpoints(messages: list[Any]) -> tuple[str, str] | None:
    for message in reversed(messages or []):
        content = message_text(getattr(message, "content", message))
        found = ALERT_ENDPOINTS_RE.search(content)
        if found:
            return found.group(1), found.group(2).split(":")[0]
    return None


def denied_flow_facts(tool_log: list[str]) -> dict[str, str] | None:
    """Pull the deny record the firewall tool already returned."""
    for entry in reversed(tool_log or []):
        if not entry.startswith("get_denied_flows:"):
            continue
        src = re.search(r"'src':\s*'([^']+)'", entry)
        dst = re.search(r"'dst':\s*'([^']+)'", entry)
        port = re.search(r"'port':\s*(\d+)", entry)
        rule = re.search(r"'rule_id':\s*'([^']+)'", entry)
        if src and dst and port:
            return {
                "src": src.group(1),
                "dst": dst.group(1),
                "port": port.group(1),
                "rule_id": rule.group(1) if rule else "unknown",
            }
    return None


def deny_rule_line(tool_log: list[str]) -> int | None:
    """Find the line number of the denying rule, if the ACL was already read."""
    for entry in reversed(tool_log or []):
        if entry.startswith("get_acl_hits:") and "'action': 'deny'" in entry:
            match = DENY_LINE_RE.search(entry)
            if match:
                return int(match.group(1))
    return None


def infer_tool_call(
    *,
    allowed: set[str],
    topology_context: str,
    zone_context: str = "",
    tool_log: list[str] | None = None,
    messages: list[Any] | None = None,
) -> ParsedToolCall | None:
    """Advance the investigation when the model burns its budget on prose.

    The next step is chosen from state, not from the model's text, so a rambling
    turn cannot repeat a tool that already succeeded.
    """
    log = tool_log or []
    hops = path_hops(topology_context)
    ends = alert_endpoints(messages or [])
    if hops:
        src, dst = hops[0], hops[-1]
    elif ends:
        src, dst = ends
    else:
        src, dst = "Web_App", "DB_Primary"

    if "propose_policy_change" in allowed:
        facts = denied_flow_facts(log)
        if facts is None:
            return ParsedToolCall(
                name="get_denied_flows",
                arguments={"source_device": src, "target_device": dst},
            )
        deny_line = deny_rule_line(log)
        if deny_line is None:
            return ParsedToolCall(
                name="get_acl_hits",
                arguments={"device_id": "FW_Edge", "rule_id": facts["rule_id"]},
            )
        return ParsedToolCall(
            name="propose_policy_change",
            arguments={
                "device_id": "FW_Edge",
                "command": (
                    "access-list DMZ_TO_TRUST extended permit tcp "
                    f"host {facts['src']} host {facts['dst']} eq {facts['port']}"
                ),
                "position": max(deny_line - 1, 1),
                "rationale": (
                    f"Synthesized by ZeroNode from denied flow {facts['rule_id']} "
                    f"({facts['src']} -> {facts['dst']}:{facts['port']}) because the model "
                    "did not emit a tool call. Requires human review."
                ),
            },
        )

    if not hops:
        return ParsedToolCall(
            name="trace_network_path",
            arguments={"source_device": src, "target_device": dst},
        )
    if not (zone_context or "").strip() and "security_boundary_check" in allowed:
        return ParsedToolCall(
            name="security_boundary_check",
            arguments={"source_device": src, "target_device": dst},
        )
    if "delegate_to_firewall_specialist" in allowed:
        devices = [hop for hop in hops if hop]
        if "FW_Edge" not in devices:
            devices.insert(1, "FW_Edge")
        context = " ".join(part for part in (topology_context, zone_context) if part)
        return ParsedToolCall(
            name="delegate_to_firewall_specialist",
            arguments={
                "context": context or f"{src} cannot reach {dst}",
                "target_devices": devices,
            },
        )
    return None
