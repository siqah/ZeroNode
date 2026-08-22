from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel, Field

from app.config import settings
from app.firewall.base import FirewallStore, FlowQuery
from app.firewall.normalize import normalise_vendor
from app.store import TopologyStore
from app.verify import verify_change, verify_rollback

MAX_VERIFY_ATTEMPTS = 3

DEVICE_PATTERN = r"^[A-Za-z][A-Za-z0-9_-]*$"


def _firewall_platform(firewall: FirewallStore) -> str:
    platform = getattr(firewall, "platform", None)
    if callable(platform):
        return normalise_vendor(platform())
    if isinstance(platform, str) and platform:
        return normalise_vendor(platform)
    return normalise_vendor(settings.firewall_backend)


class PathTraceInput(BaseModel):
    source_device: str = Field(pattern=DEVICE_PATTERN)
    target_device: str = Field(pattern=DEVICE_PATTERN)


class BlastRadiusInput(BaseModel):
    device_name: str = Field(pattern=DEVICE_PATTERN)


class BoundaryInput(BaseModel):
    source_device: str = Field(pattern=DEVICE_PATTERN)
    target_device: str = Field(pattern=DEVICE_PATTERN)


class DelegateFirewallInput(BaseModel):
    context: str
    target_devices: list[str]


class ResolveInput(BaseModel):
    summary: str


class DeniedFlowsInput(BaseModel):
    source_device: str = Field(pattern=DEVICE_PATTERN)
    target_device: str = Field(pattern=DEVICE_PATTERN)
    port: int = Field(default=443, ge=1, le=65535)


class AclHitsInput(BaseModel):
    device_id: str = Field(pattern=DEVICE_PATTERN)
    rule_id: str | None = None


class ProposeChangeInput(BaseModel):
    device_id: str = Field(pattern=DEVICE_PATTERN)
    command: str
    rationale: str
    position: int | None = Field(
        default=None,
        description=(
            "ACL line number to insert the rule at. Required when an existing deny "
            "would otherwise match first, since ACLs are evaluated in line order."
        ),
    )
    rollback: str = Field(
        default="",
        description=(
            "The command that reverses this change, usually 'no <the same command>'. "
            "Leave empty and the removal is derived, then simulated either way."
        ),
    )


@dataclass
class ToolResult:
    content: str
    state_update: dict[str, Any] = field(default_factory=dict)
    goto: str | None = None


@dataclass
class ToolContext:
    topology: TopologyStore
    firewall: FirewallStore


@dataclass
class ToolSpec:
    name: str
    description: str
    args_model: type[BaseModel]
    handler: Callable[[BaseModel, dict[str, Any], ToolContext], ToolResult]


def _unknown_device(name: str, topology: TopologyStore) -> str:
    return f"Error: device '{name}' not found. Available: {topology.known_devices()}"


def handle_path_trace(
    args: PathTraceInput, _state: dict[str, Any], ctx: ToolContext
) -> ToolResult:
    if args.source_device not in ctx.topology.known_devices():
        return ToolResult(_unknown_device(args.source_device, ctx.topology))
    if args.target_device not in ctx.topology.known_devices():
        return ToolResult(_unknown_device(args.target_device, ctx.topology))
    path = ctx.topology.path_trace(args.source_device, args.target_device)
    if not path:
        return ToolResult(
            f"Error: No physical path found between {args.source_device} and {args.target_device}. "
            "Call security_boundary_check next."
        )
    text = "Path Trace Success. Traffic flows through: " + " -> ".join(path)
    return ToolResult(content=text, state_update={"topology_context": text})


def handle_blast_radius(
    args: BlastRadiusInput, _state: dict[str, Any], ctx: ToolContext
) -> ToolResult:
    if args.device_name not in ctx.topology.known_devices():
        return ToolResult(_unknown_device(args.device_name, ctx.topology))
    impacts = ctx.topology.blast_radius(args.device_name)
    if not impacts:
        return ToolResult(f"No downstream neighbors for {args.device_name}.")
    parts = [
        f"{item.device} ({item.security_zone or 'unzoned'})" for item in impacts
    ]
    return ToolResult(f"Blast radius of {args.device_name}: " + ", ".join(parts))


def handle_security_boundary(
    args: BoundaryInput, _state: dict[str, Any], ctx: ToolContext
) -> ToolResult:
    if args.source_device not in ctx.topology.known_devices():
        return ToolResult(_unknown_device(args.source_device, ctx.topology))
    if args.target_device not in ctx.topology.known_devices():
        return ToolResult(_unknown_device(args.target_device, ctx.topology))
    result = ctx.topology.security_boundary(args.source_device, args.target_device)
    if not result:
        return ToolResult(
            f"Error: missing zone membership for {args.source_device} or {args.target_device}."
        )
    text = (
        f"source_zone={result.source_zone} dest_zone={result.dest_zone} "
        f"crosses_boundary={str(result.crosses_boundary).lower()}"
    )
    return ToolResult(content=text, state_update={"zone_context": text})


def handle_delegate_firewall(
    args: DelegateFirewallInput, state: dict[str, Any], ctx: ToolContext
) -> ToolResult:
    known = (state.get("topology_context") or "") + (state.get("zone_context") or "")
    if not known.strip():
        return ToolResult(
            "Error: query topology (security_boundary_check or trace_network_path) "
            "before delegating."
        )
    devices = ", ".join(args.target_devices)
    return ToolResult(
        content=f"Delegated to firewall_specialist for {devices}.",
        state_update={
            "active_worker": "firewall",
            "task_brief": (
                f"Task delegated from Supervisor. Context: {args.context}. "
                f"Target devices: {args.target_devices}"
            ),
        },
        goto="firewall_specialist",
    )


def handle_resolve(
    args: ResolveInput, _state: dict[str, Any], ctx: ToolContext
) -> ToolResult:
    return ToolResult(
        content="Incident marked resolved.",
        state_update={"findings_summary": args.summary, "active_worker": ""},
        goto="__end__",
    )


def handle_denied_flows(
    args: DeniedFlowsInput, _state: dict[str, Any], ctx: ToolContext
) -> ToolResult:
    source_ip = ctx.topology.device_ip(args.source_device)
    target_ip = ctx.topology.device_ip(args.target_device)
    if not source_ip or not target_ip:
        missing = args.source_device if not source_ip else args.target_device
        return ToolResult(f"Error: no address known for {missing}; cannot query the firewall.")

    query = FlowQuery(
        source_device=args.source_device,
        source_ip=source_ip,
        target_device=args.target_device,
        target_ip=target_ip,
        port=args.port,
    )
    rows = ctx.firewall.denied_flows(query)
    if not rows:
        return ToolResult(
            f"No denied flows between {args.source_device} and {args.target_device} "
            f"on port {args.port}."
        )
    return ToolResult(content=str(rows), state_update={"denied_flows": rows})


def handle_acl_hits(
    args: AclHitsInput, _state: dict[str, Any], ctx: ToolContext
) -> ToolResult:
    rows = ctx.firewall.acl_hits(args.device_id, args.rule_id)
    if not rows:
        return ToolResult(f"No ACL hits on {args.device_id}.")
    return ToolResult(content=str(rows))


def handle_propose_change(
    args: ProposeChangeInput, state: dict[str, Any], ctx: ToolContext
) -> ToolResult:
    if args.device_id not in ctx.topology.known_devices():
        return ToolResult(_unknown_device(args.device_id, ctx.topology))
    action = {
        "device": args.device_id,
        "action": "add_acl_exception",
        "command": args.command,
        "rationale": args.rationale,
        "position": args.position,
        "vendor": _firewall_platform(ctx.firewall),
    }

    # Simulate the change before a human is asked to approve it: an engineer
    # should never be shown a command that would not actually restore the flow.
    flows = list(state.get("denied_flows") or [])
    report = verify_change([action], flows, ctx.firewall)
    attempts = int(state.get("verify_attempts") or 0)

    if not report.ok and attempts < MAX_VERIFY_ATTEMPTS:
        return ToolResult(
            content=(
                "Change NOT queued. Simulation says it would not restore the flow. "
                + " ".join(report.lines)
                + " "
                + report.remediation
            ),
            state_update={"verify_attempts": attempts + 1, "verification": report.lines},
        )

    # Nothing should reach the gate without a reversal that has been shown to work.
    rollback = verify_rollback(action, flows, ctx.firewall, args.rollback)
    if not rollback.ok and attempts < MAX_VERIFY_ATTEMPTS:
        return ToolResult(
            content=(
                "Change NOT queued. The rollback would not restore the previous state. "
                + " ".join(rollback.lines)
                + " "
                + rollback.remediation
            ),
            state_update={"verify_attempts": attempts + 1, "verification": rollback.lines},
        )

    action["rollback"] = rollback.command
    action["rollback_source"] = rollback.source
    action["rollback_verified"] = rollback.ok
    action["verified"] = report.ok and rollback.ok
    action["verification"] = report.lines + rollback.lines
    status = "verified" if action["verified"] else "NOT VERIFIED after retries"
    return ToolResult(
        content=(
            f"Proposed change queued for human approval ({status}). "
            f"Rollback: {rollback.command}"
        ),
        state_update={
            "pending_actions": [action],
            "findings_summary": args.rationale,
            "verification": action["verification"],
        },
        goto="execute_change",
    )


SUPERVISOR_TOOLS: dict[str, ToolSpec] = {
    "trace_network_path": ToolSpec(
        "trace_network_path",
        "Find devices on the shortest physical path between two hostnames.",
        PathTraceInput,
        handle_path_trace,  # type: ignore[arg-type]
    ),
    "blast_radius": ToolSpec(
        "blast_radius",
        "List downstream neighbors and their security zones.",
        BlastRadiusInput,
        handle_blast_radius,  # type: ignore[arg-type]
    ),
    "security_boundary_check": ToolSpec(
        "security_boundary_check",
        "Check whether traffic between two devices crosses a firewall zone boundary.",
        BoundaryInput,
        handle_security_boundary,  # type: ignore[arg-type]
    ),
    "delegate_to_firewall_specialist": ToolSpec(
        "delegate_to_firewall_specialist",
        "Hand the investigation to the firewall specialist. Requires topology first.",
        DelegateFirewallInput,
        handle_delegate_firewall,  # type: ignore[arg-type]
    ),
    "mark_incident_resolved": ToolSpec(
        "mark_incident_resolved",
        "End the investigation with a summary.",
        ResolveInput,
        handle_resolve,  # type: ignore[arg-type]
    ),
}

FIREWALL_TOOLS: dict[str, ToolSpec] = {
    "get_denied_flows": ToolSpec(
        "get_denied_flows",
        "Return minified denied flows between two devices.",
        DeniedFlowsInput,
        handle_denied_flows,  # type: ignore[arg-type]
    ),
    "get_acl_hits": ToolSpec(
        "get_acl_hits",
        "Return minified ACL hit counters on a firewall.",
        AclHitsInput,
        handle_acl_hits,  # type: ignore[arg-type]
    ),
    "propose_policy_change": ToolSpec(
        "propose_policy_change",
        "Queue a CLI/policy change for human approval. Does not execute it.",
        ProposeChangeInput,
        handle_propose_change,  # type: ignore[arg-type]
    ),
    "resolve_without_change": ToolSpec(
        "resolve_without_change",
        "Close the incident when no ACL change is required.",
        ResolveInput,
        handle_resolve,  # type: ignore[arg-type]
    ),
}
