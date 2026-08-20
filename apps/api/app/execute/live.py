"""Post-change verification: what the device says, not what we predicted.

The simulator answers "would this work" against a policy read before the change.
This answers "did it work" against a policy read after it, which is a different
question and the only one that matters once a command has been sent. The two
disagreeing is exactly the signal worth acting on, because it means the model of
the device is wrong somewhere.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.firewall.base import FirewallStore
from app.firewall.policy import AclRule, as_network, evaluate_flow, parse_acl_command


@dataclass
class LiveReport:
    ok: bool
    lines: list[str] = field(default_factory=list)


def _same_rule(left: AclRule, right: AclRule) -> bool:
    def same_endpoint(first: str, second: str) -> bool:
        if first in ("any", "any4", "*") and second in ("any", "any4", "*"):
            return True
        try:
            return as_network(first) == as_network(second)
        except ValueError:
            return first == second

    return (
        (left.action, left.proto, left.port)
        == (right.action, right.proto, right.port)
        and same_endpoint(left.src, right.src)
        and same_endpoint(left.dst, right.dst)
    )


def _refresh(firewall: FirewallStore, device_id: str) -> list[AclRule]:
    """Re-read policy, defeating any cache: a stale read would verify nothing."""
    refresh = getattr(firewall, "refresh", None)
    if callable(refresh):
        refresh(device_id)
    return firewall.acl_policy(device_id)


def verify_applied(
    firewall: FirewallStore,
    actions: list[dict[str, Any]],
    flows: list[dict[str, Any]],
) -> LiveReport:
    """After a change: the rule is present and the flow is permitted."""
    lines: list[str] = []
    ok = True

    for action in actions:
        device = str(action.get("device", ""))
        command = str(action.get("command", ""))
        expected = parse_acl_command(command)
        policy = _refresh(firewall, device)

        if expected is not None:
            landed = next((rule for rule in policy if _same_rule(rule, expected)), None)
            if landed is None:
                ok = False
                lines.append(
                    f"LIVE FAIL {device}: the rule is not in the policy read back from the "
                    "device; the command was accepted but changed nothing."
                )
            else:
                lines.append(f"LIVE PASS {device}: rule present at line {landed.line}.")
                position = action.get("position")
                if position is not None and landed.line != int(position):
                    # Not a failure on its own; the flow check below decides.
                    lines.append(
                        f"LIVE NOTE {device}: rule landed at line {landed.line}, "
                        f"not the requested {int(position)}."
                    )

        for flow in flows:
            verdict, rule = evaluate_flow(
                policy,
                str(flow.get("src", "")),
                str(flow.get("dst", "")),
                int(flow.get("port", 0) or 0),
                str(flow.get("proto", "tcp")),
            )
            flow_text = f"{flow.get('src')} -> {flow.get('dst')}:{flow.get('port')}"
            if verdict == "permit":
                lines.append(f"LIVE PASS {flow_text} is permitted on the device.")
            else:
                ok = False
                blame = f" by {rule.rule_id or f'line {rule.line}'}" if rule else ""
                lines.append(f"LIVE FAIL {flow_text} is still '{verdict}'{blame}.")

    return LiveReport(ok=ok, lines=lines)


def verify_reverted(
    firewall: FirewallStore,
    actions: list[dict[str, Any]],
    flows: list[dict[str, Any]],
) -> LiveReport:
    """After a rollback: the rule is gone and the flow is back where it was."""
    lines: list[str] = []
    ok = True

    for action in actions:
        device = str(action.get("device", ""))
        expected = parse_acl_command(str(action.get("command", "")))
        policy = _refresh(firewall, device)

        if expected is not None and any(_same_rule(rule, expected) for rule in policy):
            ok = False
            lines.append(
                f"ROLLBACK FAIL {device}: the rule is still present after the reversal."
            )

        for flow in flows:
            verdict, _ = evaluate_flow(
                policy,
                str(flow.get("src", "")),
                str(flow.get("dst", "")),
                int(flow.get("port", 0) or 0),
                str(flow.get("proto", "tcp")),
            )
            flow_text = f"{flow.get('src')} -> {flow.get('dst')}:{flow.get('port')}"
            if verdict == "permit":
                ok = False
                lines.append(
                    f"ROLLBACK FAIL {flow_text} is still permitted; the device did not "
                    "return to its previous state."
                )
            else:
                lines.append(f"ROLLBACK PASS {flow_text} is '{verdict}' again.")

    return LiveReport(ok=ok, lines=lines)
