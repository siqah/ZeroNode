"""Simulate a proposed firewall change before a human is asked to approve it.

A proposal is only useful if the flow it targets would actually pass afterwards.
This module takes the device's current policy, splices the proposed rule in at
its stated position, and re-evaluates the denied flow with first-match
semantics. Two defects are caught: a permit shadowed by an earlier deny, which
looks correct in a change ticket and does nothing on the device, and a permit
that opens far more than the evidence justifies.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.firewall.base import FirewallStore
from app.firewall.normalize import parse_proposed_acl
from app.firewall.policy import AclRule, breadth, evaluate_flow


@dataclass
class VerificationReport:
    ok: bool
    lines: list[str]
    remediation: str = ""


def scope_findings(rule: AclRule, flows: list[dict[str, Any]]) -> tuple[list[str], str]:
    """Flag a permit that opens far more than the evidence justifies.

    Widening a single blocked flow into subnet-to-subnet access is the quiet way
    segmentation dies, and it reads as reasonable in a change ticket.
    """
    srcs = sorted({str(flow.get("src", "")) for flow in flows if flow.get("src")})
    dsts = sorted({str(flow.get("dst", "")) for flow in flows if flow.get("dst")})
    if not srcs or not dsts:
        return [], ""

    permitted = breadth(rule.src) * breadth(rule.dst)
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


@dataclass
class RollbackReport:
    ok: bool
    command: str
    source: str  # "model" when authored, "derived" when we produced it
    lines: list[str]
    remediation: str = ""


def derive_rollback(command: str) -> str:
    """The reversal of adding a line is removing it, which on Cisco is `no <line>`."""
    text = (command or "").strip()
    return text if text.lower().startswith("no ") else f"no {text}"


def verify_rollback(
    action: dict[str, Any],
    flows: list[dict[str, Any]],
    firewall: FirewallStore,
    rollback: str = "",
) -> RollbackReport:
    """Check that the proposal can actually be undone.

    A change nobody can reverse is not a change anyone should approve at two in
    the morning, so the reversal is simulated with the same machinery as the
    change: apply the proposal, apply the reversal, and require the flow to be
    back where it started.
    """
    command = str(action.get("command", ""))
    source = "model" if rollback.strip() else "derived"
    reversal = rollback.strip() or derive_rollback(command)

    device = str(action.get("device", ""))
    vendor = str(action.get("vendor") or "")
    proposed = parse_proposed_acl(command, vendor=vendor)
    if proposed is None:
        return RollbackReport(
            False, reversal, source, [f"{device}: the proposed command does not parse."]
        )

    base = firewall.acl_policy(device)
    position = action.get("position")
    proposed.line = int(position) if position is not None else (
        max((rule.line for rule in base), default=0) + 10
    )
    after_change = base + [proposed]

    removal = _removal_target(reversal, vendor=vendor)
    if removal is not None:
        if not _same_rule(removal, proposed):
            return RollbackReport(
                False,
                reversal,
                source,
                [
                    f"ROLLBACK {device}: '{reversal}' removes a different rule than the one "
                    f"being added."
                ],
                remediation=(
                    "The rollback must remove exactly the line being added: "
                    f"'{derive_rollback(command)}'."
                ),
            )
        restored = base
    else:
        # Not a removal, so treat it as a compensating rule appended after the change.
        compensating = parse_proposed_acl(reversal, vendor=vendor)
        if compensating is None:
            return RollbackReport(
                False,
                reversal,
                source,
                [f"ROLLBACK {device}: '{reversal}' does not parse as an ACL command."],
                remediation=(
                    f"Give the reversal as '{derive_rollback(command)}', or as an explicit "
                    "rule that restores the previous behaviour."
                ),
            )
        compensating.line = proposed.line - 1 if proposed.line > 1 else 1
        restored = after_change + [compensating]

    lines: list[str] = []
    ok = True
    for flow in flows:
        src_ip = str(flow.get("src", ""))
        dst_ip = str(flow.get("dst", ""))
        port = int(flow.get("port", 0) or 0)
        proto = str(flow.get("proto", "tcp"))
        before, _ = evaluate_flow(base, src_ip, dst_ip, port, proto)
        after, _ = evaluate_flow(restored, src_ip, dst_ip, port, proto)
        flow_text = f"{src_ip} -> {dst_ip}:{port}/{proto}"
        if before == after:
            lines.append(f"ROLLBACK PASS {flow_text} returns to '{before}' after the reversal.")
        else:
            ok = False
            lines.append(
                f"ROLLBACK FAIL {flow_text} is '{after}' after the reversal but was "
                f"'{before}' before the change."
            )

    remediation = (
        ""
        if ok
        else (
            "The reversal does not restore the previous behaviour. Use "
            f"'{derive_rollback(command)}'."
        )
    )
    return RollbackReport(
        ok=ok, command=reversal, source=source, lines=lines, remediation=remediation
    )


def _removal_target(command: str, *, vendor: str = "") -> AclRule | None:
    text = (command or "").strip()
    if not text.lower().startswith("no "):
        return None
    return parse_proposed_acl(text[3:], vendor=vendor)


def _same_rule(left: AclRule, right: AclRule) -> bool:
    return (left.action, left.proto, left.src, left.dst, left.port) == (
        right.action,
        right.proto,
        right.src,
        right.dst,
        right.port,
    )


def _nat_findings(
    firewall: FirewallStore, device: str, flows: list[dict[str, Any]]
) -> tuple[list[str], bool, str]:
    """Report translation that would invalidate the simulation.

    An ACL is matched against real addresses; the evidence may carry mapped
    ones. Where a translation could touch the flow we say so and stop, rather
    than producing a verdict that is confidently about the wrong packet.
    """
    assess = getattr(firewall, "nat_assessment", None)
    if assess is None:
        return [], False, ""

    addresses = sorted(
        {str(flow.get(key, "")) for flow in flows for key in ("src", "dst") if flow.get(key)}
    )
    if not addresses:
        return [], False, ""

    try:
        assessment = assess(device, addresses)
    except Exception:  # noqa: BLE001 - a backend without NAT support must not break verification
        return [], False, ""

    lines: list[str] = []
    if assessment.unresolved:
        lines.append(
            f"NOTE {device} has {len(assessment.unresolved)} NAT rule(s) that could not be "
            f"resolved: {assessment.unresolved}"
        )
    if not assessment.applies:
        return lines, False, ""

    lines.append(
        f"INCONCLUSIVE {device} translates addresses on this flow: {assessment.translated}. "
        "The ACL is evaluated against the real address, so this simulation cannot be trusted."
    )
    return (
        lines,
        True,
        (
            "Address translation applies to this flow. Confirm the real (untranslated) "
            "addresses with a human before proposing an ACL change; the simulator will not "
            "give a verdict while a translation is in play."
        ),
    )


def _unmodelled_above(policy: list[AclRule], line: int) -> list[AclRule]:
    return [rule for rule in policy if rule.action == "unparsed" and rule.line <= line]


def verify_change(
    actions: list[dict[str, Any]],
    flows: list[dict[str, Any]],
    firewall: FirewallStore,
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
        vendor = str(action.get("vendor") or "")
        rule = parse_proposed_acl(command, vendor=vendor)
        if rule is None:
            ok = False
            lines.append(f"{device}: could not parse '{command}' as an ACL rule.")
            remediation = (
                "The proposed command could not be parsed. Re-issue it as "
                "'permit tcp host <src> host <dst> eq <port>'."
            )
            continue

        base = firewall.acl_policy(device)
        nat_lines, nat_blocks, nat_fix = _nat_findings(firewall, device, flows)
        lines.extend(nat_lines)
        if nat_blocks:
            ok = False
            remediation = nat_fix

        position = action.get("position")
        if rule.line < 0 and position is not None:
            rule.line = int(position)
            lines.append(f"{device}: inserting at line {rule.line}.")
        elif rule.line < 0:
            rule.line = max((item.line for item in base), default=0) + 10
            lines.append(
                f"{device}: no position given, simulating append at line {rule.line}."
            )

        # A rule we could not model might match the flow first, so the simulation
        # cannot be trusted to be complete.
        blind = _unmodelled_above(base, rule.line)
        if blind:
            ok = False
            lines.append(
                f"INCONCLUSIVE {device} has {len(blind)} rule(s) above line {rule.line} "
                f"that could not be modelled: {[item.raw for item in blind]}"
            )
            remediation = (
                "The device policy contains rules this simulator cannot evaluate "
                "(object-groups or unsupported syntax). A human must review the ACL "
                "order manually before this change is applied."
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
