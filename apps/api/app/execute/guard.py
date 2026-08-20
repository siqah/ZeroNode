"""The preconditions for touching a device.

Approval is necessary and not sufficient. A human can only meaningfully approve
what was simulated, so execution re-checks the properties the gate depended on
rather than trusting that they were true when the button was pressed.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.firewall.policy import parse_acl_command


@dataclass
class GuardResult:
    ok: bool
    reasons: list[str]


def is_policy_command(command: str) -> bool:
    """Only ACL lines, and only ones our own parser understands.

    This is the narrowest useful rule: if the simulator could not model the
    command, nobody has demonstrated what it does, and it is not eligible to be
    sent to a device regardless of who approved it.
    """
    text = (command or "").strip()
    if not text:
        return False
    if text.lower().startswith("no "):
        text = text[3:]
    return parse_acl_command(text) is not None


def check(
    actions: list[dict[str, Any]], flows: list[dict[str, Any]], allowed_devices: set[str]
) -> GuardResult:
    reasons: list[str] = []

    if not actions:
        reasons.append("there is nothing to execute")

    if not flows:
        # Without evidence there is no post-change check, and an unverifiable
        # change is one nobody can prove worked.
        reasons.append("no denied-flow evidence, so the result could not be verified")

    for action in actions:
        device = str(action.get("device", ""))
        command = str(action.get("command", ""))
        rollback = str(action.get("rollback", ""))

        if device not in allowed_devices:
            reasons.append(
                f"{device or '(no device)'} is not in EXECUTION_DEVICES; "
                "enabling execution does not enable every device"
            )
        if not action.get("verified"):
            reasons.append(f"{device}: the change did not pass simulation")
        if not action.get("rollback_verified") or not rollback:
            reasons.append(f"{device}: no verified rollback, so this could not be undone")
        if not is_policy_command(command):
            reasons.append(f"{device}: '{command}' is not an ACL line this system can model")
        if rollback and not is_policy_command(rollback):
            reasons.append(
                f"{device}: rollback '{rollback}' is not an ACL line this system can model"
            )

    return GuardResult(ok=not reasons, reasons=reasons)
