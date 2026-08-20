"""Applying an approved change to a real device, and undoing it when it fails.

The sequence is fixed and each step earns the next: check the preconditions,
send the change, read the policy back off the device, and if what came back is
not what was approved, put it back the way it was. The last step is the reason
the whole thing is defensible — an execution path that can only move forward is
one nobody should turn on.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

from app.execute.base import (
    APPLIED,
    REFUSED,
    ROLLBACK_FAILED,
    ROLLED_BACK,
    ExecutionResult,
    ExecutionStep,
)
from app.execute.guard import check
from app.execute.live import verify_applied, verify_reverted
from app.execute.render import rendered_for
from app.execute.session import ConfigSession
from app.firewall.base import FirewallStore

logger = logging.getLogger(__name__)


class DeviceExecutor:
    def __init__(
        self,
        firewall: FirewallStore,
        session_factory: Callable[[str], ConfigSession],
        *,
        devices: set[str],
        auto_rollback: bool = True,
        platform: str = "cisco_asa",
    ) -> None:
        self.firewall = firewall
        self.session_factory = session_factory
        self.devices = devices
        self.platform = platform
        self.auto_rollback = auto_rollback
        self._sessions: dict[str, ConfigSession] = {}

    def describe(self) -> str:
        names = ", ".join(sorted(self.devices)) or "(none)"
        return f"live execution enabled for {names}"

    def apply(
        self, actions: list[dict[str, Any]], flows: list[dict[str, Any]]
    ) -> ExecutionResult:
        guard = check(actions, flows, self.devices)
        if not guard.ok:
            return ExecutionResult(
                mode="device",
                state=REFUSED,
                lines=["Refused to execute: " + "; ".join(guard.reasons)],
            )

        self._sessions = {}
        try:
            return self._apply(actions, flows)
        finally:
            # A device has a finite number of VTY lines, and a change that leaves
            # one held is a change that makes the next one harder.
            for session in self._sessions.values():
                session.close()
            self._sessions = {}

    def _session(self, device: str) -> ConfigSession:
        """One session per device for the whole change, including its reversal."""
        if device not in self._sessions:
            self._sessions[device] = self.session_factory(device)
        return self._sessions[device]

    def _apply(
        self, actions: list[dict[str, Any]], flows: list[dict[str, Any]]
    ) -> ExecutionResult:
        steps: list[ExecutionStep] = []
        for action in actions:
            device = str(action.get("device", ""))
            # What the device is sent, which carries the position the simulator
            # assumed. Sending the bare command would append the rule instead.
            lines = rendered_for(action, self.platform)
            command = "; ".join(lines)
            try:
                output = self._session(device).send_config(lines)
                steps.append(ExecutionStep(command=command, output=output))
            except Exception as exc:  # noqa: BLE001 - reported to the operator, not raised
                steps.append(ExecutionStep(command=command, error=str(exc)))
                logger.exception("%s: sending '%s' failed", device, command)
                # A partial push is exactly when a rollback matters most.
                return self._revert(
                    actions,
                    flows,
                    steps,
                    reason=f"sending '{command}' failed: {exc}",
                )

        live = verify_applied(self.firewall, actions, flows)
        if live.ok:
            return ExecutionResult(
                mode="device",
                state=APPLIED,
                lines=["Change applied and confirmed against the device."],
                steps=steps,
                verification=live.lines,
            )

        return self._revert(
            actions,
            flows,
            steps,
            reason="post-change verification failed",
            verification=live.lines,
        )

    def _revert(
        self,
        actions: list[dict[str, Any]],
        flows: list[dict[str, Any]],
        steps: list[ExecutionStep],
        *,
        reason: str,
        verification: list[str] | None = None,
    ) -> ExecutionResult:
        lines = [f"Rolling back: {reason}."]
        verification = list(verification or [])

        if not self.auto_rollback:
            return ExecutionResult(
                mode="device",
                state=ROLLBACK_FAILED,
                lines=[
                    f"{reason}. AUTO ROLLBACK IS DISABLED, so the device has been left "
                    "as it is. Apply the rollback command by hand."
                ],
                steps=steps,
                verification=verification,
            )

        for action in reversed(actions):
            device = str(action.get("device", ""))
            lines = rendered_for(action, self.platform, rollback=True)
            if not lines:
                continue
            rollback = "; ".join(lines)
            try:
                output = self._session(device).send_config(lines)
                steps.append(ExecutionStep(command=rollback, output=output))
            except Exception as exc:  # noqa: BLE001 - the failure is the whole message
                steps.append(ExecutionStep(command=rollback, error=str(exc)))
                logger.error("%s: ROLLBACK FAILED for '%s': %s", device, rollback, exc)
                return ExecutionResult(
                    mode="device",
                    state=ROLLBACK_FAILED,
                    lines=lines
                    + [
                        f"THE ROLLBACK ALSO FAILED on {device}: {exc}. The device is in a "
                        "state nobody approved. Intervene by hand now."
                    ],
                    steps=steps,
                    verification=verification,
                )

        reverted = verify_reverted(self.firewall, actions, flows)
        verification += reverted.lines
        if reverted.ok:
            return ExecutionResult(
                mode="device",
                state=ROLLED_BACK,
                lines=lines + ["The device is back in its previous state."],
                steps=steps,
                verification=verification,
            )

        return ExecutionResult(
            mode="device",
            state=ROLLBACK_FAILED,
            lines=lines
            + [
                "The rollback commands were accepted but the device did not return to "
                "its previous state. Intervene by hand now."
            ],
            steps=steps,
            verification=verification,
        )
