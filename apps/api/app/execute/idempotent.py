"""Idempotent device execution keyed by the approval ledger hash."""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

from app.execute.base import APPLIED, REFUSED, ExecutionResult, ExecutionStep
from app.execute.device import DeviceExecutor
from app.execute.guard import check
from app.execute.live import _same_rule, verify_applied
from app.execute.render import rendered_for
from app.execute.session import ConfigSession
from app.firewall.base import FirewallStore
from app.firewall.policy import parse_acl_command

logger = logging.getLogger(__name__)


class IdempotentDeviceExecutor(DeviceExecutor):
    """Skip actions that already landed under the same approval operation key."""

    def __init__(
        self,
        firewall: FirewallStore,
        session_factory: Callable[[str], ConfigSession],
        *,
        devices: set[str],
        auto_rollback: bool = True,
        platform: str = "cisco_asa",
        lookup: Callable[[str], dict[str, Any] | None] | None = None,
        store: Callable[[str, str, dict[str, Any]], None] | None = None,
    ) -> None:
        super().__init__(
            firewall,
            session_factory,
            devices=devices,
            auto_rollback=auto_rollback,
            platform=platform,
        )
        self.lookup = lookup
        self.store = store
        self._operation_key = ""

    def apply_once(
        self,
        actions: list[dict[str, Any]],
        flows: list[dict[str, Any]],
        *,
        operation_key: str,
        thread_id: str,
    ) -> ExecutionResult:
        self._operation_key = operation_key
        if self.lookup and operation_key:
            cached = self.lookup(operation_key)
            if cached is not None:
                logger.info(
                    "replaying cached execution for %s (%s)", thread_id, operation_key
                )
                return ExecutionResult(
                    mode=str(cached.get("mode", "device")),
                    state=str(cached.get("state", APPLIED)),
                    lines=list(cached.get("lines") or []),
                    steps=[
                        ExecutionStep(
                            command=str(step.get("command", "")),
                            output=str(step.get("output", "")),
                            error=str(step.get("error", "")),
                        )
                        for step in cached.get("steps") or []
                    ],
                    verification=list(cached.get("verification") or []),
                )
        result = self.apply(actions, flows)
        if self.store and operation_key and result.state != REFUSED:
            self.store(operation_key, thread_id, result.as_dict())
        return result

    def _apply(
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
        steps: list[ExecutionStep] = []
        try:
            for action in actions:
                device = str(action.get("device", ""))
                if self._already_landed(action):
                    lines = rendered_for(action, self.platform)
                    command = "; ".join(lines)
                    steps.append(
                        ExecutionStep(
                            command=command,
                            output="skipped: rule already present on device",
                        )
                    )
                    logger.info(
                        "%s: skipping already-landed change for %s",
                        device,
                        self._operation_key or "unkeyed",
                    )
                    continue
                lines = rendered_for(action, self.platform)
                command = "; ".join(lines)
                try:
                    output = self._session(device).send_config(lines)
                    steps.append(ExecutionStep(command=command, output=output))
                except Exception as exc:  # noqa: BLE001
                    steps.append(ExecutionStep(command=command, error=str(exc)))
                    logger.exception("%s: sending '%s' failed", device, command)
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
        finally:
            for session in self._sessions.values():
                session.close()
            self._sessions = {}

    def _already_landed(self, action: dict[str, Any]) -> bool:
        expected = parse_acl_command(str(action.get("command", "")))
        if expected is None:
            return False
        device = str(action.get("device", ""))
        refresh = getattr(self.firewall, "refresh", None)
        if callable(refresh):
            refresh(device)
        policy = self.firewall.acl_policy(device)
        landed = next((rule for rule in policy if _same_rule(rule, expected)), None)
        if landed is None:
            return False
        position = action.get("position")
        if position is not None and landed.line != int(position):
            # Present at another line: still treat as landed to avoid duplicates.
            logger.warning(
                "%s: expected rule already at line %s (wanted %s)",
                device,
                landed.line,
                position,
            )
        return True
