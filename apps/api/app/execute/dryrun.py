"""The default: log the change, touch nothing.

This is not a placeholder for the real executor. It is the mode the system runs
in unless someone has deliberately turned execution on for a named device, and
it stays the correct choice for any environment where a wrong command costs more
than a manual paste.
"""

from __future__ import annotations

from typing import Any

from app.execute.base import LOGGED, ExecutionResult, ExecutionStep


class DryRunExecutor:
    def describe(self) -> str:
        return "dry-run (no device is contacted)"

    def apply(
        self, actions: list[dict[str, Any]], flows: list[dict[str, Any]]
    ) -> ExecutionResult:
        steps = [
            ExecutionStep(command=str(action.get("command", "")).strip())
            for action in actions
            if str(action.get("command", "")).strip()
        ]
        return ExecutionResult(
            mode="dry-run",
            state=LOGGED,
            lines=["Commands were logged for a human to apply; nothing was sent to a device."],
            steps=steps,
        )
