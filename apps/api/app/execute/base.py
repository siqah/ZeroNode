"""What it means to carry out an approved change.

Execution is the only thing in the system that can alter a network, so the
interface is written to make refusing easy and acting hard: an executor reports
what it did, what it verified afterwards, and whether it had to undo itself.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

# Terminal states, in the order of how much explaining they need.
LOGGED = "logged"  # dry run: nothing touched a device
APPLIED = "applied"  # change is on the device and verified afterwards
REFUSED = "refused"  # a precondition failed; nothing was sent
ROLLED_BACK = "rolled_back"  # change was applied, failed verification, and undone
ROLLBACK_FAILED = "rollback_failed"  # the device is in a state nobody chose


@dataclass
class ExecutionStep:
    command: str
    output: str = ""
    error: str = ""

    @property
    def ok(self) -> bool:
        return not self.error


@dataclass
class ExecutionResult:
    mode: str
    state: str
    lines: list[str] = field(default_factory=list)
    steps: list[ExecutionStep] = field(default_factory=list)
    verification: list[str] = field(default_factory=list)

    @property
    def touched_device(self) -> bool:
        return self.state in (APPLIED, ROLLED_BACK, ROLLBACK_FAILED)

    @property
    def ok(self) -> bool:
        return self.state in (LOGGED, APPLIED)

    @property
    def needs_attention(self) -> bool:
        """A human has to look at the device now, not at their convenience."""
        return self.state == ROLLBACK_FAILED

    def as_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "state": self.state,
            "lines": self.lines,
            "verification": self.verification,
            "commands": [step.command for step in self.steps],
            "errors": [step.error for step in self.steps if step.error],
        }


class Executor(Protocol):
    def describe(self) -> str:
        """Recorded in the audit trail, so it must say whether this can write."""
        ...

    def apply(
        self, actions: list[dict[str, Any]], flows: list[dict[str, Any]]
    ) -> ExecutionResult: ...
