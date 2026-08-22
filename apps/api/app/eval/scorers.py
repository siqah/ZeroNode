"""Score a paused investigation against corpus expectations."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ScoreResult:
    incident_id: str
    passed: bool
    checks: list[str] = field(default_factory=list)
    failures: list[str] = field(default_factory=list)

    def record(self, name: str, ok: bool, detail: str = "") -> None:
        label = name if not detail else f"{name}: {detail}"
        self.checks.append(f"{'PASS' if ok else 'FAIL'} {label}")
        if not ok:
            self.failures.append(label)
            self.passed = False


def _tool_names(tool_log: list[str]) -> list[str]:
    names: list[str] = []
    for entry in tool_log:
        if entry.startswith("inferred ") or entry.startswith("parse_error:"):
            continue
        if ":" in entry:
            names.append(entry.split(":", 1)[0])
    return names


def score_incident(incident_id: str, expect: dict[str, Any], snapshot) -> ScoreResult:
    result = ScoreResult(incident_id=incident_id, passed=True)
    values = snapshot.values
    next_nodes = tuple(snapshot.next or ())

    pause_at = expect.get("pause_at", "execute_change")
    if pause_at == "__end__":
        result.record("ended", not next_nodes, f"next={next_nodes!r}")
    else:
        result.record(
            "pause_before_execute",
            next_nodes == (pause_at,),
            f"next={next_nodes!r}",
        )

    tool_log = list(values.get("tool_log") or [])
    inferred = sum(1 for line in tool_log if line.startswith("inferred "))
    parse_errors = sum(1 for line in tool_log if line.startswith("parse_error:"))
    result.record(
        "inferred_turns",
        inferred <= int(expect.get("max_inferred_turns", 0)),
        f"count={inferred}",
    )
    result.record(
        "parse_errors",
        parse_errors <= int(expect.get("max_parse_errors", 0)),
        f"count={parse_errors}",
    )

    names = _tool_names(tool_log)
    for tool in expect.get("tool_sequence_contains") or []:
        result.record(f"tool:{tool}", tool in names)

    zone_needle = expect.get("zone_context_contains")
    if zone_needle:
        zone = str(values.get("zone_context") or "")
        result.record("zone_context", zone_needle in zone, zone or "(empty)")

    summary_needle = expect.get("findings_summary_contains")
    if summary_needle:
        summary = str(values.get("findings_summary") or "")
        result.record("findings_summary", summary_needle in summary, summary or "(empty)")

    proposal = expect.get("proposal") or {}
    actions = list(values.get("pending_actions") or [])
    if pause_at == "execute_change" or expect.get("proposal"):
        result.record("proposal_present", bool(actions))
    if actions and proposal:
        action = actions[0]
        if "device" in proposal:
            result.record(
                "proposal_device",
                action.get("device") == proposal["device"],
                str(action.get("device")),
            )
        for needle in proposal.get("command_contains") or []:
            command = str(action.get("command") or "")
            result.record(f"proposal_command:{needle}", needle in command)
        if "position" in proposal:
            result.record(
                "proposal_position",
                action.get("position") == proposal["position"],
                str(action.get("position")),
            )
        if "verified" in proposal:
            result.record(
                "proposal_verified",
                bool(action.get("verified")) == bool(proposal["verified"]),
            )

    if "max_verify_attempts" in expect:
        attempts = int(values.get("verify_attempts") or 0)
        result.record(
            "verify_attempts",
            attempts <= int(expect["max_verify_attempts"]),
            str(attempts),
        )

    trace = values.get("reasoning_trace") or []
    result.record("reasoning_trace", bool(trace), f"lines={len(trace)}")
    return result
