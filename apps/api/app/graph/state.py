from typing import Annotated, Any

from langchain_core.messages import BaseMessage
from langgraph.graph import add_messages
from typing_extensions import TypedDict


def append_trace(left: list[str] | None, right: list[str] | None) -> list[str]:
    return (left or []) + (right or [])


class NetworkAgentState(TypedDict, total=False):
    messages: Annotated[list[BaseMessage], add_messages]
    incident_id: str
    active_worker: str
    findings_summary: str
    pending_actions: list[dict[str, Any]]
    denied_flows: list[dict[str, Any]]
    verification: list[str]
    verify_attempts: int
    # What happened after approval: dry run, applied, refused or rolled back.
    execution: dict[str, Any]
    topology_context: str
    zone_context: str
    # What the alert text looked like it was trying to do, if anything.
    alert_flags: list[str]
    reasoning_trace: Annotated[list[str], append_trace]
    tool_log: Annotated[list[str], append_trace]
    task_brief: str
    human_decision: str
    human_feedback: str
    human_actor: str
