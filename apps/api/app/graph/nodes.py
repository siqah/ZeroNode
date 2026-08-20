from __future__ import annotations

from dataclasses import dataclass

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage
from langgraph.graph import END
from langgraph.types import Command
from pydantic import ValidationError

from app.execute.base import (
    APPLIED,
    LOGGED,
    REFUSED,
    ROLLBACK_FAILED,
    ROLLED_BACK,
    Executor,
)
from app.execute.dryrun import DryRunExecutor
from app.firewall.base import FirewallStore
from app.graph.parser import (
    ParsedToolCall,
    extract_thinking,
    infer_tool_call,
    message_text,
    parse_tool_call,
)
from app.graph.prompts import FIREWALL_PROMPT, SUPERVISOR_PROMPT
from app.graph.state import NetworkAgentState
from app.sanitize import clean_device_output
from app.store import TopologyStore
from app.tools import FIREWALL_TOOLS, SUPERVISOR_TOOLS, ToolContext, ToolSpec
from app.verify import verify_change


@dataclass
class AgentRuntime:
    llm: BaseChatModel
    topology: TopologyStore
    firewall: FirewallStore

    @property
    def tool_context(self) -> ToolContext:
        return ToolContext(topology=self.topology, firewall=self.firewall)


def run_xml_turn(
    state: NetworkAgentState,
    agent: AgentRuntime,
    *,
    system_prompt: str,
    tools: dict[str, ToolSpec],
    default_goto: str,
    extra_system: str = "",
) -> Command:
    sys = system_prompt
    if extra_system:
        sys = system_prompt + "\n\n" + extra_system
    prompt_messages = [SystemMessage(content=sys), *state.get("messages", [])]
    response = agent.llm.invoke(prompt_messages)
    content = message_text(response.content)
    if "<tool_call>" in content.lower() and "</tool_call>" not in content.lower():
        content = content.rstrip() + "\n</tool_call>"
    thinking = extract_thinking(content)

    # Once the history holds a tool call, Ollama's Gemma template answers with a
    # native tool_calls payload and empty content, so check that before the XML.
    native = list(getattr(response, "tool_calls", None) or [])
    parsed = None
    if native:
        parsed = ParsedToolCall(
            name=str(native[0].get("name") or ""),
            arguments=dict(native[0].get("args") or {}),
        )
    if parsed is None:
        parsed = parse_tool_call(content)
    inferred = False
    if parsed is None:
        parsed = infer_tool_call(
            allowed=set(tools),
            topology_context=state.get("topology_context") or "",
            zone_context=state.get("zone_context") or "",
            tool_log=list(state.get("tool_log") or []),
            messages=list(state.get("messages") or []),
        )
        inferred = parsed is not None

    ai_message = AIMessage(content=content)
    update: dict = {"messages": [ai_message]}
    if thinking:
        update["reasoning_trace"] = [thinking]
    elif parsed is not None:
        # Native tool calls carry no prose, so the trace would otherwise be blank.
        args_text = ", ".join(f"{key}={value}" for key, value in parsed.arguments.items())
        update["reasoning_trace"] = [f"Chose {parsed.name}({args_text})"]
    if inferred and parsed is not None:
        update["tool_log"] = [f"inferred {parsed.name} after truncated model output"]

    if parsed is None:
        update["messages"] = [
            ai_message,
            HumanMessage(
                content=(
                    "Format error: reply with only "
                    '<tool_call>{"name":"...","arguments":{...}}</tool_call>'
                )
            ),
        ]
        snippet = content[:400].replace("\n", " ")
        update["tool_log"] = [f"parse_error: {snippet}"]
        return Command(goto=default_goto, update=update)

    spec = tools.get(parsed.name)
    if spec is None:
        allowed = ", ".join(tools)
        update["messages"] = [
            AIMessage(
                content=content,
                tool_calls=[
                    {
                        "name": parsed.name,
                        "args": parsed.arguments,
                        "id": "xml-1",
                        "type": "tool_call",
                    }
                ],
            ),
            ToolMessage(
                content=f"Error: unknown tool '{parsed.name}'. Available: [{allowed}]",
                tool_call_id="xml-1",
            ),
        ]
        return Command(goto=default_goto, update=update)

    try:
        args = spec.args_model.model_validate(parsed.arguments)
    except ValidationError as exc:
        update["messages"] = [
            AIMessage(
                content=content,
                tool_calls=[
                    {
                        "name": parsed.name,
                        "args": parsed.arguments,
                        "id": "xml-1",
                        "type": "tool_call",
                    }
                ],
            ),
            ToolMessage(
                content=(
                    f"Error: invalid arguments for {parsed.name}. {exc.errors()} "
                    f"Known devices: {agent.topology.known_devices()}"
                ),
                tool_call_id="xml-1",
            ),
        ]
        return Command(goto=default_goto, update=update)

    result = spec.handler(args, dict(state), agent.tool_context)
    # Tool output carries device text, and an ACL remark is somewhere an attacker
    # with config access can leave a message for the model.
    tool_content = clean_device_output(result.content)
    ai_with_call = AIMessage(
        content=content,
        tool_calls=[
            {
                "name": parsed.name,
                "args": parsed.arguments,
                "id": "xml-1",
                "type": "tool_call",
            }
        ],
    )
    merged = {
        **update,
        **result.state_update,
        "messages": [
            ai_with_call,
            ToolMessage(content=tool_content, tool_call_id="xml-1"),
        ],
        "tool_log": (update.get("tool_log") or []) + [f"{parsed.name}: {result.content}"],
    }
    return Command(goto=result.goto or default_goto, update=merged)


def _supervisor_hint(state: NetworkAgentState) -> str:
    path = (state.get("topology_context") or "").strip()
    zone = (state.get("zone_context") or "").strip()
    if not path:
        return "NEXT REQUIRED ACTION: trace_network_path."
    if not zone:
        return f"Known path: {path}\nNEXT REQUIRED ACTION: security_boundary_check."
    return (
        f"Known path: {path}\nZones: {zone}\n"
        "Topology is complete. NEXT REQUIRED ACTION: delegate_to_firewall_specialist. "
        "Do not call a topology tool again."
    )


def _firewall_hint(state: NetworkAgentState) -> str:
    log = " ".join(state.get("tool_log") or [])
    if "get_denied_flows:" not in log:
        return "NEXT REQUIRED ACTION: get_denied_flows."
    return (
        "Denied flows are known. NEXT REQUIRED ACTION: propose_policy_change on FW_Edge "
        "with the exact permit line. Use get_acl_hits to find the denying rule's line "
        "number, then pass position=<line - 1> so the permit is evaluated first, and "
        "rollback=\"no <that same permit line>\"."
    )


def supervisor_node(state: NetworkAgentState, agent: AgentRuntime) -> Command:
    return run_xml_turn(
        state,
        agent,
        system_prompt=SUPERVISOR_PROMPT,
        tools=SUPERVISOR_TOOLS,
        default_goto="supervisor",
        extra_system=_supervisor_hint(state),
    )


def firewall_node(state: NetworkAgentState, agent: AgentRuntime) -> Command:
    brief = (state.get("task_brief") or "").strip()
    extra = _firewall_hint(state)
    if brief:
        extra = f"Delegated task:\n{brief}\n\n{extra}"
    return run_xml_turn(
        state,
        agent,
        system_prompt=FIREWALL_PROMPT,
        tools=FIREWALL_TOOLS,
        default_goto="firewall_specialist",
        extra_system=extra,
    )


def execute_change(
    state: NetworkAgentState,
    firewall: FirewallStore,
    executor: Executor | None = None,
) -> Command:
    decision = (state.get("human_decision") or "").strip().lower()
    feedback = (state.get("human_feedback") or "").strip()
    actions = state.get("pending_actions") or []

    actor = (state.get("human_actor") or "unattributed").strip()

    if decision == "reject":
        note = feedback or "no details"
        return Command(
            goto="firewall_specialist",
            update={
                "messages": [
                    HumanMessage(
                        content=(
                            f"Engineer {actor} REJECTED the change. Feedback: {note}. "
                            "Revise the proposal and call propose_policy_change again."
                        )
                    )
                ],
                "pending_actions": [],
                "human_decision": "",
                "human_feedback": "",
                "human_actor": "",
                "task_brief": f"Rejected. Engineer feedback: {note}",
            },
        )

    lines = [str(item.get("command", "")).strip() for item in actions]
    commands = "\n".join(line for line in lines if line) or "(none)"
    flows = list(state.get("denied_flows") or [])
    # Re-run the simulation against the approved commands so the audit record
    # reflects what was signed off, not what was first proposed.
    report = verify_change(actions, flows, firewall)
    verdict = "VERIFIED" if report.ok else "NOT VERIFIED"
    reversals = "\n".join(
        str(item.get("rollback", "")).strip() for item in actions if item.get("rollback")
    )

    result = (executor or DryRunExecutor()).apply(actions, flows)
    headline = {
        LOGGED: f"DRY-RUN approved by {actor} ({verdict}). Commands logged, not executed:",
        APPLIED: f"APPLIED to the device, approved by {actor} ({verdict}):",
        REFUSED: f"NOT EXECUTED, approved by {actor} ({verdict}). Commands:",
        ROLLED_BACK: f"ROLLED BACK after a failed check, approved by {actor} ({verdict}):",
        ROLLBACK_FAILED: (
            f"MANUAL INTERVENTION NEEDED. Approved by {actor} ({verdict}) and the device "
            "could not be returned to its previous state:"
        ),
    }.get(result.state, f"Approved by {actor} ({verdict}):")

    summary = (
        headline
        + "\n"
        + commands
        + (f"\nEngineer note: {feedback}" if feedback else "")
        + (f"\nRollback:\n{reversals}" if reversals else "")
        + "\nSimulation: "
        + " ".join(report.lines)
        + "\nExecution: "
        + " ".join(result.lines + result.verification)
    )
    return Command(
        goto=END,
        update={
            "findings_summary": summary,
            "verification": report.lines,
            "execution": result.as_dict(),
            "active_worker": "",
        },
    )
