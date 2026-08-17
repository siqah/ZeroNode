from langchain_core.messages import HumanMessage
from langgraph.types import Command

from app.graph.builder import build_graph
from app.graph.scripted import scripted_llm
from app.store.memory import InMemoryTopology


def _run_golden():
    graph = build_graph(scripted_llm(), InMemoryTopology())
    config = {"configurable": {"thread_id": "INC-1001"}}
    graph.invoke(
        {
            "messages": [
                HumanMessage(content="New Alert: Web_App cannot reach DB_Primary:443")
            ],
            "incident_id": "INC-1001",
            "active_worker": "",
            "findings_summary": "",
            "pending_actions": [],
            "topology_context": "",
            "zone_context": "",
            "denied_flows": [],
            "verification": [],
            "verify_attempts": 0,
            "reasoning_trace": [],
            "task_brief": "",
            "human_decision": "",
            "human_feedback": "",
        },
        config,
    )
    return graph, config


def test_golden_path_pauses_before_execute():
    graph, config = _run_golden()
    snapshot = graph.get_state(config)
    assert snapshot.next == ("execute_change",)
    actions = snapshot.values["pending_actions"]
    assert actions
    assert "permit tcp" in actions[0]["command"]
    assert "10.10.1.10" in actions[0]["command"]
    assert "10.20.1.50" in actions[0]["command"]
    assert "FW_Edge" == actions[0]["device"]
    assert "crosses_boundary=true" in snapshot.values["zone_context"]
    trace = snapshot.values.get("reasoning_trace") or []
    assert trace


def test_shadowed_proposal_is_corrected_before_the_human_sees_it():
    graph, config = _run_golden()
    snapshot = graph.get_state(config)
    action = snapshot.values["pending_actions"][0]

    assert action["verified"] is True
    assert action["position"] == 39
    assert snapshot.values["verify_attempts"] == 1
    log = " ".join(snapshot.values["tool_log"])
    assert "Change NOT queued" in log


def test_golden_path_approve_is_dry_run():
    graph, config = _run_golden()
    graph.invoke(
        Command(
            resume=True,
            update={"human_decision": "approve", "human_feedback": "ticket INC-1001"},
        ),
        config,
    )
    snapshot = graph.get_state(config)
    assert snapshot.next == ()
    summary = snapshot.values["findings_summary"]
    assert summary.startswith("DRY-RUN approved (VERIFIED)")
    assert "not executed" in summary
    assert "permit tcp" in summary
    assert "PASS" in summary
