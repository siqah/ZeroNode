"""Run golden incidents through the graph and score the outcome."""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from langchain_core.language_models.fake_chat_models import FakeListChatModel
from langchain_core.messages import HumanMessage

from app.eval.corpus import IncidentSpec, load_corpus, load_incident
from app.eval.fixtures import load_firewall, load_topology
from app.eval.scorers import ScoreResult, score_incident
from app.graph.builder import build_graph
from app.observability import Metrics


@dataclass
class EvalReport:
    mode: str
    passed: bool
    incidents: list[ScoreResult] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "mode": self.mode,
            "passed": self.passed,
            "incidents": [
                {
                    "id": item.incident_id,
                    "passed": item.passed,
                    "checks": item.checks,
                    "failures": item.failures,
                }
                for item in self.incidents
            ],
        }


def _initial_state(spec: IncidentSpec) -> dict:
    return {
        "messages": [HumanMessage(content=spec.alert)],
        "incident_id": spec.ticket_id,
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
        "human_actor": "",
        "tool_log": [],
        "model_elapsed_seconds": 0.0,
        "model_seconds_by_node": {},
        "topology_site": spec.topology_site,
    }


def run_incident(
    spec: IncidentSpec,
    *,
    metrics: Metrics | None = None,
) -> ScoreResult:
    llm = FakeListChatModel(responses=list(spec.scripted_responses))
    graph = build_graph(
        llm,
        load_topology(spec.topology),
        metrics=metrics,
        firewall=load_firewall(spec.firewall),
    )
    config = {"configurable": {"thread_id": spec.ticket_id}}
    graph.invoke(_initial_state(spec), config)
    snapshot = graph.get_state(config)
    return score_incident(spec.id, spec.expect, snapshot)


def run_corpus(*, incident_ids: list[str] | None = None) -> EvalReport:
    specs = (
        [load_incident(item) for item in incident_ids]
        if incident_ids
        else load_corpus()
    )
    metrics = Metrics(enabled=True)
    results = [run_incident(spec, metrics=metrics) for spec in specs]
    passed = all(item.passed for item in results)
    return EvalReport(mode="scripted", passed=passed, incidents=results)


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Run the golden incident eval corpus.")
    parser.add_argument(
        "--incident",
        action="append",
        dest="incidents",
        help="Run one incident id (default: entire corpus)",
    )
    parser.add_argument("--json", action="store_true", help="Print machine-readable report")
    args = parser.parse_args(argv)

    report = run_corpus(incident_ids=args.incidents)
    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        for item in report.incidents:
            status = "PASS" if item.passed else "FAIL"
            print(f"{status} {item.incident_id}")
            for line in item.checks:
                print(f"  {line}")
            for line in item.failures:
                print(f"  !! {line}")
    return 0 if report.passed else 1
