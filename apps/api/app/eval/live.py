"""Run golden incidents against a live inference backend (Ollama or vLLM)."""

from __future__ import annotations

import json

from app.config import settings
from app.eval.corpus import IncidentSpec, load_corpus
from app.eval.runner import EvalReport, _initial_state
from app.eval.scorers import ScoreResult, score_incident
from app.graph.builder import build_graph
from app.inference import make_llm
from app.main import _inference_status
from app.observability import Metrics
from app.store.memory import InMemoryTopology


def inference_reachable() -> tuple[bool, str]:
    return _inference_status()


def run_live_incident(spec: IncidentSpec) -> ScoreResult:
    llm, _circuit = make_llm(settings)
    metrics = Metrics(enabled=True)
    graph = build_graph(
        llm,
        InMemoryTopology(),
        metrics=metrics,
        settings=settings,
    )
    config = {"configurable": {"thread_id": f"eval-{spec.ticket_id}"}}
    graph.invoke(_initial_state(spec), config)
    snapshot = graph.get_state(config)
    return score_incident(spec.id, spec.expect, snapshot)


def run_live_corpus(*, incident_ids: list[str] | None = None) -> EvalReport:
    from app.eval.corpus import load_incident

    specs = (
        [load_incident(item) for item in incident_ids]
        if incident_ids
        else load_corpus()
    )
    ok, detail = inference_reachable()
    if not ok:
        raise RuntimeError(f"live eval requires reachable inference: {detail}")
    results = [run_live_incident(spec) for spec in specs]
    passed = all(item.passed for item in results)
    return EvalReport(mode="live", passed=passed, incidents=results)


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        description="Score the golden corpus against live inference (Ollama or vLLM)."
    )
    parser.add_argument("--incident", action="append", dest="incidents")
    parser.add_argument("--json", action="store_true")
    parser.add_argument(
        "--probe-only",
        action="store_true",
        help="Only check that the configured inference backend responds",
    )
    args = parser.parse_args(argv)

    ok, detail = inference_reachable()
    if args.probe_only:
        print(json.dumps({"reachable": ok, "detail": detail}, indent=2))
        return 0 if ok else 1

    if not ok:
        print(f"SKIP live eval: {detail}", flush=True)
        return 0

    report = run_live_corpus(incident_ids=args.incidents)
    if args.json:
        payload = report.to_dict()
        payload["inference"] = detail
        print(json.dumps(payload, indent=2))
    else:
        print(f"inference: {detail}")
        for item in report.incidents:
            status = "PASS" if item.passed else "FAIL"
            print(f"{status} {item.incident_id}")
            for line in item.failures:
                print(f"  !! {line}")
    return 0 if report.passed else 1
