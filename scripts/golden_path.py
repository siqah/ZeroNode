#!/usr/bin/env python3
"""Run the scripted golden incident and print HITL pause state (no Ollama required)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
API = ROOT / "apps" / "api"
sys.path.insert(0, str(API))

from langchain_core.messages import HumanMessage  # noqa: E402

from app.graph.builder import build_graph  # noqa: E402
from app.graph.scripted import scripted_llm  # noqa: E402
from app.store.memory import InMemoryTopology  # noqa: E402


def main() -> int:
    graph = build_graph(scripted_llm(), InMemoryTopology())
    config = {"configurable": {"thread_id": "INC-1001"}}
    graph.invoke(
        {
            "messages": [
                HumanMessage(content="New Alert: Web_App cannot reach DB_Primary:443")
            ],
            "incident_id": "INC-1001",
            "pending_actions": [],
            "topology_context": "",
            "reasoning_trace": [],
        },
        config,
    )
    snapshot = graph.get_state(config)
    payload = {
        "next": list(snapshot.next or ()),
        "status": "awaiting_approval" if snapshot.next else "not_paused",
        "topology_context": snapshot.values.get("topology_context"),
        "proposed_actions": snapshot.values.get("pending_actions"),
        "reasoning_trace": snapshot.values.get("reasoning_trace"),
    }
    print(json.dumps(payload, indent=2))
    if snapshot.next != ("execute_change",):
        print("FAIL: expected interrupt before execute_change", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
