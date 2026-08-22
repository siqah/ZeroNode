import pytest
from langchain_core.messages import HumanMessage

from app.config import Settings
from app.graph.builder import build_graph
from app.graph.scripted import scripted_llm
from app.inference.errors import ModelBudgetExceeded
from app.store.memory import InMemoryTopology


def test_node_budget_blocks_before_model_call():
    settings = Settings(model_node_budget_seconds=1.0, model_incident_budget_seconds=0.0)
    graph = build_graph(scripted_llm(), InMemoryTopology(), settings=settings)
    with pytest.raises(ModelBudgetExceeded, match="node 'supervisor'"):
        graph.invoke(
            {
                "messages": [
                    HumanMessage(content="New Alert: Web_App cannot reach DB_Primary:443")
                ],
                "incident_id": "BUDGET-NODE",
                "tool_log": [],
                "model_elapsed_seconds": 0.0,
                "model_seconds_by_node": {"supervisor": 1.0},
            },
            {"configurable": {"thread_id": "BUDGET-NODE"}},
        )
