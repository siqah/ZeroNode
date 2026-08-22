import pytest
from langchain_core.language_models.fake_chat_models import FakeListChatModel

from app.config import Settings
from app.graph.builder import build_graph
from app.inference.errors import InferenceFallbackDisabled
from app.inference.factory import make_llm
from app.store.memory import InMemoryTopology


def test_make_llm_ollama_backend():
    settings = Settings(inference_backend="ollama")
    llm, circuit = make_llm(settings)
    assert llm is not None
    assert circuit.failure_threshold == settings.model_circuit_failures


def test_make_llm_vllm_requires_base_url():
    settings = Settings(inference_backend="vllm")
    with pytest.raises(RuntimeError, match="VLLM_BASE_URL"):
        make_llm(settings)


def test_inference_fallback_disabled_raises():
    settings = Settings(model_allow_inference_fallback=False)
    bad = FakeListChatModel(responses=["garbage with no tool call"])
    graph = build_graph(
        bad,
        InMemoryTopology(),
        settings=settings,
    )
    from langchain_core.messages import HumanMessage

    with pytest.raises(InferenceFallbackDisabled):
        graph.invoke(
            {
                "messages": [HumanMessage(content="New Alert: test")],
                "incident_id": "EVAL-FALLBACK",
                "tool_log": [],
                "model_elapsed_seconds": 0.0,
                "model_seconds_by_node": {},
            },
            {"configurable": {"thread_id": "EVAL-FALLBACK"}},
        )
