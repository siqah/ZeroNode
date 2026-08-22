from __future__ import annotations

from langchain_core.language_models.chat_models import BaseChatModel
from langgraph.checkpoint.base import BaseCheckpointSaver
from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import START, StateGraph
from langgraph.graph.state import CompiledStateGraph

from app.config import Settings
from app.execute.base import Executor
from app.firewall.base import FirewallStore
from app.firewall.mock import MockFirewall
from app.graph.nodes import AgentRuntime, execute_change, firewall_node, supervisor_node
from app.graph.state import NetworkAgentState
from app.observability import Metrics
from app.store import TopologyStore


def build_graph(
    llm: BaseChatModel,
    topology: TopologyStore,
    checkpointer: BaseCheckpointSaver | None = None,
    firewall: FirewallStore | None = None,
    executor: Executor | None = None,
    metrics: Metrics | None = None,
    settings: Settings | None = None,
) -> CompiledStateGraph:
    from app.config import settings as default_settings

    cfg = settings or default_settings
    agent = AgentRuntime(
        llm=llm,
        topology=topology,
        firewall=firewall or MockFirewall(),
        metrics=metrics,
        model_node_budget_seconds=float(cfg.model_node_budget_seconds or 0),
        model_incident_budget_seconds=float(cfg.model_incident_budget_seconds or 0),
        model_allow_inference_fallback=bool(cfg.model_allow_inference_fallback),
    )

    def supervisor(state: NetworkAgentState):
        return supervisor_node(state, agent)

    def firewall_specialist(state: NetworkAgentState):
        return firewall_node(state, agent)

    def execute(state: NetworkAgentState):
        return execute_change(state, agent.firewall, executor)

    builder = StateGraph(NetworkAgentState)
    builder.add_node("supervisor", supervisor)
    builder.add_node("firewall_specialist", firewall_specialist)
    builder.add_node("execute_change", execute)
    builder.add_edge(START, "supervisor")
    return builder.compile(
        checkpointer=checkpointer or MemorySaver(),
        interrupt_before=["execute_change"],
    )
