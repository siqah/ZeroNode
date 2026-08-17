from __future__ import annotations

from langchain_core.language_models.chat_models import BaseChatModel
from langgraph.checkpoint.base import BaseCheckpointSaver
from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import START, StateGraph
from langgraph.graph.state import CompiledStateGraph

from app.graph.nodes import AgentRuntime, execute_change, firewall_node, supervisor_node
from app.graph.state import NetworkAgentState
from app.store import TopologyStore


def build_graph(
    llm: BaseChatModel,
    topology: TopologyStore,
    checkpointer: BaseCheckpointSaver | None = None,
) -> CompiledStateGraph:
    agent = AgentRuntime(llm=llm, topology=topology)

    def supervisor(state: NetworkAgentState):
        return supervisor_node(state, agent)

    def firewall_specialist(state: NetworkAgentState):
        return firewall_node(state, agent)

    builder = StateGraph(NetworkAgentState)
    builder.add_node("supervisor", supervisor)
    builder.add_node("firewall_specialist", firewall_specialist)
    builder.add_node("execute_change", execute_change)
    builder.add_edge(START, "supervisor")
    return builder.compile(
        checkpointer=checkpointer or MemorySaver(),
        interrupt_before=["execute_change"],
    )
